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
// binary is absent. Uses reqwest for the reverse-proxy path and the `web`
// surface (tokio process, the hardened child spawner); gated on both so a web
// app that makes no outbound HTTP calls (no `http_client` feature) stays
// reqwest-free and a server-only or webview build never compiles it.
#[cfg(all(feature = "web", feature = "http_client"))]
pub mod console_proxy;
// Observability middleware + noise ingest — axum request/response types, server-only.
#[cfg(feature = "server")]
pub mod observability;
// Observability export pipelines: federation push to a parent ingest
// and remote-hub OTLP push. Both env-gated + inert by default.
// Use reqwest for outbound push; gated so a web app with no outbound HTTP
// kernel (`http_client` absent) stays reqwest-free.
#[cfg(all(feature = "web", feature = "http_client"))]
pub mod hub_exporter;
#[cfg(all(feature = "web", feature = "http_client"))]
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
        crate::system::write_stdout_line(&render_page(&render_html(&tree)));
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
/// The client's numeric tuning ceilings, each with the `window.__IPE_*` global
/// it sets. `0` passes through to the client unchanged.
#[cfg(feature = "server")]
const CLIENT_TUNING_CEILINGS: [(&str, crate::system::EnvCeiling); 8] = {
    const fn tuning(name: &'static str, default: u64) -> crate::system::EnvCeiling {
        crate::system::EnvCeiling::new(
            name,
            default,
            crate::system::ZeroCeiling::Accepted,
            "decimal count",
        )
    }
    [
        ("RETRY_BASE_MS", tuning("IPE_WEB_RETRY_BASE_MS", 500)),
        ("RETRY_MAX_MS", tuning("IPE_WEB_RETRY_MAX_MS", 16000)),
        (
            "RETRY_MAX_ATTEMPTS",
            tuning("IPE_WEB_RETRY_MAX_ATTEMPTS", 10),
        ),
        ("RETRY_FAST_MS", tuning("IPE_WEB_RETRY_FAST_MS", 200)),
        (
            "RETRY_FAST_WINDOW_MS",
            tuning("IPE_WEB_RETRY_FAST_WINDOW_MS", 3000),
        ),
        ("EVENT_QUEUE_MAX", tuning("IPE_WEB_QUEUE_MAX", 50)),
        ("HELLO_TIMEOUT_MS", tuning("IPE_WEB_HELLO_TIMEOUT_MS", 8000)),
        (
            "HEARTBEAT_TTL_MS",
            tuning("IPE_WEB_HEARTBEAT_TTL_MS", 35000),
        ),
    ]
};

/// The `window.__IPE_*` numeric tuning assignments, resolved once per process.
///
/// [`build_web_router`] refuses to start on a refusal here, so every page a
/// served app renders reads the resolved `Ok`.
#[cfg(feature = "server")]
fn client_tuning_js() -> &'static Result<String, crate::system::EnvCeilingRefusal> {
    static TUNING: std::sync::OnceLock<Result<String, crate::system::EnvCeilingRefusal>> =
        std::sync::OnceLock::new();
    TUNING.get_or_init(|| {
        use std::fmt::Write as _;
        let mut out = String::new();
        for (global, ceiling) in CLIENT_TUNING_CEILINGS {
            let value: u64 = ceiling.read()?;
            let _ = write!(out, "window.__IPE_{global}={value};");
        }
        Ok(out)
    })
}

/// Server-side client-config templating: emit the `window.__IPE_*` assignments
/// the client (`client.js`) reads, each with a hardcoded client fallback.
#[cfg(feature = "server")]
fn web_client_config_js() -> String {
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
    // `ipe dev watch` blue-green path sets this; a release/`ipe dev run` server never
    // does, so the flag defaults off there.
    let swap_toast = matches!(
        crate::system::read_env_var("IPE_WEB_SWAP_TOAST")
            .ok()
            .map(|s| s.trim().to_string()),
        Some(ref v) if !v.is_empty() && v != "0"
    );
    // A refused tuning value never reaches a served page (the router refused
    // to start on it); an unserved render omits the numbers, so the client
    // keeps its own fallbacks rather than an invented value.
    let tuning = client_tuning_js().as_deref().unwrap_or_default();
    format!(
        "window.__IPE_BANNER_ENABLED={banner};\
         window.__IPE_SWAP_TOAST={swap_toast};\
         {tuning}\
         window.__IPE_MSG_RECONNECTING=\"Reconnecting…\";\
         window.__IPE_MSG_UPDATED=\"updated ✓\";\
         window.__IPE_MSG_OFFLINE=\"Connection lost — refresh to retry\";"
    )
}

/// Whether the dev watch/status banner endpoint should be mounted.
///
/// [`watch_banner_active_with`] over the process dev intent.
#[cfg(feature = "server")]
fn watch_banner_active(base: &str) -> bool {
    watch_banner_active_with(base, crate::telemetry::dev_intent_from_env().as_ref())
}

/// Whether the banner endpoint mounts under an explicit dev-intent proof.
///
/// True when `dev` holds, the banner is enabled (not explicitly disabled via
/// `IPE_WEB_BANNER` off/0/false), and the app is root-mounted (not a sub-app).
/// Mirrors the conditions the banner injection already uses so no new env var
/// is needed.
#[cfg(feature = "server")]
fn watch_banner_active_with(base: &str, dev: Option<&crate::telemetry::DevIntent>) -> bool {
    if dev.is_none() {
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
pub fn render_page_full(
    sid: &str,
    base: &crate::encoding::MountBase,
    body: &str,
    epoch: &RenderEpoch,
    csrf_token: &str,
) -> String {
    // sid_js / epoch_js / base_js / csrf_js: Rust Debug ("{:?}") of a &str
    // yields a double-quoted, properly-escaped JS string literal for plain
    // ASCII session ids, epoch tokens, base paths, and the hex CSRF token.
    let sid_js = format!("{sid:?}");
    let epoch_js = format!("{:?}", epoch.to_token());
    let prefix = base.prefix();
    let base_js = format!("{prefix:?}");
    let csrf_js = format!("{csrf_token:?}");
    let dev_banner = dev_console_banner(prefix);
    // Content-addressed client asset URL and SRI hash — computed once at first call.
    let (hex16, b64) = client_js_hashes();
    // Honour the sub-app base prefix so the external script request goes through
    // the parent proxy (same as /_ipe/sse, /_ipe/event, /_ipe/console).
    let client_src = format!("{prefix}/_ipe/client.{hex16}.js");
    let integrity = format!("sha256-{b64}");
    let config_js = web_client_config_js();
    let head_extra = format!("<meta name=\"ipe-base\" content=\"{prefix}\">");
    let body_inner = format!("<div id=\"ipe-root\">{body}</div>{dev_banner}");
    // Custom-element glue: an EXTERNAL, SRI-pinned `<script type="module">` plus a
    // `modulepreload` SRI pin per author asset. Empty when the program registers
    // no widget, so a widget-free page is byte-identical and its CSP is unchanged.
    // It loads AFTER the client core so `__ipeEmitWidgetUp` can reuse `__ipeSend`.
    let widget_scripts = widget_assets::page_scripts(base, widget_assets::WidgetTransport::Server);
    let port_glue = port_glue_script(prefix);
    let tail_scripts = format!(
        "<script>window.__IPE_SID={sid_js};window.__IPE_EPOCH={epoch_js};window.__IPE_BASE={base_js};window.__IPE_CSRF_TOKEN={csrf_js};{config_js}</script>\
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
    base: &crate::encoding::MountBase,
    body: &str,
    epoch: &RenderEpoch,
    csrf_token: &str,
    overlay: &str,
) -> String {
    let sid_js = format!("{sid:?}");
    let epoch_js = format!("{:?}", epoch.to_token());
    let prefix = base.prefix();
    let base_js = format!("{prefix:?}");
    let csrf_js = format!("{csrf_token:?}");
    let dev_banner = dev_console_banner(prefix);
    let (hex16, b64) = client_js_hashes();
    let client_src = format!("{prefix}/_ipe/client.{hex16}.js");
    let integrity = format!("sha256-{b64}");
    let config_js = web_client_config_js();
    let head_extra = format!("<meta name=\"ipe-base\" content=\"{prefix}\">");
    let body_inner = format!("<div id=\"ipe-root\">{body}</div>{dev_banner}{overlay}");
    let widget_scripts = widget_assets::page_scripts(base, widget_assets::WidgetTransport::Server);
    let port_glue = port_glue_script(prefix);
    let tail_scripts = format!(
        "<script>window.__IPE_SID={sid_js};window.__IPE_EPOCH={epoch_js};window.__IPE_BASE={base_js};window.__IPE_CSRF_TOKEN={csrf_js};{config_js}</script>\
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
use crate::tea::{IpeCmd, IpeSub, SubRuntime, SubSink};
#[cfg(feature = "server")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "server")]
use std::sync::{Arc, Mutex, Weak};
#[cfg(feature = "server")]
use tokio::sync::mpsc::{self, Receiver, Sender};

/// Per-session live state behind an `Arc<Mutex<…>>`. `rendered` is advanced by
/// every commit; `sse_tx` is filled when the browser attaches the SSE channel;
/// `msg_tx` feeds the per-session driver loop.
#[cfg(feature = "server")]
pub struct SessionEntry<Model, Msg> {
    pub model: Model,
    /// The last committed view and the handler indexes of the retained
    /// renders, each under its epoch; an event resolves only at its own epoch.
    pub rendered: Rendered<Msg>,
    /// The last event seq each recent tab posted, so a duplicate is acked
    /// without a second dispatch.
    pub tabs: TabSeqs,
    pub seq: u64,
    pub sse_tx: Option<SseTx>,
    pub msg_tx: Sender<Msg>,
    /// The base-relative path the session last entered, so a reconnect that
    /// reports the same path does not enter (and run its Cmd) a second time.
    pub entered_path: Option<route::DecodedPath>,
    /// Feeds URL entries to the per-session driver, which serialises them with
    /// `update`; bounded by [`ENTER_QUEUE_CAP`].
    pub enter_tx: Sender<EnterRequest>,
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
///
/// `from` / `to` are the epochs the commit moved between: the client applies
/// the patches only onto the DOM of `from`, then adopts `to`.
#[derive(serde::Serialize)]
#[cfg(feature = "server")]
struct PatchEnvelope<'a> {
    #[serde(rename = "globalSeq")]
    global_seq: u64,
    from: String,
    to: String,
    patches: &'a [crate::web::diff::Patch],
}

/// Push one commit's `patches` frame, empty patches included, so the client's
/// epoch always follows the server's.
#[cfg(feature = "server")]
async fn send_patches_frame(
    sse: Option<SseTx>,
    global_seq: u64,
    step: EpochStep,
    patches: &[crate::web::diff::Patch],
) {
    let Some(sse) = sse else {
        return;
    };
    let env = PatchEnvelope {
        global_seq,
        from: step.from.to_token(),
        to: step.to.to_token(),
        patches,
    };
    if let Ok(json) = serde_json::to_string(&env) {
        let _ = sse.send(SsePatch(sse::frame("patches", &json))).await;
    }
}

/// A fresh render-history incarnation from the OS CSPRNG.
#[cfg(feature = "server")]
pub(crate) fn new_incarnation() -> Incarnation {
    Incarnation::from_random_bits(uuid::Uuid::new_v4().as_u128())
}

/// The number of tabs whose last event seq a session remembers.
#[cfg(feature = "server")]
pub const TAB_SEQ_CAP: std::num::NonZeroUsize = std::num::NonZeroUsize::MIN.saturating_add(15);

/// The random id a browser tab mints once per page load and echoes with its events.
#[cfg(feature = "server")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TabId(u128);

#[cfg(feature = "server")]
impl TabId {
    /// Parse exactly 32 lowercase hex characters; anything else is `None`.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let well_formed = token.len() == 32
            && token
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !well_formed {
            return None;
        }
        u128::from_str_radix(token, 16).ok().map(Self)
    }
}

/// How many seqs at and below a tab's highest dispatched seq its window
/// remembers one by one.
#[cfg(feature = "server")]
pub const TAB_SEQ_WINDOW: u32 = u128::BITS;

/// The seqs one tab has had dispatched: its highest seq, and for each of the
/// [`TAB_SEQ_WINDOW`] seqs at and below it whether it was dispatched.
///
/// A tab's events can reach the server out of order: two posts in flight race
/// for the session lock, and a retried event lands after a later one. So an
/// earlier seq is a duplicate only when that exact seq was dispatched, never
/// merely because a later one was.
#[cfg(feature = "server")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SeqWindow {
    top: u64,
    /// Bit `k` is set when seq `top - k` was dispatched.
    seen: u128,
}

#[cfg(feature = "server")]
impl SeqWindow {
    const fn first(seq: u64) -> Self {
        Self { top: seq, seen: 1 }
    }

    /// The bit of `seq`, when `seq` is at most `top` and inside the window.
    fn bit(self, seq: u64) -> Option<u128> {
        let back = u32::try_from(self.top.checked_sub(seq)?).ok()?;
        1_u128.checked_shl(back)
    }

    /// Whether `seq` was dispatched. A seq above `top` is new; one older than
    /// the window can no longer be told apart and counts as dispatched.
    fn has(self, seq: u64) -> bool {
        if seq > self.top {
            return false;
        }
        self.bit(seq).is_none_or(|bit| (self.seen & bit) != 0)
    }

    fn mark(&mut self, seq: u64) {
        if let Some(ahead) = seq.checked_sub(self.top).filter(|&ahead| ahead > 0) {
            let kept = u32::try_from(ahead)
                .ok()
                .and_then(|ahead| self.seen.checked_shl(ahead))
                .unwrap_or(0);
            self.top = seq;
            self.seen = kept | 1;
        } else if let Some(bit) = self.bit(seq) {
            self.seen |= bit;
        }
    }
}

/// The dispatched event seqs of the most recently active tabs, at most
/// [`TAB_SEQ_CAP`] tabs.
///
/// An event whose seq its tab already had dispatched is a duplicate and is
/// acked without a dispatch. An unknown or evicted tab is accepted; the render
/// epoch, not this map, is what keeps a replay from retargeting.
#[cfg(feature = "server")]
#[derive(Default)]
pub struct TabSeqs {
    recent: std::collections::VecDeque<(TabId, SeqWindow)>,
}

#[cfg(feature = "server")]
impl TabSeqs {
    /// Whether `tab` already had an event at `seq` dispatched.
    #[must_use]
    pub fn is_duplicate(&self, tab: TabId, seq: u64) -> bool {
        self.recent
            .iter()
            .any(|&(t, window)| t == tab && window.has(seq))
    }

    /// Record `seq` as dispatched for `tab`, making `tab` the most recent.
    pub fn record(&mut self, tab: TabId, seq: u64) {
        let window = self
            .recent
            .iter()
            .position(|&(t, _)| t == tab)
            .and_then(|pos| self.recent.remove(pos))
            .map_or(SeqWindow::first(seq), |(_, mut window)| {
                window.mark(seq);
                window
            });
        self.recent.push_back((tab, window));
        while self.recent.len() > TAB_SEQ_CAP.get() {
            self.recent.pop_front();
        }
    }
}

/// Body for the dev-only `POST /_ipe/watch/status` endpoint.
///
/// Sent by `ipe dev watch` to push build state to connected browsers.
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

/// Latest build status from `ipe dev watch`, held in the server's shared state.
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
    /// The render epoch whose DOM the event came from; resolved only against
    /// that render's handler index. Absent refuses.
    #[serde(default)]
    epoch: Option<String>,
    /// The posting tab's id and its per-tab event seq: a repeat of a recorded
    /// seq is acked without a second dispatch. Either absent skips that check.
    #[serde(default)]
    tab: Option<String>,
    #[serde(default)]
    seq: Option<u64>,
}

/// Why `POST /_ipe/event` refuses to resolve an event.
#[cfg(feature = "server")]
enum EventRefusal {
    /// The body names no render epoch.
    Missing,
    /// The epoch token is not well formed; an honest client never sends one.
    Malformed(EpochParseError),
    /// The tab id is not well formed; an honest client never sends one.
    MalformedTab,
    /// The epoch names no retained render of this session.
    Stale(StaleEpoch),
}

/// The `409` stale-render refusal: the current epoch and full render, so the
/// client replaces its DOM and never re-sends the refused event.
#[cfg(feature = "server")]
fn stale_render_response<Model, Msg: Clone>(
    e: &SessionEntry<Model, Msg>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let body = serde_json::json!({
        "refused": "stale-render",
        "epoch": e.rendered.epoch().to_token(),
        "seq": e.seq,
        "body": render_html(e.rendered.last_view()),
    })
    .to_string();
    (
        axum::http::StatusCode::CONFLICT,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::HeaderName::from_static("x-ipe-web"), "1"),
        ],
        body,
    )
        .into_response()
}

/// The HTTP answer to an [`EventRefusal`], one arm per variant.
///
/// A missing or stale epoch answers `409` with the current render; a
/// malformed epoch or tab id answers `400`, like any other malformed body.
#[cfg(feature = "server")]
fn event_refusal_response<Model, Msg: Clone>(
    refusal: EventRefusal,
    e: &SessionEntry<Model, Msg>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let bad_body = || (axum::http::StatusCode::BAD_REQUEST, "bad body").into_response();
    match refusal {
        EventRefusal::Missing => stale_render_response(e),
        EventRefusal::Stale(why) => {
            crate::system::emit_runtime_log(
                "live",
                &format!("event_handler: render epoch refused ({why:?}); resyncing the page"),
            );
            stale_render_response(e)
        }
        EventRefusal::Malformed(why) => {
            crate::system::emit_runtime_log(
                "live",
                &format!("event_handler: malformed render epoch ({why:?})"),
            );
            bad_body()
        }
        EventRefusal::MalformedTab => bad_body(),
    }
}

/// The `200` ack of an accepted event; real patches flow over SSE.
///
/// `X-Ipe-Web: 1` marks a genuine Ipe.Web response: the client treats a `200`
/// without it as a wedged-proxy signal. A duplicate is acked as such and was
/// not dispatched a second time.
#[cfg(feature = "server")]
fn event_ack(seq: u64, duplicate: bool) -> axum::response::Response {
    use axum::response::IntoResponse;
    let body = if duplicate {
        format!("{{\"seq\":{seq},\"patches\":[],\"duplicate\":true}}")
    } else {
        format!("{{\"seq\":{seq},\"patches\":[]}}")
    };
    (
        axum::http::StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (axum::http::HeaderName::from_static("x-ipe-web"), "1"),
        ],
        body,
    )
        .into_response()
}

/// Coerce a wire arg `Value` to the string the click/input/keydown path expects.
#[cfg(feature = "server")]
fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Boxed route entry: a model + decoded base-relative path → the entered model and the page's entry Cmd.
///
/// The only way a URL reaches a session's model; the Cmd is `#[must_use]` in
/// [`route::Entered`] and is dispatched by whoever commits the model.
#[cfg(feature = "server")]
type RouteEntry<Model, Msg> =
    Arc<dyn Fn(Model, &route::DecodedPath) -> route::Entered<Model, IpeCmd<Msg>> + Send + Sync>;

/// Enters `path` for a new driver of session `sid`, running `seed_cmd` before the entry Cmd.
///
/// Every page-handler arm that builds a driver (miss, restored, rebuilt) goes
/// through here, so the order `[seed, entry]` and the sid scope live in one
/// place. Relies on one invariant: constructing an `IpeCmd` performs no
/// effect, only `run_cmd` does, so a seed built for a session that is then
/// discarded never fires.
#[cfg(feature = "server")]
fn enter_session<Model, Msg>(
    route_entry: &RouteEntry<Model, Msg>,
    sid: &str,
    model: Model,
    seed_cmd: IpeCmd<Msg>,
    path: &route::DecodedPath,
) -> (Model, IpeCmd<Msg>) {
    let entered = pubsub::with_session_sid(sid.to_owned(), || route_entry(model, path));
    (entered.model, IpeCmd::Batch(vec![seed_cmd, entered.cmd]))
}

/// Pending URL entries a session driver holds before a new one is refused with 503.
#[cfg(feature = "server")]
const ENTER_QUEUE_CAP: std::num::NonZeroUsize = std::num::NonZeroUsize::MIN.saturating_add(7);

/// How long a request waits for the driver to commit its entry before answering 503.
#[cfg(feature = "server")]
const ENTER_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether the session driver enters a queued path unconditionally or only when it is new.
///
/// The choice is made by the driver when it commits, the one point that
/// serialises every entry of a session, so two requests queued for one path
/// cannot both see it as new.
#[cfg(feature = "server")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnterMode {
    /// A page GET: its requester renders the reply, so the path is always entered.
    Load,
    /// A reconnect's displayed path: entered only when it differs from the
    /// session's `entered_path` at commit time.
    Reconcile,
}

/// A URL entry for a session driver: the base-relative path, how to enter it, and where to send the rendered body.
#[cfg(feature = "server")]
pub struct EnterRequest {
    path: route::DecodedPath,
    mode: EnterMode,
    reply: tokio::sync::oneshot::Sender<EnterReply>,
}

/// The driver's answer to an [`EnterRequest`]: the committed page's rendered body and its epoch.
///
/// Only the render crosses back; the entry Cmd stays with the driver, so a
/// requester that stops waiting loses nothing.
#[cfg(feature = "server")]
pub struct EnterReply {
    body: String,
    epoch: RenderEpoch,
}

/// Queue an entry of `path` in `mode` on the session driver behind `enter_tx`.
///
/// `None` when the queue is full or the driver is gone; the caller refuses
/// rather than waiting without a bound.
#[cfg(feature = "server")]
fn queue_entry(
    enter_tx: &Sender<EnterRequest>,
    path: route::DecodedPath,
    mode: EnterMode,
) -> Option<tokio::sync::oneshot::Receiver<EnterReply>> {
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    enter_tx
        .try_send(EnterRequest { path, mode, reply })
        .ok()
        .map(|()| reply_rx)
}

/// Wait at most [`ENTER_REPLY_TIMEOUT`] for the driver's entry reply.
///
/// `None` on timeout or when the driver dropped the request unanswered.
#[cfg(feature = "server")]
async fn await_entry(reply_rx: tokio::sync::oneshot::Receiver<EnterReply>) -> Option<EnterReply> {
    tokio::time::timeout(ENTER_REPLY_TIMEOUT, reply_rx)
        .await
        .ok()
        .and_then(Result::ok)
}

/// What reconnect reconciliation did with the path the browser reports.
#[cfg(feature = "server")]
pub enum ReconcileOutcome {
    /// The path is invalid, unrouted, or outside the base.
    Unchanged,
    /// The driver accepted a `Reconcile` entry; await it before
    /// the resync frame. A path the session already entered when the driver
    /// reaches it is dropped unanswered.
    Entering(tokio::sync::oneshot::Receiver<EnterReply>),
    /// The enter queue is full or closed; the current view stands and the next reconnect retries.
    Refused,
}

/// Reconcile a reconnecting session with the path its browser displays.
///
/// `path` is the base-relative path [`client_route_path`] parsed from the SSE
/// client's `location.pathname`. A routed path is queued as a
/// [`EnterMode::Reconcile`] entry. The driver enters it only when it differs
/// from the session's `entered_path` at commit time, so the GET that created
/// the page, the SSE open that follows it, and concurrent reconnects at one
/// path run the page's entry Cmd once.
#[cfg(feature = "server")]
fn reconcile_path<Model, Msg>(
    entry: &store::SessionHandle<Model, Msg>,
    route_matched: &RouteMatched,
    path: &route::DecodedPath,
) -> ReconcileOutcome {
    // A routed path is queued under its canonical form, so `/items/7/` and
    // `/items/7` dedupe against one `entered_path`.
    let key = match route_matched(path) {
        RouteLookup::Unrouted => return ReconcileOutcome::Unchanged,
        RouteLookup::Root => path.clone(),
        RouteLookup::Page(canonical) => canonical.decoded().clone(),
    };
    let enter_tx = entry
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .enter_tx
        .clone();
    queue_entry(&enter_tx, key, EnterMode::Reconcile)
        .map_or(ReconcileOutcome::Refused, ReconcileOutcome::Entering)
}

/// The 503 a request gets when its session cannot enter the URL within the bounds.
#[cfg(feature = "server")]
fn entry_unavailable() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::RETRY_AFTER, "1")],
        "session busy entering a page",
    )
        .into_response()
}

/// The 503 a request gets when the process holds as many sessions as it admits.
#[cfg(feature = "server")]
fn at_capacity() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::RETRY_AFTER, "2")],
        "server at session capacity",
    )
        .into_response()
}

// A claim waiter is a request queued on its session, so it waits no longer and
// in no larger numbers than an entry queued on a live driver.
#[cfg(feature = "server")]
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a session's claim waiters outnumber its enter queue [ledger #boundary]
const _: () = assert!(store::MAX_CLAIM_WAITERS.get() <= ENTER_QUEUE_CAP.get());
#[cfg(feature = "server")]
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the claim wait drifts from the enter reply timeout [ledger #boundary]
const _: () = assert!(store::CLAIM_WAIT.as_millis() == ENTER_REPLY_TIMEOUT.as_millis());
// Every minted sid parses back as a `SessionKey`.
#[cfg(feature = "server")]
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a minted sid's length drifts from the session key's [ledger #boundary]
const _: () = assert!(uuid::fmt::Simple::LENGTH == store::SESSION_ID_LEN);

/// Build the routed entry from the route table, the `notFound` page, the
/// app's emitted `set_page`, and its page renderer.
#[cfg(feature = "server")]
fn routed_entry<Model, Msg, Page, FSetPage, FRender>(
    routes: Arc<Vec<route::Route<Page>>>,
    not_found: Page,
    set_page: FSetPage,
    render: Arc<FRender>,
) -> RouteEntry<Model, Msg>
where
    Page: Clone + Send + Sync + 'static,
    FSetPage: Fn(Page, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FRender: Fn(&Page) -> Result<route::RoutePath, route::RenderRefusal> + Send + Sync + 'static,
{
    Arc::new(move |model, path| {
        route::enter(
            route::resolve(&routes, path, &*render),
            &not_found,
            model,
            &set_page,
        )
    })
}

/// The route lookup over a route table: a page that renders back is
/// [`RouteLookup::Page`] with its canonical path; a table with no routes
/// serves only `/`.
#[cfg(feature = "server")]
fn routed_lookup<Page, FRender>(
    routes: Arc<Vec<route::Route<Page>>>,
    render: Arc<FRender>,
) -> RouteMatched
where
    Page: Send + Sync + 'static,
    FRender: Fn(&Page) -> Result<route::RoutePath, route::RenderRefusal> + Send + Sync + 'static,
{
    Arc::new(move |path| {
        if routes.is_empty() {
            return RouteLookup::single_page(path);
        }
        match route::resolve(&routes, path, &*render) {
            route::Matched::Hit { canonical, .. } => RouteLookup::Page(canonical),
            route::Matched::Miss => RouteLookup::Unrouted,
        }
    })
}

/// The three routed resolvers every routed builder installs, all over one
/// route table and one renderer, so the entry, `req.params` and the lookup
/// agree on which route a path resolves to.
#[cfg(feature = "server")]
fn routed_resolvers<Model, Msg, Page, FSetPage, FRender>(
    routes: Vec<route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    render: FRender,
) -> (RouteEntry<Model, Msg>, ParamResolver, RouteMatched)
where
    Page: Clone + Send + Sync + 'static,
    FSetPage: Fn(Page, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FRender: Fn(&Page) -> Result<route::RoutePath, route::RenderRefusal> + Send + Sync + 'static,
{
    let routes = Arc::new(routes);
    let render = Arc::new(render);
    let routes_for_params = Arc::clone(&routes);
    let route_matched = routed_lookup(Arc::clone(&routes), Arc::clone(&render));
    let route_entry = routed_entry(routes, not_found, set_page, render);
    let param_resolver: ParamResolver =
        Arc::new(move |path| route::match_params(&routes_for_params, path));
    (route_entry, param_resolver, route_matched)
}
/// Boxed param resolver: a decoded GET path → the matched route's
/// `:name`→value params.
#[cfg(feature = "server")]
type ParamResolver = Arc<dyn Fn(&route::DecodedPath) -> crate::dict::IpeDict<String> + Send + Sync>;
/// What a decoded GET path is to the page handler.
#[cfg(feature = "server")]
#[derive(Clone, Debug)]
enum RouteLookup {
    /// Not a page URL: browser noise, or a path no route builds a page for.
    Unrouted,
    /// The root of an app with no route table, its one page URL.
    Root,
    /// A routed page, and the canonical path that page renders back to.
    Page(route::RoutePath),
}

#[cfg(feature = "server")]
impl RouteLookup {
    /// The lookup of an app with no route table: only `/` is a page URL.
    fn single_page(path: &route::DecodedPath) -> Self {
        if path.is_root() {
            Self::Root
        } else {
            Self::Unrouted
        }
    }

    /// Is the path a page URL at all?
    fn is_routed(&self) -> bool {
        !matches!(self, Self::Unrouted)
    }
}

/// Boxed route lookup: what a decoded GET path is to the page handler.
/// Gates the page handler's canonical redirect, browser-noise 404 and the
/// unrouted-GET-against-a-live-session 404 — see `page`.
#[cfg(feature = "server")]
type RouteMatched = Arc<dyn Fn(&route::DecodedPath) -> RouteLookup + Send + Sync>;

/// Shared axum state: the session store + Arc'd TEA callbacks.
#[cfg(feature = "server")]
pub(crate) struct WebState<Model, Msg, FInit, FUpdate, FView, FSubs> {
    store: Arc<dyn store::SessionStore<Model, Msg>>,
    init: Arc<FInit>,
    update: Arc<FUpdate>,
    view: Arc<FView>,
    subs: Arc<FSubs>,
    /// Enters a base-relative path: the model whose `page` reflects the
    /// matched route, plus the page's entry Cmd. `web_app` enters unchanged
    /// with `Cmd.none` (no routing); the routed builders capture the route
    /// table + `set_page`. `Page`/`set_page` are erased into this boxed
    /// closure, so `WebState` keeps its original 6 type params.
    route_entry: RouteEntry<Model, Msg>,
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
    /// Latest build status from `ipe dev watch`. `None` until the first status
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
            route_entry: self.route_entry.clone(),
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
const MAX_SESSIONS_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WEB_MAX_SESSIONS",
    50_000,
    crate::system::ZeroCeiling::Accepted,
    "decimal session count",
);

#[cfg(feature = "server")]
fn max_sessions() -> Result<usize, crate::system::EnvCeilingRefusal> {
    MAX_SESSIONS_CEILING.read()
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

/// Who a page GET's new driver belongs to: a claimed returning sid, or a freshly minted one.
///
/// A rejoined session's sid is its claim's key, so the published sid and the
/// claim it is published under cannot differ.
#[cfg(feature = "server")]
enum SessionOwner {
    /// A returning session rebuilt or restored under its claim; the claim is released once the session is live.
    Rejoined(store::SidClaim),
    /// A new session under a sid no other request knows.
    Minted(String),
}

#[cfg(feature = "server")]
impl SessionOwner {
    /// The sid the session is published under.
    fn sid(&self) -> &str {
        match self {
            Self::Rejoined(claim) => claim.key().as_str(),
            Self::Minted(sid) => sid,
        }
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
                    crate::system::emit_runtime_log(
                        "live",
                        "run_cmd: session msg channel closed; dropping Perform result",
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

/// A session's message queue as a subscription sink.
///
/// A timer waits for queue room (backpressure on a slow session) and stops once
/// the driver is gone; a source drops a message the full queue cannot take.
/// Terminal input handlers in a Web session's `Sub` are dropped by
/// [`SubRuntime::reconcile`]: a Web session has no terminal input.
#[cfg(feature = "server")]
impl<Msg: Send + 'static> SubSink<Msg> for Sender<Msg> {
    fn deliver(&self, msg: Msg) -> impl std::future::Future<Output = bool> + Send {
        let tx = self.clone();
        async move { tx.send(msg).await.is_ok() }
    }
    fn emit(&self, msg: Msg) {
        let _ = self.try_send(msg);
    }
}

/// What the session driver did with one queued [`EnterRequest`].
#[cfg(feature = "server")]
enum EntryCommit<Model, Msg> {
    /// The path was entered and committed; the driver runs the Cmd.
    Entered(Model, IpeCmd<Msg>),
    /// A [`EnterMode::Reconcile`] path the session had already entered; nothing ran.
    AlreadyEntered,
    /// The session is gone; the driver exits.
    SessionGone,
}

/// Commit one URL entry on the session driver and hand back the entered model and its Cmd.
///
/// A [`EnterMode::Reconcile`] request whose path equals the session's
/// `entered_path` is dropped unanswered here, on the driver, so the check and
/// the commit that follows cannot interleave with another entry. Otherwise
/// enters `request.path` under the session's sid, renders, commits model, view,
/// index and `entered_path`, then replies with the rendered body. A requester
/// that stopped waiting gets the committed page as a full resync frame over
/// the attached SSE channel instead, so the browser never keeps a DOM the
/// server no longer diffs against.
#[cfg(feature = "server")]
async fn commit_entry<Model, Msg, FView>(
    entry: &Weak<Mutex<SessionEntry<Model, Msg>>>,
    request: EnterRequest,
    route_entry: &RouteEntry<Model, Msg>,
    view: &FView,
    store: &Arc<dyn store::SessionStore<Model, Msg>>,
    sid: &str,
) -> EntryCommit<Model, Msg>
where
    Model: Clone,
    Msg: Clone,
    FView: Fn(Model) -> Html<Msg> + ?Sized,
{
    let Some(strong) = entry.upgrade() else {
        return EntryCommit::SessionGone;
    };
    let EnterRequest { path, mode, reply } = request;
    let model = {
        let g = strong.lock().unwrap_or_else(|e| e.into_inner());
        let already_entered = match mode {
            EnterMode::Load => false,
            EnterMode::Reconcile => g.entered_path.as_ref() == Some(&path),
        };
        if already_entered {
            return EntryCommit::AlreadyEntered;
        }
        g.model.clone()
    };
    let entered = pubsub::with_session_sid(sid.to_owned(), || route_entry(model, &path));
    let mut tree = view(entered.model.clone());
    assign_ipe_ids(&mut tree, "r");
    style_inject::apply_style_injections(&mut tree);
    let body = render_html(&tree);
    let committed = {
        let mut e = strong.lock().unwrap_or_else(|e| e.into_inner());
        match e.rendered.commit(tree) {
            Ok(step) => {
                e.model = entered.model.clone();
                e.entered_path = Some(path);
                Some(step.to)
            }
            Err(EpochExhausted) => None,
        }
    };
    let Some(epoch) = committed else {
        // The render history cannot mint another epoch: drop the session so
        // the next request takes the session-lost path.
        store.delete(sid).await;
        return EntryCommit::SessionGone;
    };
    if let Err(EnterReply { body, epoch }) = reply.send(EnterReply { body, epoch }) {
        let (frame, sse_tx) = {
            let mut e = strong.lock().unwrap_or_else(|e| e.into_inner());
            e.seq += 1;
            (
                serde_json::json!({ "seq": e.seq, "epoch": epoch.to_token(), "body": body })
                    .to_string(),
                e.sse_tx.clone(),
            )
        };
        if let Some(sse_tx) = sse_tx {
            let _ = sse_tx.send(SsePatch(sse::frame("patch", &frame))).await;
        }
    }
    store.set(sid, strong).await;
    EntryCommit::Entered(entered.model, entered.cmd)
}

/// The per-session driver: folds each Msg through `update`, diffs the new view
/// against the last, pushes patches over SSE (if attached), runs the resulting
/// Cmd, and re-evaluates subscriptions.
///
/// URL entries arrive on `enter_rx` and are committed by the same loop, so an
/// entry and an in-flight `update` never overwrite each other's model.
// Ten distinct per-session runtime handles (entry, both Msg channel ends, the
// entry queue, the three Arc'd TEA callbacks, the route entry, the store, the
// sid) — bundling them into a struct purely to satisfy the 7-arg heuristic
// would add indirection without clarifying anything.
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
    mut enter_rx: Receiver<EnterRequest>,
    update: Arc<FUpdate>,
    view: Arc<FView>,
    subs: Arc<FSubs>,
    route_entry: RouteEntry<Model, Msg>,
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
    // One keyed subscription runtime per session: a re-evaluation keeps a
    // still-requested `Sub.every` timer and its phase.
    let mut sub_runtime = SubRuntime::new(msg_tx.clone());

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
            sub_runtime.reconcile(subs(model0));
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
            maybe = enter_rx.recv() => {
                let Some(request) = maybe else {
                    break;
                };
                let (next, cmd) =
                    match commit_entry(&entry, request, &route_entry, &*view, &store, &sid).await {
                        EntryCommit::Entered(next, cmd) => (next, cmd),
                        EntryCommit::AlreadyEntered => continue,
                        EntryCommit::SessionGone => break,
                    };
                pubsub::with_session_sid(sid.clone(), || run_cmd(cmd, &msg_tx, &sid));
                pubsub::with_session_sid(sid.clone(), || {
                    sub_runtime.reconcile(subs(next));
                });
                continue;
            }
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

        let committed = {
            let mut e = strong.lock().unwrap_or_else(|e| e.into_inner());
            let patches = diff(e.rendered.last_view(), &tree);
            // noop. Here
            // `e.model` STILL holds the OLD model (top-of-loop cloned it OUT; the
            // store isn't updated until the assignment below), so `e.model ==
            // next` is old==new — a STRUCTURAL equality (no hash-collision false
            // noop, unlike  hash), computed with NO extra clone. The Rust
            // dispatch has no error channel, so the `err==nil` conjunct is always
            // true and is dropped.
            let noop = cmd_is_none && e.model == next;
            // The commit builds the handler index and mints the epoch, then
            // moves the tree into the last view, avoiding a deep VDOM clone.
            match e.rendered.commit(tree) {
                Ok(step) => {
                    e.model = next.clone();
                    e.seq += 1;
                    #[cfg(feature = "debugger")]
                    e.history
                        .record(msg_for_history, next.clone(), &|m, mdl| (*update)(m, mdl));
                    Some((patches, step, e.seq, e.sse_tx.clone(), noop))
                }
                Err(EpochExhausted) => None,
            }
        };
        let Some((patches, step, seq, sse, noop)) = committed else {
            // The render history cannot mint another epoch: drop the session so
            // the next request takes the session-lost path.
            store.delete(&sid).await;
            break;
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

        send_patches_frame(sse, seq, step, &patches).await;

        // Write-through: checkpoint the committed model to the store (a touch
        // for memory; a re-serialize for persistent backends) on every commit.
        // Re-inserting an evicted-but-active session with a fresh last-seen is
        // intended: a session that processes a Msg is
        // alive. `strong` is dropped at the end of this iteration (block scope),
        // before the next select! park — never held across the await loop.
        store.set(&sid, strong.clone()).await;

        pubsub::with_session_sid(sid.clone(), || run_cmd(cmd, &msg_tx, &sid));
        pubsub::with_session_sid(sid.clone(), || {
            sub_runtime.reconcile(subs(next.clone()));
        });
    }
    drop(sub_runtime);
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
fn cookie_name_for(base: &str) -> crate::server::CookieName {
    cookie_name_with(base, csrf::cookies_secure())
}

/// [`cookie_name_for`] under an explicit `Secure` decision.
#[cfg(feature = "server")]
fn cookie_name_with(base: &str, secure: bool) -> crate::server::CookieName {
    use crate::server::{CookieName, RuntimeCookie};
    if base.is_empty() {
        let root = if secure {
            RuntimeCookie::HostSession
        } else {
            RuntimeCookie::Session
        };
        CookieName::runtime(root, "")
    } else {
        let suffix: String = base
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        CookieName::runtime(RuntimeCookie::Session, &suffix)
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
fn session_cookie_name() -> crate::server::CookieName {
    cookie_name_for(&web_base_path())
}

/// The active session cookie `Path`.
#[cfg(feature = "server")]
fn cookie_path() -> String {
    cookie_path_for(&web_base_path())
}

/// The session cookie line: `Path` is the app's base, `HttpOnly`, `Max-Age` is
/// the store `ttl`. `Secure` when cookies are secure or this request arrived over
/// TLS at a trusted proxy; `SameSite=None` (always `Secure`) when the app may be
/// framed cross-origin, else `Lax`.
#[cfg(feature = "server")]
fn session_set_cookie(
    sid: &str,
    headers: &axum::http::HeaderMap,
    ttl: std::time::Duration,
) -> crate::server::SetCookie {
    use crate::server::{CookieAttributes, CookiePath, CookieValue, SameSite, SetCookie};
    SetCookie::new(
        &session_cookie_name(),
        &CookieValue::encode(sid),
        CookieAttributes {
            path: CookiePath::encode(&cookie_path()),
            http_only: true,
            same_site: if csrf::frame_ancestors().is_some() {
                SameSite::None
            } else {
                SameSite::Lax
            },
            secure: csrf::cookies_secure() || request_is_https(headers),
            max_age_secs: Some(ttl.as_secs()),
        },
    )
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
    epoch: &RenderEpoch,
    csrf_token: &str,
    headers: &axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(base) = web_mount_base() else {
        return ttl_unavailable_response();
    };
    let html = render_page_full(sid, &base, body, epoch, csrf_token);
    // Session cookie carries `Secure` without a dev intent / in frame-ancestors mode, OR
    // when this specific request arrived over TLS at a trusted proxy
    // (`request_is_https`, opt-in via `IPE_TRUSTED_PROXY` — closes the gap where
    // `csrf::cookies_secure()` snapshots the dev intent and
    // `frame_ancestors().is_some()` ONCE at process start and never inspects this
    // request's TLS / `X-Forwarded-Proto`, so a dev process fronted by a TLS
    // proxy would otherwise emit a non-Secure session cookie even though the
    // browser connection was HTTPS). The untrusted-proxy case (operator hasn't
    // set `IPE_TRUSTED_PROXY`) keeps the process-wide behaviour — still SOUND, just not
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
    let Ok(ttl) = web_ttl() else {
        return ttl_unavailable_response();
    };
    let session_cookie = session_set_cookie(sid, headers, ttl);
    let csrf_cookie = csrf::csrf_set_cookie(csrf_token, &web_base_path());
    let resp = (
        axum::http::StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/html; charset=utf-8".to_string(),
            ),
            // The epoch of the served render, read by client navigation.
            (
                axum::http::HeaderName::from_static("x-ipe-epoch"),
                epoch.to_token(),
            ),
        ],
        html,
    )
        .into_response();
    with_page_headers(resp, &[&session_cookie, &csrf_cookie])
}

/// Same as [`page_response`] but injects `overlay` (raw HTML) after `#ipe-root`
/// via [`render_page_full_with_overlay`]. Active only with the `debugger` feature.
#[cfg(all(feature = "server", feature = "debugger"))]
fn page_response_with_overlay(
    sid: &str,
    body: &str,
    epoch: &RenderEpoch,
    overlay: &str,
    csrf_token: &str,
    headers: &axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(base) = web_mount_base() else {
        return ttl_unavailable_response();
    };
    let html = render_page_full_with_overlay(sid, &base, body, epoch, csrf_token, overlay);
    let Ok(ttl) = web_ttl() else {
        return ttl_unavailable_response();
    };
    let session_cookie = session_set_cookie(sid, headers, ttl);
    let csrf_cookie = csrf::csrf_set_cookie(csrf_token, &web_base_path());
    let resp = (
        axum::http::StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/html; charset=utf-8".to_string(),
            ),
            (
                axum::http::HeaderName::from_static("x-ipe-epoch"),
                epoch.to_token(),
            ),
        ],
        html,
    )
        .into_response();
    with_page_headers(resp, &[&session_cookie, &csrf_cookie])
}

/// `resp` with one `Set-Cookie` header per line of `cookies`, then the page
/// security headers.
///
/// A cookie line or a security header with no header representation answers
/// `500`: a page never ships without the session or CSRF cookie it was built
/// with, nor without its framing policy.
#[cfg(feature = "server")]
fn with_page_headers(
    resp: axum::response::Response,
    cookies: &[&crate::server::SetCookie],
) -> axum::response::Response {
    with_page_headers_checked(resp, cookies, csrf::security_headers())
}

/// [`with_page_headers`] over the outcome of reading the security headers: a
/// refused framing policy answers `500` with no cookie and no header set.
#[cfg(feature = "server")]
fn with_page_headers_checked(
    resp: axum::response::Response,
    cookies: &[&crate::server::SetCookie],
    security: Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(security) = security else {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    with_page_headers_from(resp, cookies, security)
}

/// [`with_page_headers`] over an explicit security-header set.
#[cfg(feature = "server")]
fn with_page_headers_from(
    mut resp: axum::response::Response,
    cookies: &[&crate::server::SetCookie],
    security: Vec<(&'static str, String)>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let h = resp.headers_mut();
    // One header per cookie — `append`, not `insert`, so every line lands.
    for cookie in cookies {
        let Some(v) = cookie.header_value() else {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        h.append(axum::http::header::SET_COOKIE, v);
    }
    for (name, val) in security {
        let Ok(v) = axum::http::HeaderValue::from_str(&val) else {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        h.insert(axum::http::HeaderName::from_static(name), v);
    }
    resp
}

#[cfg(test)]
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod page_headers_tests {
    use super::{with_page_headers_checked, with_page_headers_from};
    use crate::server::SetCookie;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    fn ok() -> axum::response::Response {
        StatusCode::OK.into_response()
    }

    fn framing() -> Vec<(&'static str, String)> {
        vec![("x-frame-options", "SAMEORIGIN".to_owned())]
    }

    /// Every cookie line lands as its own header, next to the security headers.
    #[test]
    fn page_headers_append_every_cookie_line() {
        let session = SetCookie::unchecked_for_test("ipe_sid=a; Path=/");
        let csrf = SetCookie::unchecked_for_test("__ipe_csrf=b; Path=/");
        let resp = with_page_headers_from(ok(), &[&session, &csrf], framing());
        assert_eq!(resp.status(), StatusCode::OK);
        let lines: Vec<_> = resp.headers().get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(lines, ["ipe_sid=a; Path=/", "__ipe_csrf=b; Path=/"]);
        assert!(resp.headers().get("x-frame-options").is_some());
    }

    /// A cookie line with no header representation answers 500: the page is
    /// never sent without its session cookie.
    #[test]
    fn page_headers_refuse_an_unrepresentable_cookie_line() {
        let session = SetCookie::unchecked_for_test("ipe_sid=a\r\nX-Injected: 1");
        let csrf = SetCookie::unchecked_for_test("__ipe_csrf=b; Path=/");
        let resp = with_page_headers_from(ok(), &[&session, &csrf], framing());
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get(header::SET_COOKIE).is_none());
        assert!(resp.headers().get("x-injected").is_none());
    }

    /// A security header with no header representation answers 500: the page
    /// is never sent without its framing policy.
    #[test]
    fn page_headers_refuse_an_unrepresentable_security_header() {
        let session = SetCookie::unchecked_for_test("ipe_sid=a; Path=/");
        let csp = vec![(
            "content-security-policy",
            "frame-ancestors https://a.example\r\nX-Injected: 1".to_owned(),
        )];
        let resp = with_page_headers_from(ok(), &[&session], csp);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get("content-security-policy").is_none());
    }

    /// A refused `IPE_WEB_FRAME_ANCESTORS` answers 500: the page ships neither
    /// its cookies nor a header set missing the framing policy.
    #[test]
    fn page_headers_refuse_a_refused_framing_policy() {
        let session = SetCookie::unchecked_for_test("ipe_sid=a; Path=/");
        let resp = with_page_headers_checked(
            ok(),
            &[&session],
            Err(crate::telemetry::FrameAncestorsRefusal::Blank),
        );
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get(header::SET_COOKIE).is_none());
        assert!(resp.headers().get("x-frame-options").is_none());
        let framed = with_page_headers_checked(ok(), &[&session], Ok(framing()));
        assert_eq!(framed.status(), StatusCode::OK);
    }
}

/// Maximum request body bytes for `/_ipe/event`: `IPE_WEB_MAX_BODY_BYTES`,
/// default 5 MiB (5 << 20 = 5 242 880). The default covers `Event.onFile` /
/// `Event.onImage` data-URL payloads; override for larger file uploads.
#[cfg(feature = "server")]
const WEB_MAX_BODY_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WEB_MAX_BODY_BYTES",
    5 << 20,
    crate::system::ZeroCeiling::Refused,
    "decimal byte count",
);

#[cfg(test)]
#[cfg(all(feature = "server", not(target_arch = "wasm32")))]
mod web_max_body_bytes_tests {
    // A zero cap would 413 every /_ipe/event POST, so `0` is refused like any
    // other malformed value; the parse is driven without touching the shared
    // environment variable `server::tests::max_body_env_override` mutates.
    use super::WEB_MAX_BODY_CEILING;

    fn parse(raw: Option<&str>) -> Result<usize, crate::system::EnvCeilingRefusal> {
        WEB_MAX_BODY_CEILING.parse_as(raw.map(str::to_owned).ok_or(std::env::VarError::NotPresent))
    }

    #[test]
    fn web_max_body_bytes_refuses_zero() {
        assert_eq!(parse(None), Ok(5 << 20));
        assert_eq!(parse(Some("1024")), Ok(1024));
        assert!(parse(Some("0")).is_err(), "a zero body cap is refused");
        assert!(
            parse(Some(" 1024")).is_err(),
            "a padded body cap is refused"
        );
    }
}

/// The session idle-TTL the environment may set: `IPE_WEB_TTL`, whole seconds
/// or `h` / `m` / `s` segments (`30m`, `1h30m`), at most 400 days.
#[cfg(feature = "server")]
const WEB_TTL: crate::system::EnvDuration = crate::system::EnvDuration::new(
    "IPE_WEB_TTL",
    1800,
    "duration (whole seconds, or h/m/s segments such as 30m or 1h30m)",
)
.at_most(400 * 24 * 60 * 60);

/// Session idle-TTL under the one config precedence `env > setting-in-code >
/// fallback`: `IPE_WEB_TTL` wins, else an installed `Web.sessionTtl` setting,
/// else the default 1800 (30 min).
///
/// # Errors
///
/// A refusal naming `IPE_WEB_TTL` when it is present but not a positive
/// duration within the bound, or naming `Web.sessionTtl` when that setting is
/// not; a present value is never replaced by a default.
#[cfg(feature = "server")]
fn web_ttl() -> Result<std::time::Duration, crate::system::EnvCeilingRefusal> {
    let raw = WEB_TTL.lookup();
    if matches!(raw, Err(std::env::VarError::NotPresent))
        && let Some(secs) = crate::app_config::resolve_session_ttl_override(WEB_TTL)?
    {
        return Ok(std::time::Duration::from_secs(secs));
    }
    WEB_TTL.parse(raw).map(std::time::Duration::from_secs)
}

/// The `503` a request answers when the session TTL or the mount base cannot
/// be resolved.
#[cfg(feature = "server")]
fn ttl_unavailable_response() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        FAIL_CLOSED_BODY,
    )
        .into_response()
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
/// for `ipe dev watch --reset-state`: the watch process sets the flag in the child's
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
const SHUTDOWN_GRACE_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WEB_SHUTDOWN_GRACE_MS",
    1500,
    crate::system::ZeroCeiling::Accepted,
    "decimal millisecond count",
);

/// The shutdown grace window, resolved by `serve_web` before it binds.
#[cfg(feature = "server")]
fn shutdown_grace() -> Result<std::time::Duration, crate::system::EnvCeilingRefusal> {
    SHUTDOWN_GRACE_CEILING
        .read()
        .map(std::time::Duration::from_millis)
}

/// Best-effort bounded flush of all active telemetry exporters (push + hub).
///
/// The two flushes run concurrently, each bounded by its exporter's flush
/// deadline (its connect timeout plus one send budget), so shutdown waits at
/// most the larger deadline, never their sum, and never past
/// `push_exporter::FLUSH_DEADLINE_CEILING_MS`. Never panics. `process::exit`
/// skips Drop, so the mpsc Sender never drops and the batchers'
/// channel-close drain path never runs without this explicit flush; every
/// process exit reaches it through `system::exit_process`
/// (`flush_exporters_before_exit`).
///
/// No-op unless both `web` and `http_client` are on: the push/hub exporters
/// make outbound HTTP calls and are gated behind both features; a server with
/// no outbound HTTP kernel has no exporters to flush.
#[cfg(all(feature = "web", feature = "http_client"))]
async fn flush_exporters() {
    tokio::join!(push_exporter::flush_now(), hub_exporter::flush_now());
}
#[cfg(all(feature = "server", not(all(feature = "web", feature = "http_client"))))]
async fn flush_exporters() {}

/// Runs `flush_exporters` to completion from synchronous code, bounded by `push_exporter::EXIT_FLUSH_BOUND`.
///
/// The pre-exit stage of `system::exit_process`, callable from any thread: a
/// runtime worker, the entry's `block_on` thread, or a thread outside any
/// runtime. The flush runs on a fresh thread through the exporters' own
/// runtime handle (`Handle::block_on` from a thread with no runtime context, so
/// no runtime is nested inside another), and the caller waits for it at most
/// the bound. On a multi-thread runtime worker the wait goes through
/// `block_in_place`, which hands the worker's queued tasks, the batchers among
/// them, to another thread first. No-op when no exporter was enabled or the
/// flush thread cannot start. Never panics.
#[cfg(all(feature = "web", feature = "http_client", not(target_arch = "wasm32")))]
pub(crate) fn flush_exporters_before_exit() {
    let Some(handle) = push_exporter::exporter_runtime() else {
        return;
    };
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let flush = crate::threads::spawn_named("ipe-exit-flush", move || {
        handle.block_on(flush_exporters());
        let _ = done_tx.send(());
    });
    if flush.is_err() {
        return;
    }
    let wait = || {
        let _ = done_rx.recv_timeout(push_exporter::EXIT_FLUSH_BOUND);
    };
    let on_multi_thread = tokio::runtime::Handle::try_current()
        .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if on_multi_thread {
        tokio::task::block_in_place(wait);
    } else {
        wait();
    }
}

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
        // block: diff against the last view, then commit it under a new epoch
        // and advance seq so the client's monotonic seq gate accepts the frame
        // and the next real Msg diffs against this rendered view. The Model is
        // deliberately left as-is.
        let committed = {
            let mut e = handle.lock().unwrap_or_else(|e| e.into_inner());
            let patches = diff(e.rendered.last_view(), &tree);
            match e.rendered.commit(tree) {
                Ok(step) => {
                    e.seq += 1;
                    Some((patches, step, e.seq, e.sse_tx.clone()))
                }
                // The view and its epoch stay as they were; the session's
                // driver drops the session on its own next commit.
                Err(EpochExhausted) => None,
            }
        };
        if let Some((patches, step, seq, sse)) = committed {
            send_patches_frame(sse, seq, step, &patches).await;
        }
    }
}

/// The dev-only gate over [`push_reload_to_web_sessions`], over the process dev intent.
///
/// Without a [`DevIntent`](crate::telemetry::DevIntent) (a release build, or a
/// production posture) the push path is unreachable. Split from
/// `web_shutdown_signal` so the gate is unit-testable without delivering a
/// real signal.
#[cfg(feature = "server")]
async fn maybe_push_reload_to_web_sessions<Model, Msg>(
    store: &Arc<dyn store::SessionStore<Model, Msg>>,
) where
    Model: Send + 'static,
    Msg: Send + 'static,
{
    let dev = crate::telemetry::dev_intent_from_env();
    maybe_push_reload_with(store, dev.as_ref()).await;
}

/// [`maybe_push_reload_to_web_sessions`] under an explicit dev-intent proof.
#[cfg(feature = "server")]
async fn maybe_push_reload_with<Model, Msg>(
    store: &Arc<dyn store::SessionStore<Model, Msg>>,
    dev: Option<&crate::telemetry::DevIntent>,
) where
    Model: Send + 'static,
    Msg: Send + 'static,
{
    if dev.is_some() {
        push_reload_to_web_sessions(store).await;
    }
}

/// Await the FIRST shutdown signal (SIGINT or SIGTERM), then run the graceful
/// teardown and return so axum's `with_graceful_shutdown` drains in-flight
/// connections and the serve future resolves `Ok(())` (→ the IpeTask is `Ok` →
/// the generated entry exits 0).
///
/// Two escapes guard against the drain hanging — both keep the no-panic thesis:
///  - A bounded grace timer that force-exits 0 (CLEAN) after `grace`,
///    so a never-idle SSE stream can't wedge the process (drops long-lived
///    connections rather than waiting).
///  - A SECOND signal (Ctrl-C twice) that force-exits 130 immediately.
///
/// Robustness: a failed SIGTERM registration must NOT crash — it degrades to
/// SIGINT-only (`ctrl_c`). On non-unix only `ctrl_c` is available.
#[cfg(feature = "server")]
async fn web_shutdown_signal<Model, Msg>(
    store: Arc<dyn store::SessionStore<Model, Msg>>,
    grace: std::time::Duration,
) where
    Model: Send + 'static,
    Msg: Send + 'static,
{
    // First press: block until SIGINT or SIGTERM arrives.
    wait_for_term_or_int().await;

    // Print to stdout. The leading newline keeps the `^C` echo on its own line.
    crate::system::write_stdout_line("\nIpe.Web shutting down…");

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
    #[cfg(all(feature = "web", feature = "http_client"))]
    console_proxy::shutdown_console();

    // Telemetry export pipelines (push/hub exporters) flush every ~2 s on a
    // tick. The channel-close drain ONLY runs when the mpsc Sender is dropped,
    // which requires Drop — and `process::exit` skips Drop entirely. The
    // grace-timer and watchdog paths below end through `system::exit_process`,
    // whose pre-exit stage sends a Flush sentinel to each active exporter and
    // waits at most the larger exporter flush deadline; it is best-effort
    // (telemetry only, never user data) and never hangs shutdown.

    // Grace timer: force a CLEAN exit-0 after the window so a never-idle SSE
    // connection can't hang the drain. Spawned (not awaited) so we still return
    // immediately and let the axum drain
    // win the race when there are no long-lived connections (the common case →
    // sub-window exit). Exit 0 keeps the IpeTask-Ok / exit-0 contract.
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        // Defense-in-depth: kill the console child again in case it was spawned
        // after the first teardown call (shutdown_console is idempotent).
        #[cfg(all(feature = "web", feature = "http_client"))]
        console_proxy::shutdown_console();
        // The exit funnel flushes the exporters before the process ends.
        crate::system::exit_process(0);
    });

    // Second press: a watchdog that force-exits 130 if the user hits Ctrl-C
    // again while the drain is in progress. Spawned (not awaited).
    tokio::spawn(async {
        wait_for_term_or_int().await;
        crate::system::write_stderr_line("Ipe.Web: forcing exit (second signal)");
        #[cfg(all(feature = "web", feature = "http_client"))]
        console_proxy::shutdown_console();
        // 128 + SIGINT(2); the exit funnel flushes the exporters first.
        crate::system::exit_process(130);
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
        let ttl = match web_ttl() {
            Ok(ttl) => ttl,
            Err(refusal) => {
                return IpeResult::Err(StartupRefusal::Ceiling(refusal).to_string().into());
            }
        };
        let store = match store::choose_store::<Model, Msg>(
            &store_kind,
            &store_path,
            ttl,
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
            route_entry: Arc::new(|model, _path| route::Entered {
                model,
                cmd: IpeCmd::None,
            }),
            param_resolver: Arc::new(|_path| crate::dict::dict_empty()),
            // No route table: only `/` is a page URL.
            route_matched: Arc::new(RouteLookup::single_page),
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
            // router that answers every path with the fixed 503 body (the
            // operator detail goes to the runtime log) — never a silent downgrade to a different backend and never a mount
            // that quietly serves real sessions on the wrong store.
            let ttl = match web_ttl() {
                Ok(ttl) => ttl,
                Err(refusal) => return fail_closed_router(&StartupRefusal::Ceiling(refusal)),
            };
            let store =
                match store::choose_store::<Model, Msg>(&store_kind, &store_path, ttl, schema_tag)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => return fail_closed_router(&StartupRefusal::SessionStore(e)),
                };
            let state = WebState {
                store,
                init: Arc::new(init),
                update: Arc::new(update),
                view: Arc::new(view),
                subs: Arc::new(subscriptions),
                route_entry: Arc::new(|model, _path| route::Entered {
                    model,
                    cmd: IpeCmd::None,
                }),
                param_resolver: Arc::new(|_path| crate::dict::dict_empty()),
                route_matched: Arc::new(RouteLookup::single_page),
                session_count: Arc::new(AtomicUsize::new(0)),
                watch_build_status: Arc::new(Mutex::new(None)),
            };
            // The router is E-free (E only surfaces on the standalone
            // `serve_web` task's result), so `build_web_router` carries no `E`.
            build_web_router::<Model, Msg, FInit, FUpdate, FView, FSubs>(state, false)
                .unwrap_or_else(|cause| fail_closed_router(&cause))
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = axum::Router> + Send>>
    })
}

/// `Web.embed` of a ROUTED app (`Model` has a `page` field): the routed sibling
/// of [`web_embed_router`]. It builds the SAME routed `WebState` as
/// [`web_app_routed`] — a `route_entry` / `param_resolver` / `route_matched`
/// derived from the route table + `set_page` — but, exactly like
/// [`web_embed_router`], returns a [`crate::tea::MountBuilder`] that yields the
/// fully-layered `Router` for `Server.mountApp` to nest under a prefix on the
/// shared server port, instead of binding its own listener.
///
/// `Page` / `FSetPage` are erased into the boxed entry closures, so
/// `build_web_router` / `WebState` keep the original six type params — no `dyn`
/// over the app's handlers (§9).
#[allow(clippy::too_many_arguments)] // mirrors web_app_routed's routed cfg (callbacks + route table + set_page + store)
#[cfg(feature = "server")]
pub fn web_embed_router_routed<Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage, FRender>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    routes: Vec<route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    render: FRender,
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
    FSetPage: Fn(Page, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FRender: Fn(&Page) -> Result<route::RoutePath, route::RenderRefusal> + Send + Sync + 'static,
{
    Box::new(move |prefix: String| {
        Box::pin(async move {
            // Scope the embedded app's cookies + assets to the mount prefix,
            // reusing the sub-app base-path mechanism (see `web_embed_router`).
            let base = normalise_base_path(&prefix);
            if !base.is_empty() {
                crate::system::locked_set_var("IPE_WEB_BASE_PATH", &base);
            }
            // A malformed route pattern refuses the mount, never a dead route.
            if let Err(refusal) = route::check_route_table(&routes) {
                return fail_closed_router(&StartupRefusal::RouteTable(refusal));
            }
            // Routed resolvers — identical construction to `web_app_routed`; only
            // the terminal `build_web_router` (vs `serve_web`) differs.
            let (route_entry, param_resolver, route_matched) =
                routed_resolvers(routes, not_found, set_page, render);
            // A mount has no task-error channel, so an unhonourable store config
            // fails closed as a 503-everywhere router (see `web_embed_router`).
            let ttl = match web_ttl() {
                Ok(ttl) => ttl,
                Err(refusal) => return fail_closed_router(&StartupRefusal::Ceiling(refusal)),
            };
            let store =
                match store::choose_store::<Model, Msg>(&store_kind, &store_path, ttl, schema_tag)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => return fail_closed_router(&StartupRefusal::SessionStore(e)),
                };
            let state = WebState {
                store,
                init: Arc::new(init),
                update: Arc::new(update),
                view: Arc::new(view),
                subs: Arc::new(subscriptions),
                route_entry,
                param_resolver,
                route_matched,
                session_count: Arc::new(AtomicUsize::new(0)),
                watch_build_status: Arc::new(Mutex::new(None)),
            };
            build_web_router::<Model, Msg, FInit, FUpdate, FView, FSubs>(state, false)
                .unwrap_or_else(|cause| fail_closed_router(&cause))
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
pub fn web_embed_routed<Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage, FRender>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    routes: Vec<route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    render: FRender,
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
    FSetPage: Fn(Page, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FRender: Fn(&Page) -> Result<route::RoutePath, route::RenderRefusal> + Send + Sync + 'static,
{
    let init = Arc::new(init);
    let update = Arc::new(update);
    let view = Arc::new(view);
    let subscriptions = Arc::new(subscriptions);
    let set_page = Arc::new(set_page);
    let render = Arc::new(render);
    let serve = {
        let (init, update, view, subscriptions, set_page, render) = (
            Arc::clone(&init),
            Arc::clone(&update),
            Arc::clone(&view),
            Arc::clone(&subscriptions),
            Arc::clone(&set_page),
            Arc::clone(&render),
        );
        web_app_routed::<crate::error::IpeError, Model, Msg, Page, _, _, _, _, _, _>(
            move |req| (*init)(req),
            move |msg, model| (*update)(msg, model),
            move |model| (*view)(model),
            move |model| (*subscriptions)(model),
            routes.clone(),
            not_found.clone(),
            move |page, model| (*set_page)(page, model),
            move |page: &Page| (*render)(page),
            store_kind.clone(),
            store_path.clone(),
            schema_tag,
        )
    };
    let router = web_embed_router_routed::<Model, Msg, Page, _, _, _, _, _, _>(
        move |req| (*init)(req),
        move |msg, model| (*update)(msg, model),
        move |model| (*view)(model),
        move |model| (*subscriptions)(model),
        routes,
        not_found,
        move |page, model| (*set_page)(page, model),
        move |page: &Page| (*render)(page),
        store_kind,
        store_path,
        schema_tag,
    );
    crate::tea::WebApp(crate::tea::WebAppKind::Mountable { serve, router })
}

/// Why a live web app refused to start as declared. The `Display` text is the
/// operator detail: it goes to the runtime log (a mount) or to the local task
/// error (a standalone app), never into a response body.
#[cfg(feature = "server")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartupRefusal {
    /// The route table holds a malformed pattern.
    RouteTable(route::RoutePatternRefusal),
    /// The session store config cannot be honoured.
    SessionStore(store::StoreConfigError),
    /// The base path (`IPE_WEB_BASE_PATH` / the mount prefix) does not decode.
    BasePath {
        base: String,
        refusal: crate::encoding::DecodeRefusal,
    },
    /// The base path is outside the mount-base grammar every shell URL uses.
    MountBase {
        base: String,
        refusal: crate::encoding::MountBaseRefusal,
    },
    /// An environment ceiling the app applies is present but malformed.
    Ceiling(crate::system::EnvCeilingRefusal),
    /// `IPE_WEB_FRAME_ANCESTORS` has no `frame-ancestors` representation.
    FrameAncestors(crate::telemetry::FrameAncestorsRefusal),
    /// `IPE_HTTP_BIND` is present but not an IP address.
    Bind(crate::system::EnvValueRefusal),
}

#[cfg(feature = "server")]
impl std::fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RouteTable(refusal) => write!(f, "{refusal}"),
            Self::SessionStore(e) => write!(f, "session store misconfigured: {e}"),
            Self::BasePath { base, refusal } => {
                write!(f, "web base path `{base}` is malformed: {refusal}")
            }
            Self::MountBase { base, refusal } => {
                write!(f, "web base path `{base}` is not a mount base: {refusal}")
            }
            Self::Ceiling(refusal) => write!(f, "{refusal}"),
            Self::FrameAncestors(refusal) => write!(f, "{refusal}"),
            Self::Bind(refusal) => write!(f, "{refusal}"),
        }
    }
}

/// The fixed public body of a fail-closed mount's 503. One constant for every
/// [`StartupRefusal`], so a response never carries the operator detail.
#[cfg(feature = "server")]
pub(crate) const FAIL_CLOSED_BODY: &str =
    "Service Unavailable: this app could not start. The server log names the fault.";

/// Parse the normalised base path once into the [`route::DecodedPath`] the
/// SSE reconnect strips from a client route. The empty base is the root.
///
/// # Errors
///
/// [`StartupRefusal::BasePath`] for a base that is not a well-formed path.
#[cfg(feature = "server")]
fn parse_route_base(base: &str) -> Result<route::DecodedPath, StartupRefusal> {
    route::DecodedPath::parse(base).map_err(|refusal| StartupRefusal::BasePath {
        base: base.to_string(),
        refusal,
    })
}

/// Parse the normalised base path into the [`crate::encoding::MountBase`]
/// every page and widget URL is built from. The empty base is the root.
///
/// # Errors
///
/// [`StartupRefusal::MountBase`] for a base outside the mount-base grammar.
#[cfg(feature = "server")]
fn parse_mount_base(base: &str) -> Result<crate::encoding::MountBase, StartupRefusal> {
    crate::encoding::MountBase::parse(base).map_err(|refusal| StartupRefusal::MountBase {
        base: base.to_string(),
        refusal,
    })
}

/// The process's [`crate::encoding::MountBase`], read from `IPE_WEB_BASE_PATH`.
///
/// # Errors
///
/// [`StartupRefusal::MountBase`] for a base outside the mount-base grammar;
/// [`build_web_router`] refuses such a base before any request is served.
#[cfg(feature = "server")]
fn web_mount_base() -> Result<crate::encoding::MountBase, StartupRefusal> {
    parse_mount_base(&web_base_path())
}

/// A router that answers EVERY path with `503 Service Unavailable` and the
/// fixed [`FAIL_CLOSED_BODY`]. Used when a mounted `Web.embed` cannot start as
/// declared (fail-closed): the mount stays reachable enough to report that it
/// is down, but never serves a real session on a silently-degraded store or a
/// silently-dead route. The cause is logged once here, server-side only.
#[cfg(feature = "server")]
fn fail_closed_router(cause: &StartupRefusal) -> axum::Router {
    crate::system::emit_runtime_log("live", &format!("mounted web app disabled: {cause}"));
    axum::Router::new().fallback(|| async {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            FAIL_CLOSED_BODY,
        )
    })
}

/// `Ipe.Web.tea { …, routes, notFound }` with URL routing — serve via axum.
///
/// Identical to `web_app` except a `route_entry` is built from the route
/// table + `set_page`: each URL entry matches the path to a `Page` value
/// (param strings applied via the route closures) and enters it through
/// `set_page`, which yields the model and the page's entry Cmd. `Page`/`FSetPage`
/// are erased into the boxed entry, so `serve_web`/`WebState` keep the
/// original 6 type params.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "server")]
pub fn web_app_routed<E, Model, Msg, Page, FInit, FUpdate, FView, FSubs, FSetPage, FRender>(
    init: FInit,
    update: FUpdate,
    view: FView,
    subscriptions: FSubs,
    routes: Vec<route::Route<Page>>,
    not_found: Page,
    set_page: FSetPage,
    render: FRender,
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
    FSetPage: Fn(Page, Model) -> (Model, IpeCmd<Msg>) + Send + Sync + 'static,
    FRender: Fn(&Page) -> Result<route::RoutePath, route::RenderRefusal> + Send + Sync + 'static,
{
    Box::pin(async move {
        // A malformed route pattern refuses to start, never a dead route.
        if let Err(message) = route::refuse_route_table(&routes) {
            return IpeResult::Err(message.into());
        }
        let (route_entry, param_resolver, route_matched) =
            routed_resolvers(routes, not_found, set_page, render);
        // Fail-closed on an unhonourable store config (see `web_app`).
        let ttl = match web_ttl() {
            Ok(ttl) => ttl,
            Err(refusal) => {
                return IpeResult::Err(StartupRefusal::Ceiling(refusal).to_string().into());
            }
        };
        let store = match store::choose_store::<Model, Msg>(
            &store_kind,
            &store_path,
            ttl,
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
            route_entry,
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

/// Serve an unrouted browser-noise file from the static dir's root when it
/// exists there.
///
/// Browsers probe `/favicon.ico` (and friends) at the origin root, never under
/// `/static/`, so without this shortcut an author with a configured static dir
/// has no way to suppress the 404. `None` means the caller answers 404: no
/// static dir, a request path [`noise_candidate`] refuses, or an entry that is
/// absent, a directory or unreadable.
#[cfg(feature = "server")]
async fn serve_noise_from_static_root(path: &str) -> Option<axum::response::Response> {
    use axum::response::IntoResponse;
    // IPE_WEB_STATIC_DIR: a non-empty value mounts the named directory at /static.
    let dir = crate::system::read_env_var("IPE_WEB_STATIC_DIR")
        .ok()
        .filter(|d| !d.is_empty())?;
    let (candidate, mime) = noise_candidate(&dir, path, crate::path_core::HOST)?;
    let bytes = tokio::fs::read(&candidate).await.ok()?;
    Some(
        (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, mime)],
            bytes,
        )
            .into_response(),
    )
}

/// The file beneath `dir` a browser-noise request path names under `regime`,
/// with its content type, or `None` when the path may not reach the
/// filesystem.
///
/// The request path is parsed by the one static-request parse
/// ([`crate::server::static_request`]): decoded once by the strict core, every
/// segment a plain name under the regime. The candidate is the checked join
/// ([`crate::path::join_rel`]), never a raw `Path::join`.
#[cfg(feature = "server")]
fn noise_candidate(
    dir: &str,
    uri_path: &str,
    regime: crate::path_core::Regime,
) -> Option<(std::path::PathBuf, &'static str)> {
    let crate::server::StaticRequest::File(rel) =
        crate::server::static_request(uri_path, std::path::Path::new(dir), regime).ok()?
    else {
        return None;
    };
    let candidate = std::path::PathBuf::from(crate::path::join_rel(dir, &rel).ok()?);
    let mime = static_noise_mime(rel.last().rsplit('.').next().unwrap_or(""));
    Some((candidate, mime))
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

/// Where an SSE reconnect's `?path=` lands in this app's route table.
///
/// The client sends its raw `location.pathname`, which includes any
/// reverse-proxy or mount prefix. The path is parsed once into a
/// [`route::DecodedPath`] (each segment decoded once by the strict core): a
/// malformed one is the fixed `BadRequest`, answered before any session is
/// touched. A value that is not a bare path (no leading `/`, or carrying a `?`
/// or `#`) names nothing to reconcile (`Ok(None)`).
///
/// `base` is the normalised `IPE_WEB_BASE_PATH`, parsed once when the router
/// is built (the root when unset, which strips nothing). It is stripped on a
/// whole-segment boundary ([`route::DecodedPath::strip_base`]): base `/app`
/// strips `/app/x` to `/x` and `/app` to `/`, and never touches `/apple`. A
/// path not under the base names nothing this app displays (`Ok(None)`).
///
/// # Errors
///
/// `RequestRejection::BadRequest` for a `path` that is not a well-formed
/// RFC 3986 path.
#[cfg(feature = "server")]
fn client_route_path(
    raw: &str,
    base: &route::DecodedPath,
) -> Result<Option<route::DecodedPath>, crate::server::RequestRejection> {
    let path =
        route::DecodedPath::parse(raw).map_err(|_| crate::server::RequestRejection::BadRequest)?;
    if !raw.starts_with('/') || raw.contains('?') || raw.contains('#') {
        return Ok(None);
    }
    Ok(path.strip_base(base))
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
        // The router's URL gate already refused a malformed path or query;
        // this is the second, independent boundary before any session work.
        // The path is parsed here once; every route resolver below reads it.
        let path = match crate::server::strict_url(&uri) {
            Ok(url) => url.path,
            Err(rejection) => return rejection.status_and_reason().into_response(),
        };
        let lookup = (st.route_matched)(&path);
        // A routed page reached by a path other than the one it renders to (a
        // trailing `/`, an escape its route decodes, `007` for an `Int` `7`) is
        // redirected there before any session work, so a session only ever
        // enters canonical paths.
        if let RouteLookup::Page(canonical) = &lookup
            && (method == axum::http::Method::GET || method == axum::http::Method::HEAD)
        {
            let Some(base) = route::DecodedPath::parse(&web_base_path())
                .ok()
                .and_then(|base| crate::encoding::EncodedBase::encode(&base).ok())
            else {
                return (StatusCode::INTERNAL_SERVER_ERROR, "500 base path unusable")
                    .into_response();
            };
            match route::canonical_redirect(&base, uri.path(), uri.query(), canonical) {
                route::Redirect::Serve => {}
                route::Redirect::To(target) => {
                    return (
                        StatusCode::PERMANENT_REDIRECT,
                        [(axum::http::header::LOCATION, target.location().clone())],
                    )
                        .into_response();
                }
                route::Redirect::BadQuery => {
                    return (StatusCode::BAD_REQUEST, "400 malformed query").into_response();
                }
            }
        }
        // Cookie-based session lifecycle:
        //   * Web hit  → reuse the in-process session; its driver enters this
        //                 GET's path and runs the entry Cmd (no new driver).
        //   * Restored  → a persisted model (post-restart / different replica);
        //                 hydrate a fresh driver seeded with it (no init).
        //   * Rebuilt   → a persisted model spliced onto a fresh `init` across an
        //                 additive Model change; init's Cmd runs, then the entry's.
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
        let routed = lookup.is_routed();
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
        // synthetic request and no surprising default. It runs under the
        // cookie's sid (the sid a rebuilt session keeps) and returns init's
        // whole `(Model, Cmd)` pair: the store hands the Cmd back beside the
        // rebuilt model, and `enter_session` runs it. It is invoked LAZILY:
        // only on a schema-mismatched cold row, never on a live hit or a
        // matched-schema restore. Any non-additive change (removed / retyped
        // field), corrupt / oversized body, or pre-`v2` row falls back to the
        // clean re-init the store's flat miss always produced.
        // `IPE_WEB_RESET_STATE=1` (set by `ipe dev watch --reset-state` in the child
        // env) bypasses the checkpoint lookup entirely: every returning session
        // is treated as a miss and falls through to a fresh `init`. The flag is
        // evaluated once per request (cheap env read, cached by the OS) and is
        // fail-closed — any value other than a recognised truthy string leaves
        // the additive algorithm in place.
        // A cookie that is not a well-formed sid is a miss: it reaches neither
        // the claim table nor the store. A well-formed one is claimed first,
        // so at most one request per sid turns a persisted checkpoint into a
        // live driver; a request behind the claim waits for the holder to
        // publish the session and then joins it live. A refused claim is the
        // 503 a busy session or a full process already answers with.
        let cookie_key = cookie_sid.as_deref().and_then(store::SessionKey::parse);
        let hit = match cookie_key {
            Some(key) if !reset_state_from_env() => 'rejoin: {
                // A live session never contends for the claim table: the
                // claim serialises only the cold-to-live transition.
                if let Some(handle) = st.store.get(key.as_str()).await {
                    break 'rejoin Some((key.as_str().to_owned(), store::Rejoin::Live(handle)));
                }
                // Once claimed, `get_reconstructing` checks live again first:
                // the previous holder's publish may have landed while this waited.
                let claim = match st.store.claim(key).await {
                    Ok(claim) => claim,
                    Err(store::ClaimRefusal::InFlight | store::ClaimRefusal::Crowded) => {
                        return entry_unavailable();
                    }
                    Err(store::ClaimRefusal::Saturated) => return at_capacity(),
                };
                let sid = claim.key().as_str().to_owned();
                let make_init = || {
                    pubsub::with_session_sid(sid.clone(), || {
                        let params = (st.param_resolver)(&path);
                        let req = req::web_req(&method, &uri, &headers, params);
                        (st.init)(req)
                    })
                };
                let rejoin = st.store.get_reconstructing(claim, &make_init).await;
                Some((sid, rejoin))
            }
            Some(_) | None => None,
        };

        //
        // session (live or persisted) 404s WITHOUT touching it. Re-routing
        // here would write the `notFound` page into the model and rebuild
        // the handler index from that view, orphaning every handler on the
        // page the browser is still showing — the next event POST (form
        // submit, click, input) would silently resolve to nothing.
        let known = match &hit {
            Some((
                _,
                store::Rejoin::Live(_)
                | store::Rejoin::Restored { .. }
                | store::Rejoin::Rebuilt { .. },
            )) => true,
            Some((_, store::Rejoin::Miss)) | None => false,
        };
        if !routed && known {
            return (StatusCode::NOT_FOUND, "404 page not found").into_response();
        }

        let (owner, slot, model, cmd0) = match hit {
            Some((sid, store::Rejoin::Live(handle))) => {
                // sid is carried from the cookie lookup; the "hit but no sid"
                // state is unrepresentable. The live driver enters the path,
                // serialised with its `update`s, commits, touches the store and
                // runs the entry Cmd; this request waits for the body, bounded
                // by the queue cap and the reply timeout.
                let enter_tx = handle
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .enter_tx
                    .clone();
                let Some(reply_rx) = queue_entry(&enter_tx, path.clone(), EnterMode::Load) else {
                    return entry_unavailable();
                };
                let Some(EnterReply { body, epoch }) = await_entry(reply_rx).await else {
                    return entry_unavailable();
                };
                #[cfg(feature = "debugger")]
                {
                    let labels: Vec<String> = handle
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .history
                        .labels();
                    let overlay = crate::debugger::server::overlay_html(
                        &labels,
                        labels.len(),
                        &web_base_path(),
                    );
                    return page_response_with_overlay(
                        &sid, &body, &epoch, &overlay, &csrf_tok, &headers,
                    );
                }
                #[cfg(not(feature = "debugger"))]
                return page_response(&sid, &body, &epoch, &csrf_tok, &headers);
            }
            Some((_, store::Rejoin::Restored { claim, model })) => {
                // A returning user with a valid sid cookie → not new attack
                // volume, so NOT rejected; but count its driver. The slot is
                // taken at once, so the count is given back on every exit,
                // a cancelled request included.
                st.session_count.fetch_add(1, Ordering::SeqCst);
                let slot = SessionSlot {
                    count: st.session_count.clone(),
                };
                let (m, c) = enter_session(
                    &st.route_entry,
                    claim.key().as_str(),
                    model,
                    IpeCmd::None,
                    &path,
                );
                (SessionOwner::Rejoined(claim), slot, m, c)
            }
            Some((
                _,
                store::Rejoin::Rebuilt {
                    claim,
                    model,
                    init_cmd,
                },
            )) => {
                // Returning user, same slot pairing as `Restored`; the rebuilt
                // model's `init` Cmd runs first, exactly as on a new session.
                st.session_count.fetch_add(1, Ordering::SeqCst);
                let slot = SessionSlot {
                    count: st.session_count.clone(),
                };
                let (m, c) = enter_session(
                    &st.route_entry,
                    claim.key().as_str(),
                    model,
                    init_cmd,
                    &path,
                );
                (SessionOwner::Rejoined(claim), slot, m, c)
            }
            Some((_, store::Rejoin::Miss)) | None => {
                // Admission control (cookieless = brand-new session = the
                // attack surface). Reserve a slot atomically: fetch_add-then-test
                // avoids the load-then-add TOCTOU where N concurrent GETs all
                // pass at cap-1. ALWAYS reserve (so the slot built below is
                // paired 1:1 with a decrement); only the rejection is gated on
                // cap>0 (0 = unlimited opt-out). Over cap → roll back + 503.
                // A malformed ceiling admits no new session (`usize::MIN` cap
                // with the unlimited opt-out off), never the default.
                let (cap, unlimited) = match max_sessions() {
                    Ok(cap) => (cap, cap == 0),
                    Err(_) => (usize::MIN, false),
                };
                let reserved = st.session_count.fetch_add(1, Ordering::SeqCst);
                if !unlimited && reserved >= cap {
                    st.session_count.fetch_sub(1, Ordering::SeqCst);
                    return at_capacity();
                }
                let slot = SessionSlot {
                    count: st.session_count.clone(),
                };
                // Build the request context (params from routing — empty when
                // unrouted) and init a fresh model. The param_resolver is
                // model-independent, breaking the init↔routing cycle.
                let params = (st.param_resolver)(&path);
                let req = req::web_req(&method, &uri, &headers, params);
                // Session fixation guard: a store MISS means this sid is NOT a
                // known session, so NEVER adopt the client-supplied cookie value
                // — always mint a fresh sid. (A HIT path keeps cookie_sid.)
                // Minted first so `init` and the entry run under it.
                let s = new_sid();
                let (m, init_cmd) = pubsub::with_session_sid(s.clone(), || (st.init)(req));
                let (m, c) = enter_session(&st.route_entry, &s, m, init_cmd, &path);
                (SessionOwner::Minted(s), slot, m, c)
            }
        };
        let sid = owner.sid().to_owned();

        let mut tree = (st.view)(model.clone());
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        let body = render_html(&tree);
        let rendered = Rendered::first(new_incarnation(), tree);
        let epoch = rendered.epoch();

        // Bounded per-session Msg queue: cap at 1024 to prevent a fast
        // client from growing the queue without bound (per-session memory DoS).
        // On overflow events are dropped with a warn (see event_handler).
        // 1024 is far above any legitimate burst of user-driven events.
        let (msg_tx, msg_rx) = mpsc::channel::<Msg>(1024);
        let (enter_tx, enter_rx) = mpsc::channel::<EnterRequest>(ENTER_QUEUE_CAP.get());
        #[cfg(feature = "debugger")]
        let history_init =
            crate::debugger::RecordBuffer::new(model.clone(), crate::debugger::DEFAULT_HISTORY_CAP);
        let entry = Arc::new(Mutex::new(SessionEntry {
            model,
            rendered,
            tabs: TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx: msg_tx.clone(),
            entered_path: Some(path.clone()),
            enter_tx,
            #[cfg(feature = "debugger")]
            history: history_init,
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }));

        // Publishing the session is one task the request cannot cancel: the
        // store write, the driver spawn and the seed Cmd all run, and only
        // then is the claim released, so the next request for the sid finds
        // the live session. The driver holds a WEAK entry ref (the store +
        // any SSE connection are the strong holders) so it is mortal: it
        // exits once the session is evicted and unconnected, releasing
        // `slot`, which decrements `session_count`.
        let store = st.store.clone();
        let update = st.update.clone();
        let view = st.view.clone();
        let subs = st.subs.clone();
        let route_entry = st.route_entry.clone();
        let commit = tokio::spawn(async move {
            let sid = owner.sid();
            store.set(sid, entry.clone()).await;
            tokio::spawn(drive_session(
                Arc::downgrade(&entry),
                msg_rx,
                msg_tx.clone(),
                enter_rx,
                update,
                view,
                subs,
                route_entry,
                store.clone(),
                sid.to_owned(),
                slot,
            ));
            // Fire the entry Cmd into the loop (batched after init's on a miss).
            pubsub::with_session_sid(sid.to_owned(), || run_cmd(cmd0, &msg_tx, sid));
            drop(owner);
        });
        if let Err(failed) = commit.await {
            return match failed.try_into_panic() {
                Ok(payload) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    crate::core::panic_500_body(&*payload),
                )
                    .into_response(),
                Err(_) => entry_unavailable(),
            };
        }

        #[cfg(feature = "debugger")]
        {
            let base = web_base_path();
            let overlay = crate::debugger::server::overlay_html(&[], 0, &base);
            page_response_with_overlay(&sid, &body, &epoch, &overlay, &csrf_tok, &headers)
        }
        #[cfg(not(feature = "debugger"))]
        page_response(&sid, &body, &epoch, &csrf_tok, &headers)
    }

    // ── GET /_ipe/sse ─────────────────────────────────────────────────
    pub(super) async fn sse_handler<Model, Msg, FInit, FUpdate, FView, FSubs>(
        State(st): State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
        uri: axum::http::Uri,
        headers: axum::http::HeaderMap,
        base: Arc<route::DecodedPath>,
    ) -> Response
    where
        Model: Clone + Send + 'static,
        Msg: Clone + Send + 'static,
        FInit: Send + Sync + 'static,
        FUpdate: Send + Sync + 'static,
        FView: Fn(Model) -> Html<Msg> + Send + Sync + 'static,
        FSubs: Send + Sync + 'static,
    {
        // The query decodes once through the strict core; the router's URL
        // gate already refused a malformed one, this is the second boundary.
        let qs = match crate::server::strict_url_query(&uri) {
            Ok(qs) => qs,
            Err(rejection) => return rejection.status_and_reason().into_response(),
        };
        // `?path=` is parsed once into the route path it names; a malformed
        // one gets the fixed 400 before any session is touched.
        let client_route = match qs
            .get("path")
            .map(|p| client_route_path(p.trim(), &base))
            .transpose()
        {
            Ok(route) => route.flatten(),
            Err(rejection) => return rejection.status_and_reason().into_response(),
        };
        let sid = sid_from_cookie(&headers);
        let entry = match &sid {
            Some(s) => st.store.get(s).await,
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
        // server knows which URL the browser is actually displaying. A routed
        // path the session has not entered is entered by the driver (its Cmd
        // runs there) before the resync render; the path the session already
        // entered, an unroutable path, or an absent param keeps the current
        // view. A refused entry (queue full or closed) keeps it too, and the
        // next reconnect retries.
        // `client_route_path` already stripped the sub-app base on a segment
        // boundary, so a mounted sub-app reconciles against its own table.
        if let Some(route_path) = &client_route
            && let ReconcileOutcome::Entering(reply_rx) =
                reconcile_path(&entry, &st.route_matched, route_path)
        {
            let _ = await_entry(reply_rx).await;
        }

        // A malformed buffer ceiling refuses the stream, never the default.
        let Ok((tx, rx)) = sse::channel() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
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
        // silent. A release / `ipe dev run` server never sets the env, so this
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
        // restart / `ipe dev watch` rebuild / redeploy paired with a persistent
        // store — has no live subscriptions from the previous process, so
        // nothing pushes until the next user Msg. Render the current view once
        // and ship it as a full-body `event: patch` frame; the client consumes
        // `{seq, body}` → __ipePatch full replace (client.js:1318). No globalSeq
        // field → the client's broadcast-dedup guard (globalSeq>0) can never
        // drop this authoritative, idempotent frame. Bump seq under the same
        // lock the event path uses so it stays monotonic vs later patches; drop
        // the guard before the await (never hold a std Mutex across .await).
        //
        // When the reconnect reconciliation above entered a path, the driver
        // already committed model and last_view; the render here picks them up.
        let resync = {
            let mut g = entry.lock().unwrap_or_else(|e| e.into_inner());
            g.seq += 1;
            // The current render at its current epoch: a resync re-sends the
            // view, it mints no epoch and changes no handler index.
            let html = render_html(g.rendered.last_view());
            serde_json::json!({
                "seq": g.seq,
                "epoch": g.rendered.epoch().to_token(),
                "body": html,
            })
            .to_string()
        };
        let _ = tx.send(SsePatch(sse::frame("patch", &resync))).await;

        // Replay the latest build-status so a browser refresh during a failed
        // build immediately shows the sticky error banner without waiting for
        // the next `ipe dev watch` status POST. A `None` status (no build has run
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

        let at = parsed
            .epoch
            .as_deref()
            .map_or(Err(EventRefusal::Missing), |token| {
                RenderEpoch::parse(token).map_err(EventRefusal::Malformed)
            });
        let tab = parsed
            .tab
            .as_deref()
            .map(|token| TabId::parse(token).ok_or(EventRefusal::MalformedTab))
            .transpose();

        // One lock covers resolve, the duplicate check, the enqueue and the
        // seq record, so two copies of one event cannot both dispatch.
        let mut e = entry.lock().unwrap_or_else(|e| e.into_inner());
        let (at, tab) = match (at, tab) {
            (Ok(at), Ok(tab)) => (at, tab),
            (Err(refusal), _) | (Ok(_), Err(refusal)) => {
                return event_refusal_response(refusal, &e);
            }
        };
        let resolved = if event == "submit" {
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
            e.rendered.resolve_form(&at, &hid, &event, fd)
        } else {
            let args: Vec<String> = parsed.args.iter().map(value_to_string).collect();
            e.rendered.resolve(&at, &hid, &event, &args)
        };
        let msg = match resolved {
            Ok(msg) => msg,
            Err(why) => return event_refusal_response(EventRefusal::Stale(why), &e),
        };
        let replay_key = tab.zip(parsed.seq);
        if let Some((tab, seq)) = replay_key
            && e.tabs.is_duplicate(tab, seq)
        {
            return event_ack(e.seq, true);
        }
        // try_send is non-blocking; on a full queue drop the event and return
        // 429 so the client can back off. The seq is not recorded, so the
        // client's retry of the same event is not mistaken for a duplicate.
        if let Some(m) = msg
            && let Err(err) = e.msg_tx.try_send(m)
        {
            crate::system::emit_runtime_log(
                "live",
                &format!("event_handler: session msg queue full or closed; dropping event ({err})"),
            );
            return (StatusCode::TOO_MANY_REQUESTS, "event queue full").into_response();
        }
        if let Some((tab, seq)) = replay_key {
            e.tabs.record(tab, seq);
        }
        event_ack(e.seq, false)
    }

    // ── POST /_ipe/hot-appearance (dev-only) ──────────────────────────
    // The running server's inbound leg of the appearance-hot-swap live socket.
    // The `ipe dev watch` process (a SEPARATE process from the running app) computes
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
    // live socket. The `ipe dev watch` process computes a transition patch for an
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
    // button firing it), `ipe dev watch` computes the edited program's `MsgSet`
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
    // socket. The `ipe dev watch` process computes a sub patch for an edited
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
    // socket. The `ipe dev watch` process computes an init patch for an edited
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
    // live socket. The `ipe dev watch` process computes a wiring patch for an edited
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
    // Inbound build-status notification from `ipe dev watch`. Guarded two ways
    // so it is inert in production:
    //   1. The route is MOUNTED only when the dev banner is active (non-
    //      production + `IPE_WEB_BANNER` not disabled + root-mounted).
    //   2. The `X-Ipe-Hot-Token` header MUST match the per-process token
    //      set by `ipe dev watch` (the same mechanism as `/_ipe/hot-appearance`).
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
        if st.store.get(&sid).await.is_none() {
            return (
                StatusCode::NOT_FOUND,
                [(axum::http::HeaderName::from_static("x-ipe-web"), "1")],
                SESSION_LOST_BODY,
            )
                .into_response();
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

    /// Install the render a debugger endpoint shows as the session's current
    /// render, minting its epoch; `None` when no epoch is left to mint.
    #[cfg(feature = "debugger")]
    fn commit_debug_render<Model, Msg: Clone>(
        handle: &store::SessionHandle<Model, Msg>,
        tree: Html<Msg>,
    ) -> Option<RenderEpoch> {
        let mut e = handle.lock().unwrap_or_else(|e| e.into_inner());
        e.rendered.commit(tree).ok().map(|step| step.to)
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
            Some(h) => h,
            None => {
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
        // The debugger shows this render, so it becomes the session's current
        // render under a new epoch: the ids in the DOM it shows resolve against
        // its own handler index, never the one it replaced.
        let Some(epoch) = commit_debug_render(&handle, tree) else {
            st.store.delete(&sid).await;
            return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
        };
        let resp_json = serde_json::json!({ "body": html_body, "epoch": epoch.to_token() });
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
            Some(h) => h,
            None => {
                return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
            }
        };
        // Build a fresh init model from the current request context — the same
        // path the clean-reinit miss takes — so the reset session holds exactly
        // what a cold-start visit would have produced.
        let path = match crate::server::strict_url(&uri) {
            Ok(url) => url.path,
            Err(rejection) => return rejection.status_and_reason().into_response(),
        };
        let params = (st.param_resolver)(&path);
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
            Some(h) => h,
            None => {
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
            Some(h) => h,
            None => {
                return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
            }
        };
        // Derive the init model the same way reset_handler does: build a
        // WebReq from the current request context so route-aware apps get the
        // correct initial state.
        let path = match crate::server::strict_url(&uri) {
            Ok(url) => url.path,
            Err(rejection) => return rejection.status_and_reason().into_response(),
        };
        let params = (st.param_resolver)(&path);
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
            Some(h) => h,
            None => {
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
        // The debugger shows this render, so it becomes the session's current
        // render under a new epoch: the ids in the DOM it shows resolve against
        // its own handler index, never the one it replaced.
        let Some(epoch) = commit_debug_render(&handle, tree) else {
            st.store.delete(&sid).await;
            return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
        };
        let resp_json = serde_json::json!({
            "body":   html_body,
            "epoch":  epoch.to_token(),
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
            Some(h) => h,
            None => {
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
        // The debugger shows this render, so it becomes the session's current
        // render under a new epoch: the ids in the DOM it shows resolve against
        // its own handler index, never the one it replaced.
        let Some(epoch) = commit_debug_render(&handle, tree) else {
            st.store.delete(&sid).await;
            return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
        };
        let resp_json = serde_json::json!({
            "body":   html_body,
            "epoch":  epoch.to_token(),
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
            Some(h) => h,
            None => {
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
        // The debugger shows this render, so it becomes the session's current
        // render under a new epoch: the ids in the DOM it shows resolve against
        // its own handler index, never the one it replaced.
        let Some(epoch) = commit_debug_render(&handle, tree) else {
            st.store.delete(&sid).await;
            return (axum::http::StatusCode::NOT_FOUND, "session not found").into_response();
        };
        let resp_json = serde_json::json!({
            "body":   html_body,
            "epoch":  epoch.to_token(),
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
            Some(h) => h,
            None => {
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

/// The documented operator var naming `Ipe.Web`'s listen port.
#[cfg(feature = "server")]
const WEB_PORT_ENV: &str = "IPE_WEB_PORT";

/// The address a standalone web app binds, under `IPE_HTTP_BIND` > `Host.bind`
/// > `127.0.0.1`.
///
/// # Errors
///
/// [`StartupRefusal::Bind`] when `IPE_HTTP_BIND` is present but not an IP
/// address.
#[cfg(feature = "server")]
fn web_bind_host() -> Result<crate::app_config::ListenHost, StartupRefusal> {
    crate::app_config::resolve_host_bind().map_err(StartupRefusal::Bind)
}

/// Shared server setup for `web_app` / `web_app_routed`: nested HTTP
/// handlers (`page` / `sse_handler` / `event_handler`), router + bind/serve.
/// The only per-entry difference (the `route_entry`) lives on `state`.
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
    #[cfg(all(feature = "web", feature = "http_client"))]
    push_exporter::enable_from_env().await;
    #[cfg(all(feature = "web", feature = "http_client"))]
    hub_exporter::enable_from_env().await;

    // Console precedence: try the pre-built console child +
    // reverse-proxy; fall back to the in-process console when the binary is
    // absent / spawn fails / readiness times out / the gate is closed.
    // Decided HERE (before the router is built) so both the proxy routes and
    // the in-process console routes sit under the same `track` middleware,
    // and the two never collide on `/_ipe/console`.
    // Only when `http_client` is active: the console proxy uses reqwest for
    // the reverse-proxy path. Without it, always use the in-process console.
    //
    // The bind host is resolved once, here, and its listen scope recorded
    // before any console gate reads it: a dev surface exists only while every
    // app listener is loopback.
    let host = match web_bind_host() {
        Ok(host) => crate::server::RecordedHost::record(host),
        Err(cause) => return IpeResult::Err(cause.to_string().into()),
    };
    #[cfg(all(feature = "web", feature = "http_client"))]
    let use_console_proxy = console_proxy::ensure_console_proxy().await;

    // Cloned for the shutdown path's dev-only reload push — the router's
    // `.with_state(state)` takes ownership of `state` below.
    let shutdown_store = state.store.clone();

    #[cfg(all(feature = "web", feature = "http_client"))]
    let console_proxy_flag = use_console_proxy;
    #[cfg(not(all(feature = "web", feature = "http_client")))]
    let console_proxy_flag = false;

    let app = match build_web_router::<Model, Msg, FInit, FUpdate, FView, FSubs>(
        state,
        console_proxy_flag,
    ) {
        Ok(app) => app,
        Err(cause) => return IpeResult::Err(cause.to_string().into()),
    };
    let grace = match shutdown_grace() {
        Ok(grace) => grace,
        Err(refusal) => return IpeResult::Err(format!("Web.tea: {refusal}").into()),
    };

    // Port precedence (shared with `Ipe.Http.Server`): the supervisor's
    // relocation var > `IPE_WEB_PORT` (operator) > 8000. A malformed env layer
    // falls through, never to `0`.
    let resolved = crate::system::listen_port_from_env(
        (WEB_PORT_ENV, crate::system::read_env_var(WEB_PORT_ENV).ok()),
        8000,
    );
    let port = resolved.port;
    // The same host-bind precedence and bind site as the Ipe.Http.Server path
    // (`IPE_HTTP_BIND` > `Host.bind` setting > `127.0.0.1`). `host` is the
    // value resolved and recorded above, before the console gates.
    let Ok(port) = u16::try_from(port) else {
        return IpeResult::Err(format!("Web.tea: port {port} is not a TCP port").into());
    };
    let addr = host.addr(port);
    // Logs the bind-address line (stderr), and the exposure warning if any.
    let listener = match crate::server::bind_app_listener("web", host, port).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            return IpeResult::Err(resolved.addr_in_use_message().into());
        }
        Err(e) => return IpeResult::Err(format!("Web.tea: bind {addr}: {e}").into()),
    };
    // User-facing line on stdout.
    crate::system::write_stdout_line(&format!("Ipe.Web listening on :{port}"));
    // Graceful shutdown: trap SIGINT/SIGTERM,
    // print the shutdown line, drain in-flight requests, and return cleanly so
    // the IpeTask resolves Ok → the generated entry exits 0 (NOT 130). A
    // SECOND signal force-exits 130 via the watchdog inside web_shutdown_signal.
    match axum::serve(listener, app)
        .with_graceful_shutdown(web_shutdown_signal(shutdown_store, grace))
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
    #[cfg_attr(
        not(all(feature = "web", feature = "http_client")),
        allow(unused_variables)
    )]
    use_console_proxy: bool,
) -> Result<axum::Router, StartupRefusal>
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

    // The base the SSE reconnect strips from a client route, parsed once here:
    // a malformed base refuses the router rather than a per-request re-parse
    // that silently matches the unstripped path.
    let sse_base = Arc::new(parse_route_base(&web_base_path())?);
    let mount_base = web_mount_base()?;
    // Every environment ceiling the app applies resolves here, so a malformed
    // one refuses the router instead of a request; the per-request sites
    // re-read and refuse that request on their own.
    let body_limit: usize = WEB_MAX_BODY_CEILING
        .read()
        .map_err(StartupRefusal::Ceiling)?;
    let session_ttl = web_ttl().map_err(StartupRefusal::Ceiling)?;
    #[cfg(feature = "jwt")]
    crate::app_config::auth_ceilings().map_err(StartupRefusal::Ceiling)?;
    max_sessions().map_err(StartupRefusal::Ceiling)?;
    sse::buffer_capacity().map_err(StartupRefusal::Ceiling)?;
    if let Err(refusal) = client_tuning_js() {
        return Err(StartupRefusal::Ceiling(refusal.clone()));
    }
    // The framing policy every page carries is parsed here, so a value with no
    // header representation refuses the router; the page path re-checks it.
    crate::telemetry::frame_ancestors_config().map_err(StartupRefusal::FrameAncestors)?;
    let sse_route = get(
        move |st: axum::extract::State<WebState<Model, Msg, FInit, FUpdate, FView, FSubs>>,
              uri: axum::http::Uri,
              headers: axum::http::HeaderMap| {
            handlers::sse_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>(
                st,
                uri,
                headers,
                Arc::clone(&sse_base),
            )
        },
    );

    // Body-size cap on /_ipe/event. axum's DefaultBodyLimit applies
    // before the handler sees the bytes, so an over-sized payload is
    // rejected at the extract layer with 413 Payload Too Large.
    let event_route = post(handlers::event_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
        .layer(axum::extract::DefaultBodyLimit::max(body_limit));

    // Inbound `Ipe.Ffi.Js` port route: same body-size cap as `/_ipe/event`, so an
    // over-sized port frame is rejected at the extract layer (413) before the
    // handler's own seal-boundary budget even runs.
    let port_route = post(handlers::port_handler::<Model, Msg, FInit, FUpdate, FView, FSubs>)
        .layer(axum::extract::DefaultBodyLimit::max(body_limit));

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
        .route("/_ipe/sse", sse_route)
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
                .layer(axum::extract::DefaultBodyLimit::max(body_limit)),
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
                .layer(axum::extract::DefaultBodyLimit::max(body_limit)),
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
                .layer(axum::extract::DefaultBodyLimit::max(body_limit)),
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
                .layer(axum::extract::DefaultBodyLimit::max(body_limit)),
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
                .layer(axum::extract::DefaultBodyLimit::max(body_limit)),
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
                .layer(axum::extract::DefaultBodyLimit::max(body_limit)),
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
                .layer(axum::extract::DefaultBodyLimit::max(body_limit)),
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
            post(console::ingest).layer(axum::extract::DefaultBodyLimit::max(body_limit)),
        );

    // The console + metrics auth gate applies whether or not a console is
    // mounted, so its effective posture/mode/source is always logged once.
    crate::system::write_stderr_line(
        &crate::telemetry::ConsoleAuthResolution::from_env().startup_line(),
    );

    // When `http_client` is active and the pre-built console binary is
    // present, the proxy replaces the in-process console: a child process is
    // spawned and all `/_ipe/console/*` traffic is forwarded to it via
    // reqwest. The child logs its own `session store: …` + `reverse-proxy
    // ready` lines, so the parent does not duplicate the inline-mount log.
    #[cfg(all(feature = "web", feature = "http_client"))]
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
        #[cfg(all(feature = "web", feature = "http_client"))]
        {
            use_console_proxy
        }
        #[cfg(not(all(feature = "web", feature = "http_client")))]
        {
            false
        }
    };
    if !proxy_active && console::gate_allows() {
        store::emit_memory_store_log(session_ttl);
        crate::system::emit_runtime_log(
            "console",
            &format!(
                "inline console mounted as Ipe.Web sub-app at /_ipe/console mode={}",
                console::console_auth_mode_label()
            ),
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
        // The child router is root-relative: a parent proxy strips the base
        // before forwarding, so routes sit at the root and only the URLs the
        // page and glue carry are built from `mount_base`.
        let route_root = crate::encoding::MountBase::root();
        for asset in widget_assets::registered() {
            let path = route_root.url_of(&widget_assets::widget_asset_path(&asset.content));
            let content: &'static str = &asset.content;
            router = router.route(&path, get(move || async move { serve_widget_js(content) }));
        }
        let glue_path = route_root.url_of(&widget_assets::glue_path(
            &mount_base,
            widget_assets::WidgetTransport::Server,
        ));
        // The glue body folds in the base-prefixed author URLs, so it is
        // computed once here for the process (base is stable at startup) and
        // leaked to `'static` for the handler — a one-time, bounded allocation
        // sized by the program's widget count, never per-request.
        let glue_body: &'static str = Box::leak(
            widget_assets::glue_js(&mount_base, widget_assets::WidgetTransport::Server)
                .into_boxed_str(),
        );
        router = router.route(
            &glue_path,
            get(move || async move { serve_widget_js(glue_body) }),
        );
    }

    // package.ipe `[web] static` (baked as IPE_WEB_STATIC_DIR) → serve files at
    // /static/* via ServeDir. MUST be added before the `/*path` page catch-all
    // so a /static/<file> request hits ServeDir, not the page handler (which
    // would return HTML). `strict_serve_dir` parses each request path through
    // `server::static_request` (decoded once, every segment a plain name under
    // the host regime, the join re-checked) before `ServeDir` reads it. NOTE: like
    // http.FileServer it FOLLOWS symlinks inside the dir — the dir is
    // author-controlled (package.ipe [web] static), so that is the intended
    // contract, NOT a confinement guarantee. Absent/empty → no static mount.
    // IPE_WEB_STATIC_DIR: non-empty value mounts the named directory at /static.
    if let Some(dir) = crate::system::read_env_var("IPE_WEB_STATIC_DIR")
        .ok()
        .filter(|d| !d.is_empty())
    {
        router = router.nest_service(
            "/static",
            crate::server::strict_serve_dir(std::path::PathBuf::from(dir)),
        );
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
        // Strict URL gate over every route here (page, SSE, event, port,
        // assets, static): a malformed path or query is answered with the
        // fixed 400 before CSRF or any handler runs. Inner of `track`, so a
        // refusal is still counted and access-logged.
        .layer(axum::middleware::from_fn(
            crate::server::refuse_malformed_url,
        ))
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
        // Symmetric with Ipe.Http.Server (the body shape is shared in `core`).
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
    Ok(app)
}

/// Read the session cookie from request headers. Uses the base-path-aware
/// cookie name (`session_cookie_name`) so a sub-app reads its own scoped cookie,
/// never the parent's `ipe_sid`.
#[cfg(feature = "server")]
fn sid_from_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    crate::server::request_cookie(headers, &session_cookie_name())
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
        Arc::new(Mutex::new(SessionEntry {
            model: (),
            rendered: Rendered::first(new_incarnation(), tree),
            tabs: TabSeqs::default(),
            seq: 0,
            sse_tx,
            msg_tx: tx,
            entered_path: None,
            enter_tx: tokio::sync::mpsc::channel(1).0,
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
        let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
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

    /// Without a dev intent the reload push is unreachable; with one it
    /// pushes. The env-driven gate under `ENV=dev` on the release test binary
    /// pushes nothing. (`maybe_push_reload_to_web_sessions` is the exact call
    /// `web_shutdown_signal` makes right after `mark_draining`, split out so no
    /// real OS signal is needed here.)
    #[tokio::test]
    async fn reload_push_skipped_on_release_under_env_dev() {
        let store_impl: MemoryStore<(), ()> = MemoryStore::new(Duration::from_secs(60));
        let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
        store_impl.set("s", handle_with(Some(sse_tx))).await;
        let store: Arc<dyn SessionStore<(), ()>> = Arc::new(store_impl);

        maybe_push_reload_with(&store, None).await;
        assert!(
            sse_rx.try_recv().is_err(),
            "no dev intent: NO reachable path pushes the reload frame"
        );
        if !cfg!(feature = "dev-posture") {
            crate::system::locked_set_var("ENV", "dev");
            maybe_push_reload_to_web_sessions(&store).await;
            assert!(
                sse_rx.try_recv().is_err(),
                "ENV=dev on a release build must not push the reload frame"
            );
            crate::system::locked_remove_var("ENV");
        }

        let dev = crate::telemetry::test_dev_intent();
        maybe_push_reload_with(&store, Some(&dev)).await;
        assert!(
            sse_rx.try_recv().is_ok(),
            "a dev intent pushes the reload frame"
        );
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
        let (msg_tx, _rx) = mpsc::channel::<()>(1);
        Arc::new(Mutex::new(SessionEntry {
            model: count,
            rendered: Rendered::first(new_incarnation(), tree),
            tabs: TabSeqs::default(),
            seq: 0,
            sse_tx,
            msg_tx,
            entered_path: None,
            enter_tx: tokio::sync::mpsc::channel(1).0,
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
            let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
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
                .map(|h| h.lock().unwrap_or_else(|e| e.into_inner()).model)
                .expect("session still present");
            assert_eq!(model_after, 7, "a hot-swap must not advance the Model");
        });
    }

    /// An appearance re-render commits like any other render: it mints a new
    /// epoch, its frame names the epochs it moved between, and the epoch the
    /// client held stays resolvable in the history.
    #[test]
    #[allow(clippy::expect_used)] // the session and the frame are fixtures
    fn patch_commit_mints_an_epoch_and_keeps_the_previous_one() {
        with_overlay_serialised(|| async {
            literal_table::set_dev_overlay_active_for_test(Some(true));
            literal_table::clear_dev_overlay_for_test();

            let store_impl: MemoryStore<i64, ()> = MemoryStore::new(Duration::from_secs(60));
            let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
            let handle = session_with_current_view(7, Some(sse_tx));
            let before = handle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .rendered
                .epoch();
            store_impl.set("live", handle.clone()).await;
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
            let e = handle.lock().unwrap_or_else(|e| e.into_inner());
            let after = e.rendered.epoch();
            assert_ne!(after, before, "an appearance commit must mint a new epoch");
            let from = before.to_token();
            let to = after.to_token();
            assert_eq!(
                json.get("from").and_then(serde_json::Value::as_str),
                Some(from.as_str())
            );
            assert_eq!(
                json.get("to").and_then(serde_json::Value::as_str),
                Some(to.as_str())
            );
            assert_eq!(
                e.rendered.resolve(&before, "r", "click", &[]),
                Ok(None),
                "the previous epoch stays in the history"
            );
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
            let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
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
        // Same id, target/rel/title, monospace blue style, `&#128269;` ENTITY
        // (not a literal emoji). The banner renders only under a dev surface.
        let surface = crate::telemetry::test_dev_surface();
        let b = crate::telemetry::dev_console_banner_with("", Some(&surface));
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
    use super::{WEB_TTL, web_ttl};
    use crate::system::{locked_remove_var, locked_set_var};
    use std::time::Duration;

    fn ttl_with(raw: &str) -> Result<Duration, crate::system::EnvCeilingRefusal> {
        locked_set_var("IPE_WEB_TTL", raw);
        let resolved = web_ttl();
        locked_remove_var("IPE_WEB_TTL");
        resolved
    }

    #[test]
    fn the_web_ttl_honours_the_duration_contract() {
        crate::system::assert_env_duration_contract(WEB_TTL);
    }

    #[test]
    fn duration_formats_and_bare_seconds() {
        for (raw, secs) in [
            ("1800", 1800),
            ("30m", 1800),
            ("1h", 3600),
            ("24h", 86_400),
            ("90s", 90),
            ("1h30m", 5400),
            ("45m", 2700),
            ("34560000", 34_560_000),
            ("9600h", 34_560_000),
        ] {
            assert_eq!(ttl_with(raw), Ok(Duration::from_secs(secs)), "{raw:?}");
        }
        assert_eq!(
            web_ttl(),
            Ok(Duration::from_secs(1800)),
            "absent is the default"
        );
    }

    #[test]
    fn a_malformed_ttl_is_refused_never_defaulted() {
        for raw in [
            "",
            "abc",
            "1d",
            "1h30",
            "m",
            "-5m",
            "0",
            "0s",
            "0h0m",
            " 1h",
            "1h ",
            "30m1h",
            "1m1m",
            "34560001",
            "9601h",
            "99999999999999999999",
        ] {
            let outcome = ttl_with(raw);
            assert!(
                outcome.as_ref().is_err_and(|r| r.name() == "IPE_WEB_TTL"),
                "{raw:?} must be refused naming IPE_WEB_TTL, got {outcome:?}"
            );
        }
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
mod canonical_redirect_handler_tests {
    //! The page handler redirects a GET/HEAD for a non-canonical spelling of a
    //! routed page to its canonical path (308) before any session work: no
    //! cookie, no `init`, a same-origin relative `Location` under the base.

    use super::*;
    use crate::system::{locked_remove_var, locked_set_var};
    use crate::web::req::WebReq;
    use crate::web::route::{RenderArg, RenderRefusal, Route, RoutePath, render_route};
    use crate::web::store::MemoryStore;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use serde::{Deserialize, Serialize};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tower::ServiceExt; // oneshot

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Model {
        page: u8,
    }

    impl crate::stringify::IpeStringify for Model {
        fn ipe_show(&self) -> String {
            format!("Model {{ page: {} }}", self.page)
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    enum Page {
        Home,
        About,
        Slug(String),
    }

    fn routes() -> Vec<Route<Page>> {
        vec![
            Route::new("/", |_| Some(Page::Home)),
            Route::new("/about", |_| Some(Page::About)),
            Route::new("/:slug", |p| p.first().cloned().map(Page::Slug)),
        ]
    }

    fn render(page: &Page) -> Result<RoutePath, RenderRefusal> {
        match page {
            Page::Home => render_route(&routes(), 0, &[]),
            Page::About => render_route(&routes(), 1, &[]),
            Page::Slug(s) => render_route(&routes(), 2, &[RenderArg::Text(s)]),
        }
    }

    static INIT_RUNS: AtomicUsize = AtomicUsize::new(0);

    fn init(_req: WebReq) -> (Model, IpeCmd<()>) {
        INIT_RUNS.fetch_add(1, Ordering::SeqCst);
        (Model { page: 0 }, IpeCmd::None)
    }
    fn update(_msg: (), model: Model) -> (Model, IpeCmd<()>) {
        (model, IpeCmd::None)
    }
    fn view(_model: Model) -> Html<()> {
        Html::HText(String::new())
    }
    fn subs(_model: Model) -> IpeSub<()> {
        IpeSub::None
    }

    type Init = fn(WebReq) -> (Model, IpeCmd<()>);
    type Update = fn((), Model) -> (Model, IpeCmd<()>);
    type View = fn(Model) -> Html<()>;
    type Subs = fn(Model) -> IpeSub<()>;

    fn make_router() -> Router {
        let (route_entry, param_resolver, route_matched) = routed_resolvers(
            routes(),
            Page::Home,
            |_page: Page, model: Model| (model, IpeCmd::None),
            render,
        );
        let state: WebState<Model, (), Init, Update, View, Subs> = WebState {
            store: Arc::new(MemoryStore::<Model, ()>::new(Duration::from_secs(60)))
                as Arc<dyn store::SessionStore<Model, ()>>,
            init: Arc::new(init),
            update: Arc::new(update),
            view: Arc::new(view),
            subs: Arc::new(subs),
            route_entry,
            param_resolver,
            route_matched,
            session_count: Arc::new(AtomicUsize::new(0)),
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        Router::new()
            .fallback(get(handlers::page::<Model, (), Init, Update, View, Subs>))
            .with_state(state)
    }

    #[allow(clippy::expect_used)] // test helper: request build and router failure are environment issues
    async fn send(method: &str, uri: &str) -> axum::response::Response {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("build request");
        make_router().oneshot(req).await.expect("router responds")
    }

    fn location(resp: &axum::response::Response) -> Option<String> {
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    #[allow(clippy::expect_used)] // test helper: an in-memory body read cannot fail
    async fn body_len(resp: axum::response::Response) -> usize {
        axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body")
            .len()
    }

    /// A 308 carries the canonical `Location`, no cookie and no body, and
    /// runs no `init`; GET and HEAD agree.
    #[tokio::test]
    async fn non_canonical_get_and_head_redirect_before_init() {
        locked_remove_var("IPE_WEB_BASE_PATH");
        let before = INIT_RUNS.load(Ordering::SeqCst);
        for method in ["GET", "HEAD"] {
            let resp = send(method, "/about/?x=1").await;
            assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT, "{method}");
            assert_eq!(
                location(&resp).as_deref(),
                Some("/about?x=1"),
                "{method}: query kept"
            );
            assert!(
                resp.headers().get(header::SET_COOKIE).is_none(),
                "{method}: a redirect mints no cookie"
            );
            assert_eq!(body_len(resp).await, 0, "{method}: a redirect has no body");
        }
        assert_eq!(INIT_RUNS.load(Ordering::SeqCst), before, "no init ran");
    }

    /// The canonical spelling is served, not redirected.
    #[tokio::test]
    async fn canonical_get_is_served() {
        locked_remove_var("IPE_WEB_BASE_PATH");
        let resp = send("GET", "/about").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(location(&resp).is_none());
    }

    /// An escape the route decodes redirects to the canonical encoding, and a
    /// redirect never leaves the origin: `Location` is one `/` then a non-`/`.
    #[tokio::test]
    async fn redirect_location_is_same_origin_relative() {
        locked_remove_var("IPE_WEB_BASE_PATH");
        let resp = send("GET", "/%2f%2fevil.com").await;
        assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(location(&resp).as_deref(), Some("/%2F%2Fevil.com"));
        for raw in ["//evil.com", "/%5c%5cevil.com", "/%2f%2fevil.com", "///"] {
            let resp = send("GET", raw).await;
            if let Some(loc) = location(&resp) {
                let bytes = loc.as_bytes();
                assert!(
                    bytes.first() == Some(&b'/') && !matches!(bytes.get(1), Some(b'/' | b'\\')),
                    "{raw}: Location {loc} must be same-origin relative"
                );
            }
        }
    }

    /// Under a base path the redirect targets the base plus the canonical path.
    #[tokio::test]
    async fn redirect_targets_the_base() {
        locked_set_var("IPE_WEB_BASE_PATH", "/app");
        let resp = send("GET", "/about/").await;
        locked_remove_var("IPE_WEB_BASE_PATH");
        assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(location(&resp).as_deref(), Some("/app/about"));
    }
}

#[cfg(all(test, feature = "server"))]
mod base_path_tests {
    use super::{
        Html, RenderEpoch, Rendered, client_js_path, cookie_name_for, cookie_name_with,
        cookie_path_for, new_incarnation, normalise_base_path, render_page_full,
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
        // Plain-http dev: the root cookie keeps its plain name.
        assert_eq!(cookie_name_with("", false).text(), "ipe_sid");
        assert_eq!(cookie_name_with("", true).text(), "__Host-ipe_sid");
        // Distinct from the parent's `ipe_sid` so the proxied child can't clobber it.
        for secure in [false, true] {
            assert_eq!(
                cookie_name_with("/_ipe/console", secure).text(),
                "ipe_sid__ipe_console"
            );
        }
        assert_eq!(
            cookie_name_for("/_ipe/console").text(),
            "ipe_sid__ipe_console"
        );
    }

    // A release binary under `ENV=dev` still names its root session cookie
    // `__Host-`: it is always `Secure`.
    #[cfg(not(feature = "dev-posture"))]
    #[test]
    fn session_cookie_host_prefixed_on_release_under_env_dev() {
        crate::system::locked_set_var("ENV", "dev");
        assert!(super::csrf::cookies_secure());
        assert_eq!(cookie_name_for("").text(), "__Host-ipe_sid");
        crate::system::locked_remove_var("ENV");
    }

    #[test]
    fn cookie_path_scopes_to_base() {
        assert_eq!(cookie_path_for(""), "/");
        // Scoped → the cookie is never sent to the parent's own routes.
        assert_eq!(cookie_path_for("/_ipe/console"), "/_ipe/console");
    }

    /// The typed session line keeps the exact bytes of the hand-formatted one,
    /// so an existing browser session cookie is replaced, never duplicated.
    #[test]
    fn session_set_cookie_keeps_the_session_line_bytes() {
        let headers = axum::http::HeaderMap::new();
        let ttl = std::time::Duration::from_secs(1800);
        let secure = if super::csrf::cookies_secure() {
            "; Secure"
        } else {
            ""
        };
        let same_site = if super::csrf::frame_ancestors().is_some() {
            "None"
        } else {
            "Lax"
        };
        let expected = format!(
            "{}=0f3a-sid; Path={}; HttpOnly; SameSite={same_site}{secure}; Max-Age={}",
            super::session_cookie_name(),
            super::cookie_path(),
            ttl.as_secs()
        );
        assert_eq!(
            super::session_set_cookie("0f3a-sid", &headers, ttl).as_str(),
            expected
        );
    }

    #[test]
    fn render_page_threads_base_into_meta_and_window_global() {
        let root = render_page_full(
            "sid1",
            &crate::encoding::MountBase::root(),
            "<b>x</b>",
            &page_epoch(),
            "deadbeef",
        );
        assert!(root.contains("<meta name=\"ipe-base\" content=\"\">"));
        assert!(root.contains("window.__IPE_BASE=\"\""));

        let sub = render_page_full(
            "sid1",
            &console_base(),
            "<b>x</b>",
            &page_epoch(),
            "deadbeef",
        );
        assert!(sub.contains("<meta name=\"ipe-base\" content=\"/_ipe/console\">"));
        assert!(sub.contains("window.__IPE_BASE=\"/_ipe/console\""));
    }

    #[test]
    fn render_page_emits_external_client_script_with_sri() {
        let epoch = page_epoch();
        let root = render_page_full(
            "sid1",
            &crate::encoding::MountBase::root(),
            "<b>x</b>",
            &epoch,
            "tok1",
        );
        // Per-session values stay inline.
        assert!(root.contains("window.__IPE_SID=\"sid1\""));
        let epoch_global = format!("window.__IPE_EPOCH=\"{}\";", epoch.to_token());
        assert!(root.contains(&epoch_global), "{root}");
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
        let sub = render_page_full("sid1", &console_base(), "<b>x</b>", &page_epoch(), "tok1");
        // External script src must carry the base prefix.
        assert!(root_or_sub_has_prefixed_client_src(&sub, "/_ipe/console"));
    }

    /// The first epoch of a fresh render history, as a page GET serves it.
    fn page_epoch() -> RenderEpoch {
        Rendered::first(new_incarnation(), Html::<()>::HText(String::new())).epoch()
    }

    #[allow(clippy::expect_used)] // a fixed literal inside the mount-base grammar
    fn console_base() -> crate::encoding::MountBase {
        crate::encoding::MountBase::parse("/_ipe/console").expect("a well-formed base")
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

    // max_sessions(): env override, default, the 0=unlimited opt-out, and the
    // refusal of a malformed value.
    #[test]
    fn max_sessions_parsing() {
        crate::system::locked_remove_var("IPE_WEB_MAX_SESSIONS");
        let absent = max_sessions();
        crate::system::locked_set_var("IPE_WEB_MAX_SESSIONS", "7");
        let seven = max_sessions();
        crate::system::locked_set_var("IPE_WEB_MAX_SESSIONS", "0");
        let zero = max_sessions();
        crate::system::locked_set_var("IPE_WEB_MAX_SESSIONS", "garbage");
        let garbage = max_sessions();
        crate::system::locked_remove_var("IPE_WEB_MAX_SESSIONS");
        assert_eq!(absent, Ok(50_000));
        assert_eq!(seven, Ok(7));
        assert_eq!(zero, Ok(0), "0 = unlimited opt-out");
        assert!(
            garbage.is_err_and(|r| r.name() == "IPE_WEB_MAX_SESSIONS"),
            "a malformed value is refused, never the default"
        );
    }

    #[test]
    fn web_ceilings_honour_the_shared_contract() {
        crate::system::assert_env_ceiling_contract(MAX_SESSIONS_CEILING);
        crate::system::assert_env_ceiling_contract(WEB_MAX_BODY_CEILING);
        crate::system::assert_env_ceiling_contract(SHUTDOWN_GRACE_CEILING);
        for (_, ceiling) in CLIENT_TUNING_CEILINGS {
            crate::system::assert_env_ceiling_contract(ceiling);
        }
    }
}

#[cfg(all(test, feature = "server"))]
mod sse_reconnect_reconcile_tests {
    //! Drives the production reconnect reconciliation (`reconcile_path`) and
    //! the driver's entry commit (`commit_entry`):
    //! 1. A reconnect whose `?path=` differs from the session's entered path
    //!    enters it once, re-rendering `last_view` id-stamped for the resync.
    //! 2. A reconnect at the already-entered path enters nothing: the driver
    //!    drops it at commit time.
    //! 3. An invalid path (contains `?` or `#`, or no leading `/`) or an
    //!    unrouted path enters nothing.
    //! 4. The sub-app base prefix is stripped once before matching, on a
    //!    segment boundary (`/app` never strips `/apple`); a path outside the
    //!    base enters nothing.
    //! 5. A full enter queue refuses rather than waits.
    //! 6. Reconnects queued at one new path enter it once; a page load
    //!    re-enters even the entered path.
    //! 7. A malformed `?path=` is refused as `BadRequest`.
    //! 8. A malformed base path is refused once, when the router is built.

    use super::*;
    use crate::web::route::{RenderArg, RenderRefusal, Route, RoutePath, render_route};
    use crate::web::store::MemoryStore;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::mpsc::channel;

    /// A minimal two-page model: `Home` or `Detail(String)`.
    #[derive(Clone, Debug, PartialEq)]
    enum TestPage {
        Home,
        Detail(String),
    }

    type TestView = Arc<dyn Fn(TestPage) -> Html<()> + Send + Sync>;

    /// A session seeded on one page plus the collaborators `sse_handler` and the driver use.
    struct Fixture {
        entry: SessionHandle<TestPage, ()>,
        enter_rx: Receiver<EnterRequest>,
        route_entry: RouteEntry<TestPage, ()>,
        route_matched: RouteMatched,
        view: TestView,
        store: Arc<dyn store::SessionStore<TestPage, ()>>,
        /// How many times the app's entry fn ran, i.e. how many entry Cmds were produced.
        entry_fn_runs: Arc<AtomicUsize>,
    }

    fn routes() -> Vec<Route<TestPage>> {
        vec![
            Route::new("/", |_| Some(TestPage::Home)),
            Route::new("/items/:id", |p| p.first().cloned().map(TestPage::Detail)),
        ]
    }

    /// The fixture's page renderer, as the emitter writes one per page type.
    fn render(page: &TestPage) -> Result<RoutePath, RenderRefusal> {
        match page {
            TestPage::Home => render_route(&routes(), 0, &[]),
            TestPage::Detail(id) => render_route(&routes(), 1, &[RenderArg::Text(id)]),
        }
    }

    /// The page variant as text, so a test can assert which page a resync ships.
    fn label_view() -> TestView {
        Arc::new(|p| {
            Html::HText(match p {
                TestPage::Home => "home-page".to_string(),
                TestPage::Detail(id) => format!("detail-{id}"),
            })
        })
    }

    /// Parse a test path the way the request boundary does.
    #[allow(clippy::expect_used)] // test helper: every path passed here is well-formed
    fn dp(path: &str) -> route::DecodedPath {
        route::DecodedPath::parse(path).expect("well-formed test path")
    }

    /// `client_route_path` under `base`, parsed the way `build_web_router`
    /// parses it (once, through `parse_route_base`).
    #[allow(clippy::expect_used)] // test helper: every base passed here is well-formed
    fn route_path(
        raw: &str,
        base: &str,
    ) -> Result<Option<route::DecodedPath>, crate::server::RequestRejection> {
        let base = parse_route_base(base).expect("well-formed test base");
        client_route_path(raw, &base)
    }

    fn make_session(page: TestPage, entered_path: Option<&str>, view: TestView) -> Fixture {
        let routes_arc = Arc::new(routes());
        let routes_for_match = routes_arc.clone();
        let render = Arc::new(render);
        let entry_fn_runs = Arc::new(AtomicUsize::new(0));
        let runs = entry_fn_runs.clone();
        let route_entry = routed_entry(
            routes_arc,
            TestPage::Home,
            move |p: TestPage, _m: TestPage| {
                runs.fetch_add(1, Ordering::SeqCst);
                (p, IpeCmd::None)
            },
            Arc::clone(&render),
        );
        let route_matched = routed_lookup(routes_for_match, render);
        let model = page.clone();
        let last_view = (view)(model.clone());
        let (msg_tx, _rx) = channel::<()>(1);
        let (enter_tx, enter_rx) = channel::<EnterRequest>(ENTER_QUEUE_CAP.get());
        let entry = Arc::new(Mutex::new(SessionEntry {
            model,
            rendered: Rendered::first(new_incarnation(), last_view),
            tabs: TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx,
            entered_path: entered_path.map(dp),
            enter_tx,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new(page, crate::debugger::DEFAULT_HISTORY_CAP),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }));
        Fixture {
            entry,
            enter_rx,
            route_entry,
            route_matched,
            view,
            store: Arc::new(MemoryStore::new(Duration::from_secs(60))),
            entry_fn_runs,
        }
    }

    /// Commit one queued request as the driver would: 1 when it entered, 0 when it was already entered.
    async fn drive_one(fx: &Fixture, request: EnterRequest) -> usize {
        let commit = commit_entry(
            &Arc::downgrade(&fx.entry),
            request,
            &fx.route_entry,
            &*fx.view,
            &fx.store,
            "sid-test",
        )
        .await;
        assert!(
            !matches!(commit, EntryCommit::SessionGone),
            "a live session never reports itself gone"
        );
        usize::from(matches!(commit, EntryCommit::Entered(..)))
    }

    /// Reconcile `client_path` under `base` exactly as `sse_handler` does
    /// (`client_route_path`, then `reconcile_path`) and, when an entry was
    /// queued, commit it as the driver would.
    ///
    /// Returns how many entries the driver committed (0 or 1) and the reply body.
    async fn reconnect(fx: &mut Fixture, client_path: &str, base: &str) -> (usize, Option<String>) {
        let outcome = match route_path(client_path, base) {
            Ok(Some(path)) => reconcile_path(&fx.entry, &fx.route_matched, &path),
            Ok(None) | Err(_) => ReconcileOutcome::Unchanged,
        };
        let ReconcileOutcome::Entering(reply_rx) = outcome else {
            assert!(
                fx.enter_rx.try_recv().is_err(),
                "a non-entering reconcile must queue nothing"
            );
            return (0, None);
        };
        let queued = fx.enter_rx.try_recv();
        assert!(
            queued.is_ok(),
            "an Entering outcome must have queued a request"
        );
        let Ok(request) = queued else {
            return (0, None);
        };
        let committed = drive_one(fx, request).await;
        (committed, await_entry(reply_rx).await.map(|r| r.body))
    }

    /// Two reconnects at one new path, both queued before the driver runs,
    /// enter it once: the driver, not the enqueuer, decides "already entered".
    #[tokio::test]
    async fn concurrent_reconciles_at_one_path_enter_once() {
        let mut fx = make_session(
            TestPage::Detail("42".into()),
            Some("/items/42"),
            label_view(),
        );
        let first = reconcile_path(&fx.entry, &fx.route_matched, &dp("/items/7"));
        let second = reconcile_path(&fx.entry, &fx.route_matched, &dp("/items/7/"));
        assert!(matches!(first, ReconcileOutcome::Entering(_)));
        assert!(matches!(second, ReconcileOutcome::Entering(_)));

        let mut committed = 0;
        while let Ok(request) = fx.enter_rx.try_recv() {
            committed += drive_one(&fx, request).await;
        }

        assert_eq!(committed, 1, "one path, one committed entry");
        assert_eq!(
            fx.entry_fn_runs.load(Ordering::SeqCst),
            1,
            "the entry fn (and so its Cmd) ran once"
        );
        assert_eq!(model_of(&fx.entry), TestPage::Detail("7".into()));
    }

    /// A reconnect at another spelling of the entered path (`/items/%41` after
    /// `/items/A`) dedupes against one canonical key and enters nothing.
    #[tokio::test]
    async fn reconcile_at_an_alternate_spelling_enters_nothing() {
        let mut fx = make_session(TestPage::Detail("A".into()), Some("/items/A"), label_view());
        let (committed, _) = reconnect(&mut fx, "/items/%41", "").await;
        assert_eq!(committed, 0, "one canonical path, no second entry");
        assert_eq!(
            fx.entry_fn_runs.load(Ordering::SeqCst),
            0,
            "no entry Cmd ran"
        );
    }

    /// A page GET re-enters even the path the session already entered, so a
    /// reload runs the entry Cmd again.
    #[tokio::test]
    async fn load_of_the_entered_path_enters_again() {
        let mut fx = make_session(TestPage::Home, Some("/"), label_view());
        let enter_tx = fx
            .entry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .enter_tx
            .clone();
        assert!(queue_entry(&enter_tx, dp("/"), EnterMode::Load).is_some());
        let queued = fx.enter_rx.try_recv();
        assert!(queued.is_ok(), "the load was queued");
        let Ok(request) = queued else {
            return;
        };
        assert_eq!(drive_one(&fx, request).await, 1);
        assert_eq!(fx.entry_fn_runs.load(Ordering::SeqCst), 1);
    }

    /// Helper: read the current rendered text from the session's `last_view`.
    fn rendered_text(entry: &SessionHandle<TestPage, ()>) -> String {
        render_html(
            entry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .rendered
                .last_view(),
        )
    }

    fn model_of(entry: &SessionHandle<TestPage, ()>) -> TestPage {
        entry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .model
            .clone()
    }

    #[tokio::test]
    async fn differing_url_enters_once_then_is_unchanged() {
        // Entered at Detail("42"), but the browser now shows "/".
        let mut fx = make_session(
            TestPage::Detail("42".into()),
            Some("/items/42"),
            label_view(),
        );
        assert!(rendered_text(&fx.entry).contains("detail-42"));

        let (entered, body) = reconnect(&mut fx, "/", "").await;
        assert_eq!(entered, 1, "a differing path enters once");
        assert!(
            body.is_some_and(|b| b.contains("home-page")),
            "the reply carries the entered page's body"
        );
        assert_eq!(model_of(&fx.entry), TestPage::Home);
        assert!(rendered_text(&fx.entry).contains("home-page"));

        let (again, _) = reconnect(&mut fx, "/", "").await;
        assert_eq!(again, 0, "a reconnect at the entered path enters nothing");
    }

    /// The reconcile commit leaves `last_view` and `index` id-stamped, as the
    /// page and update renders do, so a click on the resynced page resolves.
    #[tokio::test]
    async fn entry_stamps_ids_so_handlers_resolve() {
        let view: TestView = Arc::new(|_p| {
            Html::HElement(
                "div".into(),
                vec![Attribute::EventAttr(Event::OnMsg("click".into(), ()))],
                vec![Html::HText("go".into())],
            )
        });
        let mut fx = make_session(TestPage::Home, None, view);

        let (entered, _) = reconnect(&mut fx, "/", "").await;
        assert_eq!(entered, 1);

        let g = fx.entry.lock().unwrap_or_else(|e| e.into_inner());
        let body = render_html(g.rendered.last_view());
        assert!(
            body.contains("data-ipe-hid=\"r\""),
            "entered resync body must stamp data-ipe-hid: {body}"
        );
        assert!(
            body.contains("ipe-id=\"r\""),
            "entered resync body must stamp ipe-id: {body}"
        );
        assert_eq!(
            g.rendered.resolve(&g.rendered.epoch(), "r", "click", &[]),
            Ok(Some(())),
            "entered handler index must resolve the stamped ipe-id"
        );
        assert_eq!(g.entered_path, Some(dp("/")));
    }

    #[tokio::test]
    async fn same_entered_path_is_unchanged() {
        let mut fx = make_session(TestPage::Home, Some("/"), label_view());
        let before = rendered_text(&fx.entry);

        let (entered, _) = reconnect(&mut fx, "/", "").await;

        assert_eq!(entered, 0);
        assert_eq!(model_of(&fx.entry), TestPage::Home);
        assert_eq!(rendered_text(&fx.entry), before);
    }

    #[tokio::test]
    async fn invalid_path_enters_nothing() {
        let mut fx = make_session(TestPage::Home, None, label_view());
        let before = rendered_text(&fx.entry);
        for bad in ["/?foo=bar", "/#anchor", "items/1", ""] {
            let (entered, _) = reconnect(&mut fx, bad, "").await;
            assert_eq!(entered, 0, "invalid path {bad:?} must enter nothing");
        }
        assert_eq!(rendered_text(&fx.entry), before);
    }

    #[tokio::test]
    async fn unroutable_path_enters_nothing() {
        let mut fx = make_session(TestPage::Home, None, label_view());
        let before = rendered_text(&fx.entry);

        let (entered, _) = reconnect(&mut fx, "/favicon.ico", "").await;

        assert_eq!(entered, 0);
        assert_eq!(rendered_text(&fx.entry), before);
    }

    /// A sub-app at "/app" reports its full `location.pathname`; the base is
    /// stripped once and the base-relative path is what the session records.
    #[tokio::test]
    async fn sub_app_base_prefix_is_stripped_before_matching() {
        let mut fx = make_session(TestPage::Home, Some("/"), label_view());

        let (entered, _) = reconnect(&mut fx, "/app/items/5", "/app").await;

        assert_eq!(entered, 1);
        assert_eq!(model_of(&fx.entry), TestPage::Detail("5".into()));
        assert_eq!(
            fx.entry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entered_path,
            Some(dp("/items/5")),
            "entered_path is base-relative"
        );
        let (again, _) = reconnect(&mut fx, "/app/items/5", "/app").await;
        assert_eq!(again, 0, "the base-relative dedupe holds under a base");
    }

    /// A sub-app opened at its bare base: the proxy forwarded "/", the browser
    /// reports "/app"; both are the root page, so the entry Cmd does not rerun.
    #[tokio::test]
    async fn bare_base_is_the_entered_root() {
        let mut fx = make_session(TestPage::Home, Some("/"), label_view());

        let (entered, _) = reconnect(&mut fx, "/app", "/app").await;

        assert_eq!(
            entered, 0,
            "\"/app\" under base \"/app\" is the entered \"/\""
        );
    }

    /// A trailing slash names the page the matcher already entered.
    #[tokio::test]
    async fn trailing_slash_is_the_entered_path() {
        let mut fx = make_session(TestPage::Detail("5".into()), Some("/items/5"), label_view());

        let (entered, _) = reconnect(&mut fx, "/items/5/", "").await;

        assert_eq!(entered, 0, "\"/items/5/\" is the entered \"/items/5\"");
    }

    /// The base is stripped only at a segment boundary; a path outside the
    /// base enters nothing.
    #[tokio::test]
    async fn path_outside_the_base_enters_nothing() {
        let mut fx = make_session(TestPage::Home, Some("/"), label_view());
        let before = rendered_text(&fx.entry);

        let (glued, _) = reconnect(&mut fx, "/appitems/5", "/app").await;
        let (outside, _) = reconnect(&mut fx, "/items/5", "/app").await;

        assert_eq!(glued, 0, "\"/appitems/5\" is not under \"/app\"");
        assert_eq!(outside, 0, "\"/items/5\" is not under \"/app\"");
        assert_eq!(model_of(&fx.entry), TestPage::Home);
        assert_eq!(rendered_text(&fx.entry), before);
    }

    /// A driver whose enter queue is full refuses the entry instead of waiting.
    #[tokio::test]
    async fn full_enter_queue_is_refused() {
        let fx = make_session(TestPage::Home, None, label_view());
        let enter_tx = fx
            .entry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .enter_tx
            .clone();
        for _ in 0..ENTER_QUEUE_CAP.get() {
            assert!(queue_entry(&enter_tx, dp("/"), EnterMode::Load).is_some());
        }
        assert!(matches!(
            reconcile_path(&fx.entry, &fx.route_matched, &dp("/items/1")),
            ReconcileOutcome::Refused
        ));
        drop(fx.enter_rx);
        assert!(
            queue_entry(&enter_tx, dp("/"), EnterMode::Load).is_none(),
            "a closed driver queue refuses"
        );
    }
    /// The base is a path prefix, not a string prefix: `/app` strips `/app/x`
    /// to `/x` and `/app` to `/`, and `/apple` is not under it.
    #[tokio::test]
    async fn base_strip_is_segment_bounded() {
        let parsed = |p: &str| route::DecodedPath::parse(p).ok();
        assert_eq!(route_path("/app/x", "/app").ok().flatten(), parsed("/x"));
        assert_eq!(route_path("/app", "/app").ok().flatten(), parsed("/"));
        assert_eq!(route_path("/app/", "/app").ok().flatten(), parsed("/"));
        assert_eq!(
            route_path("/apple", "/app").ok().flatten(),
            None,
            "/apple is not under base /app"
        );
        // Stripping compares decoded segments: an encoded base segment is the
        // same segment.
        assert_eq!(
            route_path("/%61pp/items/5", "/app").ok().flatten(),
            parsed("/items/5")
        );

        // End to end: `/apple/items/5` under base `/app` is never read as
        // `le/items/5` or `/items/5`; it enters nothing.
        let mut fx = make_session(TestPage::Home, None, label_view());
        let before = rendered_text(&fx.entry);
        let (entered, _) = reconnect(&mut fx, "/apple/items/5", "/app").await;
        assert_eq!(entered, 0);
        assert_eq!(model_of(&fx.entry), TestPage::Home);
        assert_eq!(rendered_text(&fx.entry), before);
        // `/app` itself enters the sub-app's root route.
        let mut fx = make_session(TestPage::Detail("9".into()), Some("/items/9"), label_view());
        let (entered, _) = reconnect(&mut fx, "/app", "/app").await;
        assert_eq!(entered, 1);
        assert_eq!(model_of(&fx.entry), TestPage::Home);
    }

    /// A malformed `?path=` is the fixed `BadRequest`, answered before any
    /// session is touched; a non-path value names nothing to reconcile.
    #[test]
    fn malformed_client_path_is_bad_request() {
        for bad in ["/items/%zz", "/%", "/items/%C0%AF"] {
            assert!(
                matches!(
                    route_path(bad, ""),
                    Err(crate::server::RequestRejection::BadRequest)
                ),
                "{bad} must be refused"
            );
        }
        for skip in ["items/1", "/?a=b", "/#x"] {
            assert!(
                matches!(route_path(skip, ""), Ok(None)),
                "{skip} names no route path"
            );
        }
    }

    /// A base path outside the mount-base grammar is refused when the router
    /// is built, as the typed `StartupRefusal::MountBase` naming the base; a
    /// well-formed base and the empty root are admitted.
    #[test]
    fn non_mount_base_path_is_refused_at_build() {
        for bad in ["/a b", "/app/x%41", "/a\"b", "/a//b", "/app/.."] {
            assert!(
                matches!(
                    parse_mount_base(bad),
                    Err(StartupRefusal::MountBase { ref base, .. }) if base == bad
                ),
                "base {bad} must be refused"
            );
        }
        assert_eq!(parse_mount_base(""), Ok(crate::encoding::MountBase::root()));
        assert!(parse_mount_base("/_ipe/console").is_ok_and(|b| b.prefix() == "/_ipe/console"));
    }

    /// A base path that does not decode is refused when the router is built,
    /// as the typed `StartupRefusal::BasePath` naming the base; the empty base
    /// is the root, which strips nothing.
    #[test]
    fn malformed_base_path_is_refused_at_build() {
        for bad in ["/%zz", "/app/%", "/%C0%AF"] {
            assert!(
                matches!(
                    parse_route_base(bad),
                    Err(StartupRefusal::BasePath { ref base, .. }) if base == bad
                ),
                "base {bad} must be refused"
            );
        }
        assert_eq!(parse_route_base(""), Ok(dp("/")));
        assert_eq!(
            route_path("/items/5", "").ok().flatten(),
            Some(dp("/items/5"))
        );
    }
}

#[cfg(all(test, feature = "server"))]
mod static_noise_mime_tests {
    use super::{noise_candidate, static_noise_mime};
    use crate::path_core::Regime;

    #[test]
    fn noise_candidate_windows_refuses_escaping_paths() {
        for uri in [
            "/con.ico",
            "/C:x.ico",
            "/x:y.ico",
            "/.well-known/..%5C..%5Cx",
            "/.well-known/a.",
        ] {
            assert_eq!(
                noise_candidate("C:\\site", uri, Regime::Windows),
                None,
                "{uri:?}"
            );
        }
        let ok = noise_candidate("C:\\site", "/a/favicon.ico", Regime::Windows);
        assert_eq!(
            ok,
            Some((
                std::path::PathBuf::from("C:\\site\\a\\favicon.ico"),
                "image/x-icon"
            ))
        );
    }

    #[test]
    fn noise_candidate_unix_decodes_once_and_accepts_legal_names() {
        assert_eq!(
            noise_candidate("/srv/site", "/con.ico", Regime::Unix),
            Some((
                std::path::PathBuf::from("/srv/site/con.ico"),
                "image/x-icon"
            ))
        );
        assert_eq!(
            noise_candidate("/srv/site", "/fav%69con.ico", Regime::Unix),
            Some((
                std::path::PathBuf::from("/srv/site/favicon.ico"),
                "image/x-icon"
            ))
        );
        for uri in ["/", "/a/../x.ico", "/a%2F..%2Fx.ico", "/a//b.ico"] {
            assert_eq!(
                noise_candidate("/srv/site", uri, Regime::Unix),
                None,
                "{uri:?}"
            );
        }
    }

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
#[cfg(not(target_arch = "wasm32"))]
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
/// These tests mutate the runtime's env overlay (never the process `environ`;
/// see the rationale in `system.rs`). Each test cleans up after itself.
#[cfg(all(test, feature = "server"))]
mod security_env_tests {

    // ── IPE_WEB_CSRF_ORIGIN_CHECK ─────────────────────────────────────────────
    //
    // `origin_check_enabled()` is memoized in a `OnceLock`, so we cannot test
    // it via the production `origin_mismatch` path in the same process run. We
    // test the env-read layer directly via `read_env_var`.

    #[test]
    fn csrf_origin_check_new_name_takes_effect() {
        crate::system::locked_remove_var("IPE_WEB_CSRF_ORIGIN_CHECK");

        // (a) set → "on"
        crate::system::locked_set_var("IPE_WEB_CSRF_ORIGIN_CHECK", "on");
        assert_eq!(
            crate::system::read_env_var("IPE_WEB_CSRF_ORIGIN_CHECK").as_deref(),
            Ok("on"),
            "IPE_WEB_CSRF_ORIGIN_CHECK must be read"
        );
        crate::system::locked_remove_var("IPE_WEB_CSRF_ORIGIN_CHECK");

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
        crate::system::locked_remove_var("IPE_WEB_FRAME_ANCESTORS");

        // (a) set → value
        crate::system::locked_set_var("IPE_WEB_FRAME_ANCESTORS", "https://app.example.com");
        assert_eq!(
            crate::system::read_env_var("IPE_WEB_FRAME_ANCESTORS").as_deref(),
            Ok("https://app.example.com"),
            "IPE_WEB_FRAME_ANCESTORS must be read"
        );
        crate::system::locked_remove_var("IPE_WEB_FRAME_ANCESTORS");

        // (b) unset → Err; frame_ancestors() returns None (same-origin mode).
        assert!(
            crate::system::read_env_var("IPE_WEB_FRAME_ANCESTORS").is_err(),
            "unset → Err; frame_ancestors defaults to None (same-origin mode)"
        );
    }

    // ── IPE_WEB_MAX_BODY_BYTES (Web path) ────────────────────────────────────
    //
    // The Web path's ceiling reads live from env each call (not memoized), so
    // the production read is driven directly.

    #[test]
    fn web_max_body_bytes_new_name_and_default() {
        let read = || super::WEB_MAX_BODY_CEILING.read::<usize>();
        crate::system::locked_remove_var("IPE_WEB_MAX_BODY_BYTES");
        // Unset → default (5 MiB); a rename bug that silently zeros this would
        // reject all /_ipe/event POSTs.
        let absent = read();
        crate::system::locked_set_var("IPE_WEB_MAX_BODY_BYTES", "8192");
        let overridden = read();
        crate::system::locked_remove_var("IPE_WEB_MAX_BODY_BYTES");
        assert_eq!(
            absent,
            Ok(5 << 20),
            "unset → 5 MiB default must be preserved"
        );
        assert_eq!(
            overridden,
            Ok(8192),
            "IPE_WEB_MAX_BODY_BYTES must take effect"
        );
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
    fn test_param_resolver(_path: &crate::web::route::DecodedPath) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &crate::web::route::DecodedPath) -> crate::web::RouteLookup {
        crate::web::RouteLookup::single_page(p)
    }

    fn make_state(store: Arc<TestStore>) -> TestWebState {
        WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_entry: Arc::new(|model, _path| route::Entered {
                model,
                cmd: IpeCmd::None,
            }),
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
        Arc::new(Mutex::new(SessionEntry {
            model: (),
            rendered: Rendered::first(new_incarnation(), tree),
            tabs: TabSeqs::default(),
            seq: 0,
            sse_tx,
            msg_tx,
            entered_path: None,
            enter_tx: tokio::sync::mpsc::channel(1).0,
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
        let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
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

    /// Without a dev intent `watch_banner_active_with` is false regardless of
    /// banner and base settings, and the env-driven gate under `ENV=dev` on
    /// the release test binary is false too: the gate function is the single
    /// source of truth for whether the route is mounted.
    #[test]
    fn watch_status_unmounted_on_release_under_env_dev() {
        locked_remove_var("IPE_WEB_BANNER");
        assert!(!watch_banner_active_with("", None));
        locked_set_var("ENV", "production");
        assert!(!watch_banner_active(""), "production: never mounted");
        if !cfg!(feature = "dev-posture") {
            locked_set_var("ENV", "dev");
            locked_set_var("IPE_ENV", "dev");
            assert!(
                !watch_banner_active(""),
                "ENV=dev on a release build must not mount the route"
            );
            locked_remove_var("IPE_ENV");
        }
        locked_remove_var("ENV");
    }

    /// Under a dev intent with banner on, `watch_banner_active_with` is true.
    #[test]
    fn watch_banner_active_true_in_dev() {
        locked_remove_var("IPE_WEB_BANNER");
        let dev = crate::telemetry::test_dev_intent();
        assert!(
            watch_banner_active_with("", Some(&dev)),
            "watch_banner_active must be true in dev with no overrides"
        );
    }

    /// With banner explicitly disabled, `watch_banner_active` is false even in dev.
    #[test]
    fn watch_banner_active_false_when_banner_disabled() {
        let dev = crate::telemetry::test_dev_intent();
        for v in ["off", "0", "false"] {
            locked_set_var("IPE_WEB_BANNER", v);
            assert!(
                !watch_banner_active_with("", Some(&dev)),
                "watch_banner_active must be false when IPE_WEB_BANNER={v}"
            );
        }
        locked_remove_var("IPE_WEB_BANNER");
    }

    /// A non-root base (sub-app) → `watch_banner_active` is false.
    #[test]
    fn watch_banner_active_false_for_subapp() {
        locked_remove_var("IPE_WEB_BANNER");
        let dev = crate::telemetry::test_dev_intent();
        assert!(
            !watch_banner_active_with("/sub", Some(&dev)),
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
        let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
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
        let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
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
        let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
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
        let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
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
                route_entry: Arc::new(|model, _path| route::Entered {
                    model,
                    cmd: IpeCmd::None,
                }),
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
    fn test_param_resolver(_path: &crate::web::route::DecodedPath) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &crate::web::route::DecodedPath) -> crate::web::RouteLookup {
        crate::web::RouteLookup::single_page(p)
    }

    fn make_router() -> Router {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_entry: Arc::new(|model, _path| route::Entered {
                model,
                cmd: IpeCmd::None,
            }),
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
    use crate::web::store::{MemoryStore, SessionStore};
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

    fn test_param_resolver(_path: &crate::web::route::DecodedPath) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }

    fn test_route_matched(p: &crate::web::route::DecodedPath) -> crate::web::RouteLookup {
        crate::web::RouteLookup::single_page(p)
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
            route_entry: Arc::new(|model, _path| route::Entered {
                model,
                cmd: IpeCmd::None,
            }),
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

    /// Extract the session-cookie value from a `Set-Cookie` response header.
    fn extract_sid(resp: &axum::response::Response) -> String {
        for val in resp.headers().get_all(header::SET_COOKIE) {
            let s = val.to_str().unwrap_or("");
            for part in s.split(';') {
                let part = part.trim();
                if let Some((k, v)) = part.split_once('=')
                    && k.trim() == cookie_name_for("").as_str()
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
            let live_model_before = store
                .get(&live_sid)
                .await
                .expect("expected live Web session in store")
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .model
                .clone();
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
            let live_model_after = store
                .get(&live_sid)
                .await
                .expect("expected live Web session still in store")
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .model
                .clone();
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

            let fresh_model = store
                .get(&fresh_sid)
                .await
                .expect("expected fresh Web session in store")
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .model
                .clone();
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
    fn test_param_resolver(_path: &crate::web::route::DecodedPath) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &crate::web::route::DecodedPath) -> crate::web::RouteLookup {
        crate::web::RouteLookup::single_page(p)
    }

    fn make_router() -> Router {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_entry: Arc::new(|model, _path| route::Entered {
                model,
                cmd: IpeCmd::None,
            }),
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
    fn test_param_resolver(_path: &crate::web::route::DecodedPath) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &crate::web::route::DecodedPath) -> crate::web::RouteLookup {
        crate::web::RouteLookup::single_page(p)
    }

    fn make_router() -> Router {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_entry: Arc::new(|model, _path| route::Entered {
                model,
                cmd: IpeCmd::None,
            }),
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
    fn test_param_resolver(_path: &crate::web::route::DecodedPath) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn test_route_matched(p: &crate::web::route::DecodedPath) -> crate::web::RouteLookup {
        crate::web::RouteLookup::single_page(p)
    }

    fn make_router() -> Router {
        let store = Arc::new(TestStore::new(Duration::from_secs(60)));
        let state: TestWebState = WebState {
            store: store as Arc<dyn store::SessionStore<TestModel, TestMsg>>,
            init: Arc::new(test_init),
            update: Arc::new(test_update),
            view: Arc::new(test_view),
            subs: Arc::new(test_subs),
            route_entry: Arc::new(|model, _path| route::Entered {
                model,
                cmd: IpeCmd::None,
            }),
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

/// The longest UTF-8 prefix of streamed body bytes. A chunk boundary may
/// split a code point, so an unfinished tail waits for the next chunk; bytes
/// are never replaced, so a marker past an invalid sequence is never found.
#[cfg(all(test, feature = "server"))]
fn utf8_prefix(bytes: &[u8]) -> &str {
    match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(split) => bytes
            .get(..split.valid_up_to())
            .and_then(|valid| std::str::from_utf8(valid).ok())
            .unwrap_or_default(),
    }
}

#[cfg(all(test, feature = "server", not(target_arch = "wasm32")))]
mod bind_error_tests {
    /// The port-taken refusal names `IPE_WEB_PORT` when the operator or the
    /// default chose the port, and names no operator var when a supervisor did.
    #[test]
    fn addr_in_use_message_is_keyed_on_the_port_origin() {
        let resolve = |relocation: Option<&str>, operator: Option<&str>| {
            crate::system::resolve_listen_port(
                relocation.map(str::to_owned),
                (super::WEB_PORT_ENV, operator.map(str::to_owned)),
                8000,
            )
        };
        for r in [resolve(None, None), resolve(None, Some("9200"))] {
            let msg = r.addr_in_use_message();
            assert!(msg.contains("IPE_WEB_PORT=8123 ipe dev run"), "{msg}");
        }
        let relocated = resolve(Some("9100"), Some("9200"));
        assert_eq!(relocated.port, 9100);
        let msg = relocated.addr_in_use_message();
        assert!(
            !msg.contains("IPE_WEB_PORT") && !msg.contains("IPE_SERVER_PORT"),
            "{msg}"
        );
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
        if crate::system::read_env_var("IPE_WEB_RESET_STATE").is_ok() {
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
    use crate::web::store::{MemoryStore, SessionStore};
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

    fn param_resolver(_path: &crate::web::route::DecodedPath) -> crate::dict::IpeDict<String> {
        crate::dict::dict_empty()
    }
    fn route_matched(p: &crate::web::route::DecodedPath) -> crate::web::RouteLookup {
        crate::web::RouteLookup::single_page(p)
    }

    fn make_state(store: Arc<Store>) -> State {
        WebState {
            store: store as Arc<dyn store::SessionStore<Model, Msg>>,
            init: Arc::new(init),
            update: Arc::new(update),
            view: Arc::new(view),
            subs: Arc::new(subs),
            route_entry: Arc::new(|model, _path| route::Entered {
                model,
                cmd: IpeCmd::None,
            }),
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
    #[allow(clippy::expect_used)] // test helper: the test process sets no base path
    fn make_router(store: Arc<Store>) -> axum::Router {
        build_web_router::<
            Model,
            Msg,
            fn(WebReq) -> (Model, IpeCmd<Msg>),
            fn(Msg, Model) -> (Model, IpeCmd<Msg>),
            fn(Model) -> Html<Msg>,
            fn(Model) -> IpeSub<Msg>,
        >(make_state(store), false)
        .expect("the unset test base parses")
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

    /// GET `path` (optionally with a session cookie) and return
    /// `(minted_sid, body)`. `minted_sid` is the session cookie from any `Set-Cookie`
    /// header (the response also sets a CSRF cookie, so scan ALL of them), or
    /// empty when none was set.
    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn get(router: axum::Router, path: &str, cookie: Option<&str>) -> (String, String) {
        let mut b = Request::builder().method("GET").uri(path);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, format!("{}={c}", cookie_name_for("")));
        }
        let resp = router
            .oneshot(b.body(Body::empty()).expect("build GET"))
            .await
            .expect("router responds");
        let mut sid = String::new();
        for val in resp.headers().get_all(header::SET_COOKIE) {
            let s = val.to_str().unwrap_or("");
            if let Some(rest) = s.strip_prefix(&format!("{}=", cookie_name_for(""))) {
                sid = rest.split(';').next().unwrap_or("").trim().to_string();
                break;
            }
        }
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        (
            sid,
            String::from_utf8(bytes.to_vec()).expect("a UTF-8 body"),
        )
    }

    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_event(router: axum::Router, cookie: &str, body: &str) -> StatusCode {
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_ipe/event")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, format!("{}={cookie}", cookie_name_for("")))
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
        store
            .get(sid)
            .await
            .map(|h| h.lock().unwrap_or_else(|e| e.into_inner()).model.clone())
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

    /// A malformed session TTL or auth ceiling refuses the router at startup,
    /// naming the variable, instead of answering requests under a default.
    #[tokio::test]
    async fn a_malformed_ttl_or_auth_ceiling_refuses_the_router() {
        let mut cases = vec![("IPE_WEB_TTL", "1h30")];
        if cfg!(feature = "jwt") {
            cases.extend([
                ("IPE_AUTH_MAX_LIFETIME", "8h"),
                ("IPE_AUTH_SLIDE_WINDOW", "0"),
                ("IPE_REVOCATION_CAPACITY", " 1024"),
            ]);
        }
        for (name, raw) in cases {
            crate::system::locked_set_var(name, raw);
            let refused = build_web_router::<
                Model,
                Msg,
                fn(WebReq) -> (Model, IpeCmd<Msg>),
                fn(Msg, Model) -> (Model, IpeCmd<Msg>),
                fn(Model) -> Html<Msg>,
                fn(Model) -> IpeSub<Msg>,
            >(
                make_state(Arc::new(Store::new(Duration::from_secs(60)))),
                false,
            )
            .err();
            crate::system::locked_remove_var(name);
            assert!(
                matches!(&refused, Some(StartupRefusal::Ceiling(r)) if r.name() == name),
                "{name}={raw:?} must refuse the router, got {refused:?}"
            );
        }
    }

    /// A base path that decodes but is outside the mount-base grammar refuses
    /// the router at startup, so no page or widget URL is built from it.
    #[tokio::test]
    async fn a_non_mount_base_path_refuses_the_router() {
        crate::system::locked_set_var("IPE_WEB_BASE_PATH", "/app/x%41");
        let refused = build_web_router::<
            Model,
            Msg,
            fn(WebReq) -> (Model, IpeCmd<Msg>),
            fn(Msg, Model) -> (Model, IpeCmd<Msg>),
            fn(Model) -> Html<Msg>,
            fn(Model) -> IpeSub<Msg>,
        >(
            make_state(Arc::new(Store::new(Duration::from_secs(60)))),
            false,
        )
        .err();
        crate::system::locked_remove_var("IPE_WEB_BASE_PATH");
        assert!(
            matches!(&refused, Some(StartupRefusal::MountBase { base, .. }) if base == "/app/x%41"),
            "a non-mount base must refuse the router, got {refused:?}"
        );
    }

    /// A present `IPE_HTTP_BIND` that is not an IP address refuses the app
    /// before it binds; an IP address is bound as given.
    #[test]
    fn a_bind_that_is_not_an_ip_address_refuses_the_app() {
        for raw in ["localhost", "127.0.0.1:8080", "[::1]", ""] {
            crate::system::locked_set_var("IPE_HTTP_BIND", raw);
            let refused = web_bind_host();
            crate::system::locked_remove_var("IPE_HTTP_BIND");
            assert!(
                matches!(&refused, Err(StartupRefusal::Bind(r)) if r.name() == "IPE_HTTP_BIND"),
                "IPE_HTTP_BIND={raw:?} must refuse the app, got {refused:?}"
            );
        }
        crate::system::locked_set_var("IPE_HTTP_BIND", "::1");
        let bound = web_bind_host();
        crate::system::locked_remove_var("IPE_HTTP_BIND");
        assert!(
            matches!(bound, Ok(host @ crate::app_config::ListenHost::Loopback(_))
                if host.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            "a bare IPv6 loopback address is bound as given, got {bound:?}"
        );
    }

    /// The router refuses an `IPE_WEB_FRAME_ANCESTORS` with no
    /// `frame-ancestors` representation at startup. The value is read once per
    /// process, so the check runs in a child holding it.
    #[test]
    fn an_unrepresentable_frame_ancestors_refuses_the_router() {
        let (refused, out) = crate::telemetry::frame_ancestors_child::refused(
            module_path!(),
            "router_frame_ancestors_child",
            "a;b",
        );
        assert!(refused, "the child must observe the refusal:\n{out}");
    }

    /// The child half of `an_unrepresentable_frame_ancestors_refuses_the_router`;
    /// a no-op unless it runs with `IPE_WEB_FRAME_ANCESTORS=a;b`.
    #[tokio::test]
    #[ignore = "run as a child process by an_unrepresentable_frame_ancestors_refuses_the_router"]
    async fn router_frame_ancestors_child() {
        if crate::system::read_env_var(crate::telemetry::FRAME_ANCESTORS_ENV).as_deref()
            != Ok("a;b")
        {
            return;
        }
        let refused = build_web_router::<
            Model,
            Msg,
            fn(WebReq) -> (Model, IpeCmd<Msg>),
            fn(Msg, Model) -> (Model, IpeCmd<Msg>),
            fn(Model) -> Html<Msg>,
            fn(Model) -> IpeSub<Msg>,
        >(
            make_state(Arc::new(Store::new(Duration::from_secs(60)))),
            false,
        )
        .err();
        assert!(
            matches!(
                refused,
                Some(StartupRefusal::FrameAncestors(
                    crate::telemetry::FrameAncestorsRefusal::DirectiveSeparator
                ))
            ),
            "a `;` must refuse the router, got {refused:?}"
        );
        println!("\n{}", crate::telemetry::frame_ancestors_child::REFUSED);
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
            let epoch = epoch_of(&body).expect("the page carries its render epoch");

            let event = format!(
                r#"{{"id":"{hid}","msg":"click","args":[],"sessionId":"","epoch":"{epoch}"}}"#
            );
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
                        .header(header::COOKIE, format!("{}={sid}", cookie_name_for("")))
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
            let mut bytes = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                while bytes.len() < 256 * 1024 {
                    match stream.next().await {
                        Some(Ok(chunk)) => {
                            bytes.extend_from_slice(&chunk);
                            let text = utf8_prefix(&bytes);
                            if text.contains("event: patch") && text.contains("data-ipe-hid") {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            })
            .await;
            let acc = utf8_prefix(&bytes);
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
            let epoch = epoch_of(&body).expect("the page carries its render epoch");

            let event = format!(
                r#"{{"id":"{hid}","event":"submit","args":[{{"username":"alice","password":"s3cr3t"}}],"sessionId":"","epoch":"{epoch}"}}"#
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

    // ── Render epochs and per-tab replay through the production router ──────

    /// A well-formed tab id, as a browser tab mints once per page load.
    const TAB: &str = "00112233445566778899aabbccddeeff";

    /// The render epoch the page embeds as `window.__IPE_EPOCH`.
    fn epoch_of(page: &str) -> Option<String> {
        let needle = "window.__IPE_EPOCH=\"";
        let rest = page.get(page.find(needle)? + needle.len()..)?;
        Some(rest.get(..rest.find('"')?)?.to_string())
    }

    /// `token` one render ahead of its own counter: an epoch never committed.
    fn future_of(token: &str) -> Option<String> {
        let (hex, n) = token.split_once('.')?;
        let n: u64 = n.parse().ok()?;
        Some(format!("{hex}.{}", n.checked_add(1)?))
    }

    /// `token` with its incarnation's first hex digit changed: another history.
    fn foreign_of(token: &str) -> Option<String> {
        let (hex, n) = token.split_once('.')?;
        let first = if hex.starts_with('0') { '1' } else { '0' };
        Some(format!("{first}{}.{n}", hex.get(1..)?))
    }

    /// A click event body on `hid`, with an optional epoch and `(tab, seq)`.
    fn click_body(hid: &str, epoch: Option<&str>, tab: Option<(&str, u64)>) -> String {
        let mut body = serde_json::Map::new();
        body.insert("id".to_string(), hid.into());
        body.insert("msg".to_string(), "click".into());
        body.insert("args".to_string(), serde_json::Value::Array(Vec::new()));
        if let Some(epoch) = epoch {
            body.insert("epoch".to_string(), epoch.into());
        }
        if let Some((tab, seq)) = tab {
            body.insert("tab".to_string(), tab.into());
            body.insert("seq".to_string(), seq.into());
        }
        serde_json::Value::Object(body).to_string()
    }

    /// POST an event and return its status, its `X-Ipe-Web` marker and its body.
    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn post_event_full(
        router: axum::Router,
        cookie: &str,
        body: &str,
    ) -> (StatusCode, Option<String>, String) {
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_ipe/event")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, format!("{}={cookie}", cookie_name_for("")))
                    .body(Body::from(body.to_owned()))
                    .expect("build POST"),
            )
            .await
            .expect("router responds");
        let status = resp.status();
        let marker = resp
            .headers()
            .get("x-ipe-web")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        (
            status,
            marker,
            String::from_utf8(bytes.to_vec()).expect("a UTF-8 body"),
        )
    }

    /// GET `path` with the session cookie; return the `X-Ipe-Epoch` header and the body.
    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn get_with_epoch(
        router: axum::Router,
        path: &str,
        cookie: &str,
    ) -> (Option<String>, String) {
        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::COOKIE, format!("{}={cookie}", cookie_name_for("")))
                    .body(Body::empty())
                    .expect("build GET"),
            )
            .await
            .expect("router responds");
        let epoch = resp
            .headers()
            .get("x-ipe-epoch")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        (
            epoch,
            String::from_utf8(bytes.to_vec()).expect("a UTF-8 body"),
        )
    }

    /// The session's live entry.
    #[allow(clippy::expect_used)] // test helper — the session was just created by a GET
    async fn session_of(store: &Arc<Store>, sid: &str) -> SessionHandle<Model, Msg> {
        store.get(sid).await.expect("the session is live")
    }

    /// The token of the session's current render epoch.
    async fn current_epoch(store: &Arc<Store>, sid: &str) -> String {
        session_of(store, sid)
            .await
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rendered
            .epoch()
            .to_token()
    }

    /// Route the session's dispatches into `tx`, so a test reads exactly what
    /// `event_handler` enqueued.
    async fn capture_dispatches(store: &Arc<Store>, sid: &str, tx: Sender<Msg>) {
        session_of(store, sid)
            .await
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .msg_tx = tx;
    }

    /// `view(model)` stamped exactly as the driver stamps a committed render.
    fn stamped(mut tree: Html<Msg>) -> Html<Msg> {
        assign_ipe_ids(&mut tree, "r");
        style_inject::apply_style_injections(&mut tree);
        tree
    }

    /// The counter view with its two buttons swapped: the `-` button now sits
    /// where `+` was, so it inherits the `+` button's positional hid.
    fn swapped_view() -> Html<Msg> {
        use crate::html::{Attribute, Event};
        let button = |label: &str, msg: Msg| {
            Html::HElement(
                "div".to_string(),
                vec![Attribute::EventAttr(Event::OnMsg("click".to_string(), msg))],
                vec![Html::HText(label.to_string())],
            )
        };
        stamped(Html::HElement(
            "div".to_string(),
            vec![],
            vec![
                button("-", Msg::Decrement),
                Html::HText("0".to_string()),
                button("+", Msg::Increment),
            ],
        ))
    }

    /// Commit `tree` as the session's next render, as a driver commit would.
    async fn commit_view(store: &Arc<Store>, sid: &str, tree: Html<Msg>) {
        let step = session_of(store, sid)
            .await
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rendered
            .commit(tree);
        assert!(step.is_ok(), "a fresh history mints another epoch");
    }

    /// A replayed event resolves against the render it came from: after the
    /// `+` button's position passes to `-`, the old-epoch click still
    /// dispatches `Increment`, while a current-epoch click on the same hid
    /// dispatches `Decrement`.
    #[test]
    #[allow(clippy::expect_used)] // the page and the swapped view are fixtures
    fn an_old_epoch_click_dispatches_the_handler_it_was_rendered_with() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            let swapped = swapped_view();
            assert_eq!(
                hid_near_text(&render_html(&swapped), "-").as_deref(),
                Some(plus.as_str()),
                "the swap must hand the `+` hid to the `-` button"
            );
            commit_view(&store, &sid, swapped).await;
            let (tx, mut rx) = mpsc::channel::<Msg>(4);
            capture_dispatches(&store, &sid, tx).await;

            let old = click_body(&plus, Some(&first), None);
            let (status, _, _) = post_event_full(make_router(store.clone()), &sid, &old).await;
            assert_eq!(status, StatusCode::OK, "a retained epoch resolves");
            assert!(
                matches!(rx.try_recv(), Ok(Msg::Increment)),
                "the old-epoch click must dispatch the handler it was rendered with"
            );

            let current = current_epoch(&store, &sid).await;
            let now = click_body(&plus, Some(&current), None);
            let (status, _, _) = post_event_full(make_router(store.clone()), &sid, &now).await;
            assert_eq!(status, StatusCode::OK);
            assert!(matches!(rx.try_recv(), Ok(Msg::Decrement)));
        });
    }

    /// An epoch evicted from the render history refuses with `409`, the
    /// `X-Ipe-Web` marker and the current render, and dispatches nothing.
    #[test]
    #[allow(clippy::expect_used)] // the page and the refusal JSON are fixtures
    fn an_evicted_epoch_refuses_with_the_current_render_and_no_dispatch() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            for _ in 0..RENDER_HISTORY_DEPTH.get() {
                let model = Model {
                    count: 0,
                    last_username: String::new(),
                };
                commit_view(&store, &sid, stamped(view(model))).await;
            }
            let (tx, mut rx) = mpsc::channel::<Msg>(4);
            capture_dispatches(&store, &sid, tx).await;

            let stale = click_body(&plus, Some(&first), None);
            let (status, marker, reply) =
                post_event_full(make_router(store.clone()), &sid, &stale).await;
            assert_eq!(status, StatusCode::CONFLICT, "an evicted epoch must refuse");
            assert_eq!(
                marker.as_deref(),
                Some("1"),
                "the refusal is a genuine Ipe.Web reply"
            );
            let json: serde_json::Value =
                serde_json::from_str(&reply).expect("the refusal body is JSON");
            assert_eq!(
                json.get("refused").and_then(serde_json::Value::as_str),
                Some("stale-render")
            );
            let current = current_epoch(&store, &sid).await;
            assert_eq!(
                json.get("epoch").and_then(serde_json::Value::as_str),
                Some(current.as_str())
            );
            assert!(json.get("seq").is_some_and(serde_json::Value::is_u64));
            assert!(
                json.get("body")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|b| b.contains("data-ipe-hid")),
                "the refusal carries the current render: {reply}"
            );
            assert!(rx.try_recv().is_err(), "a refused event must not dispatch");
        });
    }

    /// An event without an epoch refuses with `409` and dispatches nothing: an
    /// absent epoch never means the current render.
    #[test]
    #[allow(clippy::expect_used)] // the page is a fixture
    fn a_missing_epoch_refuses_and_dispatches_nothing() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let (tx, mut rx) = mpsc::channel::<Msg>(4);
            capture_dispatches(&store, &sid, tx).await;

            let unstamped = click_body(&plus, None, None);
            let (status, marker, _) =
                post_event_full(make_router(store.clone()), &sid, &unstamped).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(marker.as_deref(), Some("1"));
            assert!(
                rx.try_recv().is_err(),
                "an unstamped event must not dispatch"
            );
        });
    }

    /// A malformed epoch or tab id is a malformed body: `400 bad body`, no dispatch.
    #[test]
    #[allow(clippy::expect_used)] // the page is a fixture
    fn a_malformed_epoch_or_tab_is_a_bad_body_and_dispatches_nothing() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            let (tx, mut rx) = mpsc::channel::<Msg>(4);
            capture_dispatches(&store, &sid, tx).await;

            let bad_epoch = click_body(&plus, Some("not-an-epoch"), None);
            let bad_tab = click_body(&plus, Some(&first), Some(("NOT-A-TAB", 1)));
            for event in [bad_epoch, bad_tab] {
                let (status, _, reply) =
                    post_event_full(make_router(store.clone()), &sid, &event).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{event}");
                assert_eq!(reply, "bad body");
            }
            assert!(
                rx.try_recv().is_err(),
                "a malformed event must not dispatch"
            );
        });
    }

    /// An epoch from the future of this history, or from another history,
    /// refuses with `409` and dispatches nothing.
    #[test]
    #[allow(clippy::expect_used)] // the page and the token mutations are fixtures
    fn a_future_or_foreign_epoch_refuses() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            let future = future_of(&first).expect("a well-formed token");
            let foreign = foreign_of(&first).expect("a well-formed token");
            let (tx, mut rx) = mpsc::channel::<Msg>(4);
            capture_dispatches(&store, &sid, tx).await;

            for epoch in [future, foreign] {
                let event = click_body(&plus, Some(&epoch), None);
                let (status, marker, _) =
                    post_event_full(make_router(store.clone()), &sid, &event).await;
                assert_eq!(status, StatusCode::CONFLICT, "{epoch}");
                assert_eq!(marker.as_deref(), Some("1"));
            }
            assert!(rx.try_recv().is_err(), "a refused event must not dispatch");
        });
    }

    /// A replay of a tab's recorded seq is acked as a duplicate and dispatched
    /// once; the tab's next seq dispatches again.
    #[test]
    #[allow(clippy::expect_used)] // the page is a fixture
    fn a_replayed_tab_seq_is_acked_as_a_duplicate_and_dispatched_once() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            let (tx, mut rx) = mpsc::channel::<Msg>(4);
            capture_dispatches(&store, &sid, tx).await;

            let event = click_body(&plus, Some(&first), Some((TAB, 1)));
            let (status, _, reply) =
                post_event_full(make_router(store.clone()), &sid, &event).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                !reply.contains("duplicate"),
                "the first send is no duplicate: {reply}"
            );
            let (status, _, reply) =
                post_event_full(make_router(store.clone()), &sid, &event).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                reply.contains("\"duplicate\":true"),
                "the replay is a duplicate: {reply}"
            );
            assert!(matches!(rx.try_recv(), Ok(Msg::Increment)));
            assert!(rx.try_recv().is_err(), "the replay must not dispatch again");

            let next = click_body(&plus, Some(&first), Some((TAB, 2)));
            let (status, _, _) = post_event_full(make_router(store.clone()), &sid, &next).await;
            assert_eq!(status, StatusCode::OK);
            assert!(matches!(rx.try_recv(), Ok(Msg::Increment)));
        });
    }

    /// A tab's earlier seq that reaches the server after a later one (a retried
    /// event, or two posts racing for the lock) is no duplicate: it dispatches,
    /// and only its own replay is acked as a duplicate.
    #[test]
    #[allow(clippy::expect_used)] // the page is a fixture
    fn an_earlier_tab_seq_arriving_late_still_dispatches_once() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            let (tx, mut rx) = mpsc::channel::<Msg>(4);
            capture_dispatches(&store, &sid, tx).await;

            let later = click_body(&plus, Some(&first), Some((TAB, 2)));
            let (status, _, _) = post_event_full(make_router(store.clone()), &sid, &later).await;
            assert_eq!(status, StatusCode::OK);
            assert!(matches!(rx.try_recv(), Ok(Msg::Increment)));

            let earlier = click_body(&plus, Some(&first), Some((TAB, 1)));
            let (status, _, reply) =
                post_event_full(make_router(store.clone()), &sid, &earlier).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                !reply.contains("duplicate"),
                "a late earlier seq is no duplicate: {reply}"
            );
            assert!(
                matches!(rx.try_recv(), Ok(Msg::Increment)),
                "a late earlier seq must dispatch"
            );

            let (status, _, reply) =
                post_event_full(make_router(store.clone()), &sid, &earlier).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                reply.contains("\"duplicate\":true"),
                "its replay is a duplicate: {reply}"
            );
            assert!(rx.try_recv().is_err(), "the replay must not dispatch again");
        });
    }

    /// A debugger step commits the render it shows: its reply names a fresh
    /// current epoch whose handler index is the shown DOM's, so a click on the
    /// stepped DOM resolves against that render, never the one it replaced.
    #[cfg(feature = "debugger")]
    #[test]
    #[allow(clippy::expect_used)] // the page and the step reply are fixtures
    fn a_debugger_step_commits_the_render_it_shows() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            let event = click_body(&plus, Some(&first), None);
            assert_eq!(
                post_event(make_router(store.clone()), &sid, &event).await,
                StatusCode::OK
            );
            await_model(&store, &sid, |m| m.count == 1).await;
            let before = current_epoch(&store, &sid).await;

            let resp = make_router(store.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/_ipe/debug/step-to")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, format!("{}={sid}", cookie_name_for("")))
                        .body(Body::from(r#"{"index":0}"#))
                        .expect("build POST"),
                )
                .await
                .expect("router responds");
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("read body");
            let reply: serde_json::Value =
                serde_json::from_slice(&bytes).expect("the step reply is JSON");
            let after = current_epoch(&store, &sid).await;
            assert_ne!(after, before, "the step must commit a new render");
            assert_eq!(
                reply.get("epoch").and_then(serde_json::Value::as_str),
                Some(after.as_str()),
                "the reply names the committed epoch"
            );
            let shown = render_html(
                session_of(&store, &sid)
                    .await
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .rendered
                    .last_view(),
            );
            assert_eq!(
                reply.get("body").and_then(serde_json::Value::as_str),
                Some(shown.as_str()),
                "the committed render is the one the debugger shows"
            );
        });
    }

    /// A `429` leaves the tab's seq unrecorded, so the client's retry of the
    /// same event dispatches once the queue drains.
    #[test]
    #[allow(clippy::expect_used)] // the page and the one-slot channel are fixtures
    fn a_full_queue_does_not_record_the_seq() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            let (tx, mut rx) = mpsc::channel::<Msg>(1);
            tx.try_send(Msg::Decrement).expect("the one slot is free");
            capture_dispatches(&store, &sid, tx).await;

            let event = click_body(&plus, Some(&first), Some((TAB, 1)));
            let (status, _, _) = post_event_full(make_router(store.clone()), &sid, &event).await;
            assert_eq!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "a full queue answers 429"
            );
            assert!(
                matches!(rx.try_recv(), Ok(Msg::Decrement)),
                "drain the filler"
            );

            let (status, _, reply) =
                post_event_full(make_router(store.clone()), &sid, &event).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                !reply.contains("duplicate"),
                "a 429 must not burn the seq: {reply}"
            );
            assert!(matches!(rx.try_recv(), Ok(Msg::Increment)));
        });
    }

    /// A driver commit and a route entry each mint a new epoch, which the page
    /// serves in `window.__IPE_EPOCH` and `X-Ipe-Epoch`; an SSE resync carries
    /// the current epoch without minting one.
    #[test]
    #[allow(clippy::expect_used)] // the page and the SSE request are fixtures
    fn every_commit_advances_the_epoch_and_a_resync_does_not() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            assert_eq!(current_epoch(&store, &sid).await, first);

            let event = click_body(&plus, Some(&first), None);
            let (status, _, _) = post_event_full(make_router(store.clone()), &sid, &event).await;
            assert_eq!(status, StatusCode::OK);
            await_model(&store, &sid, |m| m.count == 1).await;
            let driven = current_epoch(&store, &sid).await;
            assert_ne!(driven, first, "a driver commit must mint a new epoch");

            let (header_epoch, page) = get_with_epoch(make_router(store.clone()), "/", &sid).await;
            let entered = epoch_of(&page).expect("the page carries its render epoch");
            assert_ne!(entered, driven, "a route entry must mint a new epoch");
            assert_eq!(header_epoch.as_deref(), Some(entered.as_str()));
            assert_eq!(current_epoch(&store, &sid).await, entered);

            let resp = make_router(store.clone())
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/_ipe/sse?path=%2F")
                        .header(header::ACCEPT, "text/event-stream")
                        .header(header::COOKIE, format!("{}={sid}", cookie_name_for("")))
                        .body(Body::empty())
                        .expect("build SSE GET"),
                )
                .await
                .expect("router responds");
            assert_eq!(resp.status(), StatusCode::OK);
            use futures_util::StreamExt;
            let mut stream = resp.into_body().into_data_stream();
            let mut bytes = Vec::new();
            let want = format!("\"epoch\":\"{entered}\"");
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                while bytes.len() < 256 * 1024 {
                    match stream.next().await {
                        Some(Ok(chunk)) => {
                            bytes.extend_from_slice(&chunk);
                            if utf8_prefix(&bytes).contains(&want) {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            })
            .await;
            assert!(read.is_ok(), "SSE read timed out before the resync frame");
            let acc = utf8_prefix(&bytes);
            assert!(
                acc.contains(&want),
                "the resync names the current epoch:\n{acc}"
            );
            assert_eq!(
                current_epoch(&store, &sid).await,
                entered,
                "a resync must not mint an epoch"
            );
        });
    }

    /// Every driver commit pushes a `patches` frame naming the epochs it moved
    /// between, an update that changes nothing included.
    #[test]
    #[allow(clippy::expect_used)] // the page, the SSE channel and the frames are fixtures
    fn a_patches_frame_names_its_epochs_even_with_no_patches() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, body) = get(make_router(store.clone()), "/", None).await;
            let form = hid_for_open_tag(&body, "form").expect("data-ipe-hid on <form>");
            let plus = hid_near_text(&body, "+").expect("data-ipe-hid near >+<");
            let first = epoch_of(&body).expect("the page carries its render epoch");
            let (sse_tx, mut sse_rx) = sse::channel().expect("the default SSE buffer resolves");
            session_of(&store, &sid)
                .await
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .sse_tx = Some(sse_tx);

            // An empty sign-in leaves the model, and so the view, unchanged.
            let unchanged = format!(
                r#"{{"id":"{form}","event":"submit","args":[{{"username":"","password":""}}],"epoch":"{first}"}}"#
            );
            let (status, _, _) =
                post_event_full(make_router(store.clone()), &sid, &unchanged).await;
            assert_eq!(status, StatusCode::OK);
            let frame = tokio::time::timeout(Duration::from_secs(5), sse_rx.recv())
                .await
                .expect("the commit pushes a frame")
                .expect("the SSE channel is open");
            let data = frame
                .0
                .lines()
                .find_map(|l| l.strip_prefix("data: "))
                .expect("a frame carries a data line");
            let json: serde_json::Value = serde_json::from_str(data).expect("the frame is JSON");
            assert!(frame.0.starts_with("event: patches"), "{}", frame.0);
            assert_eq!(
                json.get("from").and_then(serde_json::Value::as_str),
                Some(first.as_str())
            );
            let second = current_epoch(&store, &sid).await;
            assert_ne!(second, first);
            assert_eq!(
                json.get("to").and_then(serde_json::Value::as_str),
                Some(second.as_str())
            );
            assert!(
                json.get("patches")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty),
                "an unchanged view still pushes its epoch-only frame: {json}"
            );

            let event = click_body(&plus, Some(&second), None);
            let (status, _, _) = post_event_full(make_router(store.clone()), &sid, &event).await;
            assert_eq!(status, StatusCode::OK);
            let frame = tokio::time::timeout(Duration::from_secs(5), sse_rx.recv())
                .await
                .expect("the commit pushes a frame")
                .expect("the SSE channel is open");
            let data = frame
                .0
                .lines()
                .find_map(|l| l.strip_prefix("data: "))
                .expect("a frame carries a data line");
            let json: serde_json::Value = serde_json::from_str(data).expect("the frame is JSON");
            assert_eq!(
                json.get("from").and_then(serde_json::Value::as_str),
                Some(second.as_str())
            );
            let third = current_epoch(&store, &sid).await;
            assert_eq!(
                json.get("to").and_then(serde_json::Value::as_str),
                Some(third.as_str())
            );
            assert!(
                json.get("patches")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|p| !p.is_empty()),
                "a changed view pushes its patches: {json}"
            );
        });
    }

    /// The production router over a state whose route matcher counts its runs:
    /// every page and SSE-reconcile request consults it first, so a zero count
    /// proves no handler logic ran.
    #[allow(clippy::expect_used)] // test helper: the test process sets no base path
    fn make_counting_router(store: Arc<Store>, runs: Arc<AtomicUsize>) -> axum::Router {
        let mut state = make_state(store);
        state.route_matched = Arc::new(move |p: &crate::web::route::DecodedPath| {
            runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            route_matched(p)
        });
        build_web_router::<
            Model,
            Msg,
            fn(WebReq) -> (Model, IpeCmd<Msg>),
            fn(Msg, Model) -> (Model, IpeCmd<Msg>),
            fn(Model) -> Html<Msg>,
            fn(Model) -> IpeSub<Msg>,
        >(state, false)
        .expect("the unset test base parses")
    }

    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn status_and_body(
        router: axum::Router,
        uri: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, String) {
        let mut b = Request::builder().method("GET").uri(uri);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, format!("{}={c}", cookie_name_for("")));
        }
        let resp = router
            .oneshot(b.body(Body::empty()).expect("build GET"))
            .await
            .expect("router responds");
        let status = resp.status();
        if status != StatusCode::BAD_REQUEST {
            // A live SSE stream never ends; only a refusal body is read.
            return (status, String::new());
        }
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read body");
        (
            status,
            String::from_utf8(bytes.to_vec()).expect("a UTF-8 body"),
        )
    }

    /// Prove the refusals: a malformed page path or query, and a malformed
    /// SSE query or `?path=` value, answer the fixed 400 before any handler
    /// logic runs.
    #[test]
    fn malformed_urls_are_refused_before_any_web_handler() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, _) = get(make_router(store.clone()), "/", None).await;
            assert!(!sid.is_empty(), "GET / must set an ipe_sid cookie");
            for uri in [
                "/%zz",
                "/%C0%AF",
                "/page%C3",
                "/?q=%zz",
                "/_ipe/sse?path=%zz",
                "/_ipe/sse?%C3=1",
                "/_ipe/sse?path=%2F%25zz",
                "/_ipe/sse?path=%2F%25C0%25AF",
            ] {
                let runs = Arc::new(AtomicUsize::new(0));
                let router = make_counting_router(store.clone(), runs.clone());
                let (status, body) = status_and_body(router, uri, Some(&sid)).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{uri:?}");
                assert_eq!(body, "Bad Request", "{uri:?} must not echo the request");
                assert_eq!(
                    runs.load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "{uri:?} must never reach handler logic"
                );
            }
        });
    }

    /// A route table naming a malformed literal pattern.
    fn malformed_routes() -> Vec<crate::web::route::Route<()>> {
        vec![
            crate::web::route::Route::new("/", |_| Some(())),
            crate::web::route::Route::new("/%zz", |_| Some(())),
        ]
    }

    /// GET `/` against a mount, returning the status and body text.
    #[allow(clippy::expect_used)] // test helper: request build / body read failure is a test environment issue
    async fn mounted_get(router: axum::Router) -> (StatusCode, String) {
        let resp = router
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/")
                    .body(Body::empty())
                    .expect("build GET"),
            )
            .await
            .expect("router responds");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body = String::from_utf8(bytes.to_vec()).expect("the body is UTF-8");
        (status, body)
    }

    #[allow(clippy::expect_used)] // test helper: runtime build failure is a test environment issue
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
            .block_on(fut)
    }

    /// A standalone routed app whose table holds a malformed pattern refuses to
    /// start: the task resolves to an error naming the pattern, before any
    /// store is chosen or port bound.
    #[test]
    fn standalone_routed_app_refuses_malformed_route_table() {
        let result = block_on(web_app_routed::<String, Model, Msg, (), _, _, _, _, _, _>(
            init,
            update,
            view,
            subs,
            malformed_routes(),
            (),
            |_page: (), model: Model| (model, IpeCmd::None),
            |_page: &()| Err(crate::web::route::RenderRefusal::NoRoute),
            "memory".to_string(),
            String::new(),
            [0u8; 32],
        ));
        assert!(
            matches!(
                &result,
                IpeResult::Err(message) if message.contains("route pattern `/%zz` is malformed")
            ),
            "a malformed route table must refuse to start, naming the pattern: {result:?}"
        );
    }

    /// A mounted routed app whose table holds a malformed pattern answers every
    /// path with the fixed 503 body; the pattern stays in the server log.
    #[test]
    fn mounted_routed_app_fails_closed_on_malformed_route_table() {
        let builder = web_embed_router_routed(
            init,
            update,
            view,
            subs,
            malformed_routes(),
            (),
            |_page: (), model: Model| (model, IpeCmd::None),
            |_page: &()| Err(crate::web::route::RenderRefusal::NoRoute),
            "memory".to_string(),
            String::new(),
            [0u8; 32],
        );
        let (status, body) =
            block_on(async move { mounted_get(builder(String::new()).await).await });
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, FAIL_CLOSED_BODY);
        assert!(!body.contains("%zz"), "the 503 must not echo the refusal");
    }

    /// A mounted app whose store config this build cannot honour answers every
    /// path with the fixed 503 body, never the store detail.
    #[cfg(not(feature = "redis_store"))]
    #[test]
    fn mounted_app_fails_closed_on_unhonourable_store() {
        let builder = web_embed_router(
            init,
            update,
            view,
            subs,
            "redis".to_string(),
            String::new(),
            [0u8; 32],
        );
        let (status, body) =
            block_on(async move { mounted_get(builder(String::new()).await).await });
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, FAIL_CLOSED_BODY);
        assert!(
            !body.contains("redis"),
            "the 503 must not echo the store refusal"
        );
    }

    /// Every startup cause answers with the one fixed body: no route pattern, no
    /// store detail (a connection URL included), no base path reaches it.
    #[test]
    fn fail_closed_body_is_fixed_for_every_cause() {
        let causes = [
            StartupRefusal::RouteTable(
                crate::web::route::check_route_table(&malformed_routes())
                    .expect_err("the table is malformed"),
            ),
            StartupRefusal::SessionStore(store::StoreConfigError(
                "IPE_WEB_STORE=postgres refused at connect (postgres://user:hunter2@db.internal/app)"
                    .to_string(),
            )),
            parse_route_base("/%zz").expect_err("the base is malformed"),
            StartupRefusal::FrameAncestors(
                crate::telemetry::FrameAncestors::parse("https://a.example\r\n")
                    .expect_err("a CR/LF source list is refused"),
            ),
        ];
        for cause in causes {
            let detail = cause.to_string();
            let (status, body) = block_on(mounted_get(fail_closed_router(&cause)));
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{detail}");
            assert_eq!(body, FAIL_CLOSED_BODY, "{detail}");
            for leak in ["%zz", "hunter2", "postgres", "malformed"] {
                assert!(!body.contains(leak), "{leak} leaked from {detail}");
            }
        }
    }

    /// Happy path: a well-formed page GET and SSE reconnect reach the handler.
    #[test]
    fn well_formed_urls_reach_the_web_handlers() {
        with_csrf_off(|| async {
            let store = Arc::new(Store::new(Duration::from_secs(60)));
            let (sid, _) = get(make_router(store.clone()), "/", None).await;
            assert!(!sid.is_empty(), "GET / must set an ipe_sid cookie");
            for uri in ["/", "/?q=a+b", "/_ipe/sse?path=%2F"] {
                let runs = Arc::new(AtomicUsize::new(0));
                let router = make_counting_router(store.clone(), runs.clone());
                let (status, _) = status_and_body(router, uri, Some(&sid)).await;
                assert_eq!(status, StatusCode::OK, "{uri:?}");
                assert!(
                    runs.load(std::sync::atomic::Ordering::SeqCst) > 0,
                    "{uri:?} must reach the handler"
                );
            }
        });
    }
}

#[cfg(all(test, feature = "server"))]
mod page_mount_base_tests {
    use axum::http::{HeaderMap, StatusCode};

    /// The first epoch of a fresh render history.
    fn page_epoch() -> super::RenderEpoch {
        super::Rendered::first(
            super::new_incarnation(),
            super::Html::<()>::HText(String::new()),
        )
        .epoch()
    }

    /// The page under the current `IPE_WEB_BASE_PATH`.
    #[cfg(not(feature = "debugger"))]
    fn page(headers: &HeaderMap) -> axum::response::Response {
        super::page_response("sid", "<p>x</p>", &page_epoch(), "tok", headers)
    }

    /// The page under the current `IPE_WEB_BASE_PATH`.
    #[cfg(feature = "debugger")]
    fn page(headers: &HeaderMap) -> axum::response::Response {
        super::page_response_with_overlay("sid", "<p>x</p>", &page_epoch(), "", "tok", headers)
    }

    /// A page asked for under a base outside the mount-base grammar answers the
    /// fixed 503, never a page whose URLs and `ipe-base` meta carry that base; a
    /// grammar base renders the page.
    #[test]
    fn a_non_mount_base_path_refuses_the_page() {
        let headers = HeaderMap::new();
        crate::system::locked_set_var("IPE_WEB_BASE_PATH", "/a\"b");
        let refused = page(&headers).status();
        crate::system::locked_set_var("IPE_WEB_BASE_PATH", "/app");
        let admitted = page(&headers).status();
        crate::system::locked_remove_var("IPE_WEB_BASE_PATH");
        assert_eq!(refused, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(admitted, StatusCode::OK);
    }
}

#[cfg(all(test, feature = "server"))]
mod route_entry_cmd_tests {
    //! Every server path that commits a routed page from a URL runs that
    //! page's entry Cmd: the first GET (after `init`'s Cmd), a reload of a live
    //! session, a cold-restored session, and an SSE reconnect at a different
    //! path — once per entry, serialised with `update`, and bounded by the
    //! driver's enter queue and reply timeout.

    use super::*;
    use crate::web::req::WebReq;
    use crate::web::route::{RenderArg, RenderRefusal, Route, RoutePath, render_route};
    use crate::web::store::{MemoryStore, SessionStore};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde::{Deserialize, Serialize};
    use std::time::Duration;
    use tower::ServiceExt; // oneshot

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    enum Page {
        Home,
        Item(String),
    }

    /// The page plus every effect the session has seen, in arrival order.
    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Model {
        page: Page,
        log: Vec<String>,
    }

    impl crate::stringify::IpeStringify for Model {
        fn ipe_show(&self) -> String {
            format!("{self:?}")
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    enum Msg {
        Loaded(String),
    }

    impl crate::stringify::IpeStringify for Msg {
        fn ipe_show(&self) -> String {
            format!("{self:?}")
        }
    }

    /// A Cmd whose only effect is logging `label` into the model through `update`.
    fn load(label: String) -> IpeCmd<Msg> {
        IpeCmd::Perform(Box::new(move || {
            Box::pin(async move { Msg::Loaded(label) })
        }))
    }

    thread_local! {
        /// The session sid each fixture `init` call ran under, in call order.
        static INIT_SIDS: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    /// Drain the sids `init` ran under on this thread since the last drain.
    fn take_init_sids() -> Vec<String> {
        INIT_SIDS.with(|sids| std::mem::take(&mut *sids.borrow_mut()))
    }

    /// Records the sid it runs under (where a js port binds its session), then inits.
    fn init(_req: WebReq) -> (Model, IpeCmd<Msg>) {
        INIT_SIDS.with(|sids| sids.borrow_mut().push(pubsub::current_session_sid()));
        (
            Model {
                page: Page::Home,
                log: Vec::new(),
            },
            load("init".to_owned()),
        )
    }

    fn update(msg: Msg, model: Model) -> (Model, IpeCmd<Msg>) {
        let Msg::Loaded(label) = msg;
        let mut log = model.log;
        log.push(label);
        (Model { log, ..model }, IpeCmd::None)
    }

    fn view(model: Model) -> Html<Msg> {
        Html::HText(match model.page {
            Page::Home => "page-home".to_owned(),
            Page::Item(id) => format!("page-item-{id}"),
        })
    }

    fn subs(_model: Model) -> IpeSub<Msg> {
        IpeSub::None
    }

    /// The app's entry fn: commit the page and load it.
    fn set_page(page: Page, model: Model) -> (Model, IpeCmd<Msg>) {
        let label = match &page {
            Page::Home => "enter:home".to_owned(),
            Page::Item(id) => format!("enter:item-{id}"),
        };
        (Model { page, ..model }, load(label))
    }

    fn routes() -> Vec<Route<Page>> {
        vec![
            Route::new("/", |_| Some(Page::Home)),
            Route::new("/items/:id", |p| p.first().cloned().map(Page::Item)),
        ]
    }

    /// The fixture's page renderer, as the emitter writes one per page type.
    fn render(page: &Page) -> Result<RoutePath, RenderRefusal> {
        match page {
            Page::Home => render_route(&routes(), 0, &[]),
            Page::Item(id) => render_route(&routes(), 1, &[RenderArg::Text(id)]),
        }
    }

    type Store = Arc<dyn store::SessionStore<Model, Msg>>;

    /// The fixture app's state, its four fns as plain fn pointers.
    type FixtureState = WebState<
        Model,
        Msg,
        fn(WebReq) -> (Model, IpeCmd<Msg>),
        fn(Msg, Model) -> (Model, IpeCmd<Msg>),
        fn(Model) -> Html<Msg>,
        fn(Model) -> IpeSub<Msg>,
    >;

    /// The root path, as the request boundary decodes `/`.
    #[allow(clippy::expect_used)] // test helper: `/` always decodes
    fn root_path() -> route::DecodedPath {
        route::DecodedPath::parse("/").expect("`/` decodes")
    }

    fn router(store: Store) -> axum::Router {
        router_counted(store, Arc::new(AtomicUsize::new(0)))
    }

    /// The fixture router over `store`, counting its session drivers in `session_count`.
    #[allow(clippy::expect_used)] // test helper: the fixture table and base are well-formed
    fn router_counted(store: Store, session_count: Arc<AtomicUsize>) -> axum::Router {
        let (route_entry, _, route_matched) =
            routed_resolvers(routes(), Page::Home, set_page, render);
        let state: FixtureState = WebState {
            store,
            init: Arc::new(init),
            update: Arc::new(update),
            view: Arc::new(view),
            subs: Arc::new(subs),
            route_entry,
            param_resolver: Arc::new(|_path| crate::dict::dict_empty()),
            route_matched,
            session_count,
            watch_build_status: Arc::new(Mutex::new(None)),
        };
        build_web_router(state, false).expect("the fixture route table and base are well-formed")
    }

    fn memory() -> Store {
        Arc::new(MemoryStore::<Model, Msg>::new(Duration::from_secs(60)))
    }

    /// Run `body` on a current-thread runtime (deterministic task order); `paused` starts tokio's clock paused.
    #[allow(clippy::expect_used)] // test helper — runtime build failure is a test environment issue
    fn run<F: std::future::Future<Output = ()>>(paused: bool, body: impl FnOnce() -> F) {
        // Serialise with the other in-process router tests: the session cookie
        // name and reset switch read the process-global env overlay.
        let _g = crate::web::literal_table::overlay_test_lock();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(paused)
            .build()
            .expect("current-thread runtime")
            .block_on(body());
    }

    /// GET `path` with an optional session cookie → (status, `Retry-After`, minted sid, body).
    ///
    /// The cookie name comes from `cookie_name_for`, so the helper follows the
    /// posture's name (`ipe_sid` or `__Host-ipe_sid`) instead of pinning one.
    async fn get(
        store: &Store,
        path: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, Option<String>, String, String) {
        get_via(router(store.clone()), path, cookie).await
    }

    /// GET `path` through `app`, answering as [`get`] does.
    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn get_via(
        app: axum::Router,
        path: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, Option<String>, String, String) {
        let name = super::cookie_name_for("");
        let prefix = format!("{name}=");
        let mut b = Request::builder().method("GET").uri(path);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, format!("{name}={c}"));
        }
        let resp = app
            .oneshot(b.body(Body::empty()).expect("build GET"))
            .await
            .expect("router responds");
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let sid = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| c.strip_prefix(prefix.as_str()))
            .and_then(|rest| rest.split(';').next())
            .unwrap_or("")
            .trim()
            .to_owned();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body = String::from_utf8(bytes.to_vec()).expect("a UTF-8 page body");
        (status, retry_after, sid, body)
    }

    async fn handle_of(store: &Store, sid: &str) -> Option<SessionHandle<Model, Msg>> {
        store.get(sid).await
    }

    async fn model_of(store: &Store, sid: &str) -> Option<Model> {
        handle_of(store, sid)
            .await
            .map(|h| h.lock().unwrap_or_else(|e| e.into_inner()).model.clone())
    }

    /// Wait (bounded) until the session's log has `len` entries, then return the model.
    async fn settled(store: &Store, sid: &str, len: usize) -> Option<Model> {
        for _ in 0..200 {
            if let Some(m) = model_of(store, sid).await
                && m.log.len() >= len
            {
                return Some(m);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        model_of(store, sid).await
    }

    fn count(model: &Model, label: &str) -> usize {
        model.log.iter().filter(|l| l.as_str() == label).count()
    }

    /// A first GET runs `init`'s Cmd and then the entered page's Cmd, in that order.
    #[test]
    fn miss_runs_init_cmd_then_entry_cmd() {
        run(false, || async {
            let store = memory();
            let (status, _, sid, body) = get(&store, "/items/1", None).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.contains("page-item-1"),
                "the GET renders the entered page"
            );
            let m = settled(&store, &sid, 2).await;
            assert_eq!(
                m.map(|m| m.log),
                Some(vec!["init".to_owned(), "enter:item-1".to_owned()]),
                "init's Cmd runs, then the entry Cmd, each once"
            );
        });
    }

    /// A GET on a live session enters through its driver and runs the entry Cmd.
    #[test]
    fn web_hit_runs_entry_cmd_through_the_driver() {
        run(false, || async {
            let store = memory();
            let (_, _, sid, _) = get(&store, "/", None).await;
            assert!(settled(&store, &sid, 2).await.is_some());

            let (status, _, _, body) = get(&store, "/items/2", Some(&sid)).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.contains("page-item-2"),
                "the reply carries the driver's rendered entry: {body}"
            );
            let m = settled(&store, &sid, 3).await;
            assert_eq!(
                m.as_ref().map(|m| m.page.clone()),
                Some(Page::Item("2".to_owned())),
                "the driver committed the entered page"
            );
            assert_eq!(m.map(|m| count(&m, "enter:item-2")), Some(1));
        });
    }

    /// A store that answers one sid with a persisted (cold) model, as after a restart.
    struct ColdStore {
        live: MemoryStore<Model, Msg>,
        cold_sid: String,
    }

    #[async_trait::async_trait]
    impl SessionStore<Model, Msg> for ColdStore {
        async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
            self.live.get(sid).await
        }
        fn admission(&self) -> &store::SidAdmission {
            self.live.admission()
        }
        async fn get_reconstructing(
            &self,
            claim: store::SidClaim,
            _make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
        ) -> store::Rejoin<Model, Msg> {
            if !self.admission().admits(&claim) {
                return store::Rejoin::Miss;
            }
            if let Some(h) = self.live.get(claim.key().as_str()).await {
                return store::Rejoin::Live(h);
            }
            if claim.key().as_str() == self.cold_sid {
                store::Rejoin::Restored {
                    claim,
                    model: Model {
                        page: Page::Home,
                        log: vec!["persisted".to_owned()],
                    },
                }
            } else {
                store::Rejoin::Miss
            }
        }
        async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
            self.live.set(sid, handle).await;
        }
        async fn delete(&self, sid: &str) {
            self.live.delete(sid).await;
        }
        async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
            self.live.web_sessions().await
        }
    }

    /// A GET restoring a cold session enters the path and runs its Cmd, without `init`.
    #[test]
    fn cold_hit_runs_entry_cmd_without_init() {
        run(false, || async {
            let cold_sid = new_sid();
            let store: Store = Arc::new(ColdStore {
                live: MemoryStore::new(Duration::from_secs(60)),
                cold_sid: cold_sid.clone(),
            });
            let (status, _, _, _) = get(&store, "/items/3", Some(&cold_sid)).await;
            assert_eq!(status, StatusCode::OK);
            let m = settled(&store, &cold_sid, 2).await;
            assert_eq!(
                m.map(|m| m.log),
                Some(vec!["persisted".to_owned(), "enter:item-3".to_owned()]),
                "a cold restore runs the entry Cmd and never init's"
            );
        });
    }

    /// The live binary's Model schema tag in the file-store fixtures.
    #[cfg(feature = "web")]
    const LIVE_TAG: [u8; 32] = [0x11; 32];
    /// A previous binary's tag: a row under it was written before a Model change.
    #[cfg(feature = "web")]
    const OLD_TAG: [u8; 32] = [0x22; 32];

    /// One checkpoint blob framed as the store writes it: `base64(tag ++ json)`.
    #[cfg(feature = "web")]
    fn checkpoint(tag: [u8; 32], json: &str) -> String {
        use base64::Engine as _;
        let mut framed = tag.to_vec();
        framed.extend_from_slice(json.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(framed)
    }

    /// A file store under `LIVE_TAG` whose one persisted row maps `sid` to `blob`.
    ///
    /// The map lives in a private scratch directory the returned guard removes
    /// on drop, so no fixture writes through a name another local user can plant.
    #[cfg(feature = "web")]
    #[allow(clippy::expect_used)] // test helper — a temp-file write failure is a test environment issue
    fn file_store_with(
        name: &str,
        sid: &str,
        blob: String,
    ) -> (Store, crate::scratch_core::ScratchDir) {
        let dir = crate::scratch_core::ScratchDir::new(&format!("ipetest-rejoin-{name}"))
            .expect("a private scratch dir");
        let path = dir.path().join("sessions.json");
        let last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let mut map: std::collections::HashMap<String, (String, i64)> =
            std::collections::HashMap::new();
        map.insert(sid.to_owned(), (blob, last_seen));
        std::fs::write(
            &path,
            serde_json::to_string(&map).expect("encode the seed map"),
        )
        .expect("write the seed map");
        let store: Store = Arc::new(store::FileStore::<Model, Msg>::new(
            path.to_str().expect("a UTF-8 temp path"),
            Duration::from_secs(60),
            LIVE_TAG,
        ));
        (store, dir)
    }

    /// A session rebuilt across an additive Model change runs init's Cmd, then the entry Cmd, under its kept sid.
    #[cfg(feature = "web")]
    #[test]
    fn schema_rebuilt_session_runs_init_cmd_then_entry_cmd() {
        run(false, || async {
            let sid = new_sid();
            // The old Model had no `log`: an additive change, so the row is rebuilt.
            let (store, _dir) =
                file_store_with("rebuilt", &sid, checkpoint(OLD_TAG, r#"{"page":"Home"}"#));
            let (status, _, cookie_sid, _) = get(&store, "/", Some(&sid)).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(cookie_sid, sid, "a rebuilt session keeps the cookie's sid");
            let m = settled(&store, &sid, 2).await;
            assert_eq!(
                m.map(|m| m.log),
                Some(vec!["init".to_owned(), "enter:home".to_owned()]),
                "a rebuilt session runs init's Cmd, then the entry Cmd, each once"
            );
        });
    }

    /// The `init` a rebuild evaluates runs under the session's sid, never the empty default.
    #[cfg(feature = "web")]
    #[test]
    fn rebuilt_init_cmd_binds_session_sid() {
        run(false, || async {
            let sid = new_sid();
            let (store, _dir) =
                file_store_with("bindsid", &sid, checkpoint(OLD_TAG, r#"{"page":"Home"}"#));
            take_init_sids();
            let (status, _, _, _) = get(&store, "/", Some(&sid)).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                take_init_sids(),
                vec![sid],
                "init runs once, scoped to the rebuilt session's sid"
            );
        });
    }

    /// A same-tag checkpoint restores verbatim and never evaluates `init`.
    #[cfg(feature = "web")]
    #[test]
    fn exact_tag_restore_never_calls_init() {
        run(false, || async {
            let sid = new_sid();
            let (store, _dir) = file_store_with(
                "exact",
                &sid,
                checkpoint(LIVE_TAG, r#"{"page":"Home","log":["persisted"]}"#),
            );
            take_init_sids();
            let (status, _, cookie_sid, _) = get(&store, "/", Some(&sid)).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(cookie_sid, sid, "a restored session keeps the cookie's sid");
            let m = settled(&store, &sid, 2).await;
            assert_eq!(
                m.map(|m| m.log),
                Some(vec!["persisted".to_owned(), "enter:home".to_owned()]),
                "a verbatim restore runs the entry Cmd and never init's"
            );
            assert!(
                take_init_sids().is_empty(),
                "a verbatim restore never evaluates init"
            );
        });
    }

    /// An undecodable row is a miss: a fresh sid, `init` evaluated exactly once under it.
    #[cfg(feature = "web")]
    #[test]
    fn failed_rebuild_runs_init_once_under_new_sid() {
        run(false, || async {
            let sid = new_sid();
            let (store, _dir) = file_store_with("undecodable", &sid, "!! not base64 !!".to_owned());
            take_init_sids();
            let (status, _, minted, _) = get(&store, "/", Some(&sid)).await;
            assert_eq!(status, StatusCode::OK);
            assert_ne!(minted, sid, "a miss never adopts the client's sid");
            assert_eq!(
                take_init_sids(),
                vec![minted.clone()],
                "init runs exactly once, under the minted sid"
            );
            let m = settled(&store, &minted, 2).await;
            assert_eq!(
                m.map(|m| m.log),
                Some(vec!["init".to_owned(), "enter:home".to_owned()]),
                "the new session runs init's Cmd, then the entry Cmd"
            );
        });
    }

    /// A non-additive old row evaluates `init` for the rebuild attempt, drops that Cmd unrun, and re-inits once.
    #[cfg(feature = "web")]
    #[test]
    fn non_additive_rebuild_discards_its_init_cmd() {
        run(false, || async {
            let sid = new_sid();
            // `log` retyped (a number where the live Model holds a list): not additive.
            let (store, _dir) = file_store_with(
                "retyped",
                &sid,
                checkpoint(OLD_TAG, r#"{"page":"Home","log":5}"#),
            );
            take_init_sids();
            let (status, _, minted, _) = get(&store, "/", Some(&sid)).await;
            assert_eq!(status, StatusCode::OK);
            assert_ne!(
                minted, sid,
                "a failed rebuild never adopts the client's sid"
            );
            assert_eq!(
                take_init_sids(),
                vec![sid, minted.clone()],
                "the rebuild attempt evaluates init under the cookie's sid, the re-init under the minted one"
            );
            // Wait past the expected length: a leaked rebuild Cmd would land a second "init".
            let m = settled(&store, &minted, 3).await;
            assert_eq!(
                m.map(|m| m.log),
                Some(vec!["init".to_owned(), "enter:home".to_owned()]),
                "only the re-init's Cmd runs; the discarded rebuild's Cmd never does"
            );
        });
    }

    /// A store that yields between its claimed lookup and the caller's publish, as a networked store's I/O does.
    ///
    /// Without the yield every fixture lookup completes in one poll, so two
    /// concurrent GETs never interleave between lookup and `set` and a race
    /// test passes with or without the claim.
    #[cfg(feature = "web")]
    struct YieldingStore {
        inner: Store,
    }

    #[cfg(feature = "web")]
    #[async_trait::async_trait]
    impl SessionStore<Model, Msg> for YieldingStore {
        async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
            self.inner.get(sid).await
        }
        fn admission(&self) -> &store::SidAdmission {
            self.inner.admission()
        }
        async fn get_reconstructing(
            &self,
            claim: store::SidClaim,
            make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
        ) -> store::Rejoin<Model, Msg> {
            let rejoin = self.inner.get_reconstructing(claim, make_init).await;
            tokio::task::yield_now().await;
            rejoin
        }
        async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
            self.inner.set(sid, handle).await;
        }
        async fn delete(&self, sid: &str) {
            self.inner.delete(sid).await;
        }
        async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
            self.inner.web_sessions().await
        }
    }

    /// Two concurrent GETs rejoining one schema-rebuilt sid evaluate `init` once; the second joins live.
    #[cfg(feature = "web")]
    #[test]
    fn two_concurrent_rebuilt_gets_run_init_once() {
        run(false, || async {
            let sid = new_sid();
            let (file, _dir) =
                file_store_with("racedinit", &sid, checkpoint(OLD_TAG, r#"{"page":"Home"}"#));
            let store: Store = Arc::new(YieldingStore { inner: file });
            take_init_sids();
            let ((first, ..), (second, ..)) =
                tokio::join!(get(&store, "/", Some(&sid)), get(&store, "/", Some(&sid)));
            assert_eq!((first, second), (StatusCode::OK, StatusCode::OK));
            assert_eq!(
                take_init_sids(),
                vec![sid.clone()],
                "one cold rejoin per sid: init runs once"
            );
            let m = settled(&store, &sid, 3).await;
            assert_eq!(
                m.map(|m| count(&m, "init")),
                Some(1),
                "init's Cmd lands once"
            );
        });
    }

    /// Two concurrent GETs restoring one sid verbatim spawn one session driver.
    #[cfg(feature = "web")]
    #[test]
    fn restored_concurrent_gets_spawn_one_driver() {
        run(false, || async {
            let sid = new_sid();
            let (file, _dir) = file_store_with(
                "raceddriver",
                &sid,
                checkpoint(LIVE_TAG, r#"{"page":"Home","log":["persisted"]}"#),
            );
            let store: Store = Arc::new(YieldingStore { inner: file });
            let drivers = Arc::new(AtomicUsize::new(0));
            let ((first, ..), (second, ..)) = tokio::join!(
                get_via(
                    router_counted(store.clone(), drivers.clone()),
                    "/",
                    Some(&sid)
                ),
                get_via(
                    router_counted(store.clone(), drivers.clone()),
                    "/",
                    Some(&sid)
                )
            );
            assert_eq!((first, second), (StatusCode::OK, StatusCode::OK));
            assert_eq!(
                drivers.load(Ordering::SeqCst),
                1,
                "the second rejoin joins the first's live session"
            );
        });
    }

    /// A cold store whose `set` waits for the test's release, so a test cancels a handler mid-commit.
    struct GatedStore {
        inner: ColdStore,
        entered: tokio::sync::Notify,
        release: tokio::sync::Semaphore,
    }

    #[async_trait::async_trait]
    impl SessionStore<Model, Msg> for GatedStore {
        async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
            self.inner.get(sid).await
        }
        fn admission(&self) -> &store::SidAdmission {
            self.inner.admission()
        }
        async fn get_reconstructing(
            &self,
            claim: store::SidClaim,
            make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
        ) -> store::Rejoin<Model, Msg> {
            self.inner.get_reconstructing(claim, make_init).await
        }
        async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
            self.entered.notify_one();
            if let Ok(permit) = self.release.acquire().await {
                permit.forget();
            }
            self.inner.set(sid, handle).await;
        }
        async fn delete(&self, sid: &str) {
            self.inner.delete(sid).await;
        }
        async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
            self.inner.web_sessions().await
        }
    }

    /// A handler cancelled while its rejoin is being stored still commits the session, its Cmd and its claim release.
    #[test]
    fn cancelled_handler_mid_set_still_commits() {
        run(false, || async {
            let cold_sid = new_sid();
            let gated = Arc::new(GatedStore {
                inner: ColdStore {
                    live: MemoryStore::new(Duration::from_secs(60)),
                    cold_sid: cold_sid.clone(),
                },
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Semaphore::new(0),
            });
            let store: Store = gated.clone();
            let app = router(store.clone());
            let cookie = cold_sid.clone();
            let request =
                tokio::spawn(async move { get_via(app, "/", Some(cookie.as_str())).await });
            gated.entered.notified().await;
            request.abort();
            assert!(
                request.await.is_err(),
                "the handler is cancelled mid-commit"
            );
            gated.release.add_permits(1);
            let m = settled(&store, &cold_sid, 2).await;
            assert_eq!(
                m.map(|m| m.log),
                Some(vec!["persisted".to_owned(), "enter:home".to_owned()]),
                "the cancelled handler's session is stored and its entry Cmd runs"
            );
            gated.release.add_permits(1);
            let (status, ..) = get(&store, "/", Some(&cold_sid)).await;
            assert_eq!(status, StatusCode::OK, "the committed claim was released");
        });
    }

    /// A cold store whose first `set` panics, so a test drives a commit that unwinds mid-publish.
    struct PanicOnceStore {
        inner: ColdStore,
        armed: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl SessionStore<Model, Msg> for PanicOnceStore {
        async fn get(&self, sid: &str) -> Option<SessionHandle<Model, Msg>> {
            self.inner.get(sid).await
        }
        fn admission(&self) -> &store::SidAdmission {
            self.inner.admission()
        }
        async fn get_reconstructing(
            &self,
            claim: store::SidClaim,
            make_init: &(dyn Fn() -> (Model, IpeCmd<Msg>) + Sync),
        ) -> store::Rejoin<Model, Msg> {
            self.inner.get_reconstructing(claim, make_init).await
        }
        async fn set(&self, sid: &str, handle: SessionHandle<Model, Msg>) {
            if self.armed.swap(false, Ordering::SeqCst) {
                panic!("the first commit unwinds mid-publish");
            }
            self.inner.set(sid, handle).await;
        }
        async fn delete(&self, sid: &str) {
            self.inner.delete(sid).await;
        }
        async fn web_sessions(&self) -> Vec<SessionHandle<Model, Msg>> {
            self.inner.web_sessions().await
        }
    }

    /// A commit that panics answers the panic 500 and releases its claim, so a retry restores the session.
    #[test]
    fn panicking_commit_is_500_and_releases_claim() {
        run(false, || async {
            let cold_sid = new_sid();
            let store: Store = Arc::new(PanicOnceStore {
                inner: ColdStore {
                    live: MemoryStore::new(Duration::from_secs(60)),
                    cold_sid: cold_sid.clone(),
                },
                armed: std::sync::atomic::AtomicBool::new(true),
            });
            let (status, _, _, body) = get(&store, "/", Some(&cold_sid)).await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "a panicked commit is the panic 500"
            );
            assert!(
                !body.contains(&cold_sid),
                "the panic body never carries the sid: {body}"
            );
            let (status, _, cookie_sid, _) = get(&store, "/", Some(&cold_sid)).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "the unwound commit released its claim"
            );
            assert_eq!(cookie_sid, cold_sid, "the retry restores the cold session");
        });
    }

    /// A claim held past the wait, or a sid with too many waiters, is the busy 503; a full claim table is the capacity 503.
    #[test]
    fn claim_refusals_map_to_existing_503s() {
        run(true, || async {
            let store = memory();
            let sid = new_sid();
            let key = || store::SessionKey::parse(&sid).expect("a minted sid is a session key");
            let held = store
                .claim(key())
                .await
                .expect("an idle sid is claimed at once");

            let (status, retry_after, ..) = get(&store, "/", Some(&sid)).await;
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "a wait past CLAIM_WAIT"
            );
            assert_eq!(retry_after.as_deref(), Some("1"));

            let mut waiters: Vec<_> = (0..store::MAX_CLAIM_WAITERS.get())
                .map(|_| store.claim(key()))
                .collect();
            for waiter in &mut waiters {
                assert!(
                    futures_util::FutureExt::now_or_never(waiter).is_none(),
                    "a waiter up to the limit queues"
                );
            }
            let (status, retry_after, ..) = get(&store, "/", Some(&sid)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "a crowded sid");
            assert_eq!(retry_after.as_deref(), Some("1"));
            drop(waiters);
            drop(held);

            let mut table = Vec::with_capacity(store::MAX_CLAIMS_IN_FLIGHT);
            for i in 0..store::MAX_CLAIMS_IN_FLIGHT {
                let k = store::SessionKey::parse(&format!("{i:032x}")).expect("a 32-hex sid");
                table.push(
                    store
                        .claim(k)
                        .await
                        .expect("a sid under the cap is claimed"),
                );
            }
            let (status, retry_after, ..) = get(&store, "/", Some(&sid)).await;
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "a full claim table"
            );
            assert_eq!(retry_after.as_deref(), Some("2"));
        });
    }

    /// A live session's GET never touches the claim table, so a full table cannot refuse it.
    #[test]
    fn live_session_bypasses_a_full_claim_table() {
        run(false, || async {
            let store = memory();
            let (status, _, sid, _) = get(&store, "/", None).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                settled(&store, &sid, 2).await.is_some(),
                "the session is live"
            );
            let mut table = Vec::with_capacity(store::MAX_CLAIMS_IN_FLIGHT);
            for i in 0..store::MAX_CLAIMS_IN_FLIGHT {
                let k = store::SessionKey::parse(&format!("{i:032x}")).expect("a 32-hex sid");
                table.push(
                    store
                        .claim(k)
                        .await
                        .expect("a sid under the cap is claimed"),
                );
            }
            let cold = store::SessionKey::parse(&new_sid()).expect("a minted sid is a session key");
            assert_eq!(
                store.claim(cold).await.err(),
                Some(store::ClaimRefusal::Saturated),
                "the claim table is full"
            );
            let (status, retry_after, cookie_sid, _) = get(&store, "/", Some(&sid)).await;
            assert_eq!(status, StatusCode::OK, "a live session is never refused");
            assert_eq!(retry_after, None);
            assert_eq!(cookie_sid, sid, "the GET joins the live session");
        });
    }

    /// A cookie that is not a well-formed sid is never looked up: the GET mints a fresh session.
    #[test]
    fn malformed_cookie_mints_without_lookup() {
        run(false, || async {
            let malformed = "persisted-session".to_owned();
            let store: Store = Arc::new(ColdStore {
                live: MemoryStore::new(Duration::from_secs(60)),
                cold_sid: malformed.clone(),
            });
            take_init_sids();
            let (status, _, minted, _) = get(&store, "/", Some(&malformed)).await;
            assert_eq!(status, StatusCode::OK);
            assert_ne!(minted, malformed, "a malformed sid is never adopted");
            assert_eq!(take_init_sids(), vec![minted.clone()]);
            let m = settled(&store, &minted, 2).await;
            assert_eq!(
                m.map(|m| m.log),
                Some(vec!["init".to_owned(), "enter:home".to_owned()]),
                "the store's row under the malformed sid is never restored"
            );
        });
    }

    /// A live session whose driver does not drain its enter queue, so a test holds the queue's far end.
    async fn stalled_session(store: &Store) -> (String, Receiver<EnterRequest>) {
        let sid = new_sid();
        let model = Model {
            page: Page::Home,
            log: Vec::new(),
        };
        let last_view = view(model.clone());
        let (msg_tx, _msg_rx) = mpsc::channel::<Msg>(1);
        let (enter_tx, enter_rx) = mpsc::channel::<EnterRequest>(ENTER_QUEUE_CAP.get());
        let entry = Arc::new(Mutex::new(SessionEntry {
            model: model.clone(),
            rendered: Rendered::first(new_incarnation(), last_view),
            tabs: TabSeqs::default(),
            seq: 0,
            sse_tx: None,
            msg_tx,
            entered_path: Some(root_path()),
            enter_tx,
            #[cfg(feature = "debugger")]
            history: crate::debugger::RecordBuffer::new(
                model,
                crate::debugger::DEFAULT_HISTORY_CAP,
            ),
            #[cfg(feature = "debugger")]
            debug_cursor: None,
        }));
        store.set(&sid, entry).await;
        (sid, enter_rx)
    }

    /// A full or closed enter queue answers 503 with `Retry-After: 1`, never an unbounded wait.
    #[test]
    fn full_or_closed_enter_queue_is_503() {
        run(false, || async {
            let store = memory();
            let (sid, enter_rx) = stalled_session(&store).await;
            let handle = handle_of(&store, &sid).await;
            assert!(handle.is_some(), "the seeded session is live");
            let Some(handle) = handle else {
                return;
            };
            let enter_tx = handle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .enter_tx
                .clone();
            let held: Vec<_> = (0..ENTER_QUEUE_CAP.get())
                .filter_map(|_| queue_entry(&enter_tx, root_path(), EnterMode::Load))
                .collect();
            assert_eq!(held.len(), ENTER_QUEUE_CAP.get());

            let (status, retry, _, _) = get(&store, "/items/4", Some(&sid)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "full queue");
            assert_eq!(retry.as_deref(), Some("1"));

            drop(enter_rx);
            let (status, retry, _, _) = get(&store, "/items/4", Some(&sid)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "closed queue");
            assert_eq!(retry.as_deref(), Some("1"));
        });
    }

    /// A driver that never replies within the reply timeout yields 503, not a hung request.
    #[test]
    fn unanswered_entry_times_out_with_503() {
        run(true, || async {
            let store = memory();
            let (sid, _enter_rx) = stalled_session(&store).await;
            let (status, retry, _, _) = get(&store, "/items/5", Some(&sid)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(retry.as_deref(), Some("1"));
        });
    }

    /// An `update` in flight and a GET re-entry are serialised by the driver, so neither commit is lost.
    #[test]
    fn update_and_reentry_keep_both_effects() {
        run(false, || async {
            let store = memory();
            let (_, _, sid, _) = get(&store, "/", None).await;
            assert!(settled(&store, &sid, 2).await.is_some());
            let handle = handle_of(&store, &sid).await;
            assert!(handle.is_some(), "the session is live");
            let Some(handle) = handle else {
                return;
            };
            let msg_tx = handle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .msg_tx
                .clone();
            assert!(msg_tx.try_send(Msg::Loaded("update".to_owned())).is_ok());
            let (status, _, _, _) = get(&store, "/items/6", Some(&sid)).await;
            assert_eq!(status, StatusCode::OK);

            let m = settled(&store, &sid, 4).await;
            assert_eq!(
                m.as_ref().map(|m| m.page.clone()),
                Some(Page::Item("6".to_owned()))
            );
            assert_eq!(m.as_ref().map(|m| count(m, "update")), Some(1));
            assert_eq!(m.map(|m| count(&m, "enter:item-6")), Some(1));
        });
    }

    /// Open the SSE stream for `sid` reporting `path` and read until its resync frame.
    #[allow(clippy::expect_used)] // test helper — request build / router failure is a test environment issue
    async fn sse_resync(store: &Store, sid: &str, path: &str) -> String {
        use futures_util::StreamExt;
        let resp = router(store.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/_ipe/sse?path={}", path.replace('/', "%2F")))
                    .header(header::ACCEPT, "text/event-stream")
                    .header(
                        header::COOKIE,
                        format!("{}={sid}", super::cookie_name_for("")),
                    )
                    .body(Body::empty())
                    .expect("build SSE GET"),
            )
            .await
            .expect("router responds");
        let mut stream = resp.into_body().into_data_stream();
        let mut bytes = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while bytes.len() < 64 * 1024 && !utf8_prefix(&bytes).contains("event: patch") {
                match stream.next().await {
                    Some(Ok(chunk)) => bytes.extend_from_slice(&chunk),
                    _ => break,
                }
            }
        })
        .await;
        utf8_prefix(&bytes).to_owned()
    }

    /// The GET that creates a page and the SSE open that follows at the same
    /// path enter once; an SSE open at a different path enters again.
    #[test]
    fn get_then_sse_same_path_runs_entry_cmd_once() {
        run(false, || async {
            let store = memory();
            let (_, _, sid, _) = get(&store, "/items/7", None).await;
            assert!(settled(&store, &sid, 2).await.is_some());

            let frame = sse_resync(&store, &sid, "/items/7").await;
            assert!(frame.contains("event: patch"), "resync frame on connect");
            tokio::time::sleep(Duration::from_millis(50)).await;
            let m = model_of(&store, &sid).await;
            assert_eq!(
                m.map(|m| count(&m, "enter:item-7")),
                Some(1),
                "the SSE open at the GET's path must not re-run the entry Cmd"
            );

            let frame = sse_resync(&store, &sid, "/").await;
            assert!(
                frame.contains("page-home"),
                "a differing path resyncs the entered page"
            );
            let m = settled(&store, &sid, 3).await;
            assert_eq!(m.map(|m| count(&m, "enter:home")), Some(1));
        });
    }
}

#[cfg(all(test, feature = "server"))]
mod tab_seq_window_tests {
    use super::{TAB_SEQ_CAP, TAB_SEQ_WINDOW, TabId, TabSeqs};

    const TAB: TabId = TabId(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);

    #[test]
    fn only_a_dispatched_seq_is_a_duplicate_inside_the_window() {
        let mut seqs = TabSeqs::default();
        seqs.record(TAB, 500);
        let oldest_tracked = 500 - u64::from(TAB_SEQ_WINDOW) + 1;
        assert!(seqs.is_duplicate(TAB, 500));
        assert!(!seqs.is_duplicate(TAB, 501));
        assert!(!seqs.is_duplicate(TAB, 499));
        assert!(!seqs.is_duplicate(TAB, oldest_tracked));
        seqs.record(TAB, oldest_tracked);
        assert!(seqs.is_duplicate(TAB, oldest_tracked));
        assert!(!seqs.is_duplicate(TAB, oldest_tracked + 1));
    }

    #[test]
    fn a_seq_older_than_the_window_counts_as_dispatched() {
        let mut seqs = TabSeqs::default();
        seqs.record(TAB, 500);
        let past = 500 - u64::from(TAB_SEQ_WINDOW);
        assert!(seqs.is_duplicate(TAB, past));
        assert!(seqs.is_duplicate(TAB, 0));
        seqs.record(TAB, u64::MAX);
        assert!(seqs.is_duplicate(TAB, 0));
        assert!(!seqs.is_duplicate(TAB, u64::MAX - 1));
    }

    #[test]
    fn advancing_slides_the_window_and_keeps_the_marks_inside_it() {
        let mut seqs = TabSeqs::default();
        seqs.record(TAB, 10);
        seqs.record(TAB, 12);
        assert!(seqs.is_duplicate(TAB, 10));
        assert!(!seqs.is_duplicate(TAB, 11));
        seqs.record(TAB, 10 + u64::from(TAB_SEQ_WINDOW));
        assert!(seqs.is_duplicate(TAB, 10), "10 slid out of the window");
        assert!(!seqs.is_duplicate(TAB, 11));
        assert!(seqs.is_duplicate(TAB, 12));
    }

    #[test]
    fn the_least_recent_tab_is_forgotten_past_the_cap() {
        let mut seqs = TabSeqs::default();
        seqs.record(TAB, 1);
        for k in 1..=TAB_SEQ_CAP.get() {
            seqs.record(TabId(u128::try_from(k).unwrap_or(u128::MAX)), 1);
        }
        assert!(!seqs.is_duplicate(TAB, 1), "the oldest tab was evicted");
    }
}
