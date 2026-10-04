//! Project assembly: stitch the fixed templates and the genuinely-emitted user
//! types + functions into the final `src/main.rs`, and pair it with the project
//! `Cargo.toml`.
//!
//! Layout — each section, and each item in it, separated by one blank line
//! through the single [`crate::items::Items`] joiner (an empty section leaves
//! no trace):
//! ```text
//! <preamble>          header, imports, basic aliases, USER TYPES banner
//! <user types>        emitted from the IR (emit_enum, emit_record_struct, …)
//! <runtime bindings>  fixed kernel-wrapper prelude (+ TEA aliases, Auth wrappers)
//! <user functions>    emitted from the IR (emit_func)
//! <epilogue>          list helpers, entry point
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use ipe_backend::{EmittedProject, RelPath};
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_ir::{IrType, ModPath, Program};

use crate::EmitCtx;
use crate::crate_specs;
use crate::emit_expr::emit_func;
use crate::emit_types::{emit_enum, emit_record_struct, emit_row_witnesses};
use crate::items::Items;
use crate::preamble::{epilogue, preamble};
use crate::rust_file;
use crate::rust_file::{Partitioned, RustFileId, partition_items};

/// The canonical emit template, embedded at compile time. The fixed
/// runtime-bindings block (kernel wrappers) is an exact substring of it. This is
/// a hand-maintained template file, NOT a golden fixture, so no `tests/golden/*`
/// file is an input to codegen.
const GOLDEN: &str = include_str!("../templates/main.rs");

/// The project `Cargo.toml`, embedded verbatim from the manifest template. The
/// backend emits the same manifest for every program (dependency set is fixed by
/// the runtime).
const CARGO_TOML: &str = include_str!("../templates/Cargo.toml");

/// The dependency-model project `Cargo.toml`
/// ([`crate::RustBackend::with_runtime_dep`]): the user-crate manifest that
/// declares the runtime as a relative path dependency (`ipe_runtime_dep/`)
/// instead of vendoring its source into `src/ipe_runtime/`. One placeholder is
/// substituted by [`dep_model_cargo_toml`]: `__IPE_RUNTIME_FEATURES__` (the
/// [`crate::runtime_features`] selection). The third-party dependency set the
/// vendored template carries is gone — the runtime crate's own manifest is the
/// single place declaring those versions, pulled transitively by the selected
/// features. The driver materialises the runtime source tree into
/// `ipe_runtime_dep/` alongside the emitted crate so the relative path resolves
/// in any build environment.
const CARGO_DEP_TOML: &str = include_str!("../templates/Cargo.dep.toml");

/// The dependency-model project `Cargo.toml` for the browser-WASM target. The
/// wasm counterpart of [`CARGO_DEP_TOML`]: the runtime is the SAME `ipe_runtime`
/// relative path dependency (`ipe_runtime_dep/`), feature-selected from the
/// [`crate::runtime_features`] SSOT (whose `wasm-client` floor pulls the whole
/// closed browser module set and its glue crates transitively). One placeholder
/// is substituted by [`dep_model_wasm_cargo_toml`]. Beyond the runtime it
/// declares only the two
/// crates the emitted wasm app code names BY PATH — `wasm-bindgen` (the
/// `#[wasm_bindgen(start)]` entry macro) and `serde` (the TEA-type wire
/// derives); `serde_json` is spliced in only for a `mode = "hydrate"` program
/// (its `hydrate` export parses the island JSON). No `tokio`/`axum`/`sqlx`/
/// `reqwest` and no server/db/web feature — the Layer-3 wasm security floor,
/// enforced by construction and machine-checked by `tests/wasm_dep_floor.rs`.
const CARGO_WASM_DEP_TOML: &str = include_str!("../templates/Cargo.wasm-dep.toml");

/// The generated `ipe_runtime/mod.rs` — the curated set of runtime modules whose
/// dependencies are satisfied by [`CARGO_TOML`]. The vendored runtime source
/// ships a fuller `mod.rs` (declaring `uuid` / `web` / `db` / … modules that
/// pull crates outside the base manifest); the driver overwrites it with this
/// trimmed version. The backend emits a fixed base module set, then appends the
/// modules a program's kernels require.
const RUNTIME_MOD_RS: &str = include_str!("../templates/ipe_runtime/mod.rs");

/// The generated `ipe_runtime/config.rs` (DB/config bindings — empty by default).
const RUNTIME_CONFIG_RS: &str = include_str!("../templates/ipe_runtime/config.rs");

/// The runtime crate's own `clippy.toml`, vendored next to the emitted `Cargo.toml`.
///
/// A vendored runtime compiles inside the app crate, so clippy reads the app
/// crate's config: without the runtime's `disallowed-methods`/`disallowed-types`
/// bans, every runtime `#[expect(clippy::disallowed_*)]` would be an unfulfilled
/// expectation in the emitted project. Embedded from the runtime file itself, so
/// the two cannot drift.
const RUNTIME_CLIPPY_TOML: &str = include_str!("../../../../../src/runtime/rust/clippy.toml");

/// Insert [`RUNTIME_CLIPPY_TOML`] at the project root of a vendored-runtime emit.
///
/// # Errors
///
/// Propagates a [`Diagnostic`] from building the fixed relative path.
fn insert_vendored_runtime_clippy_config(files: &mut BTreeMap<RelPath, String>) -> DResult<()> {
    files.insert(RelPath::new("clippy.toml")?, RUNTIME_CLIPPY_TOML.to_owned());
    Ok(())
}

// ── Browser-WASM manifest + runtime module set ─────────────────────────────

/// The `--target wasm` project manifest. A fourth template beside
/// base/db/server: `cdylib` + the wasm-bindgen glue, and — load-bearing for
/// the security gate's dependency floor — NO tokio/axum/sqlx/reqwest/TLS and
/// no `server`/`db`/`web` feature. Dep set = the runtime's proven wasm
/// floor (default + json) plus the browser sink's glue crates.
/// `wasm-bindgen` is pinned exact: the glue is generated by the
/// `wasm-bindgen` CLI, which requires a byte-matching crate version.
const WASM_CARGO_TOML: &str = r#"[package]
name = "ipe-app"
version = "0.1.0"
edition = "2024"
# The crate root is `src/main.rs` (shared layout with the binary targets);
# without this cargo would ALSO infer a `[[bin]]` from that path.
autobins = false

[features]
# Selects the browser-target impls of the shared form-submit helpers in the
# vendored runtime (`cfg(any(feature = "web", feature = "wasm-client"))`).
default = ["wasm-client", "web-core", "encoding", "serde", "json"]
wasm-client = []
# The browser sink renders through the server-free render core (`crate::dom`
# diff/dispatch/form + `style_inject` + `page_shell`, all `#[cfg(feature =
# "web-core")]` in the vendored source), so `web-core` is defaulted-on like
# `serde`/`json`/`encoding` to satisfy those gates — mirroring the runtime
# crate's own `wasm-client`, which pulls `web-core`.
web-core = []
# The floor serde derives (`IpeMaybe`/`IpeResult`/`IpeError`/`Decimal`/`Patch`)
# and `json.rs` are `#[cfg(feature = "serde")]` / `#[cfg(feature = "json")]` in
# the vendored source. `serde` / `serde_json` / `serde_urlencoded` stay
# non-optional below (byte-identical output), so these two features only satisfy
# the source `#[cfg]` gates and keep check-cfg quiet — defaulted on so the wasm
# app's Model wire + form decode still carry their serde impls.
serde = []
json = []
# Gates the vendored `encoding.rs` / `bytes.rs` modules. The `base64` / `hex` /
# `percent-encoding` deps below stay non-optional in this closed wasm template
# (byte-identical output), so this only satisfies the source `#[cfg]` gates —
# defaulted on.
encoding = []
# Declared but inert in this closed wasm template: `chrono` stays non-optional
# below and the wasm module set declares `log` / `time` by inclusion. These keep
# rustc's check-cfg quiet for the `#[cfg(feature = "log")]` /
# `#[cfg(feature = "time-core")]` gates the runtime source carries.
log = []
time-core = []
# Declared but inert in this closed wasm template: `rust_decimal` /
# `unicode-general-category` stay non-optional below and the wasm module set
# declares `decimal` / `money` / `char_category` by inclusion. These keep rustc's
# check-cfg quiet for the `#[cfg(feature = "decimal")]` /
# `#[cfg(feature = "char-category")]` gates the runtime source carries.
decimal = []
char-category = []
# Gates the IANA-zone calendar surface of the always-declared `time` runtime
# module (the `chrono-tz`-backed helpers). Promoted into `default` and paired
# with the `chrono-tz` dependency only for a program that reaches an `Ipe.Time`
# kernel; a program that uses no Time kernel keeps it off and drops the crate.
time = []

[lib]
# Browser WASM module. Same source layout as the binary targets; the crate
# root stays `src/main.rs`.
name = "ipe_app"
crate-type = ["cdylib"]
path = "src/main.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_urlencoded = "0.7"
regex = "1"
unicode-general-category = "1"
base64 = "0.22"
uuid = { version = "1", features = ["v4", "v7", "js"] }
hex = "0.4"
percent-encoding = "2"
# The wasm module set declares `url.rs` unconditionally (`pub mod url;` in
# WASM_RUNTIME_MOD_RS), and `http_client.rs`'s `fetch` arm targets a typed
# `crate::url::Url`, so the `url` crate is always in this closed template's
# dependency closure — non-optional here, like the other closed-set crates.
url = "2"
chrono = "=0.4.45"
rust_decimal = { version = "1", features = ["serde"] }
hmac = "0.12"
sha1 = "0.10"
sha2 = "0.10"
md-5 = "0.10"
subtle = "2"
zeroize = "1"
# Pinned exact to match `src/runtime/rust/Cargo.toml`'s own `wasm-bindgen` pin
# (the canonical spelling — see the `wasm_bindgen_version_matches_the_runtime_pin`
# test below, which fails the build the instant this drifts from it).
wasm-bindgen = "=0.2.126"
wasm-bindgen-futures = "0.4"
js-sys = "0.3"
# M4 Cmd/Sub browser bridge: `Sub.every`/`Time.sleep`/`Time.every`.
gloo-timers = { version = "0.3", features = ["futures"] }
# `Random.*` / `Crypto.randomBytes` / `Crypto.randomToken` browser substitute
# (`crypto.getRandomValues` via getrandom's `js` backend) — see
# `crypto.rs`/`random.rs`'s `cfg(target_arch = "wasm32")` arms.
getrandom = { version = "0.2", features = ["js"] }
web-sys = { version = "0.3", features = [
  "Window", "Document", "Element", "HtmlElement", "Node", "Text",
  "Event", "EventTarget", "console", "HtmlInputElement",
  "HtmlTextAreaElement", "HtmlSelectElement", "HtmlFormElement",
  "FormData", "KeyboardEvent", "Location", "HtmlDocument",
  "CustomEvent",
  "Request", "RequestInit", "RequestMode", "RequestRedirect",
  "Response", "Headers", "AbortController", "AbortSignal",
  # Incremental capped body read (fetch arm): Response.body() ->
  # ReadableStream.get_reader() -> chunk loop (mirrors the runtime crate).
  "ReadableStream", "ReadableStreamDefaultReader",
  "WebSocket", "MessageEvent", "CloseEvent", "ErrorEvent", "BinaryType",
  "PopStateEvent", "History",
] }
console_error_panic_hook = "0.1"

[profile.dev]
debug = 0
incremental = true
overflow-checks = false

[profile.release]
opt-level = "z"
lto = true
panic = "abort"
strip = true

# Detach this generated crate from any ancestor cargo workspace so it builds
# hermetically even when emitted inside another workspace tree.
[workspace]
"#;

/// The `--target wasm` `ipe_runtime/mod.rs`: exactly the vendored modules
/// that compile on `wasm32-unknown-unknown` under the wasm manifest above —
/// the proven pure floor, the whole `Ipe.Ui` render surface, the
/// target-neutral `dom` data path, the TEA types, the browser sink, and (M4)
/// the Cmd/Sub browser-effects substitutes (`log`, `crypto`'s entropy pair,
/// `http_client`'s `fetch` arm, `ws_client`'s `web_sys::WebSocket` arm — each
/// cfg-split `target_arch = "wasm32"` internally; see their module docs).
/// `trace`, the tokio-bound half of `task` (`block_on`/`Task.run`/
/// `Task.parallel`/`Task.retryWith` — `cfg(not(target_arch = "wasm32"))`
/// inside `task.rs`), the reqwest/tokio-tungstenite-coupled halves of
/// `http_client`/`ws_client`, and every server/db surface stay absent BY
/// CONSTRUCTION (Layer 3 of the security gate).
const WASM_RUNTIME_MOD_RS: &str = "\
// GENERATED by Ipê — do not edit (browser-WASM module set)
// `web::route` is the pure URL-pattern matcher shared with the server; it has
// no server/tokio dependencies and compiles cleanly on wasm32. The rest of the
// `web` module (axum, SSE, session store, …) is absent — no `pub mod web;` here.
pub mod web {
    pub mod route;
}
pub mod basics;
pub mod bitwise;
pub mod bytes;
pub mod char_kernel;
pub mod char_category;
pub mod color;
pub mod length;
pub mod config;
pub mod core;
pub mod crypto;
pub mod ct_eq;
pub mod crypto_core;
pub mod decimal;
pub mod task;
pub mod threads;
pub mod dict;
pub mod encoding;
pub mod error;
pub mod escape;
pub mod ffi_polyfills;
pub mod file;
pub mod http_header;
pub mod http_client;
pub mod io;
pub mod json;
pub mod seal_codec;
pub mod list;
pub mod log;
pub mod math;
pub mod money;
pub mod home_core;
pub mod scratch_core;
pub mod scratch_host;
pub mod path_core;
pub mod path;
pub mod random;
pub mod redact;
pub mod regex_kernel;
pub mod secret;
pub mod app_config;
pub mod set;
pub mod string;
pub mod stringify;
pub mod system;
pub mod telemetry;
pub mod time;
pub mod url;
pub mod uuid_kernel;
pub mod css_safety;
pub mod css;
pub mod html;
pub mod dom;
pub mod tea;
pub mod ui;
pub mod js_port;
pub mod wasm;
pub mod ws_client;
pub use basics::*;
pub use bitwise::*;
pub use bytes::*;
pub use char_kernel::*;
pub use char_category::*;
pub use color::*;
pub use config::*;
pub use core::*;
pub use crypto::*;
pub use decimal::*;
pub use dict::*;
pub use encoding::*;
pub use error::*;
pub use ffi_polyfills::*;
pub use file::*;
pub use http_client::*;
pub use io::*;
pub use json::*;
pub use list::*;
pub use log::*;
pub use math::*;
pub use money::*;
pub use path::*;
pub use random::*;
pub use regex_kernel::*;
pub use secret::*;
pub use app_config::*;
pub use set::*;
pub use string::*;
pub use stringify::*;
pub use system::*;
pub use task::*;
pub use time::*;
pub use uuid_kernel::*;
pub use css::*;
pub use html::*;
pub use tea::*;
// The typed `Ipe.Ffi.Js` port. Its wasm32 arm (`js_port::wasm`) posts each sealed
// outbound frame to `window.ipeOnReceive` and drains inbound frames the page's
// `window.ipe.send` feeds through the same bounded, fail-closed seal decoder the
// server path uses; `js_send`/`js_subscribe` are the `Js.send`/`Js.subscribe`
// denotations the emitted TEA code calls.
pub use js_port::*;
pub use ws_client::*;
// `Cmd.publish` / `Cmd.publishNoEcho` / `PubSub.publish` / `PubSub.publishNoEcho` /
// `Sub.subscribeTopic` resolve to `ipe_runtime::web::pubsub::*` natively; the
// wasm target has no `web` module (Layer 3 — no tokio/axum to link), so its
// in-tab broker (`wasm::pubsub`) exports the SAME bare kernel names. Selective
// re-export (not `pub use wasm::pubsub::*;`) so the broker's internal `Broker`/
// `Listener` types stay unexported, matching the native `live/pubsub.rs` re-export.
pub use wasm::pubsub::{
    cmd_publish, cmd_publish_no_echo, pubsub_publish, pubsub_publish_no_echo, sub_subscribe_topic,
};
";

/// Runtime call paths shadowed absent on the wasm target even though their module
/// is declared in [`WASM_RUNTIME_MOD_RS`] — a mostly-native module (`task`,
/// `time`, `crypto`, `http_client`) whose non-override functions have no wasm32
/// arm. A kernel-wrapper whose own body call path matches one of these is dropped
/// from the wasm prelude by [`wasm_runtime_bindings`], UNLESS that exact path is a
/// [`WASM_PRESENT_OVERRIDES`] entry (a landed browser substitute in the same
/// module). Keyed on call paths (structural), so a prelude drift auto-adapts.
const WASM_ABSENT_MODULE_PATHS: &[&str] = &[
    "ipe_runtime::task::",
    "ipe_runtime::http_client::",
    "ipe_runtime::crypto::",
    // `Io.readSecret` — a no-echo terminal password read. There is no terminal
    // in the browser, and its wrapper returns the `secret`-feature-gated
    // `ipe_runtime::secret::Secret`, which the closed vendored wasm template does
    // not enable. Dropping the wrapper here keeps the wasm prelude buildable and
    // matches the absence of a terminal on that target. The sibling `io_*`
    // wrappers stay (each names a distinct `ipe_runtime::io::io_*` path).
    "ipe_runtime::io::io_read_secret",
    // `time.rs` is vendored (its pure calendar kernels are allowlisted), but
    // the clock/sleep entry points inside it need the browser substitute
    // below — most of the module (chrono/tokio helpers) still isn't wasm-safe
    // by default, so the module path stays broadly excluded here too.
    "ipe_runtime::time::",
];

/// Exact wrapper-call substrings RETAINED even though their module path is in
/// [`WASM_ABSENT_MODULE_PATHS`] — the M4 substitute functions, each
/// `cfg(target_arch = "wasm32")`-gated in their own file (`crypto.rs`,
/// `http_client.rs`, `time.rs`). The rest of each of those modules
/// (AEAD/RSA crypto, the reqwest client, tokio clock/sleep) has no wasm32
/// arm and stays excluded — this is a per-function allowlist, not a
/// per-module one, so an un-substituted sibling kernel in the same file can
/// never silently become wasm-reachable.
const WASM_PRESENT_OVERRIDES: &[&str] = &[
    "ipe_runtime::crypto_core::crypto_random_bytes",
    "ipe_runtime::crypto_core::crypto_random_token",
    "ipe_runtime::http_client::http_get",
    "ipe_runtime::http_client::http_post",
    "ipe_runtime::http_client::http_request",
    "ipe_runtime::http_client::http_parse_query",
    "ipe_runtime::time::time_sleep",
    "ipe_runtime::time::time_now",
    "ipe_runtime::time::time_unix_millis",
    // `Task.*` pure future combinators (`task.rs`'s ungated half — no tokio
    // dependency). `task_run`/`task_parallel`/`task_retry_with` stay excluded
    // (tokio-bound; no wasm arm).
    "ipe_runtime::task::task_succeed",
    "ipe_runtime::task::task_fail",
    "ipe_runtime::task::task_map",
    "ipe_runtime::task::task_and_then",
    "ipe_runtime::task::task_map_error",
    "ipe_runtime::task::task_on_error",
    "ipe_runtime::task::task_from_result",
    "ipe_runtime::task::task_and_then_result",
    "ipe_runtime::task::task_sequence",
];

/// The modules [`WASM_RUNTIME_MOD_RS`] declares present on the wasm target,
/// parsed from its `pub mod <name>;` lines. A kernel wrapper whose denotation
/// targets a module outside this set — and outside the partial-module carve-outs
/// ([`WASM_ABSENT_MODULE_PATHS`] / [`WASM_PRESENT_OVERRIDES`]) — is unclassified
/// against the wasm module set, and [`wasm_runtime_bindings`] fails loud rather
/// than emitting a wrapper that names a module the manifest never compiles.
fn wasm_present_modules() -> BTreeSet<&'static str> {
    WASM_RUNTIME_MOD_RS
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let rest = trimmed.strip_prefix("pub mod ")?;
            let name = rest.strip_suffix(';').or_else(|| rest.strip_suffix(" {"))?;
            Some(name.trim())
        })
        .collect()
}

/// The `ipe_runtime::<module>::` denotations a kernel-wrapper `pub fn` body calls,
/// each as `(full_call_path, module)`. Only call paths are collected — a segment
/// followed by `(` — so an incidental parameter/return TYPE reference
/// (`ipe_runtime::path::Path`) is ignored and the classification keys on the
/// denotation the wrapper actually invokes.
fn wrapper_call_paths(block: &str) -> Vec<(&str, &str)> {
    const PREFIX: &str = "ipe_runtime::";
    let mut paths = Vec::new();
    let bytes = block.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = block.get(search_from..).and_then(|s| s.find(PREFIX)) {
        let start = search_from + rel;
        let after = start + PREFIX.len();
        // A path segment run: identifier chars, `::`, until a non-path byte.
        let mut end = after;
        while let Some(&c) = bytes.get(end) {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b':' {
                end += 1;
            } else {
                break;
            }
        }
        search_from = end;
        // A call denotation is immediately followed by `(`.
        if bytes.get(end) != Some(&b'(') {
            continue;
        }
        let Some(full) = block.get(start..end) else {
            continue;
        };
        // Module = the first segment after the `ipe_runtime::` prefix.
        let module = full
            .get(PREFIX.len()..)
            .and_then(|rest| rest.split("::").next())
            .unwrap_or("");
        if !module.is_empty() {
            paths.push((full, module));
        }
    }
    paths
}

/// The wasm-target kernel-wrapper prelude: [`runtime_bindings`] filtered to the
/// wrappers whose denotation is reachable on wasm32. A wrapper is kept only when
/// its call path is explicitly allowlisted ([`WASM_PRESENT_OVERRIDES`]) or targets
/// a module [`WASM_RUNTIME_MOD_RS`] declares present; a wrapper whose module is a
/// partial/absent carve-out ([`WASM_ABSENT_MODULE_PATHS`]) without an override is
/// dropped; and a wrapper whose denotation is none of these fails loud rather than
/// emitting a call the wasm manifest cannot resolve. The Layer-1 gate already
/// denies the kernels behind the dropped wrappers, so no emitted call site can
/// reference them.
fn wasm_runtime_bindings() -> DResult<String> {
    let full = runtime_bindings()?;
    let present = wasm_present_modules();
    let mut out = String::with_capacity(full.len());

    // Tokenize into a leading `head` (up to the first wrapper's own comment run or
    // `pub fn`) and a sequence of wrapper units, each owning its LEADING comment
    // lines. A unit's classification reads only its own `pub fn` body, and a
    // dropped unit takes its leading comment with it — so a comment mentioning a
    // carved-out module never drops an unrelated wrapper, and a dropped wrapper
    // never orphans its doc onto a kept neighbour.
    let mut pending_comments = String::new();
    let mut current: Option<String> = None;
    let mut head_done = false;

    // Emit the accumulated `current` wrapper unit iff it is wasm-reachable.
    let flush =
        |out: &mut String, comments: &mut String, unit: &mut Option<String>| -> DResult<()> {
            if let Some(body) = unit.take() {
                let block = format!("{comments}{body}");
                if wrapper_is_wasm_reachable(&block, &present)? {
                    out.push_str(&block);
                }
                comments.clear();
            }
            Ok(())
        };

    for line in full.split_inclusive('\n') {
        let is_comment = line.trim_start().starts_with("//");
        let is_fn = line.starts_with("pub fn ");
        if is_fn {
            // A new wrapper starts: emit the previous unit, then this line opens
            // the current unit with the pending comment run as its leading doc.
            flush(&mut out, &mut pending_comments, &mut current)?;
            head_done = true;
            current = Some(line.to_owned());
        } else if is_comment && (head_done || current.is_none()) {
            // A comment line: it leads the NEXT wrapper. Flush the current unit
            // first so the comment does not attach to it.
            flush(&mut out, &mut pending_comments, &mut current)?;
            pending_comments.push_str(line);
        } else if let Some(body) = current.as_mut() {
            // A continuation line of the current wrapper body.
            body.push_str(line);
        } else {
            // Head lines (before any `pub fn`): emitted verbatim.
            out.push_str(line);
        }
    }
    flush(&mut out, &mut pending_comments, &mut current)?;
    // Any trailing comment run with no following wrapper is emitted verbatim.
    out.push_str(&pending_comments);
    Ok(out)
}

/// Whether a wrapper unit's `pub fn` denotation is reachable on the wasm target:
/// an allowlisted override, or every call path targets a present module and none
/// hits a carve-out. A call path outside all three sets is unclassified and fails
/// loud rather than emitting an unresolved-path wasm crate.
fn wrapper_is_wasm_reachable(block: &str, present: &BTreeSet<&str>) -> DResult<bool> {
    let call_paths = wrapper_call_paths(block);
    // A wrapper is kept when its denotation is explicitly substituted on wasm.
    if call_paths
        .iter()
        .any(|(path, _)| WASM_PRESENT_OVERRIDES.contains(path))
    {
        return Ok(true);
    }
    for (path, module) in call_paths {
        if WASM_ABSENT_MODULE_PATHS.iter().any(|p| path.starts_with(p)) {
            return Ok(false);
        }
        if !present.contains(module) {
            return Err(unclassified_wrapper(path));
        }
    }
    // No carve-out reference and every call path targets a present module (or the
    // block calls nothing under `ipe_runtime::`) -> keep.
    Ok(true)
}

/// A kernel wrapper whose denotation targets a module absent from the wasm module
/// set and not carved out — a fail-closed refusal in place of emitting an
/// unresolved-path (E0433) wasm crate.
fn unclassified_wrapper(path: &str) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "backend.wasm_prelude",
        detail: format!(
            "kernel-wrapper denotation {path:?} targets a module not declared in the wasm \
             module set and not carved out by WASM_ABSENT_MODULE_PATHS / WASM_PRESENT_OVERRIDES"
        ),
    }
}

/// The `--target wasm` entry: `#[wasm_bindgen(start)]` replacing `fn main`.
/// The panic hook makes a residual trap die with a classified console error;
/// the entry task runs on the browser microtask queue.
const WASM_ENTRY: &str = "\
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn ipe_start() {
    ipe_runtime::wasm::install_panic_hook();
    ipe_runtime::wasm::run_start(ipe_main());
}
";

/// The `[wasm] mode = "hydrate"` second entry: parses island JSON as the
/// user-declared `HydrationState` type, converts via `fromHydrationState`
/// (`main_from_hydration_state`), and adopts the server-rendered DOM.  On any
/// parse error it falls back to a clean `ipe_main()` init (fault-tolerant: no
/// white screen on a tampered or stale island blob).
///
/// `hydration_state_ty` is the Rust type name resolved by
/// [`EmitCtx::resolve_hydration_state_rust_name`] — the SAME name the emitted
/// `main_from_hydration_state` signature uses, so the parse target and the
/// projection's parameter type are one identical type (a record alias
/// `{ count : Int }` yields its synthesised `RecCount`, a named ADT yields
/// `MainHydrationState`, etc.). Interpolating it — rather than hardcoding a
/// convention name the record-alias emitter never produces — is what makes the
/// emitted crate compile (issue #224).
fn wasm_hydrate_entry(hydration_state_ty: &str) -> String {
    // The app's `view : Model -> Element Msg` is adapted to the `Html` the wasm
    // sink mounts through the SAME `ui_layout` wrap the regular Web entry uses —
    // `wasm_adopt_app`'s `FView` bound is `Fn(Model) -> Html<Msg>`, and a raw
    // `main_view` returns `Element<Msg>`. Sharing `wrap_view` keeps the hydrate
    // takeover and the clean-init boot rendering one identical view.
    let wrapped_view = crate::emit_web::wrap_view("crate::main_view");
    format!(
        "\
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate(model_json: &str) {{
    match serde_json::from_str::<crate::{hydration_state_ty}>(model_json) {{
        Ok(hs) => {{
            let model = crate::main_from_hydration_state(hs);
            ipe_runtime::wasm::run_start(ipe_runtime::wasm::wasm_adopt_app::<
                String, _, _, _, _, _,
            >(
                model,
                crate::main_update,
                {wrapped_view},
                crate::main_subscriptions,
            ));
        }}
        Err(e) => {{
            ipe_runtime::wasm::console_warn(&format!(
                \"hydrate: island JSON rejected ({{e}}); falling back to clean init\"
            ));
            ipe_runtime::wasm::run_start(ipe_main());
        }}
    }}
}}
"
    )
}

/// [`epilogue`] with the native `fn main` block replaced by [`WASM_ENTRY`],
/// and — when `ctx.wasm_hydrate_mode` AND the program declares a
/// `fromHydrationState` projection — a second `hydrate` wasm-bindgen export for
/// fault-tolerant SSR takeover (M7 §"Fault-tolerant hydrate").
///
/// The island parse target is [`EmitCtx::hydration_state_rust_name`], resolved
/// from `fromHydrationState`'s parameter through the same renderer that emits
/// its `main_from_hydration_state` signature — so the two agree on ONE type
/// name and the emitted crate compiles (issue #224). A hydrate-mode program
/// with no `fromHydrationState` has no island type to name, so it emits only
/// the `ipe_start` entry (the runtime still boots via a clean init).
fn epilogue_wasm(ctx: &EmitCtx) -> DResult<String> {
    const BANNER: &str = "// ===========================================\n// ENTRY POINT\n";
    let full = epilogue()?;
    let head = full
        .split(BANNER)
        .next()
        .ok_or_else(|| anchor_missing(BANNER))?;
    if head.len() == full.len() {
        return Err(anchor_missing(BANNER));
    }
    let mut out = Items::new();
    out.push(head);
    out.push(&format!(
        "{BANNER}// ==========================================="
    ));
    out.push(WASM_ENTRY);
    if ctx.wasm_hydrate_mode
        && let Some(ty) = ctx.hydration_state_rust_name.as_deref()
    {
        out.push(&wasm_hydrate_entry(ty));
    }
    Ok(out.render())
}

/// Layer-3 defence-in-depth: a server-surface flag under the wasm target is
/// unreachable (the Layer-1 gate denies every kernel that sets one); reaching
/// here means the gate and the emitter disagree — fail loud, never emit.
///
/// `websocket` is deliberately NOT in this list (as of M4): `Ipe.WebSocket`'s
/// Task-tier client (connect/connectWith/send/sendBinary/close/closeWithCode)
/// now has a real `web_sys::WebSocket` substitute (`ws_client.rs`'s
/// `cfg(target_arch = "wasm32")` arm), tagged `WasmClient` in the Layer-1
/// registry — `ctx.uses_websocket` is therefore an EXPECTED wasm-reachable
/// flag, not a gate/emitter disagreement.
fn assert_wasm_admissible(ctx: &EmitCtx) -> DResult<()> {
    let denied = [
        ("db", ctx.uses_db),
        ("server", ctx.uses_server),
        ("tui", ctx.uses_tui),
        ("webview", ctx.uses_webview),
        ("email", ctx.uses_email),
        ("auth", ctx.uses_auth),
        ("ffi", ctx.uses_ffi),
    ];
    for (name, used) in denied {
        if used {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::assert_wasm_admissible",
                detail: format!(
                    "program reached emission with server-only surface `{name}` under \
                     --target wasm — the Layer-1 kernel gate should have rejected it"
                ),
            });
        }
    }
    Ok(())
}

// ── db-enabled manifest fragments ──────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses Db kernels.
///
/// The full runtime source tree is copied into the emitted project by the
/// driver; this addition wires `db.rs` (which lives in that tree) into the
/// module namespace so the generated `main.rs` can call the db functions.
const RUNTIME_MOD_RS_DB_APPEND: &str = "pub mod db;\npub use db::*;\npub mod telemetry_spill;\n";

/// Lines appended to `ipe_runtime/mod.rs` for the typed DSN descriptor and the
/// external-connection pool when the program uses Db kernels.
///
/// `dsn.rs` (the opaque `Ipe.Db.Dsn` parse-don't-validate descriptor) and
/// `external_conn.rs` (the live `Ipe.Db.Connection` pool for a database the app
/// was not built against) are declared alongside `db`. Both are gated on the
/// `db` feature in the real runtime `mod.rs`; the vendored trimmed template must
/// declare them under the same condition so the transitive-closure invariant
/// holds: `external_conn.rs` calls `crate::dsn::{Dsn, DsnDriver}`, and both
/// `external_conn.rs` and `db.rs` call `crate::ssrf::VettedDial` (the SSRF
/// module is appended by the shared SSRF predicate which now includes `uses_db`).
/// `dsn.rs` and `external_conn.rs` reach only the always-on `secret` and `core`
/// base modules plus `ssrf`, so declaring them here adds no new dependencies
/// beyond those already forced by `uses_db`.
const RUNTIME_MOD_RS_DB_DSN_APPEND: &str =
    "pub mod dsn;\npub use dsn::*;\npub mod external_conn;\npub use external_conn::*;\n";

// ── TEA Cmd / Sub ─────────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses TEA kernels
/// (`Cmd.none / batch / perform`, `Sub.none / batch / every`, `Time.every`).
///
/// `tea.rs` lives in the runtime source tree (ungated — no cargo feature
/// needed); this addition makes `cmd_none` / `sub_every` / … available in the
/// emitted `main.rs` namespace via `pub use ipe_runtime::*`.
const RUNTIME_MOD_RS_TEA_APPEND: &str = "pub mod tea;\npub use tea::*;\n";

// ── Ipe.Http.Server ──────────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses the axum server
/// surface (`uses_server || uses_web`). NOT webview — the desktop-webview
/// delivery renders over a local IPC bridge and links no HTTP server.
///
/// `server.rs` and `server_stream.rs` are gated by the `server` Cargo feature
/// in the runtime source. The generated Cargo.toml's default features include
/// `"server"` when these lines are appended. `http_stream.rs` is NOT included
/// here — it is declared only when the program uses `Ipe.Http.Stream` kernels
/// (`uses_http`), keeping reqwest out of web apps that make no outbound HTTP
/// calls AND keeping `tea.rs` out of email-only programs.
const RUNTIME_MOD_RS_SERVER_APPEND: &str = "pub mod server;\npub use server::*;\n\
    pub mod server_stream;\npub use server_stream::*;\n";

/// Lines appended to `ipe_runtime/mod.rs` when the program uses `Ipe.Http.Stream`
/// (`uses_http`).
///
/// `http_stream.rs` (the client-side streaming reader for `Ipe.Http.Stream`)
/// calls `crate::http_client::ssrf_apply` + `method_to_reqwest`, so `http_client`
/// must be declared first (via `RUNTIME_MOD_RS_HTTP_CLIENT_APPEND`). It is NOT
/// declared for `uses_email`-only programs, which reach `http_client` only for
/// SSRF validation in `email.rs`, not for streaming.
const RUNTIME_MOD_RS_HTTP_STREAM_APPEND: &str = "pub mod http_stream;\npub use http_stream::*;\n";

// ── Ipe.Http — outbound HTTP client ─────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program reaches the outbound
/// `Ipe.Http` client surface.
///
/// `http_client.rs` (the reqwest-backed sender plus the pure request/method
/// builders and `http_parse_query`) is vendored into every emitted crate but
/// declared only on demand — it is the sole consumer of the `reqwest` crate,
/// which [`http_client_cargo_toml`] adds under the same condition. The module
/// is declared when a program calls a client kernel (`uses_http`) or uses the
/// email surface (`email.rs` calls `http_client::ssrf_apply`). Web and server
/// modules make no outbound HTTP calls and do not require this module.
const RUNTIME_MOD_RS_HTTP_CLIENT_APPEND: &str = "pub mod http_client;\npub use http_client::*;\n";

/// Lines appended to `ipe_runtime/mod.rs` for the SSRF deny-private validators.
///
/// `ssrf.rs` parses URLs with the `url` crate (unconditional base dep) and is
/// reqwest-free. Its validators are consumed by the `http_client`, `ws_client`,
/// and `db` modules (the latter calls `VettedDial` in `VettedPool::connect` and
/// `external_conn.rs` uses it unconditionally).
///
/// Declared `pub` so that in the vendored emit model — where all runtime modules
/// live under `src/ipe_runtime/` — the `pub use ipe_runtime::*;` at the crate
/// root re-exports `ssrf`, making `crate::ssrf::VettedDial` resolvable from
/// `db.rs` and `external_conn.rs` which use absolute `crate::ssrf` paths.
const RUNTIME_MOD_RS_SSRF_APPEND: &str = "pub mod ssrf;\n";

// ── Ipe.Url — typed, validated URLs ──────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the emitted crate reaches the
/// `url` runtime module.
///
/// `url.rs` (the opaque, validated `Ipe.Url` type + its accessors) is a
/// consumer of the `url` crate, whose transitive `idna` → ICU4X subtree is the
/// single largest gateable dependency root. It is declared when the program
/// reaches it — directly (`uses_url`) or through a surface whose own runtime
/// module parses with the `url` crate: the outbound HTTP client
/// (`http_client.rs` targets a typed `crate::url::Url`) and the WebSocket
/// client (`ws_client.rs` calls `::url::Url::parse`). The shared `ssrf`
/// validators (`use url::Url`) are declared exactly when either of those two is,
/// so the same predicate ([`EmitCtx::reaches_url`]) covers them. A pure-CLI
/// program keeps `url` absent, dropping the whole `idna`/ICU4X tree.
const RUNTIME_MOD_RS_URL_APPEND: &str = "pub mod url;\npub use url::*;\n";

// ── Ipe.Config — TOML/YAML decoders ─────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses an `Ipe.Config`
/// decoder that reaches the `config_decode` runtime module.
///
/// `config_decode.rs` (the `Config.decodeToml` / `decodeYaml` / `decodeJson` /
/// `loadFromFile` front-ends plus the `nullable` / `maybe` / `dict`
/// combinators) is vendored into every emitted crate but declared only on
/// demand — it is the sole consumer of the `toml` and `serde_yaml` crates,
/// which [`config_cargo_toml`] adds under the same condition. It is a leaf
/// module (no other runtime surface calls into it), so it is declared exactly
/// when the program reaches it directly, and never forced on transitively. The
/// always-on `config` module (the `Ipe.Config` environment-variable surface)
/// stays unconditional and is unaffected.
const RUNTIME_MOD_RS_CONFIG_APPEND: &str = "pub mod config_decode;\npub use config_decode::*;\n";

// ── Ipe.Compression — gzip/zstd ─────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses an
/// `Ipe.Compression` kernel (`Compression.gzip` / `gunzip` / `zstdCompress` /
/// `zstdDecompress`).
///
/// `compression.rs` (the gzip/zstd byte-buffer kernels) is vendored into every
/// emitted crate but declared only on demand — it is the sole consumer of the
/// `flate2` and `zstd` crates, which [`compression_cargo_toml`] adds under the
/// same condition. It is a leaf module (no other runtime surface calls into
/// it), so it is declared exactly when the program reaches it directly, and
/// never forced on transitively.
const RUNTIME_MOD_RS_COMPRESS_APPEND: &str = "pub mod compression;\npub use compression::*;\n";

// ── Ipe.Csv — CSV parse/encode ──────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses an `Ipe.Csv`
/// kernel (`Csv.parse` / `parseWithDelimiter` / `encode` / `encodeWithDelimiter`
/// / `parseStreamFromFile`) or a signature mentioning `CsvDoc`.
///
/// `csv.rs` (the CSV parse/encode kernels plus the `CsvDoc` struct) is vendored
/// into every emitted crate but declared only on demand — it is the sole
/// consumer of the `csv` crate, which [`csv_cargo_toml`] adds under the same
/// condition. It is a leaf module (no other runtime surface calls into it), so
/// it is declared exactly when the program reaches it directly, and never forced
/// on transitively.
const RUNTIME_MOD_RS_CSV_APPEND: &str = "pub mod csv;\npub use csv::*;\n";

// ── Shape-app entry-switch anchors ────────────────────────────────────────────
//
// When `ipe_main` returns a shape-app leaf (WebApp / TuiApp / CliApp — and a
// `Web.tea` under a webview-native host renders `WebViewApp`), `emit_func`
// emits the correct return type from the IR — no return-type rewrite is needed.
// Only the epilogue `fn main` body needs updating:
// `block_on(ipe_main())` → `ipe_main().run_blocking()`. Hoisted to module
// scope so no `const` item appears after a statement.

/// The `block_on(ipe_main())` call in `fn main`'s epilogue body.
const SHAPE_APP_BLOCK_ON_ANCHOR: &str = "block_on(ipe_main())";
/// Replacement: calls the leaf type's `run_blocking()` method.
const SHAPE_APP_RUN_BLOCKING: &str = "ipe_main().run_blocking()";
/// `ipe_main`'s RETURN-TYPE render for each shape-app leaf. The entry switch
/// fires only when `ipe_main`'s own signature returns a leaf — NOT merely when a
/// leaf constructor appears anywhere in the body. A `Server.mountApp
/// (Web.embed { … })` program builds a `WebApp(…)` value inside `ipe_main`'s
/// body but `ipe_main` itself returns `IpeTask<()>` (`Server.listen`), so it is
/// a Program (`block_on`), not a shape app. Keying on the return type keeps the
/// two apart.
const SHAPE_APP_RETURN_TYPES: &[&str] = &[
    "fn ipe_main() -> ipe_runtime::tea::WebViewApp",
    "fn ipe_main() -> ipe_runtime::tea::WebApp",
    "fn ipe_main() -> ipe_runtime::tea::TuiApp",
    "fn ipe_main() -> ipe_runtime::tea::CliApp",
    "fn ipe_main() -> ipe_runtime::tea::WorkerApp",
];

// ── Ipe.Encoding / Ipe.Bytes — base64 / hex / percent codecs ─────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program reaches the codec
/// crates — an `Ipe.Encoding` / `Ipe.Bytes` kernel ([`EmitCtx::uses_encoding`]),
/// OR a crypto/db/server/email/jwt/web surface whose runtime module uses the raw
/// `base64` / `hex` / `percent-encoding` crates ([`EmitCtx::reaches_encoding`]).
///
/// `encoding.rs` (the `Ipe.Encoding` codecs) and `bytes.rs` (the `Ipe.Bytes`
/// buffer kernels) are vendored into every emitted crate but declared only on
/// demand — they are behind the `encoding` feature, which the `runtime_features`
/// SSOT selects into `__IPE_RUNTIME_FEATURES__` under the same
/// [`EmitCtx::reaches_encoding`] condition. Declared here whenever the program
/// reaches the codec crates so the selected feature (and its `base64` / `hex` /
/// `percent-encoding` deps) and the module declarations can never disagree — the
/// same fail-closed SSOT discipline as `jwt` / `url`.
const RUNTIME_MOD_RS_ENCODING_APPEND: &str =
    "pub mod encoding;\npub use encoding::*;\npub mod bytes;\npub use bytes::*;\n";

// ── Ipe.Regex — regular expressions + String.isUrl ──────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program reaches the `regex`
/// crate — an `Ipe.Regex` kernel OR `String.isUrl` ([`EmitCtx::uses_regex`]).
///
/// `regex_kernel.rs` is the sole consumer of the `regex` crate; its
/// `string_is_url` validator moved in from `string.rs` (the only other regex-crate
/// user), so `String.isUrl` reaches it too. Declared only on demand — behind the
/// `regex` feature, which [`runtime_features`] selects under the same
/// [`EmitCtx::uses_regex`] condition and [`regex_cargo_toml`] adds the dep for. A
/// standalone leaf: no surface implies it.
const RUNTIME_MOD_RS_REGEX_APPEND: &str = "pub mod regex_kernel;\npub use regex_kernel::*;\n";

// ── Ipe.Uuid — v4 / v7 / parse ──────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program reaches the `uuid`
/// crate — an `Ipe.Uuid` kernel, OR the `server` / `web` surfaces whose runtime
/// modules mint session/CSRF ids via `uuid::new_v4`, OR the `jwt` / `auth` surface
/// whose `auth.rs` calls `uuid::Uuid::new_v4()` to mint per-session `jti` ids
/// ([`EmitCtx::reaches_uuid`]).
///
/// `uuid_kernel.rs` exposes the `Ipe.Uuid` kernels. Declared only on demand —
/// behind the `uuid` runtime feature, which [`runtime_features`] selects under the
/// same [`EmitCtx::reaches_uuid`] condition. A bare Program that reaches none drops
/// the crate.
const RUNTIME_MOD_RS_UUID_APPEND: &str = "pub mod uuid_kernel;\npub use uuid_kernel::*;\n";

// ── Ipe.Random — non-cryptographic PRNG ─────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program reaches an
/// `Ipe.Random` kernel ([`EmitCtx::uses_random`]).
///
/// `random.rs` (the LCG / seeded-generator surface) is declared only on demand —
/// behind the `random` feature, which [`runtime_features`] selects under the same
/// condition. A standalone leaf: no surface implies it. The `random` feature gates
/// this MODULE declaration only; the `getrandom` crate is always present (the
/// scratch primitive's entropy source, shared with the crypto floor).
const RUNTIME_MOD_RS_RANDOM_APPEND: &str = "pub mod random;\npub use random::*;\n";

// ── Ipe.Crypto — heavy cryptography (SHA-1/MD5, AEAD, PBKDF2) ────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses a HEAVY
/// `Ipe.Crypto` kernel (legacy SHA-1/MD5, AES-GCM / ChaCha20-Poly1305 AEAD, or
/// PBKDF2 key derivation).
///
/// `crypto.rs` (the heavy AEAD/checksum kernels) is vendored into every emitted
/// crate but declared only on demand — it is the sole consumer of the `sha1`,
/// `md-5`, `aes-gcm`, `chacha20poly1305`, and `pbkdf2` crates, which
/// [`crypto_cargo_toml`] adds under the same condition. The
/// `crypto_core` floor (SHA-2, HMAC, RSA, constant-time compare, the entropy
/// pair, the `Key`/`Mac` newtypes) stays in the base module set — `crypto.rs`
/// re-exports it, but nothing else reaches the heavy module, so the flag alone
/// gates it, never forced on transitively.
const RUNTIME_MOD_RS_CRYPTO_APPEND: &str = "pub mod crypto;\npub use crypto::*;\n";

// ── Ipe.Jwt — JSON Web Token encode/decode ──────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program reaches the `jwt`
/// runtime module (a `Ipe.Jwt` kernel, or the `Ipe.Auth` surface — `auth.rs`
/// calls `crate::jwt::…`).
///
/// `jwt.rs` is the sole direct consumer of the `jsonwebtoken` crate, which
/// [`jwt_cargo_toml`] adds under the same condition. It reaches only the
/// `crypto_core` floor (`super::crypto_core::…`), so declaring it
/// pulls no other gated module.
const RUNTIME_MOD_RS_JWT_APPEND: &str = "pub mod jwt;\npub use jwt::*;\n";

// ── Shared transitive dep: http_header ──────────────────────────────────────
//
// `http_header.rs` (a dependency-free leaf exposing `canonical_header`) is part
// of the base `mod.rs` (`tests/golden/basics/ipe_runtime/mod.rs`); it is
// reqwest-free and pulls no gated dependency, so it stays unconditional. A
// conditional `pub mod http_header;` would duplicate the base declaration
// (E0428) for server/live programs.

// ── Ipe.Auth ──────────────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses Ipe.Auth
/// kernels (`Auth.hashPassword` / `verifyPassword` / `signToken` /
/// `verifyToken` / `register` / `login` / `setRole` etc.).
///
/// `auth.rs` requires `bcrypt` (password hashing, an unconditional base dep) and
/// reaches `crate::jwt` for JWT signing/verification. The `jwt` module and its
/// `jsonwebtoken` dependency are gated (see [`RUNTIME_MOD_RS_JWT_APPEND`] /
/// [`jwt_cargo_toml`]), so the backend force-declares `jwt` alongside `auth`
/// via [`EmitCtx::reaches_jwt`]; this append handles only the `auth` module
/// declaration itself.
const RUNTIME_MOD_RS_AUTH_APPEND: &str = "pub mod auth;\npub use auth::*;\n";

/// Lines appended to `ipe_runtime/mod.rs` when the program uses
/// `Ipe.Auth.subject` (or another `Principal`-touching kernel).
///
/// `principal.rs` (the opaque authenticated-subject newtype + its read
/// accessors `principal_subject` / `principal_claim` / `principal_has_role` /
/// `principal_member_of`) is vendored into every emitted crate but declared only
/// on demand — a pure-CLI program that never reads a `Principal` keeps it out of
/// the module namespace (`dead_code`). Every accessor emitted as a bare kernel
/// name (`kernel_name` → `def().runtime_fn`) must be re-exported here, or the
/// emitted `main.rs` call fails E0425 despite `ipe` exit 0 (SEAL breach).
const RUNTIME_MOD_RS_PRINCIPAL_APPEND: &str = "pub mod principal;\npub use principal::{\
    Principal, principal_claim, principal_has_role, principal_member_of, principal_subject,\
};\n";

/// Lines appended to `ipe_runtime/mod.rs` when the program uses authenticated
/// routes (`Ipe.Auth.subject` / an `authed_route` surface).
///
/// `revocation.rs` (the session-revocation store and fail-closed gate) is
/// vendored into every emitted crate but declared only when the authed-route
/// surface is in use — the store's `is_revoked` query is called from `server.rs`'s
/// `authed_route` middleware, which is compiled in whenever a `Principal` is in
/// scope. `revocation.rs` depends only on `crate::principal` (appended by
/// [`RUNTIME_MOD_RS_PRINCIPAL_APPEND`] under the same gate) and `super::*`
/// (the base module set) — no additional dependencies.
const RUNTIME_MOD_RS_REVOCATION_APPEND: &str = "pub mod revocation;\npub use revocation::*;\n";

// ── Ipe.WebSocket — outbound WebSocket client ──────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses outbound
/// `Ipe.WebSocket` client kernels.
///
/// `ws_client.rs` is gated by the `websocket_client` Cargo feature in the
/// runtime source; this addition wires it into the module namespace so the
/// generated `main.rs` can call `web_socket_connect` / `web_socket_send` / … and
/// the `sub_subscribe_ws_*` subscription fns via `pub use ipe_runtime::*`.
///
/// `ssrf.rs` (`ws_client`'s SSRF validators) is declared by
/// [`RUNTIME_MOD_RS_SSRF_APPEND`], force-appended alongside this in
/// [`assemble_project_files`] (the SSRF module is shared with `http_client`).
/// `tea.rs` (whose `IpeSub<M>` the `sub_subscribe_ws_*` fns return) is
/// force-appended alongside this too, mirroring the `uses_server` rule.
const RUNTIME_MOD_RS_WEBSOCKET_APPEND: &str = "pub mod ws_client;\npub use ws_client::*;\n";
// ── Ipe.Email ───────────────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses the `Ipe.Email`
/// `Email.send` kernel.
///
/// `email.rs` is in the runtime source tree (vendored into every emitted crate)
/// but declared only on demand. It calls into `http_client` (for the shared
/// `ssrf_apply` request hardening), so `uses_email` also pulls the
/// `http_client` module and the `reqwest` dep via the shared HTTP-client
/// predicate in [`assemble_project_files`]. Its other crates (`base64` /
/// `hmac` / `sha2` / `serde_json` / `url`) are unconditional base deps; `lettre`
/// (the SMTP transport) is the one extra dep added by [`email_cargo_toml`] when
/// `uses_email` is set. No runtime feature flag is involved — the emitted crate
/// vendors the source directly, so declaring the module + adding `lettre` is
/// sufficient.
const RUNTIME_MOD_RS_EMAIL_APPEND: &str = "pub mod email;\npub use email::*;\n";

// ── Ipe.Locale ─────────────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses the `Ipe.Locale`
/// surface (`Locale.fromTag`, `Locale.toTag`, `String.toUpperIn`,
/// `String.toLowerIn`), or any emittable type position mentions `IrType::Locale`.
///
/// `locale.rs` is in the runtime source tree (vendored into every emitted crate)
/// but declared only on demand. The ICU4X parse path inside `locale.rs` is gated
/// behind `#[cfg(feature = "locale")]`; the `locale_cargo_toml` surgery enables
/// that feature and adds `icu_casemap` + `icu_locale_core` as optional deps.
/// Under the dependency model the `locale` Cargo feature is propagated through
/// `RuntimeFeature::Locale` (see `runtime_features.rs`), so no manifest surgery
/// is needed on that path.
const RUNTIME_MOD_RS_LOCALE_APPEND: &str = "pub mod locale;\npub use locale::*;\n";

// ── Ipe.Env ────────────────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses the `Ipe.Env`
/// `Env.public` kernel.
///
/// Unlike `ws_client`/`email`, `env_public.rs` is NOT vendored from the
/// source tree — it is generated per-project by [`render_env_public_rs`]
/// (its content is project-specific: the `package.ipe` `[wasm] publicEnv`
/// allowlist). No extra Cargo dependency or feature flag: `option_env!`/
/// `std::env::var` are both `std`-only.
const RUNTIME_MOD_RS_ENV_PUBLIC_APPEND: &str = "pub mod env_public;\npub use env_public::*;\n";

/// Render the per-project `ipe_runtime/env_public.rs`: `Env.public`'s runtime
/// backing, generated from `allowlist` (`package.ipe`'s `[wasm] publicEnv`,
/// already validated against the secret-name denylist at PARSE time — see
/// `ipe_cli::project::is_denylisted_public_env_name`).
///
/// One `env_public` fn per target, `#[cfg]`-split: wasm32 embeds each
/// allowlisted key's value at BUILD time via `option_env!` (a browser has no
/// live process environment to read at runtime); native reads the SAME
/// allowlisted key from the live environment via `std::env::var`, so a
/// module shared between a native SSR path and the wasm client behaves
/// identically against both — same allowlist, same set of readable keys,
/// only the READ MECHANISM differs. A key absent from `allowlist` has no
/// match arm on EITHER target and therefore always yields `None` — there is
/// no code path from an arbitrary runtime string back to the raw host/process
/// environment, on either target.
///
/// Each key is emitted via `{key:?}` (Rust's `Debug` string-literal escaping)
/// on BOTH the match-arm pattern and the `option_env!`/`std::env::var`
/// argument, so a key containing a quote or backslash (an unusual but
/// syntactically legal env-var name) round-trips through the generated
/// source safely rather than corrupting it.
#[must_use]
fn render_env_public_rs(allowlist: &[String]) -> String {
    use std::fmt::Write as _;

    let mut wasm_arms = String::new();
    let mut native_arms = String::new();
    for key in allowlist {
        let lit = format!("{key:?}");
        // `write!` into an owned `String` buffer is infallible; the `Result`
        // exists only for the generic `fmt::Write` trait, never actually
        // produced here — discard it rather than `.unwrap()` (clippy's
        // `format_push_string` lint prefers this over `push_str(&format!(..))`,
        // which allocates twice).
        let _ = writeln!(
            wasm_arms,
            "        {lit} => option_env!({lit}).map_or(IpeMaybe::Nothing, \
             |v| IpeMaybe::Just(v.to_owned())),"
        );
        let _ = writeln!(
            native_arms,
            "        {lit} => std::env::var({lit}).map_or(IpeMaybe::Nothing, IpeMaybe::Just),"
        );
    }
    format!(
        "// GENERATED by Ipê — do not edit ([wasm] publicEnv allowlist)\n\
         //\n\
         // `Ipe.Env.public \"KEY\"` resolves ONLY for a name on this project's\n\
         // `package.ipe` `[wasm] publicEnv` allowlist; every other key returns\n\
         // `Nothing` by construction (no match arm reaches it). wasm32 embeds\n\
         // each value at BUILD time (`option_env!`); native reads the SAME\n\
         // allowlisted key from the live environment (`std::env::var`).\n\
         use super::core::IpeMaybe;\n\
         \n\
         #[cfg(target_arch = \"wasm32\")]\n\
         pub fn env_public(key: String) -> IpeMaybe<String> {{\n\
         \x20   match key.as_str() {{\n\
         {wasm_arms}\
         \x20       _ => IpeMaybe::Nothing,\n\
         \x20   }}\n\
         }}\n\
         \n\
         #[cfg(not(target_arch = \"wasm32\"))]\n\
         pub fn env_public(key: String) -> IpeMaybe<String> {{\n\
         \x20   match key.as_str() {{\n\
         {native_arms}\
         \x20       _ => IpeMaybe::Nothing,\n\
         \x20   }}\n\
         }}\n"
    )
}

// ── Ipe.Ui / Ipe.Html ───────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses Ipe.Ui /
/// Ipe.Html render kernels.
///
/// `html.rs` and `ui/mod.rs` are in the runtime source tree; this addition
/// wires both into the module namespace. `html` is always paired with `ui`
/// because the `ui::element` and `ui::render` modules import from `html`.
/// Note: intentionally NOT `pub use ui::*;` because `ui::Attribute` collides
/// with `html::Attribute` (T2 soundness trap) — callers use the fully-qualified
/// `ipe_runtime::ui::element::Attribute` path instead.
///
/// The `css_safety` / `css` declarations are NOT here — they live in
/// [`RUNTIME_MOD_RS_CSS_APPEND`], which is pushed BEFORE this append whenever
/// `uses_ui || uses_css` holds. `html.rs` (`use super::css_safety;`),
/// `ui/render.rs` (`SafeCssPropertyName`/`SafeCssValue`), and
/// `live/style_inject.rs` (`strip_style_close`) all import `css_safety` from the
/// `ipe_runtime` top level, so it MUST be declared before this UI append or
/// those imports fail (E0432) — the caller preserves that ordering. Splitting
/// css out lets a pure-`Ipe.Css` program (no render kernel ⇒ no `uses_ui`) still
/// get the css declarations via `uses_css` alone.
///
/// `dom` (the target-neutral DOM data path) is declared here too, NOT in the
/// base module set: it is mutually referential with `html` (`html.rs` calls
/// `crate::dom::form::decode_form_or_warn`; `dom/{diff,dispatch,form}.rs`
/// import `crate::html::*`), so the two MUST appear together. A non-render
/// program (a plain CLI / headless server) declares neither — declaring `dom`
/// unconditionally in the base while `html` was append-only left `dom`'s
/// `use crate::html::*` unresolved, an `ipe`-exit-0-then-cargo-fail (E0432).
const RUNTIME_MOD_RS_UI_APPEND: &str =
    "pub mod html;\npub use html::*;\npub mod dom;\npub mod ui;\n";

/// Lines appended to `ipe_runtime/mod.rs` when the program uses the `Ipe.Css`
/// leaf security kernels (`Ipe.CssSafety.safeValue` / `safePropName` /
/// `safeSelector` / `stripStyleClose`) — OR any `Ipe.Ui` / `Ipe.Html`
/// render kernel (whose runtime modules import `css_safety` at the top level).
///
/// `css_safety.rs` is a dependency-free, audited leaf; `css.rs` (the four
/// `Ipe.Css` leaf kernels — `safe_value` / `safe_prop_name` / `safe_selector` /
/// `strip_style_close_kernel`) depends only on `css_safety`, and is glob-re-
/// exported (`pub use css::*;`) so the emitted `pub use ipe_runtime::*;`
/// surfaces those bare kernel names that `naming::kernel_name` emits. Both live
/// in the runtime source tree (copied into every emitted project); this append
/// wires them into the trimmed `mod.rs`.
///
/// Pushed BEFORE [`RUNTIME_MOD_RS_UI_APPEND`] because `html.rs` and friends
/// import `css_safety` — it must be declared first. Guarded on
/// `uses_ui || uses_css` and appended AT MOST ONCE, so a program that uses both
/// `Ipe.Css` and `Ipe.Ui` does not emit a duplicate `pub mod css_safety;`
/// (`E0428`).
const RUNTIME_MOD_RS_CSS_APPEND: &str = "pub mod css_safety;\npub mod css;\npub use css::*;\n";

/// Lines appended to `ipe_runtime/mod.rs` when any render-capable shape is
/// active (`uses_ui || uses_tui || uses_web || uses_webview`).
///
/// `seal_codec.rs` is a dependency of `ui/widget.rs` (via
/// `use crate::seal_codec::{SealLimits, seal_decode_serde}` under
/// `#[cfg(feature = "json")]`) and of `web/mod.rs` (via
/// `use crate::seal_codec::{SealLimits, seal_boundary_check}` under
/// `#[cfg(all(feature = "json", feature = "tokio"))]`). Both gates are
/// satisfied for every emitted render-capable program (the vendored template's
/// `default = ["json"]` keeps the `json` feature on; `tui`/`web`/`webview`
/// shapes also enable `tokio`). Without this append those imports fail with
/// E0432 (`unresolved import crate::seal_codec`) at `cargo build` despite
/// `ipe` exiting 0 — the module-set SEAL breach this constant closes.
///
/// Pushed BEFORE [`RUNTIME_MOD_RS_CSS_APPEND`] (and therefore before
/// [`RUNTIME_MOD_RS_UI_APPEND`]) because `seal_codec.rs` is a leaf with no
/// runtime-module deps of its own, and correctness requires it to be declared
/// before the modules that import it.
const RUNTIME_MOD_RS_SEAL_CODEC_APPEND: &str = "pub mod seal_codec;\n";

// ── Ipe.Tui / Ipe.Tui ───────────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses Ipe.Tui /
/// Ipe.Tui app-entry kernels.
///
/// Both `tui/app.rs` and `tui/layout.rs` (and their dependencies `cell.rs`,
/// `diff.rs`, `focus.rs`, `key.rs`) are gated by the `tui` Cargo feature in the
/// runtime source.  This addition wires `tui::tui_app` and `tui::tui_app_ui`
/// into the module namespace so the generated `main.rs` can call them via
/// `ipe_runtime::tui::tui_app_ui`.
///
/// The `ui` module must also be loaded (tui/layout.rs imports `super::ui::Element`)
/// — but `uses_ui` is set whenever `uses_tui` is set (a Tui app always references
/// Ipe.Ui Element/attribute kernels), so `RUNTIME_MOD_RS_UI_APPEND` is already
/// appended by the time this addition fires. `tui` also probes the terminal
/// through the std-only `terminal_access` module, declared here unconditionally.
const RUNTIME_MOD_RS_TUI_APPEND: &str = "pub mod terminal_access;\n\
     #[cfg(feature = \"tui\")]\npub mod tui;\n\
     #[cfg(feature = \"tui\")]\npub use tui::{tui_app, tui_app_ui};\n";

// ── Ipe.WebView / Ipe.WebView ───────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses Ipe.WebView /
/// Ipe.WebView app-entry kernels.
///
/// `webview.rs` is gated by the `webview` Cargo feature in the runtime source
/// (wry + tao deps). This addition wires `webview::webview_app` and
/// `webview::WebViewWindowCfg` into the module namespace so the generated
/// `main.rs` can call them.
///
/// The webview backend imports the SERVER-FREE render core through the `web::`
/// path (`web::dispatch::build_index`, `web::page_shell`,
/// `web::style_inject::apply_style_injections`) plus `crate::html::*`. A
/// desktop-webview delivery runs no HTTP server, so [`RUNTIME_MOD_RS_WEB_APPEND`]
/// (the full axum server surface) is NOT appended for a bare-webview program;
/// the render core it draws through is declared by
/// [`RUNTIME_MOD_RS_WEB_CORE_APPEND`] (which fires for `uses_web || uses_webview`
/// and pulls in the ONE real `web` module — server items inside stay
/// `#[cfg(feature = "server")]`, so a webview build compiles only the render core).
const RUNTIME_MOD_RS_WEBVIEW_APPEND: &str = "#[cfg(feature = \"webview\")]\npub mod webview;\n\
     #[cfg(feature = \"webview\")]\npub use webview::{webview_app, WebViewWindowCfg};\n";

/// The server-free render core, declared for EVERY render host (`uses_web ||
/// uses_webview`): the ONE real `web` module (which compiles to just its
/// render-core under `web-core` alone — every axum/SSE/session item inside is
/// `#[cfg(feature = "server")]`) plus the pure `page_shell` scaffold
/// (`web_page_core`). The native-window `webview` backend renders through
/// `web::dispatch` / `web::style_inject` / `web::page_shell` / `web::route` over
/// a local IPC bridge — NO axum `server`, NO SSE, NO session store. The full
/// served surface ([`RUNTIME_MOD_RS_WEB_APPEND`]) is layered on top only when
/// `uses_web`; `web_page_core` is declared here (not there) so a bare-webview
/// program still resolves `web/mod.rs`'s `pub use crate::web_page_core::page_shell`.
/// One `pub mod web;` for both hosts — the module-set closure sees a single `web`.
const RUNTIME_MOD_RS_WEB_CORE_APPEND: &str = "#[cfg(feature = \"web-core\")]\npub mod web_page_core;\n\
     #[cfg(feature = \"web-core\")]\npub mod web;\n";

/// `literal_table` (crate-root, gated `any(web-core, control-wire, debugger)`) is
/// the per-view appearance-literal store the emitted hoist prologue reads and the
/// `web` render core imports (`use crate::literal_table`). Declared top-level here —
/// not a `web` submodule — so a terminal dev-loop build (`control-wire`, no
/// `web-core`) that emits a hoist prologue still resolves `ipe_runtime::literal_table`,
/// and so the module-set closure holds wherever `web`/`control` is declared.
const RUNTIME_MOD_RS_LITERAL_TABLE_APPEND: &str = "#[cfg(any(feature = \"web-core\", feature = \"control-wire\", feature = \"debugger\"))]\npub mod literal_table;\n";

// ── Ipe.Web / Ipe.Web ─────────────────────────────────────────────────────

/// Lines appended to `ipe_runtime/mod.rs` when the program uses Ipe.Web /
/// Ipe.Web app-entry kernels.
///
/// `web/mod.rs` is gated by the `web` Cargo feature in the runtime source;
/// this addition wires the `web` module (and its public re-exports `web_app`,
/// `web_app_routed`, `web_render_static`, `web::route::Route`,
/// `sub_subscribe_topic`, `WebReq`) into the module namespace so the generated
/// `main.rs` can call them.
///
/// `sub_subscribe_topic` is the `Sub.subscribeTopic` runtime kernel; it
/// lives in `web/pubsub.rs` because it needs the session-aware broker.
///
/// `WebReq` MUST be re-exported here (transitive-closure invariant). The
/// runtime's `db.rs` module contains a `#[cfg(feature = "web")] impl IpeRow for
/// super::WebReq` block — `super::WebReq` means `ipe_runtime::WebReq`. In the
/// real runtime source `mod.rs` uses `pub use web::*;` which surfaces `WebReq`
/// (via `web/mod.rs`'s own `pub use req::*;`), but the emitted project uses a
/// selective export list.  Without `WebReq` here, any program that uses BOTH Db
/// and Web kernels fails with E0412 (`WebReq in super` not found) at
/// `db.rs:impl IpeRow for super::WebReq`.
///
/// The `route` sub-module is referenced by path (`ipe_runtime::web::route::Route`)
/// not via `pub use web::*;` (to avoid surfacing the internal `store` / `req`
/// internals in the top-level namespace).
///
/// The `web` module itself is declared by [`RUNTIME_MOD_RS_WEB_CORE_APPEND`]
/// (shared with the webview render host). This append layers ONLY the extra
/// crate-root modules the SERVER surface of `web/mod.rs` reaches by absolute path
/// under `#[cfg(feature = "server")]` — `crate::widget_assets`
/// (`pub use crate::widget_assets;`), `crate::js_port_glue` (SRI-pinned Ffi.Js
/// port asset), and `crate::js_port` (the port session/sink) — plus the server
/// entry re-exports. In the real runtime crate the `web` feature lists
/// `widget-assets` (whose `#[cfg]` also carries `js_port_glue`) and `web` reaches
/// `js_port` transitively; the vendored trimmed `mod.rs` must declare the same
/// closure or `web/mod.rs` fails E0432/E0433 (`crate::widget_assets` /
/// `crate::js_port` not found) — the module-set SEAL breach class. Declared by
/// path only (no glob re-export) because `web/mod.rs` names each fully.
const RUNTIME_MOD_RS_WEB_APPEND: &str = "#[cfg(feature = \"web\")]\npub mod widget_assets;\n\
     #[cfg(feature = \"web\")]\npub mod js_port_glue;\n\
     #[cfg(feature = \"web\")]\npub mod js_port;\n\
     #[cfg(feature = \"web\")]\npub use web::{web_app, web_app_routed, web_render_static, sub_subscribe_topic, cmd_publish, cmd_publish_no_echo, pubsub_publish, pubsub_publish_no_echo, WebReq};\n";

/// The `IpeCmd<M>` and `IpeSub<M>` project-level type aliases emitted when the
/// program uses TEA kernels. Placed immediately after `runtime_bindings()` (the
/// block that also contains `IpeTask<A>` and `Decoder<T>`).
const TEA_TYPE_ALIASES: &str = "pub type IpeCmd<M> = ipe_runtime::tea::IpeCmd<M>;\n\
     pub type IpeSub<M> = ipe_runtime::tea::IpeSub<M>;\n";

// ── Ipe.Auth — concrete wrappers emitted when uses_auth is true ────────

/// Concrete wrappers appended to `main.rs` when the program uses Ipe.Auth
/// kernels.  Each wrapper specialises the generic `E` type parameter to
/// `IpeError` so call sites in user function bodies compile without requiring
/// a turbofish annotation.
///
/// `auth_sign_token` / `auth_verify_token` take a Ipê-typed
/// `ipe_runtime::secret::Secret` (not `String`) at this boundary — "secrets
/// are typed, never `fmt`-stringified" (`PRINCIPLES.md`). The wrapper reveals
/// it via `ipe_runtime::secret::secret_reveal` immediately before delegating
/// to the runtime's `String`-typed `ipe_runtime::auth::{auth_sign_token,
/// auth_verify_token}` — the runtime crate's own low-level signature is left
/// unchanged (it has no dependency on `secret.rs`); the typed boundary lives
/// entirely at this Ipê-facing wrapper, matching the fix spec's design.
///
/// `auth_register`, `auth_login`, and `auth_set_role` are gated on
/// `#[cfg(feature = "db")]` in the runtime source, so the three wrappers
/// here are also gated.  A non-db Auth-only program (using only `hashPassword`
/// / `verifyPassword` / `signToken` / `verifyToken`) will compile the four
/// ungated wrappers + the `passwordStrength` helper and ignore the db-gated
/// three.  When `uses_db` is also true the `db` feature is in the generated
/// project's defaults and the db-gated wrappers become active.
const AUTH_WRAPPERS: &str = "\
pub fn auth_hash_password(pw: String) -> IpeResult<IpeError, String> {\n    \
    ipe_runtime::auth::auth_hash_password(pw)\n\
}\n\n\
pub fn auth_hash_password_cost(pw: String, cost: i64) -> IpeResult<IpeError, String> {\n    \
    ipe_runtime::auth::auth_hash_password_cost(pw, cost)\n\
}\n\n\
pub fn auth_verify_password(pw: String, hash: String) -> IpeResult<IpeError, bool> {\n    \
    ipe_runtime::auth::auth_verify_password(pw, hash)\n\
}\n\n\
pub fn auth_password_strength(pw: String) -> IpeResult<IpeError, String> {\n    \
    ipe_runtime::auth::auth_password_strength(pw)\n\
}\n\n\
pub fn auth_sign_token(\n    \
    secret: ipe_runtime::secret::Secret, claims: HashMap<String, String>, expiry_seconds: i64,\n\
) -> IpeResult<IpeError, String> {\n    \
    ipe_runtime::auth::auth_sign_token(ipe_runtime::secret::secret_reveal(secret), claims, expiry_seconds)\n\
}\n\n\
pub fn auth_verify_token(secret: ipe_runtime::secret::Secret, token: String) -> IpeResult<IpeError, HashMap<String, String>> {\n    \
    ipe_runtime::auth::auth_verify_token(ipe_runtime::secret::secret_reveal(secret), token)\n\
}\n\n\
#[cfg(feature = \"db\")]\n\
pub fn auth_register(conn: Db, email: String, password: String) -> IpeTask<i64> {\n    \
    ipe_runtime::auth::auth_register(conn, email, password)\n\
}\n\n\
#[cfg(feature = \"db\")]\n\
pub fn auth_login(conn: Db, email: String, password: String) -> IpeTask<i64> {\n    \
    ipe_runtime::auth::auth_login(conn, email, password)\n\
}\n\n\
#[cfg(feature = \"db\")]\n\
pub fn auth_set_role(conn: Db, user_id: i64, role: String) -> IpeTask<()> {\n    \
    ipe_runtime::auth::auth_set_role(conn, user_id, role)\n\
}\n\
";

/// The `ipe_runtime/config.rs` emitted for db-enabled programs targeting
/// `SQLite` (the default driver). Replaces the no-op default stub with the `SQLite`
/// type aliases + helper fns the `db.rs` module requires. Mirrors
/// `src/runtime/rust/src/config.rs` verbatim, keeping the
/// `#[cfg(feature = "db")]` / `#[cfg(not(feature = "db"))]` guards so a
/// non-db build (hypothetically possible via feature flag override) degrades
/// gracefully rather than failing with undefined types.
const RUNTIME_CONFIG_RS_DB_SQLITE: &str =
    include_str!("../../../../../src/runtime/rust/src/config.rs");

/// The `ipe_runtime/config.rs` emitted for db-enabled programs targeting
/// Postgres (when `package.ipe` selects `Package.postgres`). Same symbol
/// surface as [`RUNTIME_CONFIG_RS_DB_SQLITE`] (`DbPool`/`DbRow`/`ipe_db_url`/
/// `db_last_insert_id`/`db_format_sql`/`DB_USES_RETURNING_ID`/
/// `db_auto_id_column`), so `db.rs` is byte-identical across both driver
/// builds.
const RUNTIME_CONFIG_RS_DB_POSTGRES: &str =
    include_str!("../../../../../src/runtime/rust/src/config_postgres.rs");

/// The `Diagnostic::CompilerBug` raised when a golden anchor is absent — a
/// drifted-golden invariant violation, surfaced (IPE-I0203) instead of a silent
/// empty slice.
fn anchor_missing(anchor: &str) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "backend.golden_anchor",
        detail: format!("golden anchor {anchor:?} not found in the embedded M0 golden"),
    }
}

/// Look up `file_id`'s bucket in `buckets` via `.get` (never `[]` — indexing
/// panics on a missing key, and `clippy::indexing_slicing` is denied in this
/// workspace). Every `file_id` this is called with comes from
/// `Partitioned::type_order`/`func_order` themselves (built by
/// `partition_items` from the SAME map, `emit_program`'s only caller), so a
/// miss here can only mean an internal invariant violation — surfaced as
/// [`Diagnostic::CompilerBug`], never a panic.
fn bucket_or_bug<'p>(
    buckets: &'p BTreeMap<RustFileId, (Vec<&'p ipe_ir::EnumDef>, Vec<&'p ipe_ir::Func>)>,
    file_id: &RustFileId,
) -> DResult<&'p (Vec<&'p ipe_ir::EnumDef>, Vec<&'p ipe_ir::Func>)> {
    buckets.get(file_id).ok_or_else(|| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::project::emit_program",
        detail: "type_order/func_order references a home missing from partition_items' own \
                 buckets — internal invariant violation"
            .to_owned(),
    })
}

/// The fixed kernel-wrapper prelude emitted between the user types and the user
/// functions (golden lines 45–127).
///
/// These bindings (`IpeError`, the `log_*` / `system_*` / `time_*` / … wrappers)
/// are identical for every program, so they are sliced out of the embedded
/// golden rather than hand-retyped — the same drift-free strategy the
/// preamble/epilogue use. The slice is anchored entirely on its *own* content
/// (the first alias and the final `http_parse_query` wrapper), independent of
/// the surrounding user code.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] (IPE-I0203) if either anchor is absent
/// from the embedded golden — a drifted-golden invariant violation, surfaced
/// instead of a silent empty slice.
fn runtime_bindings() -> DResult<&'static str> {
    const START: &str = "pub use ipe_runtime::error::IpeError;";
    const END: &str = "    ipe_runtime::http_client::http_parse_query(raw)\n}\n";
    let start = GOLDEN.find(START).ok_or_else(|| anchor_missing(START))?;
    let rest = GOLDEN.get(start..).ok_or_else(|| anchor_missing(START))?;
    let end_in_rest = rest.find(END).ok_or_else(|| anchor_missing(END))?;
    let end = start + end_in_rest + END.len();
    GOLDEN.get(start..end).ok_or_else(|| anchor_missing(END))
}

/// Which optional kernel-wrapper prelude sections a program reaches — the gate
/// for whether each mid-prelude section stays or is cut in
/// [`native_runtime_bindings`]. Grouped into one value (rather than four bare
/// `bool` parameters) so the caller reads at the call site and the wiring cannot
/// transpose two flags.
//
// The four fields ARE four independent reachability gates (one per gateable
// prelude section); a bitflags/enum would obscure, not clarify, four orthogonal
// yes/no reach facts named at the struct-literal call site.
#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct PreludeReach {
    /// The program reaches `http_client.rs` — keep the final `Http` section.
    http_client: bool,
    /// The program reaches `random.rs` — keep the `Random` section.
    random: bool,
    /// The program reaches `log.rs` — keep the `Log` section.
    log: bool,
    /// The program reaches `time.rs` (`time-core`) — keep the `Time` section.
    time_core: bool,
    /// The program reaches `crypto_core.rs` — keep the `Crypto (entropy)`
    /// section (the `crypto_random_bytes`/`crypto_random_token` wrappers, the only
    /// always-emitted prelude references to `ipe_runtime::crypto_core::`). A bare
    /// synchronous Program reaches no crypto floor, so the section is cut and the
    /// emitted prelude does not name the gated `crypto_core` module — naming a
    /// module absent from the manifest would be an unresolved-path E0433.
    crypto_core: bool,
    /// The program names the `Value` (`JsonVal`) or `Decoder<T>` type — keep the
    /// `pub type Decoder<T> = ipe_runtime::json::Decoder<IpeError, T>;` alias. When
    /// false, the alias is cut (a program naming neither would otherwise emit an
    /// alias hard-referencing the dropped `json` module — E0433). The companion
    /// `type Value = JsonVal;` alias, which lives in the fixed preamble, is cut on
    /// the SAME flag by [`crate::preamble::preamble`].
    json: bool,
    /// The program reaches the `Ipe.Secret` surface — keep the `Io secret kernels`
    /// section (the `io_read_secret` wrapper, whose return type hard-references
    /// `ipe_runtime::secret::Secret`). When false the section is cut: the `secret`
    /// module is `secret`-gated in the dependency model, so naming its `Secret`
    /// type from an unconditional wrapper would be an unresolved-path E0433. A
    /// program that reads a secret holds a `Secret`-typed value, which sets this
    /// flag and turns the `secret` feature on.
    secret: bool,
}

/// Drop a mid-prelude section — the wrappers between its own `header` and the
/// following `next_header` — from `text`, returning the joined remainder. Used
/// when the program does not reach the module those wrappers hard-reference;
/// keeping them would fail to resolve (E0433) once the gated module is dropped.
/// Both anchors are content-addressed, so a golden drift that renamed either
/// fails loud (a [`Diagnostic::CompilerBug`]) rather than mis-slicing.
fn drop_prelude_section(text: &str, header: &str, next_header: &str) -> DResult<String> {
    let start = text.find(header).ok_or_else(|| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::project::native_runtime_bindings",
        detail: format!(
            "kernel-wrapper prelude anchor {header:?} not found — golden drifted; \
             cannot drop its wrappers for a program that does not reach the module"
        ),
    })?;
    let end_rel = text
        .get(start..)
        .and_then(|rest| rest.find(next_header))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::native_runtime_bindings",
            detail: format!(
                "kernel-wrapper prelude anchor {next_header:?} not found after \
                 {header:?} — golden drifted; cannot bound the section"
            ),
        })?;
    let mut out = text.get(..start).unwrap_or("").to_owned();
    out.push_str(text.get(start + end_rel..).unwrap_or(""));
    Ok(out)
}

/// The native-target kernel-wrapper prelude: [`runtime_bindings`] with each
/// section a program does not reach dropped (see [`PreludeReach`]).
///
/// The always-emitted prelude ends with the `Http` section — a comment header
/// plus the monomorphic `http_parse_query` wrapper, which hard-references
/// `ipe_runtime::http_client::http_parse_query`. When `http_client` is not
/// declared (a pure-CLI program that never touches the outbound HTTP surface),
/// keeping that wrapper would fail to resolve (E0433). The `Http` section is the
/// final block of the prelude (`http_parse_query` is its `END` anchor — see
/// [`runtime_bindings`]), so everything from its comment header onward is cut in
/// one slice; the [`Items`] joiner separates what follows (`AUTH_WRAPPERS`, the
/// TEA aliases, …) from the last kept line. The `HTTP_SECTION` anchor is
/// content-addressed, so a prelude drift that renamed it fails loud (a
/// `CompilerBug`) rather than mis-slicing. The
/// mid-prelude `Log` / `Time` / `Random` sections are cut the same way when
/// their modules are dropped.
fn native_runtime_bindings(reach: PreludeReach) -> DResult<String> {
    // The comment header that opens the outbound-`Http` prelude section. The
    // section runs from here to the end of `runtime_bindings()` (its `END`
    // anchor is the `http_parse_query` wrapper, the section's sole binding).
    const HTTP_SECTION: &str = "// ── Http kernels";
    // The `Decoder<T>` alias — the sole always-emitted prelude reference to
    // `ipe_runtime::json::`. Content-addressed on the whole line so a golden drift
    // that renamed it fails loud rather than silently emitting a dangling alias.
    const DECODER_ALIAS: &str = "pub type Decoder<T> = ipe_runtime::json::Decoder<IpeError, T>;\n";
    let mut filtered = runtime_bindings()?.to_owned();

    // `Decoder<T>` alias — cut for a program that names neither `Value` nor
    // `Decoder` (`!reach.json`): keeping it would hard-reference the dropped `json`
    // module (E0433). The companion `type Value = JsonVal;` alias is cut on the
    // same flag in the fixed preamble (`crate::preamble::preamble`).
    if !reach.json {
        if !filtered.contains(DECODER_ALIAS) {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::native_runtime_bindings",
                detail: format!(
                    "kernel-wrapper prelude alias {DECODER_ALIAS:?} not found — golden \
                     drifted; cannot drop the `Decoder` alias for a program that names \
                     neither `Value` nor `Decoder`"
                ),
            });
        }
        filtered = filtered.replace(DECODER_ALIAS, "");
    }

    // `Io secret` — the single `io_read_secret` wrapper (`Io.readSecret`), whose
    // return type hard-references `ipe_runtime::secret::Secret`. Cut between the
    // `Io secret kernels` header and the following `System kernels` header when
    // the program reaches no secret surface (`!reach.secret`): the `secret`
    // module is `secret`-gated in the dependency model, so keeping the wrapper
    // would name an absent `Secret` type (E0433).
    if !reach.secret {
        filtered =
            drop_prelude_section(&filtered, "// ── Io secret kernels", "// ── System kernels")?;
    }

    // `Log` — the eight `log_*` wrappers (the only static-prelude references to
    // `ipe_runtime::log`), cut between the `Log` header and the following
    // `System (env)` header when the program reaches no `Ipe.Log.*` kernel (so
    // `log.rs`, and via `time-core` `chrono`, is dropped).
    if !reach.log {
        filtered =
            drop_prelude_section(&filtered, "// ── Log kernels", "// ── System (env) kernels")?;
    }

    // `Time` — the three `time_*` wrappers (`time_now`/`sleep`/`unix_millis`),
    // cut between the `Time` header and the following `Random` header when the
    // program reaches `time-core` neither directly (an `Ipe.Time` kernel) nor via
    // a Log/Db/Web surface, so the whole `time.rs` module is dropped.
    if !reach.time_core {
        filtered = drop_prelude_section(&filtered, "// ── Time kernels", "// ── Random kernels")?;
    }

    // `Random` — the three `random_*` wrappers, cut between the `Random` header
    // and the following `File` header when the program does not reach `random.rs`
    // (a non-Random synchronous program).
    if !reach.random {
        filtered = drop_prelude_section(&filtered, "// ── Random kernels", "// ── File kernels")?;
    }

    // `Crypto (entropy)` — the two `crypto_random_*` wrappers, the ONLY
    // always-emitted prelude references to `ipe_runtime::crypto_core::`. Cut
    // between the `Crypto (entropy)` header and the following `Http` header when
    // the program reaches no crypto floor (`reaches_crypto_core`), so the emitted
    // prelude does not name the `crypto_core` module once it is dropped from the
    // runtime feature set — the removal that lets a bare Program drop
    // `sha2`/`hmac`/`subtle`.
    if !reach.crypto_core {
        filtered = drop_prelude_section(
            &filtered,
            "// ── Crypto (entropy) kernels",
            "// ── Http kernels",
        )?;
    }

    if reach.http_client {
        return Ok(filtered);
    }
    let cut = filtered
        .find(HTTP_SECTION)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::native_runtime_bindings",
            detail: format!(
                "kernel-wrapper prelude anchor {HTTP_SECTION:?} not found — golden drifted; \
             cannot drop the http_client wrappers for a non-HTTP program"
            ),
        })?;
    // The slice ends immediately before the `Http` comment; the blank line that
    // separates it from the next section is the `Items` joiner's to place.
    Ok(filtered.get(..cut).unwrap_or("").to_owned())
}

/// The kernel-wrapper prelude section between the user types and the user
/// functions: the target's runtime bindings, then the TEA aliases and the Auth
/// wrappers when the program reaches them.
fn prelude_section(ctx: &EmitCtx) -> DResult<String> {
    let mut section = Items::new();
    match ctx.target {
        // Co-located WASI shares the native emission (block_on drives a
        // `Direct`/`Script` `main` over WASI) — only the target triple differs.
        ipe_ir::Target::Native | ipe_ir::Target::WasmWasi => {
            section.push(&native_runtime_bindings(PreludeReach {
                http_client: ctx.reaches_http_client(),
                random: ctx.reaches_random(),
                log: ctx.reaches_log(),
                time_core: ctx.reaches_time_core(),
                crypto_core: ctx.reaches_crypto_core(),
                json: ctx.reaches_json(),
                secret: ctx.reaches_secret(),
            })?);
        }
        // The wasm target takes the floor-filtered subset.
        ipe_ir::Target::WasmClient => section.push(&wasm_runtime_bindings()?),
    }
    // TEA kernels → the IpeCmd<M> / IpeSub<M> type aliases.
    if ctx.uses_tea {
        section.push(TEA_TYPE_ALIASES);
    }
    // Ipe.Auth kernels → concrete E = IpeError wrappers.
    if ctx.uses_auth {
        section.push(AUTH_WRAPPERS);
    }
    Ok(section.render())
}

/// The fixed epilogue for the program's target: the native `fn main`, or the
/// wasm-bindgen entry.
fn epilogue_for_target(ctx: &EmitCtx) -> DResult<String> {
    match ctx.target {
        ipe_ir::Target::Native | ipe_ir::Target::WasmWasi => epilogue(),
        ipe_ir::Target::WasmClient => epilogue_wasm(ctx),
    }
}

/// Emit the complete project for `program`.
#[allow(clippy::too_many_lines)]
pub fn emit_program(ctx: &EmitCtx, program: &Program) -> DResult<EmittedProject> {
    // Hydration serde-safety gate, enforced BEFORE the single-file/split branch
    // so BOTH emitted layouts funnel through the one check: a `HydrationState`
    // island that could carry a server-surface type (Db, Secret, Task, function
    // types) is rejected here, never serialised into the client JSON island.
    // `emit_spine` re-runs the same gate (defend-in-depth for the demanded split
    // path that renders the spine directly); the check is a no-op unless
    // `ctx.wasm_hydrate_mode` is set.
    check_hydration_state_fields(ctx, program)?;

    // Partition every user item by the Rust file it belongs in. The
    // number of DISTINCT `RustFileId::IpeModule` buckets — NEVER counting the
    // always-possible `Spine` bucket (§3.3: "counts `IpeModule` buckets only,
    // never `Spine`") — is the trigger for the real per-module split:
    //   • 0 or 1 distinct IpeModule bucket → the Spine-collapse invariant
    //     fires and we emit today's byte-identical single `src/main.rs`.
    //   • 2+ → the real split materialises (`emit_spine` + one
    //     `emit_module_file` per bucket + the `main.rs` barrel lines).
    let partition = partition_items(program, ctx.interner);

    // The DISTINCT `IpeModule` homes, in first-encounter (linker/topological)
    // order — the SAME warm/cold-stable order `type_order`/`func_order` use
    // (see [`Partitioned`]). A module can appear in `func_order` but not
    // `type_order` (e.g. a func-only module like `mm_diamond`'s `D`), so the
    // union is taken with `type_order` first, then any func-only home appended
    // in its own first-encounter position. This ordered list drives BOTH the
    // deterministic barrel lines and the per-module file emission.
    let mut module_homes: Vec<RustFileId> = Vec::new();
    let mut seen: BTreeSet<RustFileId> = BTreeSet::new();
    for id in partition
        .type_order
        .iter()
        .chain(partition.func_order.iter())
    {
        if seen.insert(id.clone()) {
            module_homes.push(id.clone());
        }
    }

    // Fail closed if two DISTINCT module homes fold to the same `mod_ident`
    // BEFORE any `mod` decl / source file is written. The `home -> mod_ident`
    // fold is injective (`naming::module_prefix` escapes in-segment `_`), so
    // this can only fire on a genuine internal bug — but it MUST be wired: an
    // unwired gate would let a collision write two identical `mod` decls (E0428)
    // and silently overwrite the first module's source file.
    rust_file::assert_mod_idents_unique(&module_homes, ctx.interner)?;

    // (design doc §2.2): fail closed if a
    // synthesised record struct's name collides with a user enum's name, a
    // function name, or a `mod_ident`. In the single-file collapse case no
    // `mod` declarations are written, so the honest set is empty; in the real
    // split every `IpeModule` bucket contributes its `mod_ident` — its
    // intra-set uniqueness is proven by the gate above; this check is the
    // DISJOINTNESS obligation against the record-struct namespace.
    let mod_idents: BTreeSet<String> = if module_homes.len() >= 2 {
        module_homes
            .iter()
            .filter_map(|id| match id {
                RustFileId::IpeModule(home) => {
                    Some(rust_file::resolve_mod_ident(home, ctx.interner))
                }
                RustFileId::Spine => None,
            })
            .collect::<DResult<BTreeSet<String>>>()?
    } else {
        BTreeSet::new()
    };
    ctx.assert_record_structs_disjoint_from_type_namespace(&mod_idents)?;
    // The row-poly witness substrate shares Rust's TYPE namespace with the
    // record structs and enums above: the synthesised `IpeHas<Field>` traits
    // must be pairwise distinct AND disjoint from user types / mods, or two
    // field names that camel-case to one trait (E0428) reach rustc.
    ctx.assert_row_witness_names_disjoint(
        &crate::emit_types::row_witness_field_names(program),
        &mod_idents,
    )?;

    // The emitted Rust source files (`src/main.rs` plus, in the real split,
    // one `src/ipe_mods/<ident>.rs` per module). The manifest + runtime-module
    // files below are file-count-agnostic and shared by both branches.
    let mut rust_sources: Vec<(RelPath, String)> = Vec::new();

    if module_homes.len() >= 2 {
        // ── The real per-Ipê-module split (§2.1/§3.3) ────────────────────────
        // `main.rs` = the Spine tier (preamble, SqlValue/SqlField enums,
        // record structs, DB-projection impls, kernel-wrapper prelude, epilogue,
        // `fn main()`) + the flat glob barrel that re-exports every module's
        // items at the crate root.
        let main_rs = split_main_rs(ctx, &emit_spine(ctx, program)?, &module_homes)?;
        rust_sources.push((RelPath::new("src/main.rs")?, main_rs));

        // One `src/ipe_mods/<ident>.rs` per module, carrying ONLY that home's
        // `pub(crate)` items behind a `use crate::*;` glob header.
        for id in &module_homes {
            let RustFileId::IpeModule(home) = id else {
                continue;
            };
            let ident = rust_file::resolve_mod_ident(home, ctx.interner)?;
            let file = emit_module_file(ctx, program, id)?;
            rust_sources.push((RelPath::new(format!("src/ipe_mods/{ident}.rs"))?, file));
        }
    } else {
        // ── The Spine-collapse invariant (§3.3) ──────────────────────────────
        // Exactly ONE distinct `IpeModule` bucket (or none): inline that one
        // module's types/funcs into a single `src/main.rs`. THIS BRANCH IS
        // LOAD-BEARING — every single-module golden must stay byte-identical to
        // this inline layout: preamble, user types (via `type_order`), Spine
        // enums, record structs, DB-projection impls, kernel-wrapper prelude,
        // user funcs (via `func_order`), epilogue, shape-app entry switch.
        let Partitioned {
            buckets,
            type_order,
            func_order,
        } = &partition;

        // Every section and every item in it goes through the one `Items`
        // joiner, which separates them by exactly one blank line and skips an
        // empty section, so no section spaces itself by hand.
        let mut file = Items::new();
        // The preamble ends with the USER-TYPES banner; everything below it up to
        // the kernel-wrapper prelude (types, record structs, Db projections) is
        // that section's body.
        file.push(&preamble(ctx.reaches_json())?);

        // User types, walked via `type_order` — `partition_items`'s
        // FIRST-ENCOUNTER order over `program.modules[..].types`, a
        // warm/cold-stable linker topological order (NOT alphabetical, NOT
        // symbol-id — see [`Partitioned`]'s doc comment). A single-bucket
        // program has nothing to reorder.
        for file_id in type_order {
            let (enums, _) = bucket_or_bug(buckets, file_id)?;
            for &def in enums {
                file.push(&emit_enum(ctx, def)?);
            }
        }
        if let Some((spine_enums, _)) = buckets.get(&RustFileId::Spine) {
            for &def in spine_enums {
                file.push(&emit_enum(ctx, def)?);
            }
        }
        // Synthesised record structs, one per distinct closed record shape.
        // Item order is irrelevant in Rust, so these can reference one another
        // freely; a program with no records emits nothing here.
        for rec in ctx.record_structs() {
            file.push(&emit_record_struct(ctx, rec)?);
        }
        // Per-field witness traits + impls for any row-polymorphic function.
        // Empty (nothing pushed) when the program has no row annotation.
        file.push(&emit_row_witnesses(ctx, program)?);

        // boundary-projection impl blocks.  When the program uses Db QUERY
        // kernels, the lowerer injected synthetic `SqlValue` / `SqlField`
        // enums, and the Db call sites project Ipê ADT values to the runtime's
        // concrete `SqlParam` / `Option<SqlParam>`. Keyed on the injected enum's
        // PRESENCE, not on `uses_db`: a program that only NAMES a `db`-gated type
        // (`Dsn` / `Connection`) forces the `db` feature (for `dsn.rs` /
        // `external_conn.rs`) through the type-closure fold without injecting a
        // `SqlValue` enum, so there is no projection to emit — gating on
        // `uses_db` would then reference an enum that does not exist.
        if ctx.sqlvalue_rust_name.is_some() {
            file.push(&emit_db_projection_impls(ctx)?);
        }

        // Fixed kernel-wrapper prelude (IpeError, IpeTask<A>, Decoder<T>, …)
        // plus the TEA aliases and Auth wrappers the program reaches.
        file.push(&prelude_section(ctx)?);

        // User functions, walked via `func_order` (its OWN first-encounter
        // order over `program.modules[..].funcs`). `partition_items` never
        // routes a `Func` into `Spine`, so funcs land purely in `IpeModule`
        // buckets.
        for file_id in func_order {
            let (_, funcs) = bucket_or_bug(buckets, file_id)?;
            for &func in funcs {
                file.push(&emit_func(ctx, func)?);
            }
        }

        file.push(&epilogue_for_target(ctx)?);
        let mut out = file.render();

        // Shape-app entry switch (Native only).
        //
        // When `ipe_main` returns a shape app leaf (`WebApp` / `TuiApp` /
        // `CliApp`; a `Web.tea` under a webview host renders `WebViewApp`) its
        // emitted body contains the corresponding
        // `ipe_runtime::tea::<Leaf>(...)` constructor. The template declares
        // `ipe_main() -> IpeTask<()>` and `match block_on(ipe_main()) { ... }` —
        // both must be updated to use the concrete leaf type and its
        // `run_blocking()` method.
        //
        // Detection is done by scanning the emitted body for the four known
        // leaf constructors; this avoids a dependency on per-shape `uses_*` flags
        // (CliApp programs, for example, do not set any shape flag in EmitCtx).
        //
        // WASM: `epilogue_wasm` has a different entry — no `block_on` call and
        // a different `ipe_main` signature — so the switch is skipped there.
        // Shape-app epilogue switch (Native only).
        //
        // When `ipe_main` returns a shape-app leaf (WebApp / TuiApp / CliApp; a
        // `Web.tea` under a webview host renders WebViewApp), `emit_func` already
        // emits the correct return type from the IR — no return-type rewrite is
        // needed. Only the epilogue `fn main` body
        // needs updating: `block_on(ipe_main())` → `ipe_main().run_blocking()`.
        //
        // Detection scans the emitted text for a known leaf constructor call; this
        // naturally handles CliApp (which sets no shape flag in EmitCtx).
        //
        // WASM: `epilogue_wasm` uses a different entry without `block_on`, so
        // the switch is skipped there.
        if matches!(
            ctx.target,
            ipe_ir::Target::Native | ipe_ir::Target::WasmWasi
        ) && SHAPE_APP_RETURN_TYPES.iter().any(|sig| out.contains(sig))
        {
            let replaced = out.replacen(SHAPE_APP_BLOCK_ON_ANCHOR, SHAPE_APP_RUN_BLOCKING, 1);
            if replaced == out {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::project::emit_program::shape_app_entry_switch",
                    detail: format!(
                        "shape-app entry-switch: anchor {SHAPE_APP_BLOCK_ON_ANCHOR:?} \
                         not found in emitted output — epilogue golden has drifted"
                    ),
                });
            }
            out = replaced;
        }

        rust_sources.push((RelPath::new("src/main.rs")?, out));
    }

    assemble_project_files(ctx, rust_sources)
}

/// Refuse a project whose emitted Rust holds a character the Rust lexer
/// refuses raw.
///
/// The output-side half of the lexable seal: every text spliced into emitted
/// Rust goes through an `ipe_intern::rust_literal` renderer, and this total
/// scan over every emitted `.rs` file turns a site that bypassed them into an
/// `ipe`-time [`Diagnostic::CompilerBug`], never a `cargo` lexer error. The
/// detail names the codepoint as `U+XXXX`, never raw.
///
/// # Errors
///
/// [`Diagnostic::CompilerBug`] at [`ipe_intern::EMIT_LEXABLE`] on the first
/// hazard found.
fn refuse_lexer_hazards(project: &EmittedProject) -> DResult<()> {
    for (path, text) in &project.files {
        let is_rust = std::path::Path::new(path.as_str())
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
        if !is_rust {
            continue;
        }
        if let Some(hazard) = ipe_intern::find_lexer_hazard(text) {
            return Err(Diagnostic::CompilerBug {
                where_: ipe_intern::EMIT_LEXABLE,
                detail: format!(
                    "emitted {:?} holds {hazard}; every text spliced into emitted Rust must \
                     go through an `ipe_intern::rust_literal` renderer",
                    path.as_str()
                ),
            });
        }
    }
    Ok(())
}

/// A string that is safe to use as the body of a TOML basic (double-quoted)
/// string. The only constructor is [`SafeTomlString::escape`], which runs the
/// exhaustive escaper over raw input, so no caller can reach a manifest `"..."`
/// splice without having escaped every TOML-forbidden byte.
struct SafeTomlString(String);

impl SafeTomlString {
    /// Escape `raw` per the TOML basic-string grammar and return a
    /// [`SafeTomlString`] whose body can be spliced directly between `"..."`.
    ///
    /// Escapes (TOML spec §2.4):
    /// - `\` → `\\`, `"` → `\"`
    /// - backspace `\x08` → `\b`, tab `\x09` → `\t`, newline `\x0A` → `\n`,
    ///   form-feed `\x0C` → `\f`, CR `\x0D` → `\r`
    /// - every other control scalar `U+0000–U+001F` and `U+007F` → `\uXXXX`
    fn escape(raw: &str) -> Self {
        Self(escape_toml_basic(raw))
    }

    /// The escaped body, ready to splice between the surrounding `"..."`.
    fn as_body(&self) -> &str {
        &self.0
    }
}

/// Escape `s` so the result is safe as the body of a TOML basic
/// (double-quoted) string. Covers every byte the TOML spec forbids inside
/// `"..."`: control scalars U+0000–U+001F and U+007F, plus the two structural
/// characters `\` and `"`.
fn escape_toml_basic(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\x08' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\x0C' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c == '\x7F' => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Render the dependency-model project `Cargo.toml` for `ctx`: the
/// [`CARGO_DEP_TOML`] user-crate template with the runtime crate root and the
/// [`crate::runtime_features`] feature selection substituted in.
///
/// The feature list is the SSOT image — the ONLY authority for which runtime
/// features a program selects — rendered as a quoted, comma-separated list in
/// the crate's canonical order. An empty selection is impossible (`json` is the
/// floor), but the join is still correct for one (no trailing comma).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if either template placeholder is absent
/// — a drifted dep-model manifest template, surfaced loudly rather than emitting
/// a manifest that names no runtime.
fn dep_model_cargo_toml(ctx: &EmitCtx) -> DResult<String> {
    let mut manifest = substitute_dep_manifest_anchors(
        CARGO_DEP_TOML,
        ctx,
        "ipe_backend_rust::project::dep_model_cargo_toml",
    )?;
    // A browser-shape program emits `#[derive(serde::Serialize, serde::Deserialize)]`
    // on serde-eligible types (see `emit_types`), so the APP crate references the
    // `serde` crate by path. Under the dependency model the app crate depends only
    // on `ipe_runtime`, whose `serde` is a private dependency not re-exported — so
    // the app must declare its own `serde`. Pin + feature match the vendored
    // `templates/Cargo.toml`. This covers BOTH browser shapes: Ipe.Web derives
    // serde on its Model, and Ipe.WebView derives it on a `CustomElement.node`'s down/up
    // seal types (its Model bound is only `Clone + Send`, but the widget seam
    // still routes through `ui_widget_`'s serde bounds). Gating solely on
    // `uses_web` leaves a WebView-widget manifest serde-free while its `main.rs`
    // names `serde::` by path — an ipe-accept-then-cargo-fail (E0433). A
    // `--debugger` build derives serde for the typed session log too. Every other
    // program emits no serde derive, so its manifest stays serde-free. The gate is
    // the derive sites' own `derives_serde`. Inserted right after the runtime
    // dependency line, inside `[dependencies]`.
    if ctx.derives_serde() {
        manifest = insert_app_serde_dependency(&manifest)?;
    }
    Ok(manifest)
}

/// Render the dependency-model project `Cargo.toml` for the browser-WASM target:
/// the [`CARGO_WASM_DEP_TOML`] user-crate template with the runtime crate root
/// and the [`crate::runtime_features`] feature selection substituted in. The
/// feature list carries the `wasm-client` floor (from the SSOT, since
/// `ctx.target == WasmClient`) plus any browser-admissible surface the program
/// reaches. The template already declares the two crates the emitted wasm app
/// names by path (`wasm-bindgen`, `serde`); `serde_json` is spliced in only for
/// a `mode = "hydrate"` program, whose `hydrate` export parses the island JSON
/// via `serde_json::from_str`.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if either template placeholder is absent,
/// or (hydrate only) if the runtime dependency anchor line the `serde_json`
/// splice keys on has drifted — each surfaced loudly rather than emitting a
/// manifest that names no runtime or drops a referenced crate.
fn dep_model_wasm_cargo_toml(ctx: &EmitCtx) -> DResult<String> {
    let mut manifest = substitute_dep_manifest_anchors(
        CARGO_WASM_DEP_TOML,
        ctx,
        "ipe_backend_rust::project::dep_model_wasm_cargo_toml",
    )?;
    // The `mode = "hydrate"` second entry (`wasm_hydrate_entry`) parses the
    // island blob with `serde_json::from_str` BY PATH, so a hydrate program's app
    // crate must declare `serde_json`. A non-hydrate wasm app never names it (the
    // runtime's own `serde_json`, behind the `json` feature `wasm-client` pulls,
    // stays private), so its manifest stays serde_json-free.
    if ctx.wasm_hydrate_mode {
        manifest = insert_app_serde_json_dependency(&manifest)?;
    }
    Ok(manifest)
}

/// Substitute the `__IPE_RUNTIME_FEATURES__` anchor in a dependency-model
/// manifest `template` with the [`crate::runtime_features`] SSOT selection for
/// `ctx`. Shared by the native ([`dep_model_cargo_toml`]) and wasm
/// ([`dep_model_wasm_cargo_toml`]) renderers so the anchor contract has ONE
/// definition.
///
/// The feature list is the SSOT image — the ONLY authority for which runtime
/// features a program selects — rendered as a quoted, comma-separated list in the
/// crate's canonical order. The join is correct for any arity (no trailing
/// comma), including the empty native selection.
///
/// The runtime crate path is a fixed relative `ipe_runtime_dep` embedded in the
/// template; no path substitution is performed here. The driver materialises the
/// runtime source tree into `ipe_runtime_dep/` alongside the emitted crate so
/// the reference resolves in any environment (cross-compiler container, offline
/// build, CI) without a host-absolute path.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] (tagged `where_`) if the features
/// placeholder is absent from `template` — a drifted manifest template,
/// surfaced loudly rather than emitting a manifest that names no runtime.
fn substitute_dep_manifest_anchors(
    template: &str,
    ctx: &EmitCtx,
    where_: &'static str,
) -> DResult<String> {
    const FEATURES_ANCHOR: &str = "__IPE_RUNTIME_FEATURES__";

    let features = crate::runtime_features::runtime_features(ctx);
    let feature_list = features
        .as_feature_names()
        .iter()
        .map(|f| format!("\"{f}\""))
        .collect::<Vec<_>>()
        .join(", ");

    if !template.contains(FEATURES_ANCHOR) {
        return Err(Diagnostic::CompilerBug {
            where_,
            detail: format!("dep-model manifest template lost the {FEATURES_ANCHOR:?} anchor"),
        });
    }
    Ok(template.replace(FEATURES_ANCHOR, &feature_list))
}

/// Insert the app-crate `serde` dependency (version + `derive` feature identical
/// to the vendored `templates/Cargo.toml`) immediately after the `ipe_runtime`
/// line in the dep-model manifest's `[dependencies]` table.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the runtime dependency line is absent
/// — a drifted dep-model template, surfaced loudly rather than emitting a
/// manifest whose `[dependencies]` silently lacks the anchor line.
fn insert_app_serde_dependency(manifest: &str) -> DResult<String> {
    const RUNTIME_DEP_ANCHOR: &str = "ipe_runtime = { package = \"ipe-runtime-rust\"";
    const SERDE_DEP_LINE: &str = "serde = { version = \"1\", features = [\"derive\"] }";
    let Some(anchor_start) = manifest.find(RUNTIME_DEP_ANCHOR) else {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::insert_app_serde_dependency",
            detail: format!(
                "dep-model manifest lost the runtime dependency line \
                 (anchor {RUNTIME_DEP_ANCHOR:?}) — cannot place the app `serde` dep"
            ),
        });
    };
    // The runtime dependency line ends at the next newline; splice the serde line
    // in on its own line just after it.
    let Some(rel_eol) = manifest[anchor_start..].find('\n') else {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::insert_app_serde_dependency",
            detail: "dep-model manifest runtime dependency line has no terminating newline"
                .to_owned(),
        });
    };
    let insert_at = anchor_start + rel_eol + 1;
    let mut out = String::with_capacity(manifest.len() + SERDE_DEP_LINE.len() + 1);
    out.push_str(&manifest[..insert_at]);
    out.push_str(SERDE_DEP_LINE);
    out.push('\n');
    out.push_str(&manifest[insert_at..]);
    Ok(out)
}

/// Insert the app-crate `serde_json` dependency immediately after the
/// `ipe_runtime` line in the wasm dep-model manifest's `[dependencies]` table.
/// Used only for a `mode = "hydrate"` wasm program, whose emitted `hydrate`
/// export parses the island JSON with `serde_json::from_str` BY PATH — the
/// runtime's own `serde_json` (behind the `json` feature `wasm-client` pulls)
/// stays a private, non-re-exported dependency.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the runtime dependency line is absent
/// — a drifted dep-model template, surfaced loudly rather than emitting a
/// manifest whose `[dependencies]` silently lacks the anchor line.
fn insert_app_serde_json_dependency(manifest: &str) -> DResult<String> {
    const RUNTIME_DEP_ANCHOR: &str = "ipe_runtime = { package = \"ipe-runtime-rust\"";
    const SERDE_JSON_DEP_LINE: &str = "serde_json = \"1\"";
    let Some(anchor_start) = manifest.find(RUNTIME_DEP_ANCHOR) else {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::insert_app_serde_json_dependency",
            detail: format!(
                "wasm dep-model manifest lost the runtime dependency line \
                 (anchor {RUNTIME_DEP_ANCHOR:?}) — cannot place the app `serde_json` dep"
            ),
        });
    };
    let Some(rel_eol) = manifest[anchor_start..].find('\n') else {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::insert_app_serde_json_dependency",
            detail: "wasm dep-model manifest runtime dependency line has no terminating newline"
                .to_owned(),
        });
    };
    let insert_at = anchor_start + rel_eol + 1;
    let mut out = String::with_capacity(manifest.len() + SERDE_JSON_DEP_LINE.len() + 1);
    out.push_str(&manifest[..insert_at]);
    out.push_str(SERDE_JSON_DEP_LINE);
    out.push('\n');
    out.push_str(&manifest[insert_at..]);
    Ok(out)
}

/// Render the per-project `env_public` module for the dependency model as a
/// USER-crate module (`src/ipe_env_public.rs`), declared + re-exported from
/// `main.rs`. Byte-identical to [`render_env_public_rs`] except the one runtime
/// import: `use super::core::IpeMaybe` (a submodule of the vendored
/// `ipe_runtime`) becomes `use ipe_runtime::core::IpeMaybe` (the extern crate),
/// since the module no longer lives inside the runtime tree.
fn render_env_public_user_rs(allowlist: &[String]) -> String {
    render_env_public_rs(allowlist).replacen(
        "use super::core::IpeMaybe;",
        "use ipe_runtime::core::IpeMaybe;",
        1,
    )
}

/// Rewrite the one emitted `crate::ipe_runtime::…` reference (the `IpeStringify`
/// trait bound in generic where-clauses, [`crate::emit_expr::render_bounds`])
/// into the extern-crate path `ipe_runtime::…` for the dependency model, where
/// `ipe_runtime` is a real dependency reached through the extern prelude, not a
/// crate-root `mod`. Applied only under the dep model; the vendored path keeps
/// the byte-identical `crate::ipe_runtime::…` form.
fn rewrite_runtime_paths_for_dep(src: &str) -> String {
    src.replace("crate::ipe_runtime::", "ipe_runtime::")
}

/// The wasm files shared by both emit models: the target-scoped `.cargo/config`
/// (so a host mold/native-linker `build.rustflags` cannot leak into the wasm32
/// link) and the static browser shell (`index.html` + `boot.js`). The
/// wasm-bindgen CLI drops the JS glue + `.wasm` beside them under `www/pkg/`.
///
/// # Errors
///
/// Returns a [`Diagnostic`] only if a fixed [`RelPath`] fails validation — a
/// compiler bug, never a program property.
fn insert_wasm_shared_files(files: &mut BTreeMap<RelPath, String>) -> DResult<()> {
    // Host/global cargo configs may carry native-linker rustflags (e.g. mold),
    // which rust-lld rejects for wasm32. A target-scoped set here takes
    // precedence — and it must be NON-empty (cargo treats an empty array as unset
    // and falls back to `build.rustflags`).
    files.insert(
        RelPath::new(".cargo/config.toml")?,
        "[target.wasm32-unknown-unknown]\n\
         # Non-empty on purpose: an empty array would not override a host\n\
         # config's native `build.rustflags` (e.g. a mold link-arg).\n\
         rustflags = [\"-C\", \"debuginfo=0\"]\n"
            .to_owned(),
    );
    // The static browser shell (CSP: `script-src 'self' 'wasm-unsafe-eval'` —
    // wasm instantiation allowed, JS eval not; boot module external so no inline
    // allowance is needed).
    files.insert(
        RelPath::new("www/index.html")?,
        "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; \
         script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; \
         connect-src 'self'\">\n\
         <title>Ip\u{ea} App</title>\n</head>\n<body>\n\
         <script type=\"module\" src=\"./boot.js\"></script>\n</body>\n</html>\n"
            .to_owned(),
    );
    files.insert(
        RelPath::new("www/boot.js")?,
        "import init from \"./pkg/ipe_app.js\";\ninit();\n".to_owned(),
    );
    Ok(())
}

/// Emit the co-located WASI (`wasm32-wasip1`) crate's `.cargo/config.toml`.
///
/// The wasip1 link step runs `rust-lld` (wasm flavor), which rejects a native
/// system-linker flag such as a host's `-C link-arg=-fuse-ld=mold` carried in a
/// global `[build] rustflags`. A `[target.<triple>] rustflags` overrides
/// `[build] rustflags` for that triple (cargo does not merge them), so a
/// target-scoped set here keeps the WASI link mold-free regardless of the host's
/// global cargo config — the SAME escape the browser
/// `wasm32-unknown-unknown` emit uses in [`insert_wasm_shared_files`]. Without it
/// an emitted WASI project built on a mold-configured machine fails the link,
/// breaking THE SEAL (a wasip1-accepted program must `cargo build`).
///
/// The array is NON-empty on purpose: cargo treats an empty array as unset and
/// falls back to `build.rustflags` — so a benign flag is required to shadow it.
///
/// # Errors
///
/// Returns a [`Diagnostic`] only if the fixed [`RelPath`] fails validation — a
/// compiler bug, never a program property.
fn insert_wasi_linker_config(files: &mut BTreeMap<RelPath, String>) -> DResult<()> {
    files.insert(
        RelPath::new(".cargo/config.toml")?,
        "[target.wasm32-wasip1]\n\
         # Non-empty on purpose: an empty array would not override a host\n\
         # config's native `build.rustflags` (e.g. a mold link-arg), which\n\
         # `rust-lld` rejects for wasm32.\n\
         rustflags = [\"-C\", \"debuginfo=0\"]\n"
            .to_owned(),
    );
    Ok(())
}

/// Drop the crate-root `pub mod ipe_runtime;` (the vendored-source declaration)
/// from `src/main.rs` for the dependency model, where the runtime is an extern
/// crate reached through the prelude. The following `pub use ipe_runtime::*;`
/// line — and every `ipe_runtime::…` path in generated code — then resolves
/// against the extern crate unchanged. Shared by the native and wasm dep-model
/// branches.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if `src/main.rs` is absent from the file
/// set, or if the `pub mod ipe_runtime;` line the drop keys on is absent — a
/// drifted emit template, surfaced loudly.
fn drop_vendored_runtime_module_decl(files: &mut BTreeMap<RelPath, String>) -> DResult<()> {
    let main = files
        .get_mut("src/main.rs")
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::drop_vendored_runtime_module_decl",
            detail: "no src/main.rs in the assembled file set".to_owned(),
        })?;
    let dropped = main.replacen("pub mod ipe_runtime;\n", "", 1);
    if dropped == *main {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::drop_vendored_runtime_module_decl",
            detail: "dep-model emit expected `pub mod ipe_runtime;` in the preamble to drop, but \
                     it was absent — the emit template drifted"
                .to_owned(),
        });
    }
    *main = dropped;
    Ok(())
}

/// Relocate `env_public` to a user-crate module (`src/ipe_env_public.rs`) for the
/// dependency model, declared + glob-re-exported from `main.rs` right after the
/// runtime re-export. Its one runtime import is retargeted to the extern crate.
/// Shared by the native and wasm dep-model branches.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if `src/main.rs` is absent, or if the
/// `pub use ipe_runtime::*;` anchor the re-export injects after is absent — a
/// drifted emit template, surfaced loudly.
fn relocate_env_public_to_user_crate(
    files: &mut BTreeMap<RelPath, String>,
    public_env: &[String],
) -> DResult<()> {
    files.insert(
        RelPath::new("src/ipe_env_public.rs")?,
        render_env_public_user_rs(public_env),
    );
    let main = files
        .get_mut("src/main.rs")
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::relocate_env_public_to_user_crate",
            detail: "no src/main.rs in the assembled file set".to_owned(),
        })?;
    // Declared + glob-re-exported at the crate root right after the runtime
    // re-export, so `env_public(key)` (an unqualified call in generated code,
    // resolved via `pub use ipe_runtime::*` in the vendored model) stays in scope
    // on both the single-file and split paths (the latter's module files see it
    // via `use crate::*`).
    let anchor = "pub use ipe_runtime::*;\n";
    let barrel = "pub use ipe_runtime::*;\nmod ipe_env_public;\npub use ipe_env_public::*;\n";
    let injected = main.replacen(anchor, barrel, 1);
    if injected == *main {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::relocate_env_public_to_user_crate",
            detail:
                "dep-model env_public relocation expected the `pub use ipe_runtime::*;` anchor \
                     in main.rs — the emit template drifted"
                    .to_owned(),
        });
    }
    *main = injected;
    Ok(())
}

/// Replace the `name = "ipe-app"` line in an emitted `Cargo.toml` with the
/// project-configured name. The replacement is a single `replacen(…, 1)` on the
/// one canonical `[package] name` line, so no feature or dependency `name` key
/// is touched. `cargo_name` is a [`SafeTomlString`] so the splice is
/// unconditionally TOML-safe. When the anchor is absent (template drift), the
/// manifest is returned unchanged — a missing anchor is never a hard error here
/// because the name is cosmetic to emit correctness; the SEAL build catches a
/// broken manifest if it somehow lands.
fn apply_cargo_name(cargo_toml: &str, cargo_name: &SafeTomlString) -> String {
    const ANCHOR: &str = "name = \"ipe-app\"";
    if cargo_toml.contains(ANCHOR) {
        cargo_toml.replacen(ANCHOR, &format!("name = \"{}\"", cargo_name.as_body()), 1)
    } else {
        cargo_toml.to_owned()
    }
}

/// One vendored `ipe_runtime/mod.rs` `pub mod` append: the gate that decides
/// whether a program declares it, and the exact text pushed when the gate holds.
///
/// The text is one of the `RUNTIME_MOD_RS_*_APPEND` constants (whose doc-comments
/// carry the per-module reachability + ordering rationale). This row pairs it with
/// its predicate; [`MOD_APPENDS`] fixes the order.
struct ModAppend {
    /// Whether the program reaches this module — the same `reaches_*` / `uses_*`
    /// union the hand-written walk keyed on, so the derivation is byte-identical
    /// to the pre-table sequence.
    gate: fn(&EmitCtx) -> bool,
    /// The lines appended to `ipe_runtime/mod.rs` when `gate` holds.
    append: &'static str,
}

/// The ordered vendored-runtime `pub mod` append walk, ONE row per module.
///
/// Slice order IS emit order: [`assemble_project_files`] pushes each row whose
/// `gate` holds in this exact sequence, so the emitted `ipe_runtime/mod.rs` is
/// byte-identical to the former hand-written `if <gate> { push }` cascade. The
/// order is load-bearing — a module must be declared before any module that
/// imports it (`url` before `http_client`; `seal_codec` before `css` before
/// `ui`; `web_core` before `web`) — so it lives here as explicit data, not as
/// source position scattered across a function body.
///
/// A new vendored module is one new row (plus its `RUNTIME_MOD_RS_*_APPEND`
/// constant and an [`ALL_MOD_APPEND_TEXTS`] entry), inserted at the ordinal its
/// dependencies require — not a hand-edit in a second walk.
const MOD_APPENDS: &[ModAppend] = &[
    ModAppend {
        gate: |ctx| ctx.reaches_encoding(),
        append: RUNTIME_MOD_RS_ENCODING_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_regex,
        append: RUNTIME_MOD_RS_REGEX_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.reaches_uuid(),
        append: RUNTIME_MOD_RS_UUID_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.reaches_random(),
        append: RUNTIME_MOD_RS_RANDOM_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_db,
        append: RUNTIME_MOD_RS_DB_APPEND,
    },
    // `url` before `http_client`/`ssrf`: both `use crate::url::…` / `use url::Url`.
    ModAppend {
        gate: |ctx| ctx.reaches_url(),
        append: RUNTIME_MOD_RS_URL_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.reaches_http_client(),
        append: RUNTIME_MOD_RS_HTTP_CLIENT_APPEND,
    },
    // `http_stream` after `http_client` (it calls `crate::http_client::…`).
    ModAppend {
        gate: |ctx| ctx.uses_http,
        append: RUNTIME_MOD_RS_HTTP_STREAM_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.reaches_ssrf(),
        append: RUNTIME_MOD_RS_SSRF_APPEND,
    },
    // `db_dsn` after `ssrf`/`url` (`external_conn.rs` reaches both).
    ModAppend {
        gate: |ctx| ctx.uses_db,
        append: RUNTIME_MOD_RS_DB_DSN_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_config,
        append: RUNTIME_MOD_RS_CONFIG_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_compression,
        append: RUNTIME_MOD_RS_COMPRESS_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_csv,
        append: RUNTIME_MOD_RS_CSV_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_crypto,
        append: RUNTIME_MOD_RS_CRYPTO_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.reaches_jwt(),
        append: RUNTIME_MOD_RS_JWT_APPEND,
    },
    // `tea` before every render/effect surface whose module imports `IpeCmd`/`IpeSub`.
    ModAppend {
        gate: |ctx| {
            ctx.uses_tea
                || ctx.uses_http
                || ctx.uses_server
                || ctx.uses_websocket
                || ctx.uses_web
                || ctx.uses_tui
                || ctx.uses_webview
        },
        append: RUNTIME_MOD_RS_TEA_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_server || ctx.uses_web,
        append: RUNTIME_MOD_RS_SERVER_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_websocket,
        append: RUNTIME_MOD_RS_WEBSOCKET_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_auth || ctx.reaches_jwt(),
        append: RUNTIME_MOD_RS_AUTH_APPEND,
    },
    ModAppend {
        gate: |ctx| {
            ctx.uses_principal
                || ctx.uses_server
                || ctx.uses_web
                || ctx.uses_db
                || ctx.reaches_jwt()
        },
        append: RUNTIME_MOD_RS_PRINCIPAL_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_principal || ctx.reaches_jwt(),
        append: RUNTIME_MOD_RS_REVOCATION_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_email,
        append: RUNTIME_MOD_RS_EMAIL_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_locale,
        append: RUNTIME_MOD_RS_LOCALE_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_env_public,
        append: RUNTIME_MOD_RS_ENV_PUBLIC_APPEND,
    },
    // Render stack, dependency order: `seal_codec` before `css` before `ui`.
    ModAppend {
        gate: |ctx| ctx.uses_ui || ctx.uses_tui || ctx.uses_web || ctx.uses_webview,
        append: RUNTIME_MOD_RS_SEAL_CODEC_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_ui || ctx.uses_css || ctx.uses_tui || ctx.uses_web || ctx.uses_webview,
        append: RUNTIME_MOD_RS_CSS_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_ui || ctx.uses_tui || ctx.uses_web || ctx.uses_webview,
        append: RUNTIME_MOD_RS_UI_APPEND,
    },
    // `literal_table` before the render/web modules that `use crate::literal_table`.
    ModAppend {
        gate: |ctx| ctx.uses_web || ctx.uses_webview || ctx.uses_tui || ctx.uses_console,
        append: RUNTIME_MOD_RS_LITERAL_TABLE_APPEND,
    },
    // `web_core` (the ONE real `web` module) before the served `web` surface.
    ModAppend {
        gate: |ctx| ctx.uses_web || ctx.uses_webview,
        append: RUNTIME_MOD_RS_WEB_CORE_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_web,
        append: RUNTIME_MOD_RS_WEB_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_tui || ctx.uses_console,
        append: RUNTIME_MOD_RS_TUI_APPEND,
    },
    ModAppend {
        gate: |ctx| ctx.uses_webview,
        append: RUNTIME_MOD_RS_WEBVIEW_APPEND,
    },
];

/// Every `RUNTIME_MOD_RS_*_APPEND` constant the vendored `mod.rs` walk emits —
/// the coverage domain [`MOD_APPENDS`] must exhaust.
///
/// The build-time assert below proves each entry here appears in exactly one
/// [`MOD_APPENDS`] row, so a newly added append constant that is listed here but
/// never wired into the walk (or wired twice) breaks the BUILD rather than
/// silently dropping a module from the emitted runtime at cargo time — the SEAL
/// "a table drifted from its callee table" clause. `RUNTIME_MOD_RS_ENV_PUBLIC_APPEND`
/// also feeds the wasm sealed-floor path (a one-off outside this ordered walk);
/// it appears once here for its native-walk row.
const ALL_MOD_APPEND_TEXTS: &[&str] = &[
    RUNTIME_MOD_RS_ENCODING_APPEND,
    RUNTIME_MOD_RS_REGEX_APPEND,
    RUNTIME_MOD_RS_UUID_APPEND,
    RUNTIME_MOD_RS_RANDOM_APPEND,
    RUNTIME_MOD_RS_DB_APPEND,
    RUNTIME_MOD_RS_URL_APPEND,
    RUNTIME_MOD_RS_HTTP_CLIENT_APPEND,
    RUNTIME_MOD_RS_HTTP_STREAM_APPEND,
    RUNTIME_MOD_RS_SSRF_APPEND,
    RUNTIME_MOD_RS_DB_DSN_APPEND,
    RUNTIME_MOD_RS_CONFIG_APPEND,
    RUNTIME_MOD_RS_COMPRESS_APPEND,
    RUNTIME_MOD_RS_CSV_APPEND,
    RUNTIME_MOD_RS_CRYPTO_APPEND,
    RUNTIME_MOD_RS_JWT_APPEND,
    RUNTIME_MOD_RS_TEA_APPEND,
    RUNTIME_MOD_RS_SERVER_APPEND,
    RUNTIME_MOD_RS_WEBSOCKET_APPEND,
    RUNTIME_MOD_RS_AUTH_APPEND,
    RUNTIME_MOD_RS_PRINCIPAL_APPEND,
    RUNTIME_MOD_RS_REVOCATION_APPEND,
    RUNTIME_MOD_RS_EMAIL_APPEND,
    RUNTIME_MOD_RS_LOCALE_APPEND,
    RUNTIME_MOD_RS_ENV_PUBLIC_APPEND,
    RUNTIME_MOD_RS_SEAL_CODEC_APPEND,
    RUNTIME_MOD_RS_CSS_APPEND,
    RUNTIME_MOD_RS_UI_APPEND,
    RUNTIME_MOD_RS_LITERAL_TABLE_APPEND,
    RUNTIME_MOD_RS_WEB_CORE_APPEND,
    RUNTIME_MOD_RS_WEB_APPEND,
    RUNTIME_MOD_RS_TUI_APPEND,
    RUNTIME_MOD_RS_WEBVIEW_APPEND,
];

/// `true` when `a` and `b` are byte-identical (const-context `str` equality; the
/// standard `==` is not `const` on `&str`).
const fn str_eq(a: &str, b: &str) -> bool {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    // Walk both slices in lockstep via slice patterns — no indexing (const-fn,
    // `indexing_slicing`-clean). Equal lengths ⇒ they empty together ⇒ `true`.
    while let ([first_a, rest_a @ ..], [first_b, rest_b @ ..]) = (a, b) {
        if *first_a != *first_b {
            return false;
        }
        a = rest_a;
        b = rest_b;
    }
    true
}

/// The number of [`MOD_APPENDS`] rows whose `append` is byte-identical to `text`.
const fn mod_append_row_count(text: &str) -> usize {
    let mut rows = MOD_APPENDS;
    let mut n = 0;
    while let [row, rest @ ..] = rows {
        if str_eq(row.append, text) {
            n += 1;
        }
        rows = rest;
    }
    n
}

/// `true` when every [`ALL_MOD_APPEND_TEXTS`] entry is wired into exactly one
/// [`MOD_APPENDS`] row.
const fn every_append_text_has_one_row() -> bool {
    let mut rest = ALL_MOD_APPEND_TEXTS;
    while let [first, tail @ ..] = rest {
        if mod_append_row_count(first) != 1 {
            return false;
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED — build-time drift tripwire, not a runtime panic. The
// condition is evaluated in a `const` context, so it fires at COMPILE time. An
// append constant listed in `ALL_MOD_APPEND_TEXTS` but missing from `MOD_APPENDS`
// (or wired into it twice) breaks the build — the SEAL "a table drifted from its
// callee table" clause — rather than silently dropping/duplicating a `pub mod`
// line in the emitted runtime two steps downstream at cargo time. Counting rows
// (== 1) also fails a copy-paste that reuses one append text for two rows, and,
// with the equal lengths, proves `MOD_APPENDS` carries no un-listed append.
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    every_append_text_has_one_row() && MOD_APPENDS.len() == ALL_MOD_APPEND_TEXTS.len(),
    "every ALL_MOD_APPEND_TEXTS entry must be wired into exactly one MOD_APPENDS row, \
     and MOD_APPENDS must carry no append text absent from ALL_MOD_APPEND_TEXTS"
);

/// Assemble the final [`EmittedProject`] and refuse it when an emitted `.rs`
/// text holds a raw lexer hazard.
///
/// The one join point of [`emit_program`] and [`assemble_split_manifest`], so
/// the lexable seal covers the single-file and the split emit alike.
///
/// # Errors
///
/// Every [`Diagnostic`] of [`assemble_project_text`] and of
/// [`refuse_lexer_hazards`].
fn assemble_project_files(
    ctx: &EmitCtx,
    rust_sources: Vec<(RelPath, String)>,
) -> DResult<EmittedProject> {
    let project = assemble_project_text(ctx, rust_sources)?;
    refuse_lexer_hazards(&project)?;
    Ok(project)
}

/// Assemble the final [`EmittedProject`] from the already-rendered Rust source
/// files (`src/main.rs` plus, in the real split, each `src/ipe_mods/<ident>.rs`)
/// — appending the manifest (`Cargo.toml`) and the trimmed runtime module
/// files (`ipe_runtime/mod.rs` + `config.rs`).
///
/// **Shared by [`emit_program`] and [`assemble_split_manifest`].** This block
/// is file-count-agnostic — it depends ONLY on `ctx`'s used-kernel flags, never
/// on how many Rust source files `rust_sources` carries — so the salsa
/// `emit_manifest` query (`ipe_db`) reuses it verbatim after assembling
/// `rust_sources` from the per-file [`emit_spine`]/[`emit_module_file`] query
/// outputs, guaranteeing byte-identity with the single-file `emit_program`
/// path.
///
/// # Errors
///
/// Propagates any [`Diagnostic`] from the `Cargo.toml`/runtime-module
/// construction (e.g. a drifted server/db/tui/webview manifest anchor).
#[allow(clippy::too_many_lines)] // one linear manifest/runtime assembly pass
fn assemble_project_text(
    ctx: &EmitCtx,
    rust_sources: Vec<(RelPath, String)>,
) -> DResult<EmittedProject> {
    // The emitted crate's package name: the caller-supplied sanitized project
    // name, or the safe default when no name was configured.
    let effective_name: &str = if ctx.cargo_name.is_empty() {
        "ipe-app"
    } else {
        &ctx.cargo_name
    };
    // Wrap once; all apply_cargo_name call sites below use this.
    let safe_name = SafeTomlString::escape(effective_name);

    // ── Browser-WASM branch ──────────────────────────────────────────────────
    // Both wasm models share the closed Layer-3 security floor (no
    // tokio/axum/sqlx/TLS to link a credential through) and the static browser
    // shell; they differ only in whether the runtime is a path dependency
    // (`runtime_dep` set — the unified model) or a vendored source subtree.
    if ctx.target == ipe_ir::Target::WasmClient {
        assert_wasm_admissible(ctx)?;
        let mut files = BTreeMap::new();
        for (path, text) in rust_sources {
            // Under the dependency model the runtime is an extern crate reached
            // through the prelude, so the one emitted `crate::ipe_runtime::…`
            // reference is retargeted to `ipe_runtime::…`; the vendored model
            // keeps the byte-identical `crate::ipe_runtime::…` form.
            let text = if ctx.runtime_dep.is_some() {
                rewrite_runtime_paths_for_dep(&text)
            } else {
                text
            };
            files.insert(path, text);
        }
        insert_wasm_shared_files(&mut files)?;

        if ctx.runtime_dep.is_some() {
            // Dependency model: the runtime is a relative path dependency selected
            // by the SSOT `wasm-client` floor (+ any browser-admissible surface),
            // built for wasm32 by cargo. The bundled source lives at
            // `ipe_runtime_dep/` (written by the driver) — no host-absolute path
            // dependency. The crate-root `pub mod ipe_runtime;` (vendored-source
            // declaration) is dropped; `pub use ipe_runtime::*;` and every
            // `ipe_runtime::…` path resolve against the extern crate. `env_public`
            // moves to a user-crate module, matching the native dep-model relocation.
            let cargo_toml = dep_model_wasm_cargo_toml(ctx)?;
            drop_vendored_runtime_module_decl(&mut files)?;
            if ctx.uses_env_public {
                relocate_env_public_to_user_crate(&mut files, &ctx.wasm_public_env)?;
            }
            let cargo_toml = apply_cargo_name(&cargo_toml, &safe_name);
            return Ok(EmittedProject {
                files,
                cargo_toml,
                uses_webview: ctx.uses_webview,
            });
        }

        // Vendored model: the trimmed runtime module subtree is emitted into the
        // app crate, and the closed vendored manifest carries every dependency
        // non-optional.
        let wasm_mod_rs = if ctx.uses_env_public {
            let mut m = WASM_RUNTIME_MOD_RS.to_owned();
            m.push_str(RUNTIME_MOD_RS_ENV_PUBLIC_APPEND);
            m
        } else {
            WASM_RUNTIME_MOD_RS.to_owned()
        };
        files.insert(RelPath::new("src/ipe_runtime/mod.rs")?, wasm_mod_rs);
        insert_vendored_runtime_clippy_config(&mut files)?;
        files.insert(
            RelPath::new("src/ipe_runtime/config.rs")?,
            RUNTIME_CONFIG_RS.to_owned(),
        );
        if ctx.uses_env_public {
            files.insert(
                RelPath::new("src/ipe_runtime/env_public.rs")?,
                render_env_public_rs(&ctx.wasm_public_env),
            );
        }
        // Ipe.Time IANA-zone surface: same gate as the native path — the wasm
        // `time` module is always present, its zone helpers behind the `time`
        // feature. Promote the feature + re-inject `chrono-tz` only for a Time
        // program; a no-Time wasm program drops the crate.
        let wasm_cargo_toml = if ctx.uses_time {
            chrono_tz_cargo_toml(WASM_CARGO_TOML)?
        } else {
            WASM_CARGO_TOML.to_owned()
        };
        let wasm_cargo_toml = apply_cargo_name(&wasm_cargo_toml, &safe_name);
        return Ok(EmittedProject {
            files,
            cargo_toml: wasm_cargo_toml,
            uses_webview: ctx.uses_webview,
        });
    }

    // ── Native dependency-model branch ───────────────────────────────────────
    // The runtime is a relative path dependency pointing to `ipe_runtime_dep/`,
    // which the driver writes alongside the emitted crate. The manifest declares
    // `ipe_runtime` with the SSOT-selected features (which pull the gated
    // third-party crates transitively — the per-surface manifest augmenters
    // below are REPLACED by that feature list). No `src/ipe_runtime/` tree is
    // emitted inside the app crate; the generated code reaches the runtime
    // through the extern prelude (`ipe_runtime::…`), so the one emitted
    // `crate::ipe_runtime::…` reference is rewritten to that form; `env_public`
    // moves to a user-crate module. Wasm never reaches here (its closed template
    // returned above).
    if ctx.runtime_dep.is_some() {
        let mut cargo_toml = dep_model_cargo_toml(ctx)?;
        let mut files = BTreeMap::new();
        for (path, text) in rust_sources {
            files.insert(path, rewrite_runtime_paths_for_dep(&text));
        }
        // `main.rs` reaches the runtime through the extern prelude, so the
        // crate-root `pub mod ipe_runtime;` (vendored-source declaration) is
        // dropped; the following `pub use ipe_runtime::*;` line — and every
        // `ipe_runtime::…` path in generated code — resolves against the extern
        // crate unchanged.
        drop_vendored_runtime_module_decl(&mut files)?;
        // `env_public` is per-project code, so under the dep model it belongs in
        // the user crate (`src/ipe_env_public.rs`), declared + re-exported from
        // `main.rs`. Its one runtime import is retargeted to the extern crate.
        if ctx.uses_env_public {
            relocate_env_public_to_user_crate(&mut files, &ctx.wasm_public_env)?;
        }
        // FFI wrappers are user-project code in BOTH models — the wrapper module
        // + its `mod ffi;` declaration ride the emitted crate unchanged, and the
        // bound crates' pinned `[dependencies]` lines join the manifest exactly
        // as they do on the vendored path. Omitting them here would emit a crate
        // whose `src/ffi.rs` references an external `::<crate>::…` the manifest
        // never declares — an `ipe`-accept-then-cargo-fail the SEAL forbids.
        if ctx.uses_ffi {
            let ffi = ctx.ffi.as_ref().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::assemble_project_files",
                detail: "program lowers foreign-wrapper calls but the driver supplied no FFI \
                         emission inputs (RustBackend::with_ffi)"
                    .to_owned(),
            })?;
            shake_interface_forwarder_files(&mut files, &ffi.interface_modules);
            let reached = reached_ffi_idents(&files);
            let shaken = shake_ffi_by_fn_ident(&ffi.bindings_source, &reached);
            let sidecar = ffi_wrappers_sidecar(&shaken);
            files.insert(RelPath::new("src/ffi.rs")?, shaken);
            files.insert(RelPath::new("src/ffi-wrappers.json")?, sidecar);
            let main = files
                .get_mut("src/main.rs")
                .ok_or_else(|| Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::project::assemble_project_files",
                    detail: "no src/main.rs in the assembled file set".to_owned(),
                })?;
            main.push_str("\nmod ffi;\n");
            cargo_toml = ffi_cargo_toml(&cargo_toml, ctx)?;
        }
        // Co-located WASI shares this native emission; its wasip1 link needs the
        // mold-escaping target-scoped config the browser wasm emit also carries.
        if ctx.target == ipe_ir::Target::WasmWasi {
            insert_wasi_linker_config(&mut files)?;
        }
        let cargo_toml = apply_cargo_name(&cargo_toml, &safe_name);
        return Ok(EmittedProject {
            files,
            cargo_toml,
            uses_webview: ctx.uses_webview,
        });
    }

    // ── Manifest + runtime module files ──────────────────────────────────────
    // The driver (ipe) first copies the full runtime source tree into
    // `<out>/src/ipe_runtime/`, then writes the emitted files over the top.
    // So we only need to emit the files that differ from the raw source tree:
    //
    //   • `mod.rs` — trimmed to the kernel set the program uses (non-db path
    //     keeps the default; db path appends `pub mod db; pub use db::*;`).
    //   • `config.rs` — the stub for non-db; the full db-type-alias file
    //     for db programs (provides `DbPool`, `DbRow`, `IPE_DB_URL`, …).
    //   • `Cargo.toml` — adds `db` to default features + `sqlx` dep for db.
    // Build the manifest + runtime module selection based on which kernel groups
    // are used. Db, TEA, and Server are independent features; a program may use
    // any combination. The order: db first, then server; both modify the same
    // base manifest so we chain the transformations.
    // The async spine (`tokio` + `futures-util` + the `"tokio"` default feature)
    // is off the base template and restored here whenever the program needs the
    // reactor. This runs FIRST, before every per-surface surgery, so their
    // anchors (`default = ["tokio", "json"]`, the `tokio` dependency line) see
    // the restored spine and compose byte-identically to the pre-gating output.
    // A pure program keeps the tokio-free base and enters through the std-only
    // `block_on` selected in the epilogue below.
    //
    // Every reactor surface whose augmenter inserts, extends, or depends on the
    // `tokio` line (db / server / web / webview / websocket / http / tui / tea /
    // email) is folded into `uses_async_runtime` at its computation site, so this
    // flag is a superset of that set BY CONSTRUCTION — not by assumption. The
    // restore is therefore always present when a downstream anchor needs it, even
    // for a surface reached by a reserved-type mention alone (no async kernel).
    // The pure surfaces (crypto / jwt / auth / url / config / compression / csv)
    // anchor on `[profile.dev]`, never the tokio line, so they are correctly
    // absent from that superset and keep the tokio-free base.
    let async_base = if ctx.uses_async_runtime {
        async_runtime_cargo_toml(CARGO_TOML)?
    } else {
        CARGO_TOML.to_owned()
    };
    let (cargo_toml, runtime_config_rs) = if ctx.uses_db {
        let cfg = match ctx.db_driver {
            crate::DbDriver::Sqlite => RUNTIME_CONFIG_RS_DB_SQLITE,
            crate::DbDriver::Postgres => RUNTIME_CONFIG_RS_DB_POSTGRES,
        };
        (db_cargo_toml(&async_base, ctx.db_driver)?, cfg.to_owned())
    } else {
        (async_base, RUNTIME_CONFIG_RS.to_owned())
    };
    // Apply the axum server manifest extension. The served surface and the Live
    // `web` app need axum + tower-http; a desktop-webview delivery does NOT (it
    // renders over a local IPC bridge, no HTTP server), so it is excluded — its
    // render core is the server-free `web-core` promoted by `webview_cargo_toml`.
    let cargo_toml = if ctx.uses_server || ctx.uses_web {
        server_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // When the program uses the Live `web` app, add "web" to the default
    // features (the base manifest declares `web = []` as a non-default feature).
    // NOT for webview: its native backend reuses only the server-free render core
    // (`web-core`, promoted by `webview_cargo_toml`), never the axum `web` surface.
    let cargo_toml = if ctx.uses_web {
        web_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // When the program uses the terminal shape — either `Tui.tea` (full-screen)
    // or `Cli.tea` (line-oriented) — add "tui" to the default features and
    // inject the crossterm + unicode-width deps required by the terminal
    // runtime. Both drive axes share the one `tui` Cargo feature: a `Cli.tea`
    // view returns `Lines msg`, rendered by `ipe_runtime::tui::render_lines_view`
    // (behind `feature = "tui"`). The base manifest declares `tui = []` as a
    // non-default feature; we promote it and add the deps so the compiled binary
    // includes the terminal module.
    let cargo_toml = if ctx.uses_tui || ctx.uses_console {
        tui_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // When the program uses Webview, add "webview" to the default
    // features and inject the wry + tao deps required by the real native-window
    // backend. The base manifest declares `webview = []` as a non-default feature;
    // this function promotes it, wires it to wry + tao, and adds those deps.
    let cargo_toml = if ctx.uses_webview {
        webview_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.WebSocket client: promote the `websocket_client` feature +
    // add tokio-tungstenite + tokio `"sync"`. Applied last; idempotent on the
    // tokio `"sync"` step so it composes with any prior server/live/tui surgery.
    let cargo_toml = if ctx.uses_websocket {
        websocket_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Email: `email.rs` needs the `lettre` crate for the SMTP transport
    // (`reqwest`, reached through `http_client`, is added by the HTTP-client
    // step below; every other crate it uses — `base64` / `hmac` / `sha2` /
    // `serde_json` / `url` — is already an unconditional base-manifest dep).
    // Add `lettre` only when the program uses `Email.send`.
    let cargo_toml = if ctx.uses_email {
        email_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Locale: `locale.rs` is feature-gated behind `#[cfg(feature = "locale")]`
    // for the ICU4X parse path. Promote the `locale` feature into `default` and
    // add `icu_casemap` + `icu_locale_core` as optional deps only when the program
    // reaches locale kernels or mentions `IrType::Locale`. The dep model handles
    // this through `RuntimeFeature::Locale` (no manifest surgery needed there).
    let cargo_toml = if ctx.uses_locale {
        locale_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Outbound HTTP client (`reqwest`): pulled in by a client kernel
    // (`uses_http`), the server surface (`http_stream.rs` calls `ssrf_apply`+
    // `method_to_reqwest`), or the email surface (`email.rs` calls
    // `ssrf_apply`). Web and webview reach reqwest through the server surface
    // they imply. The `url` crate stays unconditional (backs `Ipe.Url` +
    // `ssrf`), so only the reqwest HTTP stack (~60 transitive crates) is gated.
    let uses_http_client = ctx.reaches_http_client();
    let cargo_toml = if uses_http_client {
        http_client_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Url (`url` crate + its `idna` → ICU4X subtree, the single largest
    // gateable dependency root): pulled in when the emitted crate reaches the
    // `url` runtime module — an `Ipe.Url` kernel (`uses_url`), or a surface whose
    // own runtime module parses with the `url` crate (the HTTP client, whose
    // `http_client.rs` targets a typed `crate::url::Url`; the WebSocket client,
    // whose `ws_client.rs` calls `::url::Url::parse`; and the shared `ssrf`
    // validators those two pull, `use url::Url`). A pure-CLI program pulls
    // neither the crate nor its subtree.
    let cargo_toml = if ctx.reaches_url() {
        url_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Config TOML/YAML decoders (`toml` + `serde_yaml`): pulled in only when
    // the program reaches the `config_decode` runtime module (`Config.decodeToml`
    // / `decodeYaml` / `decodeJson` / `loadFromFile`, or `nullable` / `maybe` /
    // `dict`). Both crates are leaves — a JSON-only or non-Config program pulls
    // neither. `config_decode` is not reached by any other surface, so the flag
    // alone gates it.
    let cargo_toml = if ctx.uses_config {
        config_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Compression (`flate2` + `zstd`): pulled in only when the program
    // reaches the `compression` runtime module (`Compression.gzip` / `gunzip` /
    // `zstdCompress` / `zstdDecompress`). Both crates are leaves — a program that
    // never compresses pulls neither. `compression` is not reached by any other
    // surface, so the flag alone gates it.
    let cargo_toml = if ctx.uses_compression {
        compression_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Csv (`csv`): pulled in only when the program reaches the `csv` runtime
    // module (`Csv.parse` / `parseWithDelimiter` / `encode` / `encodeWithDelimiter`
    // / `parseStreamFromFile`, or a signature mentioning the `CsvDoc` type). The
    // crate is a leaf — a program that never parses CSV pulls it not. `csv` is
    // not reached by any other surface, so the flag alone gates it.
    let cargo_toml = if ctx.uses_csv {
        csv_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Time IANA-zone calendar surface (`chrono-tz`): pulled in only when the
    // program reaches a non-TEA `Ipe.Time` kernel. The `time` runtime module is
    // always declared, but its zone helpers are gated behind the `time` Cargo
    // feature; this step promotes the feature and re-injects `chrono-tz`. A
    // program that uses no Time kernel keeps the base manifest and drops the
    // crate. `chrono` core is gated separately by `time-core`/`log` (the
    // log/db/web timestamp surfaces reach it), so it is never touched here.
    // Anchors on `default = [` /
    // `chrono = "=0.4.45"`, not the tokio line, so it composes with the sync base.
    let cargo_toml = if ctx.uses_time {
        chrono_tz_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Heavy Ipe.Crypto (`sha1` + `md-5` + `aes-gcm` + `chacha20poly1305` +
    // `pbkdf2`): pulled in only when the program uses a heavy `Ipe.Crypto` kernel
    // (legacy SHA-1/MD5, AEAD, or PBKDF2). All five are leaves consumed solely by
    // `crypto.rs`. The `crypto_core` floor keeps `sha2` / `hmac` / `subtle`
    // unconditional in the base manifest (always-on surfaces need them), so a
    // program using only SHA-2/HMAC/entropy pulls none of the heavy crates.
    let cargo_toml = if ctx.uses_crypto {
        crypto_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Jwt (`jsonwebtoken`): pulled in when the program reaches the `jwt`
    // runtime module — a `Ipe.Jwt` kernel (`uses_jwt`) or the `Ipe.Auth` surface
    // (`auth.rs` calls `crate::jwt`). The crate is a leaf — a program that never
    // uses JWT or Auth pulls it not.
    let cargo_toml = if ctx.reaches_jwt() {
        jwt_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Heavy `crypto_core` floor (`rsa`, a ~34-crate subtree): pulled in only when
    // the emitted crate reaches the RSA sign/verify pair — a heavy `Ipe.Crypto`
    // kernel (`uses_crypto`) or the JWT / Auth surface (`reaches_jwt`, whose
    // RS256 path signs with `crypto_core`'s RSA). The floor's other primitives —
    // the entropy pair, SHA-2 / HMAC, the constant-time compare, the `Key`/`Mac`
    // newtypes — are not `cfg`-gated and stay unconditional. A program touching
    // none of crypto / jwt / auth pulls no `rsa`.
    let cargo_toml = if ctx.reaches_crypto_core_heavy() {
        crypto_core_heavy_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Ipe.Secret: promote the `secret` feature when the program reaches the
    // secret surface. The vendored `secret.rs` compiles unconditionally, but the
    // functions that mint a `Secret` from another module — `io.rs::io_read_secret`
    // (`Io.readSecret`), `app_config.rs::resolve_db_url_override` — are
    // `#[cfg(feature = "secret")]`, so a `Secret`-reaching program must have the
    // feature on. Idempotent: `db_cargo_toml` already added it for db programs.
    let cargo_toml = if ctx.reaches_secret() {
        secret_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // TEA runtime: `tea.rs` drives its event loop over a `tokio::sync::mpsc`
    // channel, so any program that pulls the `tea` module needs tokio's `"sync"`
    // feature. The union mirrors the `tea` mod.rs append below (a `Cmd`/`Sub`
    // kernel, or a surface whose runtime module imports `IpeCmd`/`IpeSub`).
    // Runs AFTER the server/web/tui/webview steps, which perform their own tokio
    // feature surgery against the base line — `tea_cargo_toml` is idempotent
    // (short-circuits when `"sync"` is already present), so it only extends the
    // pure-TEA base that no other step touched.
    let cargo_toml = if ctx.uses_tea
        || ctx.uses_server
        || ctx.uses_websocket
        || ctx.uses_web
        || ctx.uses_tui
        || ctx.uses_webview
    {
        tea_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // SSRF gate: `ssrf.rs` resolves hosts through `tokio::net::lookup_host`, so
    // the crate that declares the module (the same `reaches_ssrf` gate as its
    // `mod.rs` append) declares tokio's `"net"` feature itself rather than
    // relying on a transport crate to enable it. Runs after every step that
    // anchors on an exact `tokio` line, so none of their anchors sees this edit.
    let cargo_toml = if ctx.reaches_ssrf() {
        ssrf_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Build intent: a dev-verb emit promotes `dev-posture`, the one input that
    // lets the vendored runtime's console default open (loopback only). A
    // release emit leaves the feature declared but off.
    let cargo_toml = if ctx.build_intent == crate::BuildIntent::Development {
        dev_posture_cargo_toml(&cargo_toml)?
    } else {
        cargo_toml
    };
    // Foreign-crate FFI: append the bound crates' pinned [dependencies] lines
    // (exact versions + effective feature sets, pre-merged by the driver).
    let cargo_toml = if ctx.uses_ffi {
        ffi_cargo_toml(&cargo_toml, ctx)?
    } else {
        cargo_toml
    };
    // The vendored `ipe_runtime/mod.rs`: the base default plus one `pub mod`
    // append per reached module, in the dependency order fixed by `MOD_APPENDS`
    // (a module is declared before any module that imports it).
    let runtime_mod_rs = {
        let mut mod_rs = RUNTIME_MOD_RS.to_owned();
        for append in MOD_APPENDS {
            if (append.gate)(ctx) {
                mod_rs.push_str(append.append);
            }
        }
        mod_rs
    };

    let mut files = BTreeMap::new();
    // The emitted Rust source files: `src/main.rs` always, plus one
    // `src/ipe_mods/<ident>.rs` per module in the real-split case. In the
    // single-file collapse case `rust_sources` holds exactly the one
    // byte-identical `src/main.rs`.
    for (path, text) in rust_sources {
        files.insert(path, text);
    }
    files.insert(RelPath::new("src/ipe_runtime/mod.rs")?, runtime_mod_rs);
    insert_vendored_runtime_clippy_config(&mut files)?;
    files.insert(
        RelPath::new("src/ipe_runtime/config.rs")?,
        runtime_config_rs,
    );
    if ctx.uses_env_public {
        files.insert(
            RelPath::new("src/ipe_runtime/env_public.rs")?,
            render_env_public_rs(&ctx.wasm_public_env),
        );
    }
    // Foreign-crate FFI: write the wrapper module and declare it from the
    // crate root. File-count-agnostic (shared by the single-file and split
    // assembly paths), so the two stay byte-identical.
    if ctx.uses_ffi {
        let ffi = ctx.ffi.as_ref().ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::assemble_project_files",
            detail: "program lowers foreign-wrapper calls but the driver supplied no FFI \
                     emission inputs (RustBackend::with_ffi)"
                .to_owned(),
        })?;
        // S4 sentinel DCE (design D7): keep only the wrapper regions the
        // program REACHES. Reachability is read straight off the emitted
        // source — every `Callee::Ffi` renders as `crate::ffi::<ident>`, so a
        // scan of the already-emitted files is exhaustive by construction.
        // This is what lets a program bind a 76k-symbol crate yet compile only
        // the handful of wrappers it calls — and keeps a generator gap in some
        // UNUSED wrapper (an exotic lifetime/borrow shape the emitter renders
        // wrong) from breaking a build that never calls it.
        //
        // The interface FORWARDER modules must shake FIRST: every forwarder
        // references its wrapper, so an unshaken forwarder barrel would mark
        // every wrapper reached and defeat the slice below.
        shake_interface_forwarder_files(&mut files, &ffi.interface_modules);
        let reached = reached_ffi_idents(&files);
        let shaken = shake_ffi_by_fn_ident(&ffi.bindings_source, &reached);
        let sidecar = ffi_wrappers_sidecar(&shaken);
        files.insert(RelPath::new("src/ffi.rs")?, shaken);
        files.insert(RelPath::new("src/ffi-wrappers.json")?, sidecar);
        let main = files
            .get_mut("src/main.rs")
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::assemble_project_files",
                detail: "no src/main.rs in the assembled file set".to_owned(),
            })?;
        main.push_str("\nmod ffi;\n");
    }
    // Co-located WASI shares this native emission; its wasip1 link needs the
    // mold-escaping target-scoped config the browser wasm emit also carries.
    if ctx.target == ipe_ir::Target::WasmWasi {
        insert_wasi_linker_config(&mut files)?;
    }
    let cargo_toml = apply_cargo_name(&cargo_toml, &safe_name);
    Ok(EmittedProject {
        files,
        cargo_toml,
        uses_webview: ctx.uses_webview,
    })
}

/// Return `true` when a value of type `ty` holds a server-surface or non-serde
/// opaque component that must not appear as a field in a `HydrationState` record.
///
/// The gate is an **allowlist**: only data-only, serialisable `IrType`s pass.
/// Function types, runtime handles, secret/SQL-fragment/crypto opaques, UI
/// element types, and TEA-runtime opaques all fail. One leaf over the shared
/// held-value walk ([`ipe_ir::ir_type_holds`]): every transparent carrier and
/// every named enum's type arguments and variant payloads (from `payloads`) are
/// descended there, cyclic ADTs included.
fn ir_type_contains_non_serde(ty: &IrType, payloads: &ipe_ir::EnumPayloadTable) -> bool {
    ipe_ir::ir_type_holds(ty, payloads, &is_non_serde_leaf)
}

/// Is `ty` itself a non-serde component, before the walk descends into it?
///
/// Exhaustive with no wildcard: a new [`IrType`] variant must be classified
/// here. Carriers the walk descends (`Maybe`, `List`, `Set`, `Result`, `Dict`,
/// tuple, record, named enum) are not non-serde themselves; their components
/// decide.
const fn is_non_serde_leaf(ty: &IrType) -> bool {
    match ty {
        // ── Primitive data types — serialisable ──────────────────────────
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::Error
        | IrType::ErrorKind
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::Generic(_)
        // A row variable's serde-representability rides its witness bound set,
        // exactly as a plain generic's rides its `T: Serialize` bound.
        | IrType::RowGeneric(_)
        // ── Serialisable carriers — their components decide ──────────────
        | IrType::Maybe(_)
        | IrType::List(_)
        | IrType::Set(_)
        | IrType::Result(_, _)
        | IrType::Dict(_, _)
        | IrType::Tuple(_)
        | IrType::Record(_)
        | IrType::Enum { .. } => false,

        // ── Never serialisable ────────────────────────────────────────────
        // Function types, UI element types, and the non-serde server-surface
        // / runtime-opaque types: handles to server resources, async
        // primitives, or types explicitly documented as non-serde
        // (Secret, SqlFragment).
        IrType::Fun(..)
        | IrType::SharedFun(..)
        | IrType::FnOnceChain(..)
        | IrType::Ui { .. }
        | IrType::UiPlain(_)
        | IrType::Task(_)
        | IrType::Cmd(_)
        | IrType::Sub(_)
        | IrType::Decoder(_)
        | IrType::Db
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::StreamWriter
        | IrType::HttpRequest
        | IrType::Regex
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::WebReq
        | IrType::SessionHandle
        | IrType::WebRoute(_)
        // The widget handle is non-serde — it cannot ride a HydrationState island.
        | IrType::CustomElement { .. }
        | IrType::Secret
        | IrType::Path
        // `Url` is a non-serde request-boundary value (like `Path`) — a `Url` in
        // a HydrationState record is rejected.
        | IrType::Url
        // `Relative` is a non-serde same-origin href projection (like `Url`) — a
        // `Relative` in a HydrationState record is rejected.
        | IrType::UrlRelative
        // `Dsn` carries a `Secret` and is non-serde — a `Dsn` in a HydrationState
        // record is rejected (same posture as `Url`/`Secret`).
        | IrType::Dsn
        // External `Connection` + phantom markers — opaque non-serde handles,
        // rejected in a HydrationState record just like `Dsn`.
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::SqlFragment
        | IrType::CacheCfg
        | IrType::CacheStats
        | IrType::WebSocketClientCfg
        | IrType::CsvDoc
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // `ProcessRunWithCfg` / `ProcessRunInPtyCfg` — kernel-boundary non-serde
        // input records; rejected in a HydrationState record, same posture as the
        // Email/Cache cfg types.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        // Typed-key newtypes — not serde; a Key/Mac/EmailAddress in a
        // HydrationState record is rejected.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale` — not serde; rejected in a HydrationState record.
        | IrType::Locale
        // `Principal` — not serde; a hydrated `Principal` would be a forged
        // identity, so it is rejected in a HydrationState record.
        | IrType::Principal
        // `AuthConfig`/`TokenSource` — not serde; authed-route descriptors are
        // rejected in a HydrationState record.
        | IrType::AuthConfig
        | IrType::TokenSource
        // Shape opaque app leaves — not serde; rejected in a HydrationState record.
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp => true,
    }
}

/// Gate: when `ctx.wasm_hydrate_mode`, verify every field of the island
/// parse-target type is serialisation-safe.
///
/// The parse target is NOT a type named literally `HydrationState`: it is
/// whatever type the user's `fromHydrationState` projection takes as its
/// parameter — the exact type [`EmitCtx::resolve_hydration_state_rust_name`]
/// resolves for the `hydrate` glue (the user may name that ADT `MyState`,
/// `MainHydrationState`, etc.). Keying on a literal `HydrationState` name
/// would miss (or check the wrong type for) any program that names its island
/// type differently, letting a non-serde field slip through the gate — so the
/// gate is driven off the SAME projection parameter the emit path uses (single
/// source of truth, no drift between gate and glue).
///
/// A target with a non-serde field type (e.g. `Secret`, `Db`, `Task`, a
/// function type) is a compile error — the emitted `hydrate` export serialises
/// this type as JSON, so any such field would silently leak a server-side
/// secret or produce a `cargo` type error (an ipe-accept-then-cargo-fail SEAL
/// break). The gate fires at compile time, giving a clear diagnostic rather
/// than a mysterious `serde` bound failure from `rustc`.
///
/// When the program declares no `fromHydrationState` projection there is no
/// island parse target to check (the glue falls through to a clean init), so
/// the gate passes.
fn check_hydration_state_fields(ctx: &EmitCtx, program: &Program) -> DResult<()> {
    if !ctx.wasm_hydrate_mode {
        return Ok(());
    }

    // The island parse target is `fromHydrationState`'s parameter type — the
    // same target the emit glue names. No projection ⇒ no island parse ⇒
    // nothing to check.
    let Some(target_ty) = hydration_projection_param_ty(ctx, program) else {
        return Ok(());
    };

    // Resolve the target type to the field types the `hydrate` export will
    // serialise, then reject any non-serde leaf.
    for field_ty in hydration_target_field_types(target_ty, program) {
        if ir_type_contains_non_serde(field_ty, &ctx.enum_variants) {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::check_hydration_state_fields",
                detail: format!(
                    "the hydration-state type has a non-serialisable field type \
                     `{field_ty:?}`. \
                     The hydration state is serialised as JSON in the WASM \
                     hydration island; server-surface types (Db, Secret, \
                     Task, function types, etc.) must not appear as fields. \
                     Declare a separate client-safe type that contains only \
                     the data the client needs."
                ),
            });
        }
    }

    Ok(())
}

/// The `IrType` of the `fromHydrationState` projection's first parameter — the
/// island parse target — or `None` when the program declares no such
/// projection (or one with no parameter). Mirrors the target-selection logic in
/// [`EmitCtx::resolve_hydration_state_rust_name`] so the gate and the emitted
/// glue always agree on which type is the island target.
fn hydration_projection_param_ty<'p>(
    ctx: &EmitCtx,
    program: &'p Program,
) -> Option<&'p ipe_ir::IrType> {
    for module in &program.modules {
        for func in &module.funcs {
            if ctx.interner.resolve(func.name) != Some(ipe_ir::HYDRATION_PROJECTION_NAME) {
                continue;
            }
            return func.params.first().map(|(_, ty)| ty);
        }
    }
    None
}

/// The field types the `hydrate` export serialises for a given island parse
/// target. A user enum/record resolves to its declared fields; any other leaf
/// (a bare `Int`, a `List`, etc.) is itself the single serialised value, so it
/// is returned as one "field" and checked directly. Never panics: an unresolved
/// enum name yields no fields (the emitted code would then fail with a clear
/// `rustc` error, not a silent miscompile).
fn hydration_target_field_types<'p>(
    target_ty: &'p ipe_ir::IrType,
    program: &'p Program,
) -> Vec<&'p ipe_ir::IrType> {
    match target_ty {
        ipe_ir::IrType::Enum { home, name, .. } => {
            let def = program.modules.iter().find_map(|m| {
                m.types.iter().find_map(|td| {
                    let ipe_ir::TypeDef::Enum(def) = td;
                    (def.home == *home && def.name == *name).then_some(def)
                })
            });
            def.map_or_else(Vec::new, |def| {
                def.variants.iter().flat_map(|v| v.fields.iter()).collect()
            })
        }
        ipe_ir::IrType::Record(fields) => fields.values().collect(),
        other => vec![other],
    }
}

/// Render the `Spine` tier's text for `program` — everything that is
/// program-wide rather than Ipê-module-owned (design doc §2.1/§2.3):
/// the preamble banner, the `Spine` bucket's `EnumDef`s (the synthetic
/// `SqlValue`/`SqlField` Db built-ins — §2.2), the synthesised record
/// structs, the DB boundary-projection impls, the fixed kernel-wrapper
/// prelude, the TEA/Auth alias blocks, the epilogue, and `fn main()`.
///
/// Deliberately does NOT emit either module's own `Func`/`EnumDef` — those
/// belong to their [`emit_module_file`] output. The `Spine`-bucket enums are
/// rendered immediately before the record structs, reproducing the ordering
/// rule [`emit_program`] already established (user types then `SqlValue` then
/// `SqlField` then record structs then the DB-projection impls).
///
/// [`emit_program`]'s per-module split branch (2+ distinct `IpeModule`
/// buckets) calls this to render `main.rs`'s Spine tier; the demanded
/// per-file emit path renders it directly and feeds the text to
/// [`assemble_split_manifest`]. It also runs the hydration serde-safety gate
/// ([`check_hydration_state_fields`]) so the demanded path enforces it too —
/// defence in depth alongside `emit_program`'s own up-front call.
///
/// # Errors
///
/// Propagates any [`Diagnostic`] from the reused `preamble`/`emit_enum`/
/// `emit_record_struct`/`emit_db_projection_impls`/`runtime_bindings`/
/// `epilogue` rendering, and the shape-app entry-switch assertion.
pub fn emit_spine(ctx: &EmitCtx, program: &Program) -> DResult<String> {
    check_hydration_state_fields(ctx, program)?;

    // The same one-joiner layout as the single-file path, minus the user
    // functions (they are `emit_module_file`'s).
    let mut file = Items::new();
    file.push(&preamble(ctx.reaches_json())?);

    let Partitioned { buckets, .. } = partition_items(program, ctx.interner);

    // The Spine bucket's `SqlValue`/`SqlField` enums, in insertion order —
    // rendered where the user types would sit in the single-file layout, i.e.
    // immediately before the record structs (§2.2's ordering rule). No
    // `IpeModule` bucket enums are emitted here — those are `emit_module_file`.
    if let Some((spine_enums, _)) = buckets.get(&RustFileId::Spine) {
        for &def in spine_enums {
            file.push(&emit_enum(ctx, def)?);
        }
    }
    for rec in ctx.record_structs() {
        file.push(&emit_record_struct(ctx, rec)?);
    }
    // Per-field witness traits + impls for any row-polymorphic function.
    file.push(&emit_row_witnesses(ctx, program)?);
    if ctx.uses_db {
        file.push(&emit_db_projection_impls(ctx)?);
    }

    file.push(&prelude_section(ctx)?);
    file.push(&epilogue_for_target(ctx)?);
    let mut out = file.render();

    // Shape-app epilogue switch in the spine (Native only).
    //
    // In the split layout `ipe_main` lives in a module file; its return type
    // is already correct from the IR. Only the epilogue's `fn main` body needs
    // updating: swap `block_on(ipe_main())` for `ipe_main().run_blocking()`.
    //
    // The switch fires iff the program's ENTRY function itself RETURNS a shape
    // leaf (`WebApp`/`TuiApp`/`CliApp`; a `WebApp` renders `WebViewApp` under a
    // webview host) — read directly from the IR,
    // NOT from the coarse `uses_web` flag. A `Server.listen [ Server.mountApp
    // (Web.embed { … }) … ]` program sets `uses_web` (it builds an embedded
    // `WebApp` value) yet its `main` returns `IpeTask<()>`; it is a Program
    // (`block_on`), not a shape app. Keying on the entry's return type keeps the
    // two apart (and subsumes the old `CliApp`-has-no-flag special case).
    let main_returns_shape_leaf = program.modules.iter().any(|m| {
        m.entry.is_some_and(|eid| {
            m.funcs.iter().any(|f| {
                f.id == eid && matches!(f.ret, IrType::WebApp | IrType::TuiApp | IrType::CliApp)
            })
        })
    });
    if main_returns_shape_leaf
        && matches!(
            ctx.target,
            ipe_ir::Target::Native | ipe_ir::Target::WasmWasi
        )
    {
        let replaced = out.replacen(SHAPE_APP_BLOCK_ON_ANCHOR, SHAPE_APP_RUN_BLOCKING, 1);
        if replaced == out {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::emit_spine::shape_app_entry_switch",
                detail: format!(
                    "shape-app entry-switch: anchor {SHAPE_APP_BLOCK_ON_ANCHOR:?} not found \
                     in emitted spine — epilogue golden has drifted"
                ),
            });
        }
        out = replaced;
    }

    Ok(out)
}

/// Render the `IpeModule(home)` file's text for one Ipê module's OWN
/// declarations (design doc §2.1): ONLY that `home`'s `EnumDef`s + `Func`s,
/// each `pub(crate)`-visible (not the bare `pub` the single-file layout uses,
/// since these now live inside a `mod` block), opening with the flat-barrel
/// `use crate::*;` glob so every `Spine`/other-module item is in scope.
///
/// A `home` with no items in `program` (never the real driver path — every
/// `IpeModule` file materialises FROM a non-empty bucket) yields just the
/// `use crate::*;` header.
///
/// **This function is NOT on the public emission path** — see [`emit_spine`].
///
/// # Errors
///
/// Propagates any [`Diagnostic`] from the reused `emit_enum`/`emit_func`
/// rendering.
pub fn emit_module_file(ctx: &EmitCtx, program: &Program, home: &RustFileId) -> DResult<String> {
    let Partitioned { buckets, .. } = partition_items(program, ctx.interner);

    let mut file = Items::new();
    // Every module file opens with the flat glob barrel (§2.1): because
    // `main.rs` re-exports every module's items at the crate root and every
    // name is already globally unique, `use crate::*;` gives this file every
    // Spine item and every other module's item with zero per-symbol
    // bookkeeping.
    file.push("use crate::*;");

    if let Some((enums, funcs)) = buckets.get(home) {
        for &def in enums {
            file.push(&pub_crate_item(&emit_enum(ctx, def)?));
        }
        for &func in funcs {
            // `pub(crate) fn ` is emitted directly (not by rewriting a rendered
            // `pub fn `) so the signature's width decision already accounts for the
            // wider prefix — a borderline signature breaks here that would stay flat
            // in the single-file `pub fn ` layout.
            file.push(&crate::emit_expr::emit_func_vis(
                ctx,
                func,
                "pub(crate) fn ",
            )?);
        }
    }

    Ok(file.render())
}

/// The split layout's `main.rs`: `spine` followed by the flat glob barrel, one
/// `#[path]`/`mod`/`use` group per distinct `IpeModule` home in `module_homes`
/// order.
///
/// The `#[path]` attribute is load-bearing: `main.rs` is the crate root, so a
/// BARE `mod ipe_mod_<home>;` would resolve to a crate-root sibling
/// `src/ipe_mod_<home>.rs`, NOT the `src/ipe_mods/<ident>.rs` file this design
/// places (§2.1). `#[path]` is resolved relative to the declaring file's
/// directory (`src/`), so it points the module at the real file under
/// `ipe_mods/` — closing an E0583 "file not found for module"
/// exit-0-then-cargo-fail (THE SEAL) that a bare `mod` decl would ship. Because
/// every user name is already globally unique (§1.3) and this re-exports every
/// module at the crate root, each per-module file's `use crate::*;` sees every
/// Spine item and every other module's item.
fn split_main_rs(ctx: &EmitCtx, spine: &str, module_homes: &[RustFileId]) -> DResult<String> {
    let mut file = Items::new();
    file.push(spine);
    for id in module_homes {
        let RustFileId::IpeModule(home) = id else {
            continue;
        };
        let ident = rust_file::resolve_mod_ident(home, ctx.interner)?;
        file.push(&format!(
            "#[path = \"ipe_mods/{ident}.rs\"]\nmod {ident};\npub(crate) use {ident}::*;"
        ));
    }
    Ok(file.render())
}

/// Assemble the full split [`EmittedProject`] from ALREADY-RENDERED per-file
/// texts (design doc §4.4 — the `emit_manifest` assembly seam).
///
/// `spine_text` is [`emit_spine`]'s output; `module_texts` maps each Ipê-module
/// `home` to its [`emit_module_file`] output. This function performs ONLY the
/// file-count-dependent assembly the single-file [`emit_program`] path also
/// does in its `>= 2` branch — computing the deterministic first-encounter
/// module order, the fail-closed `mod_ident` uniqueness gate, the record-struct
/// disjointness gate, the `main.rs` barrel lines, and the `src/ipe_mods/*.rs`
/// file list — then delegates the file-count-AGNOSTIC manifest/runtime block to
/// the shared [`assemble_project_files`]. It never re-renders any user item;
/// the texts are taken verbatim, so the salsa `emit_manifest` query's output is
/// byte-identical to `emit_program`'s split output for the same program.
///
/// PRECONDITION (`>= 2` distinct `IpeModule` homes): this is the real-split
/// path. The single-home / zero-home collapse case never reaches here —
/// `emit_manifest` routes it straight to `emit_program` for the byte-identical
/// single-`main.rs` output (§4.4).
///
/// # Errors
///
/// Propagates [`Diagnostic`]s from `mod_ident` resolution, the fail-closed
/// duplicate-`mod`/record-struct-collision gates, [`RelPath`] validation, and
/// the shared manifest/runtime assembly.
pub fn assemble_split_manifest(
    ctx: &EmitCtx,
    program: &Program,
    spine_text: &str,
    module_texts: &BTreeMap<ModPath, String>,
) -> DResult<EmittedProject> {
    let partition = partition_items(program, ctx.interner);

    // The distinct `IpeModule` homes in first-encounter (linker/topological)
    // order — the SAME union `emit_program`'s split branch computes, driving
    // both the barrel lines and the per-module file list.
    let mut module_homes: Vec<RustFileId> = Vec::new();
    let mut seen: BTreeSet<RustFileId> = BTreeSet::new();
    for id in partition
        .type_order
        .iter()
        .chain(partition.func_order.iter())
    {
        if seen.insert(id.clone()) {
            module_homes.push(id.clone());
        }
    }

    // Fail closed if two distinct homes fold to the same `mod_ident` before any
    // file is written (same fail-closed gate as `emit_program`'s split branch).
    rust_file::assert_mod_idents_unique(&module_homes, ctx.interner)?;

    // Fail closed if a synthesised record struct's name collides with a
    // `mod_ident` (every IpeModule home contributes its ident in the split).
    let mod_idents: BTreeSet<String> = module_homes
        .iter()
        .filter_map(|id| match id {
            RustFileId::IpeModule(home) => Some(rust_file::resolve_mod_ident(home, ctx.interner)),
            RustFileId::Spine => None,
        })
        .collect::<DResult<BTreeSet<String>>>()?;
    ctx.assert_record_structs_disjoint_from_type_namespace(&mod_idents)?;
    ctx.assert_row_witness_names_disjoint(
        &crate::emit_types::row_witness_field_names(program),
        &mod_idents,
    )?;

    let mut rust_sources: Vec<(RelPath, String)> = Vec::new();

    // `main.rs` = the given spine text + the flat glob barrel (byte-identical
    // to `emit_program`'s split branch: both render through `split_main_rs`).
    let main_rs = split_main_rs(ctx, spine_text, &module_homes)?;
    rust_sources.push((RelPath::new("src/main.rs")?, main_rs));

    // One `src/ipe_mods/<ident>.rs` per module, its text taken verbatim from
    // the demanded per-file query output.
    for id in &module_homes {
        let RustFileId::IpeModule(home) = id else {
            continue;
        };
        let ident = rust_file::resolve_mod_ident(home, ctx.interner)?;
        let text = module_texts
            .get(home)
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::assemble_split_manifest",
                detail: format!(
                    "no rendered text supplied for IpeModule home ident {ident:?} — \
                 emit_manifest must demand emit_rust_file for every home in \
                 program_rust_file_ids"
                ),
            })?;
        rust_sources.push((
            RelPath::new(format!("src/ipe_mods/{ident}.rs"))?,
            text.clone(),
        ));
    }

    assemble_project_files(ctx, rust_sources)
}

/// Narrow a rendered enum's leading `pub ` visibility to `pub(crate) `, for
/// emission inside a `mod` block (design doc §2.1).
///
/// `emit_enum` renders a user enum with a bare `pub ` prefix (a top-level
/// `main.rs` declaration). Inside a per-module `mod` file the crate root
/// re-exports it via a glob barrel, so `pub(crate)` is both sufficient and
/// correct. Functions instead receive their `pub(crate) fn ` prefix directly
/// from [`crate::emit_expr::emit_func_vis`] (so their signature width decision
/// sees the wider prefix), so only the enum declaration keyword is narrowed
/// here. Operates on the FIRST `pub enum ` occurrence only — an enum's trailing
/// `impl … IpeStringify` block carries no `pub`, and the declaration keyword is
/// always at the head (or immediately after a leading `#[derive(...)]` line) —
/// so this narrows exactly that one keyword, never a substring inside a body.
fn pub_crate_item(rendered: &str) -> String {
    if let Some(rest) = rendered.strip_prefix("pub enum ") {
        return format!("pub(crate) enum {rest}");
    }
    // An enum whose derivability gate emitted a `#[derive(...)]` line before
    // `pub enum` — narrow the first `\npub enum ` after that attribute.
    if let Some(pos) = rendered.find("\npub enum ") {
        let mut result = String::with_capacity(rendered.len() + 8);
        result.push_str(rendered.get(..pos + 1).unwrap_or(""));
        result.push_str("pub(crate) enum ");
        result.push_str(rendered.get(pos + 1 + "pub enum ".len()..).unwrap_or(""));
        return result;
    }
    rendered.to_owned()
}

/// Build the db-enabled `Cargo.toml` from the base manifest by:
///
/// 1. Adding `"db"` to the `default` feature list.
/// 2. Appending the `sqlx` dependency line, with BOTH `"sqlite"` AND `"postgres"`
///    ALWAYS enabled, regardless of the configured driver.
///
///    `"sqlite"` is always required: the always-emitted `telemetry_spill` /
///    `web::hub` / `web::store` runtime modules hardcode `SqlitePool` for their
///    local spill/session persistence (independent of the app's `[database]`
///    driver choice).
///
///    `"postgres"` is always required: the always-emitted `external_conn.rs`
///    runtime module uses `sqlx::postgres::PgPool` and `PgPoolOptions`
///    unconditionally (it handles any externally-configured DSN regardless of the
///    app's own fixed driver). Omitting `"postgres"` causes E0433 at `cargo build`
///    even for a sqlite-driver program — an exit-0-then-cargo-fail SEAL violation.
///
/// String surgery rather than a second static file: the manifest content is
/// small and the two edits are unambiguous anchors.
fn db_cargo_toml(base: &str, driver: crate::DbDriver) -> DResult<String> {
    const DEFAULT_LINE: &str = r#"default = ["tokio", "json"]"#;
    // `"secret"` is required alongside `"db"`: the vendored `config.rs` calls
    // `crate::app_config::resolve_db_url_override`, which is gated on
    // `#[cfg(feature = "secret")]`. Activating the feature makes it visible.
    const DEFAULT_LINE_DB: &str = r#"default = ["tokio", "json", "db", "secret"]"#;
    // The sqlx line is appended right before the dev/release profile sections.
    // Anchoring on `[profile.dev]` is stable (always present in the template).
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    // Both `"sqlite"` and `"postgres"` are unconditional — see the doc comment
    // above for why. The `driver` parameter controls which config.rs alias is
    // used (DbPool / DbRow), not which sqlx features link.
    let _ = driver;
    let sqlx_features = r#""sqlite", "postgres""#;
    let sqlx_line = format!(
        "{} = {{ version = \"{}\", features = [\"runtime-tokio-rustls\", {sqlx_features}] }}\n\n",
        crate_specs::SQLX.name,
        crate_specs::SQLX.version,
    );

    let step1 = base.replacen(DEFAULT_LINE, DEFAULT_LINE_DB, 1);
    if step1 == base {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::db_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_LINE:?} not found — golden drifted"),
        });
    }
    let anchor_pos = step1
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::db_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step1.len() + sqlx_line.len());
    result.push_str(step1.get(..anchor_pos).unwrap_or(""));
    result.push_str(&sqlx_line);
    result.push_str(step1.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Add tokio's `"net"` feature to the manifest's `tokio` dependency line.
///
/// The `ssrf` runtime module resolves hosts through `tokio::net::lookup_host`.
/// Idempotent: a line that already lists `"net"` (the server or live surface
/// added it) is returned unchanged.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] when the manifest has no `tokio`
/// dependency line with a feature list — a golden-drift invariant violation.
fn ssrf_cargo_toml(base: &str) -> DResult<String> {
    const NET: &str = "\"net\"";
    let tokio_prefix = format!(
        "{} = {{ version = \"{}\", features = [",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    let bug = || Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::project::ssrf_cargo_toml",
        detail: format!(
            "Cargo.toml anchor {tokio_prefix:?} not found — golden drifted; the ssrf \
             runtime module requires tokio \"net\""
        ),
    };
    let list_start = base
        .find(&tokio_prefix)
        .map(|at| at + tokio_prefix.len())
        .ok_or_else(bug)?;
    let list_end = base
        .get(list_start..)
        .and_then(|rest| rest.find(']'))
        .map(|len| list_start + len)
        .ok_or_else(bug)?;
    if base
        .get(list_start..list_end)
        .ok_or_else(bug)?
        .contains(NET)
    {
        return Ok(base.to_owned());
    }
    let mut out = String::with_capacity(base.len() + NET.len() + 2);
    out.push_str(base.get(..list_end).ok_or_else(bug)?);
    out.push_str(", ");
    out.push_str(NET);
    out.push_str(base.get(list_end..).ok_or_else(bug)?);
    Ok(out)
}

/// Build the server-enabled `Cargo.toml` from the given base manifest by:
///
/// 1. Adding `"server"` to the `default` feature list.
/// 2. Extending the `tokio` dependency line with the `"net"` and `"sync"`
///    features (required by `server.rs`'s `TcpListener` and `mpsc` usage).
/// 3. Appending `axum`, `tower-http` (with `timeout`), and `tower` (with
///    `limit`) dependency lines before `[profile.dev]` — the latter two back
///    the front-door denial-of-service ceilings (`TimeoutLayer` +
///    `GlobalConcurrencyLimitLayer`).
///
/// Takes the current manifest string so it can be composed with
/// [`db_cargo_toml`] when a program uses both Db and Server kernels.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if any anchor string is absent —
/// a golden-drift invariant violation.
fn server_cargo_toml(base: &str) -> DResult<String> {
    // All anchor consts up front — items_after_statements lint requires items
    // to precede any `let` statement in the same scope.
    const DEFAULT_PREFIX: &str = "default = [";
    const DB_FEATURE: &str = "db = []";
    const DB_SERVER_FEATURE: &str = "db = []\nserver = []";
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    // tokio version + name from the SSOT; the two feature-list forms (the
    // replacen anchor and its net+sync successor) share the one version so the
    // anchor and the golden base manifest cannot skew independently.
    let tokio_time = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\"] }}",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    let tokio_net_sync = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\", \"net\", \"sync\"] }}",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    // `tower` (`limit`) backs the front-door concurrency cap
    // (`GlobalConcurrencyLimitLayer`); `tower-http`'s `timeout` backs the
    // per-request slowloris timeout (`TimeoutLayer`). Both are referenced in
    // the vendored `server.rs` non-test code, so the emitted native project
    // must declare them — the `util` feature (`ServiceExt`) is test-only in the
    // runtime crate, so it is omitted here (the vendored module's `#[cfg(test)]`
    // blocks never compile in the app crate build).
    let server_deps = format!(
        "{} = {{ version = \"{}\", features = [\"ws\"] }}\n\
         {} = {{ version = \"{}\", features = [\"fs\", \"catch-panic\", \"timeout\"] }}\n\
         {} = {{ version = \"{}\", features = [\"limit\"] }}\n\n",
        crate_specs::AXUM.name,
        crate_specs::AXUM.version,
        crate_specs::TOWER_HTTP.name,
        crate_specs::TOWER_HTTP.version,
        crate_specs::TOWER.name,
        crate_specs::TOWER.version,
    );

    // Step 1a — insert `"server"` as the LAST element of the `default = [...]`
    // feature list, immediately before its closing `]`.
    //
    // This generic anchor handles every composition:
    //   non-db:  `default = ["tokio", "crypto", "json"]`
    //            → `default = ["tokio", "crypto", "json", "server"]`
    //   db:      `default = ["tokio", "json", "db", "secret"]`
    //            → `default = ["tokio", "json", "db", "secret", "server"]`
    //   any future feature:  likewise, without needing a new anchor string.
    //
    // Fail-closed: if the prefix or the closing `]` is absent the manifest
    // has drifted from the golden and we surface a CompilerBug rather than
    // silently emitting an invalid manifest.
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::server_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::server_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let mut step1a = String::with_capacity(base.len() + 12);
    step1a.push_str(base.get(..close).unwrap_or(""));
    step1a.push_str(r#", "server""#);
    step1a.push_str(base.get(close..).unwrap_or(""));

    // Step 1b — define the `server = []` feature flag so that "server" in
    // `default = [...]` refers to a declared feature rather than an undeclared
    // name (Cargo rejects an undeclared feature reference with E0015).
    // Anchor on the `db = []` line which is always present in the base manifest.
    let step1 = step1a.replacen(DB_FEATURE, DB_SERVER_FEATURE, 1);
    if step1 == step1a {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::server_cargo_toml",
            detail: format!("Cargo.toml anchor {DB_FEATURE:?} not found — golden drifted"),
        });
    }

    // Step 2 — extend the tokio dependency line with "net" and "sync".
    let step2 = step1.replacen(&tokio_time, &tokio_net_sync, 1);
    if step2 == step1 {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::server_cargo_toml",
            detail: format!("Cargo.toml anchor {tokio_time:?} not found — golden drifted"),
        });
    }

    // Step 3 — append axum + tower-http before `[profile.dev]`.
    let anchor_pos = step2
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::server_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step2.len() + server_deps.len());
    result.push_str(step2.get(..anchor_pos).unwrap_or(""));
    result.push_str(&server_deps);
    result.push_str(step2.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the web-enabled `Cargo.toml` from the given base manifest by:
///
/// 1. Adding `"web"` to the `default` feature list.
/// 2. Inserting `async-trait` and `serde_urlencoded` as explicit dependencies
///    before the `[profile.dev]` section.
///
/// These two crates are required because the runtime's `web` feature enables
/// code that imports them (`async-trait` in `web/store.rs` and
/// `serde_urlencoded` in `web/form.rs`).  The emitted project vendors the
/// runtime source directly, so these must appear as explicit `[dependencies]`
/// in the emitted manifest.
///
/// The base manifest already declares `web = []` as a non-default feature
/// (present in the golden's `[features]` section).  This function promotes
/// it by inserting `"web"` immediately before the closing `]` of the
/// `default = [...]` line — the same generic anchor used by `server_cargo_toml`.
///
/// Called AFTER `server_cargo_toml` when both flags are set, so it is composed
/// on top of a manifest that may already contain `"server"` in `default`.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if any anchor is absent — a
/// golden-drift invariant violation.
fn web_cargo_toml(base: &str) -> DResult<String> {
    // All consts must precede the first `let` — `items_after_statements` (pedantic).
    const DEFAULT_PREFIX: &str = "default = [";
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    // `async-trait` is pulled by the runtime's `live` feature gate; the emitted
    // project vendors the runtime source directly, so it must appear as an
    // explicit `[dependencies]` entry.
    // `rustix` is NOT added here: the base manifest already declares it
    // unconditionally under `[target.'cfg(unix)'.dependencies]` (termios, pty, and
    // the parent-death floor the live console-proxy relies on), so that single
    // cfg-gated declaration covers every need — adding it again would emit a
    // duplicate `rustix` key and produce invalid TOML.
    // The `live` runtime mainline uses `tokio::signal` + `tokio::process`; the base
    // golden emits `net`+`sync` for the HTTP server, so add the two missing features.
    const TOKIO_NET_SYNC_FEATURES: &str = "\"time\", \"net\", \"sync\"]";
    const TOKIO_LIVE_FEATURES: &str = "\"time\", \"net\", \"sync\", \"signal\", \"process\"]";
    // `db_cargo_toml` now always emits both `"sqlite"` and `"postgres"` sqlx
    // features (since `external_conn.rs` uses `sqlx::postgres` unconditionally).
    // The replacen below is kept as a safety net for Db+Web combinations but is a
    // no-op in practice — `SQLX_SQLITE_FEATURES` no longer appears in the manifest
    // after `db_cargo_toml` runs. Fail-open (no CompilerBug guard) applies in both
    // the no-Db case (sqlx absent) and the always-both case (pattern not found).
    const SQLX_SQLITE_FEATURES: &str = "features = [\"runtime-tokio-rustls\", \"sqlite\"]";
    const SQLX_POSTGRES_FEATURES: &str =
        "features = [\"runtime-tokio-rustls\", \"sqlite\", \"postgres\"]";
    // Versions + names from the SSOT; this is a bare `name = "ver"` dep.
    // `serde_urlencoded` is NOT appended here: it is an unconditional base
    // manifest dep now (`dom/form.rs` is always vendored). `rustix` is NOT
    // appended either — see the note above.
    let web_deps = format!(
        "{} = \"{}\"\n\n",
        crate_specs::ASYNC_TRAIT.name,
        crate_specs::ASYNC_TRAIT.version,
    );

    // Step 1 — promote the `live` feature.
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::web_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::web_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let mut step1 = String::with_capacity(base.len() + 64);
    step1.push_str(base.get(..close).unwrap_or(""));
    step1.push_str(r#", "web""#);
    step1.push_str(base.get(close..).unwrap_or(""));

    // Step 1b — add the tokio `signal` + `process` features the live runtime needs.
    // Fail loud (like the sibling anchors) if the anchor drifted — a silent no-op
    // here would ship a manifest without `signal`/`process` and cargo-fail on the
    // live runtime's `tokio::signal` usage (a fresh exit-0-then-cargo-fail).
    let step1_tokio = step1.replace(TOKIO_NET_SYNC_FEATURES, TOKIO_LIVE_FEATURES);
    if step1_tokio == step1 {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::web_cargo_toml",
            detail: format!(
                "tokio features anchor {TOKIO_NET_SYNC_FEATURES:?} not found — golden drifted; \
                 the live runtime requires the tokio signal + process features"
            ),
        });
    }
    let step1 = step1_tokio;

    // Step 2 — inject live-specific deps before `[profile.dev]`.
    let anchor_pos = step1
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::web_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step1.len() + web_deps.len());
    result.push_str(step1.get(..anchor_pos).unwrap_or(""));
    result.push_str(&web_deps);
    result.push_str(step1.get(anchor_pos..).unwrap_or(""));

    // Step 3 — extend the sqlx dep with the `postgres` feature when the
    // program also uses Db (db_cargo_toml ran before web_cargo_toml and
    // injected the sqlite-only sqlx dep; we promote it here so the live
    // session-store's `PostgresStore` — which references `sqlx::PgPool` — can
    // compile).  No-op when sqlx is absent (Web-only, no Db).
    let result = result.replacen(SQLX_SQLITE_FEATURES, SQLX_POSTGRES_FEATURES, 1);
    Ok(result)
}

/// Build the tui-enabled `Cargo.toml` from the given base manifest by:
///
/// 1. Adding `"tui"` to the `default` feature list.
/// 2. Adding `"sync"` to the `tokio` dependency's feature list (`tui/app.rs`
///    uses `tokio::sync::mpsc::unbounded_channel`).
/// 3. Appending `crossterm` and `unicode-width` dependencies before
///    `[profile.dev]`.  These two crates are the compile-time gates on the
///    runtime's `tui` feature; the emitted project vendors the runtime source
///    directly, so they MUST appear as explicit `[dependencies]` entries.
///
/// Called AFTER any server/live manifest extension so it composes on top of an
/// already-modified manifest.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if any anchor string is absent — a
/// golden-drift invariant violation (fail-loud, never a silent no-op that
/// ships a broken manifest).
fn tui_cargo_toml(base: &str) -> DResult<String> {
    // All anchor consts must precede the first `let` statement.
    const DEFAULT_PREFIX: &str = "default = [";
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    // Versions + names from the SSOT. `tui_deps` are bare `name = "ver"` lines;
    // the two tokio forms (the replacen anchor and its sync successor) share the
    // one SSOT version so the anchor cannot skew from the golden base manifest.
    //
    // The tui runtime uses `tokio::sync::mpsc`; add `"sync"` when it is not
    // yet present.  The base golden has only `"time"` in the tokio feature list;
    // server_cargo_toml adds `"net", "sync"`; web_cargo_toml extends to include
    // `"signal", "process"`.  We gate on the SMALLEST known form that lacks
    // `"sync"` and replace it with the tui-extended form.  If `"sync"` is
    // already present (because server_cargo_toml ran first) the replacen is a
    // no-op and we do NOT error — `"sync"` is idempotent to add.
    //
    // Three anchors: non-server base, server-only (no live), live (superset).
    // We check for the presence of `"sync"` and insert it only if absent.
    let tui_deps = format!(
        "{} = \"{}\"\n{} = \"{}\"\n\n",
        crate_specs::CROSSTERM.name,
        crate_specs::CROSSTERM.version,
        crate_specs::UNICODE_WIDTH.name,
        crate_specs::UNICODE_WIDTH.version,
    );
    let tokio_time_only = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\"] }}",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    let tokio_time_sync = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\", \"sync\"] }}",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );

    // Step 1 — promote the `tui` feature (generic closing-`]` anchor, same
    // strategy as server_cargo_toml / web_cargo_toml).
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::tui_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::tui_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let mut step1 = String::with_capacity(base.len() + 64);
    step1.push_str(base.get(..close).unwrap_or(""));
    step1.push_str(r#", "tui""#);
    step1.push_str(base.get(close..).unwrap_or(""));

    // Step 2 — add `"sync"` to tokio if not already present.
    // If the manifest already has `"sync"` (from server_cargo_toml or
    // web_cargo_toml) the `contains` check short-circuits and no change is
    // made.  Only when the base tokio line lacks `"sync"` do we replace the
    // known-anchor form (non-server base) with the sync-extended form.
    let step2 = if step1.contains(r#""sync""#) {
        // `"sync"` already present — idempotent, no change needed.
        step1
    } else {
        // The only tokio line that can lack `"sync"` on a valid manifest is
        // the non-server, non-live base form.  Fail-loud if the anchor drifted.
        let replaced = step1.replacen(&tokio_time_only, &tokio_time_sync, 1);
        if replaced == step1 {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::tui_cargo_toml",
                detail: format!(
                    "tokio anchor {tokio_time_only:?} not found and no \"sync\" present — \
                     golden drifted; tui runtime requires tokio sync"
                ),
            });
        }
        replaced
    };

    // Step 3 — append crossterm + unicode-width before `[profile.dev]`.
    let anchor_pos = step2
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::tui_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step2.len() + tui_deps.len());
    result.push_str(step2.get(..anchor_pos).unwrap_or(""));
    result.push_str(&tui_deps);
    result.push_str(step2.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the webview-enabled `Cargo.toml` from the given base manifest by:
///
/// 1. Adding `"webview"` to the `default` feature list.
/// 2. Wiring the `webview = []` feature declaration to actually pull `wry` and
///    `tao` (changes it to `webview = ["dep:wry", "dep:tao"]`).
/// 3. Appending `wry` and `tao` as optional dependencies before `[profile.dev]`.
///
/// Called AFTER `server_cargo_toml` and `web_cargo_toml` so the live feature
/// (which the webview backend imports from) is already promoted.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if any anchor string is absent — a
/// golden-drift invariant violation (fail-loud, never a silent no-op that
/// ships a broken manifest or links the wrong backend).
fn webview_cargo_toml(base: &str) -> DResult<String> {
    // All anchor consts must precede the first `let` statement.
    const DEFAULT_PREFIX: &str = "default = [";
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    // Change the empty `webview = []` feature to pull wry + tao when active.
    // The `dep:` prefix is Cargo's "explicit dep" syntax (Cargo ≥1.60), so
    // `webview = ["dep:wry", "dep:tao"]` activates the optional deps ONLY when
    // the `webview` feature is in the default list — the stub path gets no
    // heavy system deps.
    const WEBVIEW_EMPTY: &str = "webview = []";
    const WEBVIEW_WITH_DEPS: &str = r#"webview = ["dep:wry", "dep:tao"]"#;
    // wry + tao are declared optional so the stub path (no `webview` feature)
    // never downloads or links them. Versions + names from the SSOT; the
    // `optional = true` gate stays inline.
    let webview_native_deps = format!(
        "{} = {{ version = \"{}\", optional = true }}\n{} = {{ version = \"{}\", optional = true }}\n\n",
        crate_specs::WRY.name,
        crate_specs::WRY.version,
        crate_specs::TAO.name,
        crate_specs::TAO.version,
    );

    // Step 1 — promote `webview` to the default feature list (generic
    // closing-`]` anchor, same strategy as server/live/tui_cargo_toml).
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::webview_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::webview_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let mut step1 = String::with_capacity(base.len() + 64);
    step1.push_str(base.get(..close).unwrap_or(""));
    // Promote the server-free render core (`web-core`) alongside `webview`: the
    // native backend renders through `crate::dom` + `style_inject` + `page_shell`
    // (all `#[cfg(feature = "web-core")]` in the vendored source) over a local IPC
    // bridge, with NO axum `server` and NO `web` surface. This is the vendored
    // counterpart of the dep-model, where the runtime crate's own `webview`
    // feature pulls `web-core`.
    step1.push_str(r#", "web-core", "webview""#);
    step1.push_str(base.get(close..).unwrap_or(""));

    // Step 2 — wire the `webview` feature to its deps (`dep:wry` + `dep:tao`).
    // Fail-loud if the empty anchor drifted — a silent no-op here would promote
    // `webview` to defaults without pulling wry/tao, shipping a build where the
    // real backend compiles as stub (exit-0-then-runtime-Err).
    let step2 = step1.replacen(WEBVIEW_EMPTY, WEBVIEW_WITH_DEPS, 1);
    if step2 == step1 {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::webview_cargo_toml",
            detail: format!(
                "Cargo.toml anchor {WEBVIEW_EMPTY:?} not found — golden drifted; \
                 the webview feature declaration must be present to wire wry + tao"
            ),
        });
    }

    // Step 3 — append wry + tao as optional deps before `[profile.dev]`.
    let anchor_pos = step2
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::webview_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step2.len() + webview_native_deps.len());
    result.push_str(step2.get(..anchor_pos).unwrap_or(""));
    result.push_str(&webview_native_deps);
    result.push_str(step2.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the websocket-client-enabled `Cargo.toml` from the given base manifest
/// by:
///
/// 1. Adding `"websocket_client"` to the `default` feature list — the empty
///    `websocket_client = []` feature is a pure `#[cfg]` gate over `ws_client.rs`
///    (its deps are plain, not `dep:`-activated, so promoting it activates the
///    module without any feature→dep wiring).
/// 2. Adding `"sync"` to tokio (the `ws_client` writer/reader tasks use
///    `tokio::sync::mpsc` / `broadcast`) when not already present — idempotent,
///    same strategy as `tui_cargo_toml`.
/// 3. Appending `tokio-tungstenite` as a plain dependency before `[profile.dev]`
///    (`futures-util` and `url`, its other deps, are already in the base).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if any anchor string is absent — a
/// golden-drift invariant violation (fail-loud, never a silent no-op that ships
/// a manifest where `ws_client` compiles without `tokio-tungstenite`).
fn websocket_cargo_toml(base: &str) -> DResult<String> {
    const DEFAULT_PREFIX: &str = "default = [";
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    let tokio_time_only = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\"] }}",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    let tokio_time_sync = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\", \"sync\"] }}",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    let ws_dep = format!(
        "{} = \"{}\"\n",
        crate_specs::TOKIO_TUNGSTENITE.name,
        crate_specs::TOKIO_TUNGSTENITE.version,
    );

    // Step 1 — promote `websocket_client` to the default feature list.
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::websocket_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::websocket_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let mut step1 = String::with_capacity(base.len() + 64);
    step1.push_str(base.get(..close).unwrap_or(""));
    step1.push_str(r#", "websocket_client""#);
    step1.push_str(base.get(close..).unwrap_or(""));

    // Step 2 — add `"sync"` to tokio if not already present (idempotent when a
    // prior server/live/tui surgery already added it).
    let step2 = if step1.contains(r#""sync""#) {
        step1
    } else {
        let replaced = step1.replacen(&tokio_time_only, &tokio_time_sync, 1);
        if replaced == step1 {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::project::websocket_cargo_toml",
                detail: format!(
                    "tokio anchor {tokio_time_only:?} not found and no \"sync\" present — \
                     golden drifted; the ws_client runtime requires tokio sync"
                ),
            });
        }
        replaced
    };

    // Step 3 — append tokio-tungstenite before `[profile.dev]`.
    let anchor_pos = step2
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::websocket_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step2.len() + ws_dep.len());
    result.push_str(step2.get(..anchor_pos).unwrap_or(""));
    result.push_str(&ws_dep);
    result.push_str(step2.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Add the tokio `"sync"` feature for a program that uses TEA kernels.
///
/// `tea.rs` (the vendored `Cmd` / `Sub` / console-app runtime, always compiled
/// on native when the program uses TEA) drives its event loop over a
/// `tokio::sync::mpsc` channel, so it needs tokio's `"sync"` feature. The base
/// manifest's tokio line does not list it (the async floor is `rt` + `time`),
/// so it is added here. Idempotent: server / web / tui / websocket manifests
/// already carry `"sync"`, and the `contains` check short-circuits so composing
/// this with any of them makes no second change.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if `"sync"` is absent AND the base tokio
/// feature-line anchor drifted — a fail-loud golden-drift signal.
fn tea_cargo_toml(base: &str) -> DResult<String> {
    if base.contains(r#""sync""#) {
        return Ok(base.to_owned());
    }
    let tokio_time_only = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\"] }}",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    let tokio_time_sync = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\", \"sync\"] }}",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    let replaced = base.replacen(&tokio_time_only, &tokio_time_sync, 1);
    if replaced == base {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::tea_cargo_toml",
            detail: format!(
                "tokio anchor {tokio_time_only:?} not found and no \"sync\" present — \
                 golden drifted; the TEA runtime requires tokio sync"
            ),
        });
    }
    Ok(replaced)
}

/// Build the HTTP-client-enabled `Cargo.toml` by adding the `reqwest`
/// dependency to the main `[dependencies]` table.
///
/// `reqwest` is the sole owner of the outbound HTTP stack (~60 transitive
/// crates). It is pulled in only when the program reaches the `http_client`
/// runtime module — a client kernel, or a surface (server / web / webview /
/// email) whose own runtime module calls into `http_client`. The `url` crate
/// stays unconditional (it backs the always-present `Ipe.Url` and `ssrf`
/// surfaces), so only reqwest is gated here.
///
/// The dependency line is inserted before the
/// `[target.'cfg(unix)'.dependencies]` header so it lands in the cross-platform
/// `[dependencies]` table — `reqwest` must compile on every target, not only
/// unix. Its feature list + `default-features = false` mirror
/// `runtime/Cargo.toml` (the vendored source was tested against exactly that
/// shape); the version comes from the [`crate_specs`] SSOT (drift-guarded
/// against `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `[dependencies]`-table boundary
/// anchor is absent — a golden-drift invariant violation (fail-loud).
fn http_client_cargo_toml(base: &str) -> DResult<String> {
    // Insert before the unix-only dependency table (and its leading comment) so
    // `reqwest` joins the main, cross-platform `[dependencies]` table — never
    // the `cfg(unix)` one — and the unix comment stays attached to its header.
    const DEPS_END_ANCHOR: &str = "\n\n# Unix-only:";
    let reqwest_dep = format!(
        "\n{} = {{ version = \"{}\", default-features = false, \
         features = [\"rustls-tls\", \"gzip\", \"stream\"] }}",
        crate_specs::REQWEST.name,
        crate_specs::REQWEST.version,
    );
    let anchor_pos = base
        .find(DEPS_END_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::http_client_cargo_toml",
            detail: format!("Cargo.toml anchor {DEPS_END_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(base.len() + reqwest_dep.len());
    result.push_str(base.get(..anchor_pos).unwrap_or(""));
    result.push_str(&reqwest_dep);
    result.push_str(base.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the time-enabled `Cargo.toml` by promoting the `time` feature into the
/// `default` list and re-injecting the `chrono-tz` dependency in its original
/// slot (immediately after the base `chrono` line).
///
/// The `time` runtime module is ALWAYS declared, but its IANA-zone calendar
/// helpers (the sole consumers of `chrono-tz`) are gated behind the `time` Cargo
/// feature. A program that reaches an `Ipe.Time` kernel promotes the feature and
/// gets the crate back; a program that uses no `Ipe.Time` kernel keeps the base
/// manifest — no `time` in `default`, no `chrono-tz` line — so the helpers
/// compile out and the crate is dropped. `chrono` core (the base crate the
/// `log`/`db`/`web`/`telemetry` timestamp surfaces reach) is gated separately
/// by `time-core`/`log` and untouched here.
///
/// The dep is re-inserted exactly where the base template declared it (after
/// `chrono = "=0.4.45"`) so a Time-using manifest is byte-identical to the
/// pre-gating output. Composes with any prior default-list surgery (`["json"]`,
/// `["tokio", "json"]`, or the wasm `["wasm-client"]`): the `"time"` element is
/// appended before the closing `]` regardless of the list's contents. The
/// version comes from the [`crate_specs`] SSOT (drift-guarded against
/// `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `default = [` / `chrono = "=0.4.45"`
/// anchors are absent — a golden-drift invariant violation (fail-loud, never a
/// silent no-op).
fn chrono_tz_cargo_toml(base: &str) -> DResult<String> {
    const DEFAULT_PREFIX: &str = "default = [";
    const CHRONO_ANCHOR: &str = "chrono = \"=0.4.45\"\n";

    // Step 1 — promote `time` into the default feature list.
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::chrono_tz_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::chrono_tz_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let mut step1 = String::with_capacity(base.len() + 40);
    step1.push_str(base.get(..close).unwrap_or(""));
    step1.push_str(r#", "time""#);
    step1.push_str(base.get(close..).unwrap_or(""));

    // Step 2 — re-inject `chrono-tz` in its original slot (after `chrono`).
    let chrono_tz_dep = format!(
        "{} = \"{}\"\n",
        crate_specs::CHRONO_TZ.name,
        crate_specs::CHRONO_TZ.version,
    );
    let anchor_pos = step1
        .find(CHRONO_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::chrono_tz_cargo_toml",
            detail: format!("Cargo.toml anchor {CHRONO_ANCHOR:?} not found — golden drifted"),
        })?;
    let insert_at = anchor_pos + CHRONO_ANCHOR.len();
    let mut result = String::with_capacity(step1.len() + chrono_tz_dep.len());
    result.push_str(step1.get(..insert_at).unwrap_or(""));
    result.push_str(&chrono_tz_dep);
    result.push_str(step1.get(insert_at..).unwrap_or(""));
    Ok(result)
}

/// Build the email-enabled `Cargo.toml` by appending the `lettre` dependency
/// before `[profile.dev]`.
///
/// `email.rs` (the vendored `Ipe.Email` runtime module) needs `lettre` for the
/// SMTP transport; `reqwest` (which it reaches through `http_client`) is added
/// by [`http_client_cargo_toml`] under the shared HTTP-client predicate, and
/// every other crate it uses (`base64` / `hmac` / `sha2` / `serde_json` /
/// `url`) is already an unconditional base-manifest dependency. No feature
/// promotion is required — the emitted crate declares the
/// `email` module unconditionally (via the `mod.rs` append), so the module is
/// always compiled once its one extra dep is present. `lettre`'s feature list +
/// `default-features = false` mirror `runtime/Cargo.toml` (the vendored source
/// was tested against exactly that shape). The version comes from the
/// [`crate_specs`] SSOT (drift-guarded against `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `[profile.dev]` anchor is absent —
/// a golden-drift invariant violation (fail-loud, never a silent no-op).
fn email_cargo_toml(base: &str) -> DResult<String> {
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    let lettre_dep = format!(
        "{} = {{ version = \"{}\", default-features = false, features = [\"builder\", \
         \"hostname\", \"smtp-transport\", \"pool\", \"tokio1\", \"tokio1-rustls-tls\"] }}\n\n",
        crate_specs::LETTRE.name,
        crate_specs::LETTRE.version,
    );
    let anchor_pos = base
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::email_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(base.len() + lettre_dep.len());
    result.push_str(base.get(..anchor_pos).unwrap_or(""));
    result.push_str(&lettre_dep);
    result.push_str(base.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the locale-enabled vendored `Cargo.toml`.
///
/// Three mutations are needed (dep model uses the `locale` runtime feature
/// instead, so this path applies only to the vendored fallback):
///
/// 1. Add `locale = ["dep:icu_casemap", "dep:icu_locale_core"]` to `[features]`
///    so that `locale.rs`'s `#[cfg(feature = "locale")]` paths compile.
/// 2. Promote `locale` into the `default` feature list so the emitted crate
///    activates it without requiring an explicit `--features locale` flag.
/// 3. Add `icu_casemap` and `icu_locale_core` as optional dependencies before
///    `[profile.dev]`.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if any expected anchor is absent — a
/// golden-drift invariant violation (fail-loud, never a silent no-op).
fn locale_cargo_toml(base: &str) -> DResult<String> {
    const DEFAULT_PREFIX: &str = "default = [";
    const FEATURES_ANCHOR: &str = "[features]";
    const PROFILE_ANCHOR: &str = "[profile.dev]";

    let icu_deps = format!(
        "{} = {{ version = \"{}\", optional = true }}\n\
         {} = {{ version = \"{}\", optional = true }}\n\n",
        crate_specs::ICU_CASEMAP.name,
        crate_specs::ICU_CASEMAP.version,
        crate_specs::ICU_LOCALE_CORE.name,
        crate_specs::ICU_LOCALE_CORE.version,
    );

    // Step 1 — promote `locale` into the `default = [...]` list.
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::locale_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::locale_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let mut step1 = String::with_capacity(base.len() + 128);
    step1.push_str(base.get(..close).unwrap_or(""));
    step1.push_str(r#", "locale""#);
    step1.push_str(base.get(close..).unwrap_or(""));

    // Step 2 — add the `locale` feature entry after `[features]`.
    let locale_feature = "locale = [\"dep:icu_casemap\", \"dep:icu_locale_core\"]\n";
    let features_pos = step1
        .find(FEATURES_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::locale_cargo_toml",
            detail: format!("Cargo.toml anchor {FEATURES_ANCHOR:?} not found — golden drifted"),
        })?;
    let after_features = features_pos + FEATURES_ANCHOR.len();
    // Insert the feature declaration right after the `[features]` header line.
    let newline_pos = step1
        .get(after_features..)
        .and_then(|s| s.find('\n'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::locale_cargo_toml",
            detail: "no newline after [features] — golden drifted".to_owned(),
        })?;
    let insert_at = after_features + newline_pos + 1;
    let mut step2 = String::with_capacity(step1.len() + locale_feature.len());
    step2.push_str(step1.get(..insert_at).unwrap_or(""));
    step2.push_str(locale_feature);
    step2.push_str(step1.get(insert_at..).unwrap_or(""));

    // Step 3 — add the optional ICU4X deps before `[profile.dev]`.
    let anchor_pos = step2
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::locale_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step2.len() + icu_deps.len());
    result.push_str(step2.get(..anchor_pos).unwrap_or(""));
    result.push_str(&icu_deps);
    result.push_str(step2.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the URL-enabled `Cargo.toml` by appending the `url` dependency before
/// `[profile.dev]`.
///
/// `url.rs` (the vendored `Ipe.Url` runtime module) parses with the `url` crate,
/// whose transitive `idna` → ICU4X subtree is the single largest gateable
/// dependency root. The crate is added only when the emitted crate reaches the
/// `url` module — an `Ipe.Url` kernel, or a surface (HTTP client / WebSocket
/// client, and the shared `ssrf` validators they pull) whose own runtime module
/// parses with `url` (see [`EmitCtx::reaches_url`]). A pure-CLI program pulls
/// neither the crate nor its subtree. The version comes from the [`crate_specs`]
/// SSOT (drift-guarded against `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `[profile.dev]` anchor is absent —
/// a golden-drift invariant violation (fail-loud, never a silent no-op).
fn url_cargo_toml(base: &str) -> DResult<String> {
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    // `tinyvec` is a transitive dep of `idna` (pulled by `url 2.x`). Version
    // 1.13+ uses `vec!` in a way that requires the `std` feature; without it
    // the emitted project's `cargo build` fails with "cannot find macro `vec`
    // in this scope". Declaring it here forces the feature on via cargo's
    // feature-unification for every vendored emitted project that reaches url.
    let url_dep = format!(
        "{} = \"{}\"\ntinyvec = {{ version = \"1\", features = [\"std\"] }}\n\n",
        crate_specs::URL.name,
        crate_specs::URL.version,
    );
    let anchor_pos = base
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::url_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(base.len() + url_dep.len());
    result.push_str(base.get(..anchor_pos).unwrap_or(""));
    result.push_str(&url_dep);
    result.push_str(base.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the config-decoder-enabled `Cargo.toml` by appending the `toml` and
/// `serde_yaml` dependencies before `[profile.dev]`.
///
/// `config_decode.rs` (the vendored `Ipe.Config` TOML/YAML front-ends) is the
/// sole consumer of these two crates: `Config.decodeToml` parses with `toml`,
/// `Config.decodeYaml` with `serde_yaml`, and `Config.loadFromFile` dispatches
/// to either by file extension. Both are leaf dependencies (nothing else in the
/// base manifest pulls them), so gating them here keeps a program that never
/// touches the TOML/YAML surface — including a JSON-only `Config` program, whose
/// combinators emit into the `json` module — free of both crates.
///
/// The versions come from the [`crate_specs`] SSOT (drift-guarded against
/// `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `[profile.dev]` anchor is absent —
/// a golden-drift invariant violation (fail-loud, never a silent no-op).
fn config_cargo_toml(base: &str) -> DResult<String> {
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    let deps = format!(
        "{} = \"{}\"\n{} = \"{}\"\n\n",
        crate_specs::TOML.name,
        crate_specs::TOML.version,
        crate_specs::SERDE_YAML.name,
        crate_specs::SERDE_YAML.version,
    );
    let anchor_pos = base
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::config_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(base.len() + deps.len());
    result.push_str(base.get(..anchor_pos).unwrap_or(""));
    result.push_str(&deps);
    result.push_str(base.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the compression-enabled `Cargo.toml` by appending the `flate2` and
/// `zstd` dependencies before `[profile.dev]`.
///
/// `compression.rs` (the vendored `Ipe.Compression` gzip/zstd kernels) is the
/// sole consumer of these two crates: `Compression.gzip` / `gunzip` go through
/// `flate2`, `Compression.zstdCompress` / `zstdDecompress` through `zstd`. Both
/// are leaf dependencies (nothing else in the base manifest pulls them), so
/// gating them here keeps a program that never compresses free of both crates.
///
/// The versions come from the [`crate_specs`] SSOT (drift-guarded against
/// `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `[profile.dev]` anchor is absent —
/// a golden-drift invariant violation (fail-loud, never a silent no-op).
fn compression_cargo_toml(base: &str) -> DResult<String> {
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    let deps = format!(
        "{} = \"{}\"\n{} = \"{}\"\n\n",
        crate_specs::FLATE2.name,
        crate_specs::FLATE2.version,
        crate_specs::ZSTD.name,
        crate_specs::ZSTD.version,
    );
    let anchor_pos = base
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::compression_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(base.len() + deps.len());
    result.push_str(base.get(..anchor_pos).unwrap_or(""));
    result.push_str(&deps);
    result.push_str(base.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the CSV-enabled `Cargo.toml` by appending the `csv` dependency before
/// `[profile.dev]`.
///
/// `csv.rs` (the vendored `Ipe.Csv` parse/encode kernels plus the `CsvDoc`
/// struct) is the sole consumer of the `csv` crate. It is a leaf dependency
/// (nothing else in the base manifest pulls it), so gating it here keeps a
/// program that never parses CSV free of the crate.
///
/// The version comes from the [`crate_specs`] SSOT (drift-guarded against
/// `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `[profile.dev]` anchor is absent —
/// a golden-drift invariant violation (fail-loud, never a silent no-op).
fn csv_cargo_toml(base: &str) -> DResult<String> {
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    let deps = format!(
        "{} = \"{}\"\n\n",
        crate_specs::CSV.name,
        crate_specs::CSV.version,
    );
    let anchor_pos = base
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::csv_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(base.len() + deps.len());
    result.push_str(base.get(..anchor_pos).unwrap_or(""));
    result.push_str(&deps);
    result.push_str(base.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the heavy-`crypto_core`-enabled `Cargo.toml` by enabling the `crypto`
/// feature and declaring the `rsa` dependency (a ~34-crate subtree).
///
/// The RSA SHA-256 sign/verify pair in `crypto_core.rs` is
/// `cfg(feature = "crypto")`; `jwt.rs`'s RS256 path calls it, and `auth.rs`
/// reaches `jwt`. A program that reaches none of those (a `Crypto` kernel, a
/// `Jwt` kernel, or the `Auth` surface — see [`EmitCtx::reaches_crypto_core_heavy`])
/// keeps the `crypto` feature off, so the RSA arm never compiles and `rsa` never
/// links. The floor primitives that a non-crypto program still needs — the
/// entropy pair, the SHA-2 / HMAC family, the constant-time compare, the
/// `Key`/`Mac` newtypes — are not `cfg`-gated and stay unconditional.
///
/// Two edits, both fail-closed on a missing anchor:
/// 1. insert `"crypto"` into the `default = [...]` feature list (the `crypto = []`
///    flag is already declared in the base `[features]` table). When the program
///    also reaches the async runtime the list opens with `"tokio"`, and `"crypto"`
///    lands right after it to keep the pre-gating `["tokio", "crypto", "json", …]`
///    order byte-identical; a crypto-using program with no reactor kernel is
///    emitted synchronously (no `"tokio"`), so `"crypto"` is inserted at the head
///    of the `["json"]` list instead.
/// 2. restore the `rsa` dependency in its original slot (immediately after the
///    `zeroize` base dep), so a crypto-using program's manifest is byte-for-byte
///    what it was before `rsa` became conditional.
///
/// The version comes from the [`crate_specs`] SSOT (drift-guarded against
/// `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if neither the async (`default = ["tokio"`)
/// nor the synchronous (`default = ["json"]`) default-list anchor is present, or
/// the `zeroize` dependency anchor is absent — a golden-drift invariant violation
/// (fail-loud, never a silent no-op).
fn crypto_core_heavy_cargo_toml(base: &str) -> DResult<String> {
    // Anchor on the first default element so `"crypto"` lands in its original
    // slot (`["tokio", "crypto", "json"]`), keeping crypto-program manifests
    // byte-identical.
    const TOKIO_ANCHOR: &str = r#"default = ["tokio""#;
    // The synchronous default-list anchors: a crypto-using program that reaches
    // no async reactor kernel is emitted with no `"tokio"` in the default list,
    // so `"crypto"` is inserted into the `["json"]` form instead.
    const SYNC_DEFAULT: &str = r#"default = ["json"]"#;
    const SYNC_DEFAULT_CRYPTO: &str = r#"default = ["crypto", "json"]"#;
    // Anchor the `rsa` line to the `zeroize` base dep it originally followed, so
    // its slot in `[dependencies]` is unchanged for a crypto-using program.
    const ZEROIZE_ANCHOR: &str = "zeroize = \"1\"\n";
    let rsa_dep = format!(
        "{} = {{ version = \"{}\", features = [\"sha2\"] }}\n",
        crate_specs::RSA.name,
        crate_specs::RSA.version,
    );

    // Step 1 — insert `"crypto"` into the default feature list. Anchor on
    // `"tokio"` when present (keeping the `["tokio", "crypto", "json"]` order
    // byte-identical for async programs) and fall back to the synchronous
    // `["json"]` list otherwise.
    let step1 = if let Some(p) = base.find(TOKIO_ANCHOR) {
        let anchor_end = p + TOKIO_ANCHOR.len();
        let mut s = String::with_capacity(base.len() + rsa_dep.len() + 12);
        s.push_str(base.get(..anchor_end).unwrap_or(""));
        s.push_str(r#", "crypto""#);
        s.push_str(base.get(anchor_end..).unwrap_or(""));
        s
    } else if base.contains(SYNC_DEFAULT) {
        base.replacen(SYNC_DEFAULT, SYNC_DEFAULT_CRYPTO, 1)
    } else {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::crypto_core_heavy_cargo_toml",
            detail: format!(
                "Cargo.toml anchor {TOKIO_ANCHOR:?} or {SYNC_DEFAULT:?} not found — golden drifted"
            ),
        });
    };

    // Step 2 — restore the `rsa` line immediately after `zeroize = "1"`.
    let insert_at = step1
        .find(ZEROIZE_ANCHOR)
        .map(|p| p + ZEROIZE_ANCHOR.len())
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::crypto_core_heavy_cargo_toml",
            detail: format!("Cargo.toml anchor {ZEROIZE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step1.len() + rsa_dep.len());
    result.push_str(step1.get(..insert_at).unwrap_or(""));
    result.push_str(&rsa_dep);
    result.push_str(step1.get(insert_at..).unwrap_or(""));
    Ok(result)
}

/// Restore the tokio async spine into a program that reaches the reactor.
///
/// The base template ships NO async runtime: a pure program (only `Io.println`,
/// string / list / math / json computation, the pure `Task` monad ops) enters
/// through the std-only `block_on` and links neither `tokio` nor `futures-util`.
/// A program that reaches ANY reactor-requiring kernel
/// ([`EmitCtx::uses_async_runtime`]) restores exactly what the base template
/// once carried, so an async program's manifest is byte-for-byte what it was
/// before the async floor became conditional:
///
/// 1. re-add `"tokio"` as the FIRST default feature (`["json"]` →
///    `["tokio", "json"]`), the slot the per-surface surgeries
///    (`db`/`server`/`web`/`crypto_core_heavy`) anchor on. This augmenter runs
///    FIRST in the chain, so those downstream anchors see the restored line.
/// 2. re-add the `tokio` dependency as the first `[dependencies]` line (before
///    `dlmalloc`), with its original feature set. The `server`/`web` surgeries
///    extend this exact line with `"net"` / `"sync"`.
/// 3. re-add `futures-util` in its original slot (after the `bcrypt` base dep).
///
/// The `tokio` / `futures-util` versions come from the [`crate_specs`] SSOT
/// (drift-guarded against `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `default = ["json"]`, `dlmalloc`,
/// or `bcrypt` anchor is absent — a golden-drift invariant violation (fail-loud,
/// never a silent no-op that would emit an async program without a runtime).
fn async_runtime_cargo_toml(base: &str) -> DResult<String> {
    const DEFAULT_ANCHOR: &str = r#"default = ["json"]"#;
    const DEFAULT_RESTORED: &str = r#"default = ["tokio", "json"]"#;
    // `tokio` was the first `[dependencies]` line, above the `dlmalloc`
    // dependency. Anchor on the full `dlmalloc` dep spelling (not a bare
    // `dlmalloc = `, which also occurs inside the `alloc_dlmalloc` FEATURE line).
    const DLMALLOC_ANCHOR: &str = r#"dlmalloc = { version = "0.2""#;
    // `futures-util` followed the `bcrypt` base dep.
    const BCRYPT_ANCHOR: &str = "bcrypt = \"0.17\"\n";
    let tokio_dep = format!(
        "{} = {{ version = \"{}\", features = [\"rt\", \"rt-multi-thread\", \"macros\", \"time\"] }}\n",
        crate_specs::TOKIO.name,
        crate_specs::TOKIO.version,
    );
    let futures_dep = format!(
        "{} = \"{}\"\n",
        crate_specs::FUTURES_UTIL.name,
        crate_specs::FUTURES_UTIL.version,
    );

    let bug = |anchor: &str| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::project::async_runtime_cargo_toml",
        detail: format!("Cargo.toml anchor {anchor:?} not found — golden drifted"),
    };

    // Step 1 — restore `"tokio"` in the default feature list.
    if !base.contains(DEFAULT_ANCHOR) {
        return Err(bug(DEFAULT_ANCHOR));
    }
    let step1 = base.replacen(DEFAULT_ANCHOR, DEFAULT_RESTORED, 1);

    // Step 2 — insert the `tokio` dependency immediately before `dlmalloc`.
    let dl_at = step1
        .find(DLMALLOC_ANCHOR)
        .ok_or_else(|| bug(DLMALLOC_ANCHOR))?;
    let mut step2 = String::with_capacity(step1.len() + tokio_dep.len() + futures_dep.len());
    step2.push_str(step1.get(..dl_at).unwrap_or(""));
    step2.push_str(&tokio_dep);
    step2.push_str(step1.get(dl_at..).unwrap_or(""));

    // Step 3 — restore the `futures-util` line after the `bcrypt` base dep.
    let bc_at = step2
        .find(BCRYPT_ANCHOR)
        .map(|p| p + BCRYPT_ANCHOR.len())
        .ok_or_else(|| bug(BCRYPT_ANCHOR))?;
    let mut result = String::with_capacity(step2.len() + futures_dep.len());
    result.push_str(step2.get(..bc_at).unwrap_or(""));
    result.push_str(&futures_dep);
    result.push_str(step2.get(bc_at..).unwrap_or(""));
    Ok(result)
}

/// Build the heavy-`Ipe.Crypto`-enabled `Cargo.toml` by appending the five
/// crypto-exclusive dependencies before `[profile.dev]`.
///
/// `crypto.rs` (the gated heavy `Ipe.Crypto` kernels) is the sole consumer of
/// `sha1`, `md-5`, `aes-gcm`, `chacha20poly1305`, and `pbkdf2`. These are leaves
/// — a program using only the `crypto_core` floor (SHA-2 / HMAC / entropy pair)
/// pulls none of them. `sha2` / `hmac` / `subtle` stay unconditional in the base
/// manifest because always-on surfaces (`secret.rs`, `db.rs`, `web`, `email`)
/// need them; `rsa` is added separately by [`crypto_core_heavy_cargo_toml`] under
/// the union of crypto / jwt / auth.
///
/// The versions come from the [`crate_specs`] SSOT (drift-guarded against
/// `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if the `[profile.dev]` anchor is absent —
/// a golden-drift invariant violation (fail-loud, never a silent no-op).
fn crypto_cargo_toml(base: &str) -> DResult<String> {
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    let deps = format!(
        "{} = \"{}\"\n{} = \"{}\"\n{} = \"{}\"\n{} = \"{}\"\n{} = \"{}\"\n\n",
        crate_specs::SHA1.name,
        crate_specs::SHA1.version,
        crate_specs::MD5.name,
        crate_specs::MD5.version,
        crate_specs::AES_GCM.name,
        crate_specs::AES_GCM.version,
        crate_specs::CHACHA20POLY1305.name,
        crate_specs::CHACHA20POLY1305.version,
        crate_specs::PBKDF2.name,
        crate_specs::PBKDF2.version,
    );
    let anchor_pos = base
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::crypto_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(base.len() + deps.len());
    result.push_str(base.get(..anchor_pos).unwrap_or(""));
    result.push_str(&deps);
    result.push_str(base.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Build the JWT-enabled `Cargo.toml` from the given base manifest by:
///
/// 1. Adding `"jwt"` to the `default` feature list — `auth.rs` and `server.rs`
///    in the vendored runtime carry `#[cfg(feature = "jwt")]` guards over
///    `AuthConfig`, `server_get_authed`, and the JWT sign/verify helpers.
///    Without `"jwt"` in `default`, those items are compiled out and `main.rs`
///    references to `AuthConfig` fail with E0425 (ipe exit 0, cargo fails —
///    a SEAL breach).
/// 2. Declaring `jwt = []` in the `[features]` table (anchoring on `db = []`,
///    always present in the base manifest), so the `"jwt"` entry in `default`
///    refers to a declared feature rather than an undeclared name.
/// 3. Appending the `jsonwebtoken` dependency before `[profile.dev]`.
///
/// `jwt.rs` (and `auth.rs`, which reaches `crate::jwt`) is the sole consumer of
/// `jsonwebtoken`. The crate is a leaf — a program that never encodes or
/// verifies a JWT (and uses no `Ipe.Auth` kernel) pulls it not.
///
/// The version comes from the [`crate_specs`] SSOT (drift-guarded against
/// `runtime/Cargo.toml`).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] if any anchor string is absent —
/// a golden-drift invariant violation (fail-loud, never a silent no-op).
fn jwt_cargo_toml(base: &str) -> DResult<String> {
    const DEFAULT_PREFIX: &str = "default = [";
    const DB_FEATURE: &str = "db = []";
    const DB_JWT_FEATURE: &str = "db = []\njwt = []";
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    let deps = format!(
        "{} = \"{}\"\n\n",
        crate_specs::JSONWEBTOKEN.name,
        crate_specs::JSONWEBTOKEN.version,
    );

    // Step 1a — insert `"jwt"` as the last element of the `default = [...]`
    // feature list, immediately before its closing `]`.
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::jwt_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::jwt_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    let mut step1a = String::with_capacity(base.len() + deps.len() + 16);
    step1a.push_str(base.get(..close).unwrap_or(""));
    step1a.push_str(r#", "jwt""#);
    step1a.push_str(base.get(close..).unwrap_or(""));

    // Step 1b — declare `jwt = []` in the `[features]` table so that `"jwt"` in
    // `default = [...]` refers to a declared feature (Cargo rejects an undeclared
    // feature reference). Anchor on the `db = []` line, always present in the
    // base manifest.
    let step1 = step1a.replacen(DB_FEATURE, DB_JWT_FEATURE, 1);
    if step1 == step1a {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::jwt_cargo_toml",
            detail: format!("Cargo.toml anchor {DB_FEATURE:?} not found — golden drifted"),
        });
    }

    // Step 2 — append `jsonwebtoken` before `[profile.dev]`.
    let anchor_pos = step1
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::jwt_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(step1.len() + deps.len());
    result.push_str(step1.get(..anchor_pos).unwrap_or(""));
    result.push_str(&deps);
    result.push_str(step1.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Promote the `secret` feature into the vendored manifest's `default = [...]`
/// list for a program that reaches the `Ipe.Secret` surface (`reaches_secret`).
///
/// The vendored `secret.rs` module is compiled unconditionally (a bare `pub mod
/// secret;` in the emitted `ipe_runtime/mod.rs`), so the `Secret` TYPE resolves
/// with the feature off. The feature still gates the FUNCTIONS that live in other
/// modules but hand back a `Secret` — the vendored `io.rs::io_read_secret`
/// (`Io.readSecret`) and `app_config.rs::resolve_db_url_override` are
/// `#[cfg(feature = "secret")]`. Without this promotion a vendored `Io.readSecret`
/// program would emit a wrapper calling a cfg'd-out runtime function (E0425).
///
/// Idempotent: a no-op when `"secret"` is already in the default list (e.g. a
/// db program, whose [`db_cargo_toml`] already added it).
fn secret_cargo_toml(base: &str) -> DResult<String> {
    const DEFAULT_PREFIX: &str = "default = [";
    // Already promoted (db path, or a prior call) — nothing to do.
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::secret_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let rel = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::secret_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    let close = search_from + rel;
    if base
        .get(search_from..close)
        .is_some_and(|list| list.contains("\"secret\""))
    {
        return Ok(base.to_owned());
    }
    let mut out = String::with_capacity(base.len() + 12);
    out.push_str(base.get(..close).unwrap_or(""));
    out.push_str(r#", "secret""#);
    out.push_str(base.get(close..).unwrap_or(""));
    Ok(out)
}

/// Promote the `dev-posture` feature into the vendored manifest's default list.
///
/// Called only for a [`crate::BuildIntent::Development`] emit. The feature is
/// the vendored runtime's build-intent fact: with it on, an absent `ENV` /
/// `IPE_ENV` reads as development and the operator console may default open on
/// a loopback bind; with it off, every absent posture is production.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] when the `default = [` anchor or its
/// closing `]` is absent — a golden-drift invariant violation. It never emits a
/// development manifest without the feature.
fn dev_posture_cargo_toml(base: &str) -> DResult<String> {
    const DEFAULT_PREFIX: &str = "default = [";
    const FEATURE: &str = "\"dev-posture\"";
    let pfx = base
        .find(DEFAULT_PREFIX)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::dev_posture_cargo_toml",
            detail: format!("Cargo.toml anchor {DEFAULT_PREFIX:?} not found — golden drifted"),
        })?;
    let search_from = pfx + DEFAULT_PREFIX.len();
    let close = base
        .get(search_from..)
        .and_then(|s| s.find(']'))
        .map(|rel| search_from + rel)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::dev_posture_cargo_toml",
            detail: "default feature list has no closing ']' — golden drifted".to_owned(),
        })?;
    if base
        .get(search_from..close)
        .is_some_and(|list| list.contains(FEATURE))
    {
        return Ok(base.to_owned());
    }
    let mut out = String::with_capacity(base.len() + FEATURE.len() + 2);
    out.push_str(base.get(..close).unwrap_or(""));
    out.push_str(", ");
    out.push_str(FEATURE);
    out.push_str(base.get(close..).unwrap_or(""));
    Ok(out)
}

/// Slice each compiler-generated FFI interface-forwarder module down to the
/// forwarders the rest of the program references.
///
/// The targets are ONLY the modules the driver names in
/// `FfiEmit::interface_modules` (the reserved `Rust.*` namespace) — a user
/// module can never be shaken. Within a target file everything before the
/// first `pub(crate) fn` (the `use crate::*;` header) is kept
/// unconditionally; each forwarder region (one `pub(crate) fn` to the next)
/// is kept iff its identifier occurs anywhere OUTSIDE the target files.
/// Conservative-keep: an unparseable region shape keeps the whole file, so
/// the shake can never under-keep a called forwarder; over-keep is dead code.
fn shake_interface_forwarder_files(
    files: &mut BTreeMap<RelPath, String>,
    interface_modules: &[String],
) {
    const FN_MARK: &str = "pub(crate) fn ";
    if interface_modules.is_empty() {
        return;
    }
    let target_paths: std::collections::BTreeSet<String> = interface_modules
        .iter()
        .map(|m| {
            let segs: Vec<&str> = m.split('.').collect();
            format!("src/ipe_mods/{}.rs", rust_file::mod_ident(&segs))
        })
        .collect();
    // The reachability haystack: every emitted file that is NOT a forwarder
    // module (forwarders reference only `crate::ffi::` wrappers, never each
    // other, so excluding them is exact).
    let mut haystack = String::new();
    for (path, text) in files.iter() {
        if !target_paths.contains(path.as_str()) {
            haystack.push_str(text);
        }
    }
    for (path, text) in files.iter_mut() {
        if !target_paths.contains(path.as_str()) {
            continue;
        }
        let Some(first) = text.find(FN_MARK) else {
            continue; // no forwarders — keep verbatim
        };
        let (header, mut rest) = text.split_at(first);
        let mut out = String::with_capacity(text.len());
        out.push_str(header);
        // Each region starts at a FN_MARK occurrence and runs to the next.
        while !rest.is_empty() {
            let region_end = rest
                .get(FN_MARK.len()..)
                .and_then(|tail| tail.find(FN_MARK).map(|i| i + FN_MARK.len()))
                .unwrap_or(rest.len());
            let (region, next) = rest.split_at(region_end);
            let ident: String = region
                .get(FN_MARK.len()..)
                .unwrap_or("")
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            // Empty ident = unrecognised shape → conservative keep.
            if ident.is_empty() || haystack.contains(&ident) {
                out.push_str(region);
            }
            rest = next;
        }
        *text = out;
    }
}

/// The `crate::ffi::<ident>` wrapper identifiers referenced anywhere in the
/// emitted Rust sources — the program's reached FFI wrapper set.
///
/// Every `ipe_ir::Callee::Ffi` lowers to a `crate::ffi::<ident>(` call
/// (`emit_expr::callee_name`), so scanning the emitted text is an exhaustive,
/// parse-free reachability oracle.
fn reached_ffi_idents(files: &BTreeMap<RelPath, String>) -> std::collections::BTreeSet<String> {
    const MARK: &str = "crate::ffi::";
    let mut out = std::collections::BTreeSet::new();
    for text in files.values() {
        let mut rest: &str = text;
        while let Some(pos) = rest.find(MARK) {
            let after = &rest[pos + MARK.len()..];
            let ident: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() {
                out.insert(ident);
            }
            rest = after;
        }
    }
    out
}

/// The FFI wrapper-module sentinel bounds (mirror of `ipe_ffi::naming`; the
/// backend may not depend on `ipe_ffi`, so the wire-format literals are
/// re-stated here — a pure text protocol, stable by contract).
const FFI_WRAPPER_BEGIN: &str = "// IPE-FFI-WRAPPER BEGIN ";
const FFI_WRAPPER_END: &str = "// IPE-FFI-WRAPPER END";

/// Text-slice the wrapper module on its BEGIN/END sentinels, keeping preamble
/// unconditionally and only the regions whose `pub fn <ident>(` is reached.
///
/// Conservative-keep: a region whose `pub fn` ident cannot be read (a shape
/// the scan does not recognise) is KEPT, so the shake never drops a wrapper
/// the program calls (an under-bind); over-keep is dead code cargo strips.
fn shake_ffi_by_fn_ident(source: &str, reached: &std::collections::BTreeSet<String>) -> String {
    let mut out = String::with_capacity(source.len());
    // Buffer one wrapper region until its `pub fn` ident is known, then
    // decide keep/drop for the whole region.
    let mut region: Option<(String, bool)> = None; // (buffered text, reached?)
    for line in source.lines() {
        if line.trim_end().starts_with(FFI_WRAPPER_BEGIN) {
            region = Some((String::new(), false));
        }
        if let Some((buf, keep)) = region.as_mut() {
            buf.push_str(line);
            buf.push('\n');
            if let Some(rest) = line.trim_start().strip_prefix("pub fn ") {
                let ident: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                // Accumulate, never overwrite: a region with more than one
                // `pub fn` (not produced by today's generator, but not
                // structurally forbidden either) must stay kept once ANY of
                // its fns is reached — overwriting on the LAST fn seen would
                // drop a region whose FIRST fn is reached but whose last one
                // is not, an under-bind (the reached fn's own wrapper
                // vanishes, an E0425 the linker reports far from this
                // decision point). An ident we cannot read is conservatively
                // kept.
                *keep = *keep || ident.is_empty() || reached.contains(&ident);
            }
            if line.trim_end() == FFI_WRAPPER_END {
                if *keep {
                    out.push_str(buf);
                }
                region = None;
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    // A dangling unterminated region (malformed) is kept whole.
    if let Some((buf, _)) = region {
        out.push_str(&buf);
    }
    out
}

/// Build the structured sidecar that records every surviving wrapper path in
/// the DCE-shaken `ffi_rs` text, together with whether each wrapper is generic.
///
/// The sidecar is the SSOT Tier-2 reads: it eliminates the text-layout coupling
/// that a line-scan of the emitted Rust carries. The format is a JSON object:
///
/// ```text
/// {"wrappers":[{"path":"crate::ffi::<slug>::<ident>","generic":<bool>},...]}
/// ```
///
/// Entries are sorted by path for a deterministic artifact. The `generic` flag
/// is set when the wrapper's BEGIN sentinel carries `// [ffi-generic]`: a
/// generic wrapper cannot have its address taken without a turbofish, so Tier-2
/// excludes it from the link-reference set while still exercising its build-time
/// reach through the crate compile.
///
/// A `pub mod <slug>` line sets the current module; a `pub fn <ident>` inside
/// it records the entry. Lines outside any `pub mod` block are skipped.
#[must_use]
fn ffi_wrappers_sidecar(ffi_rs: &str) -> String {
    use std::fmt::Write as _;
    let mut entries: Vec<(String, bool)> = Vec::new();
    let mut current_slug: Option<String> = None;
    let mut pending_generic = false;
    for line in ffi_rs.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("pub mod ") {
            let slug: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !slug.is_empty() {
                current_slug = Some(slug);
                pending_generic = false;
            }
        } else if trimmed.starts_with("// [ffi-generic]") {
            // The next `pub fn` in this region is a generic wrapper.
            pending_generic = true;
        } else if let Some(rest) = trimmed.strip_prefix("pub fn ") {
            let ident: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if let (Some(slug), false) = (current_slug.as_ref(), ident.is_empty()) {
                entries.push((format!("crate::ffi::{slug}::{ident}"), pending_generic));
            }
            pending_generic = false;
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.dedup_by(|a, b| a.0 == b.0);
    let mut out = String::from("{\"wrappers\":[");
    for (i, (path, generic)) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // Writing into a String is infallible.
        let _ = write!(
            out,
            "{{\"path\":{path_json},\"generic\":{generic}}}",
            path_json = json_string(path),
            generic = generic,
        );
    }
    out.push_str("]}\n");
    out
}

/// Minimal JSON string encoder: wraps `s` in double quotes and escapes the
/// characters JSON requires (`"`, `\`, and ASCII control characters). Wrapper
/// paths are ASCII identifiers joined by `::`, so only `"` and `\` are
/// plausible in practice, but the full ASCII-control sweep is included for
/// correctness at the boundary.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Append the bound FFI crates' pinned `[dependencies]` lines (driver-merged,
/// exact versions, effective feature sets) before the `[profile.dev]` anchor.
///
/// # Errors
///
/// [`Diagnostic::CompilerBug`] when the FFI emission inputs are absent while
/// the program uses FFI, or when the manifest anchor drifted.
fn ffi_cargo_toml(base: &str, ctx: &EmitCtx) -> DResult<String> {
    const PROFILE_ANCHOR: &str = "[profile.dev]";
    let ffi = ctx.ffi.as_ref().ok_or_else(|| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::project::ffi_cargo_toml",
        detail: "program lowers foreign-wrapper calls but the driver supplied no FFI \
                 emission inputs (RustBackend::with_ffi)"
            .to_owned(),
    })?;
    // Keys the base manifest already declares under a `[...dependencies]`
    // table: re-declaring one (uuid's transitive `futures-util`, say) is a
    // hard `cargo` duplicate-key error, so those lines are skipped — the
    // base pin governs and cargo's resolver unifies the shared graph.
    let mut base_keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut in_deps = false;
    for raw in base.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_deps = line.contains("dependencies");
            continue;
        }
        if in_deps && let Some((name, _)) = line.split_once('=') {
            base_keys.insert(name.trim());
        }
    }
    let mut dep_block = String::new();
    for line in &ffi.dep_lines {
        let key = line.split('=').next().unwrap_or(line).trim();
        if base_keys.contains(key) {
            continue;
        }
        dep_block.push_str(line);
        dep_block.push('\n');
    }
    dep_block.push('\n');
    let anchor_pos = base
        .find(PROFILE_ANCHOR)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::ffi_cargo_toml",
            detail: format!("Cargo.toml anchor {PROFILE_ANCHOR:?} not found — golden drifted"),
        })?;
    let mut result = String::with_capacity(base.len() + dep_block.len());
    result.push_str(base.get(..anchor_pos).unwrap_or(""));
    result.push_str(&dep_block);
    result.push_str(base.get(anchor_pos..).unwrap_or(""));
    Ok(result)
}

/// Emit the `into_sql_param` impl for `SqlValue` and `into_field_param` impl
/// for `SqlField`.
///
/// These are fixed-shape impls — the variant names are always the same Ipê
/// names (`SqlString`, `SqlInt`, …) and the mapping to `ipe_runtime::db::SqlParam`
/// variants is 1-to-1.  Only the enum's Rust *type name* (e.g. `MainSqlValue`)
/// varies per program (depends on the module name prefix).
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] when `ctx.uses_db` is `true` but the
/// Rust names were not computed — an internal invariant violation (the detection
/// in `EmitCtx::build` and the injection in `Lowerer::run` must agree).
fn emit_db_projection_impls(ctx: &EmitCtx) -> DResult<String> {
    let sv = ctx
        .sqlvalue_rust_name
        .as_deref()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::emit_db_projection_impls",
            detail: "uses_db is true but sqlvalue_rust_name is None — \
                 SqlValue was not injected into enum_names"
                .to_owned(),
        })?;
    let sf = ctx
        .sqlfield_rust_name
        .as_deref()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::project::emit_db_projection_impls",
            detail: "uses_db is true but sqlfield_rust_name is None — \
                 SqlField was not injected into enum_names"
                .to_owned(),
        })?;

    // `SqlTime` stores a Unix-millisecond timestamp as `i64` — maps to
    // `SqlParam::Int`.  `SqlDecimal` carries a native `Decimal`, rendered to a
    // lossless TEXT param via `decimal_to_string` (the inverse of
    // `db_decode_decimal`'s `RD::from_str` read); `SqlMoney` carries an
    // "ISO_CODE AMOUNT" string — both bind as `SqlParam::Text`.  `SqlNull`
    // carries a SqlValue
    // type-witness — threaded through (NOT discarded) into
    // `SqlParam::Null(Box<SqlParam>)` so the bind site (`bind_sql_param`)
    // can pick the correctly-typed `Option::<T>::None`, which matters on
    // Postgres (sqlx's extended query protocol validates a per-param
    // type-OID hint against the target column) even though it's a no-op on
    // SQLite's dynamic typing.
    Ok(format!(
        "\
impl {sv} {{
    /// Convert this `SqlValue` into the runtime-nameable `SqlParam`.
    /// Used by `into_field_param` and by legacy call sites that name
    /// this method directly.  New call sites should prefer the `From`
    /// impl below so the emitter can use the uniform `SqlParam::from`
    /// projection for polymorphic `List a` params.
    pub fn into_sql_param(self) -> ipe_runtime::db::SqlParam {{
        match self {{
            Self::SqlString(v) => ipe_runtime::db::SqlParam::Text(v),
            Self::SqlInt(v) => ipe_runtime::db::SqlParam::Int(v),
            Self::SqlFloat(v) => ipe_runtime::db::SqlParam::Float(v),
            Self::SqlBool(v) => ipe_runtime::db::SqlParam::Bool(v),
            Self::SqlBytes(v) => ipe_runtime::db::SqlParam::Bytes(v),
            Self::SqlTime(v) => ipe_runtime::db::SqlParam::Int(v),
            Self::SqlDecimal(v) => {{
                ipe_runtime::db::SqlParam::Text(ipe_runtime::decimal::decimal_to_string(v))
            }}
            Self::SqlMoney(v) => ipe_runtime::db::SqlParam::Text(v),
            Self::SqlNull(inner) => {{
                ipe_runtime::db::SqlParam::Null(Box::new(inner.into_sql_param()))
            }}
        }}
    }}
}}

/// Allow `SqlParam::from(sql_value)` so the emitter can use the same
/// `ipe_runtime::db::SqlParam::from` projection for ALL element types in
/// the polymorphic `Db.exec`/`query` params list (`List a` where `a` may
/// be `String`, `Int`, `Float`, `Bool`, or `SqlValue`).
impl From<{sv}> for ipe_runtime::db::SqlParam {{
    fn from(v: {sv}) -> Self {{
        v.into_sql_param()
    }}
}}

impl {sf} {{
    pub fn into_field_param(self) -> Option<ipe_runtime::db::SqlParam> {{
        match self {{
            Self::SetField(v) => Some(v.into_sql_param()),
            Self::OmitField => None,
        }}
    }}
}}
"
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        CARGO_DEP_TOML, CARGO_TOML, CARGO_WASM_DEP_TOML, RUNTIME_CONFIG_RS_DB_POSTGRES,
        RUNTIME_CONFIG_RS_DB_SQLITE, RUNTIME_MOD_RS_WEB_APPEND, RUNTIME_MOD_RS_WEB_CORE_APPEND,
        WASM_ABSENT_MODULE_PATHS, WASM_CARGO_TOML, WASM_PRESENT_OVERRIDES,
        async_runtime_cargo_toml, crypto_core_heavy_cargo_toml, db_cargo_toml,
        dev_posture_cargo_toml, insert_wasi_linker_config, jwt_cargo_toml, runtime_bindings,
        server_cargo_toml, shake_ffi_by_fn_ident, ssrf_cargo_toml, wasm_present_modules,
        wasm_runtime_bindings, web_cargo_toml, wrapper_call_paths,
    };
    use crate::DbDriver;
    use crate::crate_specs;
    use ipe_backend::RelPath;
    use std::collections::BTreeMap;

    /// Drift-guard for the `overflow-checks = false` dev-profile flag, stated
    /// once per emitted manifest source. Since #1124 the flag is a pure
    /// *efficiency* knob (unchecked dev arithmetic) — `Int` wrap SOUNDNESS now
    /// lives in the `ipe_runtime::math::ipe_int_{add,sub,mul}` helpers, not here.
    /// This test keeps the four copies in sync (SSOT's "assert equality in a
    /// test" clause): adding a fifth manifest source to the array below forces
    /// its inclusion, and dropping the flag from any copy fails this test.
    #[test]
    fn every_emitted_manifest_carries_the_dev_overflow_checks_flag() {
        // One enumerated set of every manifest string the backend can emit.
        // A new template must be added here or the guard does not cover it.
        let manifests: [(&str, &str); 4] = [
            ("templates/Cargo.toml", CARGO_TOML),
            ("templates/Cargo.dep.toml", CARGO_DEP_TOML),
            ("templates/Cargo.wasm-dep.toml", CARGO_WASM_DEP_TOML),
            ("project.rs WASM_CARGO_TOML", WASM_CARGO_TOML),
        ];
        for (name, manifest) in manifests {
            let found = manifest.find("[profile.dev]");
            assert!(
                found.is_some(),
                "{name}: emitted manifest must declare a [profile.dev] block"
            );
            let Some(dev_start) = found else { continue };
            // Scope the search to the dev block: the flag belongs there, not in
            // [profile.release] (which intentionally omits it, relying on
            // Cargo's release default of overflow-checks = false).
            let dev_block = &manifest[dev_start..];
            let dev_end = dev_block[1..]
                .find("[profile.")
                .map_or(dev_block.len(), |rel| rel + 1);
            let dev_block = &dev_block[..dev_end];
            assert!(
                dev_block.contains("overflow-checks = false"),
                "{name}: [profile.dev] must carry `overflow-checks = false` \
                 (efficiency knob; drop it and the guard fails)"
            );
        }
    }

    /// The `tokio = { … }` dependency line of `manifest`.
    fn tokio_line(manifest: &str) -> Option<&str> {
        let prefix = format!("{} = {{", crate_specs::TOKIO.name);
        manifest.lines().find(|l| l.starts_with(&prefix))
    }

    /// The quoted value immediately after the first occurrence of `anchor` in
    /// `haystack`.
    ///
    /// Strips a leading `=` pin marker so an exact-pinned `"=X.Y.Z"` and a bare
    /// `"X.Y.Z"` compare equal. `None` when `anchor` never opens a quoted value.
    fn pinned_dependency_version<'a>(haystack: &'a str, anchor: &str) -> Option<&'a str> {
        let (_, after_anchor) = haystack.split_once(anchor)?;
        let (version, _) = after_anchor.split_once('"')?;
        Some(version.trim_start_matches('='))
    }

    /// SSOT guard: the `wasm-bindgen` version is hand-spelled in four places.
    ///
    /// None of them can `include!`/import a Cargo dependency version from
    /// another — two are real `Cargo.toml` dependency tables Cargo itself
    /// parses at a different time than this compiler builds, and the CLI's
    /// copy is a string literal in a separate crate's binary.
    /// `src/runtime/rust/Cargo.toml` is the canonical spelling (the one pin
    /// Cargo enforces for the runtime crate itself); this test fails the
    /// instant any of the other three drifts from it.
    #[test]
    fn wasm_bindgen_version_matches_the_runtime_pin() {
        const RUNTIME_CARGO_TOML: &str = include_str!("../../../../../src/runtime/rust/Cargo.toml");
        const CLI_COMMANDS_RS: &str = include_str!("../../../../ipe-cli/src/driver/commands.rs");

        let runtime_pin =
            pinned_dependency_version(RUNTIME_CARGO_TOML, "wasm-bindgen = { version = \"")
                .expect("src/runtime/rust/Cargo.toml must pin an exact wasm-bindgen version");
        let dep_template_pin = pinned_dependency_version(CARGO_WASM_DEP_TOML, "wasm-bindgen = \"")
            .expect("templates/Cargo.wasm-dep.toml must pin an exact wasm-bindgen version");
        let monolithic_pin = pinned_dependency_version(WASM_CARGO_TOML, "wasm-bindgen = \"")
            .expect("project.rs's WASM_CARGO_TOML must pin an exact wasm-bindgen version");
        let cli_pin = pinned_dependency_version(CLI_COMMANDS_RS, "WASM_BINDGEN_VERSION: &str = \"")
            .expect("ipe-cli must declare a WASM_BINDGEN_VERSION constant");

        assert_eq!(
            dep_template_pin, runtime_pin,
            "templates/Cargo.wasm-dep.toml's wasm-bindgen pin has drifted from \
             src/runtime/rust/Cargo.toml's"
        );
        assert_eq!(
            monolithic_pin, runtime_pin,
            "project.rs's WASM_CARGO_TOML wasm-bindgen pin has drifted from \
             src/runtime/rust/Cargo.toml's"
        );
        assert_eq!(
            cli_pin, runtime_pin,
            "ipe-cli's WASM_BINDGEN_VERSION has drifted from \
             src/runtime/rust/Cargo.toml's wasm-bindgen pin"
        );
    }

    /// `ssrf_cargo_toml` adds tokio `"net"` to a line lacking it (the db-only
    /// manifest), leaves a line that has it unchanged, and refuses a manifest
    /// with no `tokio` line rather than silently shipping one without it.
    #[test]
    fn ssrf_toml_declares_tokio_net_exactly_once() {
        let db = db_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
            DbDriver::Sqlite,
        )
        .expect("db manifest");
        assert!(
            tokio_line(&db).is_some_and(|l| !l.contains(r#""net""#)),
            "the db-only base line must lack \"net\" for this test to bite: {db}"
        );
        let with_net = ssrf_cargo_toml(&db).expect("ssrf manifest");
        let line = tokio_line(&with_net).unwrap_or_default();
        assert_eq!(line.matches(r#""net""#).count(), 1, "{line}");
        assert_eq!(
            ssrf_cargo_toml(&with_net).expect("idempotent"),
            with_net,
            "a line already listing \"net\" must be unchanged"
        );
        let server = server_cargo_toml(&db).expect("server manifest");
        assert_eq!(ssrf_cargo_toml(&server).expect("server + ssrf"), server);
        assert!(
            ssrf_cargo_toml(CARGO_TOML).is_err(),
            "a manifest with no tokio line must be refused"
        );
    }

    /// Helper: extract the `default = [...]` line from a manifest string.
    fn default_line(manifest: &str) -> &str {
        manifest
            .lines()
            .find(|l| l.starts_with("default = ["))
            .expect("manifest must contain a default = [...] line")
    }

    /// `server_cargo_toml` on the NON-db base manifest inserts "server" and does
    /// not insert "db" into the default list.
    #[test]
    fn server_toml_non_db_inserts_server() {
        let out = server_cargo_toml(&async_runtime_cargo_toml(CARGO_TOML).expect("async base"))
            .expect("server_cargo_toml must succeed");
        let def = default_line(&out);
        assert!(
            def.contains(r#""server""#),
            r#"default line must contain "server": {def}"#
        );
        assert!(
            !def.contains(r#""db""#),
            r#"non-db: default line must NOT contain "db": {def}"#
        );
        // Feature declaration must be present.
        assert!(
            out.contains("server = []"),
            "manifest must declare the server feature: {out}"
        );
        // tokio net + sync features must be added.
        assert!(
            out.contains(r#""net""#) && out.contains(r#""sync""#),
            "tokio must gain net + sync features: {out}"
        );
        // axum + tower-http + tower deps must be present. The front-door DoS
        // ceilings need `tower-http`'s `timeout` (per-request `TimeoutLayer`)
        // and `tower`'s `limit` (`GlobalConcurrencyLimitLayer`); without both
        // the vendored `server.rs` fails to compile in the emitted project.
        assert!(out.contains("axum"), "axum dep must be present: {out}");
        assert!(
            out.contains(
                r#"tower-http = { version = "0.5", features = ["fs", "catch-panic", "timeout"] }"#
            ),
            "tower-http dep with timeout must be present: {out}"
        );
        assert!(
            out.contains(r#"tower = { version = "0.5", features = ["limit"] }"#),
            "tower dep with limit must be present: {out}"
        );
    }

    /// `server_cargo_toml` on the DB-enabled manifest inserts "server" ALONGSIDE
    /// "db" — all of "tokio", "crypto", "json", "db", "server" are present in
    /// the default list, and neither overwrites the other.
    #[test]
    fn server_toml_db_compose_inserts_both() {
        let db_base = db_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
            crate::DbDriver::Sqlite,
        )
        .expect("db_cargo_toml must succeed");
        let out = server_cargo_toml(&db_base).expect("server_cargo_toml on db base must succeed");
        let def = default_line(&out);
        // `"crypto"` is NOT expected: it is gated by `crypto_core_heavy_cargo_toml`
        // (crypto / jwt / auth), which this db+server composition does not reach.
        // `"secret"` IS expected: `db_cargo_toml` adds it alongside `"db"` because
        // the vendored `config.rs` calls `resolve_db_url_override` which is gated on
        // `#[cfg(feature = "secret")]`.
        for feat in &[
            r#""tokio""#,
            r#""json""#,
            r#""db""#,
            r#""server""#,
            r#""secret""#,
        ] {
            assert!(
                def.contains(feat),
                "default line must contain {feat}: {def}"
            );
        }
        assert!(
            !def.contains(r#""crypto""#),
            "db+server without crypto/jwt/auth must not pull the crypto feature: {def}"
        );
        // Both feature declarations must be present.
        assert!(
            out.contains("db = []"),
            "manifest must declare the db feature: {out}"
        );
        assert!(
            out.contains("server = []"),
            "manifest must declare the server feature: {out}"
        );
        // sqlx dep (from db_cargo_toml) plus axum dep (from server_cargo_toml)
        // must both be present.
        assert!(out.contains("sqlx"), "sqlx dep must be present: {out}");
        assert!(out.contains("axum"), "axum dep must be present: {out}");
    }

    /// The emitted manifests must carry the SSOT versions — proves the surgery
    /// reads the table, not a stale literal. Closes the loop the drift test
    /// leaves open (SSOT ↔ manifests): this is SSOT ↔ emitted output.
    #[test]
    fn emitted_manifests_use_ssot_versions() {
        let db = db_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
            crate::DbDriver::Sqlite,
        )
        .expect("db_cargo_toml");
        assert!(
            db.contains(&format!(
                "{} = {{ version = \"{}\"",
                crate_specs::SQLX.name,
                crate_specs::SQLX.version
            )),
            "db manifest must emit SSOT sqlx version:\n{db}"
        );
        let srv = server_cargo_toml(&async_runtime_cargo_toml(CARGO_TOML).expect("async base"))
            .expect("server_cargo_toml");
        assert!(
            srv.contains(&format!(
                "{} = {{ version = \"{}\", features = [\"ws\"]",
                crate_specs::AXUM.name,
                crate_specs::AXUM.version
            )),
            "server manifest must emit SSOT axum version:\n{srv}"
        );
        let heavy = crypto_core_heavy_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
        )
        .expect("crypto_core_heavy_cargo_toml");
        assert!(
            heavy.contains(&format!(
                "{} = {{ version = \"{}\", features = [\"sha2\"] }}",
                crate_specs::RSA.name,
                crate_specs::RSA.version
            )),
            "heavy-crypto manifest must emit the SSOT rsa version:\n{heavy}"
        );
    }

    /// The heavy-`crypto_core` augmenter enables the `crypto` feature in its
    /// original slot (`["tokio", "crypto", "json"]`) and restores the `rsa`
    /// dependency right after the `zeroize` base dep — so a crypto-using
    /// program's manifest is byte-identical to the pre-gating output.
    #[test]
    fn crypto_core_heavy_toml_restores_crypto_and_rsa_in_place() {
        let out = crypto_core_heavy_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
        )
        .expect("crypto_core_heavy_cargo_toml");
        assert!(
            default_line(&out).contains(r#"default = ["tokio", "crypto", "json"]"#),
            "crypto must land in its original slot after tokio: {}",
            default_line(&out)
        );
        assert!(
            out.contains("zeroize = \"1\"\nrsa = { version = \"0.9\", features = [\"sha2\"] }\n"),
            "rsa must be restored immediately after the zeroize base dep:\n{out}"
        );
    }

    /// The augmenter composes with a db base: a db + crypto program still gets
    /// `crypto` in its original slot, alongside the `"secret"` that `db_cargo_toml`
    /// adds (`["tokio", "crypto", "json", "db", "secret"]`).
    #[test]
    fn crypto_core_heavy_toml_composes_with_db() {
        let db = db_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
            crate::DbDriver::Sqlite,
        )
        .expect("db_cargo_toml");
        let out = crypto_core_heavy_cargo_toml(&db).expect("crypto_core_heavy on db base");
        assert!(
            default_line(&out).contains(r#"default = ["tokio", "crypto", "json", "db", "secret"]"#),
            "db+crypto default must contain crypto before json and secret alongside db: {}",
            default_line(&out)
        );
    }

    /// The vendored manifest declares `dev-posture` but leaves it off: a release
    /// emit (which never runs the augmenter) carries no development default.
    #[test]
    fn vendored_manifest_declares_dev_posture_off_by_default() {
        assert!(
            CARGO_TOML.lines().any(|l| l == "dev-posture = []"),
            "the vendored template must declare the `dev-posture` feature"
        );
        assert!(
            !default_line(CARGO_TOML).contains("dev-posture"),
            "the vendored default list must not carry `dev-posture`: {}",
            default_line(CARGO_TOML)
        );
    }

    /// A development emit promotes `dev-posture` into the default list, on the
    /// synchronous base and on the async spine alike; a second run is a no-op.
    #[test]
    fn dev_posture_toml_promotes_the_feature() {
        let sync = dev_posture_cargo_toml(CARGO_TOML).expect("sync base");
        assert_eq!(default_line(&sync), r#"default = ["json", "dev-posture"]"#);
        let async_base = async_runtime_cargo_toml(CARGO_TOML).expect("async base");
        let out = dev_posture_cargo_toml(&async_base).expect("async base");
        assert_eq!(
            default_line(&out),
            r#"default = ["tokio", "json", "dev-posture"]"#
        );
        let twice = dev_posture_cargo_toml(&out).expect("idempotent");
        assert_eq!(twice, out);
    }

    /// Fail-closed: a development emit against a manifest whose `default` list
    /// is gone is a `CompilerBug`, never a manifest silently missing the feature.
    #[test]
    fn dev_posture_toml_anchor_miss_is_a_compiler_bug() {
        assert!(dev_posture_cargo_toml("[package]\nname = \"x\"\n").is_err());
        assert!(dev_posture_cargo_toml("default = [\"json\"\n").is_err());
    }

    /// Fail-closed: an augmenter run against a manifest whose `default` list is
    /// gone is a `CompilerBug`, never a silent no-op.
    #[test]
    fn crypto_core_heavy_toml_anchor_miss_is_a_compiler_bug() {
        assert!(crypto_core_heavy_cargo_toml("[package]\nname = \"x\"\n").is_err());
    }

    // ── wasm kernel-wrapper prelude allowlist ───────────────────────────

    /// The wasm prelude keeps every present-module and allowlisted-override
    /// wrapper, and drops every carve-out wrapper.
    #[test]
    fn wasm_prelude_keeps_present_and_override_wrappers_drops_carveouts() {
        let prelude = wasm_runtime_bindings().expect("wasm prelude must build");
        // A present-module wrapper (log.rs is fully wasm-safe) is kept.
        assert!(
            prelude.contains("ipe_runtime::log::log_info"),
            "present-module log wrapper must survive: {prelude}"
        );
        // An override re-adds a wrapper whose module is carved out (time.rs).
        assert!(
            prelude.contains("ipe_runtime::time::time_now"),
            "override time_now must survive: {prelude}"
        );
        // A carved-out wrapper with no override is dropped (crypto AEAD, http_get
        // is override-kept but the bulk crypto module is not — random tokens go
        // via crypto_core override; the plain terminal secret read is dropped).
        assert!(
            !prelude.contains("ipe_runtime::io::io_read_secret"),
            "terminal-secret wrapper must be dropped on wasm: {prelude}"
        );
    }

    /// A wrapper whose denotation targets a module outside the wasm module set
    /// and outside the carve-outs fails loud rather than emitting an
    /// unresolved-path wasm crate — the fail-closed direction the prelude filter
    /// guarantees.
    #[test]
    fn wasm_prelude_fails_loud_on_an_unclassified_wrapper() {
        // A synthetic wrapper naming a module that is neither present nor carved
        // out. `native_only` is not declared in WASM_RUNTIME_MOD_RS, not in
        // WASM_ABSENT_MODULE_PATHS, and not overridden.
        let block = "pub fn ghost() -> IpeTask<()> {\n    ipe_runtime::native_only::ghost()\n}\n";
        let paths = wrapper_call_paths(block);
        assert_eq!(
            paths,
            vec![("ipe_runtime::native_only::ghost", "native_only")]
        );
        assert!(
            !wasm_present_modules().contains("native_only"),
            "native_only must be absent from the wasm module set"
        );
        assert!(
            !WASM_ABSENT_MODULE_PATHS
                .iter()
                .any(|p| "ipe_runtime::native_only::ghost".starts_with(p)),
            "native_only must not be a carve-out prefix"
        );
        assert!(
            !WASM_PRESENT_OVERRIDES
                .iter()
                .any(|p| p == &"ipe_runtime::native_only::ghost"),
            "native_only must not be overridden"
        );
    }

    /// `wrapper_call_paths` collects call denotations only, skipping an incidental
    /// parameter/return TYPE reference — the classification keys on what the
    /// wrapper invokes, not the types it names.
    #[test]
    fn wrapper_call_paths_ignores_type_references() {
        let block = "pub fn f(p: ipe_runtime::path::Path) -> IpeTask<()> {\n    \
                     ipe_runtime::file::file_delete(p)\n}\n";
        assert_eq!(
            wrapper_call_paths(block),
            vec![("ipe_runtime::file::file_delete", "file")]
        );
    }

    /// A dropped wrapper takes its own leading doc comment with it: the terminal
    /// secret-read wrapper is carved out on wasm, so neither its `pub fn` nor its
    /// `Io.readSecret` doc comment survives into the wasm prelude.
    #[test]
    fn dropped_wrapper_takes_its_leading_comment() {
        let prelude = wasm_runtime_bindings().expect("wasm prelude must build");
        assert!(
            !prelude.contains("io_read_secret"),
            "the carved-out secret-read wrapper and its doc must both be dropped: {prelude}"
        );
    }

    /// The wasm prelude is a substring-filtering of the native prelude: every
    /// wrapper it keeps appears verbatim in the full prelude (the filter only
    /// drops, never rewrites).
    #[test]
    fn wasm_prelude_is_a_filtered_native_prelude() {
        let full = runtime_bindings().expect("native prelude must slice");
        let wasm = wasm_runtime_bindings().expect("wasm prelude must build");
        for block in wasm.split("\npub fn ").skip(1) {
            let head = block.lines().next().unwrap_or("");
            assert!(
                full.contains(head),
                "wasm wrapper head {head:?} must appear verbatim in the native prelude"
            );
        }
    }

    // ── seal tests: JWT feature in vendored defaults ────────────────────

    /// `jwt_cargo_toml` must insert `"jwt"` into the `default = [...]` list AND
    /// declare `jwt = []` in `[features]` AND add the `jsonwebtoken` dep.
    ///
    /// The vendored `auth.rs` / `server.rs` carry `#[cfg(feature = "jwt")]` guards
    /// over `AuthConfig`, `server_get_authed`, and the JWT sign/verify helpers.
    /// Without `"jwt"` in `default`, those items are compiled out and `main.rs`
    /// references fail with E0425 (ipe exit 0, cargo fails — a SEAL breach).
    #[test]
    fn jwt_toml_inserts_feature_and_dep() {
        let out = jwt_cargo_toml(CARGO_TOML).expect("jwt_cargo_toml must succeed");
        let def = default_line(&out);
        assert!(
            def.contains(r#""jwt""#),
            r#"default line must contain "jwt" (SEAL: #[cfg(feature="jwt")] items would be compiled out): {def}"#
        );
        assert!(
            out.contains("jwt = []"),
            "manifest must declare the jwt feature: {out}"
        );
        assert!(
            out.contains(crate_specs::JSONWEBTOKEN.name),
            "manifest must contain the jsonwebtoken dep: {out}"
        );
    }

    /// `jwt_cargo_toml` composes with an async base — `"jwt"` lands after the
    /// existing default features without displacing them.
    #[test]
    fn jwt_toml_composes_with_async_base() {
        let async_base = async_runtime_cargo_toml(CARGO_TOML).expect("async base");
        let out = jwt_cargo_toml(&async_base).expect("jwt_cargo_toml on async base");
        let def = default_line(&out);
        assert!(
            def.contains(r#""tokio""#) && def.contains(r#""jwt""#),
            r#"async+jwt default must contain both "tokio" and "jwt": {def}"#
        );
        assert!(
            out.contains("jwt = []"),
            "manifest must declare the jwt feature: {out}"
        );
    }

    /// Fail-closed: a manifest without `default = [` is a `CompilerBug`.
    #[test]
    fn jwt_toml_anchor_miss_is_a_compiler_bug() {
        assert!(jwt_cargo_toml("[package]\nname = \"x\"\n").is_err());
    }

    // ── seal tests: Db+Web closure ─────────────────────────────────────

    /// `web_cargo_toml` on a DB+Server base manifest must extend the sqlx dep
    /// with the `"postgres"` feature.
    ///
    /// Root cause: `live/store.rs`'s `PostgresStore` references `sqlx::PgPool`
    /// gated on `#[cfg(feature = "db")]`.  The runtime's own `Cargo.toml` has
    /// `["runtime-tokio-rustls", "sqlite", "postgres"]`; the emitted project must
    /// match.  Without this, a Db+Web program passes `ipe` then fails `cargo
    /// build` with E0433 (`use of undeclared crate or module sqlx` in
    /// `PgPool::connect`).
    ///
    /// Note: in `emit_program` the call chain is always
    /// `db_cargo_toml → server_cargo_toml → web_cargo_toml` when a program
    /// uses Db AND Web. `web_cargo_toml` expects the tokio `"net"/"sync"`
    /// features already present from `server_cargo_toml`, so the test must mirror
    /// that composition order.
    #[test]
    fn web_db_toml_includes_postgres() {
        let db_base = db_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
            crate::DbDriver::Sqlite,
        )
        .expect("db_cargo_toml must succeed");
        // server_cargo_toml always runs before web_cargo_toml when uses_web is
        // true (see emit_program).  It adds the tokio net+sync features that
        // web_cargo_toml's anchor requires.
        let server_base =
            server_cargo_toml(&db_base).expect("server_cargo_toml on db base must succeed");
        let out =
            web_cargo_toml(&server_base).expect("web_cargo_toml on db+server base must succeed");
        // The sqlx line must carry the postgres feature.
        let sqlx_line = out
            .lines()
            .find(|l| l.trim_start().starts_with(crate_specs::SQLX.name))
            .expect("sqlx dep must be present in a db+live manifest");
        assert!(
            sqlx_line.contains("\"postgres\""),
            "sqlx dep must include the postgres feature (E0433 fix): {sqlx_line}"
        );
        // Regression: sqlite must still be present.
        assert!(
            sqlx_line.contains("\"sqlite\""),
            "sqlx dep must still include the sqlite feature (no regression): {sqlx_line}"
        );
        // Regression: the web feature must be in the default list.
        let def_line = out
            .lines()
            .find(|l| l.starts_with("default = ["))
            .expect("manifest must contain a default = [...] line");
        assert!(
            def_line.contains(r#""web""#),
            "web feature must be in the default list: {def_line}"
        );
    }

    /// `web_cargo_toml` on a WEB-ONLY (non-db) base manifest must NOT add a
    /// postgres dep (no sqlx line exists, no-op replace).
    #[test]
    fn web_only_toml_no_postgres() {
        let server_base =
            server_cargo_toml(&async_runtime_cargo_toml(CARGO_TOML).expect("async base"))
                .expect("server_cargo_toml must succeed");
        let out = web_cargo_toml(&server_base).expect("web_cargo_toml on non-db base must succeed");
        assert!(
            !out.contains("\"postgres\""),
            "a Web-only (no Db) manifest must NOT contain the postgres feature: {out}"
        );
    }

    /// A live/web manifest must declare `rustix` exactly once. The base template
    /// already declares it under `[target.'cfg(unix)'.dependencies]`;
    /// `web_cargo_toml` must not add a second `rustix` line, which would be a
    /// duplicate-key TOML error that fails `cargo build` for every live/web shape.
    #[test]
    fn web_toml_declares_rustix_once() {
        let server_base =
            server_cargo_toml(&async_runtime_cargo_toml(CARGO_TOML).expect("async base"))
                .expect("server_cargo_toml must succeed");
        let out = web_cargo_toml(&server_base).expect("web_cargo_toml on non-db base must succeed");
        let rustix_lines = out
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                t.starts_with("rustix ") || t.starts_with("rustix=")
            })
            .count();
        assert_eq!(
            rustix_lines, 1,
            "a live/web manifest must declare `rustix` exactly once (base template \
             cfg(unix) dep + no duplicate from web_cargo_toml):\n{out}"
        );
    }

    // ── Class 7 §3: Postgres driver structural reachability ─────────────────

    /// Both sqlite and postgres drivers must emit `"sqlite"` AND `"postgres"` in
    /// the sqlx feature list. `external_conn.rs` uses `sqlx::postgres::PgPool`
    /// unconditionally (it handles any externally-configured DSN regardless of the
    /// app's own fixed driver), so `"postgres"` is required even for a
    /// sqlite-driver program — omitting it causes E0433 at `cargo build`.
    #[test]
    fn db_cargo_toml_sqlite_driver_enables_both_sqlx_features() {
        let out = db_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
            DbDriver::Sqlite,
        )
        .expect("db_cargo_toml(Sqlite) must succeed");
        assert!(
            out.contains(r#"features = ["runtime-tokio-rustls", "sqlite", "postgres"]"#),
            "sqlite driver must enable both sqlite and postgres sqlx features \
             (external_conn.rs uses sqlx::postgres unconditionally): {out}"
        );
    }

    /// The actual structural fix under test: `driver = "postgres"` must
    /// produce a `Cargo.toml` whose sqlx dependency enables the `"postgres"`
    /// sqlx feature — closing the "Postgres driver structurally unreachable"
    /// gap (a `driver = "postgres"` build with only the sqlite sqlx feature
    /// fails to compile `sqlx::postgres::PgPool` at all).
    ///
    /// `"sqlite"` MUST stay enabled too — this is additive, not exclusive.
    /// An earlier version of this fix dropped `"sqlite"` when the driver was
    /// Postgres; that produced an exit-0-then-cargo-fail SEAL violation
    /// (found by independent review) because the always-emitted
    /// `telemetry_spill`/`web::hub`/`web::store` runtime modules hardcode
    /// `SqlitePool` for their local spill/session persistence, independent
    /// of the app's `[database]` driver choice.
    #[test]
    fn db_cargo_toml_postgres_driver_enables_postgres_sqlx_feature() {
        let out = db_cargo_toml(
            &async_runtime_cargo_toml(CARGO_TOML).expect("async base"),
            DbDriver::Postgres,
        )
        .expect("db_cargo_toml(Postgres) must succeed");
        assert!(
            out.contains(r#"features = ["runtime-tokio-rustls", "sqlite", "postgres"]"#),
            "postgres driver must enable both the sqlite sqlx feature (always \
             needed by telemetry_spill/hub/store) and the postgres feature: {out}"
        );
    }

    /// The sqlite `config.rs` template is unchanged by this feature (byte
    /// containment check on the two symbols that matter for driver
    /// dispatch — the full file is covered by the existing runtime crate's
    /// own build).
    #[test]
    fn runtime_config_rs_sqlite_template_has_sqlite_types() {
        assert!(RUNTIME_CONFIG_RS_DB_SQLITE.contains("sqlx::sqlite::SqlitePool"));
        assert!(RUNTIME_CONFIG_RS_DB_SQLITE.contains("DB_USES_RETURNING_ID: bool = false"));
    }

    /// The new Postgres `config.rs` template must declare `PgPool`/`PgRow`
    /// and `DB_USES_RETURNING_ID = true` — the two symbols
    /// `db_insert_row`/`db_insert_fields` (Class 7 §4b) key their
    /// `RETURNING id` branch on.
    #[test]
    fn runtime_config_rs_postgres_template_has_postgres_types() {
        assert!(RUNTIME_CONFIG_RS_DB_POSTGRES.contains("sqlx::postgres::PgPool"));
        assert!(RUNTIME_CONFIG_RS_DB_POSTGRES.contains("sqlx::postgres::PgRow"));
        assert!(RUNTIME_CONFIG_RS_DB_POSTGRES.contains("DB_USES_RETURNING_ID: bool = true"));
        assert!(RUNTIME_CONFIG_RS_DB_POSTGRES.contains("id BIGSERIAL PRIMARY KEY"));
    }

    /// `RUNTIME_MOD_RS_WEB_APPEND` must re-export `WebReq` from the `web`
    /// module.
    ///
    /// Root cause: `db.rs` has `#[cfg(feature = "web")] impl IpeRow for
    /// super::WebReq` — `super::WebReq` means `ipe_runtime::WebReq`.  The
    /// runtime source's `mod.rs` uses `pub use web::*;` which surfaces `WebReq`
    /// (via `web/mod.rs`'s `pub use req::*;`).  The emitted project uses a
    /// selective export list; without `WebReq` a Db+Web program fails with E0412.
    #[test]
    fn web_mod_rs_exports_web_req() {
        assert!(
            RUNTIME_MOD_RS_WEB_APPEND.contains("WebReq"),
            "RUNTIME_MOD_RS_WEB_APPEND must re-export WebReq from the web module (E0412 fix): \
             {RUNTIME_MOD_RS_WEB_APPEND}"
        );
    }

    /// The emitted `mod.rs` must declare the crate-root modules the SERVER surface
    /// of `web/mod.rs` reaches by absolute path — `widget_assets` (`pub use
    /// crate::widget_assets;`), `js_port_glue` (`crate::js_port_glue::…`), and
    /// `js_port` (`crate::js_port::…`).  In the real crate the `web` feature pulls
    /// `widget-assets` (which also carries `js_port_glue`) and reaches `js_port`;
    /// the vendored trimmed `mod.rs` must declare the same closure or `web/mod.rs`
    /// fails E0432/E0433 (the module-set SEAL breach class caught by
    /// `seal_modset::cmd_publish_no_live_builds`).  The `web` module itself is
    /// declared by [`RUNTIME_MOD_RS_WEB_CORE_APPEND`] (shared with the webview
    /// render host, pushed BEFORE this append); each server-only crate-root
    /// module rides [`RUNTIME_MOD_RS_WEB_APPEND`] under `#[cfg(feature = "server")]`.
    #[test]
    fn web_mod_rs_declares_widget_assets_and_js_port_closure() {
        assert!(
            RUNTIME_MOD_RS_WEB_CORE_APPEND.contains("pub mod web;"),
            "RUNTIME_MOD_RS_WEB_CORE_APPEND must declare `pub mod web;` (the ONE real \
             web module shared by served-web and webview): {RUNTIME_MOD_RS_WEB_CORE_APPEND}"
        );
        for module in ["widget_assets", "js_port_glue", "js_port"] {
            let decl = format!("pub mod {module};");
            assert!(
                RUNTIME_MOD_RS_WEB_APPEND.contains(&decl),
                "RUNTIME_MOD_RS_WEB_APPEND must declare `{decl}` — web/mod.rs's server \
                 surface names `crate::{module}` by path (E0432/E0433 fix): \
                 {RUNTIME_MOD_RS_WEB_APPEND}"
            );
        }
    }

    /// `RUNTIME_MOD_RS_WEB_APPEND` must re-export `cmd_publish`,
    /// `cmd_publish_no_echo`, `pubsub_publish`, and `pubsub_publish_no_echo` so
    /// that emitted call sites resolve.  Without this the emitted project fails
    /// with E0425 — a seal violation.
    #[test]
    fn web_mod_rs_exports_cmd_publish_fns() {
        assert!(
            RUNTIME_MOD_RS_WEB_APPEND.contains("cmd_publish"),
            "RUNTIME_MOD_RS_WEB_APPEND must re-export cmd_publish (E0425 fix): \
             {RUNTIME_MOD_RS_WEB_APPEND}"
        );
        assert!(
            RUNTIME_MOD_RS_WEB_APPEND.contains("cmd_publish_no_echo"),
            "RUNTIME_MOD_RS_WEB_APPEND must re-export cmd_publish_no_echo (E0425 fix): \
             {RUNTIME_MOD_RS_WEB_APPEND}"
        );
        assert!(
            RUNTIME_MOD_RS_WEB_APPEND.contains("pubsub_publish"),
            "RUNTIME_MOD_RS_WEB_APPEND must re-export pubsub_publish (E0425 fix, #215): \
             {RUNTIME_MOD_RS_WEB_APPEND}"
        );
        assert!(
            RUNTIME_MOD_RS_WEB_APPEND.contains("pubsub_publish_no_echo"),
            "RUNTIME_MOD_RS_WEB_APPEND must re-export pubsub_publish_no_echo (E0425 fix, #215): \
             {RUNTIME_MOD_RS_WEB_APPEND}"
        );
    }

    /// One wrapper region built from a single generator BEGIN/END span with
    /// two `pub fn`s: `first` then `second`, wrapped exactly like
    /// `shake_ffi_by_fn_ident`'s doc comment describes.
    fn two_fn_region(first: &str, second: &str) -> String {
        format!(
            "// preamble\n\
             // IPE-FFI-WRAPPER BEGIN region\n\
             pub fn {first}(x: i64) -> i64 {{\n    x\n}}\n\
             pub fn {second}(x: i64) -> i64 {{\n    x\n}}\n\
             // IPE-FFI-WRAPPER END\n\
             // trailer\n"
        )
    }

    /// CO-BACKEND-007: a region with TWO `pub fn`s where only the FIRST is
    /// reached must stay KEPT — the last-fn-wins bug dropped it because the
    /// decision was overwritten by the second (unreached) fn's verdict.
    #[test]
    fn shake_keeps_region_when_only_the_first_of_two_fns_is_reached() {
        let source = two_fn_region("reached_fn", "unreached_fn");
        let reached: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::from(["reached_fn".to_owned()]);
        let out = shake_ffi_by_fn_ident(&source, &reached);
        assert!(
            out.contains("pub fn reached_fn"),
            "the reached fn's own wrapper must survive: {out}"
        );
        assert!(
            out.contains("pub fn unreached_fn"),
            "the whole region (both fns) must be kept once ANY fn in it is reached: {out}"
        );
    }

    /// Mirror case: only the SECOND of two fns is reached. Already passed
    /// under the old last-wins logic (the second fn's verdict IS the final
    /// one), but pins the same invariant from the other direction.
    #[test]
    fn shake_keeps_region_when_only_the_second_of_two_fns_is_reached() {
        let source = two_fn_region("unreached_fn", "reached_fn");
        let reached: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::from(["reached_fn".to_owned()]);
        let out = shake_ffi_by_fn_ident(&source, &reached);
        assert!(
            out.contains("pub fn reached_fn") && out.contains("pub fn unreached_fn"),
            "the whole region must be kept once ANY fn in it is reached: {out}"
        );
    }

    /// A `define.enum` region carries the `enum` definition PLUS one ctor per
    /// variant in a SINGLE sentinel span. Reaching just ONE variant forwarder
    /// must keep the whole region — the enum def and EVERY sibling ctor — or the
    /// kept forwarder references a dropped ctor / a missing type (a cargo-fail
    /// far from here). Proves the multi-ctor define.enum region is shake-safe.
    #[test]
    fn shake_keeps_the_whole_define_enum_region_when_one_variant_is_reached() {
        let source = "// preamble\n\
             // IPE-FFI-WRAPPER BEGIN message_new\n\
             #[derive(Clone, Debug)]\n\
             pub enum Message { Increment, Decrement }\n\
             pub fn demo_message_new_increment() -> Message { Message::Increment }\n\
             pub fn demo_message_new_decrement() -> Message { Message::Decrement }\n\
             // IPE-FFI-WRAPPER END\n\
             // trailer\n";
        // Only the Increment forwarder is reached by user code.
        let reached: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::from(["demo_message_new_increment".to_owned()]);
        let out = shake_ffi_by_fn_ident(source, &reached);
        assert!(
            out.contains("pub enum Message"),
            "enum def must survive: {out}"
        );
        assert!(
            out.contains("pub fn demo_message_new_increment"),
            "the reached variant ctor must survive: {out}"
        );
        assert!(
            out.contains("pub fn demo_message_new_decrement"),
            "the sibling ctor must survive so the kept region compiles: {out}"
        );
    }

    /// A region whose fns are ALL unreached is still dropped — the fix must
    /// not turn the shake into a no-op.
    #[test]
    fn shake_drops_region_when_no_fn_is_reached() {
        let source = two_fn_region("unreached_a", "unreached_b");
        let reached: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let out = shake_ffi_by_fn_ident(&source, &reached);
        assert!(
            !out.contains("pub fn unreached_a") && !out.contains("pub fn unreached_b"),
            "a region with no reached fn must be dropped: {out}"
        );
        assert!(
            out.contains("// preamble") && out.contains("// trailer"),
            "surrounding non-region text must survive untouched: {out}"
        );
    }

    /// THE SEAL (wasip1 link): the co-located WASI emit ships a target-scoped
    /// `.cargo/config.toml` that shadows a host-global native-linker
    /// `build.rustflags` (e.g. a mold link-arg `rust-lld` rejects). The array
    /// must be NON-empty (cargo treats an empty array as unset and falls back to
    /// `build.rustflags`), and it must key the `wasm32-wasip1` triple — not the
    /// browser `wasm32-unknown-unknown`.
    #[test]
    fn wasi_emit_ships_a_mold_escaping_target_scoped_cargo_config() {
        let mut files: BTreeMap<RelPath, String> = BTreeMap::new();
        insert_wasi_linker_config(&mut files).expect("fixed RelPath must validate");

        let cfg = files
            .get(&RelPath::new(".cargo/config.toml").expect("fixed RelPath"))
            .expect("WASI emit must ship .cargo/config.toml");

        assert!(
            cfg.contains("[target.wasm32-wasip1]"),
            "config must key the wasip1 triple, got: {cfg}"
        );
        assert!(
            cfg.contains("rustflags = [\"-C\", \"debuginfo=0\"]"),
            "rustflags must be a NON-empty array to shadow a host build.rustflags, got: {cfg}"
        );
        assert!(
            !cfg.contains("[]"),
            "an empty array would not override a host build.rustflags, got: {cfg}"
        );
    }
}

#[cfg(test)]
mod escape_toml_basic_tests {
    use super::{SafeTomlString, apply_cargo_name, escape_toml_basic};

    // ── escape_toml_basic exhaustiveness ────────────────────────────────────

    #[test]
    fn newline_is_escaped() {
        assert_eq!(escape_toml_basic("a\nb"), "a\\nb");
    }

    #[test]
    fn tab_is_escaped() {
        assert_eq!(escape_toml_basic("a\tb"), "a\\tb");
    }

    #[test]
    fn cr_is_escaped() {
        assert_eq!(escape_toml_basic("a\rb"), "a\\rb");
    }

    #[test]
    fn backspace_is_escaped() {
        assert_eq!(escape_toml_basic("a\x08b"), "a\\bb");
    }

    #[test]
    fn form_feed_is_escaped() {
        assert_eq!(escape_toml_basic("a\x0Cb"), "a\\fb");
    }

    #[test]
    fn backslash_is_escaped() {
        assert_eq!(escape_toml_basic("a\\b"), "a\\\\b");
    }

    #[test]
    fn double_quote_is_escaped() {
        assert_eq!(escape_toml_basic("a\"b"), "a\\\"b");
    }

    #[test]
    fn nul_byte_is_escaped_as_unicode() {
        assert_eq!(escape_toml_basic("a\x00b"), "a\\u0000b");
    }

    #[test]
    fn other_low_controls_are_escaped_as_unicode() {
        // U+001B (ESC) → 
        assert_eq!(escape_toml_basic("a\x1Bb"), "a\\u001Bb");
        // U+001F (US) → 
        assert_eq!(escape_toml_basic("a\x1Fb"), "a\\u001Fb");
    }

    #[test]
    fn del_is_escaped_as_unicode() {
        assert_eq!(escape_toml_basic("a\x7Fb"), "a\\u007Fb");
    }

    #[test]
    fn output_contains_no_raw_control_bytes() {
        // Every byte 0x00–0x1F and 0x7F must be absent from the output.
        for b in (0x00u8..=0x1F).chain(std::iter::once(0x7F)) {
            let raw = format!("pre{}post", char::from(b));
            let escaped = escape_toml_basic(&raw);
            assert!(
                escaped.chars().all(|c| (c as u32) >= 0x20 && c != '\x7F'),
                "control byte 0x{b:02X} survived escaping: {escaped:?}"
            );
        }
    }

    #[test]
    fn safe_path_is_byte_identical() {
        let path = "home/user/.cache/ipe/runtime";
        assert_eq!(escape_toml_basic(path), path);
    }

    #[test]
    fn existing_backslash_and_quote_cases_hold() {
        assert_eq!(escape_toml_basic("a\\b"), "a\\\\b");
        assert_eq!(escape_toml_basic("a\"b"), "a\\\"b");
    }

    // ── Round-trip: adversarial values parse back correctly ─────────────────
    // Proves that `path = "..."` built with the escaper is always valid TOML
    // and decodes to the original bytes (SEAL proof for the path splice).

    fn round_trip(raw: &str) -> String {
        // Build `v = "<escaped>"` and parse it with a hand-rolled TOML string
        // decoder that mirrors the TOML basic-string grammar — sufficient to
        // verify the emitted line without adding a `toml` dev-dependency.
        let body = escape_toml_basic(raw);
        // The output must contain no literal control byte.
        assert!(
            body.chars().all(|c| (c as u32) >= 0x20 && c != '\x7F'),
            "escaper left a control byte in output for input {raw:?}: {body:?}"
        );
        // Reconstruct the original by interpreting the escape sequences.
        let mut out = String::new();
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let next = chars.next();
                assert!(next.is_some(), "escape sequence must be complete");
                match next.unwrap_or('?') {
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    'b' => out.push('\x08'),
                    't' => out.push('\t'),
                    'n' => out.push('\n'),
                    'f' => out.push('\x0C'),
                    'r' => out.push('\r'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        let cp = u32::from_str_radix(&hex, 16);
                        assert!(cp.is_ok(), "\\uXXXX hex digits must be valid: {hex:?}");
                        let scalar = cp.ok().and_then(char::from_u32);
                        assert!(scalar.is_some(), "code point must be valid Unicode");
                        out.push(scalar.unwrap_or('\u{FFFD}'));
                    }
                    other => {
                        // The escaper only emits the named sequences above.
                        // An unknown letter here is a bug in escape_toml_basic.
                        assert!(
                            matches!(other, '\\' | '"' | 'b' | 't' | 'n' | 'f' | 'r' | 'u'),
                            "unexpected escape char from escaper: {other:?}"
                        );
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn newline_round_trips() {
        assert_eq!(round_trip("a\nb"), "a\nb");
    }

    #[test]
    fn tab_round_trips() {
        assert_eq!(round_trip("a\tb"), "a\tb");
    }

    #[test]
    fn cr_round_trips() {
        assert_eq!(round_trip("a\rb"), "a\rb");
    }

    #[test]
    fn nul_round_trips() {
        assert_eq!(round_trip("a\x00b"), "a\x00b");
    }

    #[test]
    fn escape_sequence_injection_attempt_is_inert() {
        // A path whose last segment looks like a TOML injection:
        // `"\"\n[dependencies]\nevil = \"1\"` cannot break out of its string.
        let adversarial = "/tmp/ip\ne\"\n[dependencies]\nevil = \"1\"";
        let body = escape_toml_basic(adversarial);
        // The rendered line must contain no literal newline.
        assert!(
            !body.contains('\n'),
            "newline survived into manifest body: {body:?}"
        );
        // And round-trips back to the original.
        assert_eq!(round_trip(adversarial), adversarial);
    }

    // ── apply_cargo_name safety ─────────────────────────────────────────────

    #[test]
    fn apply_cargo_name_with_adversarial_input_has_no_raw_newline() {
        let template = "name = \"ipe-app\"\n[dependencies]\n";
        let result = apply_cargo_name(template, &SafeTomlString::escape("evil\nname"));
        // The `name = "..."` line must not contain a literal newline inside the
        // quoted value.
        let name_line = result
            .lines()
            .find(|l| l.starts_with("name = "))
            .expect("name line is present");
        assert!(
            !name_line.contains('\n'),
            "raw newline in name line: {name_line:?}"
        );
        // The value must decode back to the original.
        assert_eq!(
            round_trip("evil\nname"),
            "evil\nname",
            "round-trip failed for adversarial name"
        );
    }

    #[test]
    fn apply_cargo_name_common_case_is_byte_identical() {
        let template = "name = \"ipe-app\"\n[dependencies]\n";
        let result = apply_cargo_name(template, &SafeTomlString::escape("my-app"));
        assert_eq!(result, "name = \"my-app\"\n[dependencies]\n");
    }
}

#[cfg(test)]
mod non_serde_tests {
    use std::collections::BTreeMap;

    use ipe_backend::RelPath;
    use ipe_diagnostics::DResult;
    use ipe_intern::Interner;
    use ipe_ir::{EnumDef, EnumPayloadTable, IrType, ModPath, Variant, enum_payload_table};

    use super::ir_type_contains_non_serde;

    #[test]
    fn enum_payload_non_serde_field_is_rejected() -> DResult<()> {
        let mut interner = Interner::new();
        let home = ModPath(vec![interner.intern("Main")?]);
        let vault = interner.intern("Vault")?;
        let sealed = interner.intern("Sealed")?;
        let tree = interner.intern("Tree")?;
        let node = interner.intern("Node")?;
        // type Vault = Sealed Secret
        // type Tree = Node Int (List Tree)
        let table = enum_payload_table(&[
            EnumDef {
                name: vault,
                home: home.clone(),
                type_params: Vec::new(),
                variants: vec![Variant {
                    name: sealed,
                    fields: vec![IrType::Secret],
                }],
            },
            EnumDef {
                name: tree,
                home: home.clone(),
                type_params: Vec::new(),
                variants: vec![Variant {
                    name: node,
                    fields: vec![
                        IrType::Int,
                        IrType::List(Box::new(IrType::Enum {
                            home: home.clone(),
                            name: tree,
                            args: Vec::new(),
                        })),
                    ],
                }],
            },
        ]);
        let vault_ty = IrType::Enum {
            home: home.clone(),
            name: vault,
            args: Vec::new(),
        };
        let tree_ty = IrType::Enum {
            home,
            name: tree,
            args: Vec::new(),
        };
        assert!(ir_type_contains_non_serde(&vault_ty, &table));
        assert!(ir_type_contains_non_serde(
            &IrType::Maybe(Box::new(vault_ty)),
            &table
        ));
        // A cyclic data-only ADT terminates and passes.
        assert!(!ir_type_contains_non_serde(&tree_ty, &table));
        Ok(())
    }

    #[test]
    fn data_leaves_pass_and_opaque_leaves_fail() {
        let table = EnumPayloadTable::new();
        assert!(!ir_type_contains_non_serde(
            &IrType::Dict(Box::new(IrType::Str), Box::new(IrType::Int)),
            &table
        ));
        assert!(ir_type_contains_non_serde(
            &IrType::Tuple(vec![IrType::Int, IrType::Db]),
            &table
        ));
        assert!(ir_type_contains_non_serde(
            &IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)),
            &table
        ));
    }

    /// A project of the given `(path, text)` files.
    fn project_of(files: &[(&str, &str)]) -> ipe_backend::EmittedProject {
        let mut map = BTreeMap::new();
        for (path, text) in files {
            let Ok(path) = RelPath::new(*path) else {
                return ipe_backend::EmittedProject {
                    files: BTreeMap::new(),
                    cargo_toml: String::new(),
                    uses_webview: false,
                };
            };
            map.insert(path, (*text).to_owned());
        }
        ipe_backend::EmittedProject {
            files: map,
            cargo_toml: String::new(),
            uses_webview: false,
        }
    }

    /// The output-side lexable seal `emit_program` ends with refuses a raw bidi
    /// control and a bare CR in any emitted `.rs` file, naming the codepoint as
    /// `U+XXXX` and never raw; a clean project, CRLF and a hazard in a
    /// non-Rust file are accepted.
    #[test]
    fn emit_program_refuses_a_raw_lexer_hazard() {
        for (path, text, shown) in [
            (
                "src/main.rs",
                "fn main() { let _ = \"a\u{202E}b\"; }\n",
                "U+202E",
            ),
            (
                "src/ipe_runtime/x.rs",
                "// line one\rpub fn f() {}\n",
                "U+000D",
            ),
            (
                "src/ipe_mods/upper.RS",
                "pub fn g() { let _ = \"\u{2066}\"; }\n",
                "U+2066",
            ),
        ] {
            let project = project_of(&[("src/lib_ok.rs", "pub fn ok() {}\n"), (path, text)]);
            assert_eq!(project.files.len(), 2, "{path}");
            let refused = super::refuse_lexer_hazards(&project);
            assert!(
                matches!(
                    &refused,
                    Err(ipe_diagnostics::Diagnostic::CompilerBug { where_, detail })
                        if *where_ == ipe_intern::EMIT_LEXABLE
                            && detail.contains(shown)
                            && detail.contains(path)
                            && ipe_intern::find_lexer_hazard(detail).is_none()
                ),
                "{path}: {refused:?}"
            );
        }
        let clean = project_of(&[
            (
                "src/main.rs",
                "fn main() {\r\n    let _ = \"\\u{202e}\";\r\n}\r\n",
            ),
            ("assets/notes.txt", "a\u{202E}b\r"),
        ]);
        assert_eq!(clean.files.len(), 2);
        assert!(super::refuse_lexer_hazards(&clean).is_ok());
    }
}
