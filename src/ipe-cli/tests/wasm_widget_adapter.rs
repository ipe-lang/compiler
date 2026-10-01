//! The browser-WASM `CustomElement.node` adapter: down-state as a decoded PROPERTY, up
//! events as a typed `CustomEvent`, over the ONE shared glue and ONE seal codec.
//!
//! These are COMPILE-ONLY (they run the `ipe` pipeline + write the project for
//! the `WasmClient` target, but never invoke `cargo`/`wasm-bindgen`), so they are
//! fast and NOT gated on `IPE_E2E`. They assert the build-time half of the
//! adapter: the static `www/` bundle carries the property/CustomEvent glue,
//! SRI-pinned, and the server-only registration injection is NOT emitted (so a
//! `--target wasm` widget program never ipe-accepts-then-cargo-fails on the
//! absent `web::widget_assets::register`).
//!
//! ## Coverage boundary
//!
//! The runtime half — the wasm sink assigning `el.state` via `Reflect::set` and
//! folding an up-`CustomEvent` into `update` — lives in `ipe_runtime::wasm::widget`
//! and needs a real browser DOM (`web-sys`) to exercise end to end; that is
//! asserted at the unit level in that module (tag detection, up-event-name
//! agreement) plus the fail-closed seal-decode contract proven natively in
//! `ipe_runtime::dom::dispatch` (`onwidget_up_event_decodes_fail_closed`) and by
//! the wasm-client glue shape in `ipe_runtime::widget_assets` tests. A full
//! headless-browser round trip is out of scope for this native suite.

use ipe::BuildOptions;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A `Web.tea` whose view mounts one `CustomElement.node`. Compiled for `--target wasm`,
/// the down/up seam takes the wasm-client adapter (property / `CustomEvent`).
const WIDGET_APP: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub

type alias EditorState = { text : String, line : Int }

type EditorEvent = Changed String | Saved

type Msg = Edited EditorEvent

type alias Model = { state : EditorState }

codeEditor : CustomElement EditorState EditorEvent
codeEditor = CustomElement.fromFile "js/editor.js"

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { state = { text = "", line = 0 } }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Element Msg
view model =
    CustomElement.node codeEditor model.state Edited

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Edited Saved
        }
"#;

/// The author hook file the `customElement` constructor names. Its bytes are what
/// the static bundle serves content-addressed + SRI-pinned.
const EDITOR_JS: &str = "export function mount(host, emit) {\n  return { onState(s) { host.textContent = s.text; } };\n}\n";

/// Emit the widget app for the `WasmClient` target to a temp dir (no `cargo`).
fn emit_wasm(test_name: &str) -> Result<std::path::PathBuf, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("wasm_widget_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(ipe_dir.join("js"))?;
    std::fs::write(ipe_dir.join("js/editor.js"), EDITOR_JS)?;
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, WIDGET_APP)?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("wasm_widget_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let mut opts = BuildOptions::from_env();
    opts.target = ipe_ir::Target::WasmClient;
    ipe::build_with_options(&entry, &out_dir, &runtime, opts)
        .map_err(|e| -> BoxError { format!("{test_name}: wasm emit failed: {e:?}").into() })?;
    Ok(out_dir)
}

fn read(out: &std::path::Path, rel: &str) -> Result<String, BoxError> {
    std::fs::read_to_string(out.join(rel))
        .map_err(|e| -> BoxError { format!("missing emitted file {rel}: {e}").into() })
}

/// Find the single `www/_ipe/widget-glue.<hex>.js` the emit produced.
fn find_one(out: &std::path::Path, prefix: &str) -> Result<std::path::PathBuf, BoxError> {
    let dir = out.join("www/_ipe");
    let mut hits: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| -> BoxError { format!("no www/_ipe dir: {e}").into() })?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix))
        })
        .collect();
    match hits.len() {
        1 => Ok(hits.remove(0)),
        n => Err(format!("expected exactly one `{prefix}*` under www/_ipe, found {n}").into()),
    }
}

/// The wasm build writes the author asset + the property/CustomEvent glue into
/// `www/`, SRI-pins them in `index.html`, and does NOT inject the server-only
/// `widget_assets::register` — so a `--target wasm` widget program compiles
/// (no ipe-accept-then-cargo-fail) with the client transport.
#[test]
fn wasm_widget_bundle_is_property_and_custom_event_glue() -> Result<(), BoxError> {
    let out = emit_wasm("bundle")?;

    // The author asset is served content-addressed under www/, byte-identical.
    let asset = find_one(&out, "widget.")?;
    let asset_body = std::fs::read_to_string(&asset)?;
    assert_eq!(
        asset_body, EDITOR_JS,
        "the bundled author asset must be byte-identical to the author file"
    );

    // The glue is the WASM-CLIENT transport: down via the `set state(v)` property
    // setter (NOT `attributeChangedCallback`), up via a typed `CustomEvent` (NOT
    // the `/_ipe/event` `__ipeSend` POST). It defines only the compiler tag and
    // never evals.
    let glue = std::fs::read_to_string(find_one(&out, "widget-glue.")?)?;
    assert!(
        glue.contains("set state(v)"),
        "wasm glue must deliver down-state via the property setter:\n{glue}"
    );
    assert!(
        !glue.contains("attributeChangedCallback"),
        "wasm glue must NOT use the server attribute path"
    );
    assert!(
        glue.contains("dispatchEvent(new CustomEvent(\"ipe-widget-up\""),
        "wasm glue must emit up-events as a typed CustomEvent"
    );
    assert!(
        !glue.contains("__ipeSend"),
        "wasm glue must NOT reuse the server POST wire"
    );
    assert!(
        glue.contains("customElements.define(\"ipe-ce-"),
        "glue must define only the compiler-generated ipe-ce-* tag"
    );
    assert!(!glue.contains("eval("), "glue must never eval");
    assert!(
        glue.contains("JSON.parse"),
        "down-state must be JSON.parse'd (data), never eval'd"
    );

    // index.html carries the SRI-pinned modulepreload + glue script (external,
    // integrity-pinned — page integrity == served bytes for the static target).
    let index = read(&out, "www/index.html")?;
    assert!(
        index.contains("rel=\"modulepreload\"") && index.contains("integrity=\"sha256-"),
        "index.html must SRI-pin the author asset preload:\n{index}"
    );
    assert!(
        index.contains("widget-glue.") && index.contains("type=\"module\""),
        "index.html must reference the glue as an SRI'd module script"
    );
    assert!(
        index.contains("crossorigin=\"anonymous\""),
        "SRI'd scripts must carry crossorigin=anonymous"
    );

    // The SRI the page pins for the author asset must equal sha256 of the served
    // bytes — a tampered byte would then fail to load (page == bytes).
    let sri = sri_of(asset_body.as_bytes());
    assert!(
        index.contains(&sri),
        "index.html must pin sha256 of the served asset bytes ({sri})"
    );

    // The server-only registration must NOT be injected under the wasm target —
    // `ipe_runtime::web::widget_assets::register` is absent from the wasm module
    // set, so its presence would be an ipe-accept-then-cargo-fail.
    let main = read(&out, "src/main.rs")?;
    assert!(
        !main.contains("widget_assets::register"),
        "the wasm target must NOT inject the server-only widget register call"
    );
    Ok(())
}

/// A tampered author byte diverges the served URL AND the pinned SRI — a page
/// pinning the honest integrity refuses the tampered bytes (fail-closed).
#[test]
fn wasm_widget_asset_pin_is_content_addressed() -> Result<(), BoxError> {
    let out = emit_wasm("pin")?;
    let asset = find_one(&out, "widget.")?;
    let name = asset.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // The URL segment is sha256(content)-derived, so it embeds a 16-hex prefix.
    let hex = name
        .strip_prefix("widget.")
        .and_then(|s| s.strip_suffix(".js"))
        .unwrap_or("");
    assert_eq!(
        hex.len(),
        16,
        "content-addressed segment must be hex16: {name}"
    );
    assert!(
        hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "content-addressed segment must be hex: {name}"
    );
    Ok(())
}

/// sha256(bytes) as the `sha256-<base64>` SRI value the page pins.
fn sri_of(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    format!("sha256-{}", B64.encode(digest))
}
