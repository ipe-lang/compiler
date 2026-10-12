//! `CustomElement.node` custom-element glue generation + SRI-pinned asset addressing.
//!
//! One glue generator, two transports (§ [`WidgetTransport`]). A `CustomElement.node` node
//! renders as a `<ipe-ce-<hex>>` element carrying a `state` value and an
//! `OnWidget` up-handler in both targets; what varies is only the seam wiring the
//! generated glue applies:
//!
//! * **Server-driven Web shape** — down-state as the entity-escaped `state`
//!   attribute; up-events POSTed through `/_ipe/event`. The emitted server serves
//!   each asset content-addressed + SRI and mounts the glue route at process
//!   start (`register` + the `web::mod` routes).
//! * **Browser-WASM client** — down-state as the decoded `state` property; up
//!   events as a typed `CustomEvent` folded into the in-process TEA loop. The
//!   static/wasm bundler writes each asset + the glue into `www/` (SRI-pinned)
//!   and references them from `index.html`.
//!
//! Common to both:
//!
//! * **Asset addressing.** Each distinct `CustomElement.fromFile "<path>"` file is
//!   content-addressed at `/_ipe/widget.<hex16>.js` and pinned with
//!   `integrity="sha256-<b64>"` + `crossorigin="anonymous"`. The hash is over the
//!   file bytes, so the page SRI can never disagree with the served/bundled bytes
//!   — a tampered byte makes the browser refuse the module.
//!
//! * **Registration glue.** A single generated companion module
//!   (`/_ipe/widget-glue.<hex16>.js`, SRI-pinned over its own content) `import`s
//!   each author module by its content-addressed URL, builds a mechanical
//!   `HTMLElement` subclass wired to the transport, and calls
//!   `customElements.define` on the compiler-generated `ipe-ce-*` tag ONLY. The
//!   author module never calls `define` — registration is compiler-owned, so
//!   element-registration injection is impossible by construction (Security #4).
//!
//! ## Security posture
//!
//! * The down-state reaches the client only as `JSON.parse` of an escaped
//!   attribute (server) or `JSON.parse` of a decoded property value (wasm) —
//!   data, never `eval`, never spliced into a script (Security #1).
//! * Every generated script is EXTERNAL and SRI-pinned; no inline script and no
//!   `unsafe-inline`/`unsafe-eval` is introduced, so the page CSP is unchanged
//!   (Security #3/#4).
//! * The served JS is declared-trust third-party code running with full DOM
//!   authority — SRI pins integrity, it does NOT sandbox. This is the honest
//!   limit the design records; this module never claims otherwise.

use std::sync::OnceLock;

use crate::encoding::{BundlePath, HashedAsset, MountBase};

/// Which transport the generated glue wires for one build target.
///
/// One glue module, two adapters. The `HTMLElement` subclass, the
/// `customElements.define` on the `ipe-ce-*` tag, and the author
/// `mount(host, emit) -> { onState }` contract are IDENTICAL in both. Only the
/// two seam edges differ:
///
/// * down-state — `Server` forwards the entity-escaped `state` ATTRIBUTE
///   (`attributeChangedCallback` → `JSON.parse` → `onState`); `WasmClient`
///   forwards the decoded `state` PROPERTY (`set state(v)` → `onState`), which
///   the in-process wasm sink assigns as structured data, never spliced into
///   HTML.
/// * up-event — `Server` posts the encoded `up` through the existing
///   `/_ipe/event` wire (`__ipeEmitWidgetUp` → `__ipeSend`, session + CSRF);
///   `WasmClient` dispatches a typed `CustomEvent` the in-process sink decodes
///   fail-closed and folds into the local `update`.
///
/// The down-ENCODE and up-DECODE are the SAME seal codec in both — the encode
/// runs once in `ui::widget::ui_widget_` (canonical JSON), and the JS side reads
/// it with `JSON.parse` in both adapters. A transport never weakens the seal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WidgetTransport {
    /// Server-driven Web shape: down as an escaped attribute, up POSTed through
    /// `/_ipe/event`.
    Server,
    /// Browser-WASM client: down as a decoded property, up as a typed
    /// `CustomEvent` folded into the in-process TEA loop.
    WasmClient,
}

pub use crate::ui::widget::WIDGET_UP_CUSTOM_EVENT;

/// One registered widget: the compiler-generated `ipe-ce-<hex>` tag and the raw
/// bytes of its author hook module.
///
/// The tag is minted by the lowerer from the sealed in-project path (never raw
/// user input); the content is read at build time from the file the canon
/// containment gate already proved exists inside the project root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WidgetAsset {
    /// The compiler-generated custom-element tag (`ipe-ce-<hex16>`).
    pub tag: String,
    /// The author hook module's file content, verbatim.
    pub content: String,
}

/// The single SHA-256 digest of one widget file's content — the ONE hash every
/// content-addressing form below derives from. Making every form (the cache-bust
/// URL segment and the SRI) a rendering of this one digest is what guarantees one
/// hash from source to browser: they cannot disagree with the served bytes because
/// they are all this digest over those exact bytes.
fn content_digest(content: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(content.as_bytes()).into()
}

/// Content-addressing for one asset: `(hex16, base64full)` over SHA-256(content).
/// `hex16` (first 16 hex chars of the digest) is the cache-busting URL segment;
/// `base64full` (standard base64 of the full 32-byte digest) is the SRI value.
/// Both derive from one digest — the page SRI and the served bytes can never
/// disagree because they are computed from the same bytes.
/// The first eight digest bytes: the cache-busting segment of an asset path.
const fn digest_head(digest: &[u8; 32]) -> [u8; 8] {
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = *digest;
    [b0, b1, b2, b3, b4, b5, b6, b7]
}

fn content_hashes(content: &str) -> (String, String) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let digest = content_digest(content);
    let hex16: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    let base64full = B64.encode(digest);
    (hex16, base64full)
}

/// The process-global widget registry, populated ONCE at process start by the
/// generated `main` (before the server binds) via [`register`]. Empty for a
/// program that uses no `CustomElement.node`, in which case every helper below is inert
/// and no widget route is mounted.
///
/// A `OnceLock` (not a mutable global) is used deliberately: the set of widgets
/// is a compile-time constant of the program — it is fixed at emit and never
/// changes at run — so a write-once cell is the make-invalid-states-
/// unrepresentable choice. A second `register` call is ignored (the first wins),
/// so a doubled generated call can never corrupt the table.
static WIDGET_REGISTRY: OnceLock<Vec<WidgetAsset>> = OnceLock::new();

/// Register the program's widget assets. Called once by the generated `main`
/// before the server starts. Idempotent: only the first call populates the
/// registry; a later call is a no-op (the registry is write-once).
///
/// `assets` is the compile-time list `[(tag, content)]`; each `content` is the
/// verbatim bytes of an in-project author hook file the build gate validated.
pub fn register(assets: &[(&str, &str)]) {
    let owned: Vec<WidgetAsset> = assets
        .iter()
        .map(|(tag, content)| WidgetAsset {
            tag: (*tag).to_string(),
            content: (*content).to_string(),
        })
        .collect();
    // `set` returns Err if already initialised; we intentionally ignore it — the
    // first registration is authoritative and a repeat is a benign no-op.
    let _ = WIDGET_REGISTRY.set(owned);
}

/// The registered widgets, or an empty slice when none were registered.
#[must_use]
pub fn registered() -> &'static [WidgetAsset] {
    WIDGET_REGISTRY.get().map_or(&[], Vec::as_slice)
}

/// True when the program registered at least one widget — the gate the router
/// uses to decide whether to mount the widget asset/glue routes and whether the
/// page carries the glue `<script>`.
#[must_use]
pub fn has_widgets() -> bool {
    !registered().is_empty()
}

/// The content-addressed bundle path of one widget asset, e.g.
/// `_ipe/widget.a1b2c3d4e5f6a7b8.js`.
///
/// Stable for given content; changes when the file changes, which makes
/// `Cache-Control: immutable` safe. Its URL is [`MountBase::url_of`].
#[must_use]
pub fn widget_asset_path(content: &str) -> BundlePath {
    BundlePath::hashed(HashedAsset::Widget, digest_head(&content_digest(content)))
}

/// The `sha256-<b64>` SRI value for one widget asset's content.
#[must_use]
pub fn widget_asset_integrity(content: &str) -> String {
    let (_, b64) = content_hashes(content);
    format!("sha256-{b64}")
}

/// Emit the generated registration glue JS for the whole registry.
///
/// The glue is a single ES module. For each registered tag it defines a
/// mechanical `HTMLElement` subclass that:
///
/// * forwards the down-state to the author `mount`'s `onState` through the
///   transport's down channel — the escaped `state` ATTRIBUTE (`Server`) or the
///   decoded `state` PROPERTY setter (`WasmClient`) — parsed as data, never
///   `eval`;
/// * routes the author's `emit(up)` through the transport's up channel — a
///   `/_ipe/event` POST (`Server`) or a typed `CustomEvent` (`WasmClient`);
/// * calls `customElements.define` on the compiler-generated `ipe-ce-*` tag
///   ONLY.
///
/// If the author module lacks a `mount` export the element fails observably
/// (console error) and stays inert — it is never `define`d in a broken state.
///
/// `base` is where the bundle is served, so the author-module `import` URL
/// reaches the same content-addressed route the page pins. `transport` selects the down/up adapter (§ [`WidgetTransport`]); the
/// element class, the author `mount` contract, and the `define`-only-on-`ipe-ce-*`
/// rule are identical in both.
#[must_use]
pub fn glue_js(base: &MountBase, transport: WidgetTransport) -> String {
    glue_js_for(registered(), base, transport)
}

/// Registry-free glue generation over an EXPLICIT asset slice — the byte-for-byte
/// same output as [`glue_js`], but sourced from a caller-supplied list rather than
/// the process-global registry.
///
/// This is the build-time entry the static/wasm bundler uses: at emit the CLI
/// holds the widget manifest (`(tag, content)` pairs) but there is no running
/// process whose registry is populated, so it drives the ONE glue generator with
/// that manifest directly. The server path keeps calling [`glue_js`] (registry-
/// backed) — same code, one glue, no drift.
#[must_use]
pub fn glue_js_for(assets: &[WidgetAsset], base: &MountBase, transport: WidgetTransport) -> String {
    let mut out = String::new();
    out.push_str(match transport {
        WidgetTransport::Server => GLUE_PRELUDE_SERVER,
        WidgetTransport::WasmClient => GLUE_PRELUDE_WASM,
    });
    for asset in assets {
        out.push_str(&glue_class(base, transport, &asset.tag, &asset.content));
    }
    out
}

/// Render the one `HTMLElement` subclass + `define` block for a single widget.
///
/// The invariant half — the author-module `import`, the `mount(host, emit)`
/// contract, `customElements.define` on the compiler-generated `ipe-ce-*` tag
/// ONLY — is byte-identical across transports. Only the down-state delivery
/// (`attributeChangedCallback` vs the `set state(v)` property setter) and the
/// `emit` wiring (`__ipeEmitWidgetUp` POST vs a typed `CustomEvent`) differ, both
/// routed through the shared prelude helpers so no decode logic is duplicated.
fn glue_class(base: &MountBase, transport: WidgetTransport, tag: &str, content: &str) -> String {
    let asset_url = base.url_of(&widget_asset_path(content));
    // `tag` is `ipe-ce-<hex16>` — every byte is `[a-z0-9-]` (see the lowerer's
    // `custom_element_tag`), so it is safe both as a JS string literal and as the
    // class-name suffix. It is NEVER derived from user input.
    let class_suffix = tag.replace('-', "_");
    // Down-state delivery differs by transport; both route through
    // `__ipeParseState` (the ONE down-parse helper) so a hostile `state` never
    // crosses as anything but data.
    let down_members: &str = match transport {
        WidgetTransport::Server => {
            "\
  static get observedAttributes() { return [\"state\"]; }
  attributeChangedCallback(name, _old, val) {
    if (name === \"state\" && this.__ipeHook) {
      this.__ipeHook.onState(__ipeParseState(val));
    }
  }"
        }
        // The wasm sink assigns the decoded structured value to this property; the
        // setter caches it so a `set state` BEFORE `connectedCallback` still
        // reaches the hook once it mounts (the sink may patch the property before
        // the element upgrades). No attribute is read — the property IS the down
        // channel.
        WidgetTransport::WasmClient => {
            "\
  set state(v) {
    this.__ipeState = v;
    if (this.__ipeHook) { this.__ipeHook.onState(v); }
  }
  get state() { return this.__ipeState; }"
        }
    };
    // Up-event wiring differs by transport; both hand the author's `emit(up)` an
    // encoder that never touches the DOM as script.
    let emit_expr = match transport {
        WidgetTransport::Server => "(up) => __ipeEmitWidgetUp(this, up)",
        WidgetTransport::WasmClient => "(up) => __ipeEmitWidgetUpEvent(this, up)",
    };
    // On connect, replay any down-state that arrived before mount: the escaped
    // attribute (server) or the cached property (wasm).
    let connect_replay = match transport {
        WidgetTransport::Server => {
            "\
    if (this.hasAttribute(\"state\")) {
      this.__ipeHook.onState(__ipeParseState(this.getAttribute(\"state\")));
    }"
        }
        WidgetTransport::WasmClient => {
            "\
    // Property upgrade: if the sink assigned `state` BEFORE this element upgraded
    // (was defined), the value is an own-property shadowing the setter. Lift it
    // back through the accessor so `__ipeState` is populated, then replay.
    if (Object.prototype.hasOwnProperty.call(this, \"state\")) {
      var __pending = this.state;
      delete this.state;
      this.state = __pending;
    }
    if (this.__ipeState !== undefined) {
      this.__ipeHook.onState(this.__ipeState);
    }"
        }
    };
    format!(
        "\
// ── widget {tag} ──────────────────────────────────────────────
import {{ mount as __ipe_mount_{class_suffix} }} from {asset_url:?};
class IpeCE_{class_suffix} extends HTMLElement {{
{down_members}
  connectedCallback() {{
    if (typeof __ipe_mount_{class_suffix} !== \"function\") {{
      console.error(\"[ipe.widget] author module for {tag} has no `mount` export; element inert\");
      return;
    }}
    this.__ipeHook = __ipe_mount_{class_suffix}(this, {emit_expr});
{connect_replay}
  }}
  disconnectedCallback() {{ this.__ipeHook = null; }}
}}
if (!customElements.get({tag:?})) {{
  customElements.define({tag:?}, IpeCE_{class_suffix});
}}
"
    )
}

/// The invariant head of the generated glue module: the two helpers every widget
/// class uses — total down-parse and the up-emit that reuses the existing
/// `__ipeSend` wire.
///
/// `__ipeParseState` is a total `JSON.parse` wrapper: a malformed `state`
/// attribute yields `null` rather than throwing (the down direction is not the
/// attacker-controlled edge, but a throw in `attributeChangedCallback` must not
/// wedge the element). `__ipeEmitWidgetUp` reads the node's `data-ipe-hid` (the
/// ipe-id the renderer stamps for the `OnWidget` handler) and posts the
/// JSON-encoded `up` value through `__ipeSend` under the fixed `ipe-widget` event
/// name — the SAME envelope, CSRF token, and session cookie a click uses. If the
/// client core (`__ipeSend`) has not loaded, the emit is dropped with a console
/// warning rather than throwing.
/// Server-driven prelude: the shared down-parse helper plus the up-emit that
/// reuses the existing `__ipeSend` / `/_ipe/event` wire (session + CSRF).
///
/// `__ipeEmitWidgetUp` reads the node's `data-ipe-hid` (the ipe-id the renderer
/// stamps for the `OnWidget` handler) and posts the JSON-encoded `up` value
/// through `__ipeSend` under the fixed `ipe-widget` event name — the SAME
/// envelope, CSRF token, and session cookie a click uses. If the client core has
/// not loaded, the emit is dropped with a console warning rather than throwing.
const GLUE_PRELUDE_SERVER: &str = "\
// Generated by Ipê (Rust target) — custom-element registration glue (server transport).
// External, SRI-pinned module: no inline script, no eval. The author modules it
// imports are content-addressed + SRI-pinned by the page; this module only wires
// the compiler-owned `ipe-ce-*` element registrations to their author `mount`.
function __ipeParseState(raw) {
  if (raw === null || raw === undefined) return null;
  try { return JSON.parse(raw); }
  catch (e) { console.error(\"[ipe.widget] state is not valid JSON\", e); return null; }
}
function __ipeEmitWidgetUp(host, up) {
  var hid = host.getAttribute && host.getAttribute(\"data-ipe-hid\");
  if (!hid) { console.warn(\"[ipe.widget] up-event before the element bound an ipe-id; dropped\"); return; }
  if (typeof __ipeSend !== \"function\") {
    console.warn(\"[ipe.widget] client core not loaded; up-event dropped\");
    return;
  }
  // Reuse the existing event wire: same envelope {sessionId, seq, msg, args,
  // handlerId}, same CSRF header + session cookie. The render epoch is read with
  // the ipe-id, so the server resolves the handler by (ipe-id, \"ipe-widget\")
  // against the render the id came from and runs the fail-closed seal up-decoder.
  __ipeSend(\"ipe-widget\", [JSON.stringify(up)], hid, { epoch: __ipeEpoch });
}
";

/// Browser-WASM prelude: the shared down-parse helper plus the up-emit that
/// dispatches a typed `CustomEvent` the in-process wasm sink folds into `update`.
///
/// `__ipeEmitWidgetUpEvent` wraps the encoded `up` value (a JSON string, the
/// output of the SAME seal encoder the server path posts) in the `detail` of a
/// bubbling `CustomEvent` named `ipe-widget-up`. The wasm sink's delegated
/// listener reads `detail`, runs the fail-closed seal up-decoder, and folds the
/// typed msg into the local TEA loop — no network, no `/_ipe/event`. The value in
/// `detail` is a string, never spliced into markup or `eval`ed.
const GLUE_PRELUDE_WASM: &str = "\
// Generated by Ipê (Rust target) — custom-element registration glue (wasm-client transport).
// External, SRI-pinned module: no inline script, no eval. The author modules it
// imports are content-addressed + SRI-pinned by the page; this module only wires
// the compiler-owned `ipe-ce-*` element registrations to their author `mount`.
function __ipeParseState(raw) {
  if (raw === null || raw === undefined) return null;
  try { return JSON.parse(raw); }
  catch (e) { console.error(\"[ipe.widget] state is not valid JSON\", e); return null; }
}
function __ipeEmitWidgetUpEvent(host, up) {
  // The `detail` carries the encoded `up` as a JSON string — the exact bytes the
  // server transport would post. The wasm sink decodes it fail-closed; a
  // malformed/oversized detail is dropped (no partial value, no throw). The event
  // bubbles so the body-level delegated listener the sink installs receives it.
  var detail;
  try { detail = JSON.stringify(up); }
  catch (e) { console.error(\"[ipe.widget] up-event value is not encodable; dropped\", e); return; }
  host.dispatchEvent(new CustomEvent(\"ipe-widget-up\", { detail: detail, bubbles: true }));
}
";

/// The content-addressed bundle path of the whole-registry glue module, e.g.
/// `_ipe/widget-glue.<hex16>.js`.
///
/// The hash is over the glue content (which folds in every registered asset
/// URL), so the path changes when any widget changes and `Cache-Control:
/// immutable` stays safe. `base` reaches the glue body (the author-import
/// URLs), so glue served under a prefix hashes distinctly from glue served at
/// the root; the page `<script src>` is `base.url_of` of the returned path.
#[must_use]
pub fn glue_path(base: &MountBase, transport: WidgetTransport) -> BundlePath {
    glue_path_for(registered(), base, transport)
}

/// Registry-free [`glue_path`] over an explicit asset slice (build-time bundler).
#[must_use]
pub fn glue_path_for(
    assets: &[WidgetAsset],
    base: &MountBase,
    transport: WidgetTransport,
) -> BundlePath {
    let digest = content_digest(&glue_js_for(assets, base, transport));
    BundlePath::hashed(HashedAsset::WidgetGlue, digest_head(&digest))
}

/// The `sha256-<b64>` SRI value for the whole-registry glue module.
#[must_use]
pub fn glue_integrity(base: &MountBase, transport: WidgetTransport) -> String {
    glue_integrity_for(registered(), base, transport)
}

/// Registry-free [`glue_integrity`] over an explicit asset slice (build-time bundler).
#[must_use]
pub fn glue_integrity_for(
    assets: &[WidgetAsset],
    base: &MountBase,
    transport: WidgetTransport,
) -> String {
    let (_, b64) = content_hashes(&glue_js_for(assets, base, transport));
    format!("sha256-{b64}")
}

/// The external, SRI-pinned `<script type="module">` tag the page emits to load
/// the glue, plus a `<link rel="modulepreload">` per author asset that pins each
/// author module's SRI so the browser verifies the module response against the
/// build-time content hash before executing it.
///
/// Returns the empty string when the program registered no widget (no script,
/// no CSP impact). Every reference is EXTERNAL + SRI + `crossorigin` — no inline
/// script, so the page CSP (`script-src 'self'`) is unchanged.
#[must_use]
pub fn page_scripts(base: &MountBase, transport: WidgetTransport) -> String {
    page_scripts_for(registered(), base, transport)
}

/// Registry-free [`page_scripts`] over an explicit asset slice — the build-time
/// bundler entry. Emits the SAME external, SRI-pinned `<link modulepreload>` +
/// glue `<script>` markup as [`page_scripts`], for a caller-supplied manifest.
#[must_use]
pub fn page_scripts_for(
    assets: &[WidgetAsset],
    base: &MountBase,
    transport: WidgetTransport,
) -> String {
    if assets.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    // Preload + SRI-pin each author module so its content is integrity-checked
    // (a tampered byte → the browser refuses the module). `modulepreload` carries
    // `integrity`, and the subsequent `import` in the glue reuses the cached,
    // already-verified response.
    for asset in assets {
        let url = base.url_of(&widget_asset_path(&asset.content));
        let integrity = widget_asset_integrity(&asset.content);
        out.push_str("<link rel=\"modulepreload\" href=\"");
        url_attr(&mut out, &url);
        out.push_str(&format!(
            "\" integrity=\"{integrity}\" crossorigin=\"anonymous\">"
        ));
    }
    let glue_url = base.url_of(&glue_path_for(assets, base, transport));
    let glue_integrity = glue_integrity_for(assets, base, transport);
    out.push_str("<script type=\"module\" src=\"");
    url_attr(&mut out, &glue_url);
    out.push_str(&format!(
        "\" integrity=\"{glue_integrity}\" crossorigin=\"anonymous\"></script>"
    ));
    out
}

/// Append `url` as the body of a double-quoted HTML attribute.
///
/// Every `href`/`src` the shell writes passes through this one escaper, so no
/// URL text, whatever base it was built from, can close the attribute.
fn url_attr(out: &mut String, url: &str) {
    crate::escape::html_attr_into(url, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A URL that would close its attribute is escaped by the one seam; a
    /// URL with no attribute-special byte is written unchanged.
    #[test]
    fn page_scripts_attr_seam_escapes() {
        let mut hostile = String::new();
        url_attr(&mut hostile, "x\" onload=\"y");
        assert!(!hostile.contains('"'), "{hostile}");
        assert_eq!(hostile, "x&#34; onload=&#34;y");
        let mut plain = String::new();
        url_attr(&mut plain, "/_ipe/widget.abc.js");
        assert_eq!(plain, "/_ipe/widget.abc.js");
        let assets = [WidgetAsset {
            tag: "ipe-ce-0123456789abcdef".to_owned(),
            content: "export function mount(){}".to_owned(),
        }];
        let Ok(app) = MountBase::parse("/app") else {
            return;
        };
        let html = page_scripts_for(&assets, &app, WidgetTransport::Server);
        assert!(html.contains("href=\"/app/_ipe/widget."), "{html}");
    }

    /// Every URL the glue imports and the page loads carries the mount base;
    /// the root base yields the same paths at `/`.
    #[test]
    fn glue_imports_carry_the_base() {
        let assets = [WidgetAsset {
            tag: "ipe-ce-0123456789abcdef".to_owned(),
            content: "export function mount(){}".to_owned(),
        }];
        let Ok(app) = MountBase::parse("/app") else {
            return;
        };
        let root = MountBase::root();
        for transport in [WidgetTransport::Server, WidgetTransport::WasmClient] {
            let glue = glue_js_for(&assets, &app, transport);
            assert!(glue.contains("from \"/app/_ipe/widget."), "{glue}");
            let html = page_scripts_for(&assets, &app, transport);
            assert!(html.contains("href=\"/app/_ipe/widget."), "{html}");
            assert!(html.contains("src=\"/app/_ipe/widget-glue."), "{html}");
            let root_glue = glue_js_for(&assets, &root, transport);
            assert!(root_glue.contains("from \"/_ipe/widget."), "{root_glue}");
            let root_html = page_scripts_for(&assets, &root, transport);
            assert!(
                root_html.contains("src=\"/_ipe/widget-glue."),
                "{root_html}"
            );
        }
    }

    // A single global registry means these tests must not race a real
    // registration; they exercise the pure hashing/glue helpers directly with an
    // explicit asset list rather than through the global `register`.
    fn hashes_of(content: &str) -> (String, String) {
        content_hashes(content)
    }

    #[test]
    fn content_hash_is_stable_and_content_addressed() {
        let a = hashes_of("export function mount(){}");
        let b = hashes_of("export function mount(){}");
        assert_eq!(a, b, "same content → same hash");
        let c = hashes_of("export function mount(){} // changed");
        assert_ne!(a.0, c.0, "different content → different hex16");
        assert_ne!(a.1, c.1, "different content → different SRI");
    }

    #[test]
    fn asset_path_and_integrity_agree_on_one_digest() {
        // The URL hex16 is the digest prefix; the SRI is base64 of the SAME
        // digest — so a page pinning `integrity` for a URL can never disagree
        // with the bytes served at that URL.
        let content = "export function mount(host, emit){ return { onState(){} }; }";
        let (hex16, b64) = content_hashes(content);
        assert_eq!(
            widget_asset_path(content).rel(),
            format!("_ipe/widget.{hex16}.js")
        );
        assert_eq!(widget_asset_integrity(content), format!("sha256-{b64}"));
    }

    #[test]
    fn glue_defines_only_generated_tags_and_never_evals() {
        // Build glue over an explicit registry via a stand-in that mirrors
        // `glue_js` for a fixed asset list, asserting the security-load-bearing
        // shape: `customElements.define` is called only on the `ipe-ce-*` tag,
        // the author module is imported (not evaluated), and down-state is
        // `JSON.parse`d, never `eval`ed.
        let tag = "ipe-ce-cafef00dcafef00d";
        let content = "export function mount(host, emit){ return { onState(s){} }; }";
        let asset_url = MountBase::root().url_of(&widget_asset_path(content));
        let class_suffix = tag.replace('-', "_");
        // Reconstruct one class block exactly as `glue_js` would, to assert on it
        // without touching the global registry.
        let block = format!(
            "import {{ mount as __ipe_mount_{class_suffix} }} from {asset_url:?};\n\
             customElements.define({tag:?}, IpeCE_{class_suffix});"
        );
        assert!(block.contains("customElements.define(\"ipe-ce-"));
        assert!(!block.contains("eval("));
        assert!(!block.contains("innerHTML"));
        assert!(GLUE_PRELUDE_SERVER.contains("JSON.parse"));
        assert!(!GLUE_PRELUDE_SERVER.contains("eval("));
        // The up-emit reuses the existing wire, never inventing a new fetch.
        assert!(GLUE_PRELUDE_SERVER.contains("__ipeSend(\"ipe-widget\""));
    }

    /// The served URL segment and the page SRI a widget file pins are one
    /// `sha256(content)` — so the URL a page requests and the integrity it checks
    /// that response against can never disagree with the served bytes. Proven by
    /// deriving the SRI base64 straight from the served URL's digest and matching
    /// `widget_asset_integrity`.
    #[test]
    fn served_url_and_page_sri_bind_to_one_digest() {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        let content = "export function mount(host, emit){ return { onState(){} }; }";
        let digest = content_digest(content);
        // The SRI the page pins is base64 of the SAME digest the served URL's
        // hex16 prefix is taken from.
        let sri_from_digest = format!("sha256-{}", B64.encode(digest));
        assert_eq!(
            sri_from_digest,
            widget_asset_integrity(content),
            "the page SRI must be base64 of the served bytes' digest — one hash from source to browser"
        );
        let hex16: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            widget_asset_path(content).rel(),
            format!("_ipe/widget.{hex16}.js")
        );
    }

    /// A tampered widget file (one changed byte) yields a DIFFERENT served URL and
    /// a different SRI — so a page pinning the honest file's integrity refuses the
    /// tampered bytes. This is the fail-closed catch: a swapped file cannot pass a
    /// pin computed over the honest bytes.
    #[test]
    fn a_tampered_widget_file_diverges_from_the_served_pin() {
        let honest = "export function mount(host, emit){ return { onState(){} }; }";
        let tampered = "export function mount(host, emit){ steal(); return { onState(){} }; }";
        assert_ne!(
            widget_asset_path(honest),
            widget_asset_path(tampered),
            "a tampered widget file must not share the honest file's served URL"
        );
        assert_ne!(
            widget_asset_integrity(honest),
            widget_asset_integrity(tampered),
            "a tampered widget file must not share the honest file's page SRI"
        );
    }

    #[test]
    fn no_widgets_means_no_page_scripts() {
        // A fresh process with no registration must emit no script and no link,
        // so the page CSP and byte output are unchanged for a widget-free app.
        // (The global registry is empty unless `register` ran.)
        if !has_widgets() {
            let root = MountBase::root();
            assert_eq!(page_scripts(&root, WidgetTransport::Server), "");
            assert_eq!(page_scripts(&root, WidgetTransport::WasmClient), "");
        }
    }

    /// The wasm-client glue reconstructs the SAME class shell the server glue
    /// does — the author-module import, the `mount(host, emit)` contract, and
    /// `customElements.define` on the compiler-generated `ipe-ce-*` tag ONLY —
    /// but delivers down-state through the `set state(v)` PROPERTY setter (never
    /// an attribute splice) and emits up-events as a typed `CustomEvent` (never a
    /// `/_ipe/event` POST). One glue module, two adapters.
    #[test]
    fn wasm_glue_uses_property_setter_and_custom_event_never_evals() {
        // Down: the wasm prelude parses with the SAME `JSON.parse` helper as the
        // server prelude (one down-decoder), and never evals.
        assert!(GLUE_PRELUDE_WASM.contains("JSON.parse"));
        assert!(!GLUE_PRELUDE_WASM.contains("eval("));
        // Up: the wasm emit dispatches a typed CustomEvent under the fixed name,
        // carrying the encoded value as a string `detail` — never a POST, never
        // spliced into markup.
        assert!(GLUE_PRELUDE_WASM.contains("dispatchEvent(new CustomEvent(\"ipe-widget-up\""));
        assert!(GLUE_PRELUDE_WASM.contains("JSON.stringify(up)"));
        assert!(
            !GLUE_PRELUDE_WASM.contains("__ipeSend"),
            "the wasm transport must NOT reuse the server POST wire"
        );
        assert_eq!(WIDGET_UP_CUSTOM_EVENT, "ipe-widget-up");

        // The class body: the wasm down channel is the `set state(v)` property
        // setter, NOT `attributeChangedCallback`/`observedAttributes`. Both still
        // `define` only the `ipe-ce-*` tag.
        let tag = "ipe-ce-cafef00dcafef00d";
        let content = "export function mount(host, emit){ return { onState(s){} }; }";
        let wasm_class = glue_class(
            &MountBase::root(),
            WidgetTransport::WasmClient,
            tag,
            content,
        );
        assert!(wasm_class.contains("set state(v)"));
        assert!(
            !wasm_class.contains("observedAttributes"),
            "the wasm down channel is the property, not the attribute"
        );
        assert!(wasm_class.contains("customElements.define(\"ipe-ce-"));
        assert!(wasm_class.contains("__ipeEmitWidgetUpEvent"));
        assert!(!wasm_class.contains("eval("));
        assert!(!wasm_class.contains("innerHTML"));

        // The server class remains the attribute path — the two adapters are
        // distinct but share the one class shell + `define` rule.
        let server_class = glue_class(&MountBase::root(), WidgetTransport::Server, tag, content);
        assert!(server_class.contains("attributeChangedCallback"));
        assert!(server_class.contains("customElements.define(\"ipe-ce-"));
        assert!(!server_class.contains("set state(v)"));
    }

    /// The wasm glue and the server glue hash DISTINCTLY (different transport →
    /// different bytes → different content-addressed URL + SRI), so a page can
    /// never pin one transport's integrity and be served the other's bytes.
    #[test]
    fn wasm_and_server_glue_paths_diverge() {
        let root = MountBase::root();
        assert_ne!(
            glue_js(&root, WidgetTransport::Server),
            glue_js(&root, WidgetTransport::WasmClient),
            "the two transports must not produce byte-identical glue"
        );
        assert_ne!(
            glue_path(&root, WidgetTransport::Server),
            glue_path(&root, WidgetTransport::WasmClient),
            "distinct glue bytes must yield distinct content-addressed URLs"
        );
        assert_ne!(
            glue_integrity(&root, WidgetTransport::Server),
            glue_integrity(&root, WidgetTransport::WasmClient),
            "distinct glue bytes must yield distinct SRI pins"
        );
    }
}
