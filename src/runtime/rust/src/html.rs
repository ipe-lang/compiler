use std::borrow::Cow;
use std::collections::HashMap;

use super::css_safety;
use crate::csp::StyleNonce;
use crate::retained::{Bytes, RetainedBytes};

/// Form data delivered to an `OnForm` handler (lower-cased keys; see dispatch).
pub type FormData = HashMap<String, String>;

#[derive(Clone, Debug, PartialEq)]
pub enum Html<M> {
    /// Normal element node — matches Ipê's `HElement tag attrs children`.
    HElement(String, Vec<Attribute<M>>, Vec<Html<M>>),
    /// Text node (HTML-escaped on render) — matches Ipê's `HText s`.
    HText(String),
    /// Raw, un-escaped HTML — trusted pre-rendered content only; caller sanitises.
    /// Reachable from Ipê ONLY through the explicitly-marked `Html.unsafeRaw`
    /// surface (never a plain `Html.raw`), so every raw-injection site is named.
    /// Matches Ipê's `HRaw s`.
    HRaw(String),
}

impl<M> Drop for Html<M> {
    /// Dismantle the node tree iteratively so dropping a deeply nested `Html`
    /// can never overflow the native stack. An `Html` tree's depth is
    /// data-influenced (a rendered view whose nesting tracks model or decoded
    /// input, up to `MAX_HTML_DEPTH`), so the derived recursive destructor would
    /// abort the process on a deep tree. Draining each node's children onto an
    /// explicit heap worklist keeps teardown O(depth) heap and O(1) stack.
    fn drop(&mut self) {
        let mut pending: Vec<Html<M>> = match self {
            Html::HElement(_, _, children) => std::mem::take(children),
            Html::HText(_) | Html::HRaw(_) => return,
        };
        while let Some(mut node) = pending.pop() {
            if let Html::HElement(_, _, children) = &mut node {
                pending.append(&mut std::mem::take(children));
            }
            // `node` (now child-free) drops here without recursion.
        }
    }
}

/// Variant names mirror the Ipê stdlib `Ipe.Html.Attributes.Attribute` ADT
/// (`Attr | BoolAttr | EventAttr (Event msg) | NoAttr`) so the Rust codegen's
/// bridge (`StdHtmlAttributesAttribute<msg> = ipe_runtime::Attribute<msg>`)
/// constructs the right variants by name.
#[derive(Clone)]
pub enum Attribute<M> {
    Attr(String, String),
    BoolAttr(String, bool),
    EventAttr(Event<M>),
    /// Sentinel for a conditionally-absent attribute; skipped during render.
    NoAttr,
}

/// Variant names mirror the Ipê stdlib `Ipe.Html.Attributes.Event` ADT
/// (`OnMsg | OnString | OnBool | OnForm`). `OnString`/`OnBool` carry
/// `Arc<dyn Fn(..) -> msg>` (not bare fn pointers) so the handler can be a
/// CAPTURING closure, supporting `\s -> toMsg (parse s default)` patterns. A faithful Ipe.Web
/// app's `onChange = \s -> toMsg (parse s default)` captures locals; a bare
/// fn-pointer field rejected that. Bare ctors / non-capturing fns coerce into
/// `Arc::new` fine; capturing closures box into the trait object.
///
/// `Ui.onSubmit` / `Ipe.Html.Events.onSubmit` (the heterogeneous-payload
/// handler whose argument type is decoupled from `msg`) construct `OnForm`
/// too — `ui_on_submit_` / `html_on_raw_` close over a
/// `decode_form_or_warn::<T>` call for the CONCRETE record type `T`, recovered
/// by ordinary Rust generic inference on the handler closure's own signature
/// at the codegen call site, never `Arc<dyn Any>`. A payload erased behind
/// `Arc<dyn Any>` would be undispatchable in any backend, so no such variant
/// exists.
///
/// `OnMsg` boxes its message, so an attribute's inline size is the same for
/// every app's `Msg` and a wide `Msg` costs one allocation per handler, which
/// the view measure counts.
#[derive(Clone)]
pub enum Event<M> {
    OnMsg(String, Box<M>),
    OnString(String, std::sync::Arc<dyn Fn(String) -> M + Send + Sync>),
    OnBool(String, std::sync::Arc<dyn Fn(bool) -> M + Send + Sync>),
    /// Form-submit handler. Returns `Option<M>`: a malformed/incomplete form
    /// (decode failure) yields `None` so the live loop dispatches no Msg (see
    /// `decode_form`).
    OnForm(
        String,
        std::sync::Arc<dyn Fn(FormData) -> Option<M> + Send + Sync>,
    ),
    /// Typed custom-element up-event handler (`CustomElement.node`). The browser posts
    /// the encoded `up` value as `args[0]` through the same `/_ipe/event` wire a
    /// click uses; the closure runs the generated fail-closed seal decode over
    /// that string and dispatches the typed `msg` on success. It returns
    /// `Option<M>` for the SAME reason `OnForm` does: a payload that does not
    /// decode to the declared `up` type yields `None`, so the live loop
    /// dispatches no Msg and no partial value is ever constructed (the seal
    /// boundary's fail-closed drop).
    OnWidget(
        String,
        std::sync::Arc<dyn Fn(String) -> Option<M> + Send + Sync>,
    ),
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if an event's message is stored inline, so an attribute's size would depend on the app's `Msg` [ledger #boundary]
const _: () = assert!(size_of::<Attribute<[u8; 4096]>>() == size_of::<Attribute<()>>());

impl<M: PartialEq> PartialEq for Attribute<M> {
    fn eq(&self, o: &Self) -> bool {
        use Attribute::{Attr, BoolAttr, EventAttr, NoAttr};
        match (self, o) {
            (Attr(a, b), Attr(c, d)) => a == c && b == d,
            (BoolAttr(a, b), BoolAttr(c, d)) => a == c && b == d,
            (EventAttr(a), EventAttr(b)) => a == b,
            (NoAttr, NoAttr) => true,
            _ => false,
        }
    }
}

// The attribute name only: a value (a token, a prefilled field) never reaches
// a `{:?}` rendering.
impl<M> std::fmt::Debug for Attribute<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hidden = crate::redact::REDACTED;
        match self {
            Attribute::Attr(k, _) => write!(f, "Attr({k:?},{hidden})"),
            Attribute::BoolAttr(k, _) => write!(f, "BoolAttr({k:?},{hidden})"),
            Attribute::EventAttr(e) => write!(f, "{e:?}"),
            Attribute::NoAttr => write!(f, "NoAttr"),
        }
    }
}

// Structural equality only: (variant kind, event name). The message payload /
// closure is deliberately ignored. Ipe.Web's diff is structure-only — it just
// decides whether a DOM node carries a listener of a given event name. The
// actual handler lives server-side in the per-session handler_index, which is
// REBUILT from the fresh view on every commit, so the diff never needs to
// compare handlers. Comparing payloads here would cause spurious re-renders
// (e.g. OnMsg("click", Inc) vs OnMsg("click", Dec) are equal for diff purposes).
impl<M> PartialEq for Event<M> {
    fn eq(&self, o: &Self) -> bool {
        self.kind_name() == o.kind_name()
    }
}

impl<M> Event<M> {
    pub fn name(&self) -> &str {
        match self {
            Event::OnMsg(n, _)
            | Event::OnString(n, _)
            | Event::OnBool(n, _)
            | Event::OnForm(n, _)
            | Event::OnWidget(n, _) => n,
        }
    }

    fn kind_name(&self) -> (u8, &str) {
        match self {
            Event::OnMsg(n, _) => (0, n),
            Event::OnString(n, _) => (1, n),
            Event::OnBool(n, _) => (2, n),
            Event::OnForm(n, _) => (3, n),
            Event::OnWidget(n, _) => (4, n),
        }
    }

    fn kind_tag(&self) -> &'static str {
        match self {
            Event::OnMsg(..) => "OnMsg",
            Event::OnString(..) => "OnString",
            Event::OnBool(..) => "OnBool",
            Event::OnForm(..) => "OnForm",
            Event::OnWidget(..) => "OnWidget",
        }
    }
}

impl<M> std::fmt::Debug for Event<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Event::{}({})", self.kind_tag(), self.name())
    }
}

const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// True for HTML void elements (no children, self-closing), matched without
/// regard to ASCII case as the HTML tokenizer lowercases tag names. The render
/// sink self-closes these and the style-injection pass hoists a `<style>` to a
/// sibling slot after them, so both read the one predicate.
pub(crate) fn is_void(tag: &str) -> bool {
    VOID.iter().any(|v| tag.eq_ignore_ascii_case(v))
}

/// Render an `Html` tree to an HTML string. Text is HTML-escaped; Raw is
/// emitted verbatim; void elements self-close with no children; event
/// handlers emit a `data-ipe-on="<space-separated event names>"` marker
/// attribute that the browser client reads to bind listeners.
#[must_use]
pub fn render_html<M>(node: &Html<M>) -> String {
    render_html_in(node, &RenderCtx::Unstamped)
}

/// How a render stamps the `<style>` elements it admits.
///
/// Every serialization of a session's tree passes the session's nonce, so a
/// `<style>` written in HTML data or foreign content carries `nonce="…"`. A
/// `<style>` under an RCDATA or RAWTEXT ancestor is text, never stamped.
#[derive(Clone, Debug)]
pub enum RenderCtx<'a> {
    /// No stamp: emitted code, the static page render, the browser runtime.
    Unstamped,
    /// A session's render, stamped with that session's nonce.
    Session(&'a StyleNonce),
}

/// Render an `Html` tree to an HTML string under `stamp`.
///
/// It is [`render_html`] with every admitted `<style>` in data or foreign
/// content stamped as `stamp` says.
#[must_use]
pub fn render_html_in<M>(node: &Html<M>, stamp: &RenderCtx<'_>) -> String {
    let mut s = String::new();
    render_into_ctx(node, &mut s, ParseContext::Data, None, 0, stamp);
    s
}

/// A session render's markup and the nonce its `<style>` elements carry.
///
/// Only [`render_stamped`] builds one, so the nonce is the one the markup was
/// stamped with. Its `Debug` form shows only the markup's length, since the
/// markup holds the nonce.
#[derive(Clone)]
pub struct StampedHtml {
    html: String,
    nonce: StyleNonce,
}

impl std::fmt::Debug for StampedHtml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StampedHtml")
            .field("len", &self.html.len())
            .finish_non_exhaustive()
    }
}

impl StampedHtml {
    /// The rendered markup.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.html.as_str()
    }

    /// The nonce every `<style>` of the markup carries.
    #[must_use]
    pub const fn nonce(&self) -> &StyleNonce {
        &self.nonce
    }
}

/// Render `node` as a session's markup, stamped with `nonce`.
#[must_use]
pub fn render_stamped<M>(node: &Html<M>, nonce: &StyleNonce) -> StampedHtml {
    StampedHtml {
        html: render_html_in(node, &RenderCtx::Session(nonce)),
        nonce: nonce.clone(),
    }
}

/// Marker attribute on a radio group's `<fieldset>`.
///
/// The ipe-id stamping pass reads it to give the group's unnamed radios one
/// shared `name`, then removes it. Forging it only names the forger's own
/// unnamed radios.
pub(crate) const RADIO_GROUP_MARKER: &str = "data-ipe-radio-group";

/// Maximum Html nesting depth the renderer and the ipe-id stamper descend.
/// The Html tree is produced by the Ipê `view` from Model, and Model commonly
/// holds attacker-influenced data (nested comments / replies / a worst-case
/// string folded into a chain of wrapper elements). Recursing once per nesting
/// level with no cap would overflow the thread stack and ABORT the whole
/// process — a panic the no-runtime-error thesis forbids. At the cap we stop
/// descending (deeper nodes are not emitted / not stamped) rather than recurse
/// further: a truncated render is strictly better than a process abort, and no
/// legitimate UI nests anywhere near this deep.
///
/// `pub(crate)` so the render and diff walkers in the same Web data path
/// (`ui/render.rs`, `dom/diff.rs`) share the identical ceiling — one constant,
/// no drift.
pub(crate) const MAX_HTML_DEPTH: usize = 1024;

/// Render the children of an element admitted as `body` into `s`.
///
/// The SSE diff's whole-subtree replace writes an element's new children
/// through this, so a patched `<script>`/`<style>` body gets the same
/// neutralisation the first paint applies. `child_ctx` is the context the
/// element puts its children in (`ParseContext::enter` of its own context),
/// so a patched subtree is admitted exactly as the first paint admitted it,
/// and `stamp` is the render context of the session the patch is sent to.
pub(crate) fn render_children_into<M>(
    body: ElementBody,
    child_ctx: ParseContext,
    kids: &[Html<M>],
    s: &mut String,
    stamp: &RenderCtx<'_>,
) {
    render_body_into(body, child_ctx, kids, s, None, 0, stamp);
}

/// Render `kids`, the children of an element admitted as `body`, into `s`.
///
/// A `<script>` or `<style>` body is admitted only when every child is a
/// trusted `HRaw` node, so it is gathered verbatim into a scratch buffer and
/// neutralised as a whole: `neutralise_script_close` splits a `</script`
/// breakout, `neutralise_style_body` removes `</style` and every other markup
/// opener. `select_value` reaches only a `Markup` body's direct children, and
/// `child_ctx` is the parse context every child is written in.
fn render_body_into<M>(
    body: ElementBody,
    child_ctx: ParseContext,
    kids: &[Html<M>],
    s: &mut String,
    select_value: Option<&str>,
    depth: usize,
    stamp: &RenderCtx<'_>,
) {
    let child_depth = depth.saturating_add(1);
    match body {
        ElementBody::Markup => {
            for c in kids {
                render_into_ctx(c, s, child_ctx, select_value, child_depth, stamp);
            }
        }
        ElementBody::Script => {
            let mut raw = String::new();
            for c in kids {
                render_into_ctx(c, &mut raw, child_ctx, None, child_depth, stamp);
            }
            s.push_str(&css_safety::neutralise_script_close(&raw));
        }
        ElementBody::Style => {
            let mut raw = String::new();
            for c in kids {
                render_into_ctx(c, &mut raw, child_ctx, None, child_depth, stamp);
            }
            s.push_str(&css_safety::neutralise_style_body(&raw));
        }
    }
}

// `select_value`: when this node renders as a direct child of a `<select>` that
// carries a value, the chosen value is threaded here so the matching `<option>`
// flips `selected`. `ctx` is the parse context `node` is written in, and
// `stamp` says which nonce an admitted `<style>` carries.
#[allow(clippy::too_many_lines)]
fn render_into_ctx<M>(
    node: &Html<M>,
    s: &mut String,
    ctx: ParseContext,
    select_value: Option<&str>,
    depth: usize,
    stamp: &RenderCtx<'_>,
) {
    // Bounded descent: a tree deeper than the cap is dropped here rather than
    // recursed into (see MAX_HTML_DEPTH). The parent has already emitted its
    // open tag and will emit its close tag, so the output stays well-formed.
    if depth >= MAX_HTML_DEPTH {
        return;
    }
    match node {
        // SECURITY: text is always entity-escaped. No element body renders a
        // text node verbatim: a `<script>`/`<style>` whose children are not all
        // `HRaw` is refused by `admit_element` before any byte of it is written.
        Html::HText(t) => crate::escape::html_text_into(t, s),
        Html::HRaw(r) => s.push_str(r),
        Html::HElement(tag, attrs, kids) => {
            // SECURITY: the shared tag gate, re-checked at the sink. A refused
            // element (an unsafe tag name, an unclosable `<plaintext>`, or a
            // `<script>`/`<style>` whose body is not trusted raw markup, or a
            // `<script>` outside an HTML data-state context, or an `embed`,
            // `object` or `frame` naming a document to load) is dropped with
            // its whole subtree, so no value built on the safe surface reaches
            // a raw-text or executable element body or loads a document that
            // could share the app's origin.
            let Ok(rendered) = admit_rendered_in(ctx, tag, attrs, kids) else {
                return;
            };
            let body = match rendered {
                // The doctype string is a fixed literal and the wrapper's own
                // tag/attrs are never written; its children render as markup
                // with full name/attr/text gating.
                RenderedElement::Doctype => {
                    s.push_str("<!DOCTYPE html>");
                    render_body_into(ElementBody::Markup, ctx, kids, s, None, depth, stamp);
                    return;
                }
                RenderedElement::Element(body) => body,
            };
            s.push('<');
            s.push_str(tag);
            // Regular + bool attrs as (key, value) pairs, sorted by key below:
            // alphabetical order matches the byte-exact output expected by
            // golden tests.
            let mut pairs = attribute_pairs(tag, attrs);
            let ipe_id = attrs.iter().rev().find_map(|a| match a {
                Attribute::Attr(k, v) if k == STAMPED_ID_ATTR => Some(v.as_str()),
                _ => None,
            });
            let mut events: Vec<&str> = attrs
                .iter()
                .filter_map(|a| match a {
                    Attribute::EventAttr(e) => Some(e.name()),
                    _ => None,
                })
                .collect();
            // <textarea> and <select> have NO `value` attribute in the HTML spec
            // — a textarea's displayed value is its TEXT CONTENT; a select's is the
            // `selected` <option>. Emitting `<textarea value="…">` renders EMPTY in
            // every browser (and a server re-render would wipe the user's text). So
            // strip the `value` attr here for both, and (textarea only) splice it
            // back as escaped text content after the open tag when there are no
            // explicit children.
            let mut textarea_value: Option<String> = None;
            if (tag == "textarea" || tag == "select")
                && let Some(pos) = pairs.iter().position(|(k, _)| *k == "value")
            {
                let (_, v) = pairs.remove(pos);
                textarea_value = Some(v.into_owned());
            }
            // <option selected> flip: when rendered as a direct child of a
            // <select> with a value, set `selected` on the value-matching option
            // and drop any stale `selected` otherwise (copy-don't-mutate).
            // We touch only the local `pairs`, never the caller's
            // tree (it is the diff baseline — mutating it would corrupt the next
            // diff). Added before the sort so byte order matches  map+sort.
            if tag == "option"
                && let Some(sv) = select_value
            {
                pairs.retain(|(k, _)| *k != "selected");
                if pairs.iter().any(|(k, v)| *k == "value" && v == sv) {
                    pairs.push(("selected", Cow::Borrowed("selected")));
                }
            }
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            for (k, v) in &pairs {
                // Attr KEY is emitted unescaped; an unsafe key (`x onload=…`)
                // injects a new attribute, and a script-bearing key (`onerror`,
                // `srcdoc`) executes regardless of value-escaping. `SafeAttrName`
                // enforces both policies in one place; a key that fails is dropped.
                // The stamped identity is the one reserved name the sink writes
                // itself; every other `ipe-*` name fails `SafeAttrName`.
                let name = if *k == STAMPED_ID_ATTR {
                    STAMPED_ID_ATTR
                } else {
                    let Some(safe_key) = SafeAttrName::parse(k) else {
                        continue;
                    };
                    safe_key.as_str()
                };
                s.push(' ');
                s.push_str(name);
                s.push_str("=\"");
                crate::escape::html_attr_into(sanitise_url_attr(k, v), s);
                s.push('"');
            }
            // The session nonce is written by the sink alone: `nonce` is a
            // reserved name, so no program-built attribute reaches this spot.
            if body == ElementBody::Style
                && ctx.opens_style_element()
                && let RenderCtx::Session(nonce) = stamp
            {
                s.push_str(" nonce=\"");
                nonce.write_token(s);
                s.push('"');
            }
            // Browser-client wire markers (live/client.js): the delegated
            // binder scans for `[ipe-<event>]`, reads `data-ipe-hid` for the
            // ipe-id, and posts the `ipe-<event>` value as `msg`. We make that
            // value the EVENT NAME so the server can tell click from submit
            // (the client doesn't send the event type otherwise) — the handler
            // resolves by (ipe-id, event). `data-ipe-on` is kept for parity
            // with  render.
            // Event names are emitted unescaped as both the `data-ipe-on` value
            // and the `ipe-<ev>` attribute key — an unsafe name injects markup.
            // Drop any that aren't valid HTML names.
            events.retain(|e| is_safe_html_name(e));
            if !events.is_empty() {
                s.push_str(" data-ipe-on=\"");
                s.push_str(&events.join(" "));
                s.push('"');
                if let Some(id) = ipe_id {
                    s.push(' ');
                    s.push_str(HANDLER_ID_ATTR);
                    s.push_str("=\"");
                    crate::escape::html_attr_into(id, s);
                    s.push('"');
                }
                for ev in &events {
                    // File/image meta-events arrive already `ipe-`-prefixed
                    // (`ipe-image`/`ipe-file`); the client's upload driver reads
                    // them via the `data-ipe-ev-<name>` HTML5 data-attribute
                    // convention, while plain DOM events keep `ipe-<name>`.
                    // Emitting `ipe-ipe-image` made the driver
                    // lookup miss, so uploads never fired. `ev` is already
                    // name-gated (events.retain above), so both keys are safe.
                    let key = if ev.starts_with("ipe-") {
                        format!("data-ipe-ev-{ev}")
                    } else {
                        format!("ipe-{ev}")
                    };
                    s.push(' ');
                    s.push_str(&key);
                    s.push_str("=\"");
                    s.push_str(ev);
                    s.push('"');
                }
            }
            if is_void(tag) {
                s.push_str(" />");
                return;
            }
            s.push('>');
            // Textarea value-as-content : write the captured value as
            // escaped text content. Explicit children take precedence (a user who
            // wrote `textarea [] [ text "hi" ]` keeps that), matching
            // `isTextarea && value != "" && len(children) == 0` guard.
            if tag == "textarea"
                && let Some(v) = &textarea_value
                && !v.is_empty()
                && kids.is_empty()
            {
                crate::escape::html_text_into(v, s);
            }
            // A <select> threads its value to its option children for the
            // `selected` flip; deeper descendants reset it.
            let child_select_value = if tag == "select" {
                textarea_value.as_deref().filter(|v| !v.is_empty())
            } else {
                None
            };
            render_body_into(
                body,
                ctx.enter(tag),
                kids,
                s,
                child_select_value,
                depth,
                stamp,
            );
            s.push_str("</");
            s.push_str(tag);
            s.push('>');
        }
    }
}

/// True when `name` is safe to emit UNESCAPED as a tag name, attribute key, or
/// event name. Tag/attr/event names are NEVER escaped (an escaped `<` in a tag
/// position is meaningless), so a name carrying a structural metacharacter is a
/// direct injection: a tag `"div><script>…"` or an attr key `"x onmouseover=…"`
/// would break out of the element. Ipê `Html.node` / `Html.attribute` take the
/// name as a `String`, so it can be attacker-derived. Accept only the characters
/// that appear in real HTML names — letters, digits, and `-_:.` — and reject
/// everything else (whitespace, `<>"'=/\`, backtick, control bytes, non-ASCII). An invalid
/// name causes the element / attribute / event marker to be DROPPED rather than
/// emitted, closing the XSS hole with no escaping ambiguity.
fn is_safe_html_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

/// A child node that can say whether it is trusted raw markup.
///
/// Only a capability-disclosing constructor (`Ipe.Html.Unsafe.unsafeRaw`,
/// `unsafeScript`, `Ipe.Html.styleNode`) or a runtime-internal producer builds
/// an `HRaw` node, so "every child is trusted raw" is the proof that an element
/// body was not built from data on the safe surface. Implemented for `Html` here
/// and for `Ipe.Ui`'s `Element` beside its definition, so both constructors run
/// the one `admit_element` gate.
pub(crate) trait TrustedRawChild {
    /// True when this child is trusted raw markup.
    fn is_trusted_raw(&self) -> bool;
}

impl<M> TrustedRawChild for Html<M> {
    fn is_trusted_raw(&self) -> bool {
        matches!(self, Html::HRaw(_))
    }
}

/// How an admitted element's body is rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ElementBody {
    /// Ordinary markup: children render with full escaping and gating.
    Markup,
    /// A `<script>` whose body is trusted raw source, close-tag-neutralised.
    Script,
    /// A `<style>` whose body is trusted raw CSS, markup-opener-neutralised.
    Style,
}

/// Why `admit_element` refused an element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ElementRefusal {
    /// The tag name carries a byte that would break out of the start tag.
    UnsafeName,
    /// A `<plaintext>` element: nothing can ever close it, so every later byte
    /// of the page would render as its text.
    Unclosable,
    /// A `<script>` whose body is empty or holds a child that is not trusted
    /// raw markup: its text would execute, or an empty not-yet-started script
    /// could run a later patch's body or its `src`.
    UntrustedScript,
    /// A `<style>` holding a child that is not trusted raw markup: its text
    /// would be read as CSS, a raw-text body the safe surface never builds.
    UntrustedStyle,
    /// A trusted `<script>` under an RCDATA, RAWTEXT or foreign-content
    /// ancestor: its body would be read as text that can end that ancestor,
    /// or as live markup, instead of as script data.
    ScriptOutsideData,
    /// An `embed`, `object` or `frame` that names a document to load. The
    /// browser gives these elements no sandbox and the runtime holds no proof
    /// that the document's origin differs from the app's, so the loaded
    /// document could act as the app. Use `Html.iframe`, which the runtime
    /// always sandboxes.
    UnsandboxableFrame,
}

/// The `sandbox` tokens an `iframe` may hold, in the order the runtime paints
/// them.
///
/// `allow-same-origin` and `allow-popups-to-escape-sandbox` are not in the
/// table, so no [`SandboxTokens`] can hold them: either gives the framed
/// document, or a popup it opens, the real origin of its URL, which may be the
/// app's own. The browser client mirrors this table in `__IPE_SANDBOX_TOKENS`.
pub(crate) const SANDBOX_TOKENS: [&str; 12] = [
    "allow-downloads",
    "allow-forms",
    "allow-modals",
    "allow-orientation-lock",
    "allow-pointer-lock",
    "allow-popups",
    "allow-presentation",
    "allow-scripts",
    "allow-storage-access-by-user-activation",
    "allow-top-navigation",
    "allow-top-navigation-by-user-activation",
    "allow-top-navigation-to-custom-protocols",
];

/// The frame-loading elements the browser gives no sandbox, each with the
/// attribute it loads a document from. The browser client mirrors this table
/// in `__IPE_FRAME_LOADERS`.
pub(crate) const FRAME_LOADERS: [(&str, &str); 3] =
    [("embed", "src"), ("object", "data"), ("frame", "src")];

/// The attribute that sandboxes an `iframe`.
pub(crate) const SANDBOX_ATTR: &str = "sandbox";

/// The sandboxed frame element.
pub(crate) const IFRAME_TAG: &str = "iframe";

/// A `sandbox` value that can never grant the app's origin back: a set over
/// [`SANDBOX_TOKENS`], painted lowercase, once each, in table order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SandboxTokens([bool; SANDBOX_TOKENS.len()]);

impl SandboxTokens {
    /// The known tokens of `value`, split on ASCII whitespace as the browser
    /// splits them and matched without regard to ASCII case; every other
    /// token, a forbidden one included, is dropped.
    pub(crate) fn parse(value: &str) -> Self {
        let mut held = [false; SANDBOX_TOKENS.len()];
        for token in value.split_ascii_whitespace() {
            for (slot, known) in held.iter_mut().zip(SANDBOX_TOKENS) {
                if known.eq_ignore_ascii_case(token) {
                    *slot = true;
                }
            }
        }
        Self(held)
    }

    /// The canonical `sandbox` value: the held tokens, space-separated.
    pub(crate) fn canonical(self) -> String {
        let mut out = String::new();
        for (_, token) in self.0.iter().zip(SANDBOX_TOKENS).filter(|(held, _)| **held) {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(token);
        }
        out
    }
}

/// What the frame rule makes of an element before it renders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameVerdict {
    /// Not a frame-loading element: render as is.
    NotAFrame,
    /// An `iframe`: render with this one canonical `sandbox` value, and drop
    /// every `sandbox` pair the app wrote.
    Sandboxed(SandboxTokens),
    /// A frame-loading element carrying its loading attribute.
    Refused(ElementRefusal),
}

/// The attribute a [`FRAME_LOADERS`] element `tag` loads its document from;
/// `None` for every other tag. Tags match without regard to ASCII case.
pub(crate) fn frame_loader_key(tag: &str) -> Option<&'static str> {
    FRAME_LOADERS
        .iter()
        .find(|(loader, _)| tag.eq_ignore_ascii_case(loader))
        .map(|(_, key)| *key)
}

/// The frame rule for an element `tag` whose attributes, in order, are the
/// pairs `attrs`.
///
/// No document such an element loads can share the app's origin: an `iframe`
/// always renders one sandbox, the last `sandbox` of any ASCII case read (an
/// absent, empty or unknown value gives the empty sandbox), and a
/// [`FRAME_LOADERS`] element that carries its loading attribute at all, in any
/// key case and with any value, is refused, as `" "` resolves to the page
/// itself. Tags and keys match without regard to ASCII case only.
pub(crate) fn frame_verdict<'a>(
    tag: &str,
    mut attrs: impl Iterator<Item = (&'a str, &'a str)>,
) -> FrameVerdict {
    if tag.eq_ignore_ascii_case(IFRAME_TAG) {
        let value = attrs
            .filter(|(k, _)| k.eq_ignore_ascii_case(SANDBOX_ATTR))
            .last()
            .map_or("", |(_, v)| v);
        return FrameVerdict::Sandboxed(SandboxTokens::parse(value));
    }
    match frame_loader_key(tag) {
        Some(key) if attrs.any(|(k, _)| k.eq_ignore_ascii_case(key)) => {
            FrameVerdict::Refused(ElementRefusal::UnsandboxableFrame)
        }
        Some(_) | None => FrameVerdict::NotAFrame,
    }
}

/// The `(key, value)` pairs `attrs` paints, in order: a `BoolAttr` that holds
/// is the value `"true"`; a false one, an event and `NoAttr` carry none.
fn painted_pairs<M>(attrs: &[Attribute<M>]) -> impl Iterator<Item = (&str, &str)> {
    attrs.iter().filter_map(|a| match a {
        Attribute::Attr(k, v) => Some((k.as_str(), v.as_str())),
        Attribute::BoolAttr(k, true) => Some((k.as_str(), "true")),
        Attribute::BoolAttr(_, false) | Attribute::EventAttr(_) | Attribute::NoAttr => None,
    })
}

/// Elements whose children the HTML tokenizer reads as RCDATA or RAWTEXT.
///
/// `noscript` is RAWTEXT when scripting is enabled, which is how a browser
/// renders the page.
const RAW_OR_RCDATA_TAGS: [&str; 7] = [
    "textarea", "title", "xmp", "noscript", "iframe", "noembed", "noframes",
];

/// The tokenizer state an element's children are written in.
///
/// The render sink and the SSE diff thread it from the root down, so both
/// walkers judge a raw body against the same ancestors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParseContext {
    /// HTML namespace, no raw-text ancestor: a `<script>` start tag puts the
    /// tokenizer in script-data state.
    Data,
    /// Below an RCDATA or RAWTEXT element: every byte is that element's text
    /// until its own close tag.
    RawOrRcdata,
    /// Below an `<svg>` or `<math>` element: a `<script>` body is tokenized as
    /// markup.
    Foreign,
}

impl ParseContext {
    /// The context of the children of an element `tag` written in `self`.
    ///
    /// `svg` and `math` open foreign content, and foreign content stays sticky
    /// for the whole subtree, `foreignObject` and the HTML elements that would
    /// break out of it included. That is stricter than the HTML parser, which
    /// returns to the HTML namespace there: the divergence only refuses more
    /// scripts, so it fails closed. An RCDATA or RAWTEXT element makes its
    /// whole subtree text. Tags are matched without regard to ASCII case.
    pub(crate) fn enter(self, tag: &str) -> Self {
        match self {
            Self::Foreign => Self::Foreign,
            Self::RawOrRcdata => Self::RawOrRcdata,
            Self::Data => {
                if tag.eq_ignore_ascii_case("svg") || tag.eq_ignore_ascii_case("math") {
                    Self::Foreign
                } else if RAW_OR_RCDATA_TAGS
                    .iter()
                    .any(|t| tag.eq_ignore_ascii_case(t))
                {
                    Self::RawOrRcdata
                } else {
                    Self::Data
                }
            }
        }
    }

    /// True when a `<style>` start tag written here opens a style element.
    ///
    /// Under an RCDATA or RAWTEXT ancestor the tag is that ancestor's text.
    const fn opens_style_element(self) -> bool {
        match self {
            Self::Data | Self::Foreign => true,
            Self::RawOrRcdata => false,
        }
    }

    /// True when a `<script>` start tag written here enters script-data state.
    const fn admits_script(self) -> bool {
        match self {
            Self::Data => true,
            Self::RawOrRcdata | Self::Foreign => false,
        }
    }
}

/// Decide whether an element `tag` with attributes `attrs` and children `kids`
/// may be rendered.
///
/// This is the one tag gate of the safe surface: every element constructor
/// (`Html.node`, `Ui.taggedNode`, both template materialisers, `Ipe.Ui`'s
/// lowering) and the render sink and SSE diff all call it, so no path builds a
/// raw-text or executable element from data. Tag names are matched without
/// regard to ASCII case, as the HTML tokenizer lowercases them. A `<script>` or
/// `<style>` is admitted only when its body is trusted raw markup, which only a
/// capability-disclosing constructor produces. The other raw-text and RCDATA
/// elements (`title`, `textarea`, `noscript`, `iframe`, `xmp`, `noembed`,
/// `noframes`) are admitted as markup: their text children are entity-escaped
/// and any trusted `<style>` inside them is markup-neutralised, so no child can
/// end them early. A frame-loading element runs [`frame_verdict`]: an
/// `embed`, `object` or `frame` carrying its loading attribute is refused.
pub(crate) fn admit_element<K: TrustedRawChild, M>(
    tag: &str,
    attrs: &[Attribute<M>],
    kids: &[K],
) -> Result<ElementBody, ElementRefusal> {
    if !is_safe_html_name(tag) {
        return Err(ElementRefusal::UnsafeName);
    }
    if let FrameVerdict::Refused(refusal) = frame_verdict(tag, painted_pairs(attrs)) {
        return Err(refusal);
    }
    if tag.eq_ignore_ascii_case("plaintext") {
        return Err(ElementRefusal::Unclosable);
    }
    let all_trusted = kids.iter().all(TrustedRawChild::is_trusted_raw);
    if tag.eq_ignore_ascii_case("script") {
        return if !kids.is_empty() && all_trusted {
            Ok(ElementBody::Script)
        } else {
            Err(ElementRefusal::UntrustedScript)
        };
    }
    if tag.eq_ignore_ascii_case("style") {
        return if all_trusted {
            Ok(ElementBody::Style)
        } else {
            Err(ElementRefusal::UntrustedStyle)
        };
    }
    Ok(ElementBody::Markup)
}

/// Decide whether an element `tag` with attributes `attrs` and children
/// `kids`, written in `ctx`, may be rendered.
///
/// It runs `admit_element`, then refuses a `<script>` whose start tag would not
/// put the tokenizer in script-data state. `<style>` is admitted in every
/// context, as `neutralise_style_body` removes every markup opener from its
/// body.
pub(crate) fn admit_in_context<K: TrustedRawChild, M>(
    ctx: ParseContext,
    tag: &str,
    attrs: &[Attribute<M>],
    kids: &[K],
) -> Result<ElementBody, ElementRefusal> {
    let body = admit_element(tag, attrs, kids)?;
    match body {
        ElementBody::Script if !ctx.admits_script() => Err(ElementRefusal::ScriptOutsideData),
        ElementBody::Script | ElementBody::Markup | ElementBody::Style => Ok(body),
    }
}

/// The `Html.doctype` pseudo-tag.
///
/// It renders as `<!DOCTYPE html>` and then its children, with no element of
/// its own.
pub(crate) const DOCTYPE_WRAPPER_TAG: &str = "!doctype-wrapper";

/// How a rendered `Html` element node reaches the page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenderedElement {
    /// The `Html.doctype` wrapper: a literal `<!DOCTYPE html>`, then the
    /// children as markup.
    Doctype,
    /// An element admitted by `admit_element`, rendered with this body class.
    Element(ElementBody),
}

impl RenderedElement {
    /// The body class the node's children render with.
    pub(crate) const fn body(self) -> ElementBody {
        match self {
            Self::Doctype => ElementBody::Markup,
            Self::Element(body) => body,
        }
    }
}

/// Decide how an `Html` element node `tag` with attributes `attrs` and
/// children `kids`, written in `ctx`, is rendered.
///
/// This is the one admission rule of every rendered-tree walker (the render
/// sink and the SSE diff), so the two cannot disagree on which nodes are on
/// the page: the `Html.doctype` wrapper is recognised by its exact pseudo-tag,
/// before the name gate its `!` fails, and every other tag runs
/// `admit_in_context`. The context and the attributes are required
/// arguments, so no walker can judge a raw body without its ancestors, nor a
/// frame without its loading attribute.
pub(crate) fn admit_rendered_in<M>(
    ctx: ParseContext,
    tag: &str,
    attrs: &[Attribute<M>],
    kids: &[Html<M>],
) -> Result<RenderedElement, ElementRefusal> {
    if tag == DOCTYPE_WRAPPER_TAG {
        return Ok(RenderedElement::Doctype);
    }
    admit_in_context(ctx, tag, attrs, kids).map(RenderedElement::Element)
}

/// Attribute NAMES that execute script (or embed a scripting context) regardless
/// of how the VALUE is escaped — entity-escaping the value is useless when the
/// value IS script (event handlers like `onerror`/`onclick`) or markup
/// (`srcdoc`). `Html.attribute` takes the name as a String that can be
/// attacker-derived, and `is_safe_html_name` permits these (all valid HTML-name
/// chars), so this denylist is the gate that stops them. Case-insensitive; no
/// legitimate HTML element or non-event attribute name begins with `on`.
fn is_dangerous_attr_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("on") || lower == "srcdoc"
}

/// The attribute-name prefix the runtime reserves for its own wire markers.
///
/// The browser client binds a listener on every `[ipe-<event>]` element and
/// addresses patches by `ipe-id`, so a program-built `ipe-*` attribute would
/// forge a handler binding or an element identity. Matched ASCII-case-insensitively.
const RESERVED_ATTR_PREFIX: &[u8] = b"ipe-";

/// The attribute carrying the identity the ipe-id stamper assigns.
pub(crate) const STAMPED_ID_ATTR: &str = "ipe-id";

/// The attribute pairs an element `tag` with attributes `attrs` carries, in
/// first-appearance order: what the renderer writes at first paint and what
/// the patch diff compares, so the two never disagree on a value.
///
/// An `iframe` carries exactly one `sandbox`, last: the canonical value of
/// [`frame_verdict`], in place of every ASCII case variant of `sandbox` the
/// app wrote. Its old and new sides therefore always both hold `sandbox`, so
/// no diff removes it.
///
/// A `BoolAttr` that holds is the value `"true"`; a false one, an event and
/// `NoAttr` carry no pair. `class` (space-separated) and `style`
/// (semicolon-separated) are HTML's multi-valued attributes: a later regular
/// value of either joins the one already held, so a computed `style` and a
/// user `Ui.htmlAttribute "style" "z-index: 5"` become one `style`, not two
/// attributes of which the browser keeps only the first. Every other repeated
/// key, an empty held value, or a `BoolAttr` takes the later value.
pub(crate) fn attribute_pairs<'a, M>(
    tag: &str,
    attrs: &'a [Attribute<M>],
) -> Vec<(&'a str, Cow<'a, str>)> {
    /// Pair count past which a key lookup goes through a hash index rather
    /// than a scan, so a long attribute list costs linear time.
    const SCANNED_PAIRS: usize = 16;
    let mut pairs: Vec<(&str, Cow<'_, str>)> = Vec::with_capacity(attrs.len());
    let mut index: HashMap<&str, usize> = HashMap::new();
    for a in attrs {
        let (k, v, joins) = match a {
            Attribute::Attr(k, v) => (k.as_str(), v.as_str(), true),
            Attribute::BoolAttr(k, true) => (k.as_str(), "true", false),
            Attribute::BoolAttr(_, false) | Attribute::EventAttr(_) | Attribute::NoAttr => {
                continue;
            }
        };
        let held = if pairs.len() <= SCANNED_PAIRS {
            pairs.iter().position(|(pk, _)| *pk == k)
        } else {
            if index.is_empty() {
                index.extend(pairs.iter().enumerate().map(|(i, (pk, _))| (*pk, i)));
            }
            index.get(k).copied()
        };
        let Some((_, existing)) = held.and_then(|i| pairs.get_mut(i)) else {
            if !index.is_empty() {
                index.insert(k, pairs.len());
            }
            pairs.push((k, Cow::Borrowed(v)));
            continue;
        };
        let sep = match k {
            "class" => Some(" "),
            "style" if existing.ends_with(';') => Some(" "),
            "style" => Some("; "),
            _ => None,
        };
        match sep.filter(|_| joins && !existing.is_empty()) {
            Some(sep) => {
                let joined = existing.to_mut();
                joined.push_str(sep);
                joined.push_str(v);
            }
            None => *existing = Cow::Borrowed(v),
        }
    }
    if let FrameVerdict::Sandboxed(tokens) = frame_verdict(tag, painted_pairs(attrs)) {
        pairs.retain(|(k, _)| !k.eq_ignore_ascii_case(SANDBOX_ATTR));
        pairs.push((SANDBOX_ATTR, Cow::Owned(tokens.canonical())));
    }
    pairs
}

/// The attribute `Html.keyed` sets; the stamper reads it as the key segment.
const KEY_ATTR: &str = "ipe-key";

/// The attribute carrying an event element's handler identity.
///
/// The client posts it as the handler id of every gesture on the element, and
/// the HTML parser keeps the first of two same-named attributes, so a
/// program-built one would route the gesture to another element's handler.
pub(crate) const HANDLER_ID_ATTR: &str = "data-ipe-hid";

/// The attribute carrying a session's style nonce.
///
/// Only the render sink writes it, from the session's `RenderCtx`; a
/// program-built one would let a page's own data pick the value a policy
/// admits styles by.
const NONCE_ATTR: &str = "nonce";

/// True for a name only the runtime writes, compared ASCII-case-insensitively.
///
/// That is a name starting with [`RESERVED_ATTR_PREFIX`], [`HANDLER_ID_ATTR`],
/// or [`NONCE_ATTR`].
fn is_reserved_attr_name(name: &str) -> bool {
    name.as_bytes()
        .get(..RESERVED_ATTR_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(RESERVED_ATTR_PREFIX))
        || name.eq_ignore_ascii_case(HANDLER_ID_ATTR)
        || name.eq_ignore_ascii_case(NONCE_ATTR)
}

/// A validated HTML **attribute** name (parse-don't-validate). The ONLY way to
/// build one runs the full attribute-name policy — `is_safe_html_name` (charset:
/// no structural-breakout bytes), `!is_dangerous_attr_name` (no script-bearing
/// names) and `!is_reserved_attr_name` (no runtime wire marker) — exactly once.
/// Every emit sink consumes a `SafeAttrName` instead of a raw `&str`, so a sink
/// CANNOT forget a check: an unchecked sink leaving `htmlAttrToString` exposed
/// is unrepresentable. The stamped `ipe-id` is written by the render sink
/// itself, never through this type.
/// NB: element tag names and event-marker names are NOT attribute names — they
/// keep the plain `is_safe_html_name` gate.
struct SafeAttrName<'a>(&'a str);

impl<'a> SafeAttrName<'a> {
    fn parse(name: &'a str) -> Option<Self> {
        if is_safe_html_name(name) && !is_dangerous_attr_name(name) && !is_reserved_attr_name(name)
        {
            Some(SafeAttrName(name))
        } else {
            None
        }
    }

    const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// URL-bearing attributes whose VALUE is fetched/navigated as a URL — a
/// `javascript:` / `vbscript:` / non-image `data:` value here is a script-execution
/// (XSS) vector that HTML entity-escaping does NOT neutralise. Case-insensitive.
fn is_url_attr(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "href"
            | "src"
            | "xlink:href"
            | "formaction"
            | "action"
            | "poster"
            | "cite"
            | "background"
            | "manifest"
            | "longdesc"
            // `<object data="…">` / `<embed src>` navigate the value as a document;
            // a `data:text/html,<script>` or `javascript:` value is script-exec.
            // Not media (is_media_url_attr("data")=false) so data: is blocked here.
            // (Exact name "data" only — `data-*` custom attrs do not match.)
            | "data"
    )
}

/// Media URL attributes where an inert *raster* `data:image/...` value is
/// legitimately useful (and cannot script). `data:` is allowed ONLY here, and
/// only for the raster types in `is_inert_data_image`. All other URL attributes
/// are navigational/document-context, where `data:` is a navigable document
/// (incl. scriptable SVG) and is blocked outright.
fn is_media_url_attr(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "src" | "poster" | "background"
    )
}

/// The URL scheme = the run before the first `:` that precedes any `/`, `?` or
/// `#`, with leading C0 controls/space and intra-scheme controls/whitespace
/// stripped + lowercased (mirrors the browser URL parser, so `java\tscript:` and
/// `\x01javascript:` are caught). `None` = relative / no-scheme URL (safe). Runs
/// BEFORE HTML entity-escaping, so the value is the raw scheme the browser sees.
fn url_scheme(value: &str) -> Option<String> {
    let mut scheme = String::new();
    for ch in value.chars() {
        match ch {
            ':' => return Some(scheme),
            '/' | '?' | '#' => return None,
            c if (c as u32) <= 0x20 => {}
            c => scheme.push(c.to_ascii_lowercase()),
        }
    }
    None
}

/// True only for an inert *raster* `data:image/...` value. SVG (`image/svg+xml`)
/// is deliberately EXCLUDED — an SVG document can execute script — as is every
/// non-image / text/html data payload.
fn is_inert_data_image(value: &str) -> bool {
    let Some(rest) = value.find(':').and_then(|i| value.get(i + 1..)) else {
        return false;
    };
    let rest = rest.trim_start().to_ascii_lowercase();
    match rest.strip_prefix("image/") {
        Some(after) => {
            let subtype: String = after
                .chars()
                .take_while(|c| *c != ';' && *c != ',')
                .collect();
            matches!(
                subtype.as_str(),
                "png"
                    | "jpeg"
                    | "jpg"
                    | "gif"
                    | "webp"
                    | "bmp"
                    | "avif"
                    | "x-icon"
                    | "vnd.microsoft.icon"
            )
        }
        None => false,
    }
}

/// True if `value` is a dangerous URL for attribute `name`. `javascript:` /
/// `vbscript:` are always dangerous. `data:` is dangerous EXCEPT an inert raster
/// `data:image/...` on a media attribute (src/poster/background) — on a
/// navigational attribute (href/action/cite/…) every `data:` is blocked, since a
/// `data:image/svg+xml,<svg onload=…>` navigated there executes script.
fn is_dangerous_url(name: &str, value: &str) -> bool {
    let Some(scheme) = url_scheme(value) else {
        return false;
    };
    if matches!(scheme.as_str(), "javascript" | "vbscript") {
        return true;
    }
    if scheme == "data" {
        return !(is_media_url_attr(name) && is_inert_data_image(value));
    }
    false
}

/// For a URL-bearing attribute, neutralise a dangerous-scheme value to empty
/// (an inert URL) before it is escaped + emitted; pass any other value through.
/// Closes the `href="javascript:…"` / `src="data:text/html,…"` /
/// `href="data:image/svg+xml,…"` XSS class at the render sink (so every producer
/// — Ipe.Html, Ipe.Ui link/image — is covered).
fn sanitise_url_attr<'a>(name: &str, value: &'a str) -> &'a str {
    if is_url_attr(name) && is_dangerous_url(name, value) {
        ""
    } else {
        value
    }
}

/// Sanitise an attribute `(name, value)` pair destined for a Ipe.Web SSE
/// patch that the browser applies via `setAttribute`. Returns the safe pair to
/// set, or `None` to DROP the attribute entirely.
///
/// SSE patches bypass `render_into_ctx` (the first-paint XSS gate), so this is
/// the gate for the patch path — it applies the SAME policy by construction:
/// the name must pass [`SafeAttrName`] (rejects `on*` handlers, `srcdoc`, and
/// structural-breakout charsets) and a URL-bearing value is scheme-checked via
/// [`sanitise_url_attr`]. No HTML-entity escaping is applied: `setAttribute`
/// sets a raw DOM attribute value and does NOT re-parse it as HTML, so escaping
/// would corrupt legitimate values (and is unnecessary for safety). A name that
/// fails policy is dropped, which also covers the removal sentinel (an empty
/// value on a dangerous name must never reach `setAttribute`).
///
/// Every reserved name fails [`SafeAttrName`], so a program-built wire marker
/// never reaches `setAttribute`; the builder's own markers go through
/// [`patch_marker_attr`].
///
/// Consumed by `dom/diff.rs` (the shared patch builder) — always compiled.
pub(crate) fn safe_patch_attr<'a>(name: &'a str, value: &'a str) -> Option<(&'a str, &'a str)> {
    let SafeAttrName(safe_name) = SafeAttrName::parse(name)?;
    Some((safe_name, sanitise_url_attr(name, value)))
}

/// Gate a listener marker the patch builder writes for an event delta.
///
/// Admits a name in the HTML-name charset that carries no script and is
/// neither the stamped `ipe-id` nor `ipe-key` in any case: the `ipe-<event>`
/// and `data-ipe-ev-<event>` markers and [`HANDLER_ID_ATTR`]. Only the
/// builder's event delta calls it, never with a program-built attribute.
pub(crate) fn patch_marker_attr<'a>(name: &'a str, value: &'a str) -> Option<(&'a str, &'a str)> {
    (is_safe_html_name(name)
        && !is_dangerous_attr_name(name)
        && !name.eq_ignore_ascii_case(STAMPED_ID_ATTR)
        && !name.eq_ignore_ascii_case(KEY_ATTR))
    .then_some((name, value))
}

/// Stamp every `HElement` (not HText/HRaw) with a stable `ipe-id` attribute derived
/// from its path. Idempotent: restamping yields the same ids. HText/HRaw nodes
/// are unaddressable.
///
/// The id grammar is `{root}(_{idx}_{tag}[:{key}])*`: the embedded tag means two
/// structurally different subtrees never share an id at the same positional
/// depth, and the optional `:{key}` disambiguator (from an explicit `ipe-key`
/// attribute, or implicit from `name` on form-bearing tags) lets keyed list items
/// and named form fields keep identity across reorder.
///
/// The id is injective over (path, tag, key): the root, every tag and every key
/// pass through [`push_id_segment`], whose output never holds `_` or `:`, so the
/// separators split an id back into exactly the segments that built it. The id
/// holds only `[A-Za-z0-9_.:-]`, so `style_inject` can quote it inside a CSS
/// selector.
///
/// Every program-built `ipe-*` attribute (any ASCII case) on a stamped element is
/// removed, except the `ipe-key` the key segment is read from, so the stamped
/// `ipe-id` is the element's only reserved attribute. The render sink drops the
/// remaining `ipe-key`.
///
/// The same descent names radio groups: a `<fieldset>` carrying
/// [`RADIO_GROUP_MARKER`] loses it, and every unnamed `<input type="radio">`
/// below it (up to a nested marked fieldset) gets `name="ipe-rg-{fieldset ipe-id}"`.
/// The name is a pure function of the fieldset's path, so it is stable across
/// renders and distinct per group within one document. A radio that already
/// has a non-empty `name` keeps it. A serialiser that does not stamp
/// (`Html.toString`) leaves the marker and the radios unnamed.
pub fn assign_ipe_ids<M>(node: &mut Html<M>, path: &str) {
    let mut root = String::with_capacity(path.len());
    push_id_segment(path, &mut root);
    assign_ipe_ids_depth(node, &root, 0, None);
}

/// Separator between an id's root, index and tag segments.
const ID_STEP_SEP: char = '_';

/// Separator between an id's tag segment and its key segment.
const ID_KEY_SEP: char = ':';

/// Lead byte of a hex escape inside an id segment.
const ID_ESCAPE: char = '.';

/// Append `segment` to `out` in the injective id-segment encoding.
///
/// ASCII letters, digits and `-` pass through; every other byte, the escape
/// lead `.` included, becomes `.` followed by its two lowercase hex digits. The
/// output therefore never holds [`ID_STEP_SEP`] or [`ID_KEY_SEP`], and a decoder
/// that reads `.hh` as one byte recovers `segment` exactly.
fn push_id_segment(segment: &str, out: &mut String) {
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'-' {
            out.push(char::from(byte));
        } else {
            out.push(ID_ESCAPE);
            for nibble in [byte >> 4, byte & 0x0f] {
                if let Some(digit) = char::from_digit(u32::from(nibble), 16) {
                    out.push(digit);
                }
            }
        }
    }
}

/// True for a program-built attribute the stamper removes.
///
/// That is every reserved name except the `ipe-key` the key segment is read from.
fn is_unstamped_reserved_attr<M>(attr: &Attribute<M>) -> bool {
    match attr {
        Attribute::Attr(k, _) => k != KEY_ATTR && is_reserved_attr_name(k),
        Attribute::BoolAttr(k, _) => is_reserved_attr_name(k),
        Attribute::EventAttr(_) | Attribute::NoAttr => false,
    }
}

// Same bounded-descent rationale as render_into_ctx (see MAX_HTML_DEPTH): the
// stamper recurses once per nesting level, so an attacker-influenced deep tree
// would overflow the stack. Stop descending at the cap. Kept in step with the
// renderer's cap so a node the renderer drops is also left unstamped.
fn assign_ipe_ids_depth<M>(node: &mut Html<M>, path: &str, depth: usize, group: Option<&str>) {
    if depth >= MAX_HTML_DEPTH {
        return;
    }
    if let Html::HElement(tag, attrs, kids) = node {
        attrs.retain(|a| !is_unstamped_reserved_attr(a));
        attrs.reserve_exact(1);
        attrs.push(Attribute::Attr(STAMPED_ID_ATTR.to_owned(), path.to_owned()));
        let own_group = (tag.as_str() == "fieldset" && take_radio_group_marker(attrs))
            .then(|| format!("ipe-rg-{path}"));
        let group = own_group.as_deref().or(group);
        let mut idx = 0usize;
        for child in kids.iter_mut() {
            if let Html::HElement(ctag, cattrs, _) = child {
                if let Some(name) = group
                    && ctag.as_str() == "input"
                    && attr_value(cattrs, "type") == Some("radio")
                    && attr_value(cattrs, "name").is_none_or(str::is_empty)
                {
                    set_attr(cattrs, "name", name);
                }
                let mut seg = String::from(path);
                seg.push(ID_STEP_SEP);
                seg.push_str(&idx.to_string());
                seg.push(ID_STEP_SEP);
                push_id_segment(ctag, &mut seg);
                if let Some(key) = ipe_id_key(ctag, cattrs) {
                    seg.push(ID_KEY_SEP);
                    push_id_segment(key, &mut seg);
                }
                idx = idx.saturating_add(1);
                assign_ipe_ids_depth(child, &seg, depth.saturating_add(1), group);
            }
        }
    }
}

/// Remove [`RADIO_GROUP_MARKER`] from `attrs`; true when it was present.
fn take_radio_group_marker<M>(attrs: &mut Vec<Attribute<M>>) -> bool {
    let before = attrs.len();
    attrs.retain(|a| !matches!(a, Attribute::Attr(k, _) if k == RADIO_GROUP_MARKER));
    attrs.len() != before
}

/// Stable disambiguator for an element, or `None`.
///
/// Priority: an explicit `ipe-key` attribute (set by `Html.keyed`), then `name`
/// on form-bearing tags. The caller encodes the value with [`push_id_segment`].
fn ipe_id_key<'a, M>(tag: &str, attrs: &'a [Attribute<M>]) -> Option<&'a str> {
    if let Some(k) = attr_value(attrs, KEY_ATTR)
        && !k.is_empty()
    {
        return Some(k);
    }
    if matches!(
        tag,
        "input" | "textarea" | "select" | "form" | "button" | "fieldset"
    ) && let Some(k) = attr_value(attrs, "name")
        && !k.is_empty()
    {
        return Some(k);
    }
    None
}

fn attr_value<'a, M>(attrs: &'a [Attribute<M>], key: &str) -> Option<&'a str> {
    attrs.iter().find_map(|a| match a {
        Attribute::Attr(k, v) if k == key => Some(v.as_str()),
        _ => None,
    })
}

fn set_attr<M>(attrs: &mut Vec<Attribute<M>>, key: &str, val: &str) {
    for a in attrs.iter_mut() {
        if let Attribute::Attr(k, v) = a
            && k == key
        {
            *v = val.to_string();
            return;
        }
    }
    attrs.push(Attribute::Attr(key.to_string(), val.to_string()));
}

// --- Ipe.Html kernel wrappers (`Ffi.callPure "htmlXxx"`) ---
// These match the kernel names used in ipe-stdlib Ipe.Html.ipe — the Ipê-side
// helpers (render, escapeHtml, escapeAttr, attrToString) route here on the Rust
// backend. The codegen converts "htmlRender" → `html_render_()`, etc. Kept in
// this standalone module (not under live/) so a non-Web Ipe.Html / Ipe.Ui app
// renders via Html.toString without pulling the Ipe.Web server machinery.

/// `Ffi.callPure "htmlRender"` — render an Html tree to an HTML string.
#[must_use]
pub fn html_render_<M>(node: Html<M>) -> String {
    render_html(&node)
}

// --- Ipe.Html.Attributes builder kernels (corpus-used direct-backing) ---
//
// Every builder produces the runtime `Attribute<M>` value the render sink
// already knows how to neutralise. SECURITY (P1): the value string is escaped
// at the sink (`render_into_ctx` runs `SafeAttrName::parse` on the KEY and
// `escape::html_attr_into` on the VALUE), so no builder here re-implements escaping —
// there is exactly one escaping boundary. Fixed-key builders (`class`/`id`/…)
// pass a compile-time-literal key (never attacker data). The generic
// `attribute k v` / `boolAttribute k b` pass a runtime key, which the sink
// gates through `SafeAttrName` (drops `on*`/`srcdoc`/charset-invalid names).

/// `Ipe.Html.Attributes.{class,id,href,…}` and the generic
/// `attribute k v` — a string-valued HTML attribute. The key is a literal for
/// the fixed-key builders and a runtime string for `attribute`; both are gated
/// at the render sink.
#[must_use]
pub fn html_named_attr_<M>(key: String, val: String) -> Attribute<M> {
    Attribute::Attr(key, val)
}

/// `Ipe.Html.Attributes.{checked,disabled,…}` and the generic
/// `boolAttribute k b` — a boolean HTML attribute. Renders as `key="true"`
/// when `on` is `true`; omitted when `false` (via the `BoolAttr` render path).
#[must_use]
pub fn html_bool_named_attr_<M>(key: String, on: bool) -> Attribute<M> {
    Attribute::BoolAttr(key, on)
}

/// `Ipe.Html.Attributes.noAttr` — the identity attribute (renders nothing).
/// Makes "no attribute" a first-class value rather than an `Option`/sentinel.
#[must_use]
pub fn html_no_attr_<M>() -> Attribute<M> {
    Attribute::NoAttr
}

/// `Ipe.Html.Events.{onClick,onFocus,onBlur,onMouseOver,onMouseOut}` —
/// a zero-wire-arg event whose `Msg` dispatches as-is. The `name` is the fixed
/// DOM event name supplied by the compile-time `html_event_wire_name` (never
/// attacker data).
#[must_use]
pub fn html_on_msg_<M>(name: String, msg: M) -> Attribute<M> {
    Attribute::EventAttr(Event::OnMsg(name, Box::new(msg)))
}

/// `Ipe.Html.Events.{onInput,onChange,onKeyDown,onKeyUp}` — a
/// value-carrying event; the handler receives the input string. The compiler
/// passes the handler closure in its `Arc`.
#[must_use]
pub fn html_on_string_<M>(
    name: String,
    handler: std::sync::Arc<dyn Fn(String) -> M + Send + Sync>,
) -> Attribute<M> {
    Attribute::EventAttr(Event::OnString(name, handler))
}

/// `Ipe.Html.Events.{onBool,onCheck}` — a checkbox-state event; the
/// handler receives the checked bool.
#[must_use]
pub fn html_on_bool_<M>(
    name: String,
    handler: std::sync::Arc<dyn Fn(bool) -> M + Send + Sync>,
) -> Attribute<M> {
    Attribute::EventAttr(Event::OnBool(name, handler))
}

/// `Ipe.Html.Events.onSubmit` — a heterogeneous-payload event whose
/// handler argument type `T` is DECOUPLED from `M` at the Ipê type level (a
/// form's `onSubmit DoSignIn` must not force `LoginForm` into the surrounding
/// `Html msg`'s type). `T` stays a free HM variable in `constrain.rs`'s
/// scheme; at CODEGEN time Rust's ordinary generic inference recovers the
/// CONCRETE `T` from the handler closure `f`'s own monomorphized signature —
/// no runtime type erasure, no `Arc<dyn Any>`, no downcast — honouring the
/// PRINCIPLES.md no-`dyn Any` rule. Builds
/// `Event::OnForm` directly, reusing the already-correct, already-tested
/// `HandlerIndex::resolve_form` + `decode_form_or_warn` dispatch path.
///
/// Despite the historical name (kept to avoid an unrelated rename touching
/// `naming.rs` / emit-site literals / parity tooling), this is no longer a
/// "raw" escape hatch — it fully participates in typed dispatch.
///
/// The `F: ... + Sync` bound below is genuinely required (`Event`'s
/// `OnForm` slot stores `Arc<dyn Fn(FormData) -> Option<M> + Send + Sync>` —
/// the VNode tree is shared across the live session's dispatch table, so the
/// handler must be safely readable from any thread that services a request).
/// It is NOT enough for the caller to hand a `'static` closure whose captures
/// all happen to be `Sync`: if the emitted Ipê closure is first boxed as a
/// trait object (`Box<dyn Fn(T) -> M + Send + 'static>` — the codegen's
/// generic first-class-function-value rendering, which deliberately omits
/// `+Sync` since most Fn-value consumers only need `Send`) and THAT box is
/// passed straight through as `F`, the call fails: a trait object's
/// auto-trait set is exactly its bound list, so `Box<dyn ... + Send>` is
/// never `Sync` regardless of what the boxed closure actually captures. The
/// codegen call site (`ipe_backend_rust::emit_expr`'s `HtmlEventShape::Raw`
/// arm) closes this by re-wrapping the boxed value in a freshly-declared
/// closure at the call site instead of forwarding the box itself — see that
/// arm's comment for the full mechanism.
#[cfg(feature = "web-core")]
#[must_use]
pub fn html_on_raw_<M, T, F>(name: String, payload: F) -> Attribute<M>
where
    T: serde::de::DeserializeOwned,
    F: Fn(T) -> M + Send + Sync + 'static,
{
    Attribute::EventAttr(Event::OnForm(
        name,
        std::sync::Arc::new(move |fd: FormData| {
            crate::dom::form::decode_form_or_warn::<T>(fd).map(&payload)
        }),
    ))
}

/// Non-`live` builds (Ipe.Tui without the HTTP wire) have no `FormData`
/// decode path. `Ipe.Html.Events.onSubmit` was already inert everywhere
/// before this fix (the `OnRaw` path never dispatched in ANY backend), so
/// degrading to a structural no-op attribute here is not a regression for
/// Tui — it was never functional there and Tui has no form-submit wire
/// concept.
#[cfg(not(feature = "web-core"))]
pub fn html_on_raw_<M, T, F: Fn(T) -> M>(_name: String, _payload: F) -> Attribute<M> {
    Attribute::NoAttr
}

/// `Ipe.Html.Events.onSubmit` BARE-VALUE shape — dispatch a FIXED
/// `msg`, ignoring the submitted `FormData` entirely. Complements
/// `html_on_raw_` (the typed-record decode shape above): the "form fields
/// are already synced into Model via `onInput`/`onChange`; submit just
/// triggers a fixed action" idiom (`onSubmit DoSignUp` where `DoSignUp : Msg`
/// carries no payload — `examples/12-ipevote`'s Auth/Submit/Detail pages).
///
/// Deliberately does NOT route through `decode_form_or_warn` — there is no
/// payload type to decode into (the dispatched value is fixed regardless of
/// form content), and picking an arbitrary placeholder decode target would
/// risk a spurious decode failure on a real form's field data silently
/// swallowing the submit (`decode_form_or_warn` returns `None` — "dispatch no
/// Msg" — on any decode error). Always fires.
///
/// `M: Clone` is not a new requirement: every `Ipe.Web` `Msg` type is
/// already `Clone` by construction (`HandlerIndex<M: Clone>` — every wire
/// event handler, including plain `onClick`'s `Event::OnMsg`, already clones
/// the dispatched value).
#[cfg(feature = "web-core")]
#[must_use]
pub fn html_on_raw_fixed_<M: Clone + Send + Sync + 'static>(name: String, msg: M) -> Attribute<M> {
    Attribute::EventAttr(Event::OnForm(
        name,
        std::sync::Arc::new(move |_fd: FormData| Some(msg.clone())),
    ))
}

/// Non-`live` builds — same degrade-to-no-op rationale as `html_on_raw_`
/// above.
#[cfg(not(feature = "web-core"))]
pub fn html_on_raw_fixed_<M>(_name: String, _msg: M) -> Attribute<M> {
    Attribute::NoAttr
}

/// `Ffi.callPure "htmlEscapeText"` — HTML-escape a string for text content.
///
/// Escapes exactly `&` `<` `>` `'`, each to the entity the `crate::escape`
/// text form names, and leaves `"` raw, so the output is safe only as element
/// text content. A
/// double-quoted attribute value needs [`html_escape_attr_`], which also
/// escapes `"`. Routes through render's escaper, so the set cannot drift.
#[must_use]
pub fn html_escape_text_(s: String) -> String {
    crate::escape::html_text(&s)
}

/// `Ffi.callPure "htmlEscapeAttr"` — escape a string for use in a quoted
/// attribute. Shares render's attr escaper, so a value placed in a single- or
/// double-quoted attribute is escaped identically (no attribute-breakout hole).
#[must_use]
pub fn html_escape_attr_(s: String) -> String {
    crate::escape::html_attr(&s)
}

/// `Ffi.callPure "htmlAttrToString"` — serialise a single Attribute to its key="value" form.
pub fn html_attr_to_string_<M>(attr: Attribute<M>) -> String {
    // Gate the attribute KEY through `SafeAttrName` — the SAME single policy the
    // render_into sink uses (charset + no script-bearing names). The key is
    // emitted UNESCAPED, so a hostile key such as `x onload=alert(1)` or a live
    // `onerror`/`srcdoc` (reachable via Ipe.Html.Attributes.attribute →
    // Ipe.Html.attrToString) would inject markup or execute script that
    // value-escaping cannot stop. An unvetted name drops the whole attribute.
    // Event-marker names are not attribute names → keep `is_safe_html_name`.
    match attr {
        Attribute::Attr(k, v) if SafeAttrName::parse(&k).is_some() => {
            let v = sanitise_url_attr(&k, &v).to_string();
            format!("{}=\"{}\"", k, html_escape_attr_(v))
        }
        Attribute::BoolAttr(k, true) if SafeAttrName::parse(&k).is_some() => k,
        Attribute::EventAttr(e) if is_safe_html_name(e.name()) => {
            format!("data-ipe-on=\"{}\"", e.name())
        }
        // unsafe key / event name, false bool attr, or NoAttr → emit nothing
        Attribute::Attr(..)
        | Attribute::BoolAttr(..)
        | Attribute::EventAttr(..)
        | Attribute::NoAttr => String::new(),
    }
}

// ─── Show rows for the Html runtime types ───────────────────────────────────
// `Internals` leaves: the `<Module.Type>` marker, never the tree, an attribute
// value, or the `M` payload.
crate::stringify::show_row!("Html", Internals, [M] Html<M>, |_| "<Ipe.Html.Html>".to_owned());
crate::stringify::show_row!("HtmlAttribute", Internals, [M] Attribute<M>, |_| "<Ipe.Html.Attribute>".to_owned());
crate::stringify::show_row!("HtmlEvent", Internals, [M] Event<M>, |_| "<Ipe.Html.Events.Event>".to_owned());

// ─── Retained measures for the Html runtime types ───────────────────────────

/// How a measure counts one event.
type EventMeasure<M> = fn(&Event<M>) -> Option<Bytes>;

impl<M: RetainedBytes> Html<M> {
    /// The bytes a committed view keeps resident.
    ///
    /// As its [`RetainedBytes`] measure, except that a handler counts the
    /// allocation of its closure and not the heap the closure's captures own,
    /// which no `dyn Fn` exposes.
    #[must_use]
    pub fn view_bytes(&self) -> Option<Bytes> {
        self.measure(Event::handler_floor)
    }

    // Walked with an explicit worklist, as `Drop` is, so a deep tree is measured
    // without recursion. Each node counts its inline size once; an element adds
    // its tag, its attributes and its children list's spare slots.
    fn measure(&self, event: EventMeasure<M>) -> Option<Bytes> {
        let node = Bytes::inline::<Self>()?;
        let mut total = Bytes::ZERO;
        let mut pending: Vec<&Self> = vec![self];
        while let Some(html) = pending.pop() {
            total = total.checked_add(node)?;
            match html {
                Self::HElement(tag, attrs, children) => {
                    let spare = children.capacity().checked_sub(children.len())?;
                    let attrs_spare = attrs.capacity().checked_sub(attrs.len())?;
                    total = total
                        .plus(tag)?
                        .checked_add(Bytes::inline::<Vec<Attribute<M>>>()?)?
                        .checked_add(Bytes::slots::<Attribute<M>>(attrs_spare)?)?
                        .checked_add(Bytes::slots::<Self>(spare)?)?;
                    for attr in attrs {
                        total = total.checked_add(attr.measure(event)?)?;
                    }
                    pending.extend(children);
                }
                Self::HText(text) | Self::HRaw(text) => total = total.plus(text)?,
            }
        }
        Some(total)
    }
}

impl<M: RetainedBytes> RetainedBytes for Html<M> {
    fn retained_bytes(&self) -> Option<Bytes> {
        self.measure(<Event<M> as RetainedBytes>::retained_bytes)
    }
}

impl<M: RetainedBytes> Attribute<M> {
    fn measure(&self, event: EventMeasure<M>) -> Option<Bytes> {
        let inline = Bytes::inline::<Self>()?;
        match self {
            Self::Attr(key, value) => inline.plus(key)?.plus(value),
            Self::BoolAttr(key, on) => inline.plus(key)?.plus(on),
            Self::EventAttr(e) => inline.checked_add(event(e)?),
            Self::NoAttr => Some(inline),
        }
    }
}

impl<M: RetainedBytes> RetainedBytes for Attribute<M> {
    fn retained_bytes(&self) -> Option<Bytes> {
        self.measure(<Event<M> as RetainedBytes>::retained_bytes)
    }
}

impl<M: RetainedBytes> RetainedBytes for Event<M> {
    fn retained_bytes(&self) -> Option<Bytes> {
        let inline = Bytes::inline::<Self>()?;
        match self {
            // `plus` on the box counts its allocation (`size_of::<M>()`) and
            // the heap `M` owns.
            Self::OnMsg(name, msg) => inline.plus(name)?.plus(msg),
            // A handler's captured heap is not reachable through `dyn Fn`, so
            // its measure is unknown rather than an undercount.
            Self::OnString(..) | Self::OnBool(..) | Self::OnForm(..) | Self::OnWidget(..) => None,
        }
    }
}

impl<M: RetainedBytes> Event<M> {
    /// This event's bytes, a handler counting its closure's allocation but
    /// not the heap its captures own.
    pub(crate) fn handler_floor(&self) -> Option<Bytes> {
        let inline = Bytes::inline::<Self>()?;
        match self {
            // As in the retained measure: the box's allocation and `M`'s heap.
            Self::OnMsg(name, msg) => inline.plus(name)?.plus(msg),
            Self::OnString(name, f) => inline.plus(name)?.checked_add(closure_bytes(f.as_ref())?),
            Self::OnWidget(name, f) => inline.plus(name)?.checked_add(closure_bytes(f.as_ref())?),
            Self::OnBool(name, f) => inline.plus(name)?.checked_add(closure_bytes(f.as_ref())?),
            Self::OnForm(name, f) => inline.plus(name)?.checked_add(closure_bytes(f.as_ref())?),
        }
    }
}

/// The bytes the `Arc` allocation of closure `f` holds: its two reference
/// counters and the closure itself.
fn closure_bytes<F: ?Sized>(f: &F) -> Option<Bytes> {
    Bytes::inline::<[usize; 2]>()?.plus_count(std::mem::size_of_val(f))
}

/// The drawn source view the runtime's view-measure tests share.
///
/// One builder for the element bound in this module and the render history
/// in `dom::dispatch`, so the two modules' tests measure the same shape.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod drawn_shape {
    use super::{Attribute, Event, Html, assign_ipe_ids};

    /// A 600-byte message, as wide as a rich app `Msg`.
    #[derive(Clone)]
    #[allow(dead_code)] // the bytes are the width; nothing reads them
    pub struct Wide(pub [u8; 600]);

    crate::retained::inline_measure!(Wide);

    /// An ancestor's key, as long as an app's `Attr.key` value.
    const ANCESTOR_KEY: &str = "unit-row-key";

    /// The levels from a `code` block down to its deepest drawn element.
    ///
    /// The `code` block, a line, a coloured run and the escape inside it.
    pub const DRAWN_LEVELS: usize = 4;

    /// A source view drawn as a code viewer draws it.
    ///
    /// `depth` is the nesting depth of its deepest element, the root counted:
    /// `depth - DRAWN_LEVELS` keyed `div` ancestors hold one `code` block of
    /// `lines` line elements with newline text between them. Each line holds
    /// `runs` coloured runs, each followed by a text sibling; each run holds
    /// `escapes` escape spans, each after a text sibling and holding its
    /// spelling, the span both marked and styled. Each line carries a click
    /// handler with a [`Wide`] message when `handlers` holds. When `spare`
    /// holds, every children list keeps as many spare slots as it has
    /// children, the most a list grown by doubling keeps.
    #[derive(Clone, Copy)]
    pub struct DrawnShape {
        pub depth: usize,
        pub lines: usize,
        pub runs: usize,
        pub escapes: usize,
        pub handlers: bool,
        pub spare: bool,
    }

    impl DrawnShape {
        /// The keyed ancestors above the `code` block.
        const fn ancestors(self) -> usize {
            self.depth.saturating_sub(DRAWN_LEVELS)
        }

        /// The elements the shape draws, or `None` on overflow.
        pub fn elements(self) -> Option<usize> {
            let per_run = self.escapes.checked_add(1)?;
            let per_line = self.runs.checked_mul(per_run)?.checked_add(1)?;
            self.lines
                .checked_mul(per_line)?
                .checked_add(1)?
                .checked_add(self.ancestors())
        }

        /// The view, stamped from root `"r"`.
        pub fn build(self) -> Html<Wide> {
            let mut view = self.code();
            for _ in 0..self.ancestors() {
                view = Html::HElement(
                    "div".into(),
                    vec![Attribute::Attr("ipe-key".into(), ANCESTOR_KEY.into())],
                    vec![view],
                );
            }
            assign_ipe_ids(&mut view, "r");
            view
        }

        /// `kids` with the spare capacity the shape asks for.
        fn children(self, mut kids: Vec<Html<Wide>>) -> Vec<Html<Wide>> {
            if self.spare {
                kids.reserve_exact(kids.len());
            } else {
                kids.shrink_to_fit();
            }
            kids
        }

        fn code(self) -> Html<Wide> {
            let mut kids = Vec::new();
            for row in 0..self.lines {
                if row > 0 {
                    kids.push(Html::HText("\n".into()));
                }
                kids.push(self.line(row));
            }
            Html::HElement(
                "code".into(),
                vec![Attribute::Attr(
                    "style".into(),
                    "display:block;flex:1;white-space:pre;color:#cdcdd7;unicode-bidi:bidi-override;direction:ltr".into(),
                )],
                self.children(kids),
            )
        }

        fn line(self, row: usize) -> Html<Wide> {
            let mut attrs = vec![Attribute::Attr("style".into(), "white-space:pre".into())];
            if self.handlers {
                attrs.push(Attribute::EventAttr(Event::OnMsg(
                    "click".into(),
                    Box::new(Wide([0; 600])),
                )));
            }
            let mut kids = Vec::new();
            for col in 0..self.runs {
                kids.push(self.run(row, col));
                kids.push(Html::HText(format!(" s{col}")));
            }
            Html::HElement("span".into(), attrs, self.children(kids))
        }

        /// One coloured run: `escapes` escape spans, each after its text.
        fn run(self, row: usize, col: usize) -> Html<Wide> {
            let mut kids = Vec::new();
            for _ in 0..self.escapes {
                kids.push(Html::HText(format!("t{row}x{col}")));
                kids.push(escape());
            }
            Html::HElement(
                "span".into(),
                vec![Attribute::Attr("style".into(), "color:#c792ea".into())],
                self.children(kids),
            )
        }
    }

    /// One escape span: marked, styled, holding one escape's spelling.
    fn escape() -> Html<Wide> {
        Html::HElement(
            "span".into(),
            vec![
                Attribute::Attr("data-review-escape".into(), "true".into()),
                Attribute::Attr(
                    "style".into(),
                    "background-color:#4a3410;border:1px solid #c98a2b;border-radius:2px;color:#ffd27a".into(),
                ),
            ],
            vec![Html::HText("\\u{202E}".into())],
        )
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    #[derive(Clone, Debug, PartialEq)]
    enum Msg {
        Inc,
    }

    /// An element with no attributes.
    const NO_ATTRS: &[Attribute<()>] = &[];

    /// An element `tag` with attributes `attrs` and no children.
    fn bare(tag: &str, attrs: Vec<Attribute<()>>) -> Html<()> {
        Html::HElement(tag.into(), attrs, vec![])
    }

    fn attr(k: &str, v: &str) -> Attribute<()> {
        Attribute::Attr(k.into(), v.into())
    }

    /// The `sandbox` attributes `out` paints, in any ASCII case.
    fn sandboxes(out: &str) -> usize {
        out.to_ascii_lowercase().matches(" sandbox=").count()
    }

    /// An `iframe` the app gave no `sandbox` paints the empty one, whatever
    /// the tag's case.
    #[test]
    fn an_iframe_without_sandbox_renders_an_empty_sandbox() {
        let built =
            crate::ui::helpers::html_node_::<()>("iframe".into(), vec![attr("src", "/")], vec![]);
        let out = render_html(&built);
        assert_eq!(out, "<iframe sandbox=\"\" src=\"/\"></iframe>");
        let out = render_html(&bare("IFRAME", vec![attr("src", "/")]));
        assert_eq!(sandboxes(&out), 1, "{out}");
        assert!(out.contains(" sandbox=\"\""), "{out}");
    }

    /// Every case variant of `sandbox` folds into one, the last one read.
    #[test]
    fn every_case_of_sandbox_folds_into_one_canonical_value() {
        let out = render_html(&bare(
            "iframe",
            vec![
                attr("sandbox", "allow-forms"),
                attr("SANDBOX", "allow-modals"),
                attr("SandBox", "ALLOW-SCRIPTS allow-popups allow-scripts"),
            ],
        ));
        assert_eq!(sandboxes(&out), 1, "{out}");
        assert!(
            out.contains(" sandbox=\"allow-popups allow-scripts\""),
            "{out}"
        );
    }

    /// Neither token that gives the framed document or its popups the app's
    /// origin back reaches the page, in any case; a token that is only ASCII
    /// case-equal through a non-ASCII byte, or carries a NUL, is unknown.
    #[test]
    fn allow_same_origin_never_reaches_the_page() {
        let out = render_html(&bare(
            "iframe",
            vec![attr(
                "sandbox",
                "allow-scripts ALLOW-SAME-ORIGIN allow-same-origin allow-popups-to-escape-sandbox",
            )],
        ));
        assert_eq!(out, "<iframe sandbox=\"allow-scripts\"></iframe>");
        let out = render_html(&bare(
            "iframe",
            vec![attr(
                "sandbox",
                "allow-pointer-loc\u{212A} allow-forms\u{0} allow-modals",
            )],
        ));
        assert_eq!(out, "<iframe sandbox=\"allow-modals\"></iframe>");
    }

    /// An unknown token is dropped, and a held boolean `sandbox` (painted
    /// `"true"`, no token) is the empty sandbox.
    #[test]
    fn unknown_sandbox_tokens_are_dropped() {
        let out = render_html(&bare(
            "iframe",
            vec![attr("sandbox", "allow-everything allow-forms bogus")],
        ));
        assert_eq!(out, "<iframe sandbox=\"allow-forms\"></iframe>");
        let out = render_html(&bare(
            "iframe",
            vec![Attribute::BoolAttr("sandbox".into(), true)],
        ));
        assert_eq!(out, "<iframe sandbox=\"\"></iframe>");
    }

    /// An `embed`, `object` or `frame` carrying its loading attribute, in any
    /// key case and with any value, renders nothing, in HTML and in foreign
    /// content alike; without that attribute it still renders.
    #[test]
    fn a_frame_loader_with_its_url_renders_nothing() {
        let loaders = [
            ("embed", "src"),
            ("EMBED", "SRC"),
            ("object", "data"),
            ("Object", "Data"),
            ("frame", "src"),
            ("frame", "SRC"),
        ];
        for (tag, key) in loaders {
            for value in ["", " ", "/", "https://x"] {
                let loader = || bare(tag, vec![attr("title", "t"), attr(key, value)]);
                let shown = |outer: Html<()>| {
                    let out = render_html(&outer);
                    assert!(
                        !out.to_ascii_lowercase()
                            .contains(&format!("<{}", tag.to_ascii_lowercase())),
                        "<{tag} {key}={value:?}> rendered: {out}"
                    );
                };
                shown(Html::HElement("div".into(), vec![], vec![loader()]));
                shown(Html::HElement("svg".into(), vec![], vec![loader()]));
                shown(Html::HElement(
                    "svg".into(),
                    vec![],
                    vec![Html::HElement(
                        "foreignObject".into(),
                        vec![],
                        vec![loader()],
                    )],
                ));
            }
            assert_eq!(
                admit_element(tag, &[attr(key, "/")], &[] as &[Html<()>]),
                Err(ElementRefusal::UnsandboxableFrame)
            );
        }
        let held = bare("embed", vec![Attribute::BoolAttr("src".into(), true)]);
        assert!(!render_html(&held).contains("<embed"));
        let out = render_html(&bare("embed", vec![attr("type", "x")]));
        assert!(out.starts_with("<embed"), "{out}");
        let out = render_html(&bare("object", vec![attr("src", "/")]));
        assert!(out.starts_with("<object"), "{out}");
    }

    /// `Html.node` builds a frame loader with its URL as empty text.
    #[test]
    fn html_node_refuses_a_frame_loader() {
        for (tag, key) in FRAME_LOADERS {
            let node =
                crate::ui::helpers::html_node_::<()>(tag.into(), vec![attr(key, "/")], vec![]);
            assert!(
                matches!(&node, Html::HText(t) if t.is_empty()),
                "<{tag} {key}>: {node:?}"
            );
        }
        let kept = crate::ui::helpers::html_node_::<()>("embed".into(), vec![], vec![]);
        assert!(matches!(kept, Html::HElement(..)));
    }

    /// The browser client's literal copy of the frame tables equals the
    /// runtime's, and the rule covers exactly the four document-loading tags.
    #[test]
    fn client_js_frame_table_matches_the_runtime() {
        const CLIENT_JS: &str = include_str!("web/client.js");
        let tokens: Vec<String> = SANDBOX_TOKENS.iter().map(|t| format!("\"{t}\"")).collect();
        let tokens = format!("var __IPE_SANDBOX_TOKENS = [{}];", tokens.join(", "));
        let loaders: Vec<String> = FRAME_LOADERS
            .iter()
            .map(|(t, k)| format!("[\"{t}\", \"{k}\"]"))
            .collect();
        let loaders = format!("var __IPE_FRAME_LOADERS = [{}];", loaders.join(", "));
        for (decl, name) in [
            (tokens, "__IPE_SANDBOX_TOKENS ="),
            (loaders, "__IPE_FRAME_LOADERS ="),
        ] {
            assert_eq!(CLIENT_JS.matches(name).count(), 1, "one {name}");
            assert_eq!(CLIENT_JS.matches(decl.as_str()).count(), 1, "{decl}");
        }
        let mut tags: Vec<&str> = FRAME_LOADERS.iter().map(|(t, _)| *t).collect();
        tags.push(IFRAME_TAG);
        tags.sort_unstable();
        assert_eq!(tags, ["embed", "frame", "iframe", "object"]);
        for forbidden in ["allow-same-origin", "allow-popups-to-escape-sandbox"] {
            assert!(!SANDBOX_TOKENS.contains(&forbidden), "{forbidden}");
            assert_eq!(SandboxTokens::parse(forbidden).canonical(), "");
        }
    }

    /// A long attribute list merges and overrides exactly as a short one: the
    /// hash index past the scan threshold agrees with a plain scan.
    #[test]
    fn attribute_pairs_agree_past_the_scan_threshold() {
        fn scanned(attrs: &[Attribute<()>]) -> Vec<(&str, String)> {
            let mut pairs: Vec<(&str, String)> = vec![];
            for a in attrs {
                let (k, v, joins) = match a {
                    Attribute::Attr(k, v) => (k.as_str(), v.as_str(), true),
                    Attribute::BoolAttr(k, true) => (k.as_str(), "true", false),
                    _ => continue,
                };
                match pairs.iter_mut().find(|(pk, _)| *pk == k) {
                    Some((_, e)) if joins && !e.is_empty() && k == "class" => {
                        e.push(' ');
                        e.push_str(v);
                    }
                    Some((_, e)) if joins && !e.is_empty() && k == "style" => {
                        e.push_str(if e.ends_with(';') { " " } else { "; " });
                        e.push_str(v);
                    }
                    Some((_, e)) => *e = v.to_owned(),
                    None => pairs.push((k, v.to_owned())),
                }
            }
            pairs
        }
        let mut attrs: Vec<Attribute<()>> = vec![
            Attribute::Attr("class".into(), "a".into()),
            Attribute::Attr("style".into(), "p: 1;".into()),
        ];
        attrs.extend((0..40).map(|i| Attribute::Attr(format!("data-{i}"), i.to_string())));
        attrs.extend([
            Attribute::Attr("class".into(), "b".into()),
            Attribute::Attr("style".into(), "q: 2".into()),
            Attribute::Attr("data-3".into(), "over".into()),
            Attribute::BoolAttr("class".into(), true),
            Attribute::Attr("class".into(), "c".into()),
            Attribute::Attr("data-late".into(), String::new()),
            Attribute::Attr("data-late".into(), "set".into()),
        ]);
        for len in 0..=attrs.len() {
            let slice = attrs.get(..len).unwrap_or_default();
            let got: Vec<(&str, String)> = attribute_pairs("div", slice)
                .into_iter()
                .map(|(k, v)| (k, v.into_owned()))
                .collect();
            assert_eq!(got, scanned(slice), "{len}");
        }
    }

    // A tree far deeper than any recursion could walk is measured on the heap,
    // and the measure covers every text byte it holds.
    #[test]
    fn a_deep_tree_is_measured_without_recursion() {
        let depth = 200_000_usize;
        let mut tree: Html<()> = Html::HText("x".repeat(64));
        for _ in 0..depth {
            tree = Html::HElement("div".into(), Vec::new(), vec![tree]);
        }
        let measured = tree.retained_bytes().map(Bytes::get);
        let floor = u64::try_from(64 + 3 * depth).unwrap();
        assert!(measured.is_some_and(|n| n >= floor), "{measured:?}");
    }

    // A handler's captured heap is unreachable, so a handler event is unmeasurable.
    #[test]
    fn a_handler_event_is_unmeasurable() {
        let attr: Attribute<String> = html_on_string_("input".into(), std::sync::Arc::new(|s| s));
        assert_eq!(attr.retained_bytes(), None);
    }

    // A committed view counts a handler by its closure, so a view the
    // retained measure refuses is still charged, and every text byte with it.
    #[test]
    fn a_view_with_handlers_is_measured_by_its_closures() {
        let text = "t".repeat(4096);
        let view: Html<String> = Html::HElement(
            "input".into(),
            vec![html_on_string_("input".into(), std::sync::Arc::new(|s| s))],
            vec![Html::HText(text)],
        );
        assert_eq!(view.retained_bytes(), None);
        assert!(view.view_bytes().is_some_and(|n| n.get() >= 4096));
    }

    // A view without handlers counts the same under both measures.
    #[test]
    fn a_handler_free_view_measures_alike() {
        let view: Html<String> = Html::HElement(
            "p".into(),
            vec![
                Attribute::Attr("class".into(), "c".repeat(64)),
                Attribute::EventAttr(Event::OnMsg("click".into(), Box::new("m".repeat(64)))),
            ],
            vec![Html::HText("x".repeat(64))],
        );
        assert!(view.retained_bytes().is_some());
        assert_eq!(view.view_bytes(), view.retained_bytes());
    }

    // A message an event carries counts toward the attribute holding it.
    #[test]
    fn an_event_counts_its_message() {
        let msg = "m".repeat(4096);
        let attr: Attribute<String> =
            Attribute::EventAttr(Event::OnMsg("click".into(), Box::new(msg)));
        assert!(attr.retained_bytes().is_some_and(|n| n.get() >= 4096));
    }

    use super::drawn_shape::{DrawnShape, Wide};

    /// A 4 KiB message.
    #[derive(Clone)]
    #[allow(dead_code)] // the bytes are the width; nothing reads them
    struct Huge([u8; 4096]);

    crate::retained::inline_measure!(Huge);

    // A wide message does not widen the attribute that carries it.
    #[test]
    fn a_wide_message_keeps_the_attribute_size() {
        assert_eq!(size_of::<Attribute<Wide>>(), size_of::<Attribute<()>>());
        assert_eq!(size_of::<Attribute<Huge>>(), size_of::<Attribute<()>>());
    }

    // Every boxed message is charged at its full width, not by its pointer.
    #[test]
    fn a_boxed_message_is_charged_at_its_width() {
        let n = 32_usize;
        let view: Html<Huge> = Html::HElement(
            "div".into(),
            Vec::new(),
            (0..n)
                .map(|_| {
                    Html::HElement(
                        "button".into(),
                        vec![html_on_msg_("click".into(), Huge([0; 4096]))],
                        Vec::new(),
                    )
                })
                .collect(),
        );
        let floor = u64::try_from(n * 4096).ok();
        let measured = view.view_bytes().map(Bytes::get);
        assert!(
            measured.zip(floor).is_some_and(|(m, f)| m >= f),
            "{measured:?} < {floor:?}"
        );
    }

    // Stamping an element adds exactly the one slot its id needs.
    #[test]
    fn a_stamped_element_holds_no_spare_attribute_slot() {
        let mut view: Html<()> = Html::HElement(
            "div".into(),
            vec![Attribute::Attr("class".into(), "c".into())],
            vec![Html::HElement("span".into(), Vec::new(), Vec::new())],
        );
        assign_ipe_ids(&mut view, "0");
        let mut pending = vec![&view];
        let mut seen = 0_usize;
        while let Some(node) = pending.pop() {
            if let Html::HElement(_, attrs, kids) = node {
                assert_eq!(attrs.capacity(), attrs.len(), "{attrs:?}");
                seen += 1;
                pending.extend(kids);
            }
        }
        assert_eq!(seen, 2);
    }

    // The shape's element count is the elements it draws, and its deepest
    // element sits at its depth, so a bound taken per counted element at a
    // declared depth is a bound per drawn one at that depth.
    #[test]
    fn the_drawn_shape_draws_the_elements_it_counts() {
        let shape = DrawnShape {
            depth: 9,
            lines: 12,
            runs: 3,
            escapes: 2,
            handlers: true,
            spare: true,
        };
        let view = shape.build();
        let mut pending = vec![(&view, 1_usize)];
        let (mut seen, mut deepest) = (0_usize, 0_usize);
        while let Some((node, depth)) = pending.pop() {
            if let Html::HElement(_, _, kids) = node {
                seen += 1;
                deepest = deepest.max(depth);
                pending.extend(kids.iter().map(|kid| (kid, depth + 1)));
            }
        }
        assert_eq!(Some(seen), shape.elements());
        assert_eq!(deepest, shape.depth);
    }

    /// The element bound at the declared depth, measured on the shared shape.
    #[cfg(feature = "web")]
    mod element_bound {
        use super::super::drawn_shape::DrawnShape;
        use crate::web::budget::{DRAWN_ELEMENT_BYTES, DRAWN_ELEMENT_DEPTH};

        /// The resident bytes per element of `shape` once stamped, or `None` on overflow.
        fn bytes_per_element(shape: DrawnShape) -> Option<u64> {
            let measured = shape.build().view_bytes()?.get();
            measured.checked_div(u64::try_from(shape.elements()?).ok()?)
        }

        /// Source views of about the app's element ceiling, their deepest
        /// element at `depth`, every children list at its most spare: the line
        /// ceiling's lines of two runs of one escape each; one line of one run
        /// of six thousand escapes, the dearest element (two attributes, its
        /// spelling and a text sibling) and the most of it; and a mix.
        ///
        /// A child index past the thousandth spells four digits.
        fn drawn_at(depth: usize) -> [DrawnShape; 3] {
            let shape = |lines, runs, escapes| DrawnShape {
                depth,
                lines,
                runs,
                escapes,
                handlers: false,
                spare: true,
            };
            [shape(5000, 2, 1), shape(1, 1, 6000), shape(1000, 1, 5)]
        }

        // Every composition of a source view a code viewer draws, its deepest
        // element at the depth the contract declares under keyed ancestors,
        // stays within the per-element bound once stamped: the bound is the
        // dearest composition's, not one view's average.
        #[test]
        fn a_drawn_source_view_of_any_composition_stays_within_the_element_bound() {
            for shape in drawn_at(DRAWN_ELEMENT_DEPTH) {
                let per = bytes_per_element(shape);
                assert!(
                    per.is_some_and(|p| p <= DRAWN_ELEMENT_BYTES.get()),
                    "{per:?} > {DRAWN_ELEMENT_BYTES:?} at {} lines x {} runs x {} escapes",
                    shape.lines,
                    shape.runs,
                    shape.escapes
                );
            }
        }

        // The same views forty levels deeper than the contract pass the
        // bound: the measure sees the depth, so a deeper page turns it red.
        #[test]
        fn a_drawn_source_view_past_the_declared_depth_breaks_the_element_bound() {
            for shape in drawn_at(DRAWN_ELEMENT_DEPTH + 40) {
                let per = bytes_per_element(shape);
                assert!(
                    per.is_some_and(|p| p > DRAWN_ELEMENT_BYTES.get()),
                    "{per:?} <= {DRAWN_ELEMENT_BYTES:?} at {} lines x {} runs x {} escapes",
                    shape.lines,
                    shape.runs,
                    shape.escapes
                );
            }
        }
    }

    // An attribute's `{:?}` names the attribute and hides its value.
    #[test]
    fn attribute_debug_hides_the_value() {
        let shown = format!(
            "{:?} {:?}",
            Attribute::<()>::Attr("value".into(), "S3CR3T".into()),
            Attribute::<()>::BoolAttr("checked".into(), true),
        );
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert_eq!(
            shown,
            "Attr(\"value\",<redacted>) BoolAttr(\"checked\",<redacted>)"
        );
    }

    #[test]
    fn render_escapes_and_emits_attrs_events_void() {
        let t: Html<()> = Html::HElement(
            "div".into(),
            vec![Attribute::Attr("class".into(), "x".into())],
            vec![
                Html::HElement(
                    "input".into(),
                    vec![
                        Attribute::Attr("value".into(), "a<b".into()),
                        Attribute::BoolAttr("disabled".into(), true),
                    ],
                    vec![],
                ),
                Html::HText("1 < 2".into()),
                Html::HRaw("<b>ok</b>".into()),
            ],
        );
        let mut t = t;
        assign_ipe_ids(&mut t, "r");
        let s = render_html(&t);
        assert!(s.contains(r#"<div class="x" ipe-id="r">"#), "{s}");
        // Attrs are sorted alphabetically; BoolAttr renders as `k="true"`; void
        // elements self-close.
        assert!(
            s.contains(r#"<input disabled="true" ipe-id="r_0_input" value="a&lt;b" />"#),
            "{s}"
        );
        assert!(s.contains("1 &lt; 2"));
        assert!(s.contains("<b>ok</b>"));
        assert!(s.contains("</div>"));
    }

    // SECURITY regression: event-handler + srcdoc attribute NAMES execute script
    // regardless of value-escaping. `Html.attribute` names can be attacker-derived,
    // so the render sink must DROP them (is_safe_html_name alone permits them).
    #[test]
    fn render_drops_event_handler_and_srcdoc_attrs() {
        let t: Html<()> = Html::HElement(
            "img".into(),
            vec![
                Attribute::Attr("onerror".into(), "alert(1)".into()),
                Attribute::Attr("OnClick".into(), "x".into()),
                Attribute::Attr("srcdoc".into(), "<script>1</script>".into()),
                Attribute::Attr("alt".into(), "ok".into()),
            ],
            vec![],
        );
        let mut t = t;
        assign_ipe_ids(&mut t, "r");
        let s = render_html(&t);
        let low = s.to_ascii_lowercase();
        assert!(!low.contains("onerror"), "{s}");
        assert!(!low.contains("onclick"), "{s}");
        assert!(!low.contains("srcdoc"), "{s}");
        assert!(s.contains(r#"alt="ok""#), "{s}");
        assert!(is_dangerous_attr_name("onmouseover") && is_dangerous_attr_name("SRCDOC"));
        // Conservative by design: any name starting with `on` is dropped (no
        // legitimate non-event HTML attribute begins with `on`; custom data goes
        // through `data-*`).
        assert!(is_dangerous_attr_name("onfoo"));
        assert!(!is_dangerous_attr_name("class") && !is_dangerous_attr_name("href"));
        // SafeAttrName is the single policy both sinks share.
        assert!(SafeAttrName::parse("class").is_some());
        assert!(SafeAttrName::parse("onload").is_none() && SafeAttrName::parse("srcdoc").is_none());
    }

    // SECURITY: the sibling sink `Ipe.Html.attrToString` must drop the SAME
    // script-bearing names as render_into — both route through SafeAttrName.
    #[test]
    fn attr_to_string_drops_event_handler_and_srcdoc() {
        let onload: String =
            html_attr_to_string_(Attribute::<()>::Attr("onload".into(), "alert(1)".into()));
        let srcdoc: String = html_attr_to_string_(Attribute::<()>::Attr(
            "srcdoc".into(),
            "<script>1</script>".into(),
        ));
        let onbool: String =
            html_attr_to_string_(Attribute::<()>::BoolAttr("onclick".into(), true));
        let ok: String = html_attr_to_string_(Attribute::<()>::Attr("alt".into(), "x".into()));
        assert_eq!(onload, "");
        assert_eq!(srcdoc, "");
        assert_eq!(onbool, "");
        assert_eq!(ok, r#"alt="x""#);
    }

    #[test]
    fn style_attrs_merge_into_one_attribute() {
        // Ipe.Ui composes a computed inline `style` from layout attrs
        // (padding/background/border) AND a user `Ui.htmlAttribute "style" V`
        // adds another. The renderer MUST merge both into ONE `style="…"` —
        // emitting two `style="…"` attrs makes the browser keep only the first,
        // silently dropping the user's declarations.
        let computed = "padding: 8px; background-color: rgb(255, 102, 0)";
        let t: Html<()> = Html::HElement(
            "div".into(),
            vec![
                Attribute::Attr("style".into(), computed.into()),
                Attribute::Attr("style".into(), "z-index: 5".into()),
            ],
            vec![],
        );
        let s = render_html(&t);
        // Exactly ONE style attribute …
        assert_eq!(
            s.matches("style=\"").count(),
            1,
            "expected a single style attr: {s}"
        );
        // … containing BOTH the computed declarations AND the user's z-index,
        // joined `; ` (computed has no trailing `;`), computed first/user last.
        assert!(
            s.contains(r#"style="padding: 8px; background-color: rgb(255, 102, 0); z-index: 5""#),
            "merged style must keep both declarations: {s}"
        );
    }

    #[test]
    fn style_merge_handles_trailing_semicolon_and_user_only() {
        // Trailing `;` on the computed style ⇒ single-space join (no `;;`).
        let t: Html<()> = Html::HElement(
            "div".into(),
            vec![
                Attribute::Attr("style".into(), "color: red;".into()),
                Attribute::Attr("style".into(), "z-index: 5".into()),
            ],
            vec![],
        );
        let s = render_html(&t);
        assert!(s.contains(r#"style="color: red; z-index: 5""#), "{s}");
        assert!(!s.contains(";;"), "no double semicolon: {s}");

        // Only a user style (no computed) ⇒ emitted verbatim, single attr.
        let only: Html<()> = Html::HElement(
            "div".into(),
            vec![Attribute::Attr("style".into(), "z-index: 5".into())],
            vec![],
        );
        let s2 = render_html(&only);
        assert_eq!(s2.matches("style=\"").count(), 1, "{s2}");
        assert!(s2.contains(r#"style="z-index: 5""#), "{s2}");

        // `class` merges space-separated (HTML multi-valued parity).
        let cls: Html<()> = Html::HElement(
            "div".into(),
            vec![
                Attribute::Attr("class".into(), "a".into()),
                Attribute::Attr("class".into(), "b".into()),
            ],
            vec![],
        );
        let s3 = render_html(&cls);
        assert_eq!(s3.matches("class=\"").count(), 1, "{s3}");
        assert!(s3.contains(r#"class="a b""#), "{s3}");
    }

    #[test]
    fn textarea_value_renders_as_content_not_attr() {
        // <textarea value="…"> renders EMPTY in browsers — the value must become
        // the text content. Ipe.Ui.Input.multiline
        // sets a `value` attr; the renderer must move it into the body.
        let t: Html<()> = Html::HElement(
            "textarea".into(),
            vec![Attribute::Attr("value".into(), "fill the column".into())],
            vec![],
        );
        let s = render_html(&t);
        assert!(
            !s.contains("value=\""),
            "value attr must be stripped from textarea: {s}"
        );
        assert!(
            s.contains(">fill the column</textarea>"),
            "value must be content: {s}"
        );
    }

    #[test]
    fn textarea_value_is_escaped_and_select_strips_value() {
        // textarea content is HTML-escaped (XSS); explicit children win over the
        // attr-derived value; <select> strips a redundant `value` attr (no content).
        let ta: Html<()> = Html::HElement(
            "textarea".into(),
            vec![Attribute::Attr("value".into(), "a<b'c".into())],
            vec![],
        );
        assert!(
            render_html(&ta).contains(">a&lt;b&#39;c</textarea>"),
            "{}",
            render_html(&ta)
        );

        let ta_kids: Html<()> = Html::HElement(
            "textarea".into(),
            vec![Attribute::Attr("value".into(), "ignored".into())],
            vec![Html::HText("explicit".into())],
        );
        let s = render_html(&ta_kids);
        assert!(
            s.contains(">explicit</textarea>") && !s.contains("ignored"),
            "{s}"
        );

        let sel: Html<()> = Html::HElement(
            "select".into(),
            vec![Attribute::Attr("value".into(), "x".into())],
            vec![],
        );
        assert!(
            !render_html(&sel).contains("value="),
            "select strips value: {}",
            render_html(&sel)
        );
    }

    /// The text kernel escapes exactly `& < > '` and leaves `"` raw; the attr
    /// kernel adds `"`, the one byte that separates the two contexts. Each
    /// writes the owner's bytes; `crate::escape` pins the entities themselves.
    #[test]
    fn escape_kernels_pin_their_escaped_sets() {
        for c in (0x20u8..=0x7E).map(char::from) {
            let raw = c.to_string();
            let text = html_escape_text_(raw.clone());
            let attr = html_escape_attr_(raw.clone());
            assert_eq!(text, crate::escape::html_text(&raw), "{c:?}");
            assert_eq!(attr, crate::escape::html_attr(&raw), "{c:?}");
            assert_eq!(
                text != raw,
                matches!(c, '&' | '<' | '>' | '\''),
                "text kernel on {c:?}"
            );
            assert_eq!(
                attr != raw,
                matches!(c, '&' | '<' | '>' | '\'' | '"'),
                "attr kernel on {c:?}"
            );
        }
    }

    #[test]
    fn single_quote_is_escaped_everywhere() {
        // A `'` in attr/text/kernel output must become `&#39;` so a value placed
        // in a single-quoted attribute can't break out (XSS) and the escape set
        // matches  html.EscapeString.
        assert_eq!(
            html_escape_text_("it's <b>".to_string()),
            "it&#39;s &lt;b&gt;"
        );
        assert_eq!(html_escape_attr_("a'\"b".to_string()), "a&#39;&#34;b");
        assert_eq!(html_escape_text_("x'y".to_string()), "x&#39;y");
        assert_eq!(html_escape_attr_("x'y".to_string()), "x&#39;y");
        // Round-trips through render on a real attribute value.
        let mut t: Html<()> = Html::HElement(
            "a".into(),
            vec![Attribute::Attr("href".into(), "/x?q='z".into())],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let s = render_html(&t);
        assert!(s.contains("href=\"/x?q=&#39;z\""), "{s}");
    }

    #[test]
    fn render_emits_data_event_attr() {
        let t: Html<()> = Html::HElement(
            "button".into(),
            vec![Attribute::EventAttr(Event::OnMsg(
                "click".into(),
                Box::new(()),
            ))],
            vec![],
        );
        let mut t = t;
        assign_ipe_ids(&mut t, "r");
        let s = render_html(&t);
        assert!(s.contains(r#"data-ipe-on="click""#), "{s}");
    }

    #[test]
    fn ipe_ids_are_stable_and_pathed() {
        let mut t: Html<()> = Html::HElement(
            "div".into(),
            vec![],
            vec![
                Html::HElement("span".into(), vec![], vec![Html::HText("a".into())]),
                Html::HElement("span".into(), vec![], vec![]),
            ],
        );
        assign_ipe_ids(&mut t, "r");
        let ids = collect_ids(&t);
        assert_eq!(ids, vec!["r", "r_0_span", "r_1_span"]);
        let mut t2 = t.clone();
        assign_ipe_ids(&mut t2, "r");
        assert_eq!(collect_ids(&t2), ids);
    }

    fn collect_ids_go<M>(n: &Html<M>, out: &mut Vec<String>) {
        if let Html::HElement(_, attrs, kids) = n {
            for a in attrs {
                if let Attribute::Attr(k, v) = a
                    && k == "ipe-id"
                {
                    out.push(v.clone());
                }
            }
            for c in kids {
                collect_ids_go(c, out);
            }
        }
    }

    fn collect_ids<M>(n: &Html<M>) -> Vec<String> {
        let mut out = vec![];
        collect_ids_go(n, &mut out);
        out
    }

    fn radio_input(name: Option<&str>) -> Html<()> {
        let mut attrs = vec![Attribute::Attr("type".into(), "radio".into())];
        if let Some(n) = name {
            attrs.push(Attribute::Attr("name".into(), n.into()));
        }
        Html::HElement("input".into(), attrs, vec![])
    }

    /// A radio group the way `ui::input` builds it: a fieldset (marked or not)
    /// around a container of labelled radios.
    fn radio_fieldset(marked: bool, extra: Vec<Attribute<()>>, radios: Vec<Html<()>>) -> Html<()> {
        let mut attrs = extra;
        if marked {
            attrs.push(Attribute::Attr(RADIO_GROUP_MARKER.into(), String::new()));
        }
        let labels = radios
            .into_iter()
            .map(|r| Html::HElement("label".into(), vec![], vec![r]))
            .collect();
        Html::HElement(
            "fieldset".into(),
            attrs,
            vec![Html::HElement("div".into(), vec![], labels)],
        )
    }

    fn radio_names_go(n: &Html<()>, out: &mut Vec<Option<String>>) {
        if let Html::HElement(tag, attrs, kids) = n {
            if tag == "input" && attr_value(attrs, "type") == Some("radio") {
                out.push(attr_value(attrs, "name").map(str::to_owned));
            }
            for c in kids {
                radio_names_go(c, out);
            }
        }
    }

    fn radio_names(n: &Html<()>) -> Vec<Option<String>> {
        let mut out = vec![];
        radio_names_go(n, &mut out);
        out
    }

    fn named(name: &str) -> Option<String> {
        Some(name.to_owned())
    }

    /// Every unnamed radio of a marked fieldset gets the group name derived from
    /// the fieldset's path, and the marker is consumed. Red if the stamper stops
    /// naming radios or leaves the marker in the output.
    #[test]
    fn radio_group_gets_path_name() {
        let mut t = Html::HElement(
            "div".into(),
            vec![],
            vec![radio_fieldset(
                true,
                vec![],
                vec![radio_input(None), radio_input(None)],
            )],
        );
        assign_ipe_ids(&mut t, "r");
        let group = named("ipe-rg-r_0_fieldset");
        assert_eq!(radio_names(&t), vec![group.clone(), group]);
        assert!(!render_html(&t).contains(RADIO_GROUP_MARKER));
    }

    /// Two groups in one document never share a name, or the browser would merge
    /// them into one selection. Red if the name stops being a function of the
    /// fieldset's own path.
    #[test]
    fn two_groups_in_one_document_get_distinct_names() {
        let group = || radio_fieldset(true, vec![], vec![radio_input(None), radio_input(None)]);
        let mut t = Html::HElement("div".into(), vec![], vec![group(), group()]);
        assign_ipe_ids(&mut t, "r");
        let (first, second) = (named("ipe-rg-r_0_fieldset"), named("ipe-rg-r_1_fieldset"));
        assert_eq!(
            radio_names(&t),
            vec![first.clone(), first, second.clone(), second]
        );
    }

    /// A radio that already has a non-empty `name` keeps it; an empty `name` is
    /// as good as none. Red if the stamper overwrites an author's name.
    #[test]
    fn user_radio_name_is_not_overwritten() {
        let mut t = radio_fieldset(
            true,
            vec![],
            vec![
                radio_input(Some("mine")),
                radio_input(None),
                radio_input(Some("")),
            ],
        );
        assign_ipe_ids(&mut t, "r");
        let group = named("ipe-rg-r");
        assert_eq!(radio_names(&t), vec![named("mine"), group.clone(), group]);
    }

    /// A fieldset without the marker is an ordinary fieldset: its radios stay
    /// unnamed. Red if naming keys off the tag instead of the marker.
    #[test]
    fn unmarked_fieldset_radios_untouched() {
        let mut t = radio_fieldset(false, vec![], vec![radio_input(None), radio_input(None)]);
        assign_ipe_ids(&mut t, "r");
        assert_eq!(radio_names(&t), vec![None, None]);
    }

    /// A marked fieldset inside a marked fieldset names its own radios, and the
    /// outer group's radios keep the outer name. Red if the group name is not
    /// replaced on entering the inner fieldset.
    #[test]
    fn nested_group_uses_innermost_fieldset() {
        let inner = radio_fieldset(true, vec![], vec![radio_input(None)]);
        let mut t = Html::HElement(
            "fieldset".into(),
            vec![Attribute::Attr(RADIO_GROUP_MARKER.into(), String::new())],
            vec![radio_input(None), inner],
        );
        assign_ipe_ids(&mut t, "r");
        assert_eq!(
            radio_names(&t),
            vec![named("ipe-rg-r"), named("ipe-rg-r_1_fieldset")]
        );
    }

    /// Stamping again, or stamping a fresh build of the same view, yields the
    /// same names, so a diff sees no spurious `name` change. Red if the name
    /// depends on anything but the fieldset's path.
    #[test]
    fn radio_names_survive_diff_restamp() {
        let build = || {
            Html::HElement(
                "div".into(),
                vec![],
                vec![radio_fieldset(
                    true,
                    vec![],
                    vec![radio_input(None), radio_input(None)],
                )],
            )
        };
        let mut first = build();
        assign_ipe_ids(&mut first, "r");
        let names = radio_names(&first);
        assign_ipe_ids(&mut first, "r");
        assert_eq!(radio_names(&first), names);
        let mut second = build();
        assign_ipe_ids(&mut second, "r");
        assert_eq!(radio_names(&second), names);
        assert_eq!(render_html(&first), render_html(&second));
    }

    /// A group name built from a path that carries a hostile `ipe-key` stays in
    /// the id alphabet and cannot break out of the attribute. Red if the name
    /// uses an unsanitised key.
    #[test]
    fn radio_group_name_is_escaped_and_in_alphabet() {
        let hostile = Attribute::Attr("ipe-key".into(), "a\"<b>&'".into());
        let mut t = Html::HElement(
            "div".into(),
            vec![],
            vec![radio_fieldset(true, vec![hostile], vec![radio_input(None)])],
        );
        assign_ipe_ids(&mut t, "r");
        let names = radio_names(&t);
        assert_eq!(names.len(), 1);
        let name = names.into_iter().next().flatten().unwrap_or_default();
        assert!(name.starts_with("ipe-rg-r_0_fieldset"), "{name}");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c)),
            "{name}"
        );
        let html = render_html(&t);
        assert!(!html.contains("<b>"), "{html}");
    }

    #[test]
    fn unsafe_child_tag_never_reaches_the_ipe_id() {
        let mut t: Html<()> = Html::HElement(
            "div".into(),
            vec![],
            vec![
                Html::HElement(
                    "x\"]{}</style>".into(),
                    vec![],
                    vec![Html::HElement("b".into(), vec![], vec![])],
                ),
                Html::HElement("span".into(), vec![], vec![]),
            ],
        );
        assign_ipe_ids(&mut t, "r");
        let ids = collect_ids(&t);
        let unsafe_tag = "r_0_x.22.5d.7b.7d.3c.2fstyle.3e";
        assert_eq!(
            ids,
            vec![
                "r".to_owned(),
                unsafe_tag.to_owned(),
                format!("{unsafe_tag}_0_b"),
                "r_1_span".to_owned()
            ]
        );
        for id in &ids {
            assert!(
                !id.contains(['"', ']', '{', '<']),
                "ipe-id {id:?} holds a selector or markup metacharacter"
            );
        }
    }

    #[test]
    fn keyed_item_id_carries_position_and_key() {
        // Two keyed <li> swapped: the stamped id carries both the position and
        // the key, so a moved item's id changes and the diff replaces the list
        // rather than patching one item in place under the other's id.
        let li = |k: &str| -> Html<()> {
            Html::HElement(
                "li".into(),
                vec![Attribute::Attr("ipe-key".into(), k.into())],
                vec![Html::HText(k.into())],
            )
        };
        let mut a: Html<()> = Html::HElement("ul".into(), vec![], vec![li("alpha"), li("beta")]);
        let mut b: Html<()> = Html::HElement("ul".into(), vec![], vec![li("beta"), li("alpha")]);
        assign_ipe_ids(&mut a, "r");
        assign_ipe_ids(&mut b, "r");
        let ids_a = collect_ids(&a);
        let ids_b = collect_ids(&b);
        // alpha's id changes with its position; the key stays in it.
        assert!(ids_a.contains(&"r_0_li:alpha".to_string()), "{ids_a:?}");
        assert!(ids_b.contains(&"r_1_li:alpha".to_string()), "{ids_b:?}");
        // The key disambiguator is present, sanitised.
        assert!(
            ids_a
                .iter()
                .all(|s| s.contains(":alpha") || s.contains(":beta") || s == "r")
        );
    }

    #[test]
    fn name_on_form_tag_becomes_implicit_key() {
        let mut t: Html<()> = Html::HElement(
            "form".into(),
            vec![],
            vec![Html::HElement(
                "input".into(),
                vec![Attribute::Attr("name".into(), "email".into())],
                vec![],
            )],
        );
        assign_ipe_ids(&mut t, "r");
        assert!(collect_ids(&t).contains(&"r_0_input:email".to_string()));
    }

    /// Inverse of `push_id_segment`: `None` for a byte outside the encoding.
    fn decode_id_segment(encoded: &str) -> Option<String> {
        let mut out = Vec::new();
        let mut bytes = encoded.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'.' {
                let hi = char::from(bytes.next()?).to_digit(16)?;
                let lo = char::from(bytes.next()?).to_digit(16)?;
                out.push(u8::try_from(hi * 16 + lo).ok()?);
            } else if byte.is_ascii_alphanumeric() || byte == b'-' {
                out.push(byte);
            } else {
                return None;
            }
        }
        String::from_utf8(out).ok()
    }

    /// One decoded id step: index, tag, optional key.
    type IdStep = (usize, String, Option<String>);

    /// Split a stamped id back into its root and steps.
    fn decode_id(id: &str) -> Option<(String, Vec<IdStep>)> {
        let mut parts = id.split('_');
        let root = decode_id_segment(parts.next()?)?;
        let mut steps = Vec::new();
        while let Some(idx) = parts.next() {
            let idx = idx.parse().ok()?;
            let mut halves = parts.next()?.split(':');
            let tag = decode_id_segment(halves.next()?)?;
            let key = halves.next().map(decode_id_segment);
            if matches!(key, Some(None)) || halves.next().is_some() {
                return None;
            }
            steps.push((idx, tag, key.flatten()));
        }
        Some((root, steps))
    }

    /// The id stamped on the only child of a `div` root.
    fn only_child_id(tag: &str, key: Option<&str>) -> String {
        let attrs = key.map_or_else(Vec::new, |k| {
            vec![Attribute::Attr(KEY_ATTR.into(), k.into())]
        });
        let mut t: Html<()> = Html::HElement(
            "div".into(),
            vec![],
            vec![Html::HElement(tag.into(), attrs, vec![])],
        );
        assign_ipe_ids(&mut t, "r");
        collect_ids(&t).into_iter().nth(1).unwrap_or_default()
    }

    #[test]
    fn keys_differing_only_in_punctuation_get_distinct_ids() {
        assert_ne!(
            only_child_id("li", Some("a.b")),
            only_child_id("li", Some("a_b"))
        );
        assert_ne!(
            only_child_id("li", Some("a b")),
            only_child_id("li", Some("a/b"))
        );
    }

    #[test]
    fn colon_in_tag_never_spells_a_key() {
        assert_ne!(only_child_id("li:a", None), only_child_id("li", Some("a")));
        assert_ne!(only_child_id("x\"]", None), only_child_id("x", None));
    }

    #[test]
    fn id_segment_round_trips_over_a_small_alphabet() {
        let alphabet = ["a", "Z", "0", "-", "_", ".", ":", " ", "\u{e9}"];
        let mut inputs = vec![String::new()];
        for _ in 0..3 {
            let longer: Vec<String> = inputs
                .iter()
                .flat_map(|s| alphabet.iter().map(move |c| format!("{s}{c}")))
                .collect();
            inputs.extend(longer);
        }
        inputs.sort();
        inputs.dedup();
        for input in &inputs {
            let mut encoded = String::new();
            push_id_segment(input, &mut encoded);
            assert!(!encoded.contains(['_', ':']), "{input:?} -> {encoded:?}");
            assert_eq!(decode_id_segment(&encoded).as_deref(), Some(input.as_str()));
        }
    }

    #[test]
    fn stamped_ids_decode_to_the_shape_that_built_them() {
        let tags = [
            "li", "li:a", "li_a", "li.a", "li_0_li", "x", "x\"]", "\u{e9}",
        ];
        let keys = [
            None,
            Some("a"),
            Some("a.b"),
            Some("a_b"),
            Some("b_0_li"),
            Some("a:b"),
        ];
        let mut seen = std::collections::HashSet::new();
        for tag in tags {
            for key in keys {
                let id = only_child_id(tag, key);
                let expected = (
                    "r".to_owned(),
                    vec![(0, tag.to_owned(), key.map(str::to_owned))],
                );
                assert_eq!(decode_id(&id), Some(expected), "{id}");
                assert!(seen.insert(id.clone()), "two shapes share the id {id}");
            }
        }
    }

    #[test]
    fn safe_attr_name_refuses_the_reserved_prefix() {
        for name in ["ipe-x", "IPE-x", "Ipe-id", "ipe-key", "ipe-click"] {
            assert!(SafeAttrName::parse(name).is_none(), "{name}");
            assert_eq!(
                html_attr_to_string_::<()>(Attribute::Attr(name.into(), "v".into())),
                ""
            );
        }
        for name in [
            "ipe-id",
            "IPE-ID",
            "ipe-key",
            "ipe-click",
            "data-ipe-hid",
            "DATA-IPE-HID",
        ] {
            assert!(safe_patch_attr(name, "v").is_none(), "{name}");
        }
        for name in [
            "ipe-id", "IPE-ID", "ipe-key", "Ipe-Key", "ipe-x y", "onclick",
        ] {
            assert!(patch_marker_attr(name, "v").is_none(), "{name}");
        }
        for name in ["ipe-click", "data-ipe-ev-ipe-file", HANDLER_ID_ATTR] {
            assert!(patch_marker_attr(name, "v").is_some(), "{name}");
        }
        assert!(SafeAttrName::parse("ipe").is_some());
        assert!(SafeAttrName::parse("data-ipe-x").is_some());
    }

    /// An unstamped tree still drops every program-built reserved name other
    /// than the exact stamped-id spelling.
    #[test]
    fn render_sink_drops_program_built_reserved_attrs() {
        let t: Html<()> = Html::HElement(
            "button".into(),
            vec![
                Attribute::Attr("IPE-ID".into(), "x".into()),
                Attribute::Attr("ipe-click".into(), "y".into()),
                Attribute::Attr(KEY_ATTR.into(), "k".into()),
                Attribute::BoolAttr("Ipe-Flag".into(), true),
            ],
            vec![],
        );
        let low = render_html(&t).to_ascii_lowercase();
        assert!(!low.contains("ipe-"), "{low}");
    }

    #[test]
    fn stamper_leaves_the_stamped_id_as_the_only_reserved_attr() {
        let mut t: Html<()> = Html::HElement(
            "div".into(),
            vec![
                Attribute::Attr("ipe-id".into(), "forged".into()),
                Attribute::Attr("IPE-ID".into(), "forged".into()),
                Attribute::BoolAttr("ipe-click".into(), true),
            ],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let Html::HElement(_, attrs, _) = &t else {
            return;
        };
        let reserved: Vec<(&str, &str)> = attrs
            .iter()
            .filter_map(|a| match a {
                Attribute::Attr(k, v) if is_reserved_attr_name(k) => Some((k.as_str(), v.as_str())),
                Attribute::BoolAttr(k, _) if is_reserved_attr_name(k) => Some((k.as_str(), "")),
                Attribute::Attr(..)
                | Attribute::BoolAttr(..)
                | Attribute::EventAttr(_)
                | Attribute::NoAttr => None,
            })
            .collect();
        assert_eq!(reserved, vec![(STAMPED_ID_ATTR, "r")]);
    }

    /// The HTML parser keeps the first of two same-named attributes, so a
    /// program-built handler id rendered ahead of the stamped one would route
    /// this button's click to another element's handler.
    #[test]
    fn program_built_handler_id_never_reaches_the_page() {
        let mut t: Html<()> = Html::HElement(
            "button".into(),
            vec![
                Attribute::Attr("data-ipe-hid".into(), "r_9_button".into()),
                Attribute::Attr("Data-Ipe-Hid".into(), "r_9_button".into()),
                Attribute::EventAttr(Event::OnMsg("click".into(), Box::new(()))),
            ],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let out = render_html(&t);
        let low = out.to_ascii_lowercase();
        assert_eq!(low.matches("data-ipe-hid=").count(), 1, "{out}");
        assert!(out.contains(r#"data-ipe-hid="r""#), "{out}");
        assert!(!out.contains("r_9_button"), "{out}");
        let unstamped: Html<()> = Html::HElement(
            "b".into(),
            vec![Attribute::Attr("data-ipe-hid".into(), "r_9_button".into())],
            vec![],
        );
        assert!(!render_html(&unstamped).contains("r_9_button"));
    }

    #[test]
    fn ui_html_attribute_cannot_forge_the_stamped_id() {
        use crate::ui::helpers::{ui_el_, ui_html_attribute_, ui_text_};
        let elem = ui_el_::<()>(
            vec![
                ui_html_attribute_("IPE-ID".into(), "x".into()),
                ui_html_attribute_("ipe-id".into(), "y".into()),
            ],
            ui_text_("t".into()),
        );
        let mut html = crate::ui::render::ui_layout(vec![], elem);
        assign_ipe_ids(&mut html, "r");
        let stamped = collect_ids(&html);
        let out = render_html(&html);
        let rendered: Vec<&str> = out
            .split(" ipe-id=\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .collect();
        assert_eq!(rendered, stamped, "{out}");
        assert_eq!(
            out.to_ascii_lowercase().matches("ipe-id=").count(),
            stamped.len(),
            "{out}"
        );
    }

    #[test]
    fn html_tree_constructs() {
        let t: Html<Msg> = Html::HElement(
            "button".into(),
            vec![Attribute::EventAttr(Event::OnMsg(
                "click".into(),
                Box::new(Msg::Inc),
            ))],
            vec![Html::HText("+".into())],
        );
        match &t {
            Html::HElement(tag, attrs, kids) => {
                assert_eq!(tag, "button");
                assert_eq!(attrs.len(), 1);
                assert_eq!(kids.len(), 1);
            }
            _ => panic!("expected element"),
        }

        // Clone + PartialEq round-trip on an attribute holding a closure.
        let attr: Attribute<Msg> =
            Attribute::EventAttr(Event::OnMsg("click".into(), Box::new(Msg::Inc)));
        assert_eq!(attr, attr.clone());
        // Debug prints the variant name + event name, not a numeric discriminant.
        let dbg = format!("{attr:?}");
        assert!(
            dbg.contains("OnMsg") && dbg.contains("click"),
            "debug was: {dbg}"
        );
    }

    // ── F7: `<style>`-body injection regressions (design §Q6 #6/#8/#9) ─────────
    use crate::ui::helpers::html_style_node_;

    /// Count occurrences of `</style` (case-insensitive) in `out`. A safe
    /// `<style>` element has EXACTLY ONE — its own closing tag. Any additional
    /// occurrence means the CSS body carried a `</style` that would close the
    /// raw-text element early and let following `<script>` parse as markup.
    fn style_close_count(out: &str) -> usize {
        out.to_ascii_lowercase().matches("</style").count()
    }

    #[test]
    fn style_node_strips_close_tag_breakout() {
        // #6 — a `</style><script>` in the CSS body cannot break out. After
        // stripping, the only `</style` left is the element's own closing tag,
        // so the injected `<script>` is trapped INSIDE the raw-text <style>
        // element (inert — the HTML parser does not parse elements inside
        // <style>), never parsed as a live script element.
        let node = html_style_node_::<()>(
            vec![],
            "body{color:red}</style><script>alert(1)</script>".into(),
        );
        let out = render_html(&node);
        assert_eq!(style_close_count(&out), 1, "early </style break-out: {out}");
        assert!(
            !out.to_ascii_lowercase().contains("</style><script"),
            "{out}"
        );
    }

    #[test]
    fn hand_built_style_element_is_also_stripped() {
        // Defence-in-depth — a hand-built `<style>` (NOT via styleNode) with an
        // HRaw body is stripped at the render sink too.
        let node: Html<()> = Html::HElement(
            "style".into(),
            vec![],
            vec![Html::HRaw("x{}</StYlE ><script>".into())],
        );
        let out = render_html(&node);
        assert_eq!(style_close_count(&out), 1, "{out}");
        assert!(
            !out.to_ascii_lowercase().contains("</style><script"),
            "{out}"
        );
    }

    #[test]
    fn style_node_defeats_reconstruction_trick() {
        // #8 — the `</sty</stylele` reconstruction trick is defeated (fixpoint):
        // no residual `</style` survives in the body, only the closing tag.
        let node = html_style_node_::<()>(vec![], "a{}</sty</stylele>".into());
        let out = render_html(&node);
        assert_eq!(style_close_count(&out), 1, "{out}");
    }

    #[test]
    fn script_element_body_stays_verbatim() {
        // An ordinary script body carrying `<`/`>`/`&` is emitted verbatim (never
        // entity-escaped — that would corrupt executable code). Only a literal
        // `</script` breakout run is neutralised, so this body is unchanged.
        let node: Html<()> = Html::HElement(
            "script".into(),
            vec![],
            vec![Html::HRaw("if (1 < 2) { x(); }".into())],
        );
        assert!(render_html(&node).contains("if (1 < 2)"));
    }

    fn script_close_count(out: &str) -> usize {
        out.to_ascii_lowercase().matches("</script").count()
    }

    /// SECURITY: a `<script>` or `<style>` built on the safe surface (a text
    /// child, a child element, a mixed body, or for `<script>` an empty body)
    /// is refused at the render sink in every tag-name case: nothing of it
    /// renders, so data never becomes executable code or a raw-text body.
    #[test]
    fn safe_surface_raw_text_element_is_refused_at_sink() {
        let bodies: [fn() -> Vec<Html<()>>; 4] = [
            || vec![Html::HText("alert(document.cookie)".into())],
            || {
                vec![Html::HElement(
                    "b".into(),
                    vec![],
                    vec![Html::HText("alert(1)".into())],
                )]
            },
            || vec![Html::HRaw("x()".into()), Html::HText("alert(1)".into())],
            Vec::new,
        ];
        for tag in ["script", "SCRIPT", "Script", "style", "STYLE", "sTyLe"] {
            for (n, body) in bodies.iter().enumerate() {
                let kids = body();
                // An empty `<style>` is admitted: it holds no body to execute.
                if kids.is_empty() && tag.eq_ignore_ascii_case("style") {
                    continue;
                }
                let node: Html<()> = Html::HElement(
                    "div".into(),
                    vec![],
                    vec![Html::HElement(
                        tag.into(),
                        vec![Attribute::Attr("src".into(), "/x.js".into())],
                        kids,
                    )],
                );
                let out = render_html(&node);
                assert_eq!(
                    out, "<div></div>",
                    "<{tag}> body {n} must be refused: {out}"
                );
            }
        }
    }

    /// A `<plaintext>` element can never be closed, so it is refused in any
    /// case; an unsafe tag name keeps being refused through the same gate.
    #[test]
    fn unclosable_and_unsafe_name_elements_are_refused_at_sink() {
        for tag in [
            "plaintext",
            "PLAINTEXT",
            "PlainText",
            "div><script",
            "a b",
            "",
        ] {
            let node: Html<()> = Html::HElement(
                "div".into(),
                vec![],
                vec![Html::HElement(
                    tag.into(),
                    vec![],
                    vec![Html::HText("x".into())],
                )],
            );
            assert_eq!(render_html(&node), "<div></div>", "<{tag}> must be refused");
        }
    }

    /// The shared gate's verdict for each denied tag and for the admitted
    /// controls, tag names matched without regard to ASCII case.
    #[test]
    fn admit_element_decides_every_tag_class() {
        let text = || vec![Html::<()>::HText("t".into())];
        let raw = || vec![Html::<()>::HRaw("r".into())];
        let none: Vec<Html<()>> = Vec::new();
        assert_eq!(
            admit_element("script", NO_ATTRS, &text()),
            Err(ElementRefusal::UntrustedScript)
        );
        assert_eq!(
            admit_element("ScRiPt", NO_ATTRS, &text()),
            Err(ElementRefusal::UntrustedScript)
        );
        assert_eq!(
            admit_element("script", NO_ATTRS, &none),
            Err(ElementRefusal::UntrustedScript)
        );
        assert_eq!(
            admit_element("style", NO_ATTRS, &text()),
            Err(ElementRefusal::UntrustedStyle)
        );
        assert_eq!(
            admit_element("STYLE", NO_ATTRS, &text()),
            Err(ElementRefusal::UntrustedStyle)
        );
        assert_eq!(
            admit_element("plaintext", NO_ATTRS, &none),
            Err(ElementRefusal::Unclosable)
        );
        assert_eq!(
            admit_element("x y", NO_ATTRS, &none),
            Err(ElementRefusal::UnsafeName)
        );
        assert_eq!(
            admit_element("script", NO_ATTRS, &raw()),
            Ok(ElementBody::Script)
        );
        assert_eq!(
            admit_element("SCRIPT", NO_ATTRS, &raw()),
            Ok(ElementBody::Script)
        );
        assert_eq!(
            admit_element("style", NO_ATTRS, &raw()),
            Ok(ElementBody::Style)
        );
        assert_eq!(
            admit_element("style", NO_ATTRS, &none),
            Ok(ElementBody::Style)
        );
        for tag in [
            "div", "p", "title", "textarea", "noscript", "iframe", "template", "svg",
        ] {
            assert_eq!(
                admit_element(tag, NO_ATTRS, &text()),
                Ok(ElementBody::Markup),
                "<{tag}>"
            );
        }
    }

    /// Controls: a trusted raw `<script>`/`<style>` body still renders, in any
    /// tag-name case, with its own close tag neutralised.
    #[test]
    fn trusted_raw_script_and_style_bodies_render() {
        let script: Html<()> = Html::HElement(
            "SCRIPT".into(),
            vec![],
            vec![Html::HRaw("x();</script>y".into())],
        );
        let out = render_html(&script);
        assert!(
            out.starts_with("<SCRIPT>x();<\\/script>y</SCRIPT>"),
            "{out}"
        );
        let style: Html<()> = Html::HElement(
            "style".into(),
            vec![],
            vec![Html::HRaw(".a{color:red}".into())],
        );
        assert_eq!(render_html(&style), "<style>.a{color:red}</style>");
    }

    /// A trusted `<style>` body inside an RCDATA, RAWTEXT or foreign-content
    /// ancestor cannot end that ancestor or open a live tag.
    #[test]
    fn style_body_cannot_break_out_of_an_ancestor() {
        for ancestor in [
            "textarea", "title", "noscript", "iframe", "xmp", "svg", "math",
        ] {
            let css = format!("x{{}}</{ancestor}><img src=x onerror=alert(1)>");
            let node: Html<()> = Html::HElement(
                ancestor.into(),
                vec![],
                vec![html_style_node_::<()>(vec![], css)],
            );
            let out = render_html(&node);
            let closes = format!("</{ancestor}");
            assert_eq!(out.matches(closes.as_str()).count(), 1, "{out}");
            assert!(!out.contains("<img"), "{out}");
        }
    }

    /// A void tag in any ASCII case self-closes with no children, as the
    /// browser's tokenizer treats it.
    #[test]
    fn void_tags_match_without_regard_to_ascii_case() {
        for tag in ["br", "BR", "Img", "INPUT"] {
            assert!(is_void(tag), "{tag}");
            let node: Html<()> = Html::HElement(tag.into(), vec![], vec![Html::HText("x".into())]);
            assert_eq!(render_html(&node), format!("<{tag} />"));
        }
        assert!(!is_void("div"));
        assert!(!is_void("brx"));
    }

    /// A hand-built `<style>` over an untouched trusted raw body (not built by
    /// `styleNode`, which neutralises at construction) is neutralised by the
    /// render sink itself, so it cannot end a `<textarea>` or open a tag inside
    /// `<svg>`.
    #[test]
    fn hand_built_style_body_is_neutralised_at_the_sink() {
        for ancestor in ["textarea", "svg"] {
            let css = format!("x{{}}</{ancestor}><img src=x onerror=alert(1)>");
            let style: Html<()> = Html::HElement("style".into(), vec![], vec![Html::HRaw(css)]);
            let node: Html<()> = Html::HElement(ancestor.into(), vec![], vec![style]);
            let out = render_html(&node);
            let closes = format!("</{ancestor}");
            assert_eq!(out.matches(closes.as_str()).count(), 1, "{out}");
            assert!(!out.contains("<img"), "{out}");
            assert!(out.contains("< /"), "close tag must be split: {out}");
        }
    }

    #[test]
    fn safe_surface_script_raw_child_breakout_is_neutralised() {
        // A hand-built `Html.node "script" [] [ Html.raw … ]` (HRaw child) is also
        // close-tag-neutralised at the sink; the ONLY trusted-verbatim path is
        // `Ipe.Html.Unsafe.unsafeScript`, which neutralises at construction.
        let node: Html<()> = Html::HElement(
            "script".into(),
            vec![],
            vec![Html::HRaw("x();</SCRIPT><b>y".into())],
        );
        let out = render_html(&node);
        assert_eq!(script_close_count(&out), 1, "{out}");
    }

    // SECURITY: user content flows through `Html.text` (HText), which is
    // HTML-escaped by CONSTRUCTION — a `<script>`-bearing string renders inert,
    // never executable. Un-escaped injection is reachable ONLY through the
    // explicitly-marked `Html.unsafeRaw` surface (HRaw), the named boundary.
    #[test]
    fn text_node_escapes_script_payload_by_construction() {
        // The `Html.text` path (HText): an attacker-controlled `<script>`
        // string is entity-escaped, so the browser sees text — not a live
        // script element.
        let escaped: Html<()> = Html::HText("<script>alert(1)</script>".into());
        let out = render_html(&Html::HElement("div".into(), vec![], vec![escaped]));
        assert!(
            !out.contains("<script>") && out.contains("&lt;script&gt;"),
            "user text must render escaped, never as a live <script>: {out}"
        );

        // The `Html.unsafeRaw` path (HRaw, the only un-escaped surface):
        // verbatim by design — the `unsafe` name makes the injection explicit
        // and greppable.
        let raw: Html<()> = Html::HRaw("<b>trusted</b>".into());
        assert!(render_html(&raw).contains("<b>trusted</b>"));
    }

    // ── Snapshot port of ../ipe fixture `69-html-render-parity`  ────
    #[test]
    fn fixture69_render_parity() {
        // <select value="b"> flips `selected` onto the matching <option>, NOT the
        // first; a trusted raw <script> body emits verbatim; ordinary text stays
        // entity-escaped; Html.doctype → literal <!DOCTYPE html>.
        let tree: Html<()> = Html::HElement(
            "!doctype-wrapper".into(),
            vec![],
            vec![Html::HElement(
                "div".into(),
                vec![],
                vec![
                    Html::HElement(
                        "select".into(),
                        vec![Attribute::Attr("value".into(), "b".into())],
                        vec![
                            Html::HElement(
                                "option".into(),
                                vec![Attribute::Attr("value".into(), "a".into())],
                                vec![Html::HText("A".into())],
                            ),
                            Html::HElement(
                                "option".into(),
                                vec![Attribute::Attr("value".into(), "b".into())],
                                vec![Html::HText("B".into())],
                            ),
                        ],
                    ),
                    Html::HElement(
                        "script".into(),
                        vec![],
                        vec![Html::HRaw("if (1 < 2) { x = '&'; }".into())],
                    ),
                    Html::HElement("div".into(), vec![], vec![Html::HText("<b>raw</b>".into())]),
                ],
            )],
        );
        let out = render_html(&tree);
        assert!(out.starts_with("<!DOCTYPE html>"), "{out}");
        // selected flips onto the `b` option, not `a`.
        assert!(
            out.contains(r#"<option selected="selected" value="b">"#),
            "{out}"
        );
        assert!(!out.contains(r#"value="a" selected"#), "{out}");
        // <script> body verbatim (inline JS not entity-escaped).
        assert!(out.contains("if (1 < 2) { x = '&'; }"), "{out}");
        // ordinary text still entity-escaped.
        assert!(out.contains("&lt;b&gt;raw&lt;/b&gt;"), "{out}");
    }

    // ── attribute-builder injection regressions (design §Q6 #1–5, #10) ────

    #[test]
    fn attr_value_quote_breakout_is_escaped() {
        // #1 — a `"` in an attribute value is entity-escaped, no live handler.
        let n: Html<()> = Html::HElement(
            "div".into(),
            vec![Attribute::Attr(
                "title".into(),
                "x\" onmouseover=\"alert(1)".into(),
            )],
            vec![],
        );
        let out = render_html(&n);
        assert!(out.contains("onmouseover=&#34;"), "{out}"); // escaped, inert
        assert!(!out.contains("onmouseover=\""), "{out}"); // no live handler
    }

    #[test]
    fn javascript_href_is_neutralised() {
        // #2 — a `javascript:` scheme on href is neutralised to empty.
        let n: Html<()> = Html::HElement(
            "a".into(),
            vec![Attribute::Attr("href".into(), "javascript:alert(1)".into())],
            vec![],
        );
        let out = render_html(&n);
        assert!(out.contains("href=\"\""), "{out}");
        assert!(!out.to_ascii_lowercase().contains("javascript:"), "{out}");
    }

    #[test]
    fn data_uri_src_policy() {
        // #3 — scriptable `data:text/html` neutralised; inert raster passes.
        let bad: Html<()> = Html::HElement(
            "img".into(),
            vec![Attribute::Attr(
                "src".into(),
                "data:text/html,<script>1</script>".into(),
            )],
            vec![],
        );
        assert!(render_html(&bad).contains("src=\"\""));
        let ok: Html<()> = Html::HElement(
            "img".into(),
            vec![Attribute::Attr(
                "src".into(),
                "data:image/png;base64,iVBOR".into(),
            )],
            vec![],
        );
        assert!(render_html(&ok).contains("data:image/png;base64,iVBOR"));
    }

    #[test]
    fn generic_attribute_drops_event_and_srcdoc_names() {
        // #4 — the generic `attribute k v` setter cannot register `on*`/`srcdoc`.
        for k in ["onclick", "OnClick", "onfoo", "srcdoc"] {
            let n: Html<()> = Html::HElement(
                "div".into(),
                vec![Attribute::Attr(k.into(), "x".into())],
                vec![],
            );
            let out = render_html(&n).to_ascii_lowercase();
            assert!(
                !out.contains(&format!("{}=", k.to_ascii_lowercase())),
                "{out}"
            );
        }
    }

    #[test]
    fn unsafe_tag_name_drops_element() {
        // #5 — a start-tag breakout in the tag name drops the whole element.
        let n: Html<()> = Html::HElement("div><script>".into(), vec![], vec![]);
        assert!(!render_html(&n).contains("<script"));
    }

    #[cfg(feature = "web")]
    #[test]
    fn sse_patch_shares_the_policy() {
        // #10 — SSE patch attributes route through the same name+scheme gate.
        assert!(safe_patch_attr("onclick", "x").is_none());
        let (_, v) = safe_patch_attr("href", "javascript:alert(1)").unwrap();
        assert!(!v.to_ascii_lowercase().contains("javascript:"));
    }

    #[test]
    #[cfg(feature = "web")]
    fn html_on_submit_dispatches_via_onform() {
        // Mirror of dispatch.rs's ui_on_submit_dispatches_via_onform_not_onraw,
        // exercising Ipe.Html.Events.onSubmit's backing fn directly.
        #[derive(serde::Deserialize, Default, PartialEq, Debug)]
        #[serde(default)]
        struct Order {
            item: String,
        }
        let attr: Attribute<String> = html_on_raw_("submit".to_owned(), |o: Order| o.item);
        let mut t: Html<String> = Html::HElement("form".into(), vec![attr], vec![]);
        assign_ipe_ids(&mut t, "r");
        let idx = crate::web::build_index(&t);

        // Must dispatch via resolve_form (Event::OnForm), never resolve()'s
        // positional-args path — there is no Event::OnRaw any more.
        assert_eq!(idx.resolve("r", "submit", &[]), None);

        let mut fd = FormData::new();
        fd.insert("item".into(), "widget".into());
        assert_eq!(
            idx.resolve_form("r", "submit", fd),
            Some("widget".to_owned())
        );
    }

    // ── Html document-node regressions ─────────

    #[test]
    fn html_doctype_helper_wraps_doctype_wrapper_tag() {
        // `Html.doctype [Html.div [] []]` via the `html_doctype_` kernel helper
        // (not a hand-built tree) must round-trip through the SAME
        // `!doctype-wrapper` recognition path as `fixture69_render_parity`.
        let child: Html<()> = Html::HElement("div".into(), vec![], vec![]);
        let doc = crate::ui::helpers::html_doctype_(vec![child]);
        let out = render_html(&doc);
        assert!(
            out.starts_with("<!DOCTYPE html>"),
            "doctype prefix missing: {out}"
        );
        assert!(out.contains("<div"), "child must render: {out}");
    }

    #[test]
    fn html_title_node_wraps_raw_string_in_title() {
        let t: Html<()> = crate::ui::helpers::html_title_node_("My App".to_owned());
        let out = render_html(&t);
        assert_eq!(out, "<title>My App</title>");
    }

    #[test]
    fn html_title_node_escapes_text() {
        // titleNode wraps via HText (escaped), not HRaw — a `<` in the title
        // must not break out of the tag.
        let t: Html<()> = crate::ui::helpers::html_title_node_("<script>x</script>".to_owned());
        let out = render_html(&t);
        assert!(
            !out.contains("<script>"),
            "title text must be escaped: {out}"
        );
    }

    #[test]
    fn html_void_node_shares_generic_node_sink_and_self_closes() {
        // `Html.voidNode "br" []` shares the SAME `html_node_` runtime sink as
        // `Html.node` (the emit site bakes an empty children vec) — verify the
        // void tag still self-closes / drops any injected children via the
        // render sink's own VOID-set gate (defence in depth against an
        // injected-child XSS surface even if a caller passed non-empty kids).
        let t: Html<()> = crate::ui::helpers::html_node_(
            "br".to_owned(),
            vec![],
            vec![Html::HText("should be dropped".into())],
        );
        let out = render_html(&t);
        assert_eq!(out, "<br />");
        assert!(!out.contains("should be dropped"));
    }

    #[test]
    fn html_to_string_is_byte_identical_to_render() {
        // `Html.toString` is a distinct kernel from `Html.render` but shares
        // the same runtime fn (`html_render_`) — prove both produce identical
        // output for the same input (alias correctness).
        let t: Html<()> = Html::HElement(
            "p".into(),
            vec![Attribute::Attr("class".into(), "x".into())],
            vec![Html::HText("hi".into())],
        );
        assert_eq!(html_render_(t.clone()), render_html(&t));
    }

    fn element(tag: &str, kids: Vec<Html<()>>) -> Html<()> {
        Html::HElement(tag.into(), vec![], kids)
    }

    fn trusted_script(body: &str) -> Html<()> {
        element("script", vec![Html::HRaw(body.into())])
    }

    /// Each element's tag puts its children in the context the HTML tokenizer
    /// reads them in, and foreign content and raw text stay sticky below it.
    #[test]
    fn parse_context_follows_the_tokenizer_state() {
        assert_eq!(ParseContext::Data.enter("div"), ParseContext::Data);
        assert_eq!(ParseContext::Data.enter("svg"), ParseContext::Foreign);
        assert_eq!(ParseContext::Data.enter("MATH"), ParseContext::Foreign);
        for tag in RAW_OR_RCDATA_TAGS {
            assert_eq!(ParseContext::Data.enter(tag), ParseContext::RawOrRcdata);
            let upper = tag.to_ascii_uppercase();
            assert_eq!(ParseContext::Data.enter(&upper), ParseContext::RawOrRcdata);
        }
        for tag in ["foreignObject", "div", "textarea"] {
            assert_eq!(ParseContext::Foreign.enter(tag), ParseContext::Foreign);
        }
        for tag in ["div", "svg"] {
            assert_eq!(
                ParseContext::RawOrRcdata.enter(tag),
                ParseContext::RawOrRcdata
            );
        }
    }

    /// A trusted `<script>` is admitted only in the HTML data state; `<style>`
    /// and markup are admitted in every context.
    #[test]
    fn admit_in_context_refuses_a_script_outside_data_state() {
        let raw = vec![Html::<()>::HRaw("r".into())];
        assert_eq!(
            admit_in_context(ParseContext::Data, "script", NO_ATTRS, &raw),
            Ok(ElementBody::Script)
        );
        for ctx in [ParseContext::RawOrRcdata, ParseContext::Foreign] {
            assert_eq!(
                admit_in_context(ctx, "script", NO_ATTRS, &raw),
                Err(ElementRefusal::ScriptOutsideData)
            );
            assert_eq!(
                admit_in_context(ctx, "SCRIPT", NO_ATTRS, &raw),
                Err(ElementRefusal::ScriptOutsideData)
            );
            assert_eq!(
                admit_in_context(ctx, "style", NO_ATTRS, &raw),
                Ok(ElementBody::Style)
            );
            assert_eq!(
                admit_in_context(ctx, "div", NO_ATTRS, &raw),
                Ok(ElementBody::Markup)
            );
        }
    }

    /// A trusted script under `svg`, `math` or `svg > foreignObject` would be
    /// tokenized as markup, so it renders no script and none of its body.
    #[test]
    fn script_under_foreign_ancestor_refused() {
        let body = "<img src=x onerror=alert(1)>";
        for node in [
            element("svg", vec![trusted_script(body)]),
            element("math", vec![trusted_script(body)]),
            element(
                "svg",
                vec![element("foreignObject", vec![trusted_script(body)])],
            ),
            element("SVG", vec![element("g", vec![trusted_script(body)])]),
        ] {
            let out = render_html(&node);
            assert!(!out.contains("<img"), "{out}");
            assert!(!out.to_ascii_lowercase().contains("<script"), "{out}");
        }
    }

    /// A trusted script under an RCDATA or RAWTEXT ancestor would be that
    /// ancestor's text, so a body naming the ancestor's close tag cannot end it.
    #[test]
    fn script_under_rcdata_ancestor_refused() {
        for tag in RAW_OR_RCDATA_TAGS {
            let body = format!("</{tag}><img src=x onerror=alert(1)>");
            let out = render_html(&element(tag, vec![trusted_script(&body)]));
            let close = format!("</{tag}");
            assert_eq!(out.matches(close.as_str()).count(), 1, "{out}");
            assert!(!out.contains("<img"), "{out}");
            assert!(!out.contains("<script"), "{out}");
        }
    }

    /// A `<!--` in a script body is split, so a later `<script` cannot enter
    /// the double-escaped state and the renderer's `</script>` is the only
    /// close.
    #[test]
    fn script_body_comment_open_neutralised() {
        let out = render_html(&trusted_script("x = '<!--<script>'; y();"));
        assert!(!out.contains("<!--"), "{out}");
        assert_eq!(
            out.to_ascii_lowercase().matches("</script").count(),
            1,
            "{out}"
        );
        assert!(out.ends_with("</script>"), "{out}");
        let body = crate::css_safety::neutralise_script_close("<!--<script>");
        assert_eq!(crate::css_safety::neutralise_script_close(&body), body);
    }

    /// The control: a trusted script at the top level and under ordinary
    /// markup still renders its body verbatim.
    #[test]
    fn script_in_data_state_renders_verbatim() {
        assert_eq!(
            render_html(&trusted_script("init();")),
            "<script>init();</script>"
        );
        assert_eq!(
            render_html(&element("div", vec![trusted_script("init();")])),
            "<div><script>init();</script></div>"
        );
    }

    fn css(css: &str) -> Html<()> {
        element("style", vec![Html::HRaw(css.into())])
    }

    /// A `<style>` the tokenizer opens as an element, in HTML data state or in
    /// foreign content, carries the session nonce; one in raw text or RCDATA
    /// is text there, and an unstamped render stamps nothing.
    #[test]
    fn style_stamped_only_in_data_and_foreign() {
        let nonce = StyleNonce::from_random_bytes([0x3e; 16]);
        let attr = format!(" nonce=\"{}\"", nonce.as_token());
        let page = render_stamped(&element("div", vec![css("p{}")]), &nonce);
        assert_eq!(
            page.as_str(),
            format!("<div><style{attr}>p{{}}</style></div>")
        );
        assert_eq!(page.nonce().as_token(), nonce.as_token());
        let shown = format!("{page:?}");
        assert!(
            !shown.contains(&nonce.as_token()) && !shown.contains("nonce"),
            "{shown}"
        );
        let svg = render_stamped(&element("svg", vec![css("p{}")]), &nonce);
        assert!(
            svg.as_str().contains(&format!("<style{attr}>")),
            "{}",
            svg.as_str()
        );
        for host in ["textarea", "title"] {
            let page = render_stamped(&element(host, vec![css("p{}")]), &nonce);
            assert!(
                !page.as_str().contains("nonce"),
                "{host}: {}",
                page.as_str()
            );
        }
        for host in ["div", "svg"] {
            let out = render_html_in(&element(host, vec![css("p{}")]), &RenderCtx::Unstamped);
            assert!(!out.contains("nonce"), "{host}: {out}");
            assert_eq!(out, render_html(&element(host, vec![css("p{}")])));
        }
    }

    /// Trusted raw markup is written verbatim: a `<style>` inside it is the
    /// author's and never gets the session nonce.
    #[test]
    fn raw_style_never_stamped() {
        let nonce = StyleNonce::from_random_bytes([0x4f; 16]);
        let raw = "<style>p{}</style>";
        let page = render_stamped(&element("div", vec![Html::HRaw(raw.into())]), &nonce);
        assert_eq!(page.as_str(), format!("<div>{raw}</div>"));
    }

    /// A program-built `nonce` attribute, in any case, is refused at the render
    /// sink and the patch sink, so only the runtime's stamp is ever written.
    #[test]
    fn author_nonce_refused_at_render_and_patch() {
        for name in ["nonce", "NONCE", "nOnCe"] {
            assert!(SafeAttrName::parse(name).is_none(), "{name}");
            assert!(safe_patch_attr(name, "forged").is_none(), "{name}");
            let forged: Html<()> = Html::HElement(
                "style".into(),
                vec![Attribute::Attr(name.into(), "forged".into())],
                vec![Html::HRaw("p{}".into())],
            );
            assert!(!render_html(&forged).contains("forged"), "{name}");
            let nonce = StyleNonce::from_random_bytes([0x5a; 16]);
            let page = render_stamped(&forged, &nonce);
            assert!(
                !page.as_str().contains("forged"),
                "{name}: {}",
                page.as_str()
            );
            assert_eq!(
                page.as_str().matches("nonce=").count(),
                1,
                "{}",
                page.as_str()
            );
        }
    }
}
