use std::collections::HashMap;

use super::css_safety;

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
#[derive(Clone)]
pub enum Event<M> {
    OnMsg(String, M),
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
    let mut s = String::new();
    render_into(node, &mut s);
    s
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

/// Render `node` directly into an existing accumulator. `pub(crate)` so the
/// SSE diff's whole-subtree replace (`live/diff.rs::render_children`) can
/// write every child into one shared String instead of allocating a
/// throwaway String per child (efficiency-audit §6 medium).
pub(crate) fn render_into<M>(node: &Html<M>, s: &mut String) {
    render_into_ctx(node, s, None, 0);
}

/// Render the children of an element admitted as `body` into `s`.
///
/// The SSE diff's whole-subtree replace writes an element's new children
/// through this, so a patched `<script>`/`<style>` body gets the same
/// neutralisation the first paint applies.
pub(crate) fn render_children_into<M>(body: ElementBody, kids: &[Html<M>], s: &mut String) {
    render_body_into(body, kids, s, None, 0);
}

/// Render `kids`, the children of an element admitted as `body`, into `s`.
///
/// A `<script>` or `<style>` body is admitted only when every child is a
/// trusted `HRaw` node, so it is gathered verbatim into a scratch buffer and
/// neutralised as a whole: `neutralise_script_close` splits a `</script`
/// breakout, `neutralise_style_body` removes `</style` and every other markup
/// opener. `select_value` reaches only a `Markup` body's direct children.
fn render_body_into<M>(
    body: ElementBody,
    kids: &[Html<M>],
    s: &mut String,
    select_value: Option<&str>,
    depth: usize,
) {
    let child_depth = depth.saturating_add(1);
    match body {
        ElementBody::Markup => {
            for c in kids {
                render_into_ctx(c, s, select_value, child_depth);
            }
        }
        ElementBody::Script => {
            let mut raw = String::new();
            for c in kids {
                render_into_ctx(c, &mut raw, None, child_depth);
            }
            s.push_str(&css_safety::neutralise_script_close(&raw));
        }
        ElementBody::Style => {
            let mut raw = String::new();
            for c in kids {
                render_into_ctx(c, &mut raw, None, child_depth);
            }
            s.push_str(&css_safety::neutralise_style_body(&raw));
        }
    }
}

// `select_value`: when this node renders as a direct child of a `<select>` that
// carries a value, the chosen value is threaded here so the matching `<option>`
// flips `selected`.
#[allow(clippy::too_many_lines)]
fn render_into_ctx<M>(node: &Html<M>, s: &mut String, select_value: Option<&str>, depth: usize) {
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
            // `<script>`/`<style>` whose body is not trusted raw markup) is
            // dropped with its whole subtree, so no value built on the safe
            // surface reaches a raw-text or executable element body.
            let Ok(rendered) = admit_rendered(tag, kids) else {
                return;
            };
            let body = match rendered {
                // The doctype string is a fixed literal and the wrapper's own
                // tag/attrs are never written; its children render as markup
                // with full name/attr/text gating.
                RenderedElement::Doctype => {
                    s.push_str("<!DOCTYPE html>");
                    render_body_into(ElementBody::Markup, kids, s, None, depth);
                    return;
                }
                RenderedElement::Element(body) => body,
            };
            s.push('<');
            s.push_str(tag);
            // Collect regular + bool attrs into (key, value) pairs, then sort
            // by key — alphabetical order matches the byte-exact output expected
            // by golden tests. A BoolAttr renders as `k="true"` (the string
            // "true"), NOT a bare `k`.
            let mut pairs: Vec<(&str, String)> = vec![];
            let mut events: Vec<&str> = vec![];
            let mut ipe_id: Option<&str> = None;
            // Multi-valued attribute merge: `class` is HTML's space-separated
            // and `style` HTML's semicolon-separated multi-valued attribute: an
            // element carrying BOTH a Ipe.Ui-computed inline `style` (from
            // padding/background/border attrs) AND a user
            // `Ui.htmlAttribute "style" "z-index: 5"` must emit ONE merged
            // `style="…computed…; z-index: 5"`, not two `style="…"`
            // attributes (the browser keeps only the first → the user's
            // declarations are silently dropped). The Rust attribute list
            // never went through  map accumulation, so we fold the merge
            // here at collection time. First-seen value keeps its position
            // (Ipe.Ui composes the computed style first); later values append
            // so a user style declared last can override. Every other key is
            // last-wins (two `href`/`value` ⇒ override, matching  map set).
            for a in attrs {
                match a {
                    Attribute::Attr(k, v) => {
                        let k = k.as_str();
                        if k == "ipe-id" {
                            ipe_id = Some(v);
                        }
                        match pairs.iter_mut().find(|(pk, _)| *pk == k) {
                            Some((_, existing)) if !existing.is_empty() && k == "class" => {
                                existing.push(' ');
                                existing.push_str(v);
                            }
                            Some((_, existing)) if !existing.is_empty() && k == "style" => {
                                // `; ` separator unless `existing` already ends
                                // with `;` (then a single space) — avoids `;;`.
                                if existing.ends_with(';') {
                                    existing.push(' ');
                                } else {
                                    existing.push_str("; ");
                                }
                                existing.push_str(v);
                            }
                            Some((_, existing)) => {
                                // Last-wins for every other key (and for an
                                // empty existing style/class — nothing to join).
                                existing.clear();
                                existing.push_str(v);
                            }
                            None => pairs.push((k, v.clone())),
                        }
                    }
                    Attribute::BoolAttr(k, true) => {
                        let k = k.as_str();
                        match pairs.iter_mut().find(|(pk, _)| *pk == k) {
                            Some((_, existing)) => {
                                existing.clear();
                                existing.push_str("true");
                            }
                            None => pairs.push((k, "true".to_string())),
                        }
                    }
                    Attribute::BoolAttr(_, false) | Attribute::NoAttr => {}
                    Attribute::EventAttr(e) => events.push(e.name()),
                }
            }
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
                textarea_value = Some(v);
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
                    pairs.push(("selected", "selected".to_string()));
                }
            }
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            for (k, v) in &pairs {
                // Attr KEY is emitted unescaped; an unsafe key (`x onload=…`)
                // injects a new attribute, and a script-bearing key (`onerror`,
                // `srcdoc`) executes regardless of value-escaping. `SafeAttrName`
                // enforces both policies in one place; a key that fails is dropped.
                let Some(safe_key) = SafeAttrName::parse(k) else {
                    continue;
                };
                s.push(' ');
                s.push_str(safe_key.as_str());
                s.push_str("=\"");
                crate::escape::html_attr_into(sanitise_url_attr(k, v), s);
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
                    s.push_str(" data-ipe-hid=\"");
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
            render_body_into(body, kids, s, child_select_value, depth);
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
}

/// Decide whether an element `tag` with children `kids` may be rendered.
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
/// end them early.
pub(crate) fn admit_element<K: TrustedRawChild>(
    tag: &str,
    kids: &[K],
) -> Result<ElementBody, ElementRefusal> {
    if !is_safe_html_name(tag) {
        return Err(ElementRefusal::UnsafeName);
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

/// Decide how an `Html` element node `tag` with children `kids` is rendered.
///
/// This is the one admission rule of every rendered-tree walker (the render
/// sink and the SSE diff), so the two cannot disagree on which nodes are on
/// the page: the `Html.doctype` wrapper is recognised by its exact pseudo-tag,
/// before the name gate its `!` fails, and every other tag runs
/// `admit_element`.
pub(crate) fn admit_rendered<M>(
    tag: &str,
    kids: &[Html<M>],
) -> Result<RenderedElement, ElementRefusal> {
    if tag == DOCTYPE_WRAPPER_TAG {
        return Ok(RenderedElement::Doctype);
    }
    admit_element(tag, kids).map(RenderedElement::Element)
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

/// A validated HTML **attribute** name (parse-don't-validate). The ONLY way to
/// build one runs the full attribute-name policy — `is_safe_html_name` (charset:
/// no structural-breakout bytes) AND `!is_dangerous_attr_name` (no script-bearing
/// names) — exactly once. Every emit sink consumes a `SafeAttrName` instead of a
/// raw `&str`, so a sink CANNOT forget a check: an unchecked sink leaving
/// `htmlAttrToString` exposed is unrepresentable.
/// NB: element tag names and event-marker names are NOT attribute names — they
/// keep the plain `is_safe_html_name` gate.
struct SafeAttrName<'a>(&'a str);

impl<'a> SafeAttrName<'a> {
    fn parse(name: &'a str) -> Option<Self> {
        if is_safe_html_name(name) && !is_dangerous_attr_name(name) {
            Some(SafeAttrName(name))
        } else {
            None
        }
    }

    fn as_str(&self) -> &str {
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
/// Consumed by `dom/diff.rs` (the shared patch builder) — always compiled.
pub(crate) fn safe_patch_attr<'a>(name: &'a str, value: &'a str) -> Option<(&'a str, &'a str)> {
    let SafeAttrName(safe_name) = SafeAttrName::parse(name)?;
    Some((safe_name, sanitise_url_attr(name, value)))
}

/// Stamp every `HElement` (not HText/HRaw) with a stable `ipe-id` attribute derived
/// from its path. Idempotent: an existing ipe-id is overwritten with the same
/// value. HText/HRaw nodes are unaddressable .
///
/// Each non-root segment is `{path}_{idx}_{tag}[:{key}]` — the embedded tag means
/// two structurally different subtrees never share an id at the same positional
/// depth, and the optional `:{key}` disambiguator (from an explicit `ipe-key`
/// attribute, or implicit from `name` on form-bearing tags) lets keyed list items
/// and named form fields keep identity across reorder.
///
/// The id holds only `[A-Za-z0-9_.:-]`: a tag that fails `is_safe_html_name`
/// contributes [`UNSAFE_TAG_ID_SEGMENT`] instead of its own text, and a key is
/// sanitised, so `style_inject` can quote the id inside a CSS selector.
pub fn assign_ipe_ids<M>(node: &mut Html<M>, path: &str) {
    assign_ipe_ids_depth(node, path, 0);
}

/// The `ipe-id` tag segment of an element whose tag fails `is_safe_html_name`.
///
/// Such an element never renders, but its id still reaches `style_inject`.
const UNSAFE_TAG_ID_SEGMENT: &str = "x";

// Same bounded-descent rationale as render_into_ctx (see MAX_HTML_DEPTH): the
// stamper recurses once per nesting level, so an attacker-influenced deep tree
// would overflow the stack. Stop descending at the cap. Kept in step with the
// renderer's cap so a node the renderer drops is also left unstamped.
fn assign_ipe_ids_depth<M>(node: &mut Html<M>, path: &str, depth: usize) {
    if depth >= MAX_HTML_DEPTH {
        return;
    }
    if let Html::HElement(_tag, attrs, kids) = node {
        set_attr(attrs, "ipe-id", path);
        let mut idx = 0usize;
        for child in kids.iter_mut() {
            if let Html::HElement(ctag, cattrs, _) = child {
                let tag_seg = if is_safe_html_name(ctag) {
                    ctag.as_str()
                } else {
                    UNSAFE_TAG_ID_SEGMENT
                };
                let mut seg = format!("{path}_{idx}_{tag_seg}");
                if let Some(key) = ipe_id_key(ctag, cattrs) {
                    seg.push(':');
                    seg.push_str(&key);
                }
                idx += 1;
                assign_ipe_ids_depth(child, &seg, depth.saturating_add(1));
            }
        }
    }
}

/// Stable disambiguator for an element, or `None`. Priority: an explicit
/// `ipe-key` attribute (set by `Html.keyed`), then `name` on form-bearing tags.
/// Any matched value is sanitised so it can't corrupt the ipe-id grammar.
fn ipe_id_key<M>(tag: &str, attrs: &[Attribute<M>]) -> Option<String> {
    if let Some(k) = attr_value(attrs, "ipe-key")
        && !k.is_empty()
    {
        return Some(sanitise_ipe_id_key(k));
    }
    if matches!(
        tag,
        "input" | "textarea" | "select" | "form" | "button" | "fieldset"
    ) && let Some(k) = attr_value(attrs, "name")
        && !k.is_empty()
    {
        return Some(sanitise_ipe_id_key(k));
    }
    None
}

fn attr_value<'a, M>(attrs: &'a [Attribute<M>], key: &str) -> Option<&'a str> {
    attrs.iter().find_map(|a| match a {
        Attribute::Attr(k, v) if k == key => Some(v.as_str()),
        _ => None,
    })
}

/// Replace anything outside `[A-Za-z0-9_-]` with `_`. Prevents the key from
/// breaking ipe-id parsing, CSS selector escaping, or HTML attribute quoting.
fn sanitise_ipe_id_key(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
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
    Attribute::EventAttr(Event::OnMsg(name, msg))
}

/// `Ipe.Html.Events.{onInput,onChange,onKeyDown,onKeyUp}` — a
/// value-carrying event; the handler receives the input string. The compiler
/// Arc-wraps the emitted Ipê fn before this call.
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

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    #[derive(Clone, Debug, PartialEq)]
    enum Msg {
        Inc,
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
            vec![Attribute::EventAttr(Event::OnMsg("click".into(), ()))],
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
        assert_eq!(ids, vec!["r", "r_0_x", "r_0_x_0_b", "r_1_span"]);
        for id in &ids {
            assert!(
                !id.contains(['"', ']', '{', '<']),
                "ipe-id {id:?} holds a selector or markup metacharacter"
            );
        }
    }

    #[test]
    fn keyed_items_keep_id_across_reorder() {
        // Two keyed <li> swapped: each keeps its `:{key}` id so the diff can
        // target the moved element instead of replacing the whole list.
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
        // alpha keeps the same id in both renders even though its position moved.
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

    #[test]
    fn ipe_key_value_is_sanitised() {
        assert_eq!(sanitise_ipe_id_key("a/b c.d"), "a_b_c_d");
        assert_eq!(sanitise_ipe_id_key("keep-_OK9"), "keep-_OK9");
    }

    #[test]
    fn html_tree_constructs() {
        let t: Html<Msg> = Html::HElement(
            "button".into(),
            vec![Attribute::EventAttr(Event::OnMsg("click".into(), Msg::Inc))],
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
        let attr: Attribute<Msg> = Attribute::EventAttr(Event::OnMsg("click".into(), Msg::Inc));
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
            admit_element("script", &text()),
            Err(ElementRefusal::UntrustedScript)
        );
        assert_eq!(
            admit_element("ScRiPt", &text()),
            Err(ElementRefusal::UntrustedScript)
        );
        assert_eq!(
            admit_element("script", &none),
            Err(ElementRefusal::UntrustedScript)
        );
        assert_eq!(
            admit_element("style", &text()),
            Err(ElementRefusal::UntrustedStyle)
        );
        assert_eq!(
            admit_element("STYLE", &text()),
            Err(ElementRefusal::UntrustedStyle)
        );
        assert_eq!(
            admit_element("plaintext", &none),
            Err(ElementRefusal::Unclosable)
        );
        assert_eq!(admit_element("x y", &none), Err(ElementRefusal::UnsafeName));
        assert_eq!(admit_element("script", &raw()), Ok(ElementBody::Script));
        assert_eq!(admit_element("SCRIPT", &raw()), Ok(ElementBody::Script));
        assert_eq!(admit_element("style", &raw()), Ok(ElementBody::Style));
        assert_eq!(admit_element("style", &none), Ok(ElementBody::Style));
        for tag in [
            "div", "p", "title", "textarea", "noscript", "iframe", "template", "svg",
        ] {
            assert_eq!(
                admit_element(tag, &text()),
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
}
