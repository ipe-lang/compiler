// Boot data: the per-session values and the client config, read once from the
// page's inert JSON block `<script type="application/json" id="ipe-boot">`
// before any other code here runs. The block is the element right before this
// script's own tag, never a lookup by id: page content can carry any id, so an
// element of the app's earlier in the page never stands in for the block. A
// missing block, a block that is not JSON, or a field of the wrong type halts
// the client with an `IpeBootError` and shows the offline banner: the client
// never boots on invented defaults.
// `doc`'s own `name` accessor from `Document.prototype`.
function __ipeDocProp(doc, name) {
  var d = Object.getOwnPropertyDescriptor(Document.prototype, name);
  return d && d.get ? d.get.call(doc) : null;
}
// The document members the client reads, bound from the prototypes before any
// page content is consulted. A document's named properties (an `img`, `form`,
// `embed`, `object` or `iframe` with that `name`) shadow its built-in members
// with the element, so no read whose answer must come from the browser resolves
// through the document object's own lookup: `<img name="currentScript">` would
// hand the client the app's sibling, `<form name="body">` the app's form.
var __ipeDoc = (function(doc) {
  function prop(name) { return function() { return __ipeDocProp(doc, name); }; }
  function method(proto, name) { return proto[name].bind(doc); }
  return {
    script: prop("currentScript"),
    body: prop("body"),
    root: prop("documentElement"),
    active: prop("activeElement"),
    visibility: prop("visibilityState"),
    readyState: prop("readyState"),
    byId: method(Document.prototype, "getElementById"),
    create: method(Document.prototype, "createElement"),
    range: method(Document.prototype, "createRange"),
    query: method(Document.prototype, "querySelector"),
    queryAll: method(Document.prototype, "querySelectorAll"),
    on: method(EventTarget.prototype, "addEventListener")
  };
})(document);
// The element members the client calls on a node that may be a `<form>`,
// bound from the prototypes. A form's named controls shadow its built-in
// members with the control: `<input name="addEventListener">` makes
// `form.addEventListener` that input, so a listener bound or an attribute read
// through the form's own lookup throws before the submit is intercepted and
// the browser submits the form natively, its fields in the URL.
var __ipeNode = (function() {
  var getAttribute = Element.prototype.getAttribute;
  var setAttribute = Element.prototype.setAttribute;
  var removeAttribute = Element.prototype.removeAttribute;
  var remove = Element.prototype.remove;
  var contains = Node.prototype.contains;
  var on = EventTarget.prototype.addEventListener;
  var controls = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, "elements");
  function getter(proto, name) { return Object.getOwnPropertyDescriptor(proto, name).get; }
  var parentElement = getter(Node.prototype, "parentElement");
  var firstElementChild = getter(Element.prototype, "firstElementChild");
  var nextElementSibling = getter(Element.prototype, "nextElementSibling");
  var previousElementSibling = getter(Element.prototype, "previousElementSibling");
  var tagName = getter(Element.prototype, "tagName");
  var queryOne = Element.prototype.querySelector;
  var focusHtml = HTMLElement.prototype.focus;
  var focusSvg = SVGElement.prototype.focus;
  return {
    attr: function(el, name) { return getAttribute.call(el, name); },
    setAttr: function(el, name, v) { setAttribute.call(el, name, v); },
    removeAttr: function(el, name) { removeAttribute.call(el, name); },
    remove: function(el) { remove.call(el); },
    contains: function(el, other) { return contains.call(el, other); },
    on: function(el, type, fn) { on.call(el, type, fn); },
    // A form's controls; null for any other node.
    controls: function(el) {
      return el instanceof HTMLFormElement && controls && controls.get
          ? controls.get.call(el) : null;
    },
    parent: function(el) { return parentElement.call(el); },
    tag: function(el) { return tagName.call(el); },
    // The child-element indices leading from `root` down to `el`; null when
    // `el` is not below `root`.
    pathFrom: function(root, el) {
      var path = [];
      var node = el;
      while (node && node !== root) {
        var index = 0;
        var sibling = previousElementSibling.call(node);
        while (sibling) {
          index++;
          sibling = previousElementSibling.call(sibling);
        }
        path.push(index);
        node = parentElement.call(node);
      }
      return node === root ? path.reverse() : null;
    },
    // The element below `root` at `path`, or its deepest ancestor that exists.
    resolve: function(root, path) {
      var node = root;
      for (var i = 0; i < path.length; i++) {
        var child = firstElementChild.call(node);
        for (var k = 0; child && k < path[i]; k++) child = nextElementSibling.call(child);
        if (!child) break;
        node = child;
      }
      return node;
    },
    firstAutofocus: function(root) { return queryOne.call(root, "[autofocus]"); },
    // Whether `el` took focus: a node that cannot be focused stays unfocused.
    focus: function(el) {
      var run = el instanceof HTMLElement ? focusHtml : el instanceof SVGElement ? focusSvg : null;
      if (!run) return false;
      try { run.call(el, {preventScroll: true}); } catch (_) { return false; }
      return __ipeDoc.active() === el;
    }
  };
})();
var __IPE_BOOT_STRINGS = ["sid", "epoch", "base", "csrf"];
var __IPE_CFG_BOOLEANS = ["bannerEnabled", "swapToast"];
var __IPE_CFG_STRINGS = ["msgReconnecting", "msgUpdated", "msgOffline"];
var __IPE_TUNING_KEYS = [
  "RETRY_BASE_MS", "RETRY_MAX_MS", "RETRY_MAX_ATTEMPTS", "RETRY_FAST_MS",
  "RETRY_FAST_WINDOW_MS", "EVENT_QUEUE_MAX", "HELLO_TIMEOUT_MS", "HEARTBEAT_TTL_MS"
];
var __ipeBoot = (function() {
  function refuse(why) {
    __ipeShowBootFailure();
    var err = new Error("Ipe boot data " + why);
    err.name = "IpeBootError";
    throw err;
  }
  function isObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
  function requireType(obj, key, type, where) {
    if (!Object.prototype.hasOwnProperty.call(obj, key) || typeof obj[key] !== type) {
      refuse(where + key + " is not a " + type);
    }
  }
  var own = __ipeDoc.script();
  var node = own ? own.previousElementSibling : null;
  if (!node || node.tagName !== "SCRIPT" || node.id !== "ipe-boot" ||
      node.getAttribute("type") !== "application/json") {
    refuse("block is missing");
  }
  var data;
  try { data = JSON.parse(node.textContent); } catch (_) { refuse("block is not JSON"); }
  if (!isObject(data)) refuse("block is not an object");
  __IPE_BOOT_STRINGS.forEach(function(k) { requireType(data, k, "string", ""); });
  requireType(data, "cfg", "object", "");
  var cfg = data["cfg"];
  if (!isObject(cfg)) refuse("cfg is not an object");
  __IPE_CFG_BOOLEANS.forEach(function(k) { requireType(cfg, k, "boolean", "cfg."); });
  __IPE_CFG_STRINGS.forEach(function(k) { requireType(cfg, k, "string", "cfg."); });
  requireType(cfg, "tuning", "object", "cfg.");
  var tuning = cfg["tuning"];
  if (!isObject(tuning)) refuse("cfg.tuning is not an object");
  __IPE_TUNING_KEYS.forEach(function(k) {
    requireType(tuning, k, "number", "cfg.tuning.");
    var v = tuning[k];
    if (!isFinite(v) || v < 0 || Math.floor(v) !== v) {
      refuse("cfg.tuning." + k + " is not a count");
    }
  });
  return data;
})();
// The session globals other page scripts (the debugger overlay) read.
window.__IPE_SID = __ipeBoot["sid"];
window.__IPE_EPOCH = __ipeBoot["epoch"];
window.__IPE_BASE = __ipeBoot["base"];
window.__IPE_CSRF_TOKEN = __ipeBoot["csrf"];
var __ipeSid = __ipeBoot["sid"];
var __ipeBase = __ipeBoot["base"];
var __ipeCsrfToken = __ipeBoot["csrf"];
// The render epoch of the DOM on screen. An event carries the epoch its
// handler id was read under; the server resolves the id only against that
// render, and a refused event is answered with the current render, never
// re-sent.
var __ipeEpoch = __ipeBoot["epoch"] || null;
// A random id minted once per page load. With the client seq it lets the
// server ack a re-delivered event without dispatching it twice.
var __ipeTabId = (function() {
  try {
    var b = new Uint8Array(16);
    window.crypto.getRandomValues(b);
    var hex = "";
    for (var i = 0; i < b.length; i++) hex += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return hex;
  } catch (_) { return null; }
})();
// Split an epoch token "<32 hex>.<counter>" into its incarnation and counter.
function __ipeEpochParts(token) {
  if (typeof token !== "string" || token.indexOf(".") !== 32) return null;
  var n = token.slice(33);
  if (!/^[1-9][0-9]*$/.test(n)) return null;
  return { inc: token.slice(0, 32), n: n };
}
// Whether a full render at epoch `token` may replace the DOM: one from another
// render history always may; within one history only a render no older than
// the one on screen. Counters are canonical decimals, so a longer one is larger.
function __ipeFullBodyAdmits(token) {
  var next = __ipeEpochParts(token);
  var cur = __ipeEpochParts(__ipeEpoch);
  if (!next || !cur || next.inc !== cur.inc) return true;
  if (next.n.length !== cur.n.length) return next.n.length > cur.n.length;
  return next.n >= cur.n;
}
// Apply a full render through `applyFn` when its epoch admits it, then adopt
// that epoch. A render without a well-formed epoch leaves none, so the next
// event is refused and answered with the current render.
function __ipeAdoptFullBody(token, applyFn) {
  if (!__ipeFullBodyAdmits(token)) return;
  applyFn();
  __ipeEpoch = __ipeEpochParts(token) ? token : null;
}
// The newest full render the stream pushed while a <select> held focus (the
// proxy for an open dropdown, which any DOM mutation around it collapses),
// with its epoch gate inside `apply`. It applies once the select closes.
// `stale` marks a patches frame that could not apply meanwhile: the screen is
// then behind the server by more than the held render, so closing resyncs the
// stream instead. Until then the stream stays open: a resync's first frame
// would only be held again. A select can lose focus with no `focusout` (a
// focused node removed from the page), so a frame arriving with no select
// open, and the watchdog, release it too: nothing stays held once no select
// is open.
var __ipeHeldRender = null;
function __ipeSelectOpen() {
  var a = __ipeDoc.active();
  return !!a && a.tagName === "SELECT";
}
function __ipeHoldRender(apply) {
  __ipeHeldRender = { apply: apply, stale: false };
}
function __ipeMarkHeldStale() {
  if (__ipeHeldRender === null) __ipeHeldRender = { apply: null, stale: true };
  else __ipeHeldRender.stale = true;
}
// `picked` is a committed choice: the dropdown is shut though the select
// keeps focus.
function __ipeReleaseHeldRender(picked) {
  var held = __ipeHeldRender;
  if (held === null || (!picked && __ipeSelectOpen())) return;
  __ipeHeldRender = null;
  if (held.stale) __ipeResyncRender();
  else held.apply();
}
// A <select> closing releases the held render: on blur, and on a committed
// pick. Deferred so the select's own handlers send first, with the epoch of
// the DOM the user acted on.
__ipeDoc.on("focusout", function(ev) {
  if (ev.target && ev.target.tagName === "SELECT") {
    setTimeout(function() { __ipeReleaseHeldRender(false); }, 0);
  }
}, true);
__ipeDoc.on("change", function(ev) {
  if (ev.target && ev.target.tagName === "SELECT") {
    setTimeout(function() { __ipeReleaseHeldRender(true); }, 0);
  }
}, true);
// Server config from the boot block (`cfg`): the `IPE_WEB_BANNER`,
// `IPE_WEB_SWAP_TOAST` and `IPE_WEB_*` tuning settings resolve on the server
// and reach the client only here; the boot read checked every field.
var __ipeBootCfg = __ipeBoot["cfg"];
var __ipeBootTuning = __ipeBootCfg["tuning"];
var __ipeBannerEnabled = __ipeBootCfg["bannerEnabled"];
var __ipeRetryBaseMs = __ipeBootTuning["RETRY_BASE_MS"];
var __ipeRetryMaxMs = __ipeBootTuning["RETRY_MAX_MS"];
var __ipeRetryMaxAttempts = __ipeBootTuning["RETRY_MAX_ATTEMPTS"];
// Fast-reconnect front phase: for the first __ipeRetryFastWindowMs after a
// drop, retry on a short JITTERED constant interval (~__ipeRetryFastMs) so a
// fast server restart or a transient blip reconnects almost immediately;
// jitter spreads a mass reconnect so a recovering server is not
// thundering-herded. Past the window we fall back to exponential backoff. The
// window must outlast the expected outage: `ipe dev watch` injects a longer one
// (a dev rebuild takes seconds) while the default stays short so a real prod
// outage does not draw sustained fast retries.
var __ipeRetryFastMs = __ipeBootTuning["RETRY_FAST_MS"];
var __ipeRetryFastWindowMs = __ipeBootTuning["RETRY_FAST_WINDOW_MS"];
var __ipeEventQueueMax = __ipeBootTuning["EVENT_QUEUE_MAX"];
var __ipeMsgReconnecting = __ipeBootCfg["msgReconnecting"];
var __ipeMsgOffline = __ipeBootCfg["msgOffline"];
var __ipeMsgUpdated = __ipeBootCfg["msgUpdated"];
var __ipeHelloTimeoutMs = __ipeBootTuning["HELLO_TIMEOUT_MS"];
var __ipeHeartbeatTtlMs = __ipeBootTuning["HEARTBEAT_TTL_MS"];
// Dev-watch blue-green cutover mode. Set by the `ipe dev watch` blue-green server
// (IPE_WEB_SWAP_TOAST). When on, a reconnect is an expected rebuild cutover:
// the amber "Reconnecting…" banner is suppressed during the brief fast-window
// drop, and a successful reconnect greets the user with a small positive
// "updated ✓" toast instead. A release / `ipe dev run` server leaves this false,
// so the ordinary reconnect/offline chrome is unaffected in production.
var __ipeSwapToast = __ipeBootCfg["swapToast"];
// True once THIS page-life has seen a first `hello`. A later `hello` (or an
// explicit `swapped` frame) is therefore a reconnect, not the initial open —
// the swap toast greets only reconnects, never the first load.
var __ipeHelloEverOk = false;

// ── Input authority protocol state ───────────────────────────
// See docs/internals/web/input-authority-protocol.md §Client state.
// Step 2 populates these counters + per-input table on every send
// and response; Step 3 activates the patch filter that reads them;
// Step 4 activates the stale-drop test against __ipeLastAppliedSeq.
//
// Cycle 3 P47 (pub/sub global+local seq split — see
// docs/internals/web/pubsub-design.md §3.2): __ipeLastGlobalSeq is the
// app-wide broadcast counter. The server stamps it onto every
// broadcast-derived SSE frame (event:patches OR event:patch); the
// client dedupes against the largest value already applied so a
// replayed broadcast (e.g. SSE reconnect that re-delivers buffered
// frames) drops at the boundary without mutating state twice. Frames
// from per-session dispatch (the common case) carry globalSeq=0 OR
// omit the field; the guard treats 0 / missing as "no broadcast
// ordering constraint" and never blocks.
var __ipeClientSeq = 0;       // monotonic, client-owned; bumped on every __ipeSend
var __ipeLastAppliedSeq = 0;  // server-owned; largest local seq already applied
var __ipeLastGlobalSeq = 0;   // server-owned; largest broadcast globalSeq already applied (P47)
var __ipeInputs = {};         // ipe-id → InputEntry (populated by __ipeBindOne)

function __ipeInputEntry(sid) {
  var e = __ipeInputs[sid];
  if (!e) {
    e = __ipeInputs[sid] = {
      liveValue: "", lastSentSeq: 0, lastAckedSeq: 0,
      pendingDebounceId: null, pendingSend: null
    };
  }
  return e;
}

// __ipeInputsSnapshot — dirty-input projection bundled into every
// outgoing event. Only entries whose user-typed value is newer than
// the server's latest ack are included, so the wire stays compact
// when the client and server agree.
function __ipeInputsSnapshot() {
  var out = null;
  var ids = Object.keys(__ipeInputs);
  for (var i = 0; i < ids.length; i++) {
    var e = __ipeInputs[ids[i]];
    if (e.lastSentSeq <= e.lastAckedSeq) continue;
    if (!out) out = {};
    out[ids[i]] = {value: e.liveValue, seq: e.lastSentSeq};
  }
  return out;
}

// __ipeIngestSeq — fold a response or SSE frame's {seq, ackInputs}
// into client state. seq advances __ipeLastAppliedSeq monotonically;
// ackInputs retires per-input dirty flags so the next snapshot omits
// caught-up fields.
// __ipeIsDirty — a typable form field (input / textarea / select)
// whose DOM state is authoritative over the server's view. The check
// is scoped to those tags ONLY: buttons, anchors, divs and other
// focused-but-non-typable elements have no keystrokes to preserve,
// so treating them as dirty would wrongly block patches that wipe
// their containing subtree (e.g. navigating from a "new game"
// screen into a board view, where the focused button legitimately
// disappears). Scope signals: focus, pending debounce keyed by
// data-ipe-hid, or an unacked typed value at the input's ipe-id.
function __ipeIsDirty(el) {
  if (!el || el.nodeType !== 1) return false;
  var tag = el.tagName;
  if (tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT") return false;
  if (el === __ipeDoc.active()) return true;
  var hid = el.getAttribute && el.getAttribute("data-ipe-hid");
  if (hid && __ipeInputPending[hid]) return true;
  var sid = el.getAttribute && el.getAttribute("ipe-id");
  if (sid) {
    var e = __ipeInputs[sid];
    if (e && e.lastSentSeq > e.lastAckedSeq) return true;
  }
  return false;
}

function __ipeIngestSeq(seq, ackInputs, globalSeq) {
  if (typeof seq === "number" && seq > __ipeLastAppliedSeq) {
    __ipeLastAppliedSeq = seq;
  }
  // Cycle 3 P47: monotonic-applied semantics on the broadcast counter,
  // mirroring the local-seq path. Missing / zero / non-numeric globalSeq
  // is treated as "no broadcast ordering constraint" and ignored.
  if (typeof globalSeq === "number" && globalSeq > __ipeLastGlobalSeq) {
    __ipeLastGlobalSeq = globalSeq;
  }
  if (ackInputs) {
    var ids = Object.keys(ackInputs);
    for (var i = 0; i < ids.length; i++) {
      var e = __ipeInputs[ids[i]];
      if (!e) continue;
      var n = ackInputs[ids[i]];
      if (n > e.lastAckedSeq) e.lastAckedSeq = n;
    }
  }
}

// __ipeHandleResponse — gate DOM-mutating work behind the monotonic
// seq check (Step 4 / I2). An out-of-order or replayed frame with
// seq ≤ __ipeLastAppliedSeq is dropped entirely: a newer frame has
// already landed with a later view, and applying the stale payload
// would regress the DOM. Legacy frames that omit seq (or report 0)
// always apply — pre-upgrade servers keep working.
//
// Cycle 3 P47 (pub/sub global+local seq split — see
// docs/internals/web/pubsub-design.md §3.2): broadcast-derived frames also
// carry an OPTIONAL globalSeq. If supplied AND already applied (i.e.
// globalSeq > 0 && globalSeq <= __ipeLastGlobalSeq) the frame is
// dropped — a replayed broadcast (e.g. an SSE reconnect re-delivering
// buffered frames) would otherwise mutate state twice. Both guards
// fire independently: a frame is dropped if EITHER counter has already
// passed it; the localSeq guard alone suffices for the legacy
// non-broadcast case (globalSeq omitted / 0 → broadcast guard always
// passes).
function __ipeHandleResponse(seq, ackInputs, applyFn, globalSeq) {
  if (typeof seq === "number" && seq > 0 && seq <= __ipeLastAppliedSeq) {
    return; // stale — a newer local-seq frame already landed
  }
  if (typeof globalSeq === "number" && globalSeq > 0 && globalSeq <= __ipeLastGlobalSeq) {
    return; // stale — a newer broadcast frame already landed
  }
  __ipeIngestSeq(seq, ackInputs, globalSeq);
  applyFn();
}

// ── Focus preservation via node identity ────────────────────
// Ipe.Web renders subtrees via innerHTML replacement (both on JSON
// patches that carry p.html and on full-HTML navigations). Plain
// innerHTML DESTROYS the focused input element — even though JS is
// single-threaded, the browser's internal input-method editor (IME),
// autofill popover, undo stack, composition state, pointer-cursor
// blink, password manager affordances, and native caret are all
// tied to the live DOM NODE. Destroying it and recreating a clone
// with the same .value loses every one of those.
//
// The correct fix is to preserve node identity through the swap:
// before the replacement, locate the focused INPUT / TEXTAREA /
// SELECT, find its placeholder in the new HTML (by ipe-id → name),
// then SPLICE the live node into the new tree in place of the
// placeholder. Server-side attrs (class, type, placeholder, ...)
// get copied onto the live node, EXCEPT value/checked/selected —
// those stay under user authority.
//
// The live node never gets "destroyed" — it only moves between
// parents. .value, .selectionStart, IME state, composition buffer,
// autofill state all survive. Keystrokes in flight land on the
// same node regardless of where the browser has currently attached
// it in the DOM tree.
//
// Re-focus at the end because replaceChild on a focused element
// temporarily blurs it (focus isn't a property of the node, it's
// a property of the document). Selection is lost and must be
// restored too.

// __ipePlaceholderUncontrolled — true when the server-rendered
// element has no authority attribute set (no value/checked/selected,
// no textarea content, no option[selected]). For these the user-
// owned client state is canonical; we splice the live node across
// the swap so the user's typing isn't blanked. See
// docs/internals/web/input-authority-protocol.md §I6 (full-body
// preservation).
function __ipePlaceholderUncontrolled(placeholder) {
  if (!placeholder) return false;
  if (placeholder.hasAttribute("value")) return false;
  if (placeholder.hasAttribute("checked")) return false;
  if (placeholder.hasAttribute("selected")) return false;
  var tag = placeholder.tagName;
  if (tag === "TEXTAREA") {
    return (placeholder.textContent || "").length === 0;
  }
  if (tag === "SELECT") {
    return placeholder.querySelectorAll("option[selected]").length === 0;
  }
  // type=file: browsers refuse programmatic value assignment, the
  // user's selection is the only truth — always treat as uncontrolled.
  if (tag === "INPUT" && placeholder.getAttribute("type") === "file") return true;
  return true;
}

// __ipeFindPlaceholder — locate a live input's slot in the new tree.
// Prefer ipe-id (structurally stable + uniquely keyed). Fall back to
// tag+name only when the live element has no ipe-id AND the new tree
// has exactly one match — preventing wrong-input collisions when
// names recur (e.g. multiple address forms with name="line1").
function __ipeFindPlaceholder(tmp, live) {
  var sid = live.getAttribute && live.getAttribute("ipe-id");
  if (sid) {
    var bySid = tmp.querySelector('[ipe-id="' + sid.replace(/"/g, '\\"') + '"]');
    if (bySid) return bySid;
  }
  var name = live.getAttribute && live.getAttribute("name");
  if (!name) return null;
  var tag = live.tagName.toLowerCase();
  var matches = tmp.querySelectorAll(tag + '[name="' + name.replace(/"/g, '\\"') + '"]');
  if (matches.length === 1) return matches[0];
  return null;
}

// __ipeReplaceHTMLPreservingFocus — the authoritative swap.
// Drop-in for plain innerHTML assignment that keeps:
//   1. The currently-focused input (.value, IME state, composition
//      buffer, selection range, scroll position).
//   2. EVERY uncontrolled input/textarea/select in the subtree
//      (anything the server didn't render an authority attribute for).
//      Without this, an unfocused password field gets recreated by the
//      innerHTML swap and the user's typed secret is blanked — see
//      Bug 2 in docs/internals/web/architecture.md §Input preservation.
// __ipeApplyPatches (p.html and large p.text patches) parses and swaps in one
// call; __ipePatch (full body) takes the two steps apart to pick the page
// shell's root out of its one parse.
function __ipeReplaceHTMLPreservingFocus(container, newHTML) {
  __ipeSwapPreservingFocus(container, __ipeParseFor(container, newHTML));
}

// `html` parsed into a detached holder in `container`'s namespace, by the
// document's own parser: scripting is on, as for the markup it replaces.
function __ipeParseFor(container, html) {
  // Parse the new HTML into a detached element so we can splice
  // preserved live nodes into it before committing.
  //
  // Namespace correctness: when the container element is in a foreign-
  // content namespace (SVG or MathML), parsing the new HTML via a
  // plain detached `div` + .innerHTML = ... uses the
  // HTML insertion mode, so element names like <g>, <rect>, <text>
  // (which the diff emits as direct children when it replaces the
  // children of an <svg> element) end up in the XHTML namespace
  // rather than SVG. The elements appear in the DOM but the browser
  // doesn't lay them out as SVG primitives — the canvas silently goes
  // blank after a shape add/remove with no JS error to point at.
  //
  // Range.createContextualFragment parses HTML using the namespace
  // context of the range's container, preserving SVG/MathML element
  // namespaces correctly. The downstream code accepts either an
  // Element or a DocumentFragment via the same .firstChild /
  // .querySelectorAll / .parentNode.replaceChild surface, so no
  // other changes are needed.
  //
  // Repro before this fix: any Ipe.Web view that emits an HTML
  // patch at a ipe-id pointing at an <svg> element (the diff does
  // this whenever the SVG's children-count changes, or a child
  // tag/kind mismatches between renders) leaves the SVG with HTML-
  // namespaced children. Drawing tools, charts, and apps that swap
  // inline-SVG icon <path> children are the common victims.
  var tmp;
  if (container.namespaceURI && container.namespaceURI !== "http://www.w3.org/1999/xhtml") {
    var range = __ipeDoc.range();
    range.selectNodeContents(container);
    tmp = range.createContextualFragment(html);
  } else {
    tmp = __ipeDoc.create("div");
    tmp.innerHTML = html;
  }
  return tmp;
}

// Replace `container`'s children with the parsed holder `tmp`'s, splicing the
// live inputs described above into their placeholders.
//
// A swap never moves keyboard focus. Focus on any node inside `container` is
// recorded as the node's child-element path and the `ipe-id`s of it and its
// ancestors, and put back once the commit lands on the nearest node on that
// path carrying one of those `ipe-id`s (see `__ipeRestoreFocus`); a live field
// keeps its own node, value and selection (below). Focus outside `container`
// is not read or written.
function __ipeSwapPreservingFocus(container, tmp) {
  var focused = __ipeDoc.active();
  var inside = focused && focused !== __ipeDoc.body() &&
      __ipeNode.contains(container, focused);
  var focusPath = inside ? __ipeNode.pathFrom(container, focused) : null;
  var focusTag = inside ? __ipeNode.tag(focused) : "";
  var focusedInside = inside &&
      (focusTag === "INPUT" || focusTag === "TEXTAREA" || focusTag === "SELECT");
  // The server's identities (`ipe-id`: path, tag and key) of the focused node
  // and of its ancestors below `container`.
  var focusIds = [];
  for (var at = inside ? focused : null; at && at !== container; at = __ipeNode.parent(at)) {
    var atId = __ipeNode.attr(at, "ipe-id");
    if (atId !== null) focusIds.push(atId);
  }

  // Snapshot focused-state BEFORE any DOM mutation. Selection read
  // throws on some input types, so catch.
  var selStart = null, selEnd = null, scrollTop = 0;
  if (focusedInside) {
    try {
      selStart = focused.selectionStart;
      selEnd   = focused.selectionEnd;
    } catch (_) {}
    scrollTop = focused.scrollTop;
  }

  // Walk the LIVE container's inputs/textareas/selects and decide
  // which ones to splice. The focused element is ALWAYS spliced
  // (active typing wins). Other elements are spliced only when the
  // server-side placeholder is uncontrolled (no value/checked/
  // selected) — i.e. user state is canonical.
  var preservedFocus = null;
  var liveNodes = container.querySelectorAll("input, textarea, select");
  for (var i = 0; i < liveNodes.length; i++) {
    var live = liveNodes[i];
    var placeholder = __ipeFindPlaceholder(tmp, live);
    if (!placeholder) continue; // server unmounted: honour the server
    var isFocused = (live === focused);
    if (!isFocused && !__ipePlaceholderUncontrolled(placeholder)) {
      // Controlled field with a server-supplied value — let the
      // server win. Default innerHTML swap will recreate it from
      // placeholder.
      continue;
    }
    // Mirror placeholder attrs (class, type, placeholder, disabled,
    // aria-*, …) onto the live node — except the three authority
    // attrs the user drives. The user's .value / .checked /
    // .selected DOM property survives untouched.
    __ipeCopyAttrsExceptAuthority(placeholder, live);
    // Splice: replace the placeholder in tmp with the live node.
    // After this, the live node lives in tmp at the placeholder's
    // slot; the container still references it too (until the swap
    // below). DOM trees are tolerant of this — the upcoming
    // removeChild + appendChild commit moves it cleanly.
    placeholder.parentNode.replaceChild(live, placeholder);
    if (isFocused) preservedFocus = live;
  }

  // Commit: throw away container's current children (those we didn't
  // splice are stale; spliced ones already moved into tmp), then
  // attach tmp's children. Done.
  while (container.firstChild) container.removeChild(container.firstChild);
  while (tmp.firstChild) container.appendChild(tmp.firstChild);

  // Focus restoration on the SAME node — so .value, IME state,
  // composition buffer survive untouched. removeChild + appendChild
  // drop focus, so we re-set it now.
  if (preservedFocus) {
    try { preservedFocus.focus({preventScroll: true}); } catch (_) {
      try { preservedFocus.focus(); } catch (_) {}
    }
    if (typeof preservedFocus.setSelectionRange === "function" &&
        selStart !== null && selEnd !== null) {
      try { preservedFocus.setSelectionRange(selStart, selEnd); } catch (_) {}
    }
    if (scrollTop) preservedFocus.scrollTop = scrollTop;
  } else if (focusPath) {
    __ipeRestoreFocus(container, focusPath, focusIds);
  }
}

// Put focus back after a swap dropped it. Focus goes to the node at `path`
// below `container`, else to its nearest ancestor, that takes focus, walking
// from the path's deepest surviving node upward past `container`: a key
// handler bound on an ancestor keeps receiving keys. A node the swap created
// is a candidate only when its `ipe-id` is one of `ids`, the focused node's
// and its ancestors' before the swap; any other node at the path is another
// control, and a node without an `ipe-id` (raw markup) is never one.
// `container` and the nodes above it are the ones the swap kept. Focus that is
// already somewhere is left where it is.
function __ipeRestoreFocus(container, path, ids) {
  var now = __ipeDoc.active();
  if (now && now !== __ipeDoc.body()) return;
  var node = __ipeNode.resolve(container, path);
  while (node) {
    var kept = node === container;
    var own = kept ? null : __ipeNode.attr(node, "ipe-id");
    if ((kept || (own !== null && ids.indexOf(own) !== -1)) && __ipeNode.focus(node)) return;
    if (kept) break;
    node = __ipeNode.parent(node);
  }
  while (node) {
    if (__ipeNode.focus(node)) return;
    node = __ipeNode.parent(node);
  }
}

// The first mount of the page: the element the browser would have focused at
// parse time (the first `[autofocus]` below `root`), when nothing holds focus.
// The client mounts by patch, after the browser's own autofocus pass.
var __ipeMounted = false;
function __ipeFocusAutofocus(root) {
  var now = __ipeDoc.active();
  if (now && now !== __ipeDoc.body()) return;
  var el = __ipeNode.firstAutofocus(root);
  if (el) __ipeNode.focus(el);
}

// __ipeCopyAttrsExceptAuthority — mirror attrs from src onto dst,
// skipping the three the user drives directly. Removes attrs on
// dst that aren't in src (same "skip" rule). Used when splicing a
// live focused input into a server-rendered placeholder.
function __ipeCopyAttrsExceptAuthority(src, dst) {
  if (!src || !dst || !src.attributes || !dst.attributes) return;
  var isAuthority = function(n) {
    return n === "value" || n === "checked" || n === "selected";
  };
  // Drop attrs that aren't present in src.
  var toRemove = [];
  for (var i = 0; i < dst.attributes.length; i++) {
    var n = dst.attributes[i].name;
    if (isAuthority(n)) continue;
    if (!src.hasAttribute(n)) toRemove.push(n);
  }
  for (var r = 0; r < toRemove.length; r++) dst.removeAttribute(toRemove[r]);
  // Add / update attrs from src.
  for (var j = 0; j < src.attributes.length; j++) {
    var a = src.attributes[j];
    if (isAuthority(a.name)) continue;
    if (dst.getAttribute(a.name) !== a.value) dst.setAttribute(a.name, a.value);
  }
}

// __ipePatch: full-body replacement for ipe-nav clicks, popstate,
// and the server's full-HTML fallback path. Routes through the
// node-preservation splicer so keystrokes never land on a destroyed
// DOM node.
//
// A live re-render of the current page preserves the reader's scroll
// offset; a navigation to a new page starts at the top. Pass
// mode === "nav" for the navigation case; the default preserves scroll.
function __ipePatch(t, mode) {
  var root = __ipeDoc.byId("ipe-root");
  if (!root) return;
  // A full page (an ipe-nav or popstate fetch) contributes only its
  // `#ipe-root` contents: its head, boot block and scripts never enter the
  // live root, where script revival would run a second client.
  var parsed = __ipeShellRoot(__ipeParseFor(root, t), t);
  var scrollX = window.scrollX, scrollY = window.scrollY;
  var firstMount = !__ipeMounted;
  __ipeMounted = true;
  __ipeSwapPreservingFocus(root, parsed);
  if (firstMount) __ipeFocusAutofocus(root);
  // behavior:"instant" keeps this housekeeping scroll a synchronous jump
  // even under a global `scroll-behavior: smooth`, which would otherwise
  // animate every restore and fight the caret on per-keystroke re-renders.
  if (mode === "nav") {
    window.scrollTo({ left: 0, top: 0, behavior: "instant" });
  } else {
    window.scrollTo({ left: scrollX, top: scrollY, behavior: "instant" });
  }
  __ipeBindEvents();
  __ipeRunPaths(root);
  __ipeReviveScripts(root);
}

// The holder whose children are spliced into `#ipe-root` for the server HTML
// `t`, already parsed once as `tmp`. A page shell opens with a doctype and its
// first element after the head's is `#ipe-root`: only that element's children
// are spliced. Any other `t`, including a view that itself renders a doctype,
// is a body fragment and `tmp` is spliced whole. `t` is never re-serialized
// and parsed a second time: a parser without scripting reads a `<noscript>`
// body as markup and one with scripting reads it as text, so an attribute value
// read on the first parse could close the element on the second.
var __IPE_SHELL_HEAD_TAGS = ["META", "STYLE", "LINK", "TITLE", "BASE"];
function __ipeShellRoot(tmp, t) {
  if (!/^\s*<!doctype/i.test(t)) return tmp;
  var el = tmp.firstElementChild;
  while (el && __IPE_SHELL_HEAD_TAGS.indexOf(el.tagName) >= 0) el = el.nextElementSibling;
  return el && el.tagName === "DIV" && el.id === "ipe-root" ? el : tmp;
}

// __ipeReviveScripts: browsers DO NOT execute <script> tags inserted
// via innerHTML (or any HTML-string assignment). When Ipe.Web
// swaps the body via __ipeReplaceHTMLPreservingFocus (ipe-nav, full-
// body patches) or applies an attribute/HTML patch via
// __ipeApplyPatches, any <script src=...> or inline <script>
// element in the new content is added to the DOM but never
// executed. This breaks any app-level JS bundle injected via the
// Ipe-side Ui.html (Html.node "script" [...]) pattern (notably
// ipe-editor's Editor.scriptTag).
//
// The fix: walk the new subtree for <script> elements, replace
// each with a freshly-created one carrying a STRICT ALLOWLIST of
// attributes. Freshly-created script nodes execute on insertion.
//
// Security (Cycle 3 audit gap C9 / cycle 2 plan P31):
//   - Attribute copy is filtered through __ipeScriptAttrAllowlist.
//     Event-handler attrs (onerror, onload, onclick, …) are NEVER
//     re-emitted — the original unfiltered loop allowed an attacker
//     who controlled WYSIWYG content rendered back into Ui.html to
//     ship <script onerror=alert(1)> and watch the handler fire on
//     the next patch.
//   - Inline script bodies (textContent) are DROPPED unless the
//     element also carries a src= attribute (a same-origin opt-in:
//     Ipe-bundled scripts like ipe-editor's Editor.scriptTag set
//     src=; user-supplied inline bodies are silently rejected with
//     a console.warn so the misuse is visible during dev).
//   - Rejected scripts STILL get the data-ipe-script-revived
//     marker so a subsequent revival pass doesn't reprocess them
//     (i.e. silent-drop is idempotent — no infinite warning storm).
//
// Idempotency: each revived <script> gets a data-ipe-script-revived
// attribute; subsequent calls skip it. This prevents the bundle
// from re-loading on every patch (which would re-run any
// DOMContentLoaded handlers and re-fire setInterval-driven
// bootstraps multiple times).
//
// Safety: only matches <script> nodes inside root (the ipe-root
// container). Top-level page <script> tags (in <head> or outside
// ipe-root) are left alone — they ran on initial load and need
// no revival.
var __ipeScriptAttrAllowlist = {
  "src": 1,
  "type": 1,
  "async": 1,
  "defer": 1,
  "integrity": 1,
  "crossorigin": 1,
  "nomodule": 1,
  "referrerpolicy": 1,
  "data-ipe-script-revived": 1
};
function __ipeReviveScripts(root) {
  if (!root) return;
  var scripts = root.querySelectorAll("script:not([data-ipe-script-revived])");
  for (var i = 0; i < scripts.length; i++) {
    var old = scripts[i];
    // Mark the source element revived FIRST so a rejection branch
    // (no-src + inline body) doesn't re-trip on the next pass.
    try { old.setAttribute("data-ipe-script-revived", "1"); } catch (_) {}
    var hasSrc = old.hasAttribute("src");
    var hasInline = !!(old.textContent && old.textContent.length > 0);
    // Reject inline-only scripts (no src) — same-origin opt-in via
    // src= is the contract. Console.warn so the misuse is visible
    // during dev; never throws (one bad node mustn't kill the loop).
    if (!hasSrc && hasInline) {
      try {
        if (typeof console !== "undefined" && console.warn) {
          console.warn("[ipe.live] script revival rejected an inline <script> without src= (XSS hardening, gap C9). Bundle via src= for Ipe-side scripts.");
        }
      } catch (_) {}
      continue;
    }
    var fresh = __ipeDoc.create("script");
    // Copy ONLY allowlisted attributes. Event-handler attrs (anything
    // starting with "on…") and any non-allowlisted attribute are
    // silently dropped — see __ipeScriptAttrAllowlist.
    var droppedAttrs = null;
    for (var j = 0; j < old.attributes.length; j++) {
      var a = old.attributes[j];
      var n = a.name.toLowerCase();
      if (__ipeScriptAttrAllowlist[n] === 1) {
        try { fresh.setAttribute(a.name, a.value); } catch (_) {}
      } else {
        // Capture for a single dev-time warn at the end (a single
        // <script onerror=…> shouldn't fire one warn per attr).
        if (!droppedAttrs) droppedAttrs = [];
        droppedAttrs.push(a.name);
      }
    }
    if (droppedAttrs) {
      try {
        if (typeof console !== "undefined" && console.warn) {
          console.warn("[ipe.live] script revival dropped non-allowlisted attrs (XSS hardening, gap C9):", droppedAttrs.join(", "));
        }
      } catch (_) {}
    }
    // Inline body is now ONLY admitted when src= is also present.
    // This stays compatible with <script src=...>// optional inline
    // bootstrapping comment <\/script> patterns; the body is included
    // verbatim, the src= drives the actual execution.
    // (The escaped </ above prevents the literal closing-script tag
    // from terminating the inline JS wrapper at the HTML parser.)
    if (hasSrc && hasInline) {
      fresh.textContent = old.textContent;
    }
    fresh.setAttribute("data-ipe-script-revived", "1");
    // Replacing the old node with the fresh one triggers script
    // execution (for src= it fetches + runs; for inline it runs
    // the body).
    old.parentNode.replaceChild(fresh, old);
  }
}

// ── Loading indicator ────────────────────────────────────────
// Call __ipeLoaderStart() before network, __ipeLoaderEnd() after. An element
// with id="ipe-loader" gets the ipe-loading class added/removed. Small
// 80ms delay so fast responses don't flash the indicator.
var __ipeLoaderEl = null;
var __ipeLoaderTimer = null;
function __ipeLoaderStart() {
  __ipeLoaderEl = __ipeLoaderEl || __ipeDoc.byId("ipe-loader");
  if (!__ipeLoaderEl) return;
  clearTimeout(__ipeLoaderTimer);
  __ipeLoaderTimer = setTimeout(function() {
    __ipeLoaderEl.classList.add("ipe-loading");
  }, 80);
}
function __ipeLoaderEnd() {
  clearTimeout(__ipeLoaderTimer);
  if (__ipeLoaderEl) __ipeLoaderEl.classList.remove("ipe-loading");
}

// ── Debounce ─────────────────────────────────────────────────
var __ipeInputTimers = {};
var __ipeInputPending = {};
// `epoch` is the render epoch read with `hid` at the keystroke.
function __ipeDebouncedSend(msgName, args, hid, delay, epoch) {
  var key = hid || msgName;
  clearTimeout(__ipeInputTimers[key]);
  __ipeInputPending[key] = { msgName: msgName, args: args, hid: hid, epoch: epoch };
  __ipeInputTimers[key] = setTimeout(function() {
    delete __ipeInputPending[key];
    __ipeSend(msgName, args, hid, { noLoader: true, epoch: epoch });
  }, delay);
}
// Flush pending debounced input on blur (tab away / click elsewhere).
// Without this, typing fast then tabbing loses the last keystrokes
// because the debounce hasn't fired yet.
__ipeDoc.on("focusout", function(ev) {
  var t = ev.target;
  if (!t) return;
  var hid = t.getAttribute("data-ipe-hid");
  var key = hid || t.getAttribute("ipe-input");
  if (key && __ipeInputPending[key]) {
    clearTimeout(__ipeInputTimers[key]);
    var p = __ipeInputPending[key];
    delete __ipeInputPending[key];
    __ipeSend(p.msgName, p.args, p.hid, { noLoader: true, epoch: p.epoch });
  }
}, true);

// ── I3: flush on unmount ─────────────────────────────────────
// Any pending debounce that hasn't fired by the time the user
// navigates or closes the tab would normally be discarded — the
// setTimeout is torn down with the page. These handlers flush
// synchronously so the final keystroke always reaches the server.
// See docs/internals/web/input-authority-protocol.md §I3.

// __ipeCollectPendingBatch — snapshot every pending-debounce entry
// into a batch array, bumping __ipeClientSeq per entry so each gets
// its own order in the batch processed server-side. Clears the
// pending map as a side effect so the regular debounce callback
// can't double-fire after a beacon.
function __ipeCollectPendingBatch() {
  var keys = Object.keys(__ipeInputPending);
  if (keys.length === 0) return null;
  var batch = [];
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    clearTimeout(__ipeInputTimers[k]);
    var p = __ipeInputPending[k];
    delete __ipeInputPending[k];
    __ipeClientSeq++;
    batch.push({
      seq: __ipeClientSeq,
      msg: p.msgName || "",
      args: p.args || [],
      handlerId: p.hid || "",
      epoch: p.epoch
    });
  }
  return batch;
}

// __ipeFlushPendingBeacon — POST pending debounces on page unload so
// the request survives. Single payload carries the whole batch + the
// latest inputState snapshot so the server ingests the final DOM
// values before dispatching. Silent no-op when there's nothing
// pending.
//
// Uses a keepalive fetch (not navigator.sendBeacon) because the CSRF
// middleware rejects POSTs to /_ipe/event without a matching
// X-Ipe-Csrf header — and sendBeacon cannot set request headers, so a
// beacon would be silently dropped whenever CSRF is enabled. keepalive
// fetch survives unload AND carries the header. sendBeacon remains a
// best-effort fallback only when CSRF is disabled (empty token) or
// keepalive is unsupported.
function __ipeFlushPendingBeacon() {
  var batch = __ipeCollectPendingBatch();
  var snapshot = __ipeInputsSnapshot();
  if (!batch && !snapshot) return;
  var body = { sessionId: __ipeSid };
  if (batch)    body.batch = batch;
  if (snapshot) body.inputState = snapshot;
  var json = JSON.stringify(body);
  try {
    var headers = {"Content-Type":"application/json"};
    if (__ipeCsrfToken) headers["X-Ipe-Csrf"] = __ipeCsrfToken;
    fetch(__ipeBase + "/_ipe/event", {
      method: "POST",
      headers: headers,
      body: json,
      credentials: "same-origin",
      keepalive: true
    }).catch(function(_){});
    return;
  } catch (_) {}
  // Legacy fallback: keepalive fetch unsupported. sendBeacon cannot
  // carry the CSRF header, so this only reaches the server when CSRF
  // is disabled; otherwise it is dropped (no worse than no flush).
  if (navigator && typeof navigator.sendBeacon === "function") {
    try {
      var blob = new Blob([json], {type: "application/json"});
      navigator.sendBeacon(__ipeBase + "/_ipe/event", blob);
    } catch (_) {}
  }
}

// __ipeFlushPendingSync — synchronous variant for same-page
// transitions where sendBeacon is overkill. Calls __ipeSend for
// each pending entry; the fetch requests are fire-and-forget and
// the browser keeps them alive across same-origin navigation.
function __ipeFlushPendingSync() {
  var batch = __ipeCollectPendingBatch();
  if (!batch) return;
  for (var i = 0; i < batch.length; i++) {
    var b = batch[i];
    __ipeSend(b.msg, b.args, b.handlerId, {noLoader: true, epoch: b.epoch});
  }
}

// Capture-phase click listener inside ipe-root: before a link click
// leaves the current page, drain any pending debounce so the final
// typed value reaches the server in the same origin as the
// outgoing navigation. Beacon path handles cross-page; sync path
// handles SPA-style internal routing.
__ipeDoc.on("click", function(ev) {
  var a = ev.target && ev.target.closest && ev.target.closest("a[href]");
  if (!a) return;
  var root = __ipeDoc.byId("ipe-root");
  if (!root || !root.contains(a)) return;
  var href = a.getAttribute("href") || "";
  // External or cross-origin → beacon (browser will tear down the
  // page, fetch would be cancelled). Same-origin navigation inside
  // SPA-style routing → sync flush (fetch survives).
  var isExternal = /^(https?:)?\/\//.test(href) && a.host !== location.host;
  if (isExternal || href === "") {
    __ipeFlushPendingBeacon();
  } else {
    __ipeFlushPendingSync();
  }
}, true);

// Tab close / navigate away: sendBeacon is the only path that
// survives the teardown. Listen on both events because iOS Safari
// + bfcache fire pagehide instead of beforeunload.
window.addEventListener("beforeunload", __ipeFlushPendingBeacon);
window.addEventListener("pagehide", __ipeFlushPendingBeacon);

// ── Core send ────────────────────────────────────────────────
// Wire format (see docs/internals/web/input-authority-protocol.md §Request):
//   {sessionId, seq, msg, args, handlerId, epoch?, tab?, inputState?}
//   * seq is client-monotonic — server uses it to match responses to
//     the inputState snapshot that produced them; with tab it marks a
//     re-delivered event as a duplicate.
//   * epoch names the render handlerId was read from.
//   * inputState carries the user's current DOM values for every
//     dirty input so the server's diff can align against reality
//     before emitting patches.
function __ipeSend(msgName, args, handlerId, opts) {
  opts = opts || {};
  if (!opts.noLoader) __ipeLoaderStart();
  __ipeClientSeq++;
  var mySeq = __ipeClientSeq;
  // Stamp every currently-dirty input with this seq. The server's
  // ack (for a future response) will clear them back to parity.
  var dirtyIds = Object.keys(__ipeInputs);
  for (var di = 0; di < dirtyIds.length; di++) {
    var de = __ipeInputs[dirtyIds[di]];
    if (de.liveValue !== "" || de.pendingDebounceId !== null) {
      de.lastSentSeq = mySeq;
    }
  }
  var snapshot = __ipeInputsSnapshot();
  var body = {
    sessionId: __ipeSid,
    seq: mySeq,
    msg: msgName || "",
    args: args || [],
    handlerId: handlerId || ""
  };
  // The epoch read with the handler id, or the current one for a caller that
  // reads no id from the DOM. A retry re-posts this body, so it keeps the stamp.
  var epoch = ("epoch" in opts) ? opts.epoch : __ipeEpoch;
  if (epoch) body.epoch = epoch;
  if (__ipeTabId) body.tab = __ipeTabId;
  if (snapshot) body.inputState = snapshot;
  __ipePostEvent(body);
}

// ── POST retry queue ─────────────────────────────────────────
// Wire-protocol POSTs are cheap (small JSON, idempotent on the
// server's seq-ordered state machine), so a transient network blip
// shouldn't lose the click. Failures push the body onto __ipeEventQueue;
// retries fire on exponential backoff (500ms, 1s, 2s, … cap 16s);
// the SSE 'open' handler drains the queue eagerly when the server
// comes back. Cap at 50 entries — beyond that the user has been
// offline so long that replay isn't useful, drop oldest with a
// console warn so the page doesn't accumulate megabytes of state.
var __ipeEventQueue = [];
var __ipeRetryTimer = null;
var __ipeRetryAttempts = 0;
// Epoch ms of the first retry in the current disconnect burst (0 = connected).
// Bounds the fast-reconnect window; reset to 0 on a successful (re)connect.
var __ipeReconnectSince = 0;
// __ipeRetryBaseMs / __ipeRetryMaxMs / __ipeRetryMaxAttempts /
// __ipeEventQueueMax are templated at the top of this script from
// the IPE_WEB_RETRY_* / IPE_WEB_QUEUE_MAX env vars.
function __ipePostEvent(body) {
  // Phase 1.2 — attach the per-session CSRF token. The server-side
  // middleware () rejects POSTs
  // without a matching X-Ipe-Csrf / __ipe_csrf cookie pair. Empty
  // token means CSRF is disabled at the runtime level (package.ipe
  // [security] csrf = false) — header omitted, middleware skipped.
  var headers = {"Content-Type":"application/json"};
  if (__ipeCsrfToken) headers["X-Ipe-Csrf"] = __ipeCsrfToken;
  fetch(__ipeBase + "/_ipe/event", {
    method: "POST",
    headers: headers,
    body: JSON.stringify(body),
    credentials: "same-origin"
  }).then(function(r){
    if (r.status === 409 && r.headers.get("X-Ipe-Web") === "1") {
      // The server refused the event's render epoch and sent the current
      // render. Apply it and end here: the refused event is never re-sent,
      // since its handler id may now name another handler.
      return r.json().then(function(data) {
        __ipeLoaderEnd();
        __ipeOnPostSuccess();
        if (!data || typeof data.body !== "string") return;
        // The epoch gate orders this render against the DOM on screen; the
        // seq it carries is the session's, which an earlier ack may equal.
        __ipeAdoptFullBody(data.epoch, function() { __ipePatch(data.body); });
      }).catch(function() { __ipeLoaderEnd(); });
    }
    if (!r.ok && r.status >= 500) {
      // Server is up but rejecting (502/503/504 from a deploying LB,
      // or 500 from a panic that survived the recover guard). Treat
      // as transient — same retry path as a network failure.
      throw new Error("server " + r.status);
    }
    // Reverse-proxy wedge detection: a real Ipe.Web response always
    // carries X-Ipe-Web: 1. Without it, we're looking at a proxy-
    // rewritten response (e.g. some edges turn upstream 502 into 200
    // OK with an HTML error page). Applying that as a "patch" would
    // replace the user's DOM with the proxy's error page, so we refuse
    // it and route through the failure path instead.
    //
    // For JSON content-type we keep a backwards-compat shim during
    // rolling deploys: a pre-marker server still returns valid JSON
    // with seq + patches, structurally indistinguishable from the
    // marked form, so accept it. HTML / text responses without the
    // marker are always rejected — those are the proxy-wedge shape.
    var ipeMark = r.headers.get("X-Ipe-Web");
    var ct = r.headers.get("Content-Type") || "";
    var isJson = ct.indexOf("application/json") >= 0;
    if (ipeMark !== "1" && !isJson) {
      throw new Error("non-ipe response " + r.status);
    }
    if (isJson) {
      return r.json().then(function(data) {
        // Even JSON is rejected if it lacks the protocol shape (no
        // seq field): some proxies (Cloudflare access denied, fly.io
        // edge errors) return JSON error envelopes with 200 OK.
        if (ipeMark !== "1" && (!data || typeof data.seq === "undefined")) {
          throw new Error("non-ipe json response");
        }
        __ipeLoaderEnd();
        __ipeOnPostSuccess();
        if (!data) return;
        __ipeHandleResponse(data.seq, data.ackInputs, function() {
          if (data.patches) __ipeApplyPatches(data.patches);
        }, data.globalSeq);
      });
    }
    return r.text().then(function(t) {
      __ipeLoaderEnd();
      __ipeOnPostSuccess();
      var seqStr = r.headers.get("X-Ipe-Seq");
      var seq = seqStr ? parseInt(seqStr, 10) : 0;
      var ackRaw = r.headers.get("X-Ipe-Ack-Inputs");
      var ack = null;
      if (ackRaw) { try { ack = JSON.parse(ackRaw); } catch(_) {} }
      __ipeHandleResponse(seq, ack, function() { __ipePatch(t); });
    });
  }).catch(function() {
    __ipeLoaderEnd();
    __ipeOnPostFailure(body);
  });
}
function __ipeOnPostSuccess() {
  // A successful POST proves the server reachable — clear any
  // backoff state and drain queued events behind this one. If the
  // SSE was the trigger that drained the queue, this is a no-op.
  __ipeRetryAttempts = 0;
  __ipeReconnectSince = 0;  // reopen the fast-reconnect window for the next drop
  if (__ipeRetryTimer !== null) {
    clearTimeout(__ipeRetryTimer);
    __ipeRetryTimer = null;
  }
  if (__ipeStatus !== "connected") {
    __ipeSetStatus("connected", "");
  }
  // SSE recovery: if the watchdog tore down the EventSource (offline
  // terminal state), a successful POST proves the network is back, so
  // reopen the stream too — otherwise subscriptions and Cmd.perform
  // results would silently not arrive even though clicks work. Cancel
  // any pending reopen-with-backoff and bring it forward.
  if (__ipeSSE === null) {
    if (__ipeSseReopenTimer !== null) {
      clearTimeout(__ipeSseReopenTimer);
      __ipeSseReopenTimer = null;
    }
    __ipeOpenSSE();
  }
  __ipeDrainQueue();
}
function __ipeOnPostFailure(body) {
  // FIFO drop when the queue is at the cap — bail on the oldest
  // pending event rather than the new one, so the user's most
  // recent intent is preserved.
  if (__ipeEventQueue.length >= __ipeEventQueueMax) {
    var dropped = __ipeEventQueue.shift();
    if (window.console && console.warn) {
      console.warn("[ipe.live] event queue at cap; dropped oldest", dropped);
    }
  }
  __ipeEventQueue.push(body);
  __ipeShowReconnecting();
  __ipeScheduleRetry();
}
function __ipeShowReconnecting() {
  if (__ipeStatus === "offline") return;
  // Dev blue-green: a drop inside the fast-reconnect window is almost always a
  // rebuild cutover, not an outage — stay quiet and let the "updated ✓" toast
  // fire when the new binary answers. If the reconnect does NOT land inside the
  // window (a genuine connection loss), we fall through to the amber banner.
  if (__ipeSwapToast && __ipeInFastReconnect()) return;
  if (__ipeStatus === "connected") {
    __ipeSetStatus("reconnecting", __ipeMsgReconnecting);
  }
}
// True while still inside the fast-reconnect window after a drop. Starts the
// disconnect clock on first call. Fast-phase retries are NOT counted toward the
// give-up cap, so the window always runs its full duration.
function __ipeInFastReconnect() {
  var now = (Date.now ? Date.now() : new Date().getTime());
  if (__ipeReconnectSince === 0) __ipeReconnectSince = now;
  return (now - __ipeReconnectSince) < __ipeRetryFastWindowMs;
}
// ±20% jitter, whole ms, never below 1 — spreads a mass reconnect so a
// recovering server is not thundering-herded.
function __ipeJitter(ms) {
  return Math.max(1, Math.round(ms * (0.8 + Math.random() * 0.4)));
}
// Exponential backoff for the post-window phase: 500, 1000, 2000, … capped at
// __ipeRetryMaxMs, jittered.
function __ipeExpBackoffDelay() {
  return __ipeJitter(Math.min(__ipeRetryBaseMs * Math.pow(2, __ipeRetryAttempts - 1), __ipeRetryMaxMs));
}
function __ipeScheduleRetry() {
  if (__ipeRetryTimer !== null) return;  // already pending
  var delay;
  if (__ipeInFastReconnect()) {
    delay = __ipeJitter(__ipeRetryFastMs);  // fast phase — not counted toward give-up
  } else {
    if (__ipeRetryAttempts >= __ipeRetryMaxAttempts) {
      __ipeSetStatus("offline", __ipeMsgOffline);
      return;
    }
    __ipeRetryAttempts++;
    delay = __ipeExpBackoffDelay();
  }
  __ipeRetryTimer = setTimeout(function() {
    __ipeRetryTimer = null;
    __ipeDrainQueue();
  }, delay);
}
function __ipeDrainQueue() {
  if (__ipeEventQueue.length === 0) return;
  // Send the head of the queue. If it succeeds, __ipeOnPostSuccess
  // recurses into __ipeDrainQueue to send the next one. If it
  // fails, the body re-enters the queue and the retry loop kicks
  // back in. Order is preserved (FIFO) — the server's seq matching
  // tolerates late deliveries via __ipeHandleResponse.
  var head = __ipeEventQueue.shift();
  __ipePostEvent(head);
}

// Apply a list of ipe-id addressed patches with input authority (I1):
// value/checked/selected attrs on dirty inputs are dropped so the
// user's DOM wins; innerHTML patches route through
// __ipeReplaceHTMLPreservingFocus which splices the live focused
// input (same DOM node, same .value, same IME/composition state)
// through the new HTML so it's never destroyed. Per-attr and
// textContent updates are fine as-is — they don't regenerate nodes.
// Attributes a patch mirrors onto a live property, by attribute name. Once the
// user or the client sets `checked` or `selected` the property stops following
// its attribute, so a patch writes the property beside the attribute on every
// set and every removal: a removed attribute clears its property.
var __IPE_LIVE_PROPS = Object.freeze({
  checked: "checked",
  selected: "selected",
  disabled: "disabled"
});
function __ipeApplyPatches(patches) {
  if (!patches || patches.length === 0) return;
  __ipeMounted = true;
  // Open <select> defence: native dropdowns close on ANY DOM mutation
  // inside the open select OR any ancestor that would re-mount it.
  // There's no JS API for "is the dropdown open", so use focus as the
  // conservative proxy: if a SELECT is the active element, treat its
  // subtree (and ancestors that would re-mount it) as off-limits for
  // this patch cycle. The next user interaction (option click, blur)
  // triggers a fresh response and reconciliation. Sibling subtrees
  // and unrelated parts of the DOM apply normally — the dropdown is
  // unaffected. See Bug 3 in docs/internals/web/architecture.md.
  var openSel = (__ipeDoc.active() && __ipeDoc.active().tagName === "SELECT")
      ? __ipeDoc.active() : null;
  for (var i = 0; i < patches.length; i++) {
    var p = patches[i];
    var el = __ipeDoc.query('[ipe-id="' + p.id.replace(/"/g, '\\"') + '"]');
    if (!el) continue;
    if (openSel && (el === openSel || __ipeNode.contains(el, openSel) ||
        __ipeNode.contains(openSel, el))) {
      // Skip: any mutation here would close the dropdown mid-pick.
      continue;
    }
    if (p.text !== undefined && p.text !== null) {
      // textContent on a container that contains the focused node
      // would also wipe it (replaces all children with one
      // text node). Guard the same way as innerHTML.
      if (__ipeContainsFocus(el)) {
        __ipeReplaceHTMLPreservingFocus(el, __ipeEscapeHTML(p.text));
      } else {
        el.textContent = p.text;
      }
    }
    if (p.html !== undefined && p.html !== null) {
      __ipeReplaceHTMLPreservingFocus(el, p.html);
    }
    if (p.attrs) {
      var dirty = __ipeIsDirty(el);
      var keys = Object.keys(p.attrs);
      // Cursor preservation: when applying a "value" attr to a
      // focused INPUT or TEXTAREA, snapshot the selection range
      // BEFORE setting .value (which otherwise resets the cursor
      // to the end of the new string). Common case: user clicked
      // into a textarea, paused so their dirty flag cleared, and
      // the server pushes a fresh value via SSE. Without this,
      // the cursor jumps to the end mid-edit. Clamping handles
      // shorter new values (selectionStart > newLen -> newLen).
      var isInputLike = el.tagName === "INPUT" || el.tagName === "TEXTAREA";
      var hadFocus = isInputLike && el === __ipeDoc.active();
      var savedSelStart = null, savedSelEnd = null, savedScrollTop = 0;
      if (hadFocus) {
        try {
          savedSelStart = el.selectionStart;
          savedSelEnd = el.selectionEnd;
        } catch (_) {}
        savedScrollTop = el.scrollTop;
      }
      var valueChanged = false;
      for (var j = 0; j < keys.length; j++) {
        var k = keys[j], v = p.attrs[k];
        // Authority filter: the user is currently editing this
        // field, so the server's proposed value/checked/selected
        // would stomp in-flight keystrokes. Drop them and let the
        // next event round-trip settle the state.
        if (dirty && (k === "value" || k === "checked" || k === "selected")) {
          continue;
        }
        var prop = Object.prototype.hasOwnProperty.call(__IPE_LIVE_PROPS, k)
            ? __IPE_LIVE_PROPS[k] : null;
        if (v === "") {
          __ipeNode.removeAttr(el, k);
          if (prop !== null) el[prop] = false;
        } else {
          __ipeNode.setAttr(el, k, v);
          // Sync DOM properties that don't reflect from attrs.
          if (k === "value" && ("value" in el)) {
            el.value = v;
            valueChanged = true;
          }
          if (prop !== null) el[prop] = v !== "false";
        }
      }
      // Restore selection on focused input/textarea after a value
      // update. Clamp to the new value length so a shorter server
      // value does not throw RangeError. Scroll restore matters
      // mostly for multi-line textarea where the user may have
      // scrolled below the visible area.
      if (hadFocus && valueChanged && savedSelStart !== null &&
          typeof el.setSelectionRange === "function") {
        var newLen = (el.value || "").length;
        var s = Math.min(savedSelStart, newLen);
        var e = Math.min(savedSelEnd === null ? s : savedSelEnd, newLen);
        try { el.setSelectionRange(s, e); } catch (_) {}
        if (savedScrollTop) el.scrollTop = savedScrollTop;
      }
    }
    if (p.remove) __ipeNode.remove(el);
  }
  // Any new ipe-* attribute in the patched DOM needs a listener.
  __ipeBindEvents();
  // After SSE-driven patches the URL also needs reconciling — without
  // this, programmatic Navigate Msgs would only update the in-memory
  // model and leave the address bar pointing at the previous page.
  __ipeRunPaths();
  // Any <script> in newly-patched HTML wouldn't execute via innerHTML
  // — revive them so JS bundles (e.g. ipe-editor) bootstrap correctly
  // when their host element first appears via a patch (not the initial
  // SSR).  See __ipeReviveScripts above for the full rationale.
  var ipeRootForPatches = __ipeDoc.byId("ipe-root");
  if (ipeRootForPatches) __ipeReviveScripts(ipeRootForPatches);
}

// Whether a wholesale rewrite of `el`'s children would drop focus: focus is
// on a node below `el`, or on `el` itself when `el` is a field.
function __ipeContainsFocus(el) {
  var a = __ipeDoc.active();
  if (!a || a === __ipeDoc.body()) return false;
  if (!__ipeNode.contains(el, a)) return false;
  if (el !== a) return true;
  var tag = a.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

function __ipeEscapeHTML(s) {
  var d = __ipeDoc.create("div");
  d.textContent = s == null ? "" : String(s);
  return d.innerHTML;
}

// ── TEA event binding ────────────────────────────────────────
// Walks the DOM for ipe-<event> attributes and binds a native listener
// that extracts args and dispatches through the TEA update cycle.
// Re-run after every DOM patch because new ipe-* attrs may have appeared.
function __ipeBindEvents() {
  var events = ["click", "dblclick", "input", "change", "submit", "focus", "blur",
                "keydown", "keyup", "keypress", "mouseover", "mouseout",
                "mousedown", "mouseup"];
  for (var i = 0; i < events.length; i++) {
    __ipeBindOne(events[i]);
  }
}

// __ipeRunPaths: safer, CSP-friendly alternative to data-ipe-eval for
// the specific case of "update the address bar after a render." Looks
// for [data-ipe-path] elements and pushes / replaces history if the
// value differs from location. No new Function(), no eval; the only
// DOM APIs touched are getAttribute and history.pushState /
// replaceState. Works under strict CSP (no 'unsafe-eval') and has no
// XSS surface (the value is a URL path, never executed).
//
// The element is intentionally NOT removed after running — Ipe.Web's
// patches identify elements by ipe-id and look them up via
// querySelector; removing the data-ipe-path element would orphan its
// ipe-id, and the next attribute patch (when the path changes) would
// silently skip. The path-check makes the call idempotent, so leaving
// the element in place is cheap — at most one comparison per patch.
function __ipeRunPaths(root) {
  var sel = "[data-ipe-path]";
  var els = root ? root.querySelectorAll(sel) : __ipeDoc.queryAll(sel);
  for (var i = 0; i < els.length; i++) {
    var p = els[i].getAttribute("data-ipe-path");
    if (!p) continue;
    if (location.pathname !== p) {
      try { history.pushState({}, "", p); } catch (_) {}
    } else if (location.search) {
      try { history.replaceState({}, "", p); } catch (_) {}
    }
  }
}

// The elements already carrying the client's listener, per event name. Kept
// beside the elements, never on them: a form's control named after a marker
// property would answer for it.
var __ipeBound = Object.create(null);
function __ipeBindOne(eventName) {
  var bound = __ipeBound[eventName] || (__ipeBound[eventName] = new WeakSet());
  var nodes = __ipeDoc.queryAll("[ipe-" + eventName + "]");
  for (var i = 0; i < nodes.length; i++) {
    var el = nodes[i];
    if (bound.has(el)) continue;
    bound.add(el);
    __ipeNode.on(el, eventName, function(ev) {
      // A bound submit is the client's to send, never the browser's: it is
      // prevented before anything here can throw.
      if (ev.type === "submit") ev.preventDefault();
      var target = ev.currentTarget;
      var msgName = __ipeNode.attr(target, "ipe-" + ev.type);
      var hid     = __ipeNode.attr(target, "data-ipe-hid");
      var epoch   = __ipeEpoch;
      if (!msgName && !hid) return;
      var args = __ipeExtractArgs(ev);
      if (ev.type === "input") {
        // Track live value against ipe-id so the snapshot bundled in
        // the next __ipeSend reflects the user's actual DOM state,
        // and so Step 3's patch filter can recognise dirty inputs.
        var sid = __ipeNode.attr(target, "ipe-id");
        if (sid) {
          var e = __ipeInputEntry(sid);
          e.liveValue = args && args.length > 0 ? String(args[0]) : "";
        }
        __ipeDebouncedSend(msgName, args, hid, 150, epoch);
        return;
      }
      __ipeSend(msgName, args, hid, { epoch: epoch });
    });
  }
}

// Extract the args array for a DOM event following the legacy Ipe.Web
// convention:
//   * click / focus / blur / mouse*    → []         (just the msg)
//   * input / change                   → [value]    (typed input value)
//   * submit                           → [formData] (plain object of [name]=value)
//   * keydown / keyup / keypress       → [key]      (event.key string)
function __ipeExtractArgs(ev) {
  var t = ev.target;
  switch (ev.type) {
    case "input":
    case "change":
      if (!t) return [""];
      if (t.type === "checkbox" || t.type === "radio") return [t.checked];
      if (t.type === "number" || t.type === "range") return [t.valueAsNumber || 0];
      return [t.value == null ? "" : String(t.value)];
    case "submit":
      // Form-data assembly. Two non-obvious rules:
      //
      // 1. SUBMITTER FILTER. <button type="submit"> and
      //    <input type="submit"> entries appear in form.elements.
      //    Spec: only the SUBMITTER (the button that actually
      //    triggered the submit) contributes its name/value to
      //    the payload — peer submit buttons MUST NOT. Editors
      //    routinely use multiple submit buttons sharing one
      //    name="action" (Save / Format / Check); the naive
      //    "iterate everything" loop lets later buttons clobber
      //    earlier ones, so the LAST button name=action wins
      //    regardless of which the user clicked. Honour
      //    ev.submitter (modern browsers; falls back to
      //    the active element for old Safari).
      //
      // 2. Disabled fields are excluded by the spec — skip them
      //    too so a disabled-but-submittable field doesn't leak
      //    a stale value.
      //
      // The form's own members are read through `__ipeNode`: its named
      // controls shadow them. `data` has no prototype, so a control named
      // `__proto__` is a field like any other.
      var data = Object.create(null);
      var active = __ipeDoc.active();
      var submitter = ev.submitter ||
          (active && t && __ipeNode.contains(t, active) ? active : null);
      var controls = __ipeNode.controls(t);
      if (controls) {
        for (var i = 0; i < controls.length; i++) {
          var el = controls[i];
          if (!el.name || el.disabled) continue;
          if (el.type === "submit" || el.type === "button" ||
              el.type === "image" || el.type === "reset") {
            // Only the submitter button contributes its name/value.
            if (el === submitter) data[el.name] = el.value;
            continue;
          }
          if (el.type === "checkbox" || el.type === "radio") {
            if (el.checked) data[el.name] = el.value;
          } else if (el.type === "file") {
            // File handling via ipe-file / ipe-image drivers (below).
          } else {
            data[el.name] = el.value;
          }
        }
      }
      return [data];
    case "keydown":
    case "keyup":
    case "keypress":
      return [ev.key || ""];
    default:
      return [];
  }
}

// ── File / Image drivers ─────────────────────────────────────
// onFile / onImage register via data-ipe-ev-ipe-file / -ipe-image
// attributes. The client reads the chosen file, optionally resizes
// (for images), and sends a base64 data URL as the event value.
__ipeDoc.on("change", function(ev) {
  var el = ev.target;
  if (!el || el.tagName !== "INPUT" || el.type !== "file") return;
  // The data-attr value is the EVENT NAME (ipe-file / ipe-image); the
  // handler is resolved server-side by (handlerId, event), so the id
  // travels in data-ipe-hid — the same wire shape click/submit use.
  var fileEv  = el.getAttribute("data-ipe-ev-ipe-file");
  var imageEv = el.getAttribute("data-ipe-ev-ipe-image");
  var hid     = el.getAttribute("data-ipe-hid");
  // Read with the id, before the asynchronous read below.
  var epoch   = __ipeEpoch;
  var f = el.files && el.files[0];
  if (!f) return;
  // Client-side size guard via fileMaxSize. Saves the round-trip when
  // the user picks a 100MB file: drop with a console.warn rather than
  // streaming the bytes server-side just to reject them. Server-side
  // validation should still happen — this is a UX nicety, not a
  // security boundary.
  var maxSize = parseInt(el.getAttribute("data-ipe-ev-ipe-file-max-size") || "0");
  if (maxSize > 0 && f.size > maxSize) {
    if (window.console && console.warn) {
      console.warn(
        "[ipe.live] file " + f.name + " (" + f.size +
        " bytes) exceeds fileMaxSize " + maxSize + "; dispatch dropped"
      );
    }
    el.value = "";  // clear the input so the user can pick another
    return;
  }
  if (fileEv) {
    var r = new FileReader();
    // __ipeSend's args param is List a on the wire (server expects
    // []json.RawMessage); a bare string would unmarshal-fail. Wrap
    // the data URL in a single-element array — the Ipe-side Msg
    // constructor declared as 'String -> Msg' reads args[0].
    r.onload = function(e) { __ipeSend(fileEv, [e.target.result], hid, { epoch: epoch }); };
    r.readAsDataURL(f);
  }
  if (imageEv) {
    var maxW = parseInt(el.getAttribute("data-ipe-ev-ipe-file-max-width")  || "1200");
    var maxH = parseInt(el.getAttribute("data-ipe-ev-ipe-file-max-height") || "1200");
    __ipeResizeImage(f, maxW, maxH, function(dataUrl) {
      // Same wire-format reason as the onFile branch — wrap in array.
      __ipeSend(imageEv, [dataUrl], hid, { epoch: epoch });
    });
  }
});

function __ipeResizeImage(file, maxW, maxH, cb) {
  var img = new Image();
  var url = URL.createObjectURL(file);
  img.onload = function() {
    URL.revokeObjectURL(url);
    var w = img.width, h = img.height;
    if (w > maxW) { h = Math.round(h * maxW / w); w = maxW; }
    if (h > maxH) { w = Math.round(w * maxH / h); h = maxH; }
    var canvas = __ipeDoc.create("canvas");
    canvas.width = w; canvas.height = h;
    canvas.getContext("2d").drawImage(img, 0, 0, w, h);
    cb(canvas.toDataURL("image/jpeg", 0.85));
  };
  img.src = url;
}

// Expose programmatic dispatch for custom JS integrations (e.g. Firebase
// auth callbacks that need to send a Msg after the SDK resolves). The
// contract is (handlerId, value, options): a caller targets a specific
// registered handler by id, so the id maps to __ipeSend's handlerId slot
// (not msgName) and value maps to args.
// The caller reads no id from the DOM, so the event carries the epoch current
// at the call.
window.__ipe_send = function(id, value, opts) {
  __ipeSend("", value, id, { noLoader: !!(opts && opts.noLoader), epoch: __ipeEpoch });
};

// Ipe.Ffi.Js inbound port seam. The port glue (window.ipe.send) stringifies
// the developer's value and hands the raw JSON string here; this POSTs it
// to /_ipe/port with the per-session CSRF token. The server authenticates
// by the session cookie, gates the frame fail-closed through the bounded
// seal budget, and delivers it to THIS session's js_subscribe only — never
// another session's. Fire-and-forget: a network failure drops the one
// frame (the port is best-effort, unlike the seq-ordered event path), so
// there is no retry queue here. `raw` is already a JSON string, so it is
// wrapped in a small envelope {payload: raw} the server parses.
window.__ipePortSend = function(raw) {
  if (typeof raw !== "string") return;
  var headers = {"Content-Type":"application/json"};
  if (__ipeCsrfToken) headers["X-Ipe-Csrf"] = __ipeCsrfToken;
  fetch(__ipeBase + "/_ipe/port", {
    method: "POST",
    headers: headers,
    body: JSON.stringify({ payload: raw }),
    credentials: "same-origin"
  }).catch(function() { /* best-effort port send; drop on failure */ });
};

// ipe-nav: intercept clicks on <a ipe-nav ...> links so navigation is a
// client-side fetch + innerHTML swap instead of a full page reload.
// Falls back to normal navigation on modifier keys (cmd/ctrl/shift/alt),
// middle-click, and non-GET targets.
//
// The last document location the client actually rendered. popstate has no
// access to the prior URL, so tracking it here lets the popstate handler
// tell a pure in-page fragment jump from a real path/query change.
var __ipeNavPath   = window.location.pathname;
var __ipeNavSearch = window.location.search;
var __ipeNavHref   = window.location.href;
// The URL to record for a navigation fetch: the canonical URL the server
// redirected it to, or `fallback`. A followed URL is used only when it is
// same-origin and its path begins with exactly one `/`; the original hash is
// kept. Never assigns `location`.
function __ipeFollowed(r, fallback) {
  if (!r.redirected) return fallback;
  try {
    var u = new URL(r.url);
    if (u.origin !== window.location.origin) return fallback;
    if (u.pathname.charAt(0) !== "/" || u.pathname.charAt(1) === "/") return fallback;
    var hash = "";
    try { hash = new URL(fallback, window.location.href).hash; } catch (_) {}
    return u.pathname + u.search + hash;
  } catch (_) { return fallback; }
}
__ipeDoc.on("click", function(ev) {
  if (ev.defaultPrevented) return;
  if (ev.button !== 0) return;
  if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
  var el = ev.target;
  while (el && el.tagName !== "A") el = el.parentElement;
  if (!el) return;
  if (!el.hasAttribute("ipe-nav")) return;
  var href = el.getAttribute("href");
  if (!href || href.charAt(0) === "#") return;
  // External links are left to the browser.
  try {
    var u = new URL(href, window.location.href);
    if (u.origin !== window.location.origin) return;
  } catch (e) { return; }
  ev.preventDefault();
  fetch(href, { headers: { "X-Ipe-Nav": "1" }, credentials: "same-origin" })
    .then(function(r) {
      var url = __ipeFollowed(r, href);
      var epoch = r.headers.get("X-Ipe-Epoch");
      return r.text().then(function(t) { return { t: t, url: url, epoch: epoch }; });
    })
    .then(function(res) {
      __ipeAdoptFullBody(res.epoch, function() { __ipePatch(res.t, "nav"); });
      window.history.pushState({}, "", res.url);
      __ipeNavPath   = window.location.pathname;
      __ipeNavSearch = window.location.search;
      __ipeNavHref   = window.location.href;
    })
    .catch(function() { window.location.href = href; });
});
window.addEventListener("popstate", function() {
  // A pure fragment change (same path + query, only the hash differs) is
  // an in-page anchor jump: let the browser scroll to the target natively.
  // Re-fetching + restoring the pre-jump offset would freeze a smooth
  // in-page scroll mid-animation, so only re-fetch on a path/query change.
  var here = window.location;
  if (here.href === __ipeNavHref) return;
  if (here.pathname === __ipeNavPath && here.search === __ipeNavSearch) {
    __ipeNavHref = here.href;
    return;
  }
  __ipeNavPath = here.pathname;
  __ipeNavSearch = here.search;
  __ipeNavHref = here.href;
  fetch(here.href, { headers: { "X-Ipe-Nav": "1" }, credentials: "same-origin" })
    .then(function(r) {
      if (r.redirected) {
        try { window.history.replaceState({}, "", __ipeFollowed(r, here.href)); } catch (_) {}
        __ipeNavPath   = window.location.pathname;
        __ipeNavSearch = window.location.search;
        __ipeNavHref   = window.location.href;
      }
      var epoch = r.headers.get("X-Ipe-Epoch");
      return r.text().then(function(t) { return { t: t, epoch: epoch }; });
    })
    .then(function(res) {
      __ipeAdoptFullBody(res.epoch, function() { __ipePatch(res.t, "nav"); });
    });
});
// ── Status banner (connection state) ─────────────────────────
// Single bottom-pinned element rendered by the runtime (NOT by the
// user's view) showing connection health. State machine:
//   "connected"      → invisible
//   "reconnecting"   → amber bar, "Reconnecting…" + attempt counter
//   "offline"        → red bar, "Connection lost — refresh to retry"
//   "recompiling"    → amber bar, "Recompiling app", until the next result
//   "build-ok"       → green transient toast, "Updated!", auto-hides
//   "build-failed"   → red sticky bar, persists until next green build
// The two build-* states are dev-only; they are only ever entered via
// an `ipe-build-status` SSE event or the sessionStorage reload flag —
// neither fires in production, so prod emit is byte-identical.
var __ipeStatus = "connected";          // current state
var __ipeStatusEl = null;               // banner root, set on DOMContentLoaded
var __ipeStatusMsgEl = null;            // text node child
var __ipeStatusGraceTimer = null;       // 500ms anti-flicker timer
var __ipeBuildOkTimer = null;           // auto-hide timer for build-ok toast
function __ipeSetStatus(state, msg) {
  // Cancel any pending build-ok auto-hide when switching to a different state.
  if (__ipeBuildOkTimer !== null && state !== "build-ok") {
    clearTimeout(__ipeBuildOkTimer);
    __ipeBuildOkTimer = null;
  }
  __ipeStatus = state;
  if (!__ipeStatusEl) return;           // banner not yet injected
  // Strip the previous state class, add the current one.
  var classes = __ipeStatusEl.className.split(" ").filter(function(c) {
    return c.indexOf("ipe-status--") !== 0;
  });
  classes.push("ipe-status--" + state);
  __ipeStatusEl.className = classes.join(" ");
  if (__ipeStatusMsgEl && msg !== undefined) {
    __ipeStatusMsgEl.textContent = msg;
  }
}

// Show a transient green "Updated!" toast, then revert to connected.
// prefers-reduced-motion: use a slightly longer hold, no fade (opacity
// transition is on the element; we just flip states faster/slower).
function __ipeShowBuildOk() {
  if (!__ipeBannerEnabled) return;
  if (__ipeBuildOkTimer !== null) {
    clearTimeout(__ipeBuildOkTimer);
    __ipeBuildOkTimer = null;
  }
  __ipeSetStatus("build-ok", "Updated!");
  var reducedMotion = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var holdMs = reducedMotion ? 2000 : 1500;
  __ipeBuildOkTimer = setTimeout(function() {
    __ipeBuildOkTimer = null;
    __ipeSetStatus("connected", "");
  }, holdMs);
}
function __ipeInjectStatusBanner() {
  if (__ipeStatusEl) return;            // idempotent
  if (!__ipeBannerEnabled) return;      // IPE_WEB_BANNER=off
  var built = __ipeBuildStatusEl("connected");
  __ipeDoc.body().appendChild(built.el);
  __ipeStatusEl = built.el;
  __ipeStatusMsgEl = built.msgEl;
  // Replay current state in case it changed before DOM was ready.
  __ipeSetStatus(__ipeStatus, "");
}
// Show the offline banner for a page whose boot data was refused. It runs
// before any config is known, so it ignores the banner setting: a page that
// cannot start always says so. It runs at most once (the refusal throws), so it
// never looks for an existing banner: page content can carry the banner's id.
function __ipeShowBootFailure() {
  function show() {
    var built = __ipeBuildStatusEl("offline");
    built.msgEl.textContent = "Page failed to start — reload to retry";
    (__ipeDoc.body() || __ipeDoc.root()).appendChild(built.el);
  }
  if (__ipeDoc.body()) show();
  else __ipeDoc.on("DOMContentLoaded", show);
}
// The `#__ipe-status` banner element in `state`, with its message span. Its
// state colours are the page shell's `STATUS_CSS` rules, so the client
// creates no `<style>` element.
function __ipeBuildStatusEl(state) {
  var el = __ipeDoc.create("div");
  el.id = "__ipe-status";
  el.className = "ipe-status ipe-status--" + state;
  el.setAttribute("role", "status");
  el.setAttribute("aria-live", "polite");
  // Inline styles — no global stylesheet leak. Max z-index puts the
  // banner above any user fixed-position element. Fixed position
  // bottom-center; transitions for fade in/out feel less jarring.
  el.style.cssText = [
    "position:fixed",
    "left:50%",
    "bottom:16px",
    "transform:translateX(-50%)",
    "padding:8px 16px",
    "border-radius:6px",
    "font:13px/1.4 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
    "color:#fff",
    "box-shadow:0 2px 8px rgba(0,0,0,0.25)",
    "z-index:2147483647",
    "pointer-events:none",            // never intercept clicks
    "transition:opacity 200ms",
    "opacity:1"
  ].join(";");
  var msgEl = __ipeDoc.create("span");
  msgEl.className = "ipe-status__msg";
  el.appendChild(msgEl);
  return { el: el, msgEl: msgEl };
}
// ── Swap toast (dev blue-green cutover cue) ──────────────────
// A brief, positive, non-blocking toast shown when the `ipe dev watch` blue-green
// proxy has cut a rebuild over. It replaces the amber "Reconnecting…" banner
// for the expected dev-rebuild case: appears, then auto-dismisses (~1.5s). It
// is a SEPARATE element from the connection-status banner (which stays for a
// genuine outage). Dev-only — never fires unless __ipeSwapToast is set, which a
// release / `ipe dev run` server leaves false. aria-live polite for screen readers.
var __ipeSwapToastEl = null;
var __ipeSwapToastTimer = null;
function __ipeShowSwapToast() {
  if (!__ipeBannerEnabled) return;
  if (!__ipeDoc.body()) return;
  var el = __ipeSwapToastEl;
  if (!el) {
    el = __ipeDoc.create("div");
    el.id = "__ipe-swap-toast";
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
    el.style.cssText = [
      "position:fixed",
      "left:50%",
      "bottom:16px",
      "transform:translateX(-50%)",
      "padding:8px 16px",
      "border-radius:6px",
      "font:13px/1.4 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
      "color:#fff",
      "background:#15803d",              // green — a positive cue
      "box-shadow:0 2px 8px rgba(0,0,0,0.25)",
      "z-index:2147483647",
      "pointer-events:none",            // never intercept clicks
      "transition:opacity 200ms",
      "opacity:0"
    ].join(";");
    __ipeDoc.body().appendChild(el);
    __ipeSwapToastEl = el;
  }
  el.textContent = __ipeMsgUpdated;
  // Force a style flush so the opacity transition runs on re-show.
  el.style.opacity = "0";
  void el.offsetWidth;
  el.style.opacity = "1";
  if (__ipeSwapToastTimer !== null) clearTimeout(__ipeSwapToastTimer);
  __ipeSwapToastTimer = setTimeout(function() {
    __ipeSwapToastTimer = null;
    if (__ipeSwapToastEl) __ipeSwapToastEl.style.opacity = "0";
  }, 1500);
}

// ── Server-Sent Events ───────────────────────────────────────
// Frame envelope since v0.9.3+: {seq, body, ackInputs?}. Falls back to
// treating e.data as a raw HTML body when JSON parsing fails, so a
// mixed-version rollout doesn't break the open-SSE connection.
//
// Reverse-proxy hardening: the browser's EventSource has no
// application-level liveness check — if a misbehaving proxy holds the
// socket open with no body or rewrites an upstream 502 to 200 with a
// non-SSE HTML payload, EventSource will fire 'open' and never fire
// 'error', leaving the client silently wedged. The server now sends
// an immediate 'hello' event and a periodic 'heartbeat'; the client
// watchdog (below) treats absence of either as a wedge and force-
// reconnects with backoff. See docs/internals/web/architecture.md
// §SSE wedge detection.
var __ipeSSE = null;
var __ipeOpenAt = 0;          // ms timestamp of last EventSource.open
var __ipeLastSseAt = 0;       // ms timestamp of any SSE event
var __ipeHelloOk = false;     // server sent its handshake this connection
var __ipeWatchdogTimer = null;
var __ipeSseReopenTimer = null;
var __ipeForcedClose = false; // true while we're tearing down to reopen
// data-ipe-live on <html> is the app's deterministic readiness signal: "1"
// exactly while the SSE handshake is live, "0" otherwise. The server binds
// this session's outbound Ipe.Ffi.Js port sink to the SSE connection (an
// unbound sink drops frames fire-and-forget), so a Cmd that rides the port —
// Geo.current, Clipboard.read — only round-trips once the handshake has
// landed. A driver (test, health check) that waits for data-ipe-live="1"
// before dispatching such a Cmd observes a bound sink, never a dropped frame.
function __ipeSetLive(on) {
  try { __ipeDoc.root().setAttribute("data-ipe-live", on ? "1" : "0"); } catch (_) {}
}
__ipeSetLive(false);
function __ipeOpenSSE() {
  __ipeSetLive(false);
  __ipeForcedClose = false;
  __ipeHelloOk = false;
  __ipeOpenAt = 0;
  // Carry the tab's current path on every (re)open so the server can reconcile
  // the model's route with the URL the browser is actually showing (bfcache
  // Back/Forward, reload, full-page navigation). Re-read location.pathname here
  // (not at module load) so a bfcache restore — which sets a new pathname before
  // reopening the SSE — sends the restored page's path, not the previous one.
  var ssePath = __ipeBase + "/_ipe/sse?path=" + encodeURIComponent(location.pathname);
  __ipeSSE = new EventSource(ssePath);
  __ipeSSE.addEventListener("hello", function(e) {
    // Handshake received — we know we hit a real Ipe.Web v2 server,
    // not a proxy that intercepted with a generic 200. Anything
    // before hello is suspect, so the connected-state flip happens
    // HERE, not on EventSource.open. Remember that THIS page's
    // server speaks v2 so future watchdog cycles can tighten the
    // wedge-detection threshold to the fast 8s hello timeout.
    __ipeServerSpeaksV2 = true;
    __ipeHelloOk = true;
    __ipeSetLive(true);
    __ipeLastSseAt = Date.now();
    if (__ipeStatusGraceTimer !== null) {
      clearTimeout(__ipeStatusGraceTimer);
      __ipeStatusGraceTimer = null;
    }
    // Dev blue-green: a `hello` after a prior one is a rebuild cutover. Greet it
    // with the positive toast rather than leaving the amber banner up. Guarded
    // on __ipeSwapToast, so a production reconnect keeps the ordinary chrome.
    if (__ipeSwapToast && __ipeHelloEverOk) __ipeShowSwapToast();
    __ipeHelloEverOk = true;
    if (__ipeStatus !== "connected") {
      __ipeSetStatus("connected", "");
    }
    __ipeRetryAttempts = 0;
    __ipeReconnectSince = 0;
    if (__ipeRetryTimer !== null) {
      clearTimeout(__ipeRetryTimer);
      __ipeRetryTimer = null;
    }
    if (__ipeEventQueue.length > 0) __ipeDrainQueue();
  });
  __ipeSSE.addEventListener("heartbeat", function(e) {
    __ipeLastSseAt = Date.now();
  });
  __ipeSSE.addEventListener("patch", function(e) {
    __ipeLastSseAt = Date.now();
    // Old servers (pre-handshake) only ever send "patch" events.
    // A real patch is itself proof we're talking to a Ipe.Web server,
    // not a proxy-rewritten 200-OK, so treat first-patch-without-hello
    // as an implicit handshake. This keeps a new client from trapping
    // itself when a rolling deploy puts it in front of an old server.
    if (!__ipeHelloOk) {
      __ipeHelloOk = true;
      __ipeSetLive(true);
      if (__ipeStatusGraceTimer !== null) {
        clearTimeout(__ipeStatusGraceTimer);
        __ipeStatusGraceTimer = null;
      }
      if (__ipeStatus !== "connected") {
        __ipeSetStatus("connected", "");
      }
      __ipeRetryAttempts = 0;
      __ipeReconnectSince = 0;
      if (__ipeRetryTimer !== null) {
        clearTimeout(__ipeRetryTimer);
        __ipeRetryTimer = null;
      }
    }
    var frame;
    try { frame = JSON.parse(e.data); } catch (_) {
      // Legacy frame (pre-v0.9.3 server) — raw HTML, no seq to gate on.
      // Open-<select> defence: an SSE-pushed full-body re-render during an
      // open dropdown would collapse it, so the body is held until the
      // select closes. Active user paths (ipe-nav, popstate, POST text
      // fallback) are NOT defended — those are user-initiated and holding
      // them would be worse UX than the dropdown collapsing.
      var raw = e.data.replace(/\\n/g, "\n");
      if (__ipeSelectOpen()) {
        __ipeHoldRender(function() { __ipePatch(raw); });
        return;
      }
      __ipeHeldRender = null;
      return __ipePatch(raw);
    }
    if (frame && typeof frame === "object") {
      __ipeHandleResponse(frame.seq, frame.ackInputs, function() {
        if (!frame.body) return;
        var body = frame.body.replace(/\\n/g, "\n");
        var apply = function() {
          __ipeAdoptFullBody(frame.epoch, function() { __ipePatch(body); });
        };
        if (__ipeSelectOpen()) __ipeHoldRender(apply);
        else {
          // This render supersedes any held one and any patches it missed.
          __ipeHeldRender = null;
          apply();
        }
      }, frame.globalSeq);
    }
  });
  // Cycle 3 P50b / Gap C11 — structural-patches SSE event.
  //
  // The producer (Cycle 3 P50a) now ships event:patches for any
  // render whose diff against the previous tree fits in a small
  // patch list (the typical 1-3 attribute/text node change at
  // ~200-1000 B, vs the ~14 KB full body). The legacy event:patch
  // handler above stays for first-renders, reconnect-resync,
  // full-replace fallbacks, and any pre-P50a server.
  //
  // Shape parity with the HTTP /_ipe/event reply: frame is
  // {seq, ackInputs, patches} — identical to writeEventJSON's
  // envelope, so __ipeApplyPatches consumes both routes without
  // divergence. seq-gating via __ipeHandleResponse means out-of-
  // order frames (a stale patches frame arriving after a fresher
  // patch frame, e.g. across a brief network blip) are dropped at
  // the same monotonic guard the HTTP path uses.
  //
  // A frame that applies goes through __ipeApplyPatches, whose per-patch
  // focus-restore + open-select skip is the canonical defence. A frame that
  // cannot apply while a <select> is open marks the held render stale rather
  // than resyncing, since the resync's first frame would only be held again.
  // Focus / input-authority / dirty-input filtering all flow through
  // the same code path as the HTTP-side patches application, so
  // in-flight typing is preserved without server-side clientState
  // alignment (the SSE producer passes nil clientState to diffTrees;
  // the client's __ipeIsDirty filter takes over).
  __ipeSSE.addEventListener("patches", function(e) {
    __ipeLastSseAt = Date.now();
    // Same implicit-handshake defence as the legacy patch listener:
    // a real patches frame proves we're talking to a Ipe.Web server,
    // so unstick the hello check even if the dedicated 'hello' event
    // got eaten by a misbehaving proxy.
    if (!__ipeHelloOk) {
      __ipeHelloOk = true;
      __ipeSetLive(true);
      if (__ipeStatusGraceTimer !== null) {
        clearTimeout(__ipeStatusGraceTimer);
        __ipeStatusGraceTimer = null;
      }
      if (__ipeStatus !== "connected") {
        __ipeSetStatus("connected", "");
      }
      __ipeRetryAttempts = 0;
      __ipeReconnectSince = 0;
      if (__ipeRetryTimer !== null) {
        clearTimeout(__ipeRetryTimer);
        __ipeRetryTimer = null;
      }
    }
    var frame;
    try { frame = JSON.parse(e.data); }
    catch (_) {
      // Producer guarantees JSON for event:patches; a non-JSON
      // payload is impossible from a P50a+ server. Drop silently
      // rather than running __ipePatch on garbage.
      return;
    }
    if (!frame || typeof frame !== "object" || !frame.patches) return;
    // The patches diff the render `from` against `to`: they apply only onto
    // the DOM of `from`. Any other DOM resyncs through a fresh SSE open, whose
    // first frame is the full current render.
    if (typeof frame.from === "string" && frame.from !== __ipeEpoch) {
      if (__ipeSelectOpen()) __ipeMarkHeldStale();
      else {
        __ipeHeldRender = null;
        __ipeResyncRender();
      }
      return;
    }
    __ipeHandleResponse(frame.seq, frame.ackInputs, function() {
      __ipeApplyPatches(frame.patches);
      if (typeof frame.to === "string") __ipeEpoch = frame.to;
    }, frame.globalSeq);
  });
  // Ipe.Ffi.Js outbound port frame: the server's js_send delivers the seal
  // wire string (a JSON string) for THIS session over its own SSE
  // stream. Hand it to the port glue's receiver (window.ipeOnReceive),
  // which parses it as data (never eval) and calls the page's
  // ipe.onReceive/onSync handler. A frame that arrives before the glue
  // has wired a receiver is a no-op (deliver checks typeof).
  __ipeSSE.addEventListener("port", function(e) {
    __ipeLastSseAt = Date.now();
    if (typeof window.ipeOnReceive === "function") {
      window.ipeOnReceive(e.data);
    }
  });
  // Dev-watch blue-green cutover cue. The watch server sends this right after
  // `hello` on every open when running behind the proxy. It is redundant with
  // the hello-based reconnect detection above (kept as an explicit, named
  // signal), so it is likewise gated on a PRIOR hello — the first-load frame
  // draws nothing. Never emitted by a release / `ipe dev run` server.
  __ipeSSE.addEventListener("swapped", function() {
    __ipeLastSseAt = Date.now();
    if (__ipeSwapToast && __ipeHelloEverOk) __ipeShowSwapToast();
  });
  __ipeSSE.addEventListener("open", function() {
    // EventSource fired open — but we don't trust this alone, since a
    // proxy can rewrite a non-SSE 200 OK into something that fires
    // open without ever delivering a frame. Wait for 'hello' to flip
    // to connected. Just record the open timestamp so the watchdog
    // can measure "how long have we been open without a hello".
    __ipeOpenAt = Date.now();
    __ipeLastSseAt = Date.now();
  });
  __ipeSSE.addEventListener("error", function() {
    // Suppress the banner when we triggered the close ourselves
    // (force-reopen path) — those errors are an artefact of our own
    // teardown, not a real outage signal.
    if (__ipeForcedClose) return;
    // CLOSED (2) means the browser failed the connection permanently.
    // Per the EventSource spec, this happens for any non-200 HTTP
    // response (Caddy/Nginx 502 when upstream is down, 504 timeout,
    // 503 service unavailable) AND for the wrong Content-Type. The
    // browser will NOT retry on its own — we have to drive the
    // reconnect ourselves. Without this branch the whole reconnect
    // story collapses behind a reverse proxy that returns proper
    // 5xx codes during outages.
    if (__ipeSSE && __ipeSSE.readyState === 2) {
      __ipeForceReopenSSE();
      return;
    }
    // CONNECTING (0): browser is auto-retrying (network blip, no HTTP
    // response received yet). Show the banner only if the situation
    // persists past the grace window — a quick error+reopen burst
    // shouldn't paint chrome.
    if (__ipeStatus !== "connected") return;
    if (__ipeStatusGraceTimer !== null) return;
    __ipeStatusGraceTimer = setTimeout(function() {
      __ipeStatusGraceTimer = null;
      if (__ipeSSE && __ipeSSE.readyState === 1 && __ipeHelloOk) return;
      // Dev blue-green: suppress the amber banner while still inside the
      // fast-reconnect window — a rebuild cutover reconnects within it and the
      // "updated ✓" toast takes over. A drop that outlasts the window is a real
      // outage and still paints the banner.
      if (__ipeSwapToast && __ipeInFastReconnect()) return;
      __ipeSetStatus("reconnecting", __ipeMsgReconnecting);
    }, 500);
  });
  // Dev-only build-status event: server pushes this when `ipe dev watch`
  // reports a compile or cargo failure, and when a subsequent build
  // succeeds. Only reachable when `ipe dev watch` is running; never
  // triggered in production (the POST endpoint is not mounted there).
  __ipeSSE.addEventListener("ipe-build-status", function(e) {
    var data;
    try { data = JSON.parse(e.data); } catch(_) { return; }
    if (!data) return;
    if (data.phase === "recompiling") {
      // A rebuild is in flight — a multi-second silent window otherwise. Show a
      // soft-yellow "Recompiling app" banner until the ok/error result lands.
      if (__ipeBannerEnabled) __ipeSetStatus("recompiling", "Recompiling app");
    } else if (data.ok === false && typeof data.error === "string") {
      __ipeSetStatus("build-failed", "Recompilation failed \xB7 " + data.error);
    } else if (data.ok === true) {
      // A successful rebuild or an appearance hot-swap that recovers from a prior
      // failure: show the green "Updated!" toast to confirm the change landed. A
      // full-rebuild reload may also use the sessionStorage path when the page
      // reloads before this event lands.
      __ipeShowBuildOk();
    }
  });
}

// __ipeForceReopenSSE — close the current EventSource and queue a
// fresh open with backoff. Each call bumps the retry counter; once
// it exceeds __ipeRetryMaxAttempts the banner flips to "offline" but
// reconnect attempts CONTINUE in the background at the max delay so
// a healed proxy is picked up automatically (otherwise the user is
// permanently stuck unless they click something or refresh, which is
// surprising on push-driven UIs like dashboards or chat). Backoff
// matches the POST retry schedule so the user doesn't see two
// independent timers.
// __ipeResyncRender — the DOM on screen is not the render a patches frame was
// diffed from. Reopen the stream at once: its first frame is the full current
// render with its epoch.
function __ipeResyncRender() {
  __ipeForcedClose = true;
  try { if (__ipeSSE) __ipeSSE.close(); } catch (_) {}
  __ipeSSE = null;
  if (__ipeSseReopenTimer !== null) {
    clearTimeout(__ipeSseReopenTimer);
    __ipeSseReopenTimer = null;
  }
  __ipeOpenSSE();
}
function __ipeForceReopenSSE() {
  __ipeForcedClose = true;
  __ipeSetLive(false);
  try { if (__ipeSSE) __ipeSSE.close(); } catch (_) {}
  __ipeSSE = null;
  if (__ipeStatus === "connected") {
    __ipeSetStatus("reconnecting", __ipeMsgReconnecting);
  }
  // Session-loss probe: when the SSE is wedged (typically a server
  // restart with the memory store, or a package.ipe [live] store change
  // wiping the persistent session), no amount of reopen retries can
  // recover the lost session — the only path forward is a full page
  // reload, which fires handleInitial and creates a fresh session.
  // We probe with a fake POST: a 404 + X-Ipe-Web: 1 + body
  // containing "session not found" is the unambiguous signal that the
  // server is up but doesn't know our cookie. Anything else (network
  // error, 5xx, healthy 200) keeps the normal retry path engaged so
  // we don't reload on a transient blip — full reload destroys
  // uncontrolled-input state that v0.11.7's preservation rules can't
  // bring back.
  __ipeProbeSessionLost();
  if (__ipeSseReopenTimer !== null) {
    clearTimeout(__ipeSseReopenTimer);
  }
  var delay;
  if (__ipeInFastReconnect()) {
    delay = __ipeJitter(__ipeRetryFastMs);  // fast phase — not counted toward give-up
  } else {
    __ipeRetryAttempts++;
    if (__ipeRetryAttempts >= __ipeRetryMaxAttempts && __ipeStatus !== "offline") {
      __ipeSetStatus("offline", __ipeMsgOffline);
    }
    delay = __ipeExpBackoffDelay();
  }
  __ipeSseReopenTimer = setTimeout(function() {
    __ipeSseReopenTimer = null;
    __ipeOpenSSE();
  }, delay);
}

// __ipeProbeSessionLost — fire-and-forget POST whose only purpose is
// to read the server's reaction to our existing ipe_sid cookie. If
// the server is up AND has lost our session (memory-store restart,
// store-kind change, session TTL expiry), we get a 404 with the
// X-Ipe-Web marker and a "session not found" body. That's the cue
// to hard-reload — every reopen attempt would otherwise loop on the
// same 404 forever.
//
// Must NOT trigger any user-visible side effects on the server. We
// send a Msg name that no real app registers and supply no
// handlerId, so handleEvent's code path goes:
//   session not found → 404 (the case we're probing for)
//   session found, handler not found → 404 with a different body
//   (we explicitly check the body string to avoid false positives).
var __ipeProbedReload = false;  // one-shot guard so we don't trigger
                                // multiple reloads from a burst of
                                // failed reopen attempts.
function __ipeProbeSessionLost() {
  if (__ipeProbedReload) return;
  var headers = {"Content-Type": "application/json"};
  if (__ipeCsrfToken) headers["X-Ipe-Csrf"] = __ipeCsrfToken;
  fetch(__ipeBase + "/_ipe/event", {
    method: "POST",
    headers: headers,
    body: JSON.stringify({sessionId: __ipeSid, msg: "__ipeSessionPing", args: []}),
    credentials: "same-origin"
  }).then(function(r) {
    if (r.status !== 404) return;
    if (r.headers.get("X-Ipe-Web") !== "1") return;
    return r.text().then(function(body) {
      // Specifically "session not found" — distinguishes from
      // "handler not found" (which means the session is fine, just
      // our probe Msg name doesn't exist; that's expected and
      // doesn't warrant a reload).
      if (body.indexOf("session not found") < 0) return;
      __ipeProbedReload = true;
      if (window.console && console.warn) {
        console.warn("[ipe.live] server lost our session — reloading page to recover");
      }
      // Signal the freshly-loaded page to show the build-ok toast.
      try { sessionStorage.setItem("__ipe_reloaded", "1"); } catch(_) {}
      window.location.reload();
    });
  }).catch(function() {
    // Network error / server down. Keep retrying via normal path.
  });
}

// __ipeWatchdog — runs every 5s. Two wedge detectors layered:
//   1. Connection has been quiet for longer than __ipeHeartbeatTtlMs
//      (35s default). Catches every wedge shape — a proxy holding
//      the socket open with no body, an upstream 502 rewritten to
//      200 + HTML, mid-stream TCP stalls. The 35s threshold is
//      tuned to be just over 2× the server's 15s heartbeat; if the
//      server is new we miss at most one heartbeat before reacting.
//   2. Faster handshake check: once this PAGE has confirmed the
//      server speaks the v2 protocol (any session received a hello),
//      tighten the threshold to __ipeHelloTimeoutMs (8s) on every
//      subsequent connection. Pre-v2 servers stay on the slower
//      heartbeat-ttl path so a rolling deploy doesn't wedge new
//      clients hitting old pods. The page-scoped flag survives SSE
//      teardowns + reopens within the same tab.
// Both paths increment the retry counter via __ipeForceReopenSSE,
// so a wedge that persists reaches "offline" instead of looping
// forever — but reopen attempts continue at the max delay so a
// healed proxy reconnects automatically without a refresh.
var __ipeServerSpeaksV2 = false;
function __ipeWatchdog() {
  __ipeReleaseHeldRender(false);
  // If we have no live EventSource AND no reopen scheduled, the
  // 'error' handler must have missed (rare race) or some path tore
  // it down without re-arming. Drive the reopen here so the page
  // never gets permanently disconnected.
  if (!__ipeSSE && __ipeSseReopenTimer === null) {
    __ipeForceReopenSSE();
    return;
  }
  if (!__ipeSSE) return;
  // CLOSED (2): browser failed the connection (non-200, wrong CT)
  // and won't retry. The 'error' handler should have caught this,
  // but cover the case where it didn't fire (e.g. error during
  // initial handshake before listeners attached, or a browser
  // implementation quirk). Single source of truth — both paths end
  // in __ipeForceReopenSSE.
  if (__ipeSSE.readyState === 2) {
    if (!__ipeForcedClose) {
      __ipeForceReopenSSE();
    }
    return;
  }
  if (__ipeSSE.readyState !== 1) return;  // CONNECTING (0): browser is retrying, leave it
  var now = Date.now();
  // Effective threshold:
  //   - Brand-new SSE on a v2-confirmed server → fast hello timeout
  //     (8s) since we expect a hello promptly.
  //   - Otherwise → conservative heartbeat ttl (35s) so old servers
  //     and idle dashboards don't false-positive.
  var quietMs = now - __ipeLastSseAt;
  var threshold = __ipeHeartbeatTtlMs;
  if (__ipeServerSpeaksV2 && !__ipeHelloOk) {
    threshold = __ipeHelloTimeoutMs;
  }
  if (quietMs > threshold) {
    if (window.console && console.warn) {
      console.warn("[ipe.live] SSE quiet for " + quietMs +
        "ms (threshold " + threshold + "ms) — reopening");
    }
    __ipeForceReopenSSE();
  }
}

// Kick off the SSE connection + watchdog. Watchdog interval is short
// enough (5s) that a wedge is detected within 5s + helloTimeout / ttl
// of the actual fault, and long enough to not be a measurable CPU cost.
__ipeOpenSSE();
__ipeWatchdogTimer = setInterval(__ipeWatchdog, 5000);

// On tab visibility change, re-evaluate immediately — when a tab
// resumes from background the OS may have torn down the underlying
// TCP, but EventSource sometimes lags in detecting it. Eager check
// avoids the user staring at a stale UI for the full watchdog cycle.
__ipeDoc.on("visibilitychange", function() {
  if (__ipeDoc.visibility() === "visible") {
    __ipeWatchdog();
  }
});

// ── Init ─────────────────────────────────────────────────────
// Bind initial DOM event listeners + inject the status banner once
// the HTML is parsed. Banner needs the body to exist, so it
// goes through the same gate as event binding.
function __ipeInit() {
  __ipeBindEvents();
  __ipeInjectStatusBanner();
  // After a dev-mode session-recovery reload, show the green build-ok toast.
  try {
    if (sessionStorage.getItem("__ipe_reloaded") === "1") {
      sessionStorage.removeItem("__ipe_reloaded");
      __ipeShowBuildOk();
    }
  } catch(_) {}
}
if (__ipeDoc.readyState() === "loading") {
  __ipeDoc.on("DOMContentLoaded", __ipeInit);
} else {
  __ipeInit();
}
