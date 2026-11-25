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
// The HTML namespace.
var __IPE_HTML_NS = "http://www.w3.org/1999/xhtml";
// The document members the client reads, bound from the prototypes before any
// page content is consulted. A document's named properties (an `img`, `form`,
// `embed`, `object` or `iframe` with that `name`) shadow its built-in members
// with the element, so no read whose answer must come from the browser resolves
// through the document object's own lookup: `<img name="currentScript">` would
// hand the client the app's sibling, `<form name="body">` the app's form.
var __ipeDoc = (function(doc) {
  function prop(name) { return function() { return __ipeDocProp(doc, name); }; }
  // A method the browser lacks refuses every call: boot never stops on it.
  function method(proto, name) {
    var fn = proto[name];
    if (typeof fn !== "function") {
      return function() { throw new TypeError("Ipe client: browser member unavailable"); };
    }
    return fn.bind(doc);
  }
  return {
    script: prop("currentScript"),
    body: prop("body"),
    root: prop("documentElement"),
    active: prop("activeElement"),
    visibility: prop("visibilityState"),
    hasFocus: method(Document.prototype, "hasFocus"),
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
// The frame tables of the runtime (`html.rs` `SANDBOX_TOKENS`,
// `TRUSTED_SANDBOX_TOKENS`, `FRAME_LOADERS` and `FRAME_PERMISSIONS`, and
// `frames.rs` `DELEGATION_FEATURES` as `[name, class, grant suffixes]`); a
// native test asserts this copy equals them. A framed document gets more than
// an opaque origin only when its one loading URL starts with a listed origin
// that is not the page's own: an untrusted `iframe` holds only the
// `__IPE_SANDBOX_TOKENS`, `allow-same-origin` never among them, and no
// permission attribute; an untrusted `embed`, `object` or `frame` never holds
// the attribute it loads a document from.
var __IPE_SANDBOX_TOKENS = ["allow-downloads", "allow-forms", "allow-modals", "allow-orientation-lock", "allow-pointer-lock", "allow-popups", "allow-presentation", "allow-scripts", "allow-storage-access-by-user-activation", "allow-top-navigation", "allow-top-navigation-by-user-activation", "allow-top-navigation-to-custom-protocols"];
var __IPE_FRAME_LOADERS = [["embed", "src"], ["object", "data"], ["frame", "src"]];
var __IPE_TRUSTED_SANDBOX_TOKENS = ["allow-downloads", "allow-forms", "allow-modals", "allow-orientation-lock", "allow-pointer-lock", "allow-popups", "allow-popups-to-escape-sandbox", "allow-presentation", "allow-same-origin", "allow-scripts", "allow-storage-access-by-user-activation", "allow-top-navigation", "allow-top-navigation-by-user-activation", "allow-top-navigation-to-custom-protocols"];
var __IPE_FRAME_PERMISSIONS = ["allow", "allowfullscreen", "allowpaymentrequest", "allowusermedia"];
var __IPE_DELEGATION_FEATURES = [["accelerometer", "undisclosed", []], ["ambient-light-sensor", "undisclosed", []], ["autoplay", "plain", []], ["bluetooth", "undisclosed", []], ["camera", "gated", ["camera", "recorder"]], ["clipboard-read", "undisclosed", []], ["clipboard-write", "plain", []], ["compute-pressure", "undisclosed", []], ["display-capture", "undisclosed", []], ["encrypted-media", "plain", []], ["fullscreen", "plain", []], ["gamepad", "plain", []], ["geolocation", "gated", ["geolocation"]], ["gyroscope", "undisclosed", []], ["hid", "undisclosed", []], ["identity-credentials-get", "undisclosed", []], ["idle-detection", "undisclosed", []], ["local-fonts", "undisclosed", []], ["magnetometer", "undisclosed", []], ["microphone", "gated", ["microphone", "recorder"]], ["midi", "undisclosed", []], ["otp-credentials", "undisclosed", []], ["payment", "never", []], ["picture-in-picture", "plain", []], ["publickey-credentials-create", "undisclosed", []], ["publickey-credentials-get", "undisclosed", []], ["screen-wake-lock", "plain", []], ["serial", "undisclosed", []], ["storage-access", "undisclosed", []], ["usb", "undisclosed", []], ["web-share", "plain", []], ["window-management", "undisclosed", []], ["xr-spatial-tracking", "undisclosed", []]];
// The node keep's field tables (`dom/keep.rs` `FIELD_TAGS`, `AUTHORITY_ATTRS`
// and `CONTROLLED_ATTR`); a native test asserts this copy equals them. A
// field is a form element whose value the user edits, an authority attribute
// carries that value, and the render sink writes the marker on every field
// whose view owns its value, so an unticked box or an empty field the view
// set is still the view's.
var __IPE_FIELD_TAGS = ["input", "textarea", "select"];
var __IPE_AUTHORITY_ATTRS = ["value", "checked", "selected"];
var __IPE_CONTROLLED_ATTR = "ipe-controlled";
// `s` with its ASCII letters lowercased and every other character kept, as
// the runtime compares tags, keys and tokens.
function __ipeAsciiLower(s) {
  return String(s).replace(/[A-Z]+/g, function(m) { return m.toLowerCase(); });
}
// Whether the element `el` is one of `__IPE_FIELD_TAGS`.
function __ipeIsField(el) {
  return !!el && el.nodeType === 1 &&
      __IPE_FIELD_TAGS.indexOf(__ipeAsciiLower(__ipeNode.tag(el))) !== -1;
}
// Whether the attribute name `n` is one of `__IPE_AUTHORITY_ATTRS`, ASCII
// case folded.
function __ipeIsAuthorityAttr(n) {
  return __IPE_AUTHORITY_ATTRS.indexOf(__ipeAsciiLower(n)) !== -1;
}
// The canonical sandbox of the `sandbox` value `v` (null when absent): the
// known tokens it holds, split on ASCII whitespace, once each in table order.
function __ipeSandbox(v) {
  var held = typeof v === "string" ? v.split(/[\t\n\f\r ]+/).map(__ipeAsciiLower) : [];
  return __IPE_SANDBOX_TOKENS.filter(function(t) { return held.indexOf(t) !== -1; }).join(" ");
}
// The attribute the frame loader `tag` loads its document from; null for
// every other tag.
function __ipeFrameLoaderKey(tag) {
  var name = __ipeAsciiLower(tag);
  for (var i = 0; i < __IPE_FRAME_LOADERS.length; i++) {
    if (__IPE_FRAME_LOADERS[i][0] === name) return __IPE_FRAME_LOADERS[i][1];
  }
  return null;
}
// The boot block's frame list `key` (written origins or granted suffixes);
// empty when the page has no boot block or lists none.
function __ipeFrameList(key) {
  var boot = typeof __ipeBoot === "object" && __ipeBoot !== null ? __ipeBoot : null;
  return boot && Array.isArray(boot[key]) ? boot[key] : [];
}
// Whether a trusted frame's popups may leave its sandbox: the server holds
// them, and this page is the top-level document its opener policy binds.
function __ipeEscapePopups() {
  var boot = typeof __ipeBoot === "object" && __ipeBoot !== null ? __ipeBoot : null;
  return !!boot && boot["escapePopups"] === true && window.top === window.self;
}
// The listed origin `url` loads from, by its exact characters: no character
// at or below U+0020, no U+007F and no `\`, then a listed origin followed by
// the end, `/`, `?` or `#`. Null when it names none.
function __ipeListedOrigin(url) {
  if (typeof url !== "string" || /[\x00-\x20\x7f\\]/.test(url)) return null;
  var list = __ipeFrameList("frameOrigins");
  for (var i = 0; i < list.length; i++) {
    var o = list[i];
    if (typeof o === "string" && o !== "" && url.indexOf(o) === 0) {
      var next = url.charAt(o.length);
      if (next === "" || next === "/" || next === "?" || next === "#") return o;
    }
  }
  return null;
}
// Whether the listed `origin` may be the page's own on a page at `pageHost`
// (`location.host`), so its frame is untrusted (`frames.rs` `served_on`): an
// `https` origin on the page's host at any port, an `https` loopback-name
// origin (last label `localhost`) on any loopback-name page, a loopback
// `http` origin on a loopback-name page at its port, and every origin when the
// host does not read as `Authority::parse` reads one (labels of at most 63
// bytes with no edge `-`, at most 253 bytes, a port in `1..=65535` with no
// leading zero). An IP-literal page host is never a listed origin's.
function __ipeServedOn(origin, pageHost) {
  if (typeof pageHost !== "string") return true;
  if (pageHost.charAt(0) === "[") return false;
  var page = /^([a-z0-9-]+(?:\.[a-z0-9-]+)*)(?::([1-9][0-9]{0,4}))?$/.exec(__ipeAsciiLower(pageHost));
  var o = /^(https?):\/\/([a-z0-9.-]+)(?::([0-9]+))?$/.exec(origin);
  if (!page || !o || page[1].length > 253 || +page[2] > 65535) return true;
  var odd = function(l) { return l.length > 63 || l.charAt(0) === "-" || l.charAt(l.length - 1) === "-"; };
  if (page[1].split(".").some(odd)) return true;
  var loopback = function(name) { return /(^|\.)localhost$/.test(name); };
  if (o[1] === "https") return o[2] === page[1] || (loopback(o[2]) && loopback(page[1]));
  return loopback(page[1]) && o[3] === page[2];
}
// The listed origin a frame element `tag` whose attribute reader is `get`
// (a value, or null when absent) loads from, on a page at `pageHost`; null
// when the frame is untrusted. A `frame`, an `iframe` with a `srcdoc`, and an
// origin that is the page's own are never trusted.
function __ipeFrameTarget(tag, get, pageHost) {
  var name = __ipeAsciiLower(tag);
  var loads = name === "iframe" ? "src" : name === "frame" ? null : __ipeFrameLoaderKey(name);
  if (loads === null) return null;
  if (name === "iframe" && get("srcdoc") !== null) return null;
  var origin = __ipeListedOrigin(get(loads));
  return origin === null || __ipeServedOn(origin, pageHost) ? null : origin;
}
// A trusted frame's canonical sandbox: the trusted tokens `v` holds, the
// escape token only beside `allow-popups` and when `popups` are held.
function __ipeTrustedSandbox(v, popups) {
  var held = typeof v === "string" ? v.split(/[\t\n\f\r ]+/).map(__ipeAsciiLower) : [];
  var escape = popups && held.indexOf("allow-popups") !== -1;
  return __IPE_TRUSTED_SANDBOX_TOKENS.filter(function(t) {
    return held.indexOf(t) !== -1 && (t !== "allow-popups-to-escape-sandbox" || escape);
  }).join(" ");
}
// A trusted frame's canonical `allow` (`frames.rs` `Delegation`), or null when
// it delegates nothing: each directive of `v` whose feature is a table row,
// whose tokens are each `'src'` or `origin`, and whose class the `grants`
// open, as `<feature> 'src'` in table order; `fullscreen` when
// `allowfullscreen` is present. A value over 1024 characters or 64
// directives, or holding a character outside U+0021..U+007E and `allow`
// whitespace, delegates nothing; a feature written twice is delegated only
// when no occurrence is dropped.
function __ipeAllow(v, fullscreen, origin, grants) {
  var admitted = {}, refused = {};
  if (typeof v === "string") {
    if (v.length > 1024 || !/^[\x21-\x7e\t\n\f\r ]*$/.test(v) || v.split(";").length > 64) {
      return null;
    }
    v.split(";").forEach(function(d) {
      var words = d.split(/[\t\n\f\r ]+/).filter(function(w) { return w !== ""; });
      var row = null;
      for (var i = 0; i < __IPE_DELEGATION_FEATURES.length && words.length > 0; i++) {
        if (__IPE_DELEGATION_FEATURES[i][0] === words[0]) row = __IPE_DELEGATION_FEATURES[i];
      }
      if (row === null) return;
      var scoped = words.slice(1).every(function(t) { return t === "'src'" || t === origin; });
      var delegable = row[1] === "plain" || row[1] === "undisclosed" ||
          (row[1] === "gated" && row[2].some(function(g) { return grants.indexOf(g) !== -1; }));
      if (scoped && delegable) admitted[row[0]] = true; else refused[row[0]] = true;
    });
  }
  if (fullscreen) admitted["fullscreen"] = true;
  var out = __IPE_DELEGATION_FEATURES.filter(function(r) {
    return admitted[r[0]] === true && refused[r[0]] !== true;
  }).map(function(r) { return r[0] + " 'src'"; });
  return out.length > 0 ? out.join("; ") : null;
}
// The grant of an `iframe` aimed at `origin` (null when untrusted) whose
// attribute reader is `get`: `[sandbox, allow]`, `allow` null when absent.
function __ipeFrameGrant(origin, get) {
  if (origin === null) return [__ipeSandbox(get("sandbox")), null];
  return [
    __ipeTrustedSandbox(get("sandbox"), __ipeEscapePopups()),
    __ipeAllow(get("allow"), get("allowfullscreen") !== null, origin, __ipeFrameList("frameGrants"))
  ];
}
// The keys a patch of a frame element `tag` plans as one, grant keys first;
// empty for every other tag.
function __ipeFramePatchKeys(tag) {
  var name = __ipeAsciiLower(tag);
  if (name === "iframe") return ["sandbox"].concat(__IPE_FRAME_PERMISSIONS, ["src", "srcdoc"]);
  var loads = __ipeFrameLoaderKey(name);
  return loads === null ? [] : __IPE_FRAME_PERMISSIONS.concat([loads]);
}
var __ipeNode = (function() {
  // A member the browser lacks is a function that refuses every call: boot
  // never stops on it, and a read that needs it throws rather than answer
  // through the node's own lookup.
  function missing() { throw new TypeError("Ipe client: DOM member unavailable"); }
  function own(fn) { return typeof fn === "function" ? fn : missing; }
  function getter(proto, name) {
    var d = Object.getOwnPropertyDescriptor(proto, name);
    return own(d && d.get);
  }
  function setter(proto, name) {
    var d = Object.getOwnPropertyDescriptor(proto, name);
    return own(d && d.set);
  }
  var getAttribute = own(Element.prototype.getAttribute);
  var setAttribute = own(Element.prototype.setAttribute);
  var removeAttribute = own(Element.prototype.removeAttribute);
  var remove = own(Element.prototype.remove);
  var contains = own(Node.prototype.contains);
  var removeChild = own(Node.prototype.removeChild);
  var appendChild = own(Node.prototype.appendChild);
  var replaceChild = own(Node.prototype.replaceChild);
  var query = own(Element.prototype.querySelector);
  var fragmentQuery = own(DocumentFragment.prototype.querySelector);
  var queryAll = own(Element.prototype.querySelectorAll);
  var fragmentQueryAll = own(DocumentFragment.prototype.querySelectorAll);
  var on = own(EventTarget.prototype.addEventListener);
  var controls = getter(HTMLFormElement.prototype, "elements");
  var parentElement = getter(Node.prototype, "parentElement");
  var parentNode = getter(Node.prototype, "parentNode");
  var firstChild = getter(Node.prototype, "firstChild");
  var nextSibling = getter(Node.prototype, "nextSibling");
  var textContent = setter(Node.prototype, "textContent");
  var firstElementChild = getter(Element.prototype, "firstElementChild");
  var nextElementSibling = getter(Element.prototype, "nextElementSibling");
  var tagName = getter(Element.prototype, "tagName");
  var namespaceURI = getter(Element.prototype, "namespaceURI");
  var localName = getter(Element.prototype, "localName");
  var templateContent = typeof HTMLTemplateElement === "function"
      ? getter(HTMLTemplateElement.prototype, "content") : missing;
  var closest = own(Element.prototype.closest);
  // `focus()` per element interface: HTML, SVG and MathML elements are every
  // element that has one. An interface the browser lacks is left out.
  var focusers = [
    typeof HTMLElement === "function" ? HTMLElement : null,
    typeof SVGElement === "function" ? SVGElement : null,
    typeof MathMLElement === "function" ? MathMLElement : null
  ].filter(function(c) { return c !== null; }).map(function(c) {
    return {of: c, run: own(c.prototype.focus)};
  });
  return {
    attr: function(el, name) { return getAttribute.call(el, name); },
    setAttr: function(el, name, v) { setAttribute.call(el, name, v); },
    removeAttr: function(el, name) { removeAttribute.call(el, name); },
    contains: function(el, other) { return contains.call(el, other); },
    on: function(el, type, fn) { on.call(el, type, fn); },
    // A form's controls; null for any other node.
    controls: function(el) {
      return el instanceof HTMLFormElement ? controls.call(el) : null;
    },
    parent: function(el) { return parentElement.call(el); },
    parentNode: function(el) { return parentNode.call(el); },
    firstChild: function(el) { return firstChild.call(el); },
    nextSibling: function(el) { return nextSibling.call(el); },
    firstElement: function(el) { return firstElementChild.call(el); },
    next: function(el) { return nextElementSibling.call(el); },
    removeChild: function(el, child) { removeChild.call(el, child); },
    append: function(el, child) { appendChild.call(el, child); },
    replaceChild: function(el, fresh, old) { replaceChild.call(el, fresh, old); },
    queryAll: function(el, sel) { return queryAll.call(el, sel); },
    closest: function(el, sel) { return closest.call(el, sel); },
    setText: function(el, text) { textContent.call(el, text); },
    tag: function(el) { return tagName.call(el); },
    ns: function(el) { return namespaceURI.call(el); },
    local: function(el) { return localName.call(el); },
    // A template's inert content fragment.
    content: function(el) { return templateContent.call(el); },
    // The first, or every, match below the detached holder `tmp` (an element
    // or a fragment).
    queryIn: function(tmp, sel) {
      return (tmp instanceof DocumentFragment ? fragmentQuery : query).call(tmp, sel);
    },
    queryAllIn: function(tmp, sel) {
      return (tmp instanceof DocumentFragment ? fragmentQueryAll : queryAll).call(tmp, sel);
    },
    // Removes `autofocus` from every element below the detached holder `tmp`
    // (an element or a fragment), returning them in document order.
    stripAutofocus: function(tmp) {
      var found = (tmp instanceof DocumentFragment ? fragmentQueryAll : queryAll).call(tmp, "[autofocus]");
      var stripped = [];
      for (var i = 0; i < found.length; i++) {
        removeAttribute.call(found[i], "autofocus");
        stripped.push(found[i]);
      }
      return stripped;
    },
    // Fences every frame below the detached holder `tmp` (an element or a
    // fragment) before its nodes connect: an `iframe` gets the grant of its
    // target and no other permission attribute, an `embed`, `object` or
    // `frame` loses every permission attribute, and one holding the
    // attribute it loads from toward an untrusted target is removed.
    fenceFrames: function(tmp) {
      var found = (tmp instanceof DocumentFragment ? fragmentQueryAll : queryAll).call(tmp, "iframe, embed, object, frame");
      for (var i = 0; i < found.length; i++) {
        var el = found[i];
        var tag = __ipeAsciiLower(localName.call(el));
        var loads = __ipeFrameLoaderKey(tag);
        var get = function(k) { return getAttribute.call(el, k); };
        var origin = __ipeFrameTarget(tag, get, location.host);
        if (tag === "iframe") {
          var grant = __ipeFrameGrant(origin, get);
          for (var j = 1; j < __IPE_FRAME_PERMISSIONS.length; j++) {
            removeAttribute.call(el, __IPE_FRAME_PERMISSIONS[j]);
          }
          setAttribute.call(el, "sandbox", grant[0]);
          if (grant[1] === null) removeAttribute.call(el, "allow");
          else setAttribute.call(el, "allow", grant[1]);
        } else {
          for (var m = 0; m < __IPE_FRAME_PERMISSIONS.length; m++) {
            removeAttribute.call(el, __IPE_FRAME_PERMISSIONS[m]);
          }
          if (loads !== null && get(loads) !== null && origin === null) remove.call(el);
        }
      }
    },
    // Whether `el` took focus: a node that cannot be focused stays unfocused.
    focus: function(el) {
      var run = null;
      for (var i = 0; i < focusers.length && run === null; i++) {
        if (el instanceof focusers[i].of) run = focusers[i].run;
      }
      if (run === null) return false;
      var ran = __ipeAsRuntimeFocus(function() {
        try { run.call(el, {preventScroll: true}); return true; } catch (_) { return false; }
      });
      return ran && __ipeDoc.active() === el;
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
  ["frameOrigins", "frameGrants"].forEach(function(k) {
    if (Object.prototype.hasOwnProperty.call(data, k) && (!Array.isArray(data[k]) ||
        data[k].some(function(x) { return typeof x !== "string"; }))) {
      refuse(k + " is not a list of strings");
    }
  });
  if (Object.prototype.hasOwnProperty.call(data, "escapePopups")) {
    requireType(data, "escapePopups", "boolean", "");
  }
  if (!__ipeEpochParts(data["epoch"])) refuse("epoch is not an epoch token");
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
var __ipeEpoch = __ipeBoot["epoch"];
// The render history this document was served from, fixed for the document's
// life. Its styles are admitted by that history's nonce, so only a render of
// the same history can style correctly here.
Object.defineProperty(window, "__ipeBootInc", {
  value: __ipeEpochParts(__ipeBoot["epoch"]).inc,
  writable: false,
  configurable: false,
  enumerable: false
});
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
  var inc = token.slice(0, 32);
  var n = token.slice(33);
  if (!/^[0-9a-f]{32}$/.test(inc) || !/^[1-9][0-9]*$/.test(n)) return null;
  return { inc: inc, n: n };
}
// The parts of `token` when it is an epoch of this document's own history;
// null for any other value.
function __ipeOwnEpoch(token) {
  var parts = __ipeEpochParts(token);
  return parts && parts.inc === __ipeBootInc ? parts : null;
}
// The order of two counters of one history: negative, zero or positive.
// Counters are canonical decimals, so a longer one is larger.
function __ipeCounterOrder(a, b) {
  if (a.n.length !== b.n.length) return a.n.length - b.n.length;
  return a.n === b.n ? 0 : (a.n > b.n ? 1 : -1);
}
// `__ipeEpoch` is written only by the two adopt functions below, and each
// adopts only a token it has parsed as an epoch of this document's history.
//
// Apply a full render through `applyFn` when its epoch is of this document's
// history and no older than the render on screen, then adopt that epoch; true
// when it applied. A render with no epoch, or of another history, would style
// against a nonce this document does not hold: it is never applied, and the
// document is stale.
//
// An applied render then records the route it was committed with as the
// location, rewriting the current entry.
function __ipeAdoptFullBody(token, applyFn, route) {
  if (__ipeStale) return false;
  var next = __ipeOwnEpoch(token);
  if (!next) {
    __ipeStaleDocument();
    return false;
  }
  var cur = __ipeOwnEpoch(__ipeEpoch);
  if (cur && __ipeCounterOrder(next, cur) < 0) return false;
  __ipeKeepFocus(function() {
    applyFn();
    __ipeEpoch = token;
    __ipeSyncRoute(route, false, next);
  }, null);
  return true;
}
// Where the patches diffed from render `from` to render `to` stand against the
// DOM on screen: "next" when `from` is the render on screen and `to` follows it
// in this document's history; "behind" when the screen is another render of
// that history; "foreign" when either end is not an epoch of this history, or
// `to` does not follow `from`.
function __ipePatchStep(from, to) {
  var a = __ipeOwnEpoch(from);
  var b = __ipeOwnEpoch(to);
  if (!a || !b || __ipeCounterOrder(b, a) <= 0) return "foreign";
  return from === __ipeEpoch ? "next" : "behind";
}
// Apply the patches `frame` carries and adopt its `to`, only as the next step
// from the render on screen, record the route it was committed with, then
// move focus as the frame addresses it. The route is a new history entry only
// in the tab whose own event made the commit; every other tab rewrites its
// current entry. The one caller of `__ipeApplyPatches`.
function __ipeAdoptPatches(frame) {
  if (__ipeStale || __ipePatchStep(frame.from, frame.to) !== "next") return;
  var own = frame.history === "push" && !!__ipeTabId && frame.tab === __ipeTabId;
  __ipeKeepFocus(function() {
    __ipeApplyPatches(frame.patches);
    __ipeEpoch = frame.to;
    __ipeSyncRoute(frame.route, own, __ipeOwnEpoch(frame.to));
    __ipeFocusAddressed(frame);
  }, frame.patches);
}
// Record `route`, the browser path a render at epoch `at` was committed with,
// as the location: a new entry when `push`, otherwise the current entry
// rewritten. A route that is not a same-origin path under this app's base is
// never recorded, and a route that is already the location's path records
// nothing, so its query and fragment stay. A render with no route (an
// unrouted app, or a page whose route does not render) leaves the URL as it is.
//
// The route is judged as the browser resolves it: one the URL parser rewrites
// (a dot segment, an encoded dot, a backslash, a query or fragment) is not a
// path the server minted, and the base check reads the resolved path.
function __ipeSyncRoute(route, push, at) {
  if (typeof route !== "string" || !at) return;
  if (route.charAt(0) !== "/" || route.charAt(1) === "/") return;
  var u;
  try { u = new URL(route, window.location.href); } catch (_) { return; }
  if (u.origin !== window.location.origin || u.pathname !== route) return;
  var path = u.pathname;
  if (__ipeBase && path !== __ipeBase && path.indexOf(__ipeBase + "/") !== 0) return;
  if (path === window.location.pathname) return;
  __ipeRecordNav(path, push, at);
}
// Set once this document has refused a render of another history: from then
// on it applies no patch and no full render.
var __ipeStale = false;
// Set once the server closed this document's session with a `closed` frame:
// from then on nothing reopens the stream, posts an event, probes the session
// or reloads the page.
var __ipeEnded = false;
// The sessionStorage record of the last stale-document reload, and the window
// within which a second one is refused.
var __IPE_INC_RELOAD_KEY = "__ipe_inc_reload";
var __IPE_INC_RELOAD_WINDOW_MS = 30000;
// Leave a document whose render history is gone: reload it at most once per
// window, so the fresh document joins the live history. Over that budget, or
// with no sessionStorage to keep it, nothing reloads; the banner says the page
// is out of date and the document stays as it is.
function __ipeStaleDocument() {
  if (__ipeStale) return;
  __ipeStale = true;
  var now = Date.now();
  var stamp = String(now);
  var reload = false;
  try {
    var last = Number(sessionStorage.getItem(__IPE_INC_RELOAD_KEY));
    var recent = last > 0 && now >= last && now - last < __IPE_INC_RELOAD_WINDOW_MS;
    if (!recent) {
      sessionStorage.setItem(__IPE_INC_RELOAD_KEY, stamp);
      reload = sessionStorage.getItem(__IPE_INC_RELOAD_KEY) === stamp;
    }
  } catch (_) { reload = false; }
  if (reload) {
    __ipeReloadDocument();
    return;
  }
  __ipeShowStale();
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
  return !!a && __ipeNode.tag(a) === "SELECT";
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
  if (ev.target && __ipeNode.tag(ev.target) === "SELECT") {
    setTimeout(function() { __ipeReleaseHeldRender(false); }, 0);
  }
}, true);
__ipeDoc.on("change", function(ev) {
  if (ev.target && __ipeNode.tag(ev.target) === "SELECT") {
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

// ── Input authority state ────────────────────────────────────
// __ipeClientSeq numbers this page's events. __ipeLastAppliedSeq is the
// largest local seq already applied. __ipeLastGlobalSeq is the app-wide
// broadcast counter the server stamps onto every broadcast-derived frame: a
// frame whose globalSeq is already applied (a broadcast an SSE reconnect
// re-delivers) drops at the boundary. A frame with no globalSeq, or 0, has
// no broadcast ordering constraint.
var __ipeClientSeq = 0;
var __ipeLastAppliedSeq = 0;
var __ipeLastGlobalSeq = 0;
// ipe-id → the entry of a field the user has typed into.
var __ipeInputs = {};

// The entry of the field `sid`, made on its first input event.
//   * liveValue is the value the field shows. The input handler writes it,
//     and every server write to the field re-reads it, so it mirrors the DOM.
//   * edited is true from an input event until the next event stamps it.
//   * pendingSeq is the seq of the event that carries the user's latest
//     value, or 0. It ends once the server has answered an event at or after
//     it: an accept, a stale answer, or a render frame of this tab's own
//     event. While it holds, the field is the user's, not the view's.
//   * refusedValue is the value a refused event carried, or null. While the
//     field still shows it, no later event carries it.
function __ipeInputEntry(sid) {
  var e = __ipeInputs[sid];
  if (!e) {
    e = __ipeInputs[sid] = {
      liveValue: "", edited: false, pendingSeq: 0, refusedValue: null
    };
  }
  return e;
}

// Stamp every field edited since its last stamp with the event `seq` that
// carries its value.
function __ipeStampEdited(seq) {
  var ids = Object.keys(__ipeInputs);
  for (var i = 0; i < ids.length; i++) {
    var e = __ipeInputs[ids[i]];
    if (!e.edited) continue;
    e.pendingSeq = seq;
    e.edited = false;
  }
}

// End every pending value an event at or before `seq` carries: the server
// has answered that event, so the view's value is the field's again. An
// earlier event's answer that never arrives cannot hold a value pending.
function __ipeRetirePending(seq) {
  if (typeof seq !== "number" || seq <= 0) return;
  var ids = Object.keys(__ipeInputs);
  for (var i = 0; i < ids.length; i++) {
    var e = __ipeInputs[ids[i]];
    if (e.pendingSeq > 0 && e.pendingSeq <= seq) e.pendingSeq = 0;
  }
}

// Retire what a stream `frame` answers: a render of this tab's own event
// `tabSeq` follows that event's dispatch.
function __ipeRetireOwnFrame(frame) {
  if (!frame || !__ipeTabId || frame.tab !== __ipeTabId) return;
  __ipeRetirePending(frame.tabSeq);
}

// Re-read the field `el` into its entry after the server wrote it.
function __ipeResyncField(el) {
  var sid = __ipeNode.attr(el, "ipe-id");
  if (sid === null) return;
  var e = __ipeInputs[sid];
  if (e) e.liveValue = String(__ipeFieldValue(el));
}

// Re-read every entry's field after a swap, and drop the entry of a field
// the page no longer holds, so the table is bounded by the live document.
function __ipeResyncInputs() {
  var ids = Object.keys(__ipeInputs);
  for (var i = 0; i < ids.length; i++) {
    var el = null;
    try { el = __ipeDoc.query("[ipe-id=" + __ipeCssString(ids[i]) + "]"); } catch (_) { el = null; }
    if (!__ipeIsField(el)) {
      delete __ipeInputs[ids[i]];
      continue;
    }
    __ipeInputs[ids[i]].liveValue = String(__ipeFieldValue(el));
  }
}

// The values of pending fields, bundled into every outgoing event. A field
// the server has answered for is left out, so an accepted value rides no
// later event. A value the server refused is left out until the user edits
// it: the refusal would otherwise ride on every event.
function __ipeInputsSnapshot() {
  var out = null;
  var ids = Object.keys(__ipeInputs);
  for (var i = 0; i < ids.length; i++) {
    var e = __ipeInputs[ids[i]];
    if (e.refusedValue !== null && e.refusedValue !== e.liveValue) e.refusedValue = null;
    if (e.pendingSeq === 0) continue;
    if (e.refusedValue !== null) continue;
    if (!out) out = {};
    out[ids[i]] = {value: e.liveValue, seq: e.pendingSeq};
  }
  return out;
}

// __ipeIsDirty — a field whose DOM state is authoritative over the server's
// view: it holds focus, its debounced input event has not been sent, or its
// sent value is pending. Only fields count: a focused button or link has no
// keystrokes to keep, and treating it as dirty would block the patch that
// replaces its subtree.
function __ipeIsDirty(el) {
  if (!__ipeIsField(el)) return false;
  if (el === __ipeDoc.active()) return true;
  var hid = __ipeNode.attr(el, "data-ipe-hid");
  if (hid && __ipeInputPending[hid]) return true;
  var sid = __ipeNode.attr(el, "ipe-id");
  if (sid !== null) {
    var e = __ipeInputs[sid];
    if (e && e.pendingSeq > 0) return true;
  }
  return false;
}

// Fold a response or frame's `seq` and `globalSeq` into the applied counters,
// each monotonically. A missing, zero or non-numeric globalSeq has no
// broadcast ordering constraint.
function __ipeIngestSeq(seq, globalSeq) {
  if (typeof seq === "number" && seq > __ipeLastAppliedSeq) {
    __ipeLastAppliedSeq = seq;
  }
  if (typeof globalSeq === "number" && globalSeq > __ipeLastGlobalSeq) {
    __ipeLastGlobalSeq = globalSeq;
  }
}

// __ipeHandleResponse — run `applyFn` unless a newer frame already landed:
// a frame whose seq is at or below __ipeLastAppliedSeq, or whose globalSeq is
// at or below __ipeLastGlobalSeq, would regress the DOM and is dropped. Either
// guard drops alone. A frame with no seq (or 0) always applies.
function __ipeHandleResponse(seq, applyFn, globalSeq) {
  if (typeof seq === "number" && seq > 0 && seq <= __ipeLastAppliedSeq) {
    return;
  }
  if (typeof globalSeq === "number" && globalSeq > 0 && globalSeq <= __ipeLastGlobalSeq) {
    return;
  }
  __ipeIngestSeq(seq, globalSeq);
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

// __ipePlaceholderUncontrolled — true when the server-rendered field
// leaves its value to the user: no `__IPE_CONTROLLED_ATTR` marker, no
// authority attribute, no textarea text, no option[selected]. Such a
// field's live node is spliced across the swap so the user's state is
// not blanked; a controlled one is rebuilt with the view's value. The
// same rule as `dom/keep.rs` `Control::of`.
function __ipePlaceholderUncontrolled(placeholder) {
  if (!placeholder) return false;
  if (placeholder.hasAttribute(__IPE_CONTROLLED_ATTR)) return false;
  for (var i = 0; i < __IPE_AUTHORITY_ATTRS.length; i++) {
    if (placeholder.hasAttribute(__IPE_AUTHORITY_ATTRS[i])) return false;
  }
  var tag = __ipeAsciiLower(placeholder.tagName);
  if (tag === "textarea") {
    return (placeholder.textContent || "").length === 0;
  }
  if (tag === "select") {
    return placeholder.querySelectorAll("option[selected]").length === 0;
  }
  return true;
}

// `s` as a quoted CSS string, every character escaped as the CSS syntax
// requires: an attribute value from the page or the server (a newline, a
// backslash, a quote) never ends the string or makes the selector throw.
var __ipeCssEscape =
    typeof CSS === "object" && CSS !== null && typeof CSS.escape === "function"
        ? CSS.escape
        : function() { throw new TypeError("Ipe client: CSS.escape unavailable"); };
function __ipeCssString(s) {
  return '"' + __ipeCssEscape(s) + '"';
}

// __ipeFindPlaceholder — locate a live input's slot in the new tree.
// Prefer ipe-id (structurally stable + uniquely keyed). Fall back to
// tag+name only when the live element has no ipe-id AND the new tree
// has exactly one match — preventing wrong-input collisions when
// names recur (e.g. multiple address forms with name="line1").
function __ipeFindPlaceholder(tmp, live) {
  var sid = live.getAttribute && live.getAttribute("ipe-id");
  if (sid) {
    var bySid = __ipeNode.queryIn(tmp, "[ipe-id=" + __ipeCssString(sid) + "]");
    if (bySid) return bySid;
  }
  var name = live.getAttribute && live.getAttribute("name");
  if (!name) return null;
  var tag = live.tagName.toLowerCase();
  var matches = __ipeNode.queryAllIn(tmp, tag + "[name=" + __ipeCssString(name) + "]");
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
  var parsed = __ipeParseFor(container, newHTML);
  if (__ipeIsTemplate(container)) {
    // A template's markup lives in its inert content, never in the document:
    // no field or focus is there to keep.
    var content = __ipeNode.content(container);
    var gone;
    while ((gone = __ipeNode.firstChild(content))) __ipeNode.removeChild(content, gone);
    var moved;
    while ((moved = __ipeNode.firstChild(parsed))) __ipeNode.append(content, moved);
    return;
  }
  __ipeSwapPreservingFocus(container, parsed);
}

function __ipeIsTemplate(el) {
  return __ipeNode.ns(el) === __IPE_HTML_NS && __ipeNode.local(el) === "template";
}

// `html` parsed into a detached holder in `container`'s namespace and context,
// by the document's own parser: scripting is on, as for the markup it
// replaces. An HTML holder is an element of `container`'s own tag, so the
// parser reads the markup in the insertion mode `container` sets (a `<tr>`
// below a `<tbody>`, an `<option>` below a `<select>`, text below a
// `<textarea>`); a `div` would drop the table tags and keep only their text.
// A custom element's name would run its constructor on the holder, so it gets
// a `div`; a template's markup is parsed into a template's inert content.
// Every `autofocus` attribute is removed before the holder's nodes connect:
// the browser focuses an autofocus element on insertion while focus is on the
// body, so a render the user did not cause would move focus. The runtime moves
// focus itself (`__ipeFocusAutofocus`, `__ipeFocusAddressed`). The stripped
// elements are pushed onto `stripped` when given.
function __ipeParseFor(container, html, stripped) {
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
  var ns = __ipeNode.ns(container);
  if (ns && ns !== __IPE_HTML_NS) {
    var range = __ipeDoc.range();
    range.selectNodeContents(container);
    tmp = range.createContextualFragment(html);
  } else {
    var local = __ipeNode.local(container);
    var holder = __ipeDoc.create(local.indexOf("-") >= 0 ? "div" : local);
    holder.innerHTML = html;
    tmp = __ipeIsTemplate(container) ? __ipeNode.content(holder) : holder;
  }
  __ipeNode.fenceFrames(tmp);
  var found = __ipeNode.stripAutofocus(tmp);
  if (stripped) for (var i = 0; i < found.length; i++) stripped.push(found[i]);
  return tmp;
}

// The ordered writes (`[key, value]`, null removes) that patch the frame
// element `el` by the patch attributes `attrs` (`html.rs`
// `plan_frame_patch`). The final state is read first: each frame key from
// `attrs` (the last of any key case; a string sets, null removes), else from
// `el`. Its target and grant decide every grant key, written first: the
// sandbox always, `allow` set or removed, every other permission attribute
// removed. Then each navigation key `attrs` names, a loader's only toward a
// trusted target. So a patch moving a frame off a trusted origin withdraws
// its grant before it navigates. Empty for every other element.
function __ipeFramePlan(el, attrs) {
  var tag = __ipeAsciiLower(__ipeNode.local(el));
  var keys = __ipeFramePatchKeys(tag);
  if (keys.length === 0) return [];
  var asked = {};
  Object.keys(attrs).forEach(function(k) {
    var key = __ipeAsciiLower(k), v = attrs[k];
    if (keys.indexOf(key) !== -1 && (v === null || typeof v === "string")) asked[key] = v;
  });
  var has = function(k) { return Object.prototype.hasOwnProperty.call(asked, k); };
  var get = function(k) { return has(k) ? asked[k] : __ipeNode.attr(el, k); };
  var origin = __ipeFrameTarget(tag, get, location.host);
  var iframe = tag === "iframe";
  var writes = [];
  if (iframe) {
    var grant = __ipeFrameGrant(origin, get);
    writes.push(["sandbox", grant[0]], ["allow", grant[1]]);
  }
  __IPE_FRAME_PERMISSIONS.forEach(function(p) {
    if (!(iframe && p === "allow")) writes.push([p, null]);
  });
  keys.forEach(function(k) {
    if (k === "sandbox" || __IPE_FRAME_PERMISSIONS.indexOf(k) !== -1 || !has(k)) return;
    writes.push([k, iframe || origin !== null ? asked[k] : null]);
  });
  return writes;
}

// Replace `container`'s children with the parsed holder `tmp`'s, splicing the
// live inputs described above into their placeholders.
//
// A focused live field keeps its own node, value and selection (below). Focus
// the swap drops anywhere else is put back by the frame's focus keep
// (`__ipeKeepFocus`), never here. Focus outside `container` is not read or
// written. Every member read on `container` goes through `__ipeNode`: it may
// be a `<form>`.
function __ipeSwapPreservingFocus(container, tmp) {
  var focused = __ipeDoc.active();
  var inside = focused && focused !== __ipeDoc.body() &&
      __ipeNode.contains(container, focused);
  var focusedInside = inside && __ipeIsField(focused);

  // Snapshot focused-state BEFORE any DOM mutation. Selection read
  // throws on some input types, so catch.
  var selStart = null, selEnd = null, selDir = "none", scrollTop = 0;
  if (focusedInside) {
    try {
      selStart = focused.selectionStart;
      selEnd   = focused.selectionEnd;
      selDir   = focused.selectionDirection || "none";
    } catch (_) {}
    scrollTop = focused.scrollTop;
  }

  // Walk the LIVE container's inputs/textareas/selects and decide
  // which ones to splice. The focused element is ALWAYS spliced
  // (active typing wins). Other elements are spliced only when the
  // server-side placeholder is uncontrolled (no value/checked/
  // selected) — i.e. user state is canonical.
  var preservedFocus = null;
  var liveNodes = __ipeNode.queryAll(container, __IPE_FIELD_TAGS.join(", "));
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
    __ipeNode.replaceChild(__ipeNode.parentNode(placeholder), live, placeholder);
    if (isFocused) preservedFocus = live;
  }

  // Commit: throw away container's current children (those we didn't
  // splice are stale; spliced ones already moved into tmp), then
  // attach tmp's children. Done.
  var gone;
  while ((gone = __ipeNode.firstChild(container))) __ipeNode.removeChild(container, gone);
  var moved;
  while ((moved = __ipeNode.firstChild(tmp))) __ipeNode.append(container, moved);

  // Focus restoration on the SAME node — so .value, IME state,
  // composition buffer survive untouched. removeChild + appendChild
  // drop focus, so we re-set it now.
  if (preservedFocus) {
    __ipeAsRuntimeFocus(function() {
      try { preservedFocus.focus({preventScroll: true}); } catch (_) {
        try { preservedFocus.focus(); } catch (_) {}
      }
    });
    if (typeof preservedFocus.setSelectionRange === "function" &&
        selStart !== null && selEnd !== null) {
      try { preservedFocus.setSelectionRange(selStart, selEnd, selDir); } catch (_) {}
    }
    if (scrollTop) preservedFocus.scrollTop = scrollTop;
  }
  __ipeResyncInputs();
}

// The focus keep: focus after a frame is a function of the view, never of the
// patch the diff chose (`dom::focus`, the rule the wasm runtime runs too).
// Before the frame, the view chain of the focused node is recorded: the
// `ipe-id` and tag of each element from `#ipe-root`'s child down to it, cut at
// the first element with no `ipe-id`, and recorded only when the first one
// carries one (focus in the debugger overlay, on the body or outside the view
// records nothing). After the frame, when nothing holds focus, focus goes to
// the deepest node of the chain still in the view that takes focus, else to
// `#ipe-root`. The check runs at the end of the commit. When a patch of the
// frame targets the chain and focus held, the browser's own later drop of the
// focused node to nothing (its fixup for a node a patch made unfocusable) is
// answered once, by the drop event it raises, in a task posted after the whole
// focus change. Neither check moves focus the user moved since the commit, nor
// one a newer frame owns, nor while the runtime is moving focus itself.
var __IPE_FOCUS_CHAIN_MAX = 1024;
// The event whose dispatch answers the drop check (`dom::focus::FOCUS_DROP_EVENT`).
var __IPE_FOCUS_DROP_EVENT = "focusout";
// The armed drop check of the newest frame: {chain, rec, held}; null when none.
var __ipeFocusPending = null;
// The view chain of the focused node below `root`, downward; null when focus
// is not below `root`, its first link carries no `ipe-id`, or it is nested
// deeper than `__IPE_FOCUS_CHAIN_MAX`.
function __ipeFocusChain(root) {
  var now = __ipeDoc.active();
  if (!root || !now || now === __ipeDoc.body() || !__ipeNode.contains(root, now)) return null;
  var upward = [];
  for (var at = now; at && at !== root; at = __ipeNode.parent(at)) {
    if (upward.length >= __IPE_FOCUS_CHAIN_MAX) return null;
    upward.push({id: __ipeNode.attr(at, "ipe-id"), tag: __ipeNode.tag(at)});
  }
  var chain = [];
  for (var i = upward.length - 1; i >= 0 && upward[i].id !== null; i--) chain.push(upward[i]);
  return chain.length > 0 ? chain : null;
}
// Whether the keep may put focus back for the frame `rec`: nothing holds
// focus, the user moved none since the commit, `rec` is the newest frame, and
// the runtime is not moving focus.
function __ipeFocusSettleDue(rec) {
  var now = __ipeDoc.active();
  var held = !!now && now !== __ipeDoc.body();
  return !held && __ipeFocusEpoch === rec.epoch && __ipeEpoch === rec.frame &&
      !__ipeRuntimeFocusing;
}
// Whether a frame arms the drop check (`dom::focus::arms`): focus is held, by
// the node focused before the frame, and some patch targets the chain or an
// earlier frame's check carries.
function __ipeFocusArms(chain, patched, heldUnchanged, focusHeld, carried) {
  return focusHeld && heldUnchanged && (carried || chain.some(function(link) { return patched(link.id); }));
}
// Whether an earlier frame's armed drop check carries into this frame
// (`dom::focus::carries`): armed on the node focused before this frame, with
// no focus move since.
function __ipeFocusCarries(armedOnHeld, noMoveSince) {
  return armedOnHeld && noMoveSince;
}
// Whether a drop answers the armed check (`dom::focus::drop_answers`): the
// held node itself lost focus to nothing.
function __ipeFocusDropAnswers(targetIsHeld, relatedIsNull) {
  return targetIsHeld && relatedIsNull;
}
// Runs `run`, the one commit of a frame, inside the focus keep; `patches` are
// the frame's patches, null for a whole-body swap, which arms no drop check.
function __ipeKeepFocus(run, patches) {
  var before = __ipeDoc.active();
  var chain = __ipeFocusChain(__ipeDoc.byId("ipe-root"));
  var epoch = __ipeFocusEpoch;
  var earlier = __ipeFocusPending;
  __ipeFocusPending = null;
  run();
  if (chain === null) return;
  var rec = {chain: chain, epoch: epoch, frame: __ipeEpoch};
  if (__ipeFocusSettleDue(rec)) __ipeRestoreFocus(rec.chain);
  if (!patches) return;
  var held = __ipeDoc.active();
  var patched = function(id) {
    return patches.some(function(p) { return String(p.id) === id; });
  };
  var carried = !!earlier &&
      __ipeFocusCarries(earlier.held === before, earlier.rec.epoch === epoch);
  if (__ipeFocusArms(chain, patched, !!held && held === before,
      !!held && held !== __ipeDoc.body(), carried)) {
    __ipeFocusPending = {chain: chain, rec: rec, held: held};
  }
}
// Answers the armed drop check in a task posted after the whole focus change:
// a microtask would run between `focusout` and `focusin` and read a Tab as a
// drop.
__ipeDoc.on(__IPE_FOCUS_DROP_EVENT, function(ev) {
  var pending = __ipeFocusPending;
  if (!pending) return;
  var related = ev.relatedTarget;
  if (!__ipeFocusDropAnswers(ev.target === pending.held,
      related === null || related === undefined)) return;
  __ipeFocusPending = null;
  setTimeout(function() {
    if (__ipeFocusSettleDue(pending.rec)) __ipeRestoreFocus(pending.rec.chain);
  }, 0);
}, true);
// The ONE element child of `at` whose `ipe-id` and tag equal `link`; null when
// none or several do, or when the children cannot be read. The children are
// walked through the core node members (`firstChild`, `nextSibling`), which
// every DOM has.
function __ipeOnlyChild(at, link) {
  try {
    var only = null;
    var count = 0;
    for (var kid = __ipeNode.firstChild(at); kid; kid = __ipeNode.nextSibling(kid)) {
      if (!(kid instanceof Element)) continue;
      if (__ipeNode.attr(kid, "ipe-id") === link.id && __ipeNode.tag(kid) === link.tag) {
        only = kid;
        count++;
      }
    }
    return count === 1 ? only : null;
  } catch (_) {
    return null;
  }
}
// Puts focus on the landing of `chain`: descending from `#ipe-root`, each
// depth takes the ONE element child whose `ipe-id` and tag equal the link (none
// or several end the descent); the matched nodes, deepest first, then
// `#ipe-root`, are tried until one takes focus. An equal `ipe-id` under another
// tag or another chain never matches, and a node that moved keeps its match.
// A landing node bound to `onFocus` delivers that message once. A depth whose
// children cannot be read (a DOM member the browser lacks) ends the descent:
// the depths above it are proven, so focus still lands, never stops.
function __ipeRestoreFocus(chain) {
  var root = __ipeDoc.byId("ipe-root");
  if (!root) return;
  var found = [];
  var at = root;
  for (var d = 0; d < chain.length; d++) {
    var only = __ipeOnlyChild(at, chain[d]);
    if (only === null) break;
    found.push(only);
    at = only;
  }
  for (var m = found.length - 1; m >= 0; m--) {
    if (__ipeNode.focus(found[m])) return;
  }
  __ipeNode.focus(root);
}

// The first mount of the page focuses the element the browser would have
// focused at load (the first element the server's page marks `autofocus`,
// found again by its `ipe-id`) only while the load's own autofocus is still
// due: nothing has held focus since the client started, the user has not
// pressed a key or a pointer, and the URL names no fragment target (the
// browser skips autofocus for one too). No
// `autofocus` attribute reaches the live DOM from a swap or a patch, so the
// browser never focuses an inserted element itself. Any frame puts lost focus
// back through the focus keep (`__ipeKeepFocus`). A later patches frame moves
// focus onto a new element only through `__ipeFocusAddressed`: onto the element the server named as
// newly autofocused, when the frame answers this tab's own user act, applies
// as the next step, and focus has not moved since that act.
var __ipeMounted = false;
// The `ipe-id` of the first element the server's page marks `autofocus`, read
// as the client starts; null when it marks none, or one with no `ipe-id`.
var __ipeLoadAutofocus = (function() {
  var el = __ipeDoc.query("#ipe-root [autofocus]");
  return el ? __ipeNode.attr(el, "ipe-id") : null;
})();
var __ipeAutofocusSpent = (function() {
  var now = __ipeDoc.active();
  return !!now && now !== __ipeDoc.body();
})();
// The page events after which the load's own autofocus is spent; the wasm
// loader hears the same list (`dom::diff::AUTOFOCUS_SPENDING_EVENTS`).
var __IPE_AUTOFOCUS_SPENDING = ["focusin", "pointerdown", "mousedown", "touchstart", "keydown"];
__IPE_AUTOFOCUS_SPENDING.forEach(function(type) {
  __ipeDoc.on(type, function() { __ipeAutofocusSpent = true; }, true);
});
// Counts the user's focus moves: a focus change or a pointer press the runtime
// did not cause itself. A key press is not a move: it is what sends the event.
var __ipeFocusEpoch = 0;
var __ipeRuntimeFocusing = false;
// Runs `move` as the runtime's own focus move and returns its result. The flag
// is restored, never cleared: a move nested in another keeps the outer one's.
function __ipeAsRuntimeFocus(move) {
  var was = __ipeRuntimeFocusing;
  __ipeRuntimeFocusing = true;
  try { return move(); } finally { __ipeRuntimeFocusing = was; }
}
["focusin", "pointerdown", "mousedown", "touchstart"].forEach(function(type) {
  __ipeDoc.on(type, function() {
    if (!__ipeRuntimeFocusing) __ipeFocusEpoch += 1;
  }, true);
});
// The window events that count a focus move when the window itself is their
// target: focus leaving the document (`dom::focus::WINDOW_FOCUS_MOVES`). An
// element's own `blur` crossing the capture phase is not one: the browser
// raises it for a node a patch made unfocusable.
var __IPE_WINDOW_FOCUS_MOVES = ["blur"];
__IPE_WINDOW_FOCUS_MOVES.forEach(function(type) {
  window.addEventListener(type, function(ev) {
    if (ev.target === window && !__ipeRuntimeFocusing) __ipeFocusEpoch += 1;
  }, true);
});
// The event kinds that are a deliberate act of the user: a key, a click, an
// edit, a submit. A pointer crossing (`mouseover`, `mouseout`) is not one: a
// render that shifts layout under a pointer at rest raises a trusted one. Nor
// is a focus change (`focus`, `blur`): the runtime raises one when it puts
// focus back.
var __IPE_USER_ACTS = Object.freeze({
  click: 1, dblclick: 1, input: 1, change: 1, submit: 1,
  keydown: 1, keyup: 1, keypress: 1, mousedown: 1, mouseup: 1
});
// The focus epoch of the user act `ev` is, read as it arrives; undefined when
// `ev` proves no act of the user's: an event the runtime or a render can
// raise, an untrusted one, or one raised while the runtime moves focus (the
// `change` a field commits as the runtime focuses another node), or an edit or
// key an input method is still composing (moving focus would cut the
// composition off). An event with no epoch keeps no record, so its render
// moves no focus.
function __ipeUserActEpoch(ev) {
  if (!ev.isTrusted || __ipeRuntimeFocusing) return undefined;
  if (ev.isComposing === true || ev.keyCode === 229) return undefined;
  if (!Object.prototype.hasOwnProperty.call(__IPE_USER_ACTS, ev.type)) return undefined;
  return __ipeFocusEpoch;
}
// The focus epoch of the user act behind each of this tab's recent events, by
// the tab's own seq. The epoch is read at the act itself (the key, the click,
// the file pick), never at the send: a file read, a resize or a debounce sends
// later, after the user may have moved focus. A frame names the seq of the
// event it answers, so the check binds to that event alone, never to acks or to
// the other events in flight. An event no user act of this document raised (a
// widget's emit, a page script's `__ipe_send`) keeps no record, so its render
// moves no focus: the runtime cannot prove a user drove it. At the cap the
// oldest record is dropped: a frame whose record is gone moves no focus.
var __IPE_FOCUS_SENDS_MAX = 64;
var __ipeFocusSends = [];
function __ipeFocusSent(seq, actEpoch) {
  if (typeof actEpoch !== "number") return;
  if (__ipeFocusSends.length >= __IPE_FOCUS_SENDS_MAX) __ipeFocusSends.shift();
  __ipeFocusSends.push({seq: seq, epoch: actEpoch});
}
// The focus epoch of the act behind the event at `seq`, taking its record out
// (one event commits one render); null when this tab holds no record of it.
function __ipeFocusTakeSent(seq) {
  for (var i = 0; i < __ipeFocusSends.length; i++) {
    if (__ipeFocusSends[i].seq === seq) return __ipeFocusSends.splice(i, 1)[0].epoch;
  }
  return null;
}
// A patches frame just applied as the next step moves focus onto the element
// it names only when it answers a user act of this tab and focus has not moved
// since that act. A target the frame's own patches removed, or one
// that cannot take focus, leaves focus alone.
function __ipeFocusAddressed(frame) {
  if (!__ipeTabId || frame.tab !== __ipeTabId) return;
  if (typeof frame.tabSeq !== "number") return;
  var sentIn = __ipeFocusTakeSent(frame.tabSeq);
  if (sentIn === null || sentIn !== __ipeFocusEpoch) return;
  if (typeof frame.focus !== "string") return;
  var el = null;
  try { el = __ipeDoc.query("[ipe-id=" + __ipeCssString(frame.focus) + "]"); } catch (_) { return; }
  if (el) __ipeNode.focus(el);
}
// The element the URL fragment names, resolved from the URL itself: `:target`
// matches only once the browser has applied the fragment, which can follow the
// first frame.
function __ipeFragmentTarget() {
  var raw = window.location.hash.slice(1);
  if (!raw) return null;
  var found = __ipeDoc.byId(raw);
  if (found) return found;
  try { return __ipeDoc.byId(decodeURIComponent(raw)); } catch (_) { return null; }
}
function __ipeAutofocusDue() {
  return !__ipeMounted && __ipeLoadAutofocus !== null && !__ipeAutofocusSpent &&
      !__ipeFragmentTarget();
}
// Focuses `el`, the mount's copy of the load's autofocus element, once the
// swap has landed below `root`. A live field the swap spliced in its place is
// found by its `ipe-id`; an element that did not land takes no focus.
function __ipeFocusAutofocus(root, el) {
  var now = __ipeDoc.active();
  if (__ipeAutofocusSpent || (now && now !== __ipeDoc.body())) return;
  if (!__ipeNode.contains(root, el)) {
    var id = __ipeNode.attr(el, "ipe-id");
    el = null;
    if (id !== null) {
      try { el = __ipeDoc.query("[ipe-id=" + __ipeCssString(id) + "]"); } catch (_) { el = null; }
    }
  }
  if (el && __ipeNode.contains(root, el)) __ipeNode.focus(el);
}

// __ipeCopyAttrsExceptAuthority — mirror attrs from src onto dst,
// skipping the three the user drives directly. Removes attrs on
// dst that aren't in src (same "skip" rule). Used when splicing a
// live focused input into a server-rendered placeholder.
function __ipeCopyAttrsExceptAuthority(src, dst) {
  if (!src || !dst || !src.attributes || !dst.attributes) return;
  var isAuthority = __ipeIsAuthorityAttr;
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
  var stripped = [];
  var parsed = __ipeShellRoot(__ipeParseFor(root, t, stripped), t);
  var loadTarget = null;
  for (var i = 0; i < stripped.length && loadTarget === null; i++) {
    if (__ipeNode.contains(parsed, stripped[i]) &&
        __ipeNode.attr(stripped[i], "ipe-id") === __ipeLoadAutofocus) {
      loadTarget = stripped[i];
    }
  }
  var scrollX = window.scrollX, scrollY = window.scrollY;
  // Read before the swap: a fragment target the swap replaces stops matching.
  var autofocus = __ipeAutofocusDue();
  __ipeMounted = true;
  __ipeSwapPreservingFocus(root, parsed);
  if (autofocus && loadTarget !== null) __ipeFocusAutofocus(root, loadTarget);
  // behavior:"instant" keeps this housekeeping scroll a synchronous jump
  // even under a global `scroll-behavior: smooth`, which would otherwise
  // animate every restore and fight the caret on per-keystroke re-renders.
  if (mode === "nav") {
    window.scrollTo({ left: 0, top: 0, behavior: "instant" });
  } else {
    window.scrollTo({ left: scrollX, top: scrollY, behavior: "instant" });
  }
  __ipeBindEvents();
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
  var el = __ipeNode.firstElement(tmp);
  while (el && __IPE_SHELL_HEAD_TAGS.indexOf(__ipeNode.tag(el)) >= 0) el = __ipeNode.next(el);
  return el && __ipeNode.tag(el) === "DIV" && __ipeNode.attr(el, "id") === "ipe-root" ? el : tmp;
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
    // Bound reads: the script's parent may be a `<form>`, whose control named
    // `replaceChild` (or `parentNode`) would answer for the member.
    __ipeNode.replaceChild(__ipeNode.parentNode(old), fresh, old);
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
// `epoch` is the render epoch read with `hid` at the keystroke, and `focus` the
// focus epoch read at that keystroke.
function __ipeDebouncedSend(msgName, args, hid, delay, epoch, focus) {
  var key = hid || msgName;
  clearTimeout(__ipeInputTimers[key]);
  // Re-inserted, so the pending map lists its keys by their latest edit.
  delete __ipeInputPending[key];
  __ipeInputPending[key] = { msgName: msgName, args: args, hid: hid, epoch: epoch, focus: focus };
  __ipeInputTimers[key] = setTimeout(function() { __ipeSendPendingInput(key); }, delay);
}
// Send the pending debounced input of `key` now, if any. Its event coalesces
// under `key`: queued behind another event of the same key, it replaces it.
function __ipeSendPendingInput(key) {
  var p = __ipeInputPending[key];
  if (!p) return;
  clearTimeout(__ipeInputTimers[key]);
  delete __ipeInputPending[key];
  __ipeSend(p.msgName, p.args, p.hid, { noLoader: true, epoch: p.epoch, focus: p.focus, coalesce: key });
}
// Send every pending debounced input now, in the order of their latest edits.
// Each was typed before the event about to be sent, so each is posted ahead of
// it: an event never reaches the server before an edit the user made first.
function __ipeSendAllPendingInput() {
  var keys = Object.keys(__ipeInputPending);
  for (var i = 0; i < keys.length; i++) __ipeSendPendingInput(keys[i]);
}
// Flush pending debounced input on blur (tab away / click elsewhere).
// Without this, typing fast then tabbing loses the last keystrokes
// because the debounce hasn't fired yet.
__ipeDoc.on("focusout", function(ev) {
  var t = ev.target;
  // A focusable `<form>` loses focus too; its controls shadow `getAttribute`.
  if (!(t instanceof Element)) return;
  var hid = __ipeNode.attr(t, "data-ipe-hid");
  var key = hid || __ipeNode.attr(t, "ipe-input");
  if (key) __ipeSendPendingInput(key);
}, true);

// ── Flush on leaving ─────────────────────────────────────────
// An edit still waiting on its debounce when the user follows a link or
// leaves the page is sent at once, through the one ordered channel: it joins
// the queue behind every event sent before it, never ahead. Its post asks the
// browser to keep it alive past the page (__ipeKeepAlive), so an edit posted
// while no event is in flight reaches the server; one queued behind an
// unanswered event goes only if the page stays.
function __ipeFlushOnLeave() {
  if (__ipeEnded) return;
  __ipeLeaving = true;
  try { __ipeSendAllPendingInput(); } finally { __ipeLeaving = false; }
}
// True only while __ipeFlushOnLeave sends: the bodies sent then are kept alive.
var __ipeLeaving = false;
// The bodies whose posts the browser keeps alive past the page.
var __ipeKeepAlive = new WeakSet();

// Capture-phase click listener inside ipe-root: before a link click leaves
// the current page, send any pending debounce so the final typed value reaches
// the server ahead of whatever the navigation sends.
__ipeDoc.on("click", function(ev) {
  // The target may be a `<form>`, whose control named `closest` would answer.
  var a = ev.target instanceof Element ? __ipeNode.closest(ev.target, "a[href]") : null;
  if (!a) return;
  var root = __ipeDoc.byId("ipe-root");
  if (!root || !root.contains(a)) return;
  __ipeFlushOnLeave();
}, true);

// Tab close / navigate away. Listen on both events because iOS Safari
// + bfcache fire pagehide instead of beforeunload.
window.addEventListener("beforeunload", __ipeFlushOnLeave);
window.addEventListener("pagehide", __ipeFlushOnLeave);

// ── Core send ────────────────────────────────────────────────
// Wire format (see docs/internals/web/input-authority-protocol.md §Request):
//   {sessionId, seq, msg, args, handlerId, epoch?, tab?, inputState?}
//   * seq is client-monotonic — server uses it to match responses to
//     the inputState snapshot that produced them; with tab it marks a
//     re-delivered event as a duplicate.
//   * epoch names the render handlerId was read from.
//   * opts.focus (client-only, never posted) is the focus epoch read at the
//     user act that raised the event; without it the event records no focus.
//   * inputState carries the user's value of every pending field.
function __ipeSend(msgName, args, handlerId, opts) {
  if (__ipeEnded) return;
  __ipeSendAllPendingInput();
  opts = opts || {};
  if (!opts.noLoader) __ipeLoaderStart();
  __ipeClientSeq++;
  var mySeq = __ipeClientSeq;
  // This event carries every value edited since the last event; the
  // server's answer to it ends them.
  __ipeStampEdited(mySeq);
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
  __ipeFocusSent(mySeq, opts.focus);
  if (typeof opts.coalesce === "string") __ipeCoalesceKey.set(body, opts.coalesce);
  if (__ipeLeaving) __ipeKeepAlive.add(body);
  __ipePostEvent(body);
}

// ── POST retry queue ─────────────────────────────────────────
// Wire-protocol POSTs are cheap (small JSON, idempotent on the
// server's seq-ordered state machine), so a transient network blip
// shouldn't lose the click. Failures push the body onto __ipeEventQueue;
// retries fire on exponential backoff (500ms, 1s, 2s, … cap 16s);
// the SSE 'open' handler drains the queue eagerly when the server
// comes back.
var __ipeEventQueue = [];
var __ipeRetryTimer = null;
var __ipeRetryAttempts = 0;
// Epoch ms of the first retry in the current disconnect burst (0 = connected).
// Bounds the fast-reconnect window; reset to 0 on a successful (re)connect.
var __ipeReconnectSince = 0;
// __ipeRetryBaseMs / __ipeRetryMaxMs / __ipeRetryMaxAttempts /
// __ipeEventQueueMax are templated at the top of this script from
// the IPE_WEB_RETRY_* / IPE_WEB_QUEUE_MAX env vars.
// The debounce key of an input event, by its body. A queued input event is
// replaced by a later one of the same key queued right behind it: the later
// one carries the field's newer value and every pending value the first
// carried, and its answer ends them all.
var __ipeCoalesceKey = new WeakMap();
// How long a posted event waits for its answer before it is retried. The
// server ends a request it cannot answer within its own request timeout (30 s
// by default), so a post past this bound is lost on the way: it goes back to
// the head of the queue, and a re-post the server already dispatched is
// answered without a second dispatch.
var __ipeEventAnswerBoundMs = 40000;
// A post the browser keeps alive past the page carries at most 64 KiB, shared
// by every such post in flight. A body of at most this many UTF-16 units is
// at most 48 KiB of UTF-8.
var __IPE_KEEPALIVE_BODY_MAX = 16384;
// The outcomes an answer to an event POST can have. Each has one handler in
// __ipeOnEventAnswer; a network failure or a post past its bound is TRANSIENT.
var __IPE_EVENT_ANSWER = Object.freeze({
  ACCEPTED: "accepted", STALE: "stale", SESSION_LOST: "session-lost",
  TRANSIENT: "transient", TOO_LARGE: "too-large", REFUSED: "refused"
});
// The one reading of an event answer's status. A status no row names is
// REFUSED: the client says so and never sends the event again, since a retry
// of a refusal is refused again.
function __ipeEventAnswer(r) {
  var status = r.status;
  var marked = r.headers.get("X-Ipe-Web") === "1";
  if (marked && status === 409) return __IPE_EVENT_ANSWER.STALE;
  if (marked && status === 404) return __IPE_EVENT_ANSWER.SESSION_LOST;
  if (status >= 200 && status < 300) return __IPE_EVENT_ANSWER.ACCEPTED;
  if (status === 408 || status === 425 || status === 429) return __IPE_EVENT_ANSWER.TRANSIENT;
  if (status >= 500 && status < 600) return __IPE_EVENT_ANSWER.TRANSIENT;
  if (status === 413 || status === 414 || status === 431) return __IPE_EVENT_ANSWER.TOO_LARGE;
  return __IPE_EVENT_ANSWER.REFUSED;
}
// How a post ends: its event is ANSWERED (accepted, stale, or refused, and
// never sent again) or goes back to the head of the queue to RETRY.
var __IPE_POST_SETTLED = Object.freeze({ ANSWERED: "answered", RETRY: "retry" });
// The attempt posted and still unsettled, or null. Events go one at a time, so
// a later one never reaches the server before an earlier one: two posts in
// flight at once race for the session, and the later act could be dispatched
// first. Each post is its own attempt, so a late answer to an attempt already
// settled (past its bound, say) never settles the retry of the same event.
var __ipeEventInFlight = null;
// The one place a post ends: it frees the slot, then sends the next event
// (ANSWERED) or puts this one back at the head of the queue (RETRY; anything
// else too, failing closed onto the path that loses nothing). True only for
// the attempt holding the slot, the first time: every later settle of it is a
// no-op, so an answer is acted on once and an event is never queued twice.
function __ipeSettle(attempt, outcome) {
  if (__ipeEventInFlight !== attempt) return false;
  __ipeEventInFlight = null;
  clearTimeout(attempt.bound);
  __ipeLoaderEnd();
  if (__ipeEnded) return true;
  if (outcome === __IPE_POST_SETTLED.ANSWERED) {
    __ipeDrainQueue();
    return true;
  }
  __ipeEnqueue(attempt.body, true);
  __ipeShowReconnecting();
  __ipeScheduleRetry();
  return true;
}
// `fromQueue` marks the head of the retry queue. An event posted while the
// queue holds events or an event is in flight joins its tail, so it never
// overtakes them.
function __ipePostEvent(body, fromQueue) {
  if (__ipeEnded) return;
  if (!fromQueue && (__ipeEventQueue.length > 0 || __ipeEventInFlight)) {
    __ipeEnqueue(body, false);
    if (__ipeRetryTimer === null && !__ipeEventInFlight) __ipeDrainQueue();
    return;
  }
  var controller = typeof AbortController === "function" ? new AbortController() : null;
  var attempt = { body: body, bound: null };
  __ipeEventInFlight = attempt;
  attempt.bound = setTimeout(function() {
    __ipeSettle(attempt, __IPE_POST_SETTLED.RETRY);
    if (controller) controller.abort();
  }, __ipeEventAnswerBoundMs);
  // Phase 1.2 — attach the per-session CSRF token. The server-side
  // middleware () rejects POSTs
  // without a matching X-Ipe-Csrf / __ipe_csrf cookie pair. Empty
  // token means CSRF is disabled at the runtime level (package.ipe
  // [security] csrf = false) — header omitted, middleware skipped.
  var headers = {"Content-Type":"application/json"};
  if (__ipeCsrfToken) headers["X-Ipe-Csrf"] = __ipeCsrfToken;
  var json = JSON.stringify(body);
  var init = {
    method: "POST",
    headers: headers,
    body: json,
    credentials: "same-origin"
  };
  if (controller) init.signal = controller.signal;
  if (__ipeKeepAlive.has(body) && json.length <= __IPE_KEEPALIVE_BODY_MAX) init.keepalive = true;
  // An answer arm settles the attempt itself; one that throws, or a network
  // failure, ends at the RETRY below, a no-op once an arm has settled it.
  fetch(__ipeBase + "/_ipe/event", init)
    .then(function(r) { return __ipeOnEventAnswer(attempt, r); })
    .then(function() { __ipeSettle(attempt, __IPE_POST_SETTLED.RETRY); },
          function() { __ipeSettle(attempt, __IPE_POST_SETTLED.RETRY); });
}
// Act on the answer to `attempt`. Every arm settles it before acting, so the
// next event is sent and nothing the arm does afterwards can re-queue it.
function __ipeOnEventAnswer(attempt, r) {
  var body = attempt.body;
  var kind = __ipeEventAnswer(r);
  switch (kind) {
    case __IPE_EVENT_ANSWER.STALE:
      // The server refused the event's render epoch and sent the current
      // render. Apply it and end here: the refused event is never re-sent,
      // since its handler id may now name another handler. An unreadable
      // refusal still answers the event: the events queued behind it go.
      return r.json().then(function(data) {
        if (!__ipeSettle(attempt, __IPE_POST_SETTLED.ANSWERED)) return;
        __ipeOnPostSuccess();
        // The server answered the event: its values are no longer the
        // user's alone, and the render it sent is the view's.
        __ipeRetirePending(body.seq);
        if (!data || typeof data.body !== "string") return;
        // The epoch gate orders this render against the DOM on screen; the
        // seq it carries is the session's, which an earlier frame may equal.
        __ipeAdoptFullBody(data.epoch, function() { __ipePatch(data.body); }, data.route);
      }, function() {
        __ipeSettle(attempt, __IPE_POST_SETTLED.ANSWERED);
      });
    case __IPE_EVENT_ANSWER.SESSION_LOST:
      // The marked 404 no DOM may show. The probe confirms it and reloads,
      // and the event waits in the retry queue meanwhile.
      __ipeProbeSessionLost();
      __ipeSettle(attempt, __IPE_POST_SETTLED.RETRY);
      return;
    case __IPE_EVENT_ANSWER.TRANSIENT:
      // A timeout, a full queue, or a server or deploying edge that is up
      // but not answering: the same retry path as a network failure.
      __ipeSettle(attempt, __IPE_POST_SETTLED.RETRY);
      return;
    case __IPE_EVENT_ANSWER.TOO_LARGE:
      __ipeOnPostRefused(attempt, __IPE_EVENT_ANSWER.TOO_LARGE);
      return;
    case __IPE_EVENT_ANSWER.REFUSED:
      __ipeOnPostRefused(attempt, __IPE_EVENT_ANSWER.REFUSED);
      return;
    case __IPE_EVENT_ANSWER.ACCEPTED:
      break;
    default:
      throw new Error("unclassified event answer");
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
    throw new Error("non-ipe response");
  }
  if (!isJson) {
    // An accepted event is answered in JSON.
    throw new Error("non-json event response");
  }
  return r.json().then(function(data) {
    // Even JSON is rejected if it lacks the protocol shape (no
    // seq field): some proxies (Cloudflare access denied, fly.io
    // edge errors) return JSON error envelopes with 200 OK.
    if (ipeMark !== "1" && (!data || typeof data.seq === "undefined")) {
      throw new Error("non-ipe json response");
    }
    if (!__ipeSettle(attempt, __IPE_POST_SETTLED.ANSWERED)) return;
    __ipeOnPostSuccess();
    if (!data) return;
    // An accepted event's render arrives over the stream, whose frames
    // name the epochs they move between. Any patches an answer carries
    // have no epoch to gate on: they never apply. The answer's `seq` is
    // the session's commit count, not this tab's event seq, so it neither
    // retires a value nor moves the frame gate: folded there, it would drop
    // a `patch` frame (a reconnect's resync) of an equal or lower count.
    // The marked accept of this event ends every value it carries.
    if (ipeMark === "1" && typeof data.seq === "number") __ipeRetirePending(body.seq);
  });
}
// A refused event is never sent again. The values it carried are left out of
// every later event until the user edits them, the refusal is said, and the
// events queued behind it still go.
function __ipeOnPostRefused(attempt, kind) {
  if (!__ipeSettle(attempt, __IPE_POST_SETTLED.ANSWERED)) return;
  var sent = attempt.body.inputState;
  if (sent) {
    var ids = Object.keys(sent);
    for (var i = 0; i < ids.length; i++) {
      var e = __ipeInputs[ids[i]];
      if (e && sent[ids[i]]) e.refusedValue = sent[ids[i]].value;
    }
  } else {
    __ipeRefusedBare = true;
  }
  __ipeShowRefused(kind);
}
// True once an event that carried no input was refused, until an event is
// accepted.
var __ipeRefusedBare = false;
// The answer kind of the latest refusal, which its notice names.
var __ipeRefusedKind = null;
// True while a refusal still stands: a refused event carried no input and
// none has been accepted since, or an input on the page still shows the value
// a refused event carried.
function __ipeRefusalStands() {
  if (__ipeRefusedKind === null) return false;
  if (__ipeRefusedBare) return true;
  var ids = Object.keys(__ipeInputs);
  for (var i = 0; i < ids.length; i++) {
    var e = __ipeInputs[ids[i]];
    if (e.refusedValue === null || e.refusedValue !== e.liveValue) continue;
    var el = null;
    try { el = __ipeDoc.query("[ipe-id=" + __ipeCssString(ids[i]) + "]"); } catch (_) { el = null; }
    if (el) return true;
  }
  return false;
}
function __ipeOnPostSuccess() {
  // A successful POST proves the server reachable — clear any
  // backoff state. Its settle already sent the next event.
  __ipeRetryAttempts = 0;
  __ipeReconnectSince = 0;  // reopen the fast-reconnect window for the next drop
  __ipeRefusedBare = false;
  if (__ipeRetryTimer !== null) {
    clearTimeout(__ipeRetryTimer);
    __ipeRetryTimer = null;
  }
  // A refusal that still stands keeps its notice (__ipeSetStatus).
  if (__ipeStatus !== "connected") {
    __ipeSetStatus("connected", "");
  }
  // SSE recovery: if the watchdog tore down the EventSource (offline
  // terminal state), a successful POST proves the network is back, so
  // reopen the stream too — otherwise subscriptions and Cmd.perform
  // results would silently not arrive even though clicks work. Cancel
  // any pending reopen-with-backoff and bring it forward.
  if (__ipeSSE === null && __ipeLiveOwnsStream()) {
    if (__ipeSseReopenTimer !== null) {
      clearTimeout(__ipeSseReopenTimer);
      __ipeSseReopenTimer = null;
    }
    __ipeOpenSSE();
  }
}
// Queue `body` for a retry: at the head for the queue's own head, which keeps
// its place, else at the tail. An input event appended right behind one of
// the same key replaces it (__ipeCoalesceKey), so typing while an event is
// in flight queues one event per field. At the cap the oldest event behind
// the head is dropped, so the user's most recent intent is preserved.
function __ipeEnqueue(body, atHead) {
  var key = __ipeCoalesceKey.get(body);
  var tail = __ipeEventQueue.length > 0 ? __ipeEventQueue[__ipeEventQueue.length - 1] : null;
  if (!atHead && key !== undefined && tail !== null && __ipeCoalesceKey.get(tail) === key) {
    __ipeEventQueue.pop();
    __ipeFocusTakeSent(tail.seq);
  }
  if (__ipeEventQueue.length >= __ipeEventQueueMax) {
    var dropped = __ipeEventQueue.shift();
    if (window.console && console.warn) {
      console.warn("[ipe.live] event queue at cap; dropped oldest", dropped);
    }
  }
  if (atHead) __ipeEventQueue.unshift(body);
  else __ipeEventQueue.push(body);
}
function __ipeShowReconnecting() {
  if (__ipeStatus === "offline") return;
  // Dev blue-green: a drop inside the fast-reconnect window is almost always a
  // rebuild cutover, not an outage — stay quiet and let the "updated ✓" toast
  // fire when the new binary answers. If the reconnect does NOT land inside the
  // window (a genuine connection loss), we fall through to the amber banner.
  if (__ipeSwapToast && __ipeInFastReconnect()) return;
  if (__ipeConnectionStatus() === "connected") {
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
  if (__ipeEnded) return;
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
  if (__ipeEnded) return;
  if (__ipeEventInFlight) return;
  if (__ipeEventQueue.length === 0) return;
  // Send the head of the queue. Its settle sends the next one once it is
  // answered. If it fails,
  // the body re-enters the queue at its head and the retry loop kicks
  // back in. Order is preserved (FIFO): one queued event is in flight
  // at a time, and a live send waits behind the queue.
  var head = __ipeEventQueue.shift();
  __ipePostEvent(head, true);
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
  if (__ipeStale || !patches || patches.length === 0) return;
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
  var openSel = __ipeSelectOpen() ? __ipeDoc.active() : null;
  for (var i = 0; i < patches.length; i++) {
    var p = patches[i];
    var el = __ipeDoc.query("[ipe-id=" + __ipeCssString(String(p.id)) + "]");
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
        __ipeNode.setText(el, p.text);
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
      var elTag = __ipeNode.tag(el);
      var isInputLike = elTag === "INPUT" || elTag === "TEXTAREA";
      var hadFocus = isInputLike && el === __ipeDoc.active();
      var savedSelStart = null, savedSelEnd = null, savedSelDir = "none", savedScrollTop = 0;
      if (hadFocus) {
        try {
          savedSelStart = el.selectionStart;
          savedSelEnd = el.selectionEnd;
          savedSelDir = el.selectionDirection || "none";
        } catch (_) {}
        savedScrollTop = el.scrollTop;
      }
      var valueChanged = false;
      var wroteAuthority = false;
      var framePlan = __ipeFramePlan(el, p.attrs);
      for (var f = 0; f < framePlan.length; f++) {
        if (framePlan[f][1] === null) __ipeNode.removeAttr(el, framePlan[f][0]);
        else __ipeNode.setAttr(el, framePlan[f][0], framePlan[f][1]);
      }
      var frameKeys = __ipeFramePatchKeys(elTag);
      for (var j = 0; j < keys.length; j++) {
        var k = keys[j], v = p.attrs[k];
        // No `autofocus` reaches a live node: a later move would focus it.
        if (String(k).toLowerCase() === "autofocus") {
          __ipeNode.removeAttr(el, k);
          continue;
        }
        // A frame key is written by the frame plan above, never alone.
        if (frameKeys.indexOf(__ipeAsciiLower(k)) !== -1) continue;
        // Authority filter: the user owns this field's value until the
        // server has answered the event carrying it, so the server's
        // proposed value/checked/selected would stomp in-flight
        // keystrokes. Drop them; the render after that answer settles it.
        var authority = __ipeIsAuthorityAttr(k);
        if (dirty && authority) continue;
        if (authority) wroteAuthority = true;
        var prop = Object.prototype.hasOwnProperty.call(__IPE_LIVE_PROPS, k)
            ? __IPE_LIVE_PROPS[k] : null;
        // A removal crosses as null; a set as a string, the empty string
        // included. Any other shape is refused.
        if (v === null) {
          __ipeNode.removeAttr(el, k);
          if (prop !== null) el[prop] = false;
        } else if (typeof v !== "string") {
          continue;
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
      if (wroteAuthority) __ipeResyncField(el);
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
        try { el.setSelectionRange(s, e, savedSelDir); } catch (_) {}
        if (savedScrollTop) el.scrollTop = savedScrollTop;
      }
    }
  }
  // Any new ipe-* attribute in the patched DOM needs a listener.
  __ipeBindEvents();
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
  return __ipeIsField(a);
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
// The events a node binds through an `ipe-<event>` attribute; the user acts
// (`__IPE_USER_ACTS`) are a subset of them.
var __IPE_BOUND_EVENTS = ["click", "dblclick", "input", "change", "submit", "focus", "blur",
                          "keydown", "keyup", "keypress", "mouseover", "mouseout",
                          "mousedown", "mouseup"];
function __ipeBindEvents() {
  for (var i = 0; i < __IPE_BOUND_EVENTS.length; i++) {
    __ipeBindOne(__IPE_BOUND_EVENTS[i]);
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
      var focus   = __ipeUserActEpoch(ev);
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
          e.edited = true;
        }
        __ipeDebouncedSend(msgName, args, hid, 150, epoch, focus);
        return;
      }
      __ipeSend(msgName, args, hid, { epoch: epoch, focus: focus });
    });
  }
}

// Extract the args array for a DOM event following the legacy Ipe.Web
// convention:
//   * click / focus / blur / mouse*    → []         (just the msg)
//   * input / change                   → [value]    (typed input value)
//   * submit                           → [formData] (plain object of [name]=value)
//   * keydown / keyup / keypress       → [key]      (event.key string)
// The value the field `t` shows, as an input or change event posts it: a
// checkbox or radio's checkedness, a number or range's number, otherwise
// its text.
function __ipeFieldValue(t) {
  if (t.type === "checkbox" || t.type === "radio") return t.checked;
  if (t.type === "number" || t.type === "range") return t.valueAsNumber || 0;
  return t.value == null ? "" : String(t.value);
}

function __ipeExtractArgs(ev) {
  var t = ev.target;
  switch (ev.type) {
    case "input":
    case "change":
      return [t ? __ipeFieldValue(t) : ""];
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
  // Read with the id and at the pick, before the asynchronous read below: the
  // user may move focus while the file is read.
  var epoch   = __ipeEpoch;
  var focus   = __ipeUserActEpoch(ev);
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
    r.onload = function(e) {
      __ipeSend(fileEv, [e.target.result], hid, { epoch: epoch, focus: focus });
    };
    r.readAsDataURL(f);
  }
  if (imageEv) {
    var maxW = parseInt(el.getAttribute("data-ipe-ev-ipe-file-max-width")  || "1200");
    var maxH = parseInt(el.getAttribute("data-ipe-ev-ipe-file-max-height") || "1200");
    __ipeResizeImage(f, maxW, maxH, function(dataUrl) {
      // Same wire-format reason as the onFile branch — wrap in array.
      __ipeSend(imageEv, [dataUrl], hid, { epoch: epoch, focus: focus });
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
// at the call. A page script may call it with no user act, so its event keeps
// no focus record and its render moves no focus.
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
  if (__ipeEnded) return;
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
// The epoch, as parts, of the newest navigation answer or render whose
// location the URL records; null before any.
var __ipeNavEpoch = null;
// The one writer of the document's history. Record `url`, the location the
// navigation answer or render at epoch `at` names: a new history entry when
// `push` (none when `url` is already the location), otherwise the current
// entry rewritten. A location older than the one recorded is refused: the
// driver enters routes in order, so the newest answer or render names the
// route every later render shows, whatever order the answers arrive in.
function __ipeRecordNav(url, push, at) {
  if (__ipeStale) return;
  if (__ipeNavEpoch && __ipeCounterOrder(at, __ipeNavEpoch) < 0) return;
  __ipeNavEpoch = at;
  try {
    if (!push) window.history.replaceState({}, "", url);
    else if (new URL(url, window.location.href).href !== window.location.href) {
      window.history.pushState({}, "", url);
    }
  } catch (_) {}
  __ipeNavPath   = window.location.pathname;
  __ipeNavSearch = window.location.search;
  __ipeNavHref   = window.location.href;
}
// The newest navigation the reader started, a followed link or a popped
// entry, by sequence number; and its target while its answer is pending,
// otherwise null.
var __ipeNavIntent = 0;
var __ipeNavWanted = null;
// Start a navigation to `url`; its sequence number.
function __ipeStartNav(url) {
  __ipeNavIntent += 1;
  __ipeNavWanted = url;
  return __ipeNavIntent;
}
// Navigation `intent` got an answer this document orders: its target is no
// longer pending.
function __ipeSettleNav(intent) {
  if (intent === __ipeNavIntent) __ipeNavWanted = null;
}
// The document an absolute `href` loads: `href` without its fragment. A
// serialized URL's first `#` opens its fragment.
function __ipeDocumentOf(href) {
  var at = href.indexOf("#");
  return at < 0 ? href : href.slice(0, at);
}
// A full browser load of `url` that leaves the reader on `url`. The location
// itself reloads. A target with a fragment on the document on screen is a
// fragment navigation, which moves the location and adds its entry at once
// but loads nothing, so the now-current target then reloads. Any other target
// is a full load of its own, which a reload queued behind it would cancel.
function __ipeLoad(url) {
  var target = url;
  try { target = new URL(url, window.location.href).href; } catch (_) {}
  var here = window.location.href;
  if (target === here) {
    window.location.reload();
  } else if (target.indexOf("#") >= 0 && __ipeDocumentOf(target) === __ipeDocumentOf(here)) {
    window.location.assign(target);
    window.location.reload();
  } else {
    window.location.assign(target);
  }
}
// Navigation `intent` has no answer this document can show: the browser loads
// its own target `url`, never the location, which a later answer or render
// may have moved meanwhile. A navigation started since owns the location, so
// an older one loads nothing.
function __ipeLoadNav(intent, url) {
  if (intent !== __ipeNavIntent) return;
  __ipeNavWanted = null;
  __ipeLoad(url);
}
// Reload the document where the reader is going: the target of the pending
// navigation, otherwise the location. The reload is the newest navigation, so
// no answer to an earlier one loads anything after it. An ended session
// reloads nothing, so its notice stays on screen.
function __ipeReloadDocument() {
  if (__ipeEnded) return;
  var wanted = __ipeNavWanted;
  __ipeNavIntent += 1;
  __ipeNavWanted = null;
  if (typeof wanted === "string") __ipeLoad(wanted);
  else window.location.reload();
}
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
  // Bound reads: a `<form>` with a control named `parentElement` answers that
  // read with the control, whose parent is the form again, so the walk loops.
  while (el && __ipeNode.tag(el) !== "A") el = __ipeNode.parent(el);
  if (!el) return;
  if (!el.hasAttribute("ipe-nav")) return;
  // A link that opens elsewhere or downloads is the browser's to follow.
  var linkTarget = el.getAttribute("target");
  if (linkTarget && linkTarget.toLowerCase() !== "_self") return;
  if (el.hasAttribute("download")) return;
  // A stale document applies no render, so its links are left to the
  // browser, whose full load joins the live history.
  if (__ipeStale) return;
  var href = el.getAttribute("href");
  if (!href || href.charAt(0) === "#") return;
  // External links are left to the browser. The link's target is fixed now:
  // a later answer or render may move the location `href` is relative to.
  var target;
  try {
    var u = new URL(href, window.location.href);
    if (u.origin !== window.location.origin) return;
    target = u.href;
  } catch (e) { return; }
  ev.preventDefault();
  var intent = __ipeStartNav(target);
  fetch(target, { headers: { "X-Ipe-Nav": "1" }, credentials: "same-origin" })
    .then(function(r) {
      var url = __ipeFollowed(r, target);
      var epoch = r.headers.get("X-Ipe-Epoch");
      var route = r.headers.get("X-Ipe-Route");
      return r.text().then(function(t) { return { t: t, url: url, epoch: epoch, route: route }; });
    })
    .then(function(res) {
      // An answer of no history or of another one is not this document's to
      // show, and a stale document shows none: the browser loads the link
      // itself, so the document it gets carries the policy that answer's
      // styles need.
      var next = __ipeEpochParts(res.epoch);
      if (!next || next.inc !== __ipeBootInc || __ipeStale) {
        __ipeLoadNav(intent, target);
        return;
      }
      // The answer's URL is recorded, unless a later answer or render already
      // named the location; the answer then applies unless the screen already
      // shows a later render, and its route rewrites the entry just recorded.
      __ipeSettleNav(intent);
      __ipeRecordNav(res.url, true, next);
      __ipeAdoptFullBody(res.epoch, function() { __ipePatch(res.t, "nav"); }, res.route);
    })
    .catch(function() { __ipeLoadNav(intent, target); });
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
  // The popped entry, fixed now: the live location moves with any later
  // navigation, or answer or render recorded while this one is pending.
  var popped = here.href;
  var intent = __ipeStartNav(popped);
  // A stale document applies no render: the browser loads the popped entry,
  // as it follows a stale document's links.
  if (__ipeStale) {
    __ipeLoadNav(intent, popped);
    return;
  }
  fetch(popped, { headers: { "X-Ipe-Nav": "1" }, credentials: "same-origin" })
    .then(function(r) {
      var url = __ipeFollowed(r, popped);
      var epoch = r.headers.get("X-Ipe-Epoch");
      var route = r.headers.get("X-Ipe-Route");
      return r.text().then(function(t) { return { t: t, url: url, epoch: epoch, route: route }; });
    })
    .then(function(res) {
      // An answer of no history or of another one is not this document's to
      // show, and a stale document shows none: the browser loads the entry
      // itself, as it follows such an answer to a link.
      var next = __ipeOwnEpoch(res.epoch);
      if (!next || __ipeStale) {
        __ipeLoadNav(intent, popped);
        return;
      }
      // The answer rewrites the current entry to its URL, unless a later
      // answer or render already named the location, then to its route.
      __ipeSettleNav(intent);
      __ipeRecordNav(res.url, false, next);
      __ipeAdoptFullBody(res.epoch, function() { __ipePatch(res.t, "nav"); }, res.route);
    })
    // With no answer to show, the browser loads the popped entry itself.
    .catch(function() { __ipeLoadNav(intent, popped); });
});
// The served page's route rewrites the entry it was served at.
__ipeSyncRoute(__ipeBoot["route"], false, __ipeOwnEpoch(__ipeEpoch));
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
// The connection state the banner stands for. A refusal notice is drawn over a
// connection that is up, so it reads as "connected": a dropped connection
// replaces it, and another tab mirrors the connection, never this tab's notice.
function __ipeConnectionStatus() {
  return __ipeStatus === "refused" ? "connected" : __ipeStatus;
}
function __ipeSetStatus(state, msg) {
  // A stale document keeps its banner: no later state replaces it.
  if (__ipeStale) return;
  // A refusal that still stands keeps its notice over a recovered connection.
  if (state === "connected" && __ipeRefusalStands()) {
    __ipeShowRefused(__ipeRefusedKind);
    return;
  }
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
  __ipeStatusEl.removeAttribute("data-ipe-refused");
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
// Show the offline banner on a stale document. It ignores the banner setting:
// a page that has stopped applying updates always says so.
function __ipeShowStale() {
  if (__ipeBuildOkTimer !== null) {
    clearTimeout(__ipeBuildOkTimer);
    __ipeBuildOkTimer = null;
  }
  __ipeStatus = "offline";
  function show() {
    if (!__ipeStatusEl) {
      var built = __ipeBuildStatusEl("offline");
      __ipeDoc.body().appendChild(built.el);
      __ipeStatusEl = built.el;
      __ipeStatusMsgEl = built.msgEl;
    }
    __ipeStatusEl.className = "ipe-status ipe-status--offline";
    __ipeStatusMsgEl.textContent = "Page is out of date \u2014 reload";
  }
  if (__ipeDoc.body()) show();
  else __ipeDoc.on("DOMContentLoaded", show);
}
// The notice for a session the server closed, by the frame's tag. The text is
// the client's own: the tag only picks it, and a tag outside this set gets the
// generic notice.
function __ipeClosedNotice(tag) {
  switch (tag) {
    case "over_ceiling":
      return "This page grew past its session limit and was closed \u2014 reload to start over";
    case "revoked":
      return "Your sign-in is no longer valid \u2014 reload to sign in again";
    case "ended":
      return "This session has ended \u2014 reload to start a new one";
    default:
      return "This session was closed \u2014 reload to start a new one";
  }
}
// The notice for an event the server refused, by its answer kind. The text is
// the client's own, and a kind outside this set gets the generic notice.
function __ipeRefusedNotice(kind) {
  switch (kind) {
    case __IPE_EVENT_ANSWER.TOO_LARGE:
      return "This change is too large to send and was not saved \u2014 shorten it and try again";
    case __IPE_EVENT_ANSWER.REFUSED:
      return "The server refused this action and did not apply it \u2014 reload the page";
    default:
      return "The server did not apply this action \u2014 reload the page";
  }
}
// Show the notice for a refused event. It ignores the banner setting: a write
// the server refused is always said. A stale or ended document keeps its own
// banner.
function __ipeShowRefused(kind) {
  if (__ipeEnded || __ipeStale) return;
  if (__ipeBuildOkTimer !== null) {
    clearTimeout(__ipeBuildOkTimer);
    __ipeBuildOkTimer = null;
  }
  __ipeStatus = "refused";
  __ipeRefusedKind = kind;
  var notice = __ipeRefusedNotice(kind);
  function show() {
    if (__ipeStatus !== "refused") return;
    if (!__ipeStatusEl) {
      var built = __ipeBuildStatusEl("offline");
      __ipeDoc.body().appendChild(built.el);
      __ipeStatusEl = built.el;
      __ipeStatusMsgEl = built.msgEl;
    }
    __ipeStatusEl.className = "ipe-status ipe-status--offline";
    __ipeStatusEl.setAttribute("data-ipe-refused", kind);
    __ipeStatusMsgEl.textContent = notice;
  }
  if (__ipeDoc.body()) show();
  else __ipeDoc.on("DOMContentLoaded", show);
}
// End this document's session for good: the server closed it, so no reopen,
// retry, probe or reload can bring it back. The banner tells the reader why
// and the document stays as it is.
function __ipeEndSession(tag) {
  if (__ipeEnded) return;
  __ipeEnded = true;
  __ipeStale = true;
  __ipeProbedReload = true;
  __ipeCloseSSE();
  __ipeSetLive(false);
  __ipeHelloOk = false;
  if (__ipeRetryTimer !== null) {
    clearTimeout(__ipeRetryTimer);
    __ipeRetryTimer = null;
  }
  if (__ipeStatusGraceTimer !== null) {
    clearTimeout(__ipeStatusGraceTimer);
    __ipeStatusGraceTimer = null;
  }
  if (__ipeBuildOkTimer !== null) {
    clearTimeout(__ipeBuildOkTimer);
    __ipeBuildOkTimer = null;
  }
  __ipeEventQueue.length = 0;
  __ipeLoaderEnd();
  __ipeStatus = "offline";
  var notice = __ipeClosedNotice(tag);
  function show() {
    if (!__ipeStatusEl) {
      var built = __ipeBuildStatusEl("offline");
      __ipeDoc.body().appendChild(built.el);
      __ipeStatusEl = built.el;
      __ipeStatusMsgEl = built.msgEl;
    }
    __ipeStatusEl.className = "ipe-status ipe-status--offline";
    __ipeStatusEl.setAttribute("data-ipe-closed", "1");
    __ipeStatusMsgEl.textContent = notice;
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
// Frame envelope: {seq, body, ...}. Falls back to
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
var __ipeOpenStartedAt = 0;   // ms timestamp of the last __ipeOpenSSE
var __ipeLastSseAt = 0;       // ms timestamp of any SSE event
var __ipeHelloOk = false;     // server sent its handshake this connection
var __ipeWatchdogTimer = null;
var __ipeSseReopenTimer = null;
var __ipeForcedClose = false; // true while we're tearing down to reopen
// data-ipe-live on <html> is the app's deterministic readiness signal: "1"
// exactly while the session's SSE handshake is live (this tab's own stream, or
// the leader tab's it follows), "0" otherwise. The server binds
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
  if (__ipeEnded) return;
  // Only the tab that holds the session's stream opens one (see "One live
  // stream per session" below).
  if (!__ipeLiveOwnsStream()) return;
  __ipeSetLive(false);
  __ipeOpenStartedAt = Date.now();
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
  __ipeLiveRelayed.forEach(function(type) {
    __ipeSSE.addEventListener(type, function(e) {
      __ipeLiveRelay(type, e.data);
      __ipeLiveFrames[type](e.data, false);
    });
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
    if (__ipeEnded) return;
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
    if (__ipeConnectionStatus() !== "connected") return;
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
}
// The handlers of the stream frames a leader relays, keyed by event type. Each
// takes the frame text and whether it came relayed from the leader tab. A
// frame retires pending input values only when its `tab` names this tab,
// relayed or not.
var __ipeLiveFrames = {
  hello: function(text, relayed) {
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
  },
  heartbeat: function(text, relayed) {
    __ipeLastSseAt = Date.now();
  },
  patch: function(text, relayed) {
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
    // Every patch frame is JSON carrying its epoch; any other payload has no
    // render history to gate on and is dropped.
    try { frame = JSON.parse(text); } catch (_) { return; }
    if (frame && typeof frame === "object") {
      __ipeHandleResponse(frame.seq, function() {
        __ipeRetireOwnFrame(frame);
        if (!frame.body) return;
        var body = frame.body.replace(/\\n/g, "\n");
        var apply = function() {
          __ipeAdoptFullBody(frame.epoch, function() { __ipePatch(body); }, frame.route);
        };
        if (__ipeSelectOpen()) __ipeHoldRender(apply);
        else {
          // This render supersedes any held one and any patches it missed.
          __ipeHeldRender = null;
          apply();
        }
      }, frame.globalSeq);
    }
  },
  // Cycle 3 P50b / Gap C11 — structural-patches SSE event.
  //
  // The producer (Cycle 3 P50a) now ships event:patches for any
  // render whose diff against the previous tree fits in a small
  // patch list (the typical 1-3 attribute/text node change at
  // ~200-1000 B, vs the ~14 KB full body). The legacy event:patch
  // handler above stays for first-renders, reconnect-resync,
  // full-replace fallbacks, and any pre-P50a server.
  //
  // A frame of this tab's own event names it as {tab, tabSeq}: its
  // render follows that event's dispatch, so it ends the values that
  // event carries before the patches apply. seq-gating via __ipeHandleResponse means out-of-
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
  patches: function(text, relayed) {
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
    try { frame = JSON.parse(text); }
    catch (_) {
      // Producer guarantees JSON for event:patches; a non-JSON
      // payload is impossible from a P50a+ server. Drop silently
      // rather than running __ipePatch on garbage.
      return;
    }
    if (__ipeStale || !frame || typeof frame !== "object" || !frame.patches) return;
    // The patches diff the render `from` against `to`: they apply only onto
    // the DOM of `from`. Another render of this history resyncs through a
    // fresh SSE open, whose first frame is the full current render; a frame
    // either end of which is not of this history leaves the document stale.
    var step = __ipePatchStep(frame.from, frame.to);
    if (step === "foreign") {
      __ipeStaleDocument();
      return;
    }
    if (step === "behind") {
      if (__ipeSelectOpen()) __ipeMarkHeldStale();
      else {
        __ipeHeldRender = null;
        __ipeResyncRender();
      }
      return;
    }
    __ipeHandleResponse(frame.seq, function() {
      __ipeRetireOwnFrame(frame);
      __ipeAdoptPatches(frame);
    }, frame.globalSeq);
  },
  // Dev-watch blue-green cutover cue. The watch server sends this right after
  // `hello` on every open when running behind the proxy. It is redundant with
  // the hello-based reconnect detection above (kept as an explicit, named
  // signal), so it is likewise gated on a PRIOR hello — the first-load frame
  // draws nothing. Never emitted by a release / `ipe dev run` server.
  swapped: function(text, relayed) {
    __ipeLastSseAt = Date.now();
    if (__ipeSwapToast && __ipeHelloEverOk) __ipeShowSwapToast();
  },
  // Dev-only build-status event: server pushes this when `ipe dev watch`
  // reports a compile or cargo failure, and when a subsequent build
  // succeeds. Only reachable when `ipe dev watch` is running; never
  // triggered in production (the POST endpoint is not mounted there).
  "ipe-build-status": function(text, relayed) {
    var data;
    try { data = JSON.parse(text); } catch(_) { return; }
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
  },
  // The server closed the session; the data is the reason's tag. It is the
  // stream's last frame.
  closed: function(text, relayed) {
    __ipeEndSession(text);
  }
};

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
// A tab that follows another's stream asks the leader to reopen instead.
function __ipeResyncRender() {
  if (__ipeEnded) return;
  if (!__ipeLiveOwnsStream()) {
    __ipeLiveAskResync();
    return;
  }
  __ipeCloseSSE();
  __ipeOpenSSE();
}
// Close this tab's own stream, if any, and cancel a queued reopen.
function __ipeCloseSSE() {
  __ipeForcedClose = true;
  try { if (__ipeSSE) __ipeSSE.close(); } catch (_) {}
  __ipeSSE = null;
  if (__ipeSseReopenTimer !== null) {
    clearTimeout(__ipeSseReopenTimer);
    __ipeSseReopenTimer = null;
  }
}
function __ipeForceReopenSSE() {
  if (__ipeEnded) return;
  if (!__ipeLiveOwnsStream()) return;
  __ipeForcedClose = true;
  __ipeSetLive(false);
  try { if (__ipeSSE) __ipeSSE.close(); } catch (_) {}
  __ipeSSE = null;
  if (__ipeConnectionStatus() === "connected") {
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
  if (__ipeEnded || __ipeProbedReload) return;
  var headers = {"Content-Type": "application/json"};
  if (__ipeCsrfToken) headers["X-Ipe-Csrf"] = __ipeCsrfToken;
  fetch(__ipeBase + "/_ipe/event", {
    method: "POST",
    headers: headers,
    body: JSON.stringify({sessionId: __ipeSid, msg: "__ipeSessionPing", args: []}),
    credentials: "same-origin"
  }).then(function(r) {
    if (__ipeEventAnswer(r) !== __IPE_EVENT_ANSWER.SESSION_LOST) return;
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
      __ipeReloadDocument();
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
  if (__ipeEnded) return;
  __ipeReleaseHeldRender(false);
  // A follower watches the leader instead of a stream of its own.
  if (__ipeLiveRole === "follower") {
    __ipeLiveMaybeSteal();
    return;
  }
  if (!__ipeLiveOwnsStream()) return;
  __ipeLiveBeat();
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

// ── One live stream per session ──────────────────────────────
// A browser keeps at most 6 HTTP/1.1 connections per host, and an open
// EventSource holds one for as long as the page lives. With one stream per
// tab, the 7th tab of an origin waits forever for a connection to fetch its
// page. So the tabs of one session share ONE stream: a Web Lock named after
// the session elects the tab that opens it (the leader), and the leader
// relays each frame over a BroadcastChannel of the same name to the other
// tabs (the followers), whatever the tab count.
//   - A closed or discarded tab drops its lock with it; the next tab in the
//     lock's queue is granted it and opens the stream.
//   - A visible follower takes the lock from a leader that has been hidden
//     for __ipeHelloTimeoutMs, or that has gone quiet: a background tab may
//     be throttled or frozen, and must not starve the tab on screen.
//   - A focused follower takes the lock from a leader without focus. The
//     stream's `?path=` sets the session's route and its `port` frames run in
//     the tab that holds it, so the tab the user works in holds it. Focus is
//     one tab's at a time, so two tabs never take it from each other in turn.
//   - `port` frames stay with the leader: exactly one tab runs each outbound
//     port Cmd.
//   - A follower applies a body-changing frame only when the leader shows the
//     same path, so a tab never takes another route's render.
// A browser without Web Locks or BroadcastChannel (an insecure context) keeps
// one stream per tab ("solo").
var __ipeLiveRelayed = ["hello", "heartbeat", "patch", "patches", "swapped", "ipe-build-status", "closed"];
var __ipeLiveStatuses = ["connected", "reconnecting", "offline"];
var __ipeLiveName = typeof __ipeSid === "string" && __ipeSid !== ""
    ? "ipe-live:" + __ipeBase + ":" + __ipeSid
    : null;
var __ipeLiveLocks = (function() {
  try {
    var locks = navigator.locks;
    return locks && typeof locks.request === "function" ? locks : null;
  } catch (_) { return null; }
})();
// "stopped" (before boot, and while the page is hidden in the back-forward
// cache), "solo", "leader" or "follower".
var __ipeLiveRole = "stopped";
// Bumped on every role change: a lock callback or rejection of an older
// request is ignored.
var __ipeLiveGen = 0;
var __ipeLiveQueued = null;      // AbortController of the queued lock request
var __ipeLiveRelease = null;     // releases the held lock
var __ipeLiveChan = null;
var __ipeLeaderAt = 0;           // ms of the last message from the leader
var __ipeLeaderHiddenSince = 0;  // ms the leader first reported hidden; 0 while visible
var __ipeLeaderUnfocused = false; // the leader's last beat reported no focus
var __ipeResyncAskedAt = 0;      // follower: ms of the last resync request
var __ipeResyncPending = false;  // leader: a resync reopen whose full render has not landed
// Whether this document has focus; a browser without the member never claims it.
function __ipeHasFocus() {
  try { return __ipeDoc.hasFocus() === true; } catch (_) { return false; }
}
function __ipeLiveOwnsStream() {
  return __ipeLiveRole === "leader" || __ipeLiveRole === "solo";
}
function __ipeLivePost(msg) {
  if (__ipeLiveChan === null) return;
  try { __ipeLiveChan.postMessage(msg); } catch (_) {}
}
// Leader: hand a frame of its own stream to the followers.
function __ipeLiveRelay(type, text) {
  if (type === "patch") __ipeResyncPending = false;
  if (__ipeLiveRole !== "leader") return;
  __ipeLivePost({ t: "ev", type: type, data: text, path: location.pathname });
}
// Leader: tell the followers whether the stream is live and the tab visible.
function __ipeLiveBeat() {
  if (__ipeLiveRole !== "leader") return;
  __ipeLivePost({
    t: "beat",
    live: __ipeHelloOk,
    visible: __ipeDoc.visibility() !== "hidden",
    focused: __ipeHasFocus(),
    status: __ipeConnectionStatus()
  });
}
function __ipeLiveAskResync() {
  var now = Date.now();
  if (now - __ipeResyncAskedAt < __ipeHelloTimeoutMs) return;
  __ipeResyncAskedAt = now;
  __ipeLivePost({ t: "resync" });
}
// Follower: take the leader's liveness and connection state as its own.
function __ipeLiveMirror(live, status) {
  if (live && !__ipeHelloOk) {
    __ipeHelloOk = true;
    __ipeHelloEverOk = true;
    __ipeSetLive(true);
    if (__ipeEventQueue.length > 0) __ipeDrainQueue();
  } else if (!live && __ipeHelloOk) {
    __ipeHelloOk = false;
    __ipeSetLive(false);
  }
  var mine = __ipeConnectionStatus();
  if (status === mine) return;
  if (__ipeLiveStatuses.indexOf(status) < 0 || __ipeLiveStatuses.indexOf(mine) < 0) return;
  if (status === "connected") __ipeSetStatus("connected", "");
  else if (status === "reconnecting") __ipeSetStatus("reconnecting", __ipeMsgReconnecting);
  else __ipeSetStatus("offline", __ipeMsgOffline);
}
// Every message is checked for its shape: any script of the origin can post
// on the channel.
function __ipeLiveOnMessage(ev) {
  var m = ev ? ev.data : null;
  if (!m || typeof m !== "object" || typeof m.t !== "string") return;
  if (m.t === "ask") {
    __ipeLiveBeat();
    return;
  }
  if (m.t === "resync") {
    // A stream that is not live yet sends the full render when it opens, and
    // one reopen answers every request until its full render lands.
    if (__ipeLiveRole !== "leader" || !__ipeHelloOk) return;
    if (__ipeResyncPending && Date.now() - __ipeOpenStartedAt < __ipeHelloTimeoutMs) return;
    __ipeResyncPending = true;
    __ipeResyncRender();
    return;
  }
  if (__ipeLiveRole !== "follower") return;
  if (m.t === "ev") {
    if (typeof m.type !== "string" || __ipeLiveRelayed.indexOf(m.type) < 0) return;
    if (typeof m.data !== "string" || typeof m.path !== "string") return;
    __ipeLeaderAt = Date.now();
    if ((m.type === "patch" || m.type === "patches") && m.path !== location.pathname) return;
    __ipeLiveFrames[m.type](m.data, true);
    return;
  }
  if (m.t === "beat") {
    if (typeof m.live !== "boolean" || typeof m.visible !== "boolean") return;
    if (typeof m.focused !== "boolean" || typeof m.status !== "string") return;
    var now = Date.now();
    __ipeLeaderAt = now;
    __ipeLeaderUnfocused = !m.focused;
    if (m.visible) __ipeLeaderHiddenSince = 0;
    else if (__ipeLeaderHiddenSince === 0) __ipeLeaderHiddenSince = now;
    __ipeLiveMirror(m.live, m.status);
    __ipeLiveMaybeSteal();
  }
}
// Queue for the session's lock, or take it from its holder (`steal`).
function __ipeLiveRequest(steal) {
  var gen = __ipeLiveGen;
  var opts;
  if (steal) {
    opts = { steal: true };
  } else {
    __ipeLiveQueued = new AbortController();
    opts = { signal: __ipeLiveQueued.signal };
  }
  var held;
  try {
    held = __ipeLiveLocks.request(__ipeLiveName, opts, function() {
      // An outdated request releases the lock at once.
      if (gen !== __ipeLiveGen) return undefined;
      return new Promise(function(release) {
        __ipeLiveRelease = release;
        __ipeLiveLead();
      });
    });
  } catch (_) {
    __ipeLiveSolo();
    return;
  }
  held.then(function() {}, function() {
    if (gen !== __ipeLiveGen) return;
    // The held lock was taken: hand the stream over and queue again.
    if (__ipeLiveRole === "leader") __ipeLiveFollow();
    // A request refused for any other reason leaves no election.
    else if (__ipeLiveRole === "follower") __ipeLiveSolo();
  });
}
function __ipeLiveLead() {
  __ipeLiveRole = "leader";
  __ipeLiveQueued = null;
  __ipeResyncPending = false;
  __ipeOpenSSE();
  __ipeLiveBeat();
}
function __ipeLiveFollow() {
  __ipeLiveGen++;
  __ipeLiveRelease = null;
  __ipeCloseSSE();
  __ipeLiveRole = "follower";
  __ipeLeaderAt = Date.now();
  __ipeLeaderHiddenSince = 0;
  __ipeLeaderUnfocused = false;
  __ipeLiveRequest(false);
  __ipeLivePost({ t: "ask" });
}
function __ipeLiveSolo() {
  __ipeLiveGen++;
  __ipeLiveDropLock();
  if (__ipeLiveChan !== null) {
    try { __ipeLiveChan.close(); } catch (_) {}
    __ipeLiveChan = null;
  }
  __ipeLiveRole = "solo";
  if (__ipeSSE === null) __ipeOpenSSE();
}
function __ipeLiveDropLock() {
  if (__ipeLiveQueued !== null) {
    try { __ipeLiveQueued.abort(); } catch (_) {}
    __ipeLiveQueued = null;
  }
  if (__ipeLiveRelease !== null) {
    var release = __ipeLiveRelease;
    __ipeLiveRelease = null;
    release();
  }
}
// Follower: take the lock from a leader that is hidden or silent.
function __ipeLiveMaybeSteal() {
  if (__ipeLiveRole !== "follower") return;
  var now = Date.now();
  var quiet = now - __ipeLeaderAt;
  var take;
  if (__ipeDoc.visibility() === "hidden") {
    take = quiet > 3 * __ipeHeartbeatTtlMs;
  } else {
    take = quiet > __ipeHeartbeatTtlMs ||
        (__ipeLeaderHiddenSince > 0 && now - __ipeLeaderHiddenSince >= __ipeHelloTimeoutMs) ||
        (__ipeLeaderUnfocused && __ipeHasFocus());
  }
  if (!take) return;
  __ipeLiveGen++;
  if (__ipeLiveQueued !== null) {
    try { __ipeLiveQueued.abort(); } catch (_) {}
    __ipeLiveQueued = null;
  }
  __ipeLeaderAt = now;
  __ipeLeaderHiddenSince = 0;
  __ipeLeaderUnfocused = false;
  __ipeLiveRequest(true);
}
function __ipeLiveStart() {
  __ipeLiveGen++;
  if (__ipeLiveName === null || __ipeLiveLocks === null ||
      typeof BroadcastChannel !== "function" || typeof AbortController !== "function") {
    __ipeLiveSolo();
    return;
  }
  try {
    __ipeLiveChan = new BroadcastChannel(__ipeLiveName);
  } catch (_) {
    __ipeLiveSolo();
    return;
  }
  __ipeLiveChan.onmessage = __ipeLiveOnMessage;
  __ipeLiveRole = "follower";
  __ipeLeaderAt = Date.now();
  __ipeLeaderHiddenSince = 0;
  __ipeLeaderUnfocused = false;
  __ipeLiveRequest(false);
  __ipeLivePost({ t: "ask" });
}
// Leaving the page (unload, or the back-forward cache) closes the stream and
// frees the lock at once, so another tab takes over; a page restored from the
// cache joins again.
function __ipeLiveStop() {
  __ipeLiveGen++;
  __ipeLiveDropLock();
  __ipeCloseSSE();
  __ipeSetLive(false);
  __ipeHelloOk = false;
  if (__ipeLiveChan !== null) {
    try { __ipeLiveChan.close(); } catch (_) {}
    __ipeLiveChan = null;
  }
  __ipeLiveRole = "stopped";
}
window.addEventListener("pagehide", __ipeLiveStop);
// Focus moving between tabs: the leader reports it, a follower may take over.
window.addEventListener("focus", function() {
  __ipeLiveBeat();
  __ipeLiveMaybeSteal();
});
window.addEventListener("blur", __ipeLiveBeat);
window.addEventListener("pageshow", function(ev) {
  if (ev.persisted && __ipeLiveRole === "stopped") __ipeLiveStart();
});

// Kick off the SSE connection + watchdog. Watchdog interval is short
// enough (5s) that a wedge is detected within 5s + helloTimeout / ttl
// of the actual fault, and long enough to not be a measurable CPU cost.
__ipeLiveStart();
__ipeWatchdogTimer = setInterval(__ipeWatchdog, 5000);

// On tab visibility change, re-evaluate immediately — when a tab
// resumes from background the OS may have torn down the underlying
// TCP, but EventSource sometimes lags in detecting it. Eager check
// avoids the user staring at a stale UI for the full watchdog cycle.
__ipeDoc.on("visibilitychange", function() {
  __ipeLiveBeat();
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
