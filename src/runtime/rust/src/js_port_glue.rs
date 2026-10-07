//! The browser `Ipe.Ffi.Js` port surface, served content-addressed with SRI.
//!
//! One ES module exposes the developer-facing `window.ipe` port object — the
//! IDENTICAL surface on the server-driven and the browser-WASM target:
//!
//! * `ipe.send(value)` — hand a JSON value to the Ipê program's inbound port.
//!   The value is stringified once and delivered to the runtime's in-channel
//!   (`js_subscribe` decodes it fail-closed).
//! * `ipe.onReceive(fn)` — register the handler the runtime calls with each
//!   outbound port frame a `js_send` produced (the frame is the canonical seal
//!   wire string; the handler parses it).
//! * `ipe.onSync(fn)` — alias of `onReceive` for a page that reads the outbound
//!   frame as a state sync rather than a message; one registration slot, so a
//!   page never wires two conflicting receivers.
//!
//! The module is addressed by the hash of its own bytes (`/_ipe/port.<hex16>.js`)
//! and pinned with an `integrity="sha256-<b64>"` SRI attribute — the same
//! content-addressing `widget_assets` uses, so a tampered byte makes the browser
//! refuse the module. The bytes are a fixed asset (no user input is ever spliced
//! in), so the address and SRI are constants of the build.

use sha2::{Digest, Sha256};

/// Schemes a shared URL may carry — the Rust SSOT mirroring `Ipe.Browser.Share.shareSchemes`.
/// The JS `shareSink` scheme check is generated from this slice; adding a scheme here
/// automatically tightens both the typed Ipê layer and the JS defence-in-depth guard.
pub const SHARE_SCHEMES: &[&str] = &["http", "https"];

// --- port glue JS assembly ---
//
// The ES module is assembled from two raw-string halves; the scheme-check snippet
// between them is generated from `SHARE_SCHEMES` so the JS transport guard is
// always consistent with the Ipê typed layer.  The `LazyLock` builds the string
// once per process; `digest()`/`port_glue_path()`/`port_glue_integrity()` all
// derive from the assembled bytes.

const PORT_GLUE_JS_HEAD: &str = r#"// Ipe.Ffi.Js browser port surface. Values cross as JSON strings only.
(function () {
  var onReceive = null;
  // The document members the sinks read, bound from the prototypes before any
  // page content is consulted: an `img`, `form`, `embed`, `object` or `iframe`
  // named after a document member shadows that member with the element. Null
  // where the host has no document.
  var doc = typeof document === "undefined" || typeof Document === "undefined" ? null : (function (d) {
    function prop(name) {
      var desc = Object.getOwnPropertyDescriptor(Document.prototype, name);
      return function () { return desc && desc.get ? desc.get.call(d) : undefined; };
    }
    function method(proto, name) {
      return typeof proto[name] === "function" ? proto[name].bind(d) : null;
    }
    return {
      visibility: prop("visibilityState"),
      root: prop("documentElement"),
      fullscreenElement: prop("fullscreenElement"),
      create: method(Document.prototype, "createElement"),
      exitFullscreen: method(Document.prototype, "exitFullscreen"),
      on: method(EventTarget.prototype, "addEventListener")
    };
  })(document);
  // Return an inbound typed frame to the Ipê program: a decoded intent, never a
  // thrown error, so a host permission denial is an ordinary case the program's
  // subscription decodes (parse-don't-validate at the trust boundary). Each frame
  // carries a `tag` naming its first-party sink so a module's inbound decoder
  // selects only its own frames; unknown tags simply fail that decoder closed.
  // When `corId` is non-null, the runtime-private `__ipe_id` field is added so
  // the runtime routes this reply to the matching one-shot waiter rather than
  // broadcasting it to `js_subscribe` subscribers.
  function reply(frame, corId) {
    if (corId !== null && corId !== undefined) {
      frame.__ipe_id = corId;
    }
    if (typeof window.__ipePortSend === "function") {
      try { window.__ipePortSend(JSON.stringify(frame)); }
      catch (_e) { /* best-effort inbound reply */ }
    }
  }
  // First-party Ipe.Browser.* sinks. Each recognises its own closed outbound
  // command shape and reaches exactly one Web API, trapping any host denial /
  // unavailability / timeout to a typed inbound frame (never a panic, never a
  // throw). The bytes are stdlib's and SRI-pinned, so a dependency cannot
  // substitute them.
  function clipboardSink(value, corId) {
    // Ipe.Browser.Clipboard: `WriteText text` -> navigator.clipboard.writeText.
    if (value && typeof value === "object" && typeof value.WriteText === "string") {
      var text = value.WriteText;
      if (!navigator || !navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
        reply({ tag: "clipboard", event: "write", ok: false, error: "unavailable" }, corId);
        return true;
      }
      navigator.clipboard.writeText(text).then(
        function () { reply({ tag: "clipboard", event: "write", ok: true }, corId); },
        function () { reply({ tag: "clipboard", event: "write", ok: false, error: "denied" }, corId); }
      );
      return true;
    }
    // Ipe.Browser.Clipboard: `ReadText` -> navigator.clipboard.readText. The
    // nullary variant is externally tagged as the bare string "ReadText".
    if (value === "ReadText") {
      if (!navigator || !navigator.clipboard || typeof navigator.clipboard.readText !== "function") {
        reply({ tag: "clipboard", event: "read", ok: false, error: "unavailable" }, corId);
        return true;
      }
      navigator.clipboard.readText().then(
        function (text) { reply({ tag: "clipboard", event: "read", ok: true, text: String(text) }, corId); },
        function () { reply({ tag: "clipboard", event: "read", ok: false, error: "denied" }, corId); }
      );
      return true;
    }
    return false;
  }
  // Ipe.Browser.Geolocation: `Current opts` / `Watch opts` / `ClearWatch id`
  // -> navigator.geolocation.getCurrentPosition / watchPosition / clearWatch. A
  // position resolves to a typed `Coords` frame; a host denial, position
  // unavailability, or timeout traps to the matching typed error frame — the
  // three inbound error variants the module enumerates exhaustively.
  var geoWatchIds = [];
  function geoOptions(opts) {
    // The Ipê `Options` record crosses as `{ enableHighAccuracy, timeout,
    // maximumAge }` (milliseconds). A non-positive `timeout` means "no deadline"
    // -> Infinity; a negative `maximumAge` is clamped to a fresh fix (0).
    var o = (opts && typeof opts === "object") ? opts : {};
    return {
      enableHighAccuracy: o.enableHighAccuracy === true,
      timeout: (typeof o.timeout === "number" && o.timeout > 0) ? o.timeout : Infinity,
      maximumAge: (typeof o.maximumAge === "number" && o.maximumAge > 0) ? o.maximumAge : 0,
    };
  }
  function makeGeoCallbacks(corId) {
    return {
      onPosition: function(pos) {
        var c = pos && pos.coords ? pos.coords : {};
        reply({
          tag: "geolocation", ok: true,
          lat: Number(c.latitude), lng: Number(c.longitude), accuracy: Number(c.accuracy),
        }, corId);
      },
      onError: function(err) {
        // PERMISSION_DENIED=1, POSITION_UNAVAILABLE=2, TIMEOUT=3 — mapped to the
        // module's closed inbound error vocabulary; anything else is unavailable.
        var code = err && typeof err.code === "number" ? err.code : 2;
        var kind = code === 1 ? "denied" : (code === 3 ? "timeout" : "unavailable");
        reply({ tag: "geolocation", ok: false, error: kind }, corId);
      },
    };
  }
  function geolocationSink(value, corId) {
    // An outbound `JsCmd` is externally tagged: a payload-carrying variant is
    // `{ Current: opts }` / `{ Watch: opts }`; the nullary `ClearWatch` is the
    // bare string `"ClearWatch"`.
    var isClear = value === "ClearWatch" ||
      (value && typeof value === "object" && value.ClearWatch !== undefined);
    var isCurrent = value && typeof value === "object" && value.Current !== undefined;
    var isWatch = value && typeof value === "object" && value.Watch !== undefined;
    if (!isCurrent && !isWatch && !isClear) return false;
    if (isClear) {
      if (geoWatchIds.length > 0 && navigator && navigator.geolocation &&
          typeof navigator.geolocation.clearWatch === "function") {
        for (var i = 0; i < geoWatchIds.length; i++) {
          navigator.geolocation.clearWatch(geoWatchIds[i]);
        }
      }
      geoWatchIds = [];
      return true;
    }
    if (!navigator || !navigator.geolocation) {
      reply({ tag: "geolocation", ok: false, error: "unavailable" }, corId);
      return true;
    }
    var opts = geoOptions(isCurrent ? value.Current : value.Watch);
    var cbs = makeGeoCallbacks(corId);
    if (isCurrent) {
      if (typeof navigator.geolocation.getCurrentPosition !== "function") {
        reply({ tag: "geolocation", ok: false, error: "unavailable" }, corId);
        return true;
      }
      navigator.geolocation.getCurrentPosition(cbs.onPosition, cbs.onError, opts);
    } else {
      if (typeof navigator.geolocation.watchPosition !== "function") {
        reply({ tag: "geolocation", ok: false, error: "unavailable" }, corId);
        return true;
      }
      geoWatchIds.push(navigator.geolocation.watchPosition(cbs.onPosition, cbs.onError, opts));
    }
    return true;
  }
  // Ipe.Browser.Notification: `RequestPermission` / `Show { title, body, tag }`
  // -> Notification.requestPermission / new Notification. A grant resolves to a
  // typed `granted` frame; a denial or an absent API traps to the matching typed
  // error frame — never a throw.
  function notificationSink(value, corId) {
    // `RequestPermission` is the bare string; `Show` is `{ Show: options }`.
    var isRequest = value === "RequestPermission" ||
      (value && typeof value === "object" && value.RequestPermission !== undefined);
    var isShow = value && typeof value === "object" && value.Show !== undefined;
    if (!isRequest && !isShow) return false;
    if (typeof Notification === "undefined") {
      reply({ tag: "notification", ok: false, error: "unavailable" }, corId);
      return true;
    }
    if (isRequest) {
      if (typeof Notification.requestPermission !== "function") {
        reply({ tag: "notification", ok: false, error: "unavailable" }, corId);
        return true;
      }
      Promise.resolve(Notification.requestPermission()).then(
        function (perm) {
          if (perm === "granted") {
            reply({ tag: "notification", ok: true, event: "granted" }, corId);
          } else {
            reply({ tag: "notification", ok: false, error: "denied" }, corId);
          }
        },
        function () { reply({ tag: "notification", ok: false, error: "denied" }, corId); }
      );
      return true;
    }
    // isShow: only display when permission is already granted; otherwise a typed
    // denial, never a silent no-op and never an unsolicited permission prompt.
    var opts = (value.Show && typeof value.Show === "object") ? value.Show : {};
    if (Notification.permission !== "granted") {
      reply({ tag: "notification", ok: false, error: "denied" }, corId);
      return true;
    }
    try {
      var body = typeof opts.body === "string" ? opts.body : "";
      var tag = typeof opts.tag === "string" ? opts.tag : "";
      new Notification(String(opts.title || ""), { body: body, tag: tag });
      reply({ tag: "notification", ok: true, event: "shown" }, corId);
    } catch (_e) {
      reply({ tag: "notification", ok: false, error: "unavailable" }, corId);
    }
    return true;
  }
  // Ipe.Browser.Storage: `Get key` / `Set { key, value }` / `Remove key` / `Clear`
  // -> localStorage.getItem / setItem / removeItem / clear. A read resolves to a
  // typed value frame (value omitted for an absent key); a private-mode quota throw
  // or an absent store traps to `unavailable` — never a throw.
  function storageSink(value, corId) {
    var isGet = value && typeof value === "object" && value.Get !== undefined;
    var isSet = value && typeof value === "object" && value.Set !== undefined;
    var isRemove = value && typeof value === "object" && value.Remove !== undefined;
    var isClear = value === "Clear" ||
      (value && typeof value === "object" && value.Clear !== undefined);
    if (!isGet && !isSet && !isRemove && !isClear) return false;
    var store = null;
    try { store = window.localStorage; } catch (_e) { store = null; }
    if (!store) {
      reply({ tag: "storage", ok: false, error: "unavailable" }, corId);
      return true;
    }
    try {
      if (isGet) {
        var got = store.getItem(String(value.Get));
        if (got === null || got === undefined) {
          reply({ tag: "storage", ok: true, event: "get" }, corId);
        } else {
          reply({ tag: "storage", ok: true, event: "get", value: String(got) }, corId);
        }
      } else if (isSet) {
        var entry = (value.Set && typeof value.Set === "object") ? value.Set : {};
        store.setItem(String(entry.key || ""), String(entry.value || ""));
        reply({ tag: "storage", ok: true, event: "set" }, corId);
      } else if (isRemove) {
        store.removeItem(String(value.Remove));
        reply({ tag: "storage", ok: true, event: "remove" }, corId);
      } else {
        store.clear();
        reply({ tag: "storage", ok: true, event: "clear" }, corId);
      }
    } catch (_e2) {
      reply({ tag: "storage", ok: false, error: "unavailable" }, corId);
    }
    return true;
  }
  // Ipe.Browser.Vibration: `Vibrate ms` / `Pattern [..]` / `Cancel`
  // -> navigator.vibrate(ms) / vibrate([..]) / vibrate(0). A supported actuator
  // replies `vibrated`; an absent API or a rejected request traps to `unavailable`.
  function vibrationSink(value, corId) {
    var isVibrate = value && typeof value === "object" && value.Vibrate !== undefined;
    var isPattern = value && typeof value === "object" && value.Pattern !== undefined;
    var isCancel = value === "Cancel" ||
      (value && typeof value === "object" && value.Cancel !== undefined);
    if (!isVibrate && !isPattern && !isCancel) return false;
    if (!navigator || typeof navigator.vibrate !== "function") {
      reply({ tag: "vibration", ok: false, error: "unavailable" }, corId);
      return true;
    }
    var arg;
    if (isVibrate) {
      arg = Number(value.Vibrate) || 0;
    } else if (isPattern) {
      arg = Array.isArray(value.Pattern) ? value.Pattern.map(function (n) { return Number(n) || 0; }) : [];
    } else {
      arg = 0;
    }
    var accepted = false;
    try { accepted = navigator.vibrate(arg); } catch (_e) { accepted = false; }
    if (accepted) {
      reply({ tag: "vibration", ok: true }, corId);
    } else {
      reply({ tag: "vibration", ok: false, error: "unavailable" }, corId);
    }
    return true;
  }
  // Ipe.Browser.Share: `Share { title, text, url }` -> navigator.share. A
  // completion replies `shared`; a user dismissal (AbortError) traps to
  // `cancelled`, an absent API to `unavailable` — never a throw. Empty payload
  // fields are omitted so the platform sheet only shows populated fields.
  //
  // The URL scheme is allowlisted here to `http`/`https` before it reaches
  // `navigator.share`, mirroring the `Ipe.Browser.Share.shareSchemes` seal. This
  // is a second, transport-level boundary independent of the ipe-level `ShareUrl`
  // type: the raw JS transport is not ipe-typed, so a `data:`/`file:` URL that
  // slips past the type (or is injected at the JS layer) is turned back here.
  // Absent proof the scheme is `http`/`https`, the URL is dropped from the
  // payload — never passed through — so no exfiltrating scheme reaches the sheet.
  // The scheme check itself is generated from the `SHARE_SCHEMES` SSOT and spliced
  // in after this half, so the JS allowlist can never drift from the Ipê layer.
  function shareSink(value, corId) {
    if (!(value && typeof value === "object" && value.Share !== undefined)) return false;
    if (!navigator || typeof navigator.share !== "function") {
      reply({ tag: "share", ok: false, error: "unavailable" }, corId);
      return true;
    }
    var p = (value.Share && typeof value.Share === "object") ? value.Share : {};
    var data = {};
    if (typeof p.title === "string" && p.title !== "") data.title = p.title;
    if (typeof p.text === "string" && p.text !== "") data.text = p.text;
"#;

// The tail of the share sink + rest of the module — spliced in after the
// generated scheme check.
const PORT_GLUE_JS_TAIL: &str = r#"    try {
      navigator.share(data).then(
        function () { reply({ tag: "share", ok: true }, corId); },
        function (err) {
          var name = err && err.name ? String(err.name) : "";
          var kind = name === "AbortError" ? "cancelled" : "unavailable";
          reply({ tag: "share", ok: false, error: kind }, corId);
        }
      );
    } catch (_e) {
      reply({ tag: "share", ok: false, error: "unavailable" }, corId);
    }
    return true;
  }
  // Ipe.Browser.Battery: `Query` / `Watch` -> navigator.getBattery(). A reading
  // frame carries charging / level / chargingTime / dischargingTime; a
  // never-ending time (`Infinity`) is normalised to the -1 sentinel. An absent API
  // traps to `unavailable` — never a throw. `Watch` also attaches change listeners
  // that push fresh readings.
  function batteryReadingFrame(bat, corId) {
    function finite(x) {
      var n = Number(x);
      return (isFinite(n)) ? n : -1;
    }
    reply({
      tag: "battery", ok: true,
      charging: bat.charging === true,
      level: Number(bat.level),
      chargingTime: finite(bat.chargingTime),
      dischargingTime: finite(bat.dischargingTime),
    }, corId);
  }
  function batterySink(value, corId) {
    var isQuery = value === "Query" ||
      (value && typeof value === "object" && value.Query !== undefined);
    var isWatch = value === "Watch" ||
      (value && typeof value === "object" && value.Watch !== undefined);
    if (!isQuery && !isWatch) return false;
    if (!navigator || typeof navigator.getBattery !== "function") {
      reply({ tag: "battery", ok: false, error: "unavailable" }, corId);
      return true;
    }
    navigator.getBattery().then(
      function (bat) {
        batteryReadingFrame(bat, corId);
        if (isWatch) {
          // A watch subscription receives every subsequent change as a fresh
          // broadcast reading; the change events carry no correlation id.
          var push = function () { batteryReadingFrame(bat, null); };
          bat.addEventListener("chargingchange", push);
          bat.addEventListener("levelchange", push);
          bat.addEventListener("chargingtimechange", push);
          bat.addEventListener("dischargingtimechange", push);
        }
      },
      function () { reply({ tag: "battery", ok: false, error: "unavailable" }, corId); }
    );
    return true;
  }
  // Ipe.Browser.NetworkInfo: `Query` / `Watch` -> navigator.connection. A reading
  // frame carries effectiveType / downlink / rtt / saveData; an absent API traps to
  // `unavailable` — never a throw. `Watch` attaches a `change` listener that pushes
  // fresh readings.
  function networkInfoReadingFrame(conn, corId) {
    reply({
      tag: "network-info", ok: true,
      effectiveType: typeof conn.effectiveType === "string" ? conn.effectiveType : "",
      downlink: Number(conn.downlink) || 0,
      rtt: Number(conn.rtt) || 0,
      saveData: conn.saveData === true,
    }, corId);
  }
  function networkInfoSink(value, corId) {
    var isQuery = value === "Query" ||
      (value && typeof value === "object" && value.Query !== undefined);
    var isWatch = value === "Watch" ||
      (value && typeof value === "object" && value.Watch !== undefined);
    if (!isQuery && !isWatch) return false;
    var conn = navigator ? (navigator.connection || navigator.mozConnection || navigator.webkitConnection) : null;
    if (!conn) {
      reply({ tag: "network-info", ok: false, error: "unavailable" }, corId);
      return true;
    }
    networkInfoReadingFrame(conn, corId);
    if (isWatch && typeof conn.addEventListener === "function") {
      // A watch subscription receives every subsequent change as a fresh
      // broadcast reading; the change event carries no correlation id.
      conn.addEventListener("change", function () { networkInfoReadingFrame(conn, null); });
    }
    return true;
  }
  // Ipe.Browser.FilePicker: `PickFile` / `PickImage` -> <input type="file">.
  // A transient file-input element is created programmatically; after the user
  // selects a file, `FileReader.readAsDataURL` reads the contents and the full
  // data: URL is returned as the `dataUrl` field. A user cancellation resolves
  // to the typed `cancelled` frame; an absent File API or a read error to
  // `unavailable` — never a thrown error or a silent drop.
  function filePickerSink(value, corId) {
    var isPickFile = value === "PickFile" ||
      (value && typeof value === "object" && value.PickFile !== undefined);
    var isPickImage = value === "PickImage" ||
      (value && typeof value === "object" && value.PickImage !== undefined);
    if (!isPickFile && !isPickImage) return false;
    if (!doc || typeof File === "undefined" || typeof FileReader === "undefined") {
      reply({ tag: "file-picker", ok: false, error: "unavailable" }, corId);
      return true;
    }
    var input = doc.create("input");
    input.type = "file";
    if (isPickImage) {
      input.accept = "image/*";
    }
    var settled = false;
    input.addEventListener("change", function () {
      if (settled) return;
      settled = true;
      var file = input.files && input.files[0];
      if (!file) {
        reply({ tag: "file-picker", ok: false, error: "cancelled" }, corId);
        return;
      }
      var reader = new FileReader();
      reader.onload = function (ev) {
        reply({
          tag: "file-picker", ok: true,
          name: String(file.name),
          mime: String(file.type || "application/octet-stream"),
          dataUrl: String(ev.target.result),
        }, corId);
      };
      reader.onerror = function () {
        reply({ tag: "file-picker", ok: false, error: "unavailable" }, corId);
      };
      reader.readAsDataURL(file);
    });
    // A focus event after the dialog closes without a selection signals cancel.
    window.addEventListener("focus", function onFocus() {
      window.removeEventListener("focus", onFocus);
      setTimeout(function () {
        if (!settled) {
          settled = true;
          reply({ tag: "file-picker", ok: false, error: "cancelled" }, corId);
        }
      }, 400);
    }, { once: true });
    input.click();
    return true;
  }
  // Ipe.Browser.Camera: `CapturePhoto` -> <input type="file" capture="environment"
  // accept="image/*">. On mobile this directs the OS to open the camera; on
  // desktop it falls back to a plain image file picker. The result shape is
  // identical: a Captured frame carrying name / mime / dataUrl. A user
  // cancellation resolves to `cancelled`; an absent File API to `unavailable`.
  function cameraSink(value, corId) {
    var isCapture = value === "CapturePhoto" ||
      (value && typeof value === "object" && value.CapturePhoto !== undefined);
    if (!isCapture) return false;
    if (!doc || typeof File === "undefined" || typeof FileReader === "undefined") {
      reply({ tag: "camera", ok: false, error: "unavailable" }, corId);
      return true;
    }
    var input = doc.create("input");
    input.type = "file";
    input.accept = "image/*";
    input.capture = "environment";
    var settled = false;
    input.addEventListener("change", function () {
      if (settled) return;
      settled = true;
      var file = input.files && input.files[0];
      if (!file) {
        reply({ tag: "camera", ok: false, error: "cancelled" }, corId);
        return;
      }
      var reader = new FileReader();
      reader.onload = function (ev) {
        reply({
          tag: "camera", ok: true,
          name: String(file.name),
          mime: String(file.type || "image/jpeg"),
          dataUrl: String(ev.target.result),
        }, corId);
      };
      reader.onerror = function () {
        reply({ tag: "camera", ok: false, error: "unavailable" }, corId);
      };
      reader.readAsDataURL(file);
    });
    window.addEventListener("focus", function onFocus() {
      window.removeEventListener("focus", onFocus);
      setTimeout(function () {
        if (!settled) {
          settled = true;
          reply({ tag: "camera", ok: false, error: "cancelled" }, corId);
        }
      }, 400);
    }, { once: true });
    input.click();
    return true;
  }
  // Ipe.Browser.Microphone: `CaptureAudio { maxDurationMs, mimeType }` →
  // getUserMedia({ audio: true }) → MediaRecorder. The host records for
  // `maxDurationMs` milliseconds (capped at 8 000 ms to fit inside the
  // Js.request deadline), collects ondataavailable chunks, assembles them into
  // one Blob, reads it via FileReader.readAsDataURL, and replies ONCE with the
  // base-64 audio data URL. Every host trap (getUserMedia rejection, absent
  // MediaRecorder, permission denied) → a typed Denied or Unavailable frame,
  // never a throw. No eval, no innerHTML.
  function microphoneSink(value, corId) {
    var opts = value && typeof value === "object" && value.CaptureAudio;
    if (!opts || typeof opts !== "object") return false;
    // Deny-by-default: require corId so the result is only routed to the
    // correct one-shot waiter, never broadcast to js_subscribe subscribers.
    if (corId === null || corId === undefined) {
      return true; // recognised but uncorrelated — swallow, never broadcast
    }
    // Cap maxDurationMs at 8 000 ms: the Js.request deadline is 10 s; the
    // sink needs the remainder for Blob assembly and FileReader.readAsDataURL.
    var maxMs = (typeof opts.maxDurationMs === "number" && opts.maxDurationMs > 0)
      ? Math.min(opts.maxDurationMs, 8000) : 3000;
    var mimeType = (typeof opts.mimeType === "string" && opts.mimeType !== "")
      ? opts.mimeType : "";
    if (!navigator || typeof navigator.mediaDevices === "undefined" ||
        typeof navigator.mediaDevices.getUserMedia !== "function") {
      reply({ tag: "microphone", ok: false, error: "unavailable" }, corId);
      return true;
    }
    if (typeof MediaRecorder === "undefined") {
      reply({ tag: "microphone", ok: false, error: "unavailable" }, corId);
      return true;
    }
    navigator.mediaDevices.getUserMedia({ audio: true }).then(
      function (stream) {
        var recOpts = {};
        // Only set the mimeType when the browser reports it as supported;
        // passing an unsupported type throws a NotSupportedError.
        if (mimeType !== "" && MediaRecorder.isTypeSupported(mimeType)) {
          recOpts.mimeType = mimeType;
        }
        var recorder;
        try {
          recorder = new MediaRecorder(stream, recOpts);
        } catch (_e) {
          stream.getTracks().forEach(function (t) { t.stop(); });
          reply({ tag: "microphone", ok: false, error: "unavailable" }, corId);
          return;
        }
        var chunks = [];
        var actualMime = recorder.mimeType || "audio/webm";
        var startTime = Date.now();
        var settled = false;
        function finish() {
          if (settled) return;
          settled = true;
          stream.getTracks().forEach(function (t) { t.stop(); });
          var blob = new Blob(chunks, { type: actualMime });
          var durationMs = Math.min(Date.now() - startTime, maxMs);
          var reader = new FileReader();
          reader.onload = function (ev) {
            reply({
              tag: "microphone", ok: true,
              data: String(ev.target.result),
              mime: actualMime,
              durationMs: durationMs,
            }, corId);
          };
          reader.onerror = function () {
            reply({ tag: "microphone", ok: false, error: "unavailable" }, corId);
          };
          reader.readAsDataURL(blob);
        }
        recorder.ondataavailable = function (ev) {
          if (ev.data && ev.data.size > 0) {
            chunks.push(ev.data);
          }
        };
        recorder.onstop = finish;
        recorder.onerror = function () {
          if (!settled) {
            settled = true;
            stream.getTracks().forEach(function (t) { t.stop(); });
            reply({ tag: "microphone", ok: false, error: "unavailable" }, corId);
          }
        };
        try {
          recorder.start();
        } catch (_e) {
          stream.getTracks().forEach(function (t) { t.stop(); });
          reply({ tag: "microphone", ok: false, error: "unavailable" }, corId);
          return;
        }
        setTimeout(function () {
          if (recorder.state !== "inactive") {
            try { recorder.stop(); } catch (_e) { finish(); }
          }
        }, maxMs);
      },
      function (err) {
        // getUserMedia rejection — map to typed denial or unavailability.
        var name = err && err.name ? String(err.name) : "";
        var kind = name === "NotAllowedError" || name === "PermissionDeniedError"
          ? "denied" : "unavailable";
        reply({ tag: "microphone", ok: false, error: kind }, corId);
      }
    );
    return true;
  }
  // Ipe.Browser.Recorder: `Start { video, mimeType, timesliceMs }` / `Stop` ->
  // getUserMedia({ audio: true[, video: true] }) + MediaRecorder, delivered as a
  // bounded session-stream: one `started` frame, N `chunk` data-URL frames (one
  // per ondataavailable blob), then a terminal `ended` frame on Stop or a
  // host-side track end. All frames are broadcast (corId stripped) exactly like
  // the Gamepad session stream.
  //
  // Fail-closed by construction:
  //   * `recorderActive` is a ONE-WAY flag: `Stop` (and any host-side track end)
  //     flips it to false BEFORE stopping the recorder / releasing the tracks, and
  //     `ondataavailable` drops its blob when the flag is false — so NO `chunk`
  //     frame is ever emitted after the session closes.
  //   * a getUserMedia rejection -> a typed `denied` (NotAllowedError) or
  //     `unavailable` frame; an absent getUserMedia / MediaRecorder -> `unavailable`.
  //     Never a throw, never a leaked track.
  //   * a fresh `Start` first tears the previous session down (flag off, recorder
  //     stopped, tracks released) and bumps the grant epoch, so a double Start
  //     cannot leave two live streams — the earlier, now-stale grant releases its
  //     tracks when it resolves instead of going live.
  //   * a `Stop` (even with nothing active) bumps the grant epoch too, so a Start
  //     whose getUserMedia is still pending is cancelled: when it resolves it
  //     releases the granted tracks and emits no `started`/`chunk` frame.
  var recorderState = null; // { recorder, stream, active }
  // Monotonic generation for the in-flight getUserMedia grant. Each Start
  // captures the current value; a later Stop / teardown / Start bumps it, so a
  // grant that resolves after its session was closed or superseded sees a stale
  // epoch and releases its just-granted tracks instead of going live.
  var recorderEpoch = 0;
  function recorderTeardown() {
    // Invalidate any pending grant so a getUserMedia still in flight cancels.
    recorderEpoch += 1;
    if (recorderState === null) return;
    // Flip the one-way active flag FIRST so a racing ondataavailable is dropped.
    recorderState.active = false;
    var st = recorderState;
    recorderState = null;
    try {
      if (st.recorder && st.recorder.state !== "inactive") { st.recorder.stop(); }
    } catch (_e) { /* best-effort */ }
    try {
      if (st.stream) { st.stream.getTracks().forEach(function (t) { t.stop(); }); }
    } catch (_e) { /* best-effort */ }
  }
  function recorderSink(value, _corId) {
    var startOpts = value && typeof value === "object" && value.Start;
    var isStop = value === "Stop" ||
      (value && typeof value === "object" && value.Stop !== undefined);
    if ((!startOpts || typeof startOpts !== "object") && !isStop) return false;
    if (isStop) {
      // Close the session: teardown flips the flag and releases tracks, then we
      // emit the single terminal `ended` frame. A no-op when nothing is active.
      var wasActive = recorderState !== null;
      recorderTeardown();
      if (wasActive) { reply({ tag: "recorder", event: "ended" }, null); }
      return true;
    }
    // isStart. Tear down any prior session so a double Start never leaves two
    // live getUserMedia streams running.
    recorderTeardown();
    var wantVideo = startOpts.video === true;
    var mimeType = (typeof startOpts.mimeType === "string" && startOpts.mimeType !== "")
      ? startOpts.mimeType : "";
    // Clamp the chunk interval to a >= 100 ms floor: a zero/negative timeslice
    // would spin ondataavailable every event-loop tick.
    var timeslice = (typeof startOpts.timesliceMs === "number" && startOpts.timesliceMs >= 100)
      ? startOpts.timesliceMs : 1000;
    if (!navigator || typeof navigator.mediaDevices === "undefined" ||
        typeof navigator.mediaDevices.getUserMedia !== "function" ||
        typeof MediaRecorder === "undefined") {
      reply({ tag: "recorder", event: "unavailable" }, null);
      return true;
    }
    var constraints = wantVideo ? { audio: true, video: true } : { audio: true };
    // Capture this Start's generation. If a Stop / teardown / later Start bumps
    // the epoch while getUserMedia is pending, both arms below see the mismatch
    // and abandon the grant.
    var myEpoch = ++recorderEpoch;
    navigator.mediaDevices.getUserMedia(constraints).then(
      function (stream) {
        // A superseded or cancelled grant: release the just-granted tracks and
        // start / emit nothing, so no camera or mic stays live past its session.
        if (myEpoch !== recorderEpoch) {
          stream.getTracks().forEach(function (t) { t.stop(); });
          return;
        }
        var recOpts = {};
        if (mimeType !== "" && MediaRecorder.isTypeSupported(mimeType)) {
          recOpts.mimeType = mimeType;
        }
        var recorder;
        try {
          recorder = new MediaRecorder(stream, recOpts);
        } catch (_e) {
          stream.getTracks().forEach(function (t) { t.stop(); });
          reply({ tag: "recorder", event: "unavailable" }, null);
          return;
        }
        var actualMime = recorder.mimeType || (wantVideo ? "video/webm" : "audio/webm");
        recorderState = { recorder: recorder, stream: stream, active: true };
        recorder.ondataavailable = function (ev) {
          // Deny-by-default: drop a blob that arrives after the session closed —
          // this is the no-frame-after-close guarantee at the sink.
          if (!recorderState || recorderState.active !== true) return;
          if (!ev.data || ev.data.size <= 0) return;
          var reader = new FileReader();
          reader.onload = function (rev) {
            // Re-check the flag at delivery time: a Stop may have arrived while the
            // FileReader was decoding this chunk.
            if (!recorderState || recorderState.active !== true) return;
            reply({
              tag: "recorder", event: "chunk",
              data: String(rev.target.result),
              mime: actualMime,
            }, null);
          };
          reader.onerror = function () { /* drop an unreadable chunk, never throw */ };
          reader.readAsDataURL(ev.data);
        };
        recorder.onstop = function () {
          // A host-side track end (user revokes, device unplugged) also lands here.
          if (recorderState !== null) {
            recorderTeardown();
            reply({ tag: "recorder", event: "ended" }, null);
          }
        };
        recorder.onerror = function () {
          if (recorderState !== null) {
            recorderTeardown();
            reply({ tag: "recorder", event: "ended" }, null);
          }
        };
        try {
          recorder.start(timeslice);
        } catch (_e) {
          recorderTeardown();
          reply({ tag: "recorder", event: "unavailable" }, null);
          return;
        }
        reply({ tag: "recorder", event: "started", mime: actualMime }, null);
      },
      function (err) {
        // A rejection for a superseded or cancelled grant is not this session's
        // to report: stay silent so no stale denied/unavailable frame leaks out.
        if (myEpoch !== recorderEpoch) { return; }
        var name = err && err.name ? String(err.name) : "";
        var kind = name === "NotAllowedError" || name === "PermissionDeniedError"
          ? "denied" : "unavailable";
        reply({ tag: "recorder", event: kind }, null);
      }
    );
    return true;
  }
  // Ipe.Browser.Speech: `Speak { text, options }` → speechSynthesis.speak.
  // Cancels any queued utterance first, constructs a SpeechSynthesisUtterance,
  // applies rate/pitch/volume/lang from options, and calls speechSynthesis.speak.
  // Resolves once via `onend` (Spoken) or `onerror` (Failed). An absent API
  // traps to Unavailable — never a throw, never a broadcast.
  // `Cancel` calls speechSynthesis.cancel() and sends no reply.
  function speechSink(value, corId) {
    var isSpeak = value && typeof value === "object" && value.Speak !== undefined;
    var isCancel = value === "Cancel" ||
      (value && typeof value === "object" && value.Cancel !== undefined);
    if (!isSpeak && !isCancel) return false;
    if (isCancel) {
      if (window.speechSynthesis && typeof window.speechSynthesis.cancel === "function") {
        try { window.speechSynthesis.cancel(); } catch (_e) { /* best-effort */ }
      }
      return true;
    }
    // isSpeak — require corId so the result is only routed to the correct
    // one-shot waiter, never broadcast to js_subscribe subscribers.
    if (corId === null || corId === undefined) {
      return true; // recognised but uncorrelated — swallow, never broadcast
    }
    if (!window.speechSynthesis || typeof window.speechSynthesis.speak !== "function" ||
        typeof SpeechSynthesisUtterance === "undefined") {
      reply({ tag: "speech", ok: false, error: "unavailable" }, corId);
      return true;
    }
    var p = (value.Speak && typeof value.Speak === "object") ? value.Speak : {};
    var text = typeof p.text === "string" ? p.text : "";
    var opts = (p.options && typeof p.options === "object") ? p.options : {};
    // Cancel any in-progress utterance so the new one starts immediately.
    try { window.speechSynthesis.cancel(); } catch (_e) { /* best-effort */ }
    var utterance;
    try { utterance = new SpeechSynthesisUtterance(text); } catch (_e) {
      reply({ tag: "speech", ok: false, error: "unavailable" }, corId);
      return true;
    }
    if (typeof opts.rate === "number") { utterance.rate = opts.rate; }
    if (typeof opts.pitch === "number") { utterance.pitch = opts.pitch; }
    if (typeof opts.volume === "number") { utterance.volume = opts.volume; }
    if (typeof opts.lang === "string" && opts.lang !== "") { utterance.lang = opts.lang; }
    var settled = false;
    utterance.onend = function () {
      if (settled) return;
      settled = true;
      reply({ tag: "speech", ok: true }, corId);
    };
    utterance.onerror = function (ev) {
      if (settled) return;
      settled = true;
      // "interrupted" and "cancelled" mean a subsequent cancel() arrived — still
      // a typed Failed outcome, not a throw or a silent drop.
      reply({ tag: "speech", ok: false, error: "failed" }, corId);
    };
    try {
      window.speechSynthesis.speak(utterance);
    } catch (_e) {
      if (!settled) {
        settled = true;
        reply({ tag: "speech", ok: false, error: "unavailable" }, corId);
      }
    }
    return true;
  }
  // Ipe.Browser.Gamepad: `Watch` / `StopWatch` -> navigator.getGamepads() +
  // gamepadconnected / gamepaddisconnected events. A `Watch` command registers
  // the two lifecycle listeners and starts a `requestAnimationFrame` poll that
  // snapshots all connected gamepads once per frame, pushing typed `state`
  // frames inbound. A `StopWatch` cancels the poll and removes the listeners.
  // An absent Gamepad API traps to a typed `unavailable` frame — never a throw.
  // No correlation-id semantics: all frames are broadcast (corId stripped).
  var gamepadRafId = null;
  var gamepadConnectHandler = null;
  var gamepadDisconnectHandler = null;
  function gamepadSink(value, _corId) {
    var isWatch = value === "Watch" ||
      (value && typeof value === "object" && value.Watch !== undefined);
    var isStop = value === "StopWatch" ||
      (value && typeof value === "object" && value.StopWatch !== undefined);
    if (!isWatch && !isStop) return false;
    if (isStop) {
      if (gamepadRafId !== null) {
        cancelAnimationFrame(gamepadRafId);
        gamepadRafId = null;
      }
      if (gamepadConnectHandler !== null && window.removeEventListener) {
        window.removeEventListener("gamepadconnected", gamepadConnectHandler);
        gamepadConnectHandler = null;
      }
      if (gamepadDisconnectHandler !== null && window.removeEventListener) {
        window.removeEventListener("gamepaddisconnected", gamepadDisconnectHandler);
        gamepadDisconnectHandler = null;
      }
      return true;
    }
    // isWatch: check API availability before registering anything.
    if (!navigator || typeof navigator.getGamepads !== "function") {
      reply({ tag: "gamepad", event: "unavailable" }, null);
      return true;
    }
    // Remove any previously registered listeners and cancel an existing poll
    // so a double Watch does not accumulate duplicate handlers.
    if (gamepadRafId !== null) { cancelAnimationFrame(gamepadRafId); gamepadRafId = null; }
    if (gamepadConnectHandler !== null && window.removeEventListener) {
      window.removeEventListener("gamepadconnected", gamepadConnectHandler);
    }
    if (gamepadDisconnectHandler !== null && window.removeEventListener) {
      window.removeEventListener("gamepaddisconnected", gamepadDisconnectHandler);
    }
    // Connect/disconnect handlers push typed lifecycle frames inbound.
    gamepadConnectHandler = function (ev) {
      var gp = ev && ev.gamepad ? ev.gamepad : {};
      reply({
        tag: "gamepad", event: "connected",
        index: Number(gp.index) || 0,
        id: typeof gp.id === "string" ? gp.id : "",
      }, null);
    };
    gamepadDisconnectHandler = function (ev) {
      var gp = ev && ev.gamepad ? ev.gamepad : {};
      reply({ tag: "gamepad", event: "disconnected", index: Number(gp.index) || 0 }, null);
    };
    window.addEventListener("gamepadconnected", gamepadConnectHandler);
    window.addEventListener("gamepaddisconnected", gamepadDisconnectHandler);
    // Poll via requestAnimationFrame: snapshot all connected gamepads each frame.
    // Each connected gamepad emits one `state` frame per animation tick carrying
    // its current button-pressed flags and axis values. The poll runs until
    // `StopWatch` cancels `gamepadRafId`.
    function poll() {
      var gamepads = [];
      try { gamepads = navigator.getGamepads() || []; } catch (_e) { gamepads = []; }
      for (var i = 0; i < gamepads.length; i++) {
        var gp = gamepads[i];
        if (!gp) continue;
        var buttons = [];
        for (var b = 0; b < gp.buttons.length; b++) {
          var btn = gp.buttons[b];
          buttons.push(btn && btn.pressed === true);
        }
        var axes = [];
        for (var a = 0; a < gp.axes.length; a++) {
          axes.push(Number(gp.axes[a]) || 0);
        }
        reply({
          tag: "gamepad", event: "state",
          index: Number(gp.index),
          buttons: buttons,
          axes: axes,
        }, null);
      }
      gamepadRafId = requestAnimationFrame(poll);
    }
    gamepadRafId = requestAnimationFrame(poll);
    return true;
  }
  // Ipe.Browser.Visibility: `Query` / `Watch` -> the visibility state +
  // visibilitychange. A `Query` reads the current state once; a `Watch` also
  // attaches a `visibilitychange` listener that pushes fresh readings. An absent
  // Page Visibility API traps to `unavailable` — never a throw.
  function visibilitySink(value, corId) {
    var isQuery = value === "Query" ||
      (value && typeof value === "object" && value.Query !== undefined);
    var isWatch = value === "Watch" ||
      (value && typeof value === "object" && value.Watch !== undefined);
    if (!isQuery && !isWatch) return false;
    if (!doc || typeof doc.visibility() !== "string") {
      reply({ tag: "visibility", ok: false, error: "unavailable" }, corId);
      return true;
    }
    reply({ tag: "visibility", ok: true, visible: doc.visibility() === "visible" }, corId);
    if (isWatch && doc.on) {
      // Each change event delivers a fresh reading; no correlation id on broadcasts.
      doc.on("visibilitychange", function () {
        reply({ tag: "visibility", ok: true, visible: doc.visibility() === "visible" }, null);
      });
    }
    return true;
  }
  // Ipe.Browser.MediaQuery: `Match { Match: query }` / `Watch { Watch: query }`
  // -> window.matchMedia(query). A `Match` evaluates the query once; a `Watch`
  // also attaches a `change` listener on the returned MediaQueryList. An absent
  // `matchMedia` API traps to `unavailable` — never a throw. The query string
  // comes from the sealed `JsCmd` payload, never from untrusted input.
  function mediaQuerySink(value, corId) {
    var isMatch = value && typeof value === "object" && value.Match !== undefined;
    var isWatch = value && typeof value === "object" && value.Watch !== undefined;
    if (!isMatch && !isWatch) return false;
    var query = isMatch ? value.Match : value.Watch;
    if (typeof query !== "string") {
      reply({ tag: "media-query", ok: false, error: "unavailable" }, corId);
      return true;
    }
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      reply({ tag: "media-query", ok: false, error: "unavailable" }, corId);
      return true;
    }
    var mql;
    try { mql = window.matchMedia(query); } catch (_e) { mql = null; }
    if (!mql) {
      reply({ tag: "media-query", ok: false, error: "unavailable" }, corId);
      return true;
    }
    reply({ tag: "media-query", ok: true, matches: mql.matches === true }, corId);
    if (isWatch && typeof mql.addEventListener === "function") {
      // Each change event delivers a fresh match result; no correlation id on broadcasts.
      mql.addEventListener("change", function (ev) {
        reply({ tag: "media-query", ok: true, matches: ev.matches === true }, null);
      });
    }
    return true;
  }
  // Ipe.Browser.Connectivity: `Query` / `Watch` -> navigator.onLine + online/offline
  // window events. A `Query` reads `navigator.onLine` once; a `Watch` also attaches
  // `online`/`offline` event listeners. An absent `navigator.onLine` traps to
  // `unavailable` — never a throw.
  function connectivitySink(value, corId) {
    var isQuery = value === "Query" ||
      (value && typeof value === "object" && value.Query !== undefined);
    var isWatch = value === "Watch" ||
      (value && typeof value === "object" && value.Watch !== undefined);
    if (!isQuery && !isWatch) return false;
    if (typeof navigator === "undefined" || typeof navigator.onLine !== "boolean") {
      reply({ tag: "connectivity", ok: false, error: "unavailable" }, corId);
      return true;
    }
    reply({ tag: "connectivity", ok: true, online: navigator.onLine === true }, corId);
    if (isWatch && typeof window !== "undefined" && typeof window.addEventListener === "function") {
      // Each online/offline event delivers a fresh state; no correlation id on broadcasts.
      window.addEventListener("online", function () {
        reply({ tag: "connectivity", ok: true, online: true }, null);
      });
      window.addEventListener("offline", function () {
        reply({ tag: "connectivity", ok: true, online: false }, null);
      });
    }
    return true;
  }
  // Ipe.Browser.Orientation: `Watch` / `StopWatch` -> deviceorientation event.
  // A `Watch` attaches a `deviceorientation` listener on `window`; each event
  // delivers alpha/beta/gamma fields (each may be null when the axis is
  // unsupported). A `StopWatch` removes the listener. An absent event type
  // traps to a typed `unavailable` frame — never a throw.
  var orientationHandler = null;
  function orientationSink(value, _corId) {
    var isWatch = value === "Watch" ||
      (value && typeof value === "object" && value.Watch !== undefined);
    var isStop = value === "StopWatch" ||
      (value && typeof value === "object" && value.StopWatch !== undefined);
    if (!isWatch && !isStop) return false;
    if (isStop) {
      if (orientationHandler !== null && window.removeEventListener) {
        window.removeEventListener("deviceorientation", orientationHandler);
        orientationHandler = null;
      }
      return true;
    }
    // isWatch
    if (typeof window === "undefined" || typeof window.addEventListener !== "function") {
      reply({ tag: "orientation", event: "unavailable" }, null);
      return true;
    }
    if (orientationHandler !== null && window.removeEventListener) {
      window.removeEventListener("deviceorientation", orientationHandler);
    }
    orientationHandler = function (ev) {
      reply({
        tag: "orientation",
        event: "reading",
        alpha: (ev.alpha !== null && ev.alpha !== undefined) ? Number(ev.alpha) : null,
        beta: (ev.beta !== null && ev.beta !== undefined) ? Number(ev.beta) : null,
        gamma: (ev.gamma !== null && ev.gamma !== undefined) ? Number(ev.gamma) : null,
      }, null);
    };
    window.addEventListener("deviceorientation", orientationHandler);
    return true;
  }
  // Ipe.Browser.Motion: `Watch` / `StopWatch` -> devicemotion event.
  // A `Watch` attaches a `devicemotion` listener on `window`; each event
  // delivers acceleration (x/y/z in m/s²) and rotationRate (alpha/beta/gamma
  // in deg/s) fields (each may be null when the axis is unsupported). A
  // `StopWatch` removes the listener. An absent event type traps to a typed
  // `unavailable` frame — never a throw.
  var motionHandler = null;
  function motionSink(value, _corId) {
    var isWatch = value === "Watch" ||
      (value && typeof value === "object" && value.Watch !== undefined);
    var isStop = value === "StopWatch" ||
      (value && typeof value === "object" && value.StopWatch !== undefined);
    if (!isWatch && !isStop) return false;
    if (isStop) {
      if (motionHandler !== null && window.removeEventListener) {
        window.removeEventListener("devicemotion", motionHandler);
        motionHandler = null;
      }
      return true;
    }
    // isWatch
    if (typeof window === "undefined" || typeof window.addEventListener !== "function") {
      reply({ tag: "motion", event: "unavailable" }, null);
      return true;
    }
    if (motionHandler !== null && window.removeEventListener) {
      window.removeEventListener("devicemotion", motionHandler);
    }
    function maybeNum(v) { return (v !== null && v !== undefined) ? Number(v) : null; }
    motionHandler = function (ev) {
      var a = (ev.acceleration && typeof ev.acceleration === "object") ? ev.acceleration : {};
      var r = (ev.rotationRate && typeof ev.rotationRate === "object") ? ev.rotationRate : {};
      reply({
        tag: "motion",
        event: "reading",
        accelX: maybeNum(a.x),
        accelY: maybeNum(a.y),
        accelZ: maybeNum(a.z),
        rotAlpha: maybeNum(r.alpha),
        rotBeta: maybeNum(r.beta),
        rotGamma: maybeNum(r.gamma),
      }, null);
    };
    window.addEventListener("devicemotion", motionHandler);
    return true;
  }
  // Ipe.Browser.Channel: `Open name` / `Send name payload` / `Close name` ->
  // BroadcastChannel. `Open` creates a BroadcastChannel and attaches a `message`
  // listener that routes inbound frames. `Send` posts a string message. `Close`
  // closes and removes the channel. An absent API traps to a typed `unavailable`
  // frame — never a throw. Multiple channels keyed by name are tracked.
  var broadcastChannels = {};
  function channelSink(value, _corId) {
    var isOpen = value && typeof value === "object" && value.Open !== undefined;
    var isSend = value && typeof value === "object" && value.Send !== undefined;
    var isClose = value && typeof value === "object" && value.Close !== undefined;
    if (!isOpen && !isSend && !isClose) return false;
    if (typeof BroadcastChannel === "undefined") {
      reply({ tag: "channel", event: "unavailable" }, null);
      return true;
    }
    if (isOpen) {
      var name = typeof value.Open === "string" ? value.Open : String(value.Open);
      if (broadcastChannels[name]) { try { broadcastChannels[name].close(); } catch (_e) {} }
      var ch;
      try { ch = new BroadcastChannel(name); } catch (_e) {
        reply({ tag: "channel", event: "unavailable" }, null);
        return true;
      }
      ch.onmessage = function (ev) {
        var payload = typeof ev.data === "string" ? ev.data : JSON.stringify(ev.data);
        reply({ tag: "channel", event: "message", payload: payload }, null);
      };
      broadcastChannels[name] = ch;
      return true;
    }
    if (isSend) {
      var parts = (value.Send && typeof value.Send === "object") ? value.Send : {};
      // Send is [name, payload] encoded as { "0": name, "1": payload } or as an array.
      var sendName = (parts && typeof parts[0] === "string") ? parts[0] :
        (typeof parts.name === "string" ? parts.name : null);
      var sendPayload = (parts && typeof parts[1] === "string") ? parts[1] :
        (typeof parts.payload === "string" ? parts.payload : null);
      if (sendName && broadcastChannels[sendName]) {
        try { broadcastChannels[sendName].postMessage(sendPayload !== null ? sendPayload : ""); }
        catch (_e) { /* best-effort */ }
      }
      return true;
    }
    // isClose
    var closeName = typeof value.Close === "string" ? value.Close : String(value.Close);
    if (broadcastChannels[closeName]) {
      try { broadcastChannels[closeName].close(); } catch (_e) {}
      delete broadcastChannels[closeName];
    }
    return true;
  }
  // Ipe.Browser.Fullscreen: `Request` / `Exit` / `Watch` ->
  // the root element's requestFullscreen / the document's exitFullscreen /
  // fullscreenchange. `Request` and `Exit` are correlated one-shot; `Watch`
  // attaches a `fullscreenchange` listener for broadcast state frames. An absent
  // or denied API traps to typed frames — never a throw.
  function fullscreenSink(value, corId) {
    var isRequest = value === "Request" ||
      (value && typeof value === "object" && value.Request !== undefined);
    var isExit = value === "Exit" ||
      (value && typeof value === "object" && value.Exit !== undefined);
    var isWatch = value === "Watch" ||
      (value && typeof value === "object" && value.Watch !== undefined);
    if (!isRequest && !isExit && !isWatch) return false;
    if (isWatch) {
      if (doc && doc.on) {
        doc.on("fullscreenchange", function () {
          var isFull = !!doc.fullscreenElement();
          reply({ tag: "fullscreen", event: "changed", fullscreen: isFull }, null);
        });
      }
      return true;
    }
    if (isRequest) {
      var root = doc ? doc.root() : null;
      if (!root || typeof root.requestFullscreen !== "function") {
        reply({ tag: "fullscreen", event: "unavailable" }, corId);
        return true;
      }
      root.requestFullscreen().then(
        function () { reply({ tag: "fullscreen", event: "ok" }, corId); },
        function () { reply({ tag: "fullscreen", event: "denied" }, corId); }
      );
      return true;
    }
    // isExit
    if (!doc || !doc.exitFullscreen) {
      reply({ tag: "fullscreen", event: "unavailable" }, corId);
      return true;
    }
    doc.exitFullscreen().then(
      function () { reply({ tag: "fullscreen", event: "ok" }, corId); },
      function () { reply({ tag: "fullscreen", event: "denied" }, corId); }
    );
    return true;
  }
  // Ipe.Browser.ScreenOrientation: `Lock typeStr` / `Unlock` / `Query` ->
  // screen.orientation.lock / screen.orientation.unlock / screen.orientation.type.
  // `Lock` and `Unlock` are correlated one-shot; `Query` reads the current type
  // once. An absent or denied API traps to typed frames — never a throw.
  function screenOrientationSink(value, corId) {
    var isLock = value && typeof value === "object" && value.Lock !== undefined;
    var isUnlock = value === "Unlock" ||
      (value && typeof value === "object" && value.Unlock !== undefined);
    var isQuery = value === "Query" ||
      (value && typeof value === "object" && value.Query !== undefined);
    if (!isLock && !isUnlock && !isQuery) return false;
    if (typeof screen === "undefined" || !screen.orientation ||
        typeof screen.orientation.type !== "string") {
      reply({ tag: "screen-orientation", event: "unavailable" }, corId);
      return true;
    }
    if (isQuery) {
      reply({ tag: "screen-orientation", event: "orientation", type: screen.orientation.type }, corId);
      return true;
    }
    if (isUnlock) {
      try { screen.orientation.unlock(); } catch (_e) { /* best-effort */ }
      reply({ tag: "screen-orientation", event: "ok" }, corId);
      return true;
    }
    // isLock
    var lockType = typeof value.Lock === "string" ? value.Lock : "portrait-primary";
    if (typeof screen.orientation.lock !== "function") {
      reply({ tag: "screen-orientation", event: "unavailable" }, corId);
      return true;
    }
    screen.orientation.lock(lockType).then(
      function () { reply({ tag: "screen-orientation", event: "ok" }, corId); },
      function () { reply({ tag: "screen-orientation", event: "denied" }, corId); }
    );
    return true;
  }
  // Ipe.Browser.WakeLock: `Acquire` / `Release` ->
  // navigator.wakeLock.request("screen") / sentinel.release().
  // `Acquire` is a correlated one-shot; `Release` is fire-and-forget. An absent
  // or denied API traps to typed frames — never a throw.
  var wakeLockSentinel = null;
  function wakeLockSink(value, corId) {
    var isAcquire = value === "Acquire" ||
      (value && typeof value === "object" && value.Acquire !== undefined);
    var isRelease = value === "Release" ||
      (value && typeof value === "object" && value.Release !== undefined);
    if (!isAcquire && !isRelease) return false;
    if (isRelease) {
      if (wakeLockSentinel !== null) {
        try { wakeLockSentinel.release(); } catch (_e) { /* best-effort */ }
        wakeLockSentinel = null;
      }
      return true;
    }
    // isAcquire
    if (typeof navigator === "undefined" || !navigator.wakeLock ||
        typeof navigator.wakeLock.request !== "function") {
      reply({ tag: "wake-lock", event: "unavailable" }, corId);
      return true;
    }
    navigator.wakeLock.request("screen").then(
      function (sentinel) {
        wakeLockSentinel = sentinel;
        reply({ tag: "wake-lock", event: "acquired" }, corId);
      },
      function () { reply({ tag: "wake-lock", event: "denied" }, corId); }
    );
    return true;
  }
  // Ipe.Browser.WebAuthn: `Create opts` / `Get opts` ->
  // navigator.credentials.create / navigator.credentials.get. A one-shot
  // ceremony: it requires a corId so its opaque result routes only to the
  // matching Js.request waiter, never broadcast to js_subscribe subscribers.
  //
  // Fail-closed by construction:
  //   * every buffer-shaped field crosses as a base64url string; the sink
  //     decodes challenge / credential ids to ArrayBuffers for the browser and
  //     re-encodes every returned buffer to base64url, so no raw key material is
  //     ever placed in a frame.
  //   * a NotAllowedError / user cancellation / security refusal -> a typed
  //     `denied` frame; an absent navigator.credentials / PublicKeyCredential ->
  //     `unavailable`. Never a throw, never a leaked credential structure.
  function b64urlToBuf(s) {
    // Decode a base64url string to an ArrayBuffer. Invalid input yields an empty
    // buffer rather than throwing — the ceremony then fails closed downstream.
    var str = String(s || "");
    var b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    var pad = b64.length % 4;
    if (pad === 2) { b64 += "=="; } else if (pad === 3) { b64 += "="; }
    var bin;
    try { bin = atob(b64); } catch (_e) { return new ArrayBuffer(0); }
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i += 1) { bytes[i] = bin.charCodeAt(i); }
    return bytes.buffer;
  }
  function bufToB64url(buf) {
    if (!buf) { return ""; }
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i += 1) { bin += String.fromCharCode(bytes[i]); }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function webAuthnUnavailable() {
    return (typeof navigator === "undefined" || !navigator.credentials ||
      typeof PublicKeyCredential === "undefined");
  }
  function webAuthnFail(err, corId) {
    // A NotAllowedError / SecurityError / abort maps to a user-facing denial;
    // any other rejection is treated as unavailable. Never rethrown.
    var name = err && err.name ? String(err.name) : "";
    var kind = (name === "NotAllowedError" || name === "SecurityError" ||
      name === "AbortError") ? "denied" : "unavailable";
    reply({ tag: "web-authn", ok: false, error: kind }, corId);
  }
  function webAuthnSink(value, corId) {
    if (!value || typeof value !== "object") { return false; }
    var isCreate = value.Create && typeof value.Create === "object";
    var isGet = value.Get && typeof value.Get === "object";
    if (!isCreate && !isGet) { return false; }
    // Deny-by-default: a ceremony result must route to its one-shot waiter only.
    if (corId === null || corId === undefined) {
      return true; // recognised but uncorrelated — swallow, never broadcast
    }
    if (webAuthnUnavailable()) {
      reply({ tag: "web-authn", ok: false, error: "unavailable" }, corId);
      return true;
    }
    if (isCreate) {
      var c = value.Create;
      var createOpts = {
        publicKey: {
          rp: { id: String(c.rpId || ""), name: String(c.rpName || "") },
          user: {
            id: b64urlToBuf(c.userId),
            name: String(c.userName || ""),
            displayName: String(c.userDisplayName || ""),
          },
          challenge: b64urlToBuf(c.challenge),
          pubKeyCredParams: (Array.isArray(c.algorithms) ? c.algorithms : []).map(
            function (alg) { return { type: "public-key", alg: Number(alg) }; }
          ),
          timeout: (typeof c.timeoutMs === "number" && c.timeoutMs > 0) ? c.timeoutMs : undefined,
          authenticatorSelection: { userVerification: String(c.userVerification || "preferred") },
        },
      };
      navigator.credentials.create(createOpts).then(
        function (cred) {
          if (!cred || !cred.response) {
            reply({ tag: "web-authn", ok: false, error: "unavailable" }, corId);
            return;
          }
          reply({
            tag: "web-authn", ok: true, event: "registered",
            id: String(cred.id || ""),
            rawId: bufToB64url(cred.rawId),
            clientDataJson: bufToB64url(cred.response.clientDataJSON),
            attestationObject: bufToB64url(cred.response.attestationObject),
          }, corId);
        },
        function (err) { webAuthnFail(err, corId); }
      );
      return true;
    }
    var g = value.Get;
    var getOpts = {
      publicKey: {
        rpId: String(g.rpId || ""),
        challenge: b64urlToBuf(g.challenge),
        allowCredentials: (Array.isArray(g.allowCredentials) ? g.allowCredentials : []).map(
          function (id) { return { type: "public-key", id: b64urlToBuf(id) }; }
        ),
        timeout: (typeof g.timeoutMs === "number" && g.timeoutMs > 0) ? g.timeoutMs : undefined,
        userVerification: String(g.userVerification || "preferred"),
      },
    };
    navigator.credentials.get(getOpts).then(
      function (cred) {
        if (!cred || !cred.response) {
          reply({ tag: "web-authn", ok: false, error: "unavailable" }, corId);
          return;
        }
        reply({
          tag: "web-authn", ok: true, event: "asserted",
          id: String(cred.id || ""),
          rawId: bufToB64url(cred.rawId),
          clientDataJson: bufToB64url(cred.response.clientDataJSON),
          authenticatorData: bufToB64url(cred.response.authenticatorData),
          signature: bufToB64url(cred.response.signature),
          userHandle: bufToB64url(cred.response.userHandle),
        }, corId);
      },
      function (err) { webAuthnFail(err, corId); }
    );
    return true;
  }
  function builtinSink(value, corId) {
    if (clipboardSink(value, corId)) return true;
    if (geolocationSink(value, corId)) return true;
    if (notificationSink(value, corId)) return true;
    if (storageSink(value, corId)) return true;
    if (vibrationSink(value, corId)) return true;
    if (shareSink(value, corId)) return true;
    if (batterySink(value, corId)) return true;
    if (networkInfoSink(value, corId)) return true;
    if (filePickerSink(value, corId)) return true;
    if (cameraSink(value, corId)) return true;
    if (microphoneSink(value, corId)) return true;
    if (recorderSink(value, corId)) return true;
    if (speechSink(value, corId)) return true;
    if (gamepadSink(value, corId)) return true;
    if (visibilitySink(value, corId)) return true;
    if (mediaQuerySink(value, corId)) return true;
    if (connectivitySink(value, corId)) return true;
    if (orientationSink(value, corId)) return true;
    if (motionSink(value, corId)) return true;
    if (channelSink(value, corId)) return true;
    if (fullscreenSink(value, corId)) return true;
    if (screenOrientationSink(value, corId)) return true;
    if (wakeLockSink(value, corId)) return true;
    if (webAuthnSink(value, corId)) return true;
    return false;
  }
  function deliver(raw) {
    var value;
    try { value = JSON.parse(raw); } catch (_e) { return; /* drop a malformed frame */ }
    // If this frame carries a correlation id, it is a `js_request` envelope:
    // extract the id and the inner payload command, and pass the id through to
    // the reply so the runtime can route it to the one-shot waiter.
    var corId = null;
    if (value && typeof value === "object" && "__ipe_id" in value) {
      corId = value.__ipe_id;
      value = value.payload !== undefined ? value.payload : value;
    }
    // A first-party browser-capability command is handled by its built-in sink;
    // anything else is a developer port frame routed to the registered receiver.
    if (builtinSink(value, corId)) return;
    // For non-first-party frames, if there is a correlation id the developer JS
    // handler must echo it back; we pass it as a second argument to onReceive.
    if (typeof onReceive === "function") { onReceive(value, corId); }
  }
  // The runtime calls this with each outbound seal frame (a JSON string).
  window.ipeOnReceive = deliver;
  window.ipe = {
    send: function (value) {
      var raw;
      try { raw = JSON.stringify(value); } catch (_e) { return; }
      if (typeof window.__ipePortSend === "function") {
        window.__ipePortSend(raw);
      }
    },
    onReceive: function (fn) { onReceive = fn; },
    onSync: function (fn) { onReceive = fn; },
  };
})();
"#;

/// Assembled ES module: HEAD + generated scheme check + TAIL.
///
/// The URL scheme check inside `shareSink` is generated from `SHARE_SCHEMES`
/// so the JS transport guard is always consistent with the Ipê typed layer.
static PORT_GLUE_JS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    // Build a JS array literal from SHARE_SCHEMES, e.g. `["http","https"]`.
    let schemes_js: String = {
        let quoted: Vec<String> = SHARE_SCHEMES.iter().map(|s| format!("\"{s}\"")).collect();
        format!("[{}]", quoted.join(","))
    };
    // The generated snippet replaces the bare `data.url = p.url` assignment with
    // a fail-closed scheme guard: only http/https URLs reach the share sheet.
    let url_check = format!(
        "    if (typeof p.url === \"string\" && p.url !== \"\") {{\n      var _s = p.url.split(\":\")[0].toLowerCase();\n      if ({schemes_js}.indexOf(_s) !== -1) {{ data.url = p.url; }}\n    }}"
    );
    format!("{PORT_GLUE_JS_HEAD}{url_check}\n{PORT_GLUE_JS_TAIL}")
});

/// The full 32-byte SHA-256 digest of the glue bytes.
fn digest() -> [u8; 32] {
    Sha256::digest(PORT_GLUE_JS.as_bytes()).into()
}

/// The glue module's source bytes.
#[must_use]
pub fn port_glue_js() -> &'static str {
    &PORT_GLUE_JS
}

/// The content-addressed URL PATH (no base prefix) for the port glue asset,
/// `/_ipe/port.<hex16>.js`. Stable for given bytes; changes when the bytes
/// change — making `Cache-Control: immutable` safe.
#[must_use]
pub fn port_glue_path() -> String {
    let d = digest();
    let hex16: String = d[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("/_ipe/port.{hex16}.js")
}

/// The `sha256-<b64>` SRI value for the port glue asset.
#[must_use]
pub fn port_glue_integrity() -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    format!("sha256-{}", B64.encode(digest()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The glue reads no document member through the document's own lookup.
    #[test]
    fn glue_reads_the_document_only_through_the_bound_table() {
        let js = port_glue_js();
        assert_eq!(
            crate::js_document_scan::unbound_document_reads(js),
            Vec::<String>::new(),
            "the port glue names `document` only in its bound table"
        );
        assert_eq!(js.matches("})(document);").count(), 1);
    }

    #[test]
    fn path_is_content_addressed_and_stable() {
        let p = port_glue_path();
        assert!(p.starts_with("/_ipe/port."));
        assert!(p.ends_with(".js"));
        assert_eq!(p, port_glue_path()); // deterministic
    }

    #[test]
    fn integrity_is_a_sha256_sri() {
        let i = port_glue_integrity();
        assert!(i.starts_with("sha256-"));
        assert_eq!(i, port_glue_integrity()); // deterministic
    }

    #[test]
    fn surface_exposes_send_receive_sync() {
        let js = port_glue_js();
        assert!(js.contains("window.ipe"));
        assert!(js.contains("send:"));
        assert!(js.contains("onReceive:"));
        assert!(js.contains("onSync:"));
        assert!(js.contains("window.ipeOnReceive"));
        // Values cross as JSON only — never eval.
        assert!(js.contains("JSON.parse"));
        assert!(js.contains("JSON.stringify"));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn clipboard_sink_reaches_the_web_api_and_traps_denial_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Clipboard sink reaches its two Web APIs…
        assert!(js.contains("navigator.clipboard.writeText"));
        assert!(js.contains("navigator.clipboard.readText"));
        assert!(js.contains("WriteText"));
        assert!(js.contains("ReadText"));
        // …and traps a host denial / absence to a typed inbound frame, never a
        // throw: both the denied and the unavailable branches reply, no `eval`.
        assert!(js.contains("\"denied\""));
        assert!(js.contains("\"unavailable\""));
        assert!(js.contains("tag: \"clipboard\""));
        assert!(js.contains("reply("));
    }

    #[test]
    fn web_authn_sink_reaches_the_ceremonies_and_keeps_credentials_opaque() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.WebAuthn sink reaches both ceremonies…
        assert!(js.contains("navigator.credentials.create"));
        assert!(js.contains("navigator.credentials.get"));
        assert!(js.contains("value.Create"));
        assert!(js.contains("value.Get"));
        // …emits the two success events…
        assert!(js.contains("event: \"registered\""));
        assert!(js.contains("event: \"asserted\""));
        assert!(js.contains("tag: \"web-authn\""));
        // …carries every buffer field as base64url, never raw bytes…
        assert!(js.contains("bufToB64url"));
        assert!(js.contains("b64urlToBuf"));
        // …and traps a refusal / absence to a typed inbound frame, never a throw.
        assert!(js.contains("NotAllowedError"));
        assert!(js.contains("\"denied\""));
        assert!(js.contains("\"unavailable\""));
        assert!(js.contains("reply("));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn web_authn_sink_requires_a_correlation_id_and_never_broadcasts() {
        let js = port_glue_js();
        // The ceremony is one-shot: an uncorrelated frame is recognised and
        // swallowed, never broadcast to js_subscribe subscribers.
        assert!(js.contains("recognised but uncorrelated"));
    }

    #[test]
    fn geolocation_sink_reaches_the_web_api_and_enumerates_the_three_error_variants() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Geolocation sink reaches its Web APIs…
        assert!(js.contains("navigator.geolocation.getCurrentPosition"));
        assert!(js.contains("navigator.geolocation.watchPosition"));
        assert!(js.contains("navigator.geolocation.clearWatch"));
        assert!(js.contains("Current"));
        assert!(js.contains("Watch"));
        // …resolves a position to a typed Coords frame…
        assert!(js.contains("tag: \"geolocation\""));
        assert!(js.contains("lat:"));
        assert!(js.contains("lng:"));
        assert!(js.contains("accuracy:"));
        // …and enumerates all three inbound error variants, never a throw / eval.
        assert!(js.contains("\"denied\""));
        assert!(js.contains("\"unavailable\""));
        assert!(js.contains("\"timeout\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn notification_sink_reaches_the_web_api_and_traps_denial_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Notification sink reaches its Web APIs…
        assert!(js.contains("Notification.requestPermission"));
        assert!(js.contains("new Notification("));
        assert!(js.contains("RequestPermission"));
        assert!(js.contains("value.Show"));
        // …resolves a grant / display to a typed frame…
        assert!(js.contains("tag: \"notification\""));
        assert!(js.contains("\"granted\""));
        assert!(js.contains("\"shown\""));
        // …and traps a denial / absence to a typed inbound frame, never a throw.
        assert!(js.contains("\"denied\""));
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn storage_sink_reaches_web_storage_and_traps_unavailability_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Storage sink reaches localStorage…
        assert!(js.contains("localStorage"));
        assert!(js.contains("store.getItem("));
        assert!(js.contains("store.setItem("));
        assert!(js.contains("store.removeItem("));
        assert!(js.contains("store.clear()"));
        assert!(js.contains("value.Get"));
        assert!(js.contains("value.Set"));
        // …resolves reads / writes to typed events…
        assert!(js.contains("tag: \"storage\""));
        assert!(js.contains("event: \"get\""));
        assert!(js.contains("event: \"set\""));
        // …and traps a private-mode / absent store to a typed frame, never a throw.
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn vibration_sink_reaches_the_web_api_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Vibration sink reaches navigator.vibrate…
        assert!(js.contains("navigator.vibrate"));
        assert!(js.contains("value.Vibrate"));
        assert!(js.contains("value.Pattern"));
        // …acknowledges a supported actuator…
        assert!(js.contains("tag: \"vibration\""));
        // …and traps an absent actuator to a typed frame, never a throw.
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn share_sink_reaches_the_web_api_and_traps_cancel_and_absence_to_typed_results() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Share sink reaches navigator.share…
        assert!(js.contains("navigator.share"));
        assert!(js.contains("value.Share"));
        // …acknowledges a completion…
        assert!(js.contains("tag: \"share\""));
        // …and enumerates the cancel + unavailable outcomes, never a throw.
        assert!(js.contains("AbortError"));
        assert!(js.contains("\"cancelled\""));
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    /// Pin that the JS `shareSink` URL scheme guard is generated from `SHARE_SCHEMES`
    /// and that every scheme in `SHARE_SCHEMES` appears in the assembled JS.
    /// Drift — adding a scheme to `SHARE_SCHEMES` without it reaching the JS — fails
    /// this test, not a silent desync.
    #[test]
    fn share_sink_url_scheme_check_matches_share_schemes() {
        let js = port_glue_js();
        // The assembled JS must contain the generated scheme array literal.
        let schemes_js: String = {
            let quoted: Vec<String> = SHARE_SCHEMES.iter().map(|s| format!("\"{s}\"")).collect();
            format!("[{}]", quoted.join(","))
        };
        assert!(
            js.contains(&schemes_js),
            "JS share sink scheme guard is missing or desynced; expected array {schemes_js:?} in glue"
        );
        // Every individual scheme from the SSOT must appear in the JS guard.
        for scheme in SHARE_SCHEMES {
            assert!(
                js.contains(scheme),
                "SHARE_SCHEMES scheme {scheme:?} missing from assembled JS — SSOT drift"
            );
        }
        // Fail-closed: `data.url = p.url` appears ONLY inside the scheme-checked
        // branch — the guard is generated AND there is no bare/duplicate assignment
        // escaping it.
        assert!(
            js.contains("indexOf(_s) !== -1) { data.url = p.url; }"),
            "the scheme-guarded url assignment is missing — guard not generated"
        );
        assert_eq!(
            js.matches("data.url = p.url").count(),
            1,
            "expected exactly one (guarded) `data.url = p.url`; a bare or duplicate assignment escapes the scheme check"
        );
    }

    /// The static JS harness cannot execute the emitted glue, so this test drives
    /// the scheme predicate directly against the same fail-closed rule the emitted
    /// generated `SHARE_SCHEMES` guard implements, pinning that a `data:`/`file:`/
    /// `javascript:`/relative URL is refused and only `http`/`https` (any case)
    /// is admitted before the URL can reach `navigator.share`.
    #[test]
    fn share_url_scheme_predicate_refuses_non_web_schemes() {
        fn share_scheme_allowed(u: &str) -> bool {
            let scheme = match u.split_once(':') {
                Some((s, _)) if !s.is_empty() => s,
                _ => return false,
            };
            let Some(&head) = scheme.as_bytes().first() else {
                return false;
            };
            if !head.is_ascii_alphabetic() {
                return false;
            }
            if !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
            {
                return false;
            }
            let lowered = scheme.to_ascii_lowercase();
            lowered == "http" || lowered == "https"
        }

        // Refused — the exfiltration / injection schemes the issue flags…
        assert!(!share_scheme_allowed(
            "data:text/html,<script>steal()</script>"
        ));
        assert!(!share_scheme_allowed("file:///etc/passwd"));
        assert!(!share_scheme_allowed("javascript:alert(1)"));
        assert!(!share_scheme_allowed("blob:https://x/y"));
        assert!(!share_scheme_allowed("ftp://host/f"));
        // …and a relative / schemeless URL (no vetted absolute scheme).
        assert!(!share_scheme_allowed("/relative/path"));
        assert!(!share_scheme_allowed("example.com"));
        assert!(!share_scheme_allowed(""));
        // Admitted — only the vetted web schemes, case-insensitively.
        assert!(share_scheme_allowed("http://example.com"));
        assert!(share_scheme_allowed("https://example.com/path?q=1#f"));
        assert!(share_scheme_allowed("HTTPS://EXAMPLE.COM"));
    }

    #[test]
    fn battery_sink_reaches_the_web_api_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Battery sink reaches navigator.getBattery…
        assert!(js.contains("navigator.getBattery"));
        // …emits a typed reading with all four status fields…
        assert!(js.contains("tag: \"battery\""));
        assert!(js.contains("charging:"));
        assert!(js.contains("level:"));
        assert!(js.contains("chargingTime:"));
        assert!(js.contains("dischargingTime:"));
        // …and traps an absent API to a typed frame, never a throw.
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn network_info_sink_reaches_the_web_api_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.NetworkInfo sink reaches navigator.connection…
        assert!(js.contains("navigator.connection"));
        // …emits a typed reading with all four hint fields…
        assert!(js.contains("tag: \"network-info\""));
        assert!(js.contains("effectiveType:"));
        assert!(js.contains("downlink:"));
        assert!(js.contains("rtt:"));
        assert!(js.contains("saveData:"));
        // …and traps an absent API to a typed frame, never a throw.
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn file_picker_sink_opens_input_element_and_traps_cancel_and_absence_to_typed_results() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.FilePicker sink creates a file input element…
        assert!(js.contains("filePickerSink"));
        assert!(js.contains("PickFile"));
        assert!(js.contains("PickImage"));
        assert!(js.contains("input.type = \"file\""));
        assert!(js.contains("FileReader"));
        assert!(js.contains("readAsDataURL"));
        // …resolves a selection to a typed frame with name / mime / dataUrl fields…
        assert!(js.contains("tag: \"file-picker\""));
        assert!(js.contains("name:"));
        assert!(js.contains("mime:"));
        assert!(js.contains("dataUrl:"));
        // …and enumerates the cancelled + unavailable outcomes, never a throw.
        assert!(js.contains("\"cancelled\""));
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn camera_sink_uses_capture_attribute_and_traps_cancel_and_absence_to_typed_results() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Camera sink uses the capture attribute…
        assert!(js.contains("cameraSink"));
        assert!(js.contains("CapturePhoto"));
        assert!(js.contains("input.capture = \"environment\""));
        assert!(js.contains("input.accept = \"image/*\""));
        // …reads via FileReader…
        assert!(js.contains("FileReader"));
        assert!(js.contains("readAsDataURL"));
        // …resolves a capture to a typed frame with name / mime / dataUrl fields…
        assert!(js.contains("tag: \"camera\""));
        // …and enumerates the cancelled + unavailable outcomes, never a throw.
        assert!(js.contains("\"cancelled\""));
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn microphone_sink_reaches_get_user_media_and_traps_denial_and_absence_to_typed_results() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Microphone sink reaches getUserMedia…
        assert!(js.contains("microphoneSink"));
        assert!(js.contains("CaptureAudio"));
        assert!(js.contains("navigator.mediaDevices.getUserMedia"));
        assert!(js.contains("MediaRecorder"));
        // …caps maxDurationMs to 8 000 ms…
        assert!(js.contains("Math.min(opts.maxDurationMs, 8000)"));
        // …assembles chunks via FileReader.readAsDataURL…
        assert!(js.contains("ondataavailable"));
        assert!(js.contains("FileReader"));
        assert!(js.contains("readAsDataURL"));
        // …resolves a recording to a typed frame with data / mime / durationMs fields…
        assert!(js.contains("tag: \"microphone\""));
        assert!(js.contains("data:"));
        assert!(js.contains("durationMs:"));
        // …and enumerates the denied + unavailable outcomes, never a throw / eval.
        assert!(js.contains("\"denied\""));
        assert!(js.contains("\"unavailable\""));
        assert!(js.contains("NotAllowedError"));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn recorder_sink_streams_chunks_and_never_emits_after_close() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Recorder sink reaches getUserMedia +
        // MediaRecorder and reacts to the Start / Stop verbs.
        assert!(js.contains("recorderSink"));
        assert!(js.contains("value.Start"));
        assert!(js.contains("value.Stop"));
        assert!(js.contains("navigator.mediaDevices.getUserMedia"));
        assert!(js.contains("MediaRecorder"));
        // The audio-only vs audio+video getUserMedia constraint switch.
        assert!(js.contains("{ audio: true, video: true }"));
        assert!(js.contains("{ audio: true }"));
        // Delivers a session-stream of typed started / chunk / ended frames.
        assert!(js.contains("tag: \"recorder\""));
        assert!(js.contains("event: \"started\""));
        assert!(js.contains("event: \"chunk\""));
        assert!(js.contains("event: \"ended\""));
        assert!(js.contains("ondataavailable"));
        assert!(js.contains("readAsDataURL"));
        // The no-frame-after-close guarantee: a one-way active flag flipped false
        // on teardown, re-checked at chunk delivery time so a late blob is dropped.
        assert!(js.contains("recorderState.active !== true"));
        assert!(js.contains("recorderState.active = false"));
        // Denial + unavailability trap to typed terminal frames, never a throw / eval.
        assert!(js.contains("event: kind"));
        assert!(js.contains("NotAllowedError"));
        assert!(js.contains("event: \"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn recorder_sink_cancels_a_superseded_in_flight_grant_via_epoch() {
        let js = port_glue_js();
        // A monotonic epoch tracks the in-flight getUserMedia grant. Each Start
        // captures the current generation before requesting media.
        assert!(js.contains("var recorderEpoch = 0;"));
        assert!(js.contains("var myEpoch = ++recorderEpoch;"));
        // teardown (hence every Stop, including a no-op null-state Stop) bumps the
        // epoch, so a pending grant becomes cancellable.
        assert!(js.contains("recorderEpoch += 1;"));
        // Stop-before-grant: the success arm of a superseded grant releases the
        // just-granted tracks and starts / emits nothing.
        assert!(js.contains("if (myEpoch !== recorderEpoch) {"));
        assert!(js.contains("stream.getTracks().forEach(function (t) { t.stop(); });"));
        // The reject arm of a superseded grant stays silent — no stale
        // denied / unavailable frame leaks after the session closed.
        assert!(js.contains("if (myEpoch !== recorderEpoch) { return; }"));
    }

    #[test]
    fn speech_sink_reaches_the_web_api_and_traps_absence_and_failure_to_typed_results() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Speech sink reaches speechSynthesis…
        assert!(js.contains("speechSink"));
        assert!(js.contains("value.Speak"));
        assert!(js.contains("window.speechSynthesis.speak"));
        assert!(js.contains("SpeechSynthesisUtterance"));
        assert!(js.contains("window.speechSynthesis.cancel"));
        // …applies rate / pitch / volume / lang options…
        assert!(js.contains("utterance.rate"));
        assert!(js.contains("utterance.pitch"));
        assert!(js.contains("utterance.volume"));
        assert!(js.contains("utterance.lang"));
        // …resolves a completed utterance to a typed Spoken frame…
        assert!(js.contains("tag: \"speech\""));
        assert!(js.contains("ok: true"));
        // …and traps absence + failure to typed frames, never a throw / eval.
        assert!(js.contains("\"unavailable\""));
        assert!(js.contains("\"failed\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn visibility_sink_reaches_the_web_api_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Visibility sink reads the visibility state…
        assert!(js.contains("visibilitySink"));
        assert!(js.contains("visibility: prop(\"visibilityState\")"));
        assert!(js.contains("visibilitychange"));
        // …emits a typed reading with the `visible` boolean field…
        assert!(js.contains("tag: \"visibility\""));
        assert!(js.contains("visible:"));
        // …and traps an absent API to a typed frame, never a throw.
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn media_query_sink_reaches_the_web_api_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.MediaQuery sink reaches window.matchMedia…
        assert!(js.contains("mediaQuerySink"));
        assert!(js.contains("window.matchMedia"));
        assert!(js.contains("mql.matches"));
        // …emits a typed reading with the `matches` boolean field…
        assert!(js.contains("tag: \"media-query\""));
        assert!(js.contains("matches:"));
        // …and traps an absent API to a typed frame, never a throw.
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn connectivity_sink_reaches_the_web_api_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Connectivity sink reads navigator.onLine…
        assert!(js.contains("connectivitySink"));
        assert!(js.contains("navigator.onLine"));
        // …attaches online/offline event listeners for the watch path…
        assert!(js.contains("\"online\""));
        assert!(js.contains("\"offline\""));
        // …emits a typed reading with the `online` boolean field…
        assert!(js.contains("tag: \"connectivity\""));
        assert!(js.contains("online:"));
        // …and traps an absent API to a typed frame, never a throw.
        assert!(js.contains("\"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn geolocation_watch_ids_tracked_as_set_so_double_watch_is_fully_clearable() {
        let js = port_glue_js();
        // Ids stored in an array, not a single scalar — a second Watch pushes
        // rather than overwrites, so ClearWatch drains every id in the set.
        assert!(js.contains("geoWatchIds"));
        assert!(js.contains("geoWatchIds.push("));
        assert!(js.contains("geoWatchIds.length"));
        assert!(js.contains("geoWatchIds = []"));
        // No single-id scalar: the old geoWatchId variable must not exist.
        assert!(!js.contains("geoWatchId ="));
        assert!(!js.contains("geoWatchId !=="));
    }

    #[test]
    fn gamepad_sink_polls_via_raf_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        // The first-party Ipe.Browser.Gamepad sink registers lifecycle listeners…
        assert!(js.contains("gamepadSink"));
        assert!(js.contains("Watch"));
        assert!(js.contains("StopWatch"));
        assert!(js.contains("gamepadconnected"));
        assert!(js.contains("gamepaddisconnected"));
        // …polls via requestAnimationFrame, not a busy-loop…
        assert!(js.contains("requestAnimationFrame"));
        assert!(js.contains("cancelAnimationFrame"));
        // …reaches navigator.getGamepads() for state frames…
        assert!(js.contains("navigator.getGamepads"));
        // …emits typed connect / disconnect / state frames with the right fields…
        assert!(js.contains("tag: \"gamepad\""));
        assert!(js.contains("event: \"connected\""));
        assert!(js.contains("event: \"disconnected\""));
        assert!(js.contains("event: \"state\""));
        assert!(js.contains("buttons:"));
        assert!(js.contains("axes:"));
        // …and traps an absent API to a typed frame, never a throw / eval.
        assert!(js.contains("event: \"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn orientation_sink_attaches_deviceorientation_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        assert!(js.contains("orientationSink"));
        assert!(js.contains("deviceorientation"));
        assert!(js.contains("tag: \"orientation\""));
        assert!(js.contains("event: \"reading\""));
        assert!(js.contains("alpha:"));
        assert!(js.contains("beta:"));
        assert!(js.contains("gamma:"));
        assert!(js.contains("event: \"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn motion_sink_attaches_devicemotion_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        assert!(js.contains("motionSink"));
        assert!(js.contains("devicemotion"));
        assert!(js.contains("tag: \"motion\""));
        assert!(js.contains("event: \"reading\""));
        assert!(js.contains("accelX:"));
        assert!(js.contains("rotAlpha:"));
        assert!(js.contains("event: \"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn channel_sink_uses_broadcast_channel_and_traps_absence_to_a_typed_result() {
        let js = port_glue_js();
        assert!(js.contains("channelSink"));
        assert!(js.contains("BroadcastChannel"));
        assert!(js.contains("tag: \"channel\""));
        assert!(js.contains("event: \"message\""));
        assert!(js.contains("event: \"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn fullscreen_sink_reaches_the_web_api_and_traps_absence_and_denial_to_typed_results() {
        let js = port_glue_js();
        assert!(js.contains("fullscreenSink"));
        assert!(js.contains("requestFullscreen"));
        assert!(js.contains("exitFullscreen"));
        assert!(js.contains("fullscreenchange"));
        assert!(js.contains("tag: \"fullscreen\""));
        assert!(js.contains("event: \"ok\""));
        assert!(js.contains("event: \"denied\""));
        assert!(js.contains("event: \"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn screen_orientation_sink_reaches_the_web_api_and_traps_absence_to_typed_results() {
        let js = port_glue_js();
        assert!(js.contains("screenOrientationSink"));
        assert!(js.contains("screen.orientation"));
        assert!(js.contains("tag: \"screen-orientation\""));
        assert!(js.contains("event: \"orientation\""));
        assert!(js.contains("event: \"ok\""));
        assert!(js.contains("event: \"unavailable\""));
        assert!(!js.contains("eval("));
    }

    #[test]
    fn wake_lock_sink_reaches_navigator_wake_lock_and_traps_absence_to_typed_results() {
        let js = port_glue_js();
        assert!(js.contains("wakeLockSink"));
        assert!(js.contains("navigator.wakeLock"));
        assert!(js.contains("wakeLock.request"));
        assert!(js.contains("tag: \"wake-lock\""));
        assert!(js.contains("event: \"acquired\""));
        assert!(js.contains("event: \"denied\""));
        assert!(js.contains("event: \"unavailable\""));
        assert!(!js.contains("eval("));
    }
}
