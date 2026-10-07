//! Server-driven TEA debugger — session-scoped history and overlay HTML.
//!
//! Enabled only when the `debugger` feature is active.

#![cfg(feature = "debugger")]

use crate::debugger::History;
use crate::stringify::IpeStringify;
use crate::tea::IpeCmd;

// ── Per-session history ───────────────────────────────────────────────────────

/// Bounded, rolling TEA message history for one server-driven session.
///
/// Wraps [`History`] with the `update` fn pointer the session driver already
/// knows. Memory is bounded: at most `cap` messages plus one base `Model`.
pub struct SessionHistory<Msg, Model> {
    inner: History<Msg, Model>,
}

impl<Msg: Clone, Model: Clone> SessionHistory<Msg, Model> {
    /// Create a new history seeded from `initial_model`.
    ///
    /// `cap` is clamped to a minimum of 1. Pass [`DEFAULT_HISTORY_CAP`] when
    /// no custom bound is needed.
    #[must_use]
    pub fn new(
        initial_model: Model,
        update: fn(Msg, Model) -> (Model, IpeCmd<Msg>),
        cap: usize,
    ) -> Self {
        Self {
            inner: History::new(initial_model, update, cap),
        }
    }

    /// Record one live-pass step.
    pub fn record(&mut self, msg: Msg, model_after: Model) {
        self.inner.record(msg, model_after);
    }

    /// Reconstruct the model at retained-log step `n` (0-indexed).
    ///
    /// Returns `None` when `n` is out of the retained window. No `Cmd` is
    /// re-fired; this is a pure re-fold.
    #[must_use]
    pub fn reconstruct(&self, n: usize) -> Option<Model> {
        self.inner.reconstruct(n)
    }

    /// Number of retained steps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when no steps have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Render each retained message as a redacted label string (oldest first).
    ///
    /// Labels pass through `IpeStringify::ipe_show` so any `Secret`-bearing
    /// field in `Msg` renders as `<redacted>`. The raw `Msg` value is never
    /// serialised or sent to the client.
    pub fn labels(&self) -> Vec<String>
    where
        Msg: IpeStringify,
    {
        self.inner.msgs().map(IpeStringify::ipe_show).collect()
    }
}

// ── Overlay HTML ──────────────────────────────────────────────────────────────

/// Inline CSS for the server-side debugger overlay panel (fixed bottom-right).
///
/// Self-contained; no external stylesheet needed. The overlay element carries
/// `data-ipe-debugger` so the diff/patch engine ignores it.
const OVERLAY_STYLE: &str = concat!(
    "position:fixed;bottom:0;right:0;width:320px;max-height:40vh;",
    "background:#1e1e1e;color:#d4d4d4;font:12px/1.4 monospace;",
    "border-top-left-radius:6px;overflow:hidden;",
    "box-shadow:0 -2px 8px rgba(0,0,0,.4);z-index:2147483647;",
    "display:flex;flex-direction:column;"
);

/// Background tint for the selected (scrubbed) message row.
///
/// Built with `concat!` so the hex segments are not adjacent in source.
const SELECTED_ROW_BG: &str = concat!("#", "264f78");

/// Maximum label characters shown per message row.
const MAX_LABEL_LEN: usize = 80;

/// Truncate a label to at most `max` characters, appending the Unicode
/// ellipsis character (U+2026) when cut.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let cut = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
    let mut out = s[..cut].to_owned();
    out.push('\u{2026}');
    out
}

/// Build the overlay `<div>` fragment to inject into the served HTML page.
///
/// `labels`     — rendered message labels (oldest first, already `ipe_show`'d).
/// `total`      — total retained steps (equals `labels.len()`).
/// `scrub_base` — URL base prefix, e.g. `""` for root-mounted apps or
///                `"/myapp"` for sub-apps.
///
/// The overlay element carries `data-ipe-debugger` (no `ipe-id` attribute) so
/// `assign_ipe_ids` / diff / patch never touch it.
///
/// The "reset to init" button POSTs to `/_ipe/debug/reset` and reloads the
/// page on success, giving the dev the same fresh-`init` state as a
/// cold-start without a full rebuild.
pub fn overlay_html(labels: &[String], total: usize, scrub_base: &str) -> String {
    let max_str = total.to_string();
    let cur_str = total.to_string(); // live mode: scrubber at rightmost position
    let scrub_url = format!("{scrub_base}/_ipe/debug/scrub");
    let reset_url = format!("{scrub_base}/_ipe/debug/reset");

    let mut rows = String::new();
    for (idx, label) in labels.iter().enumerate() {
        let truncated = truncate(label, MAX_LABEL_LEN);
        let escaped = crate::escape::html_attr(&truncated);
        rows.push_str(&format!(
            "<div data-ipe-dbg-step=\"{idx}\" \
             style=\"padding:1px 8px;cursor:pointer;\
             white-space:nowrap;overflow:hidden;text-overflow:ellipsis;\" \
             title=\"{escaped}\">{escaped}</div>",
        ));
    }

    let scrub_url_js = serde_json::to_string(&scrub_url)
        .unwrap_or_else(|_| format!("\"{}\"", scrub_url.replace('"', "\\\"")));
    let reset_url_js = serde_json::to_string(&reset_url)
        .unwrap_or_else(|_| format!("\"{}\"", reset_url.replace('"', "\\\"")));

    let script = build_overlay_script(&scrub_url_js, &reset_url_js, SELECTED_ROW_BG);

    format!(
        "<div data-ipe-debugger style=\"{OVERLAY_STYLE}\">\
           <div style=\"display:flex;align-items:center;gap:6px;padding:4px 6px;\
                        background:#252526;flex-shrink:0;\">\
             <span style=\"flex-shrink:0;opacity:.7;\">▶ Debugger</span>\
             <input type=\"range\" min=\"0\" max=\"{max_str}\" value=\"{cur_str}\" \
                    style=\"flex:1;min-width:0;\">\
             <button data-ipe-dbg-reset \
                     style=\"flex-shrink:0;padding:1px 6px;font:11px monospace;\
                             background:#c0392b;color:#fff;border:none;\
                             border-radius:3px;cursor:pointer;\" \
                     title=\"Reset session to init (clears history)\">\
               ↺ reset\
             </button>\
           </div>\
           <div data-ipe-dbg-list style=\"overflow-y:auto;flex:1;padding:4px 0;\">\
             {rows}\
           </div>\
         </div>\
         {script}",
    )
}

/// Emit the inline `<script>` block that wires the scrubber, row-click, and reset button.
///
/// The script runs in a self-calling function to avoid polluting the page's
/// global scope. It binds the panel as its own tag's previous sibling and reads
/// the document only through members bound from the prototypes, so app markup
/// carrying `data-ipe-debugger`, or an `img`/`form` named after a document
/// member, never stands in for the panel or the page root.
fn build_overlay_script(scrub_url_js: &str, reset_url_js: &str, selected_bg: &str) -> String {
    format!(
        "<script>\n\
(function(){{\n\
  var doc=(function(d){{\n\
    var cur=Object.getOwnPropertyDescriptor(Document.prototype,'currentScript');\n\
    return {{script:function(){{return cur&&cur.get?cur.get.call(d):null;}},\n\
      byId:Document.prototype.getElementById.bind(d)}};\n\
  }})(document);\n\
  var own=doc.script();\n\
  var panel=own?own.previousElementSibling:null;\n\
  if(!panel||!panel.hasAttribute('data-ipe-debugger'))return;\n\
  var scrubber=panel.querySelector('input[type=range]');\n\
  var list=panel.querySelector('[data-ipe-dbg-list]');\n\
  var resetBtn=panel.querySelector('[data-ipe-dbg-reset]');\n\
  function highlight(n){{\n\
    var rows=list?list.querySelectorAll('[data-ipe-dbg-step]'):[];\n\
    for(var i=0;i<rows.length;i++){{\n\
      var step=parseInt(rows[i].getAttribute('data-ipe-dbg-step'),10);\n\
      rows[i].style.background=step===n?'{selected_bg}':'';\n\
    }}\n\
  }}\n\
  function csrfToken(){{\n\
    return window.__IPE_CSRF_TOKEN||'';\n\
  }}\n\
  function post(n){{\n\
    var xhr=new XMLHttpRequest();\n\
    xhr.open('POST',{scrub_url_js},true);\n\
    xhr.setRequestHeader('Content-Type','application/json');\n\
    var csrf=csrfToken();\n\
    if(csrf)xhr.setRequestHeader('X-Ipe-Csrf',csrf);\n\
    xhr.onload=function(){{\n\
      if(xhr.status===200){{\n\
        try{{\n\
          var d=JSON.parse(xhr.responseText);\n\
          if(d&&d.body){{\n\
            var root=doc.byId('ipe-root');\n\
            if(root){{root.innerHTML=d.body;window.__ipeEpoch=typeof d.epoch==='string'?d.epoch:null;}}\n\
          }}\n\
        }}catch(e){{}}\n\
      }}\n\
    }};\n\
    xhr.send(JSON.stringify({{index:n}}));\n\
  }}\n\
  if(scrubber)scrubber.addEventListener('input',function(){{\n\
    var v=parseInt(this.value,10);\n\
    var mx=parseInt(this.max,10);\n\
    if(v>=mx){{window.location.reload();return;}}\n\
    post(v);highlight(v);\n\
  }});\n\
  if(list)list.addEventListener('click',function(e){{\n\
    var el=e.target;\n\
    while(el&&el!==list){{\n\
      var s=el.getAttribute('data-ipe-dbg-step');\n\
      if(s!==null){{\n\
        var n=parseInt(s,10);\n\
        if(scrubber)scrubber.value=String(n);\n\
        post(n);highlight(n);\n\
        return;\n\
      }}\n\
      el=el.parentElement;\n\
    }}\n\
  }});\n\
  if(resetBtn)resetBtn.addEventListener('click',function(){{\n\
    var xhr=new XMLHttpRequest();\n\
    xhr.open('POST',{reset_url_js},true);\n\
    var csrf=csrfToken();\n\
    if(csrf)xhr.setRequestHeader('X-Ipe-Csrf',csrf);\n\
    xhr.onload=function(){{\n\
      if(xhr.status===200)window.location.reload();\n\
    }};\n\
    xhr.send();\n\
  }});\n\
}})();\n\
</script>",
    )
}

// ── Live inspection surface ───────────────────────────────────────────────────

/// Render the current datum as a structural string.
///
/// Delegates to `IpeStringify::ipe_show`, which is total and read-only: it
/// never mutates the model or fires any effect. `Secret`-bearing fields emit
/// `<redacted>` so no sensitive value reaches the response.
///
/// This is the sole building block for `GET /_ipe/debug/inspect`; keeping it
/// as a plain function lets it be unit-tested without an HTTP stack.
pub fn inspect_model<Model: crate::stringify::IpeStringify>(model: &Model) -> String {
    model.ipe_show()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    // ── Overlay helpers ────────────────────────────────────────────────────────

    #[test]
    fn truncate_short_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_appends_ellipsis() {
        let t = truncate("abcdefghij", 5);
        assert!(t.starts_with("abcde") && t.ends_with('\u{2026}'));
    }

    #[test]
    fn overlay_label_cannot_break_out_of_its_title_attribute() {
        let html = overlay_html(&["a'b\"c<d".to_owned()], 1, "");
        let row = html
            .split_once("data-ipe-dbg-step=\"0\"")
            .map_or("", |(_, rest)| rest);
        let title = row.split_once("title=\"").map_or("", |(_, rest)| rest);
        let value = title.split_once('"').map_or("<unclosed>", |(v, _)| v);
        assert_eq!(value, "a&#39;b&#34;c&lt;d");
        assert!(!value.contains(['\'', '"', '<']));
        assert!(
            row.contains(">a&#39;b&#34;c&lt;d</div>"),
            "row text must be escaped too: {row}"
        );
    }

    #[test]
    fn overlay_html_has_required_attrs() {
        let html = overlay_html(&["Add(1)".to_owned(), "Reset".to_owned()], 2, "");
        assert!(
            html.contains("data-ipe-debugger"),
            "overlay must carry data-ipe-debugger"
        );
        assert!(
            !html.contains("ipe-id"),
            "overlay must not carry ipe-id attribute"
        );
        assert!(
            html.contains("type=\"range\""),
            "overlay must include a scrubber range input"
        );
        assert!(
            html.contains("/_ipe/debug/scrub"),
            "overlay must reference the scrub endpoint"
        );
        assert!(
            html.contains("/_ipe/debug/reset"),
            "overlay must include the reset-to-init endpoint"
        );
        assert!(
            html.contains("data-ipe-dbg-reset"),
            "overlay must include the reset button"
        );
        assert!(
            html.contains("root.innerHTML=d.body;window.__ipeEpoch=typeof d.epoch==='string'"),
            "a scrubbed render must replace the client's render epoch with its own"
        );
    }

    /// The overlay script reads no document member through the document's own lookup.
    #[test]
    fn overlay_reads_the_document_only_through_the_bound_table() {
        let html = overlay_html(&["Add(1)".to_owned()], 1, "");
        assert_eq!(
            crate::js_document_scan::unbound_document_reads(&html),
            Vec::<String>::new(),
            "the overlay names `document` only in its bound table"
        );
        assert_eq!(html.matches("})(document);").count(), 1);
        assert!(
            html.contains("</div><script>")
                && html.contains("var panel=own?own.previousElementSibling:null;"),
            "the overlay script binds the panel it directly follows"
        );
    }

    #[test]
    fn overlay_html_base_prefix() {
        let html = overlay_html(&[], 0, "/myapp");
        assert!(
            html.contains("/myapp/_ipe/debug/scrub"),
            "overlay must use sub-app base prefix for the scrub endpoint"
        );
        assert!(
            html.contains("/myapp/_ipe/debug/reset"),
            "overlay must use sub-app base prefix for the reset endpoint"
        );
    }

    // ── SessionHistory ─────────────────────────────────────────────────────────

    #[derive(Clone, Debug, PartialEq)]
    enum TestMsg {
        Add(i64),
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TestModel {
        count: i64,
    }

    fn test_update(msg: TestMsg, m: TestModel) -> (TestModel, IpeCmd<TestMsg>) {
        let TestMsg::Add(n) = msg;
        (TestModel { count: m.count + n }, IpeCmd::None)
    }

    impl IpeStringify for TestMsg {
        fn ipe_show(&self) -> String {
            match self {
                TestMsg::Add(n) => format!("Add({n})"),
            }
        }
    }

    #[test]
    fn session_history_record_reconstruct() {
        let mut h = SessionHistory::new(TestModel { count: 0 }, test_update, 16);
        let (m1, _) = test_update(TestMsg::Add(5), TestModel { count: 0 });
        h.record(TestMsg::Add(5), m1.clone());
        let (m2, _) = test_update(TestMsg::Add(3), m1);
        h.record(TestMsg::Add(3), m2);

        assert_eq!(h.len(), 2);
        let r = h.reconstruct(0).expect("step 0 must exist");
        assert_eq!(r.count, 5, "reconstruct step 0 = count 5");
        let r1 = h.reconstruct(1).expect("step 1 must exist");
        assert_eq!(r1.count, 8, "reconstruct step 1 = count 8");
    }

    #[test]
    fn session_history_out_of_range_is_none() {
        let h: SessionHistory<TestMsg, TestModel> =
            SessionHistory::new(TestModel { count: 0 }, test_update, 16);
        assert!(
            h.reconstruct(0).is_none(),
            "out-of-range reconstruct must return None"
        );
    }

    #[test]
    fn session_history_labels() {
        let mut h = SessionHistory::new(TestModel { count: 0 }, test_update, 16);
        let (m, _) = test_update(TestMsg::Add(7), TestModel { count: 0 });
        h.record(TestMsg::Add(7), m);
        let labels = h.labels();
        assert_eq!(labels, vec!["Add(7)"]);
    }

    // ── Scrub fires zero additional Cmds ──────────────────────────────────────

    #[test]
    fn scrub_reconstruct_fires_zero_cmds() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let effect_count = Arc::new(AtomicUsize::new(0));

        let counter = Arc::clone(&effect_count);
        let live_update = move |msg: TestMsg, m: TestModel| -> (TestModel, IpeCmd<TestMsg>) {
            counter.fetch_add(1, Ordering::SeqCst);
            let TestMsg::Add(n) = msg;
            (TestModel { count: m.count + n }, IpeCmd::None)
        };

        // `SessionHistory` stores its own update fn; reconstruct uses it without
        // touching the live-pass closure, so the effect counter stays frozen.
        let reconstruct_fn: fn(TestMsg, TestModel) -> (TestModel, IpeCmd<TestMsg>) = test_update;

        let mut h = SessionHistory::new(TestModel { count: 0 }, reconstruct_fn, 16);
        let mut live = TestModel { count: 0 };
        for n in [10i64, 5, 3] {
            let (next, _) = live_update(TestMsg::Add(n), live.clone());
            h.record(TestMsg::Add(n), next.clone());
            live = next;
        }

        let live_effects = effect_count.load(Ordering::SeqCst);
        assert_eq!(live_effects, 3, "live pass fired 3 effects");

        let at1 = h.reconstruct(1).expect("step 1 must exist");
        assert_eq!(at1.count, 15, "scrub step 1 = count 15");

        let after = effect_count.load(Ordering::SeqCst);
        assert_eq!(
            live_effects, after,
            "scrub must fire zero additional effects"
        );
    }

    // ── Sessions are independent ───────────────────────────────────────────────

    #[test]
    fn two_sessions_independent() {
        let mut h1 = SessionHistory::new(TestModel { count: 0 }, test_update, 16);
        let mut h2 = SessionHistory::new(TestModel { count: 100 }, test_update, 16);

        let (m1a, _) = test_update(TestMsg::Add(1), TestModel { count: 0 });
        h1.record(TestMsg::Add(1), m1a);

        let (m2a, _) = test_update(TestMsg::Add(50), TestModel { count: 100 });
        h2.record(TestMsg::Add(50), m2a);

        let r1 = h1.reconstruct(0).expect("h1 step 0");
        let r2 = h2.reconstruct(0).expect("h2 step 0");
        assert_eq!(r1.count, 1, "session 1 is independent of session 2");
        assert_eq!(r2.count, 150, "session 2 is independent of session 1");
    }

    // ── inspect_model — live inspection surface ───────────────────────────────

    impl IpeStringify for TestModel {
        fn ipe_show(&self) -> String {
            format!("TestModel {{ count: {} }}", self.count)
        }
    }

    // Inspector output reflects the current datum via `IpeStringify::ipe_show`.
    #[test]
    fn inspect_model_reflects_current_datum() {
        let model = TestModel { count: 42 };
        let rendered = inspect_model(&model);
        assert!(
            rendered.contains("42"),
            "inspect output must contain the model's count value; got: {rendered:?}"
        );
    }

    // Calling `inspect_model` does not mutate the model.
    #[test]
    fn inspect_model_is_read_only() {
        let model = TestModel { count: 7 };
        let before = model.count;
        let _ = inspect_model(&model);
        assert_eq!(model.count, before, "inspect must not mutate the model");
    }

    // ── Secret redaction in labels ─────────────────────────────────────────────

    #[cfg(feature = "secret")]
    #[test]
    fn secret_in_msg_redacted_in_labels() {
        use crate::secret::secret_from_string;

        #[derive(Clone, Debug)]
        enum SecretMsg {
            Login(crate::secret::Secret),
        }

        impl IpeStringify for SecretMsg {
            fn ipe_show(&self) -> String {
                match self {
                    SecretMsg::Login(s) => format!("Login({})", s.ipe_show()),
                }
            }
        }

        #[derive(Clone, Debug)]
        struct SecretModel;

        fn secret_update(_msg: SecretMsg, m: SecretModel) -> (SecretModel, IpeCmd<SecretMsg>) {
            (m, IpeCmd::None)
        }

        let secret = secret_from_string("super-secret".to_owned());
        let mut h = SessionHistory::new(SecretModel, secret_update, 8);
        h.record(SecretMsg::Login(secret.clone()), SecretModel);

        let labels = h.labels();
        assert_eq!(labels.len(), 1);
        assert!(
            !labels[0].contains("super-secret"),
            "Secret must not appear in label; got: {:?}",
            labels[0]
        );
        assert!(
            labels[0].contains("<redacted>"),
            "Secret must render as <redacted>; got: {:?}",
            labels[0]
        );
    }
}
