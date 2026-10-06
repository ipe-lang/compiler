//! `WebReq` — the typed request context passed to a TEA `init`.
//!
//! Target-neutral: the server builds it from the incoming HTTP parts
//! (`web::req::web_req`), the browser-WASM client synthesises it from
//! `location` + `document.cookie`. Fields mirror the  record.

use crate::dict::IpeDict;

#[derive(Clone)]
pub struct WebReq {
    pub path: String,
    pub query: String,
    pub method: String,
    pub params: IpeDict<String>,
    pub headers: IpeDict<String>,
    pub cookies: IpeDict<String>,
}

crate::stringify::show_row!("WebReq", Redacted, [] WebReq, |_| crate::stringify::REDACTED_SHOW.to_owned());

// Every field but the method is client-supplied data that can carry a credential
// (a session cookie, an `Authorization` header, a token in the path or query);
// the Ipê record fixes the field types, so the masking lives in `Debug`.
crate::redact::redacting_debug!(WebReq {
    shown: [method],
    masked: [path, query, params, headers, cookies],
});

impl WebReq {
    /// The initial-load request for a host with no incoming HTTP request — a
    /// native window (`web desktop` webview) whose app opens at its root. The
    /// same `WebReq` a browser tab reports on a fresh `GET /` load: a `GET`
    /// method, the root path, and no query, params, headers, or cookies. A
    /// `Web.tea` `init : WebReq -> …` receives this so the webview host runs the
    /// SAME init as the served and WASM hosts, never a separate `()` shape.
    #[must_use]
    pub fn local_root() -> Self {
        Self {
            path: "/".to_owned(),
            query: String::new(),
            method: "GET".to_owned(),
            params: IpeDict::new(),
            headers: IpeDict::new(),
            cookies: IpeDict::new(),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn web_req_debug_prints_only_the_method() {
        let one = |v: &str| IpeDict::from([("k".to_owned(), v.to_owned())]);
        let req = WebReq {
            path: "/reset/P4THT0K".to_owned(),
            query: "token=QT0K3N".to_owned(),
            method: "GET".to_owned(),
            params: one("PR4M"),
            headers: one("Bearer H34D3R"),
            cookies: one("C00K13"),
        };
        let shown = format!("{req:?}");
        for planted in ["P4THT0K", "QT0K3N", "PR4M", "H34D3R", "C00K13"] {
            assert!(!shown.contains(planted), "{planted} leaked: {shown}");
        }
        assert!(shown.contains("\"GET\""), "{shown}");
    }
}
