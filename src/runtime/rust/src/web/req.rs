//! `WebReq` — the typed request context passed to an `Ipe.Web` `init`.
//!
//! `req.path` / `req.query` / `req.method` are strings;
//! `req.params` / `req.headers` / `req.cookies` are `Dict String String`.

use crate::dict::IpeDict;

pub use crate::dom::req::WebReq;

/// Build a `WebReq` from the incoming request parts + the matched route params.
///
/// `headers` is the listener's one header fold, the dict `Ipe.Server` reads
/// too; `raw` is read only by the cookie parser.
pub(crate) fn web_req(
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    raw: &axum::http::HeaderMap,
    headers: &crate::http_header::RequestHeaders,
    params: IpeDict<String>,
) -> WebReq {
    // Decoded through the one request-cookie parser, first value wins, so
    // `req.cookies` agrees with `Server.getCookie` and the session reader.
    let mut cookies: IpeDict<String> = IpeDict::new();
    for (name, value) in crate::server::request_cookie_jar(raw) {
        cookies.entry(name).or_insert(value);
    }
    WebReq {
        path: uri.path().to_string(),
        query: uri.query().unwrap_or("").to_string(),
        method: method.as_str().to_string(),
        params,
        headers: headers.as_dict().clone(),
        cookies,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_req_parses_headers_and_cookies() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            "ipe_sid=abc; theme=dark".parse().unwrap(),
        );
        h.insert("x-custom", "v".parse().unwrap());
        let uri: axum::http::Uri = "/apps/ipe?q=1".parse().unwrap();
        let folded = crate::http_header::RequestHeaders::parse(&h).unwrap();
        let req = web_req(
            &axum::http::Method::GET,
            &uri,
            &h,
            &folded,
            crate::dict::dict_empty(),
        );
        assert_eq!(req.path, "/apps/ipe");
        assert_eq!(req.query, "q=1");
        assert_eq!(req.method, "GET");
        assert_eq!(req.cookies.get("ipe_sid").map(String::as_str), Some("abc"));
        assert_eq!(req.cookies.get("theme").map(String::as_str), Some("dark"));
        assert_eq!(req.headers.get("X-Custom").map(String::as_str), Some("v"));
        assert!(
            !req.headers.contains_key("Cookie"),
            "the cookie parser alone reads `Cookie`"
        );
    }

    /// `req.cookies` keeps the session cookie beside a pair with a non-ASCII byte.
    #[test]
    fn web_req_keeps_the_cookies_beside_a_non_ascii_pair() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_bytes(b"x=\xC3\xA9; ipe_sid=abc").unwrap(),
        );
        let uri: axum::http::Uri = "/".parse().unwrap();
        let folded = crate::http_header::RequestHeaders::parse(&h).unwrap();
        let req = web_req(
            &axum::http::Method::GET,
            &uri,
            &h,
            &folded,
            crate::dict::dict_empty(),
        );
        assert_eq!(req.cookies.get("ipe_sid").map(String::as_str), Some("abc"));
        assert!(
            !req.cookies.contains_key("x"),
            "the non-ASCII pair is skipped"
        );
    }
}
