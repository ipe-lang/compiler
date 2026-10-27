//! `Ipe.Debug` — the development-only escape hatch.
//!
//! `Debug.log label value` prints `"<label>: <value>"` to stderr as a side
//! effect and returns `value` UNCHANGED, so it can be spliced into any
//! expression without altering its result. The value renders through
//! `IpeStringify` in the dev view when the build has the `dev-posture`
//! feature: each `Redacted` row its `show_row!` marks `Reveal` prints its
//! contents, while a `Secret`, a crypto key and every credential field keep the
//! marker. Without the feature the value renders in the shown view, the one
//! every implicit rendering (`Error.toString`, logs, web, the debugger) uses.
//!
//! This is the ONE deliberate impure escape hatch in the language — NOT a
//! `Task`. `ipe release` rejects any `Debug.*` use at compile time (IPE-L0140),
//! and a release build never selects `dev-posture`, so a production binary
//! holds no dev view.

use crate::stringify::{IpeStringify, View};

/// The view `Debug.log` renders in: the dev view in a dev-posture build.
#[cfg(feature = "dev-posture")]
const fn log_view() -> View {
    crate::stringify::dev_view()
}

/// The view `Debug.log` renders in: the shown view outside a dev-posture
/// build.
#[cfg(not(feature = "dev-posture"))]
const fn log_view() -> View {
    View::Shown
}

/// Build the scrubbed `"<label>: <value>"` line `debug_log` writes.
///
/// Both `label` and the rendered `value` are routed through
/// `system::scrub_log_controls`: the dev view prints contents an author,
/// driver, remote request or file shaped, so an ESC/CR/LF/bidi-control
/// sequence in either can neither forge extra terminal lines nor reorder/hide
/// the ones already there. Split out from `debug_log` so the scrub can be
/// asserted directly, without capturing the real stderr side effect.
fn debug_log_line<T: IpeStringify>(label: &str, value: &T) -> String {
    let label = crate::system::scrub_log_controls(label);
    let rendered = value.ipe_render(log_view());
    let rendered = crate::system::scrub_log_controls(&rendered);
    format!("{label}: {rendered}")
}

/// `Debug.log : String -> a -> a`. Writes `"<label>: <value>"` + a newline to
/// stderr (fallibly, through `system::write_stderr_line`, so a broken pipe
/// never panics), then returns `value`
/// unchanged.
#[must_use]
pub fn debug_log<T: IpeStringify>(label: String, value: T) -> T {
    crate::system::write_stderr_line(&debug_log_line(&label, &value));
    value
}

/// `Debug.todo : String -> a`. Prints `"TODO at <file>:<line>: <note>"` to
/// stderr then exits with a non-zero code.  Returns `!` (the never type),
/// which coerces to any `A` at the call site — no Rust `panic!` is used.
///
/// `location` is a `"<file>:<line>"` string injected by the lowerer at
/// compile time from the call-site source span; it is never computed at
/// runtime.  `note` is the developer-supplied string argument.
pub fn debug_todo<A>(location: String, note: String) -> A {
    crate::system::write_stderr_line(&format!("TODO at {location}: {note}"));
    crate::system::system_exit(1)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::debug_log_line;

    /// Both the label and the value can carry attacker-influenced text (a
    /// spliced-in driver error, a request field, a trace value) — pin that
    /// neither an ESC sequence, a bare CR/LF, nor a bidi-reorder control
    /// survives into the line handed to `write_stderr_line`.
    #[test]
    fn scrubs_esc_cr_lf_and_bidi_controls_from_label_and_value() {
        let label = "label\r\n\x1b[2J".to_string();
        let value = "value\u{2066}\u{202e}bidi".to_string();
        let line = debug_log_line(&label, &value);
        assert!(
            !line.chars().any(|c| c == '\x1b' || c == '\r' || c == '\n'),
            "ESC/CR/LF survived scrubbing: {line:?}"
        );
        assert!(
            !line.contains('\u{2066}') && !line.contains('\u{202e}'),
            "a bidi control survived scrubbing: {line:?}"
        );
    }

    /// Without `dev-posture`, `Debug.log` prints the shown view: a `Redacted`
    /// row renders its marker, never its contents.
    #[cfg(all(not(feature = "dev-posture"), feature = "url"))]
    #[test]
    fn debug_log_without_dev_posture_renders_shown() {
        use crate::stringify::IpeStringify;
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let url = parse_url("https://u:S3CR3TPW@example.com:8443/a/b?q=S3CR3TQ")
            .expect("a literal absolute URL");
        let line = debug_log_line("u", &url);
        assert_eq!(line, format!("u: {}", url.ipe_show()));
        assert!(!line.contains("S3CR3T"), "{line}");
        assert!(!line.contains("/a/b"), "{line}");
        assert_eq!(debug_log_line("b", &vec![1u8, 2, 3]), "b: <3 bytes>");
    }

    /// A literal URL parsed through the `Url.fromString` boundary.
    #[cfg(feature = "url")]
    fn parse_url(raw: &str) -> Option<crate::url::Url> {
        match crate::url::url_from_string::<String>(raw.to_owned()) {
            crate::core::IpeResult::Ok(u) => Some(u),
            crate::core::IpeResult::Err(_) => None,
        }
    }

    /// The dev view of `value`.
    #[cfg(all(feature = "dev-posture", any(feature = "url", feature = "server")))]
    fn dev<T: crate::stringify::IpeStringify + ?Sized>(value: &T) -> String {
        value.ipe_render(crate::stringify::dev_view())
    }

    /// `Debug.log` of a `Url` prints its path, query and fragment; the
    /// userinfo password keeps the marker.
    #[cfg(all(feature = "dev-posture", feature = "url"))]
    #[test]
    fn dev_posture_pin_debug_log_reveals_url_path() {
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let url = parse_url("https://alice:S3CR3TPW@example.com:8443/a/b?q=1#frag")
            .expect("a literal absolute URL");
        assert_eq!(
            debug_log_line("u", &url),
            "u: https://alice:<redacted>@example.com:8443/a/b?q=1#frag"
        );
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let plain = parse_url("https://example.com/reset/tok?x=1").expect("a literal absolute URL");
        assert_eq!(dev(&plain), "https://example.com/reset/tok?x=1");
        // A credential that spilled out of the userinfo stays withheld.
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let spilled = parse_url("https://S3CR3TUSER:1/S3CR3TPW@example.com/x")
            .expect("a literal absolute URL");
        assert!(!dev(&spilled).contains("S3CR3T"), "{}", dev(&spilled));
        // A password under an empty user name keeps the `@` that ends the userinfo.
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let no_user = parse_url("https://:S3CR3TPW@example.com/p").expect("a literal absolute URL");
        assert_eq!(dev(&no_user), "https://:<redacted>@example.com/p");
    }

    /// One value per `Reveal` row, rendered `(leaf, dev, shown)`.
    #[cfg(all(feature = "dev-posture", feature = "full"))]
    #[allow(clippy::expect_used)] // fixtures: every literal below is valid input
    #[allow(clippy::too_many_lines)] // one case per row, in table order
    fn reveal_cases() -> Vec<(&'static str, String, String)> {
        use crate::core::{IpeMaybe, IpeResult};
        use crate::stringify::IpeStringify;
        use std::collections::HashMap;

        fn case<T: IpeStringify>(leaf: &'static str, v: &T) -> (&'static str, String, String) {
            (leaf, dev(v), v.ipe_show())
        }
        fn ok<E, A>(r: IpeResult<E, A>) -> Option<A> {
            match r {
                IpeResult::Ok(a) => Some(a),
                IpeResult::Err(_) => None,
            }
        }
        fn just<A>(m: IpeMaybe<A>) -> Option<A> {
            match m {
                IpeMaybe::Just(a) => Some(a),
                IpeMaybe::Nothing => None,
            }
        }
        let headers: HashMap<String, String> = [("Accept".to_owned(), "text/html".to_owned())]
            .into_iter()
            .collect();
        let address = || {
            just(crate::email::email_address_parse(
                "a@example.com".to_owned(),
            ))
            .expect("a valid address")
        };
        let attachment = crate::email::EmailAttachment {
            filename: "a.txt".to_owned(),
            mimeType: "text/plain".to_owned(),
            content: b"hello".to_vec(),
        };
        let key = just(crate::crypto_core::crypto_key_from_string("k".to_owned())).expect("a key");
        vec![
            case(
                "CryptoMac",
                &crate::crypto_core::crypto_hmac_sha256_key(key, "m".to_owned()),
            ),
            case("Bytes", &b"hello".to_vec()),
            case(
                "Url",
                &parse_url("https://example.com/a?q=1").expect("a literal absolute URL"),
            ),
            case(
                "Principal",
                &crate::principal::principal_mint("alice".to_owned()),
            ),
            case(
                "Dsn",
                &ok(crate::dsn::dsn_parse::<String>(
                    "postgres://alice@db.example.com:5432/app".to_owned(),
                ))
                .expect("a literal DSN"),
            ),
            case(
                "DbLocation",
                &crate::db::db_location_dsn(
                    ok(crate::dsn::dsn_parse::<String>(
                        "postgres://alice@db.example.com:5432/app".to_owned(),
                    ))
                    .expect("a literal DSN"),
                ),
            ),
            case(
                "SqlFragment",
                &crate::db::sql_eq(
                    crate::db::sql_column("name".to_owned()),
                    crate::db::sql_param("alice".to_owned()),
                ),
            ),
            case(
                "ServerRequest",
                &crate::server::ServerRequest {
                    method: "GET".to_owned(),
                    path: "/a".to_owned(),
                    body: String::new(),
                    headers: headers.clone(),
                    params: HashMap::new(),
                    query: HashMap::new(),
                    cookies: HashMap::new(),
                    remoteAddr: "127.0.0.1".to_owned(),
                },
            ),
            case(
                "ServerResponse",
                &crate::server::ServerResponse {
                    status: 200,
                    body: "ok".to_owned(),
                    headers,
                    contentType: "text/plain".to_owned(),
                    cookies: Vec::new(),
                },
            ),
            case(
                "ServerCookie",
                &ok(crate::server::server_cookie(
                    "sid".to_owned(),
                    "v".to_owned(),
                ))
                .expect("a valid cookie"),
            ),
            case("WebReq", &crate::dom::req::WebReq::local_root()),
            case(
                "HttpRequest",
                &crate::http_client::HttpRequest {
                    body: String::new(),
                    headers: vec![("Accept".to_owned(), "text/html".to_owned())],
                    method: crate::http_client::HttpMethod::Get,
                    redirects: crate::http_client::RedirectPolicy::NoRedirects,
                    timeout: 30,
                    url: "https://example.com/a".to_owned(),
                },
            ),
            case(
                "AuthConfig",
                &crate::server::server_auth_config(
                    crate::secret::secret_from_string("k".to_owned()),
                    crate::server::TokenSource::BearerHeader,
                ),
            ),
            case("TokenSource", &crate::server::TokenSource::BearerHeader),
            case(
                "WebSocketClientCfg",
                &crate::ws_client::WsClientCfg {
                    url: "wss://example.com/s".to_owned(),
                    headers: Vec::new(),
                    timeout: 30,
                    pingInterval: 10,
                },
            ),
            case(
                "ProcessRunWithCfg",
                &crate::system::ProcessRunWithCfg {
                    command: "ls".to_owned(),
                    args: vec!["-l".to_owned()],
                    cwd: IpeMaybe::Nothing,
                    env: Vec::new(),
                },
            ),
            case(
                "ProcessRunInPtyCfg",
                &crate::system::ProcessRunInPtyCfg {
                    command: "ls".to_owned(),
                    args: Vec::new(),
                    cwd: IpeMaybe::Nothing,
                    env: Vec::new(),
                    cols: 80,
                    rows: 24,
                },
            ),
            case(
                "CacheCfg",
                &crate::cache::CacheCfg {
                    maxEntries: 10,
                    ttlMs: 1000,
                    maxBytes: 4096,
                },
            ),
            case(
                "Regex",
                &ok(crate::regex_kernel::regex_compile::<String>(
                    "a+b".to_owned(),
                ))
                .expect("a valid pattern"),
            ),
            case(
                "EmailMessage",
                &crate::email::EmailMessage {
                    from: address(),
                    to: vec![address()],
                    cc: Vec::new(),
                    bcc: Vec::new(),
                    subject: "hi".to_owned(),
                    textBody: "body".to_owned(),
                    htmlBody: String::new(),
                    attachments: vec![attachment.clone()],
                    replyTo: address(),
                },
            ),
            case("EmailAttachment", &attachment),
            case(
                "EmailSesConfig",
                &crate::email::SesConfig {
                    region: "us-east-1".to_owned(),
                    key: "AKIA".to_owned(),
                    secret: crate::secret::secret_from_string("k".to_owned()),
                },
            ),
            case(
                "EmailSmtpConfig",
                &crate::email::SmtpConfig {
                    host: "smtp.example.com".to_owned(),
                    port: 587,
                    user: "alice".to_owned(),
                    pass: crate::secret::secret_from_string("k".to_owned()),
                },
            ),
        ]
    }

    /// Every `Reveal` row of the table has a case, and each case's dev view
    /// differs from its shown view.
    #[cfg(all(feature = "dev-posture", feature = "full"))]
    #[test]
    fn dev_posture_pin_debug_log_reveals_each_reveal_row() {
        use crate::stringify::{DevView, SHOWN_ROWS};
        let cases = reveal_cases();
        for (leaf, _, view) in SHOWN_ROWS {
            let covered = cases.iter().any(|(case, _, _)| *case == leaf);
            assert_eq!(
                covered,
                view == DevView::Reveal,
                "{leaf}: a Reveal row needs exactly one dev case, and only a Reveal row has one"
            );
        }
        for (leaf, dev_text, shown) in &cases {
            assert_ne!(dev_text, shown, "{leaf}: the dev view revealed nothing");
        }
    }

    /// The signing secret, the passwords and every credential header or cookie
    /// value keep the marker in the dev view, as do `Secret` and `Key`.
    #[cfg(all(feature = "dev-posture", feature = "full"))]
    #[test]
    #[allow(clippy::expect_used)] // fixtures: every literal below is valid input
    fn dev_posture_pin_debug_log_withholds_secret_key_and_credential_fields() {
        use crate::core::{IpeMaybe, IpeResult};
        use crate::stringify::{IpeStringify, REDACTED_SHOW};
        use std::collections::HashMap;
        let secret = || crate::secret::secret_from_string("S3CR3TPW".to_owned());
        let dsn = match crate::dsn::dsn_parse::<String>(
            "postgres://alice:S3CR3TPW@db.example.com:5432/app".to_owned(),
        ) {
            IpeResult::Ok(d) => Some(d),
            IpeResult::Err(_) => None,
        }
        .expect("a literal DSN");
        let key = match crate::crypto_core::crypto_key_from_string("S3CR3TPW".to_owned()) {
            IpeMaybe::Just(k) => Some(k),
            IpeMaybe::Nothing => None,
        }
        .expect("a non-empty key");
        let header = |name: &str| (name.to_owned(), "S3CR3TPW".to_owned());
        let request = crate::server::ServerRequest {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            body: String::new(),
            headers: [
                header("Authorization"),
                header("cookie"),
                header("Set-Cookie"),
                header("X-Api-Key"),
                header("Proxy-Authorization"),
                header("X-Amz-Security-Token"),
                header("X-Custom-Token"),
                header("X-Client-Secret"),
                header("Authorizatıon"),
            ]
            .into_iter()
            .collect(),
            params: HashMap::new(),
            query: HashMap::new(),
            cookies: [header("sid")].into_iter().collect(),
            remoteAddr: String::new(),
        };
        let rendered = [
            dev(&secret()),
            dev(&key),
            dev(&dsn),
            dev(&crate::db::db_location_dsn(dsn.clone())),
            dev(&crate::email::SmtpConfig {
                host: "smtp.example.com".to_owned(),
                port: 587,
                user: "alice".to_owned(),
                pass: secret(),
            }),
            dev(&crate::email::SesConfig {
                region: "us-east-1".to_owned(),
                key: "AKIA".to_owned(),
                secret: secret(),
            }),
            dev(&crate::server::server_auth_config(
                secret(),
                crate::server::TokenSource::BearerHeader,
            )),
            dev(&request),
            dev(&crate::http_client::HttpRequest {
                body: String::new(),
                headers: vec![header("AUTHORIZATION"), header("X-Api-Key")],
                method: crate::http_client::HttpMethod::Get,
                redirects: crate::http_client::RedirectPolicy::NoRedirects,
                timeout: 30,
                url: String::new(),
            }),
        ];
        for text in &rendered {
            assert!(!text.contains("S3CR3T"), "a credential leaked: {text}");
        }
        assert_eq!(dev(&secret()), REDACTED_SHOW);
        assert_eq!(dev(&key), key.ipe_show());
        assert!(dev(&dsn).contains("alice"), "{}", dev(&dsn));
        let location = dev(&crate::db::db_location_dsn(dsn.clone()));
        assert!(location.contains("alice"), "{location}");
    }

    /// In a dev-posture build every implicit rendering stays on the shown view:
    /// `Error.toString` and `ipe_show` of every `Redacted` row equal the shown
    /// rendering, whatever the dev view prints.
    #[cfg(all(feature = "dev-posture", feature = "full"))]
    #[test]
    fn dev_posture_pin_error_to_string_stays_redacted() {
        use crate::stringify::REDACTED_SHOW;
        for (leaf, _, shown) in reveal_cases() {
            let expected = match leaf {
                "Bytes" => "<5 bytes>",
                "Url" => "https://example.com/<redacted>",
                _ => REDACTED_SHOW,
            };
            assert_eq!(shown, expected, "{leaf}");
        }
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let url = parse_url("https://example.com/a?q=1").expect("a literal absolute URL");
        assert_eq!(
            crate::basics::basics_error_to_string(url),
            "https://example.com/<redacted>"
        );
    }

    /// `Debug.log` hands back the very value it was given.
    #[cfg(all(feature = "dev-posture", feature = "url"))]
    #[test]
    fn dev_posture_pin_debug_log_returns_value_unchanged() {
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let url = parse_url("https://example.com/a?q=1").expect("a literal absolute URL");
        let back = super::debug_log("u".to_owned(), url.clone());
        assert_eq!(back, url);
        assert_eq!(super::debug_log("n".to_owned(), 7i64), 7);
    }

    /// Every structural carrier forwards the dev view to its elements: a nested
    /// `Url` reveals its path, a nested `Secret` keeps the marker.
    #[cfg(all(feature = "dev-posture", feature = "url", feature = "secret"))]
    #[test]
    fn dev_posture_pin_carriers_forward_view() {
        use crate::core::{IpeMaybe, IpeResult};
        use std::collections::{BTreeSet, HashMap};
        #[allow(clippy::expect_used)] // fixture: a literal absolute URL always parses
        let url = parse_url("https://example.com/a").expect("a literal absolute URL");
        let secret = || crate::secret::secret_from_string("S3CR3TPW".to_owned());
        let u = "https://example.com/a";
        let r = crate::stringify::REDACTED_SHOW;
        assert_eq!(dev(&vec![url.clone()]), format!("[{u}]"));
        assert_eq!(dev(&[url.clone()][..]), format!("[{u}]"));
        assert_eq!(dev(&Box::new(url.clone())), u);
        assert_eq!(dev(&&url), u);
        assert_eq!(dev(&IpeMaybe::Just(url.clone())), format!("Just {u}"));
        let ok: IpeResult<String, crate::url::Url> = IpeResult::Ok(url.clone());
        assert_eq!(dev(&ok), format!("Ok {u}"));
        let err: IpeResult<crate::secret::Secret, i64> = IpeResult::Err(secret());
        assert_eq!(dev(&err), format!("Err {r}"));
        let map: HashMap<String, crate::url::Url> =
            [("k".to_owned(), url.clone())].into_iter().collect();
        assert_eq!(dev(&map), format!("map[k:{u}]"));
        let set: BTreeSet<String> = ["s".to_owned()].into_iter().collect();
        assert_eq!(dev(&set), "[s]");
        assert_eq!(dev(&(url, secret())), format!("{{{u} {r}}}"));
        assert_eq!(dev(&vec![secret()]), format!("[{r}]"));
    }

    /// The dev view of a request renders the same text whatever order its
    /// header map iterates in.
    #[cfg(all(feature = "dev-posture", feature = "server"))]
    #[test]
    fn dev_posture_pin_dev_render_is_deterministic() {
        use std::collections::HashMap;
        let request = || {
            let headers: HashMap<String, String> = (0..16)
                .map(|i| (format!("x-header-{i:02}"), format!("v{i}")))
                .collect();
            crate::server::ServerRequest {
                method: "GET".to_owned(),
                path: "/".to_owned(),
                body: String::new(),
                headers: headers.clone(),
                params: headers.clone(),
                query: headers.clone(),
                cookies: headers,
                remoteAddr: String::new(),
            }
        };
        let first = dev(&request());
        for _ in 0..64 {
            assert_eq!(dev(&request()), first);
        }
    }
}
