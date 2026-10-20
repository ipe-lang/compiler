//! Minimal blocking HTTP client for the CLI's own network needs.
//!
//! One dependency-light client with the same rustls backend the runtime uses,
//! serving the release version check, the registry fast-path and the
//! signing-key registration; the compiler/runtime HTTP surface is a separate,
//! feature-gated concern.
//!
//! The agent never leaves this module: every call returns its body already
//! read through [`crate::remote_ingest::read_capped`], so no caller holds a
//! response body it could read without a ceiling. No `ureq` type leaves it
//! either — a failure is a [`Error`] — so this is the one file in the crate
//! that names the HTTP client, and every call takes this module's policy.

use std::time::Duration;

use crate::remote_ingest::{ByteBudget, CappedReadError, IngestSource, JSON_RESPONSE_MAX_BYTES};

/// Redirects followed before a call fails with a redirect error.
pub const MAX_REDIRECTS: u32 = 4;

/// The one agent every CLI HTTP call goes through.
///
/// HTTPS only (redirects included), Mozilla's root store through rustls, no
/// proxy read from the environment, at most [`MAX_REDIRECTS`] redirects with
/// the `Authorization` header never carried across one, and `timeout` bounding
/// the whole call from DNS lookup to the last body byte. A 4xx/5xx answer is
/// returned as a response, so each caller judges the status itself.
fn agent(timeout: Duration) -> ureq::Agent {
    agent_config(timeout).new_agent()
}

/// The configuration [`agent`] builds from.
fn agent_config(timeout: Duration) -> ureq::config::Config {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::WebPki)
        .disable_verification(false)
        .build();
    ureq::Agent::config_builder()
        .https_only(true)
        .tls_config(tls)
        .proxy(None)
        .http_status_as_error(false)
        .max_redirects(MAX_REDIRECTS)
        .max_redirects_will_error(true)
        .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
        .timeout_global(Some(timeout))
        .build()
}

/// Why an HTTP call got no answer.
///
/// Each variant's text is fixed: it never repeats a URL, a header value, or a
/// token the call carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The URL, or a redirect's target, is not `https://`.
    NotHttps,
    /// The URL could not be parsed into a request.
    BadRequest,
    /// The answer was a redirect past [`MAX_REDIRECTS`], or one the request
    /// body could not follow.
    Redirect,
    /// The call ran past its timeout.
    Timeout,
    /// The host name did not resolve.
    HostNotFound,
    /// The connection failed with this I/O error kind.
    Io(std::io::ErrorKind),
    /// The connection could not be made.
    Connection,
    /// The TLS handshake or certificate check failed.
    Tls,
    /// The server's answer was not well-formed HTTP.
    Protocol,
    /// An error status, for an agent that turns statuses into errors.
    Status(u16),
    /// Any other client failure.
    Other,
}

impl From<ureq::Error> for Error {
    fn from(error: ureq::Error) -> Self {
        match error {
            ureq::Error::RequireHttpsOnly(_) | ureq::Error::TlsRequired => Self::NotHttps,
            ureq::Error::BadUri(_) | ureq::Error::Http(_) | ureq::Error::BodyExceedsLimit(_) => {
                Self::BadRequest
            }
            ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => Self::Redirect,
            ureq::Error::Timeout(_) => Self::Timeout,
            ureq::Error::HostNotFound => Self::HostNotFound,
            ureq::Error::Io(io) => Self::Io(io.kind()),
            ureq::Error::ConnectionFailed
            | ureq::Error::ConnectProxyFailed(_)
            | ureq::Error::InvalidProxyUrl => Self::Connection,
            ureq::Error::Tls(_) | ureq::Error::Pem(_) | ureq::Error::Rustls(_) => Self::Tls,
            ureq::Error::Protocol(_)
            | ureq::Error::LargeResponseHeader(..)
            | ureq::Error::BodyStalled => Self::Protocol,
            ureq::Error::StatusCode(status) => Self::Status(status),
            // `ureq::Error` is non-exhaustive: a variant added upstream is
            // reported as a client failure, never as an answer.
            _ => Self::Other,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotHttps => f.write_str("the URL or a redirect is not https://"),
            Self::BadRequest => f.write_str("the request could not be built"),
            Self::Redirect => f.write_str("the answer redirected too often or unfollowably"),
            Self::Timeout => f.write_str("the call timed out"),
            Self::HostNotFound => f.write_str("the host name did not resolve"),
            Self::Io(kind) => write!(f, "the connection failed: {kind}"),
            Self::Connection => f.write_str("the connection could not be made"),
            Self::Tls => f.write_str("the TLS handshake or certificate check failed"),
            Self::Protocol => f.write_str("the server's answer was not well-formed HTTP"),
            Self::Status(status) => write!(f, "the server answered status {status}"),
            Self::Other => f.write_str("the HTTP client failed"),
        }
    }
}

impl std::error::Error for Error {}

/// An HTTP answer whose body was read whole under a byte ceiling.
#[derive(Debug)]
pub struct Answer {
    status: u16,
    body: Result<Vec<u8>, CappedReadError>,
}

impl Answer {
    /// Read `response`'s body through [`crate::remote_ingest::read_capped`]
    /// at `cap`, keeping its status.
    fn read(
        response: ureq::http::Response<ureq::Body>,
        cap: ByteBudget,
        source: IngestSource,
    ) -> Self {
        let status = response.status().as_u16();
        let body = response.into_body();
        let body = crate::remote_ingest::read_capped(body.into_reader(), cap, source);
        Self { status, body }
    }

    /// The answer's status code.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status
    }

    /// The body, or why it was not read whole within the ceiling.
    ///
    /// # Errors
    ///
    /// The [`CappedReadError`] of a body that failed mid-read or ran past the
    /// ceiling.
    pub fn body(&self) -> Result<&[u8], &CappedReadError> {
        self.body.as_deref()
    }
}

/// GET `url`, returning the response body as a string.
///
/// `None` on any failure (DNS, connect, TLS, non-2xx, timeout, oversized body):
/// a network error is never fatal here — the caller decides how to degrade.
#[must_use]
pub fn get(url: &str) -> Option<String> {
    get_with_accept(url, "application/vnd.github+json")
}

/// GET `url`, returning the response body as a string, requesting `accept` as
/// the `Accept` header.
///
/// The body is read through [`crate::remote_ingest::read_capped`] at
/// [`crate::remote_ingest::JSON_RESPONSE_MAX_BYTES`].
///
/// `None` on any failure (DNS, connect, TLS, non-2xx, non-HTTPS URL, timeout,
/// oversized body): a network error is never fatal here — the caller decides
/// how to degrade. The registry's static Pages read API serves
/// `application/json`, so the registry fetch passes that rather than the
/// GitHub API media type.
#[must_use]
pub fn get_with_accept(url: &str, accept: &str) -> Option<String> {
    let response = agent(Duration::from_secs(5))
        .get(url)
        .header("User-Agent", "ipe-cli")
        .header("Accept", accept)
        .call()
        .ok()?;
    success_body(response)
}

/// The body of a 2xx `response` as UTF-8 text; `None` for any other status,
/// an oversized body, or a body that is not UTF-8. The body of a refused
/// status is never read.
fn success_body(response: ureq::http::Response<ureq::Body>) -> Option<String> {
    if !response.status().is_success() {
        return None;
    }
    let answer = Answer::read(response, JSON_RESPONSE_MAX_BYTES, IngestSource::HttpGet);
    String::from_utf8(answer.body.ok()?).ok()
}

/// POST `body` to `url` with `headers`, under a `timeout` bounding the whole
/// call, reading the answer's body at
/// [`crate::remote_ingest::JSON_RESPONSE_MAX_BYTES`] as `source`.
///
/// Every status is returned as an [`Answer`]; the caller judges it.
///
/// # Errors
///
/// The [`Error`] of a call that got no HTTP answer: a non-HTTPS URL, DNS,
/// connect, TLS, a redirect past [`MAX_REDIRECTS`], or the timeout.
pub fn post(
    url: &str,
    timeout: Duration,
    headers: &[(&str, &str)],
    body: &str,
    source: IngestSource,
) -> Result<Answer, Error> {
    let mut request = agent(timeout).post(url);
    for &(name, value) in headers {
        request = request.header(name, value);
    }
    let response = request.send(body)?;
    Ok(Answer::read(response, JSON_RESPONSE_MAX_BYTES, source))
}

/// An HTTP answer with `status` and `body`, as the agent hands it back.
///
/// Private to this module, so no client type reaches another file.
#[cfg(test)]
fn response(status: u16, body: &[u8]) -> ureq::http::Response<ureq::Body> {
    ureq::http::Response::builder()
        .status(status)
        .body(ureq::Body::builder().data(body.to_vec()))
        .expect("a well-formed response")
}

/// Answers built without a network, for the tests of this module's callers.
#[cfg(test)]
pub(crate) mod testing {
    use super::{Answer, ByteBudget, IngestSource};

    /// The [`Answer`] the agent hands back for `status` and `body`, its body
    /// read at `cap` as `source`.
    pub fn answer(status: u16, body: &[u8], cap: ByteBudget, source: IngestSource) -> Answer {
        Answer::read(super::response(status, body), cap, source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The libtest path of [`proxy_env_child`].
    const PROXY_ENV_CHILD: &str = "net::tests::proxy_env_child";

    #[test]
    fn agent_pins_its_policy() {
        let config = agent_config(Duration::from_secs(7));
        assert!(config.https_only());
        assert!(!config.http_status_as_error());
        assert_eq!(config.max_redirects(), MAX_REDIRECTS);
        assert!(config.max_redirects_will_error());
        assert!(matches!(
            config.redirect_auth_headers(),
            ureq::config::RedirectAuthHeaders::Never
        ));
        assert_eq!(config.timeouts().global, Some(Duration::from_secs(7)));
        assert!(matches!(
            config.tls_config().root_certs(),
            ureq::tls::RootCerts::WebPki
        ));
        assert!(!config.tls_config().disable_verification());
    }

    /// Run by [`a_proxy_in_the_environment_is_never_used`] with every proxy
    /// variable set: the environment names a proxy, yet the agent holds none.
    #[test]
    #[ignore = "run as a child with proxy variables set"]
    fn proxy_env_child() {
        assert!(
            ureq::Proxy::try_from_env().is_some(),
            "the child must see the proxy variables its parent set"
        );
        assert!(agent_config(Duration::from_secs(1)).proxy().is_none());
    }

    #[test]
    fn a_proxy_in_the_environment_is_never_used() {
        let exe = std::env::current_exe().expect("the test binary");
        let mut child = std::process::Command::new(exe);
        child.args(["--exact", PROXY_ENV_CHILD, "--ignored", "--test-threads=1"]);
        for var in [
            "ALL_PROXY",
            "all_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
        ] {
            child.env(var, "http://127.0.0.1:9");
        }
        let output = child.output().expect("run the child test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "child failed: {output:?}");
        assert!(
            stdout.contains(&format!("test {PROXY_ENV_CHILD} ... ok")),
            "the child must run its one test: {output:?}"
        );
    }

    #[test]
    fn only_a_success_status_yields_its_body() {
        assert_eq!(
            success_body(response(200, b"ok")).as_deref(),
            Some("ok"),
            "a 200 answer yields its body"
        );
        for status in [204, 299] {
            assert!(success_body(response(status, b"")).is_some(), "{status}");
        }
        for status in [100, 301, 302, 304, 400, 404, 500, 503] {
            assert_eq!(
                success_body(response(status, b"body")),
                None,
                "status {status} must be refused"
            );
        }
    }

    #[test]
    fn a_success_body_that_is_not_utf8_is_refused() {
        assert_eq!(success_body(response(200, &[0xff, 0xfe])), None);
    }

    #[test]
    fn an_answer_keeps_its_status_and_capped_body() {
        let answer = Answer::read(
            response(422, b"{}"),
            JSON_RESPONSE_MAX_BYTES,
            IngestSource::GithubApi,
        );
        assert_eq!(answer.status_code(), 422);
        assert_eq!(answer.body().ok(), Some(&b"{}"[..]));
    }

    #[test]
    fn plain_http_is_refused_before_connecting() {
        let result = agent(Duration::from_secs(1))
            .get("http://127.0.0.1:9/")
            .call();
        assert!(
            matches!(result, Err(ureq::Error::RequireHttpsOnly(_))),
            "a non-HTTPS URL must be refused by the agent"
        );
        assert_eq!(get("http://127.0.0.1:9/"), None);
        assert!(matches!(
            post(
                "http://127.0.0.1:9/",
                Duration::from_secs(1),
                &[],
                "",
                IngestSource::GithubApi
            ),
            Err(Error::NotHttps)
        ));
    }

    #[test]
    fn a_client_failure_maps_to_its_kind_and_never_echoes_its_detail() {
        let secret = "https://user:token@host/\u{1b}[2K";
        for (failure, kind) in [
            (
                ureq::Error::RequireHttpsOnly(secret.to_owned()),
                Error::NotHttps,
            ),
            (ureq::Error::BadUri(secret.to_owned()), Error::BadRequest),
            (
                ureq::Error::ConnectProxyFailed(secret.to_owned()),
                Error::Connection,
            ),
            (ureq::Error::TooManyRedirects, Error::Redirect),
            (ureq::Error::Timeout(ureq::Timeout::Global), Error::Timeout),
            (ureq::Error::HostNotFound, Error::HostNotFound),
            (
                ureq::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    secret,
                )),
                Error::Io(std::io::ErrorKind::ConnectionRefused),
            ),
            (ureq::Error::StatusCode(401), Error::Status(401)),
        ] {
            let mapped = Error::from(failure);
            assert_eq!(mapped, kind);
            let text = mapped.to_string();
            assert!(
                !text.contains("token") && !text.contains('\u{1b}'),
                "{text:?}"
            );
        }
    }
}
