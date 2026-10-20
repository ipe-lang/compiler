//! Minimal blocking HTTP client for the CLI's own network needs.
//!
//! One dependency-light client with the same rustls backend the runtime uses,
//! serving the release version check, the registry fast-path and the
//! signing-key registration; the compiler/runtime HTTP surface is a separate,
//! feature-gated concern.

use std::time::Duration;

/// Redirects followed before a call fails with a redirect error.
pub const MAX_REDIRECTS: u32 = 4;

/// The one agent every CLI HTTP call goes through.
///
/// HTTPS only (redirects included), Mozilla's root store through rustls, no
/// proxy read from the environment, at most [`MAX_REDIRECTS`] redirects with
/// the `Authorization` header never carried across one, and `timeout` bounding
/// the whole call from DNS lookup to the last body byte. A 4xx/5xx answer is
/// returned as a response, so each caller judges the status itself.
#[must_use]
pub fn agent(timeout: Duration) -> ureq::Agent {
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
    if !response.status().is_success() {
        return None;
    }
    let body = response.into_body();
    let bytes = crate::remote_ingest::read_capped(
        body.into_reader(),
        crate::remote_ingest::JSON_RESPONSE_MAX_BYTES,
        crate::remote_ingest::IngestSource::HttpGet,
    )
    .ok()?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_pins_its_policy() {
        let config = agent_config(Duration::from_secs(7));
        assert!(config.https_only());
        assert!(config.proxy().is_none());
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
    }
}
