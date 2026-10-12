//! The target authority of an inbound request, parsed once, and the admission
//! every app listener judges it by.
//!
//! A DNS name pointed at a loopback app (DNS rebinding) is same-origin with the
//! app in the browser, so every same-origin defence passes for it. An app
//! listener therefore admits an IP-literal host and a loopback name (RFC 6761
//! section 6.3) on any port, and any other DNS name only when the operator
//! declares it. The pure parsers here compile in every build; the request
//! judgement and the service wrapping an app's router need the `server`
//! feature.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::str::FromStr;

/// The most bytes one DNS label may hold.
const MAX_LABEL_BYTES: usize = 63;

/// The most bytes a DNS name may hold, dots included.
const MAX_NAME_BYTES: usize = 253;

/// The most names a declared host list may hold.
pub const MAX_DECLARED_NAMES: usize = 64;

/// The label that makes a name a loopback name.
const LOOPBACK_LABEL: &str = "localhost";

/// A DNS name: ASCII letter-digit-hyphen labels, lowercased.
///
/// Each label is 1 to 63 bytes, never starts or ends with `-`, and the whole
/// name is 1 to 253 bytes with no trailing dot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegName(String);

impl RegName {
    /// The name `raw` spells, or `None` when it is not letter-digit-hyphen labels.
    fn parse(raw: &str) -> Option<Self> {
        let fits = !raw.is_empty() && raw.len() <= MAX_NAME_BYTES;
        (fits && raw.split('.').all(is_ldh_label)).then(|| Self(raw.to_ascii_lowercase()))
    }

    /// The name's labels, left to right.
    #[must_use]
    pub fn labels(&self) -> std::str::Split<'_, char> {
        self.0.split('.')
    }

    /// The name as text, lowercased.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the name's last label is `localhost`.
    fn is_loopback(&self) -> bool {
        self.0.rsplit('.').next() == Some(LOOPBACK_LABEL)
    }
}

/// Whether `label` is 1 to 63 letters, digits and inner hyphens.
fn is_ldh_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edges_ok = matches!(
        (bytes.first(), bytes.last()),
        (Some(first), Some(last)) if *first != b'-' && *last != b'-'
    );
    edges_ok
        && bytes.len() <= MAX_LABEL_BYTES
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// One entry of a declared host list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamePattern {
    /// `name`: exactly this name.
    Exact(RegName),
    /// `.name`: any name with more labels that ends in this name's labels.
    Subdomains(RegName),
}

impl NamePattern {
    /// Whether `name` matches, by label comparison.
    fn matches(&self, name: &RegName) -> bool {
        match self {
            Self::Exact(exact) => exact == name,
            Self::Subdomains(suffix) => {
                let mut theirs = name.labels().rev();
                suffix
                    .labels()
                    .rev()
                    .all(|label| theirs.next() == Some(label))
                    && theirs.next().is_some()
            }
        }
    }
}

/// The DNS names an operator declares an app listener serves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredNames(Vec<NamePattern>);

impl DeclaredNames {
    /// The empty set: only IP literals and loopback names admit.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// Parse a comma-separated host list: `name` or `.name` items, each trimmed
    /// of ASCII spaces.
    ///
    /// # Errors
    ///
    /// [`HostListRefusal::Empty`] for an empty value, [`HostListRefusal::TooMany`]
    /// past [`MAX_DECLARED_NAMES`] items, and [`HostListRefusal::Malformed`] for
    /// the first item that is empty, carries a port or a `*`, is an IP literal
    /// (always admitted), or names a loopback name (always admitted).
    pub fn parse(raw: &str) -> Result<Self, HostListRefusal> {
        if raw.is_empty() {
            return Err(HostListRefusal::Empty);
        }
        let mut patterns = Vec::new();
        for (index, item) in raw.split(',').enumerate() {
            if index >= MAX_DECLARED_NAMES {
                return Err(HostListRefusal::TooMany);
            }
            let item = item.trim_matches(' ');
            let pattern = match item.strip_prefix('.') {
                Some(suffix) => declared_name(suffix).map(NamePattern::Subdomains),
                None => declared_name(item).map(NamePattern::Exact),
            };
            patterns.push(pattern.ok_or(HostListRefusal::Malformed { index })?);
        }
        Ok(Self(patterns))
    }

    /// How many patterns the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set holds no pattern.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `host` admits: an IP literal or loopback name always, a DNS
    /// name when a pattern matches it.
    #[must_use]
    pub fn admits(&self, host: &AuthorityHost) -> bool {
        match host {
            AuthorityHost::Ip(_) | AuthorityHost::LoopbackName => true,
            AuthorityHost::Name(name) => self.0.iter().any(|pattern| pattern.matches(name)),
        }
    }
}

/// A host list item's name, or `None` for an IP literal, a loopback name, or
/// anything that is not a DNS name.
fn declared_name(raw: &str) -> Option<RegName> {
    if Ipv4Addr::from_str(raw).is_ok() {
        return None;
    }
    RegName::parse(raw).filter(|name| !name.is_loopback())
}

/// Why a declared host list is refused; never echoes the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostListRefusal {
    /// The value is set but empty.
    Empty,
    /// The item at `index` (from 0) is not a DNS name or `.suffix`.
    Malformed {
        /// The refused item's position, from 0.
        index: usize,
    },
    /// The list holds more than [`MAX_DECLARED_NAMES`] items.
    TooMany,
}

impl std::fmt::Display for HostListRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => {
                f.write_str("is set but empty; unset it to serve only IP literals and localhost")
            }
            Self::Malformed { index } => write!(
                f,
                "item {} is not a DNS name or a dot-prefixed DNS suffix (IP literals and loopback names need no entry)",
                index.saturating_add(1)
            ),
            Self::TooMany => write!(f, "declares more than {MAX_DECLARED_NAMES} names"),
        }
    }
}

/// The host part of a request's target authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityHost {
    /// A strict IPv4 dotted quad or a bracketed IPv6 address.
    Ip(IpAddr),
    /// `localhost`, or a name whose last label is `localhost`.
    LoopbackName,
    /// Any other DNS name.
    Name(RegName),
}

/// A request's target authority: its host and optional port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    host: AuthorityHost,
    port: Option<NonZeroU16>,
}

impl Authority {
    /// Parse `raw` (`host`, `host:port`, `[v6]`, `[v6]:port`).
    ///
    /// # Errors
    ///
    /// [`AuthorityRefusal::Malformed`] for anything else: a byte outside visible
    /// ASCII, userinfo, a `%`, an empty, signed, zero or out-of-range port, an
    /// unbracketed IPv6 address, an `IPvFuture` literal, a zone, or a host that
    /// is neither an IP literal nor a DNS name (a trailing dot included).
    pub fn parse(raw: &str) -> Result<Self, AuthorityRefusal> {
        let clean = raw
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'@' && b != b'%');
        if !clean {
            return Err(AuthorityRefusal::Malformed);
        }
        if let Some(bracketed) = raw.strip_prefix('[') {
            let (inside, after) = bracketed
                .split_once(']')
                .ok_or(AuthorityRefusal::Malformed)?;
            let ip = Ipv6Addr::from_str(inside).map_err(|_| AuthorityRefusal::Malformed)?;
            let port = match after {
                "" => None,
                rest => Some(parse_port(
                    rest.strip_prefix(':').ok_or(AuthorityRefusal::Malformed)?,
                )?),
            };
            return Ok(Self {
                host: AuthorityHost::Ip(IpAddr::V6(ip)),
                port,
            });
        }
        let (host, port) = match raw.split_once(':') {
            Some((host, port)) => (host, Some(parse_port(port)?)),
            None => (raw, None),
        };
        let host = match Ipv4Addr::from_str(host) {
            Ok(ip) => AuthorityHost::Ip(IpAddr::V4(ip)),
            Err(_) => {
                let name = RegName::parse(host).ok_or(AuthorityRefusal::Malformed)?;
                if name.is_loopback() {
                    AuthorityHost::LoopbackName
                } else {
                    AuthorityHost::Name(name)
                }
            }
        };
        Ok(Self { host, port })
    }

    /// The authority's host.
    #[must_use]
    pub const fn host(&self) -> &AuthorityHost {
        &self.host
    }

    /// The authority's port, when it names one.
    #[must_use]
    pub const fn port(&self) -> Option<NonZeroU16> {
        self.port
    }
}

/// A decimal port in `1..=65535`.
fn parse_port(raw: &str) -> Result<NonZeroU16, AuthorityRefusal> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AuthorityRefusal::Malformed);
    }
    raw.parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or(AuthorityRefusal::Malformed)
}

/// Why a request's target authority is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityRefusal {
    /// The request names no host.
    Absent,
    /// The request carries more than one `Host` header.
    Duplicate,
    /// The request target's authority and the `Host` header differ.
    Disagrees,
    /// The authority is not a host with an optional port.
    Malformed,
}

impl std::fmt::Display for AuthorityRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Absent => "the request names no host",
            Self::Duplicate => "the request carries two Host headers",
            Self::Disagrees => "the request target and its Host header disagree",
            Self::Malformed => "the request host is malformed",
        })
    }
}

#[cfg(feature = "server")]
mod served {
    use super::{Authority, AuthorityRefusal, DeclaredNames};
    use axum::http::{HeaderValue, StatusCode, header, request::Parts};
    use std::collections::BTreeSet;
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};

    /// The most distinct refused hosts logged by name; later ones are counted.
    const MAX_LOGGED_HOSTS: usize = 64;

    /// The most characters of a refused host a log line or the logged set
    /// keeps.
    const MAX_LOGGED_HOST_CHARS: usize = 256;

    /// The mark ending a logged host cut at [`MAX_LOGGED_HOST_CHARS`].
    ///
    /// Every character of a logged host is at most U+00FF (a URI authority is
    /// ASCII, a header byte maps to the code point of the same value), so the
    /// mark never occurs in an uncut one.
    const LOGGED_HOST_CUT: char = '\u{2026}';

    /// The fixed body a refused request answers with.
    const REFUSED_BODY: &str = r#"{"status":"host_not_admitted"}"#;

    impl Authority {
        /// The target authority `parts` names: the URI's authority
        /// (absolute-form, or HTTP/2 `:authority`), else the one `Host` header.
        ///
        /// # Errors
        ///
        /// [`AuthorityRefusal::Duplicate`] for two `Host` headers,
        /// [`AuthorityRefusal::Absent`] for neither source,
        /// [`AuthorityRefusal::Disagrees`] when both are present and differ, and
        /// [`AuthorityRefusal::Malformed`] when either does not parse.
        pub fn from_request(parts: &Parts) -> Result<Self, AuthorityRefusal> {
            let mut hosts = parts.headers.get_all(header::HOST).iter();
            let host = hosts.next();
            if hosts.next().is_some() {
                return Err(AuthorityRefusal::Duplicate);
            }
            let from_header = |value: &HeaderValue| {
                value
                    .to_str()
                    .map_err(|_| AuthorityRefusal::Malformed)
                    .and_then(Self::parse)
            };
            match (parts.uri.authority(), host) {
                (None, None) => Err(AuthorityRefusal::Absent),
                (Some(target), None) => Self::parse(target.as_str()),
                (None, Some(value)) => from_header(value),
                (Some(target), Some(value)) => {
                    let target = Self::parse(target.as_str())?;
                    if from_header(value)? == target {
                        Ok(target)
                    } else {
                        Err(AuthorityRefusal::Disagrees)
                    }
                }
            }
        }
    }

    /// Why a well-formed authority is refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum HostRefusal {
        /// A DNS name no declared pattern matches.
        UndeclaredName,
    }

    impl std::fmt::Display for HostRefusal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::UndeclaredName => "the request host is a DNS name this app does not declare",
            })
        }
    }

    /// The host admission of one app listener.
    #[derive(Clone, Debug)]
    pub struct HostAdmission {
        names: DeclaredNames,
    }

    impl HostAdmission {
        /// The admission that admits IP literals, loopback names and `names`.
        #[must_use]
        pub const fn new(names: DeclaredNames) -> Self {
            Self { names }
        }

        /// The declared names this admission admits beyond IP literals and
        /// loopback names.
        #[must_use]
        pub const fn names(&self) -> &DeclaredNames {
            &self.names
        }

        /// Judge `authority`; total over every parsed authority.
        ///
        /// # Errors
        ///
        /// [`HostRefusal::UndeclaredName`] for a DNS name no pattern matches.
        pub fn judge(&self, authority: &Authority) -> Result<(), HostRefusal> {
            if self.names.admits(authority.host()) {
                Ok(())
            } else {
                Err(HostRefusal::UndeclaredName)
            }
        }
    }

    /// The refused hosts one listener has logged, bounded.
    #[derive(Debug, Default)]
    struct RefusalLog {
        seen: std::sync::Mutex<BTreeSet<String>>,
        unlogged: AtomicU64,
    }

    /// What the [`RefusalLog`] does with one refusal.
    enum LogDecision {
        /// A host not logged before: log it by name.
        Fresh,
        /// A host already logged: stay quiet.
        Repeat,
        /// The set is full: this is the `n`th unlogged refusal.
        Counted(u64),
    }

    impl RefusalLog {
        /// Record one refusal of `host` (already capped).
        fn decide(&self, host: &str) -> LogDecision {
            {
                let mut seen = self
                    .seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if seen.contains(host) {
                    return LogDecision::Repeat;
                }
                if seen.len() < MAX_LOGGED_HOSTS {
                    seen.insert(host.to_owned());
                    return LogDecision::Fresh;
                }
            }
            let previous = self
                .unlogged
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .unwrap_or(u64::MAX);
            LogDecision::Counted(previous.saturating_add(1))
        }
    }

    /// What one listener's admission service shares across connections.
    #[derive(Debug)]
    struct Shared {
        admission: HostAdmission,
        tag: &'static str,
        log: RefusalLog,
    }

    impl Shared {
        /// Log the refusal of `parts` for `reason`: once per distinct host, then
        /// at each power-of-two count of unlogged refusals.
        fn log_refusal(&self, parts: &Parts, reason: &dyn std::fmt::Display) {
            let host = target_text(parts);
            match self.log.decide(&host) {
                LogDecision::Fresh => {
                    crate::system::emit_runtime_log(self.tag, &fresh_record(reason, &host));
                }
                LogDecision::Repeat => {}
                LogDecision::Counted(n) if n.is_power_of_two() => crate::system::emit_runtime_log(
                    self.tag,
                    &format!(
                        "host.refused: {n} refusals past the first {MAX_LOGGED_HOSTS} distinct hosts, not logged by name"
                    ),
                ),
                LogDecision::Counted(_) => {}
            }
        }
    }

    /// The record logging the first refusal of `host` for `reason`. Raw: the
    /// one runtime log emitter scrubs it.
    fn fresh_record(reason: &dyn std::fmt::Display, host: &str) -> String {
        format!("host.refused: {reason}: host `{host}`")
    }

    /// The target authority text `parts` carries, capped for a log line: the
    /// URI's authority, else the first `Host` header, else empty.
    ///
    /// A header's bytes map to the code points of the same value, and a cut
    /// text ends in [`LOGGED_HOST_CUT`], so two distinct texts within the cap
    /// never record alike.
    fn target_text(parts: &Parts) -> String {
        match parts.uri.authority() {
            Some(target) => capped_host(target.as_str().chars()),
            None => parts
                .headers
                .get(header::HOST)
                .map(|value| capped_host(value.as_bytes().iter().map(|b| char::from(*b))))
                .unwrap_or_default(),
        }
    }

    /// The first [`MAX_LOGGED_HOST_CHARS`] of `chars`, ending in
    /// [`LOGGED_HOST_CUT`] when more follow.
    fn capped_host(chars: impl Iterator<Item = char>) -> String {
        let mut out = String::new();
        for (kept, c) in chars.enumerate() {
            if kept == MAX_LOGGED_HOST_CHARS {
                out.push(LOGGED_HOST_CUT);
                break;
            }
            out.push(c);
        }
        out
    }

    /// The response a refused request answers with: `421`, a fixed body, no
    /// cookie, never cached.
    fn refused() -> axum::response::Response {
        use axum::response::IntoResponse;
        (
            StatusCode::MISDIRECTED_REQUEST,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            REFUSED_BODY,
        )
            .into_response()
    }

    /// The layer that judges every request's authority before the wrapped
    /// service sees it.
    #[derive(Clone, Debug)]
    pub struct HostAdmissionLayer {
        shared: Arc<Shared>,
    }

    impl HostAdmissionLayer {
        /// The layer for one app listener, logging refusals under `tag`.
        #[must_use]
        pub fn new(admission: HostAdmission, tag: &'static str) -> Self {
            Self {
                shared: Arc::new(Shared {
                    admission,
                    tag,
                    log: RefusalLog::default(),
                }),
            }
        }
    }

    impl<S> tower::Layer<S> for HostAdmissionLayer {
        type Service = HostAdmissionService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            HostAdmissionService {
                inner,
                shared: Arc::clone(&self.shared),
            }
        }
    }

    /// A service that answers `421` to a request whose authority its
    /// listener's admission refuses, and forwards every other one.
    #[derive(Clone, Debug)]
    pub struct HostAdmissionService<S> {
        inner: S,
        shared: Arc<Shared>,
    }

    /// The future of [`HostAdmissionService`]: the refusal, or the inner call.
    type AdmissionFuture<F> = futures_util::future::Either<
        std::future::Ready<Result<axum::response::Response, Infallible>>,
        F,
    >;

    impl<S> tower::Service<axum::extract::Request> for HostAdmissionService<S>
    where
        S: tower::Service<
                axum::extract::Request,
                Response = axum::response::Response,
                Error = Infallible,
            >,
    {
        type Response = axum::response::Response;
        type Error = Infallible;
        type Future = AdmissionFuture<S::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, request: axum::extract::Request) -> Self::Future {
            let (parts, body) = request.into_parts();
            let admitted = match Authority::from_request(&parts) {
                Ok(authority) => match self.shared.admission.judge(&authority) {
                    Ok(()) => true,
                    Err(refusal) => {
                        self.shared.log_refusal(&parts, &refusal);
                        false
                    }
                },
                Err(refusal) => {
                    self.shared.log_refusal(&parts, &refusal);
                    false
                }
            };
            if admitted {
                futures_util::future::Either::Right(
                    self.inner
                        .call(axum::extract::Request::from_parts(parts, body)),
                )
            } else {
                futures_util::future::Either::Left(std::future::ready(Ok(refused())))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::{Authority, AuthorityRefusal};
        use super::{LOGGED_HOST_CUT, MAX_LOGGED_HOST_CHARS, fresh_record, target_text};
        use axum::http::{HeaderValue, Request};

        /// The refusal line one `Host` header of `bytes` logs, as emitted.
        fn logged_line(bytes: &[u8]) -> String {
            let refused =
                parts(Request::get("/").header("host", HeaderValue::from_bytes(bytes).unwrap()));
            crate::system::runtime_log_line(
                None,
                "web",
                &fresh_record(&AuthorityRefusal::Malformed, &target_text(&refused)),
            )
        }

        #[test]
        fn a_refused_host_is_escaped_once_and_capped() {
            // One scrub: `\` shows as `\\`, a tab as `\t`, a C1 control as
            // `\u{9b}`, never their escapes escaped again.
            let line = logged_line(b"a\\b\t\x9b.example");
            assert!(line.contains("host `a\\\\b\\t\\u{9b}.example`"), "{line}");
            // A host past the cap keeps its first characters and the cut mark;
            // one at the cap is whole.
            let long = vec![b'a'; MAX_LOGGED_HOST_CHARS + 1];
            let line = logged_line(&long);
            let kept = "a".repeat(MAX_LOGGED_HOST_CHARS);
            assert!(
                line.contains(&format!("host `{kept}{LOGGED_HOST_CUT}`")),
                "{line}"
            );
            let line = logged_line(&long[..MAX_LOGGED_HOST_CHARS]);
            assert!(line.contains(&format!("host `{kept}`")), "{line}");
            assert!(!line.contains(LOGGED_HOST_CUT), "{line}");
            // An absolute-form target is logged from the URI.
            let target = parts(Request::get("http://evil.example/"));
            assert_eq!(target_text(&target), "evil.example");
        }

        /// The request parts of `builder` with an empty body.
        fn parts(builder: axum::http::request::Builder) -> axum::http::request::Parts {
            builder.body(()).unwrap().into_parts().0
        }

        #[test]
        fn duplicate_absent_and_disagreeing_authorities_refuse() {
            let two_hosts = parts(
                Request::get("/")
                    .header("host", "127.0.0.1")
                    .header("host", "127.0.0.1"),
            );
            assert_eq!(
                Authority::from_request(&two_hosts),
                Err(AuthorityRefusal::Duplicate)
            );
            let no_host = parts(Request::get("/"));
            assert_eq!(
                Authority::from_request(&no_host),
                Err(AuthorityRefusal::Absent)
            );
            let disagree = parts(Request::get("http://127.0.0.1/").header("host", "evil.example"));
            assert_eq!(
                Authority::from_request(&disagree),
                Err(AuthorityRefusal::Disagrees)
            );
            // The admitted neighbours: one Host header, and an absolute-form
            // target its Host header agrees with.
            let one_host = parts(Request::get("/").header("host", "127.0.0.1:8000"));
            assert!(Authority::from_request(&one_host).is_ok());
            let agree = parts(Request::get("http://127.0.0.1/").header("host", "127.0.0.1"));
            assert!(Authority::from_request(&agree).is_ok());
            let target_only = parts(Request::get("http://[::1]:9/"));
            assert!(Authority::from_request(&target_only).is_ok());
            let non_ascii = parts(Request::get("/").header(
                "host",
                axum::http::HeaderValue::from_bytes(b"\xe9xample").unwrap(),
            ));
            assert_eq!(
                Authority::from_request(&non_ascii),
                Err(AuthorityRefusal::Malformed)
            );
        }
    }
}

#[cfg(feature = "server")]
pub use served::{HostAdmission, HostAdmissionLayer, HostAdmissionService, HostRefusal};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_refusals_are_typed() {
        let label64 = "a".repeat(64);
        let a63 = "a".repeat(63);
        let a62 = "a".repeat(62);
        let a61 = "a".repeat(61);
        let name254 = format!("{a63}.{a63}.{a63}.{a62}");
        let rows: &[&str] = &[
            "",
            " ",
            "evil.example:",
            "evil.example:0",
            "evil.example:65536",
            "evil.example:+80",
            ":80",
            "user@127.0.0.1",
            "127.0.0.1:80:80",
            "[::1",
            "::1",
            "[v1.x]",
            "[fe80::1%25eth0]",
            "exa mple",
            "ex%41mple",
            "\u{e9}xample",
            "localhost.",
            "-evil.example",
            label64.as_str(),
            name254.as_str(),
        ];
        for raw in rows {
            assert_eq!(
                Authority::parse(raw),
                Err(AuthorityRefusal::Malformed),
                "`{raw}` must refuse as malformed"
            );
        }
        // One step inside each length bound parses.
        let name253 = format!("{a63}.{a63}.{a63}.{a61}");
        assert_eq!(name253.len(), 253);
        assert_eq!(name254.len(), 254);
        for raw in [a63.as_str(), name253.as_str()] {
            assert!(
                matches!(
                    Authority::parse(raw),
                    Ok(Authority {
                        host: AuthorityHost::Name(_),
                        port: None
                    })
                ),
                "`{raw}` must parse as a name"
            );
        }
        assert_eq!(
            Authority::parse("Evil.Example:8000").map(|a| (a.host().clone(), a.port())),
            Ok((
                AuthorityHost::Name(RegName("evil.example".to_owned())),
                NonZeroU16::new(8000)
            ))
        );
    }

    #[test]
    fn ip_and_loopback_names_admit_on_any_port() {
        let none = DeclaredNames::none();
        for raw in [
            "127.0.0.1",
            "127.0.0.1:1",
            "[::1]:65535",
            "10.0.0.5:80",
            "LOCALHOST:8000",
            "app.localhost",
        ] {
            let authority = Authority::parse(raw).unwrap();
            assert!(none.admits(authority.host()), "`{raw}` must admit");
        }
    }

    /// Whether `raw` parses and `names` admits it.
    fn admitted(names: &DeclaredNames, raw: &str) -> bool {
        Authority::parse(raw).is_ok_and(|a| names.admits(a.host()))
    }

    #[test]
    fn undeclared_names_refuse() {
        let none = DeclaredNames::none();
        for raw in [
            "evil.example",
            "evil.example:8000",
            "127.1",
            "0x7f.1",
            "127.000.0.1",
            "localhost.evil.example",
            "evillocalhost",
        ] {
            assert!(
                matches!(
                    Authority::parse(raw),
                    Ok(Authority {
                        host: AuthorityHost::Name(_),
                        ..
                    })
                ),
                "`{raw}` must parse as a DNS name"
            );
            assert!(
                !admitted(&none, raw),
                "`{raw}` must refuse with no declared name"
            );
        }
        let subdomains = DeclaredNames::parse(".example.com").unwrap();
        assert!(admitted(&subdomains, "a.example.com"));
        assert!(admitted(&subdomains, "A.Example.Com:443"));
        for raw in ["example.com", "evilexample.com", "example.com.evil"] {
            assert!(
                !admitted(&subdomains, raw),
                "`{raw}` must refuse under `.example.com`"
            );
        }
        let exact = DeclaredNames::parse("example.com").unwrap();
        assert!(admitted(&exact, "example.com"));
        assert!(!admitted(&exact, "a.example.com"));
    }

    #[test]
    fn host_list_refusals_are_typed() {
        let too_many = vec!["a.com"; MAX_DECLARED_NAMES.saturating_add(1)].join(",");
        let rows: &[(&str, HostListRefusal)] = &[
            ("", HostListRefusal::Empty),
            (",", HostListRefusal::Malformed { index: 0 }),
            ("a.com,,b.com", HostListRefusal::Malformed { index: 1 }),
            ("a.com:80", HostListRefusal::Malformed { index: 0 }),
            ("*", HostListRefusal::Malformed { index: 0 }),
            ("*.a.com", HostListRefusal::Malformed { index: 0 }),
            ("127.0.0.1", HostListRefusal::Malformed { index: 0 }),
            ("localhost", HostListRefusal::Malformed { index: 0 }),
            (".localhost", HostListRefusal::Malformed { index: 0 }),
            (too_many.as_str(), HostListRefusal::TooMany),
        ];
        for (raw, refusal) in rows {
            assert_eq!(DeclaredNames::parse(raw), Err(*refusal), "`{raw}`");
            let shown = refusal.to_string();
            assert!(
                raw.is_empty() || !shown.contains(raw),
                "the refusal of `{raw}` must not echo it: {shown}"
            );
        }
        // The admitted neighbours: the most items allowed, and spaced items.
        let most = vec!["a.com"; MAX_DECLARED_NAMES].join(",");
        assert_eq!(
            DeclaredNames::parse(&most).map(|n| n.len()),
            Ok(MAX_DECLARED_NAMES)
        );
        assert_eq!(
            DeclaredNames::parse(" a.com , .b.com ").map(|n| n.len()),
            Ok(2)
        );
    }
}
