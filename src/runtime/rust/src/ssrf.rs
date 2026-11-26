//! SSRF deny-private guard — reqwest-free URL/host validation.
//!
//! Factored out of `http_client.rs` so the WebSocket client (which dials outside
//! reqwest) and any other surface can validate URLs against the deny-private
//! policy WITHOUT linking the reqwest HTTP stack. URL parsing uses the `url`
//! crate directly — `reqwest::Url` is `pub use url::Url;` (reqwest/src/lib.rs),
//! so this is the exact same parser reqwest uses. The reqwest-coupled
//! `ssrf_apply` (it takes a `reqwest::ClientBuilder`) stays in `http_client.rs`
//! and imports the helpers below.
//!
//! ## SSRF protection
//!
//! Blocks requests whose resolved host is loopback, RFC-1918 private,
//! link-local, unique-local (ULA), unspecified, or v4-mapped-private.
//! The guard is **default-ON in production, default-OFF in dev**:
//!
//! * `IPE_HTTP_DENY_PRIVATE` set to a truthy value (`1`/`on`/`true`) → ON.
//! * `IPE_HTTP_DENY_PRIVATE` set to anything else → OFF (explicit opt-out).
//! * `IPE_HTTP_DENY_PRIVATE` unset → follows the production gate
//!   (`production_from_env`): ON in production, OFF in dev so localhost
//!   development keeps working.
//!
//! ## Pinning
//!
//! A vetted name is resolved exactly once, through tokio's non-blocking
//! resolver under a bounded deadline, and the caller dials the vetted address
//! itself ([`VettedDial::Pinned`]). A dial that resolves the name a second
//! time would reopen the DNS-rebinding window: the first answer passes the
//! check, the second points at an internal host.
//!
//! A TLS dial that must carry the name (SNI and certificate hostname
//! verification) runs through a private local relay on Unix
//! (`pinned_relay`): the driver keeps the name for TLS and dials the relay's
//! socket, and the relay carries the bytes to the vetted address.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use url::Url;

pub use crate::url::SchemeShown;

/// Returns `true` when the SSRF deny-private guard is active.
///
/// Default-ON in production (PRINCIPLES #1: the safe outcome must be the default
/// for untrusted input). The decision:
///   * `IPE_HTTP_DENY_PRIVATE` set to a truthy value (`1`/`on`/`true`) → ON.
///   * `IPE_HTTP_DENY_PRIVATE` set to anything else (`0`/`off`/`false`/…) → OFF
///     (explicit opt-out, so a production deploy that genuinely needs to reach a
///     private host can disable it deliberately).
///   * `IPE_HTTP_DENY_PRIVATE` UNSET → tied to the production gate
///     (`production_from_env`): ON in production (`ENV`/`IPE_ENV` not in
///     {unset, dev, development, local}), OFF in dev so localhost development
///     keeps working unchanged.
///
/// Env is read only through the crate's locked accessors (`read_env_var` +
/// `production_from_env`), never raw `std::env`.
pub(crate) fn ssrf_deny_private_enabled() -> bool {
    match crate::system::read_env_var("IPE_HTTP_DENY_PRIVATE") {
        Ok(v) => matches!(v.to_ascii_lowercase().trim(), "1" | "on" | "true"),
        Err(_) => crate::telemetry::production_from_env(),
    }
}

/// The deny-private policy a dial runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialPolicy {
    /// Refuse every blocked address and pin the dial to the vetted one.
    DenyPrivate,
    /// Dial any host (local development, or an explicit opt-out).
    AllowAll,
}

impl DialPolicy {
    /// The policy `IPE_HTTP_DENY_PRIVATE` and the production gate select.
    #[must_use]
    pub fn from_env() -> Self {
        if ssrf_deny_private_enabled() {
            Self::DenyPrivate
        } else {
            Self::AllowAll
        }
    }
}

/// The class of a blocked address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockedRange {
    /// Loopback: `127.0.0.0/8`, `::1`.
    Loopback,
    /// Link-local: `169.254.0.0/16` (cloud metadata), `fe80::/10`.
    LinkLocal,
    /// A private network: RFC 1918, unique-local `fc00::/7`, CGNAT `100.64.0.0/10`.
    Private,
    /// Unspecified, this-network, IETF protocol, benchmarking, or reserved space.
    Reserved,
}

impl std::fmt::Display for BlockedRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Private => "private",
            Self::Reserved => "reserved",
        })
    }
}

/// The blocked class `ip` belongs to, or `None` for a routable public address.
///
/// Covers:
/// - loopback        (127.0.0.0/8, ::1)
/// - RFC-1918        (10/8, 172.16/12, 192.168/16)
/// - link-local      (169.254/16, fe80::/10)
/// - unique-local    (fc00::/7 — fc00:: and fd00::)
/// - unspecified     (0.0.0.0, ::)
/// - this-network    (0.0.0.0/8 — RFC 1122; whole /8, not just 0.0.0.0)
/// - CGNAT/shared    (100.64.0.0/10 — RFC 6598; cloud internal hosts live here)
/// - IETF protocol   (192.0.0.0/24 — incl. 192.0.0.192)
/// - benchmarking    (198.18.0.0/15 — RFC 2544)
/// - reserved/bcast  (240.0.0.0/4 — incl. 255.255.255.255)
/// - v4-mapped IPv6  (::ffff:0:0/96) whose embedded v4 is in the above ranges
/// - NAT64           (64:ff9b::/96) / 6to4 (2002::/16) whose embedded v4 is blocked
///
/// The std `Ipv4Addr` predicates for CGNAT / benchmarking / reserved are
/// nightly-only (`is_shared`/`is_benchmarking`/`is_reserved`), so those ranges
/// are matched by octet.
#[must_use]
pub fn blocked_range(ip: IpAddr) -> Option<BlockedRange> {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => blocked_v6(v6),
    }
}

fn blocked_v4(v4: Ipv4Addr) -> Option<BlockedRange> {
    // Array-destructure (not indexing) → provably total, no panic site.
    let [a, b, c, _] = v4.octets();
    // 100.64.0.0/10 (CGNAT, RFC 6598).
    let cgnat = a == 100 && (b & 0xc0) == 0x40;
    // 0.0.0.0/8 "this network" (RFC 1122), 192.0.0.0/24 (IETF protocol),
    // 198.18.0.0/15 (benchmarking), 240.0.0.0/4 (reserved, incl. broadcast).
    let reserved =
        a == 0 || (a == 192 && b == 0 && c == 0) || (a == 198 && (b & 0xfe) == 18) || a >= 240;
    if v4.is_loopback() {
        Some(BlockedRange::Loopback)
    } else if v4.is_link_local() {
        Some(BlockedRange::LinkLocal)
    } else if v4.is_private() || cgnat {
        Some(BlockedRange::Private)
    } else if v4.is_unspecified() || reserved {
        Some(BlockedRange::Reserved)
    } else {
        None
    }
}

/// The IPv4 address carried in two IPv6 segments (`hi:lo`).
const fn v4_from_segments(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

fn blocked_v6(v6: Ipv6Addr) -> Option<BlockedRange> {
    if v6.is_loopback() {
        return Some(BlockedRange::Loopback);
    }
    if v6.is_unspecified() {
        return Some(BlockedRange::Reserved);
    }
    // Slice-pattern destructure (not indexing) → provably total, no panic site.
    let [s0, s1, s2, _s3, _s4, _s5, s6, s7] = v6.segments();
    // Link-local: fe80::/10
    if (s0 & 0xffc0) == 0xfe80 {
        return Some(BlockedRange::LinkLocal);
    }
    // Unique-local: fc00::/7 (covers fc00:: and fd00::)
    if (s0 & 0xfe00) == 0xfc00 {
        return Some(BlockedRange::Private);
    }
    // NAT64: 64:ff9b::/96 embeds the destination IPv4 in the low 32 bits.
    // to_ipv4_mapped/to_ipv4 miss it (high bits non-zero), so a private v4
    // reachable through a NAT64 gateway would slip past the v4 checks below.
    if s0 == 0x0064 && s1 == 0xff9b {
        return blocked_v4(v4_from_segments(s6, s7));
    }
    // 6to4: 2002::/16 embeds the IPv4 in segments 1..=2 (2002:V4HI:V4LO::/48).
    if s0 == 0x2002 {
        return blocked_v4(v4_from_segments(s1, s2));
    }
    // v4-mapped: ::ffff:0:0/96
    if let Some(v4) = v6.to_ipv4_mapped() {
        return blocked_v4(v4);
    }
    // v4-compatible (deprecated): ::a.b.c.d, e.g. ::10.0.0.1 still routes to
    // the embedded private IPv4 — to_ipv4() covers both compat + mapped.
    #[allow(deprecated)]
    if let Some(v4) = v6.to_ipv4() {
        return blocked_v4(v4);
    }
    None
}

/// Returns `true` when `ip` is in any range [`blocked_range`] classifies.
#[must_use]
pub fn is_private_ip(ip: IpAddr) -> bool {
    blocked_range(ip).is_some()
}

/// Whether a refusal may name the host it vetted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostDisclosure {
    /// The host cannot be part of a credential, so a refusal names it.
    Named,
    /// The host may be part of a URL's credentials, so a refusal names neither
    /// it nor any address it resolved to.
    Withheld,
}

/// A refused host as the refusal shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostShown {
    /// The host as the caller named it.
    Named(String),
    /// A host that may be part of a URL's credentials.
    Withheld,
}

impl HostShown {
    /// `host` as a refusal under `disclosure` shows it.
    fn of(host: &str, disclosure: HostDisclosure) -> Self {
        match disclosure {
            HostDisclosure::Named => Self::Named(host.to_owned()),
            HostDisclosure::Withheld => Self::Withheld,
        }
    }
}

impl std::fmt::Display for HostShown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(host) => write!(f, "host {host:?}"),
            Self::Withheld => write!(f, "host {WITHHELD_HOST}"),
        }
    }
}

/// A blocked host as the refusal shows it.
///
/// The blocked address exists only beside a named host: an IP-literal host's
/// address re-encodes the host's own text (`1234567` is `0.18.214.135`), so a
/// withheld host carries no address to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockedHost {
    /// A host the refusal may name, with the blocked address.
    Named {
        /// The host as the caller named it.
        host: String,
        /// The blocked address.
        ip: IpAddr,
    },
    /// A host that may be part of a URL's credentials.
    Withheld,
}

/// Why the SSRF gate refused a dial target.
///
/// `Display` carries no caller prefix; each surface adds its own (`http:`,
/// `ws:`, `db:`, `email.send/Smtp:`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SsrfRefusal {
    /// The host is, or resolved to, an address in a blocked range.
    Blocked {
        /// The host, and the blocked address when the host may be named.
        host: BlockedHost,
        /// The class of the blocked address.
        range: BlockedRange,
    },
    /// The resolver failed for the host.
    Unresolvable {
        /// The host as the refusal shows it.
        host: HostShown,
        /// The resolver's failure class.
        kind: std::io::ErrorKind,
    },
    /// The host resolved to no addresses.
    NoAddresses {
        /// The host as the refusal shows it.
        host: HostShown,
    },
    /// Resolution did not finish before the deadline.
    Timeout {
        /// The host as the refusal shows it.
        host: HostShown,
        /// The deadline that expired.
        after: Duration,
    },
    /// The target is a local Unix-domain socket, which reaches the local server
    /// exactly as loopback TCP does.
    LocalSocket,
    /// The connection URL names no host, so the driver picks a target the gate
    /// cannot prove safe.
    UnprovenTarget,
    /// Certificate verification needs the host name, and this platform has no
    /// relay that pins the dial while TLS keeps the name.
    UnpinnableTlsName {
        /// The host the certificate would be verified against.
        host: ConfiguredHost,
    },
}

impl std::fmt::Display for SsrfRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked {
                host: BlockedHost::Named { host, ip },
                range,
            } => {
                if strip_ipv6_brackets(host).parse::<IpAddr>().is_ok() {
                    write!(f, "blocked: {range} host {ip}")?;
                } else {
                    write!(f, "blocked: host {host:?} resolved to {range} address {ip}")?;
                }
            }
            Self::Blocked {
                host: BlockedHost::Withheld,
                range,
            } => write!(f, "blocked: {range} host {WITHHELD_HOST}")?,
            Self::Unresolvable { host, kind } => {
                write!(f, "blocked: could not resolve {host}: {kind}")?;
            }
            Self::NoAddresses { host } => {
                write!(f, "blocked: {host} resolved to no addresses")?;
            }
            Self::Timeout { host, after } => write!(
                f,
                "blocked: resolving {host} timed out after {} ms",
                after.as_millis()
            )?,
            Self::LocalSocket => f.write_str("blocked: local socket dial target")?,
            Self::UnprovenTarget => f.write_str(
                "blocked: connection URL names no host, so the dial target is unproven",
            )?,
            Self::UnpinnableTlsName { host } => write!(
                f,
                "blocked: sslmode=verify-full checks the certificate against host {:?}, \
                 but the dial is pinned to its vetted address; use an IP-literal host \
                 whose certificate names that address, or sslmode=verify-ca",
                host.as_str()
            )?,
        }
        f.write_str(" (IPE_HTTP_DENY_PRIVATE)")
    }
}

impl std::error::Error for SsrfRefusal {}

/// Name resolution the SSRF gate vets.
pub trait HostResolver: Sync {
    /// Every address `host:port` resolves to.
    fn lookup(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = std::io::Result<Vec<SocketAddr>>> + Send;
}

/// The system resolver, through tokio's non-blocking lookup.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    async fn lookup(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// Default deadline for one SSRF-gate name resolution.
const DNS_TIMEOUT_MS_DEFAULT: u64 = 5_000;

/// The deadline for one SSRF-gate name resolution.
///
/// A stalling resolver must not hold a task indefinitely: a remote party that
/// controls the target name's authoritative server could otherwise pile up
/// pending dials. Overridable via `IPE_HTTP_DNS_TIMEOUT_MS` (a positive
/// integer); anything else falls back to the default.
#[must_use]
pub fn dns_timeout() -> Duration {
    let ms = crate::system::read_env_var("IPE_HTTP_DNS_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DNS_TIMEOUT_MS_DEFAULT);
    Duration::from_millis(ms)
}

/// Strip a single surrounding `[`…`]` from an IPv6-literal host as it appears in
/// a URL authority (`Url::host_str()` returns `"[::1]"`, not `"::1"`). Returns the
/// inner slice when BOTH brackets are present, else the input unchanged — a plain
/// hostname or bare v4 literal is returned as-is (they carry no brackets), so a
/// subsequent `IpAddr::parse` still correctly fails for a hostname.
///
/// This is the single normalization point that puts every v6 URL host back on the
/// `is_private_ip` path; it is also used to key reqwest's `resolve_to_addrs`, whose
/// lookup key is the UNBRACKETED host (hyper's `Uri::host`).
pub(crate) fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Refuse `ip` when it is blocked, showing `host` as `disclosure` allows.
fn refuse_blocked(host: &str, disclosure: HostDisclosure, ip: IpAddr) -> Result<(), SsrfRefusal> {
    blocked_range(ip).map_or(Ok(()), |range| {
        let host = match disclosure {
            HostDisclosure::Named => BlockedHost::Named {
                host: host.to_owned(),
                ip,
            },
            HostDisclosure::Withheld => BlockedHost::Withheld,
        };
        Err(SsrfRefusal::Blocked { host, range })
    })
}

/// Every address a host passed the SSRF gate with — never empty.
///
/// The only constructor is [`vet_host_addrs_with`], so holding one proves
/// every address in it is outside every blocked range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VettedAddrs {
    first: SocketAddr,
    rest: Vec<SocketAddr>,
}

impl VettedAddrs {
    /// The address a single-address dialler uses.
    #[must_use]
    pub const fn first(&self) -> SocketAddr {
        self.first
    }

    /// Every vetted address, first one first.
    #[must_use]
    pub fn into_vec(self) -> Vec<SocketAddr> {
        let mut all = Vec::with_capacity(self.rest.len().saturating_add(1));
        all.push(self.first);
        all.extend(self.rest);
        all
    }
}

/// Resolve `host` once and return every address to dial, refusing any blocked one.
///
/// An IP literal (bracketed or not) is decided without a lookup. A name is
/// resolved through `resolver` within `deadline`; if ANY answer is blocked the
/// whole host is refused (a multi-record answer mixing public and private
/// addresses is ambiguous), otherwise every answer, carrying `port`, is
/// returned for the caller to dial directly. A refusal shows `host` only as
/// `disclosure` allows.
///
/// # Errors
///
/// [`SsrfRefusal`] naming why the host was refused.
pub async fn vet_host_addrs_with<R: HostResolver>(
    resolver: &R,
    host: &str,
    disclosure: HostDisclosure,
    port: u16,
    deadline: Duration,
) -> Result<VettedAddrs, SsrfRefusal> {
    // Parse-don't-validate at the boundary: a URL host taken from
    // `Url::host_str()` returns an IPv6 literal BRACKETED (`"[::1]"`). Strip a
    // single bracket pair and parse the IP literal FIRST, so every v6 literal
    // is decided by `blocked_range` instead of reaching the resolver.
    if let Ok(ip) = strip_ipv6_brackets(host).parse::<IpAddr>() {
        return refuse_blocked(host, disclosure, ip).map(|()| VettedAddrs {
            first: SocketAddr::new(ip, port),
            rest: Vec::new(),
        });
    }
    let addrs = match tokio::time::timeout(deadline, resolver.lookup(host, port)).await {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(e)) => {
            return Err(SsrfRefusal::Unresolvable {
                host: HostShown::of(host, disclosure),
                kind: e.kind(),
            });
        }
        Err(_elapsed) => {
            return Err(SsrfRefusal::Timeout {
                host: HostShown::of(host, disclosure),
                after: deadline,
            });
        }
    };
    for addr in &addrs {
        refuse_blocked(host, disclosure, addr.ip())?;
    }
    let mut vetted = addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr.ip(), port));
    vetted.next().map_or_else(
        || {
            Err(SsrfRefusal::NoAddresses {
                host: HostShown::of(host, disclosure),
            })
        },
        |first| {
            Ok(VettedAddrs {
                first,
                rest: vetted.collect(),
            })
        },
    )
}

/// Resolve `host` once and return the address to dial, refusing any blocked one.
///
/// The first address [`vet_host_addrs_with`] vets, for a dialler that takes
/// one address.
///
/// # Errors
///
/// [`SsrfRefusal`] naming why the host was refused.
pub async fn vet_host_with<R: HostResolver>(
    resolver: &R,
    host: &str,
    disclosure: HostDisclosure,
    port: u16,
    deadline: Duration,
) -> Result<SocketAddr, SsrfRefusal> {
    vet_host_addrs_with(resolver, host, disclosure, port, deadline)
        .await
        .map(|vetted| vetted.first())
}

/// A host a refusal may name, because it cannot be part of a URL's credentials.
///
/// Built only from a configuration field that holds a host and nothing else
/// (`ConfiguredHost::from_config`) or from a URL whose userinfo is proven
/// not to run past its authority (`UnambiguousUrl`). A host read from any
/// other URL has no way into this type, so no refusal naming a
/// `ConfiguredHost` can echo part of a user name or password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredHost(String);

impl ConfiguredHost {
    /// The host a configuration field names on its own, never read from a URL.
    #[cfg_attr(not(any(feature = "db", feature = "email")), allow(dead_code))]
    pub(crate) const fn from_config(host: String) -> Self {
        Self(host)
    }

    /// The host as configured.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Why a URL is not an [`UnambiguousUrl`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "db"), allow(dead_code))]
pub(crate) enum UrlUnproven {
    /// Its user name and password may run past its authority
    /// ([`userinfo_is_ambiguous`]).
    AmbiguousUserinfo,
    /// It does not parse.
    Invalid,
}

/// A URL whose user name and password cannot run past its authority.
///
/// Built only after [`userinfo_is_ambiguous`] clears the parse it holds, so
/// every host read from it, by its authority or a query parameter, is a
/// [`ConfiguredHost`]. Holds the URL's credentials, so it has no `Debug` or
/// `Display`.
#[cfg_attr(not(feature = "db"), allow(dead_code))]
pub(crate) struct UnambiguousUrl {
    raw: String,
    parsed: Url,
}

#[cfg_attr(not(feature = "db"), allow(dead_code))]
impl UnambiguousUrl {
    /// Parse `raw`, refusing it when its userinfo is ambiguous.
    ///
    /// Ambiguity is decided first, so a URL that does not parse and holds an
    /// `@` is refused as ambiguous.
    pub(crate) fn parse(raw: &str) -> Result<Self, UrlUnproven> {
        let parsed = Url::parse(raw);
        if userinfo_is_ambiguous(raw, parsed.as_ref().ok()) {
            return Err(UrlUnproven::AmbiguousUserinfo);
        }
        parsed
            .map(|parsed| Self {
                raw: raw.to_owned(),
                parsed,
            })
            .map_err(|_| UrlUnproven::Invalid)
    }

    /// `parsed`, the parse of `raw`, unless `raw`'s userinfo is ambiguous.
    pub(crate) fn of_parsed(raw: &str, parsed: Url) -> Option<Self> {
        (!userinfo_is_ambiguous(raw, Some(&parsed))).then(|| Self {
            raw: raw.to_owned(),
            parsed,
        })
    }

    /// The URL as written.
    pub(crate) const fn as_str(&self) -> &str {
        self.raw.as_str()
    }

    /// The parse the ambiguity check cleared.
    pub(crate) const fn url(&self) -> &Url {
        &self.parsed
    }

    /// The authority's host, when it names a non-empty one.
    pub(crate) fn host(&self) -> Option<ConfiguredHost> {
        self.parsed
            .host_str()
            .filter(|host| !host.is_empty())
            .map(|host| ConfiguredHost(host.to_owned()))
    }

    /// The value of a `host` or `hostaddr` query parameter of this URL equal to
    /// `value`.
    pub(crate) fn query_host(&self, value: &str) -> Option<ConfiguredHost> {
        self.parsed
            .query_pairs()
            .find(|(key, named)| matches!(&**key, "host" | "hostaddr") && named == value)
            .map(|(_, named)| ConfiguredHost(named.into_owned()))
    }

    /// `host` when this URL names it, by its authority or by a `host` or
    /// `hostaddr` query parameter, as a driver's own reading of the URL does.
    pub(crate) fn named_host(&self, host: &str) -> Option<ConfiguredHost> {
        self.host()
            .filter(|named| named.as_str() == host)
            .or_else(|| self.query_host(host))
    }
}

/// An address the SSRF gate vetted, carried by [`VettedDial::Pinned`].
///
/// Its field is private to this module, so only the gate's constructors mint
/// one: a dialler that takes a `VettedAddr` cannot be handed a raw address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(any(feature = "db", feature = "email", feature = "websocket_client")),
    allow(dead_code)
)]
pub(crate) struct VettedAddr(SocketAddr);

#[cfg_attr(
    not(any(feature = "db", feature = "email", feature = "websocket_client")),
    allow(dead_code)
)]
impl VettedAddr {
    /// The vetted socket address to dial.
    pub(crate) const fn socket_addr(self) -> SocketAddr {
        self.0
    }

    /// Treat `addr` as vetted, for tests that stand up a local server.
    #[cfg(test)]
    pub(crate) const fn assume_vetted_for_test(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

/// Proof that `host:port` passed the SSRF gate under the policy in effect.
///
/// The only constructors are [`VettedDial::for_configured_host`],
/// [`VettedDial::for_configured_host_with`], [`VettedDial::for_url`] and
/// [`vet_url_with`].
/// Under [`DialPolicy::DenyPrivate`] the proof is the vetted address itself,
/// and the caller MUST dial that address rather than the name — dialling the
/// name resolves it again and reopens the DNS-rebinding window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(any(feature = "db", feature = "email", feature = "websocket_client")),
    allow(dead_code)
)]
pub(crate) enum VettedDial {
    /// Deny-private is on: dial exactly this address.
    Pinned(VettedAddr),
    /// Deny-private is off: the host may be dialled by name.
    Unrestricted,
}

#[cfg_attr(not(any(feature = "db", feature = "email")), allow(dead_code))]
impl VettedDial {
    /// Vet `host:port` under the environment's policy and the system resolver.
    pub(crate) async fn for_configured_host(
        host: &ConfiguredHost,
        port: u16,
    ) -> Result<Self, SsrfRefusal> {
        Self::for_configured_host_with(DialPolicy::from_env(), &SystemResolver, host, port).await
    }

    /// Vet `host:port` under `policy`, resolving through `resolver`.
    ///
    /// A [`ConfiguredHost`] cannot be part of a URL's credentials, so a
    /// refusal names it.
    pub(crate) async fn for_configured_host_with<R: HostResolver>(
        policy: DialPolicy,
        resolver: &R,
        host: &ConfiguredHost,
        port: u16,
    ) -> Result<Self, SsrfRefusal> {
        match policy {
            DialPolicy::DenyPrivate => vet_host_with(
                resolver,
                host.as_str(),
                HostDisclosure::Named,
                port,
                dns_timeout(),
            )
            .await
            .map(|addr| Self::Pinned(VettedAddr(addr))),
            DialPolicy::AllowAll => Ok(Self::Unrestricted),
        }
    }

    /// Vet `url`'s host under the environment's policy and the system resolver.
    // Sole consumer is `ws_client.rs`. `cfg_attr`+`allow`, not `#[cfg]`:
    // generated projects include this module without declaring the
    // `websocket_client` Cargo feature, so a `#[cfg]` would remove the fn
    // from under a generated WebSocket caller.
    #[cfg_attr(not(feature = "websocket_client"), allow(dead_code))]
    pub(crate) async fn for_url(url: &str) -> Result<Self, UrlRefusal> {
        vet_url_with(DialPolicy::from_env(), &SystemResolver, url, dns_timeout()).await
    }

    /// The host string to hand a dialler: the vetted IP when pinned, else `host`.
    pub(crate) fn dial_host(self, host: &str) -> String {
        match self {
            Self::Pinned(addr) => addr.socket_addr().ip().to_string(),
            Self::Unrestricted => host.to_owned(),
        }
    }
}

/// The schemes an outbound surface may dial under deny-private.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatedSchemes {
    /// `http` and `https`: the HTTP request surface.
    Http,
    /// `http`, `https`, `ws` and `wss`.
    HttpAndWebSocket,
}

impl GatedSchemes {
    /// Every scheme this set admits.
    const fn schemes(self) -> &'static [&'static str] {
        match self {
            Self::Http => &["http", "https"],
            Self::HttpAndWebSocket => &["http", "https", "ws", "wss"],
        }
    }

    /// Whether `scheme` is one of this set's.
    fn admits(self, scheme: &str) -> bool {
        self.schemes().contains(&scheme)
    }
}

impl std::fmt::Display for GatedSchemes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.schemes().join("/"))
    }
}

/// Why the SSRF gate refused a URL.
///
/// `Display` carries no caller prefix; each surface adds its own (`http:`,
/// `ws:`). No variant holds text read from the URL's credentials: an
/// unparseable URL is not shown at all, a scheme only through
/// [`SchemeShown`], and a host only when [`DisplayableUrl`] would show it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UrlRefusal {
    /// The URL's user name and password may run past its parsed userinfo
    /// ([`userinfo_may_spill_past_the_query`]).
    MisplacedUserinfo,
    /// The URL did not parse.
    Invalid {
        /// The parser's reason.
        reason: url::ParseError,
    },
    /// The scheme is not one the surface dials.
    Scheme {
        /// The URL's scheme, when it may be named.
        scheme: SchemeShown,
        /// The schemes the surface dials.
        admitted: GatedSchemes,
    },
    /// The URL names no host.
    NoHost,
    /// The URL's host was refused.
    Host(SsrfRefusal),
}

impl std::fmt::Display for UrlRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MisplacedUserinfo => f.write_str(
                "blocked: the URL has a `\\`, or an `@` in its path or fragment, so its user \
                 name and password may run into the host or path; percent-encode `@`, `/`, \
                 `?`, `#` and `\\` in the user name and password (as %40, %2F, %3F, %23, \
                 %5C), and `@` in the path (as %40)",
            ),
            Self::Invalid { reason } => {
                write!(f, "blocked: invalid URL: {reason} (IPE_HTTP_DENY_PRIVATE)")
            }
            Self::Scheme { scheme, admitted } => write!(
                f,
                "blocked: scheme {scheme} is not {admitted} (IPE_HTTP_DENY_PRIVATE)"
            ),
            Self::NoHost => f.write_str("blocked: URL has no host (IPE_HTTP_DENY_PRIVATE)"),
            Self::Host(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for UrlRefusal {}

/// Stands in for the part of a URL an error message cannot show safely.
const WITHHELD_URL_TAIL: &str = "<withheld: may hold credentials>";

/// Stands in for a refused host that may be part of a URL's credentials.
const WITHHELD_HOST: &str = "<withheld: may be part of the URL's credentials>";

/// Whether `raw`'s user name and password may run past what the parser read
/// as its userinfo into its host, path, or fragment.
///
/// Only the authority's last `@` separates the userinfo from the host, and the
/// authority ends at the first `/`, `?`, or `#` — and, for `http`, `https`,
/// `ws`, `wss`, `ftp`, and `file`, at `\`. A credential holding one of those
/// ends the authority early, and the parser reads the rest of it as host,
/// path, query, or fragment. The parser keeps `@` literal outside the
/// authority, so the userinfo may have spilled when `parsed` holds an `@` in
/// its path or fragment, when `raw` holds a `\` under any scheme, or when
/// `raw` does not parse and holds an `@`. An `@` in the query is left to
/// [`userinfo_is_ambiguous`].
pub(crate) fn userinfo_may_spill_past_the_query(raw: &str, parsed: Option<&Url>) -> bool {
    raw.contains('\\')
        || parsed.map_or_else(
            || raw.contains('@'),
            |url| {
                url.path().contains('@')
                    || url
                        .fragment()
                        .is_some_and(|fragment| fragment.contains('@'))
            },
        )
}

/// Whether `raw`'s user name and password may run past what the parser read
/// as its userinfo anywhere in the URL.
///
/// [`userinfo_may_spill_past_the_query`], or an `@` in the query: a user name
/// holding a `?` ends the authority there.
pub(crate) fn userinfo_is_ambiguous(raw: &str, parsed: Option<&Url>) -> bool {
    userinfo_may_spill_past_the_query(raw, parsed)
        || parsed.is_some_and(|url| url.query().is_some_and(|query| query.contains('@')))
}

/// Refuse a URL to dial whose user name and password may run into its host
/// or path ([`userinfo_may_spill_past_the_query`]).
///
/// The dial would reach a host read from the credential and send the rest of
/// it in the request path, so the URL is refused under every policy. An `@`
/// in the query is admitted: e-mail addresses and account names routinely
/// travel there, and a refusal that shows the host withholds it
/// ([`DisplayableUrl`]). A URL that does not parse is left to the dialler's
/// own parse, which refuses it.
///
/// # Errors
///
/// [`UrlRefusal::MisplacedUserinfo`].
pub(crate) fn refuse_misplaced_userinfo(raw: &str) -> Result<(), UrlRefusal> {
    let spills = Url::parse(raw).map_or_else(
        |_| raw.contains('\\'),
        |url| userinfo_may_spill_past_the_query(raw, Some(&url)),
    );
    if spills {
        Err(UrlRefusal::MisplacedUserinfo)
    } else {
        Ok(())
    }
}

/// A URL as an error message or log line may show it: scheme, host, and port.
///
/// Derived from the parse the gate dials, never from a second reading of the
/// text. The userinfo, path, query, and fragment are never shown: a token
/// travels in any of them (`?access_token=`, `/ws/<session>`). The host is
/// withheld too when the URL does not parse, its scheme is not nameable, or
/// its userinfo is ambiguous ([`userinfo_is_ambiguous`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayableUrl(Shown);

/// How much of a URL [`DisplayableUrl`] shows.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Shown {
    /// A well-known scheme with the host the parser read and any explicit port.
    Origin {
        /// The URL's scheme.
        scheme: &'static str,
        /// The host as the URL serializes it (an IPv6 literal bracketed).
        host: String,
        /// The port, when the URL names one other than its scheme's default.
        port: Option<u16>,
    },
    /// Only the scheme, as [`SchemeShown`] allows.
    SchemeOnly(SchemeShown),
}

impl DisplayableUrl {
    /// `raw` as it may be shown, parsed with the gate's parser.
    // Sole consumer is `ws_client.rs`; see `VettedDial::for_url`.
    #[cfg_attr(not(feature = "websocket_client"), allow(dead_code))]
    pub(crate) fn of(raw: &str) -> Self {
        Self::of_parsed(raw, Url::parse(raw).ok().as_ref())
    }

    /// `raw` as it may be shown, given the gate's parse of it.
    pub(crate) fn of_parsed(raw: &str, parsed: Option<&Url>) -> Self {
        let Some(parsed) = parsed else {
            return Self(Shown::SchemeOnly(SchemeShown::Withheld));
        };
        let scheme = SchemeShown::of(parsed.scheme());
        let SchemeShown::Known(known) = scheme else {
            return Self(Shown::SchemeOnly(scheme));
        };
        if userinfo_is_ambiguous(raw, Some(parsed)) {
            return Self(Shown::SchemeOnly(scheme));
        }
        parsed
            .host_str()
            .map_or(Self(Shown::SchemeOnly(scheme)), |host| {
                Self(Shown::Origin {
                    scheme: known,
                    host: host.to_owned(),
                    port: parsed.port(),
                })
            })
    }

    /// Whether the host the parser read is shown, so it cannot be part of the
    /// URL's credentials.
    pub(crate) const fn shows_host(&self) -> bool {
        matches!(self.0, Shown::Origin { .. })
    }

    /// How a host refusal for this URL may show the host.
    const fn host_disclosure(&self) -> HostDisclosure {
        if self.shows_host() {
            HostDisclosure::Named
        } else {
            HostDisclosure::Withheld
        }
    }
}

impl std::fmt::Display for DisplayableUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Shown::Origin {
                scheme,
                host,
                port: Some(port),
            } => write!(f, "{scheme}://{host}:{port}"),
            Shown::Origin {
                scheme,
                host,
                port: None,
            } => write!(f, "{scheme}://{host}"),
            Shown::SchemeOnly(SchemeShown::Known(scheme)) => {
                write!(f, "{scheme}:{WITHHELD_URL_TAIL}")
            }
            Shown::SchemeOnly(SchemeShown::Withheld) => f.write_str(WITHHELD_URL_TAIL),
        }
    }
}

/// How a host refusal for `raw` may show the host `parsed` read from it.
pub(crate) fn url_host_disclosure(raw: &str, parsed: &Url) -> HostDisclosure {
    DisplayableUrl::of_parsed(raw, Some(parsed)).host_disclosure()
}

/// Parse `url` and admit only a scheme in `admitted`.
///
/// # Errors
///
/// [`UrlRefusal::Invalid`] or [`UrlRefusal::Scheme`].
pub(crate) fn parse_gated_url_within(url: &str, admitted: GatedSchemes) -> Result<Url, UrlRefusal> {
    let parsed = Url::parse(url).map_err(|reason| UrlRefusal::Invalid { reason })?;
    if admitted.admits(parsed.scheme()) {
        Ok(parsed)
    } else {
        Err(UrlRefusal::Scheme {
            scheme: SchemeShown::of(parsed.scheme()),
            admitted,
        })
    }
}

/// Parse `url` and admit only `http`, `https`, `ws`, or `wss`.
///
/// # Errors
///
/// [`UrlRefusal::Invalid`] or [`UrlRefusal::Scheme`].
pub(crate) fn parse_gated_url(url: &str) -> Result<Url, UrlRefusal> {
    parse_gated_url_within(url, GatedSchemes::HttpAndWebSocket)
}

/// Vet `url` under `policy`, resolving its host through `resolver` within `deadline`.
///
/// A URL whose userinfo may run into its host or path is refused under every
/// policy ([`refuse_misplaced_userinfo`]). Under [`DialPolicy::DenyPrivate`]
/// the URL must parse, carry a gated scheme and a host, and the host must
/// pass [`vet_host_with`]; the proof pins the vetted address with the URL's
/// port. Under [`DialPolicy::AllowAll`] the URL is otherwise dialled as given.
///
/// # Errors
///
/// [`UrlRefusal`] naming why the URL was refused.
#[cfg_attr(not(feature = "websocket_client"), allow(dead_code))]
pub(crate) async fn vet_url_with<R: HostResolver>(
    policy: DialPolicy,
    resolver: &R,
    url: &str,
    deadline: Duration,
) -> Result<VettedDial, UrlRefusal> {
    refuse_misplaced_userinfo(url)?;
    match policy {
        DialPolicy::AllowAll => Ok(VettedDial::Unrestricted),
        DialPolicy::DenyPrivate => {
            let parsed = parse_gated_url(url)?;
            let host = parsed.host_str().ok_or(UrlRefusal::NoHost)?;
            // Every gated scheme has a known default port, so the fallback is
            // unreachable; port 0 would fail the dial, never reach a service.
            let port = parsed.port_or_known_default().unwrap_or(0);
            let disclosure = url_host_disclosure(url, &parsed);
            vet_host_with(resolver, host, disclosure, port, deadline)
                .await
                .map(|addr| VettedDial::Pinned(VettedAddr(addr)))
                .map_err(UrlRefusal::Host)
        }
    }
}

/// Non-blocking redirect-hop guard: a URL's scheme and, for an IP-literal host, its range.
///
/// A named host is vetted by the HTTP client's connect-time resolver, which
/// runs the same [`vet_host_addrs_with`] gate, so re-resolving here would only
/// add a lookup inside reqwest's sync redirect closure. IP-literal redirect
/// targets bypass the resolver, so they MUST still be range-checked here —
/// that check is pure and non-blocking.
///
/// # Errors
///
/// [`UrlRefusal`] naming why the hop was refused.
// Only `http_client::ssrf_apply`'s reqwest redirect closure calls this; the `ssrf`
// module also compiles under `db`/`websocket_client` where that caller is absent.
#[cfg_attr(not(feature = "http_client"), allow(dead_code))]
pub(crate) fn ssrf_check_url_nonblocking(url: &str) -> Result<(), UrlRefusal> {
    let parsed = parse_gated_url(url)?;
    let host = parsed.host_str().ok_or(UrlRefusal::NoHost)?;
    // Only IP literals are decided here (no DNS); a named host defers to the
    // connect-time resolver. `strip_ipv6_brackets` puts a `[::1]`-style literal
    // back on the `blocked_range` path; a hostname simply fails the parse.
    strip_ipv6_brackets(host)
        .parse::<IpAddr>()
        .map_or(Ok(()), |ip| {
            refuse_blocked(host, url_host_disclosure(url, &parsed), ip).map_err(UrlRefusal::Host)
        })
}

#[cfg(all(feature = "db", unix))]
pub(crate) use pinned_relay::{PinnedRelay, RelayUnavailable};

/// A private local relay that carries a driver's socket dial to a pinned address.
///
/// A TLS driver that verifies the certificate against a host name dials that
/// name, resolving it a second time. The relay lets the driver keep the name
/// for SNI and hostname verification while every byte travels to the address
/// the gate vetted: the driver dials a Unix socket in an owner-only directory,
/// and the relay copies each accepted connection to the pinned address. No
/// name is resolved after the gate.
#[cfg(all(feature = "db", unix))]
mod pinned_relay {
    use super::VettedAddr;
    use std::future::Future;
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::net::{TcpStream, UnixListener, UnixStream};
    use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

    /// How long one dial of the pinned address may take.
    const RELAY_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

    /// The pause after a failed accept, so a persistent error cannot spin.
    const RELAY_ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

    /// The bytes one direction of a relayed connection buffers.
    const RELAY_BUFFER_BYTES: usize = 16 * 1024;

    /// How many fresh directory names the relay tries per base directory.
    const RELAY_DIR_ATTEMPTS: u32 = 8;

    /// The longest socket path every Unix `sockaddr_un` holds, terminator excluded.
    const SOCKET_PATH_MAX_BYTES: usize = 103;

    /// The relay could not be opened; the dial is refused rather than unpinned.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RelayUnavailable;

    /// A running relay from a private Unix socket to one pinned address.
    ///
    /// The driver dials the socket at `.s.PGSQL.{port}` inside
    /// [`PinnedRelay::socket_dir`]. Dropping the relay stops accepting and
    /// removes the socket and its directory; connections already relayed run
    /// on until either end closes.
    #[derive(Debug)]
    pub struct PinnedRelay {
        /// The owner-only directory holding the socket.
        socket_dir: PathBuf,
        /// The vetted address every accepted connection is carried to.
        target: VettedAddr,
        /// Dropping this sender stops the accept loop.
        _stop: oneshot::Sender<()>,
    }

    impl PinnedRelay {
        /// Open a relay to `target` whose socket answers for `socket_port`.
        ///
        /// At most `max_connections` relayed connections are open at once, the
        /// ceiling of the pool dialling through the relay, so the relay never
        /// stalls a connection the pool may open.
        ///
        /// # Errors
        ///
        /// [`RelayUnavailable`] when no owner-only directory or socket can be
        /// created.
        pub(crate) fn open(
            target: VettedAddr,
            socket_port: u16,
            max_connections: u32,
        ) -> Result<Self, RelayUnavailable> {
            let socket_name = format!(".s.PGSQL.{socket_port}");
            let (socket_dir, owner) = create_private_dir(&socket_name)?;
            let socket = RelaySocket {
                path: socket_dir.join(&socket_name),
                dir: socket_dir.clone(),
            };
            // A failed bind drops `socket`, which removes the directory.
            let listener = UnixListener::bind(&socket.path).map_err(|_| RelayUnavailable)?;
            let (stop, stopped) = oneshot::channel();
            tokio::spawn(serve(
                listener,
                socket,
                target,
                owner,
                relay_ceiling(max_connections),
                stopped,
            ));
            Ok(Self {
                socket_dir,
                target,
                _stop: stop,
            })
        }

        /// The directory the driver's socket option names.
        pub fn socket_dir(&self) -> &Path {
            &self.socket_dir
        }

        /// The vetted address the relay carries connections to.
        #[cfg_attr(not(test), allow(dead_code))]
        pub(crate) const fn target(&self) -> VettedAddr {
            self.target
        }

        /// Keep the relay running until `closed` completes.
        pub fn hold_until<F>(self, closed: F)
        where
            F: Future<Output = ()> + Send + 'static,
        {
            tokio::spawn(async move {
                closed.await;
                drop(self);
            });
        }
    }

    /// Create an owner-only directory whose socket path fits a `sockaddr_un`.
    ///
    /// Returns the directory and its owner's uid, the only uid the relay
    /// serves.
    fn create_private_dir(socket_name: &str) -> Result<(PathBuf, u32), RelayUnavailable> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        create_private_dir_in(
            &[std::env::temp_dir(), PathBuf::from("/tmp")],
            socket_name,
            || NEXT.fetch_add(1, Ordering::Relaxed),
        )
    }

    /// Create an owner-only directory under the first of `bases` that admits one.
    ///
    /// Each base is tried with up to [`RELAY_DIR_ATTEMPTS`] names numbered by
    /// `next`: a name already taken moves on to the next number, and a base
    /// whose socket path would not fit a `sockaddr_un`, or that refuses the
    /// directory, moves on to the next base.
    fn create_private_dir_in(
        bases: &[PathBuf],
        socket_name: &str,
        mut next: impl FnMut() -> u64,
    ) -> Result<(PathBuf, u32), RelayUnavailable> {
        let pid = std::process::id();
        for base in bases {
            for _ in 0..RELAY_DIR_ATTEMPTS {
                let n = next();
                let dir = base.join(format!("ipe-pg-relay-{pid}-{n}"));
                if dir.join(socket_name).as_os_str().len() > SOCKET_PATH_MAX_BYTES {
                    break;
                }
                match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                    Ok(()) => return owner_only(&dir).map(|owner| (dir, owner)),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(_) => break,
                }
            }
        }
        Err(RelayUnavailable)
    }

    /// The owner of `dir`, once it is proven a real directory no other user can enter.
    fn owner_only(dir: &Path) -> Result<u32, RelayUnavailable> {
        match std::fs::symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() && meta.mode() & 0o077 == 0 => Ok(meta.uid()),
            _ => {
                let _removed = std::fs::remove_dir(dir);
                Err(RelayUnavailable)
            }
        }
    }

    /// The relayed-connection ceiling for a pool of `max_connections`.
    fn relay_ceiling(max_connections: u32) -> usize {
        usize::try_from(max_connections)
            .unwrap_or(usize::MAX)
            .clamp(1, Semaphore::MAX_PERMITS)
    }

    /// The socket and directory a relay owns, removed when dropped.
    ///
    /// The accept loop owns it, so both are removed when the loop stops and
    /// also when the runtime drops the loop before it runs to its end.
    struct RelaySocket {
        /// The socket the driver dials.
        path: PathBuf,
        /// The owner-only directory holding it.
        dir: PathBuf,
    }

    impl Drop for RelaySocket {
        fn drop(&mut self) {
            remove_quietly(&self.path, &self.dir);
        }
    }

    /// Remove the socket and its directory, ignoring what is already gone.
    fn remove_quietly(socket_path: &Path, socket_dir: &Path) {
        let _socket_removed = std::fs::remove_file(socket_path);
        let _dir_removed = std::fs::remove_dir(socket_dir);
    }

    /// Accept connections from `owner` and relay each to `target` until stopped.
    ///
    /// At most `ceiling` relayed connections are open at once; `socket` is
    /// removed once the loop ends or is dropped.
    async fn serve(
        listener: UnixListener,
        socket: RelaySocket,
        target: VettedAddr,
        owner: u32,
        ceiling: usize,
        mut stopped: oneshot::Receiver<()>,
    ) {
        let permits = Arc::new(Semaphore::new(ceiling));
        loop {
            let permit = tokio::select! {
                _ = &mut stopped => break,
                permit = Arc::clone(&permits).acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
            };
            let accepted = tokio::select! {
                _ = &mut stopped => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((client, _)) = accepted else {
                tokio::time::sleep(RELAY_ACCEPT_BACKOFF).await;
                continue;
            };
            if client.peer_cred().is_ok_and(|cred| cred.uid() == owner) {
                tokio::spawn(relay_connection(client, target, permit));
            }
        }
        drop(listener);
        drop(socket);
    }

    /// Carry one accepted connection to `target` in both directions.
    async fn relay_connection(
        client: UnixStream,
        target: VettedAddr,
        _permit: OwnedSemaphorePermit,
    ) {
        let dialed = tokio::time::timeout(RELAY_DIAL_TIMEOUT, dial_relay_target(target)).await;
        let Ok(Ok(server)) = dialed else {
            return;
        };
        let _nodelay = server.set_nodelay(true);
        tokio::select! {
            () = pump(&client, &server) => {},
            () = pump(&server, &client) => {},
        }
    }

    /// Dial the pinned address the gate vetted.
    async fn dial_relay_target(target: VettedAddr) -> io::Result<TcpStream> {
        tokio::net::TcpStream::connect(target.socket_addr()).await
    }

    /// One end of a relayed connection, driven by readiness and non-blocking calls.
    trait RelayEnd: Sync {
        /// Wait until the end may be readable.
        fn ready_to_read(&self) -> impl Future<Output = io::Result<()>> + Send;
        /// Read what is available without waiting.
        fn read_now(&self, buf: &mut [u8]) -> io::Result<usize>;
        /// Wait until the end may be writable.
        fn ready_to_write(&self) -> impl Future<Output = io::Result<()>> + Send;
        /// Write what fits without waiting.
        fn write_now(&self, buf: &[u8]) -> io::Result<usize>;
    }

    impl RelayEnd for UnixStream {
        fn ready_to_read(&self) -> impl Future<Output = io::Result<()>> + Send {
            self.readable()
        }
        fn read_now(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.try_read(buf)
        }
        fn ready_to_write(&self) -> impl Future<Output = io::Result<()>> + Send {
            self.writable()
        }
        fn write_now(&self, buf: &[u8]) -> io::Result<usize> {
            self.try_write(buf)
        }
    }

    impl RelayEnd for TcpStream {
        fn ready_to_read(&self) -> impl Future<Output = io::Result<()>> + Send {
            self.readable()
        }
        fn read_now(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.try_read(buf)
        }
        fn ready_to_write(&self) -> impl Future<Output = io::Result<()>> + Send {
            self.writable()
        }
        fn write_now(&self, buf: &[u8]) -> io::Result<usize> {
            self.try_write(buf)
        }
    }

    /// Whether a non-blocking call found nothing to do yet.
    fn not_ready(e: &io::Error) -> bool {
        matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        )
    }

    /// Copy bytes from `from` to `to` until either end closes or fails.
    async fn pump<A: RelayEnd, B: RelayEnd>(from: &A, to: &B) {
        let mut buf = vec![0_u8; RELAY_BUFFER_BYTES];
        loop {
            if from.ready_to_read().await.is_err() {
                return;
            }
            let filled = match from.read_now(&mut buf) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) if not_ready(&e) => continue,
                Err(_) => return,
            };
            let mut pending = buf.get(..filled).unwrap_or_default();
            while !pending.is_empty() {
                if to.ready_to_write().await.is_err() {
                    return;
                }
                match to.write_now(pending) {
                    Ok(0) => return,
                    Ok(n) => pending = pending.get(n..).unwrap_or_default(),
                    Err(e) if not_ready(&e) => {}
                    Err(_) => return,
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            PinnedRelay, RELAY_DIR_ATTEMPTS, RelayUnavailable, SOCKET_PATH_MAX_BYTES, Semaphore,
            VettedAddr, create_private_dir_in, owner_only, relay_ceiling,
        };
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// Bytes written to the relay socket reach the pinned address and its
        /// answer comes back.
        #[tokio::test]
        async fn relay_carries_bytes_both_ways_to_the_pinned_address() {
            let server = tokio::net::TcpListener::bind("127.0.0.1:0").await;
            assert!(server.is_ok(), "{:?}", server.as_ref().err());
            let Ok(server) = server else { return };
            let Ok(target) = server.local_addr() else {
                return;
            };
            let echo = tokio::spawn(async move {
                let Ok((mut conn, _)) = server.accept().await else {
                    return;
                };
                let mut got = [0_u8; 5];
                if conn.read_exact(&mut got).await.is_ok() {
                    let _echoed = conn.write_all(&got).await;
                }
            });
            let relay = PinnedRelay::open(VettedAddr::assume_vetted_for_test(target), 5432, 4);
            assert!(relay.is_ok(), "{:?}", relay.as_ref().err());
            let Ok(relay) = relay else { return };
            let socket = relay.socket_dir().join(".s.PGSQL.5432");
            let client = tokio::net::UnixStream::connect(&socket).await;
            assert!(client.is_ok(), "{:?}", client.as_ref().err());
            let Ok(mut client) = client else { return };
            assert!(client.write_all(b"hello").await.is_ok());
            let mut back = [0_u8; 5];
            assert!(client.read_exact(&mut back).await.is_ok());
            assert_eq!(&back, b"hello");
            let _served = echo.await;
        }

        /// The relay socket lives in a directory only its owner can enter, on a
        /// path every `sockaddr_un` holds, and both are gone once it drops.
        #[tokio::test]
        async fn relay_socket_is_private_and_removed_on_drop() {
            let target = unroutable();
            let relay = PinnedRelay::open(target, 5432, 4);
            assert!(relay.is_ok(), "{:?}", relay.as_ref().err());
            let Ok(relay) = relay else { return };
            let dir = relay.socket_dir().to_path_buf();
            let mode = std::fs::metadata(&dir).map(|m| m.permissions().mode() & 0o777);
            assert!(matches!(mode, Ok(0o700)), "{mode:?}");
            let socket = dir.join(".s.PGSQL.5432");
            assert!(socket.as_os_str().len() <= SOCKET_PATH_MAX_BYTES);
            assert!(socket.exists());
            assert_eq!(relay.target(), target);
            drop(relay);
            for _ in 0..100 {
                if !dir.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(!dir.exists(), "{dir:?} must be removed");
        }

        /// A runtime that shuts down under a live relay drops its accept loop,
        /// and the socket directory goes with it.
        #[test]
        fn relay_socket_is_removed_when_the_runtime_shuts_down() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            assert!(runtime.is_ok(), "{:?}", runtime.as_ref().err());
            let Ok(runtime) = runtime else { return };
            let relay = runtime.block_on(async { PinnedRelay::open(unroutable(), 5432, 4) });
            assert!(relay.is_ok(), "{:?}", relay.as_ref().err());
            let Ok(relay) = relay else { return };
            let dir = relay.socket_dir().to_path_buf();
            assert!(dir.exists());
            drop(runtime);
            assert!(!dir.exists(), "{dir:?} must be removed with the runtime");
            drop(relay);
        }

        /// The relay admits exactly as many connections as the pool may open,
        /// and at least one.
        #[test]
        fn relay_ceiling_follows_the_pool_ceiling() {
            assert_eq!(relay_ceiling(0), 1);
            assert_eq!(relay_ceiling(1), 1);
            assert_eq!(relay_ceiling(16), 16);
            assert_eq!(relay_ceiling(300), 300);
            let widest = usize::try_from(u32::MAX).map_or(Semaphore::MAX_PERMITS, |max| {
                max.min(Semaphore::MAX_PERMITS)
            });
            assert_eq!(relay_ceiling(u32::MAX), widest);
        }

        /// A directory another user may enter is refused and removed.
        #[test]
        fn owner_only_refuses_group_or_other_access() {
            let base = Scratch::new("owner-only");
            for mode in [0o750, 0o705, 0o770, 0o777] {
                let dir = base.path().join(format!("m{mode:o}"));
                assert!(std::fs::create_dir(&dir).is_ok());
                let set = std::fs::set_permissions(&dir, Permissions::from_mode(mode));
                assert!(set.is_ok(), "{set:?}");
                assert_eq!(owner_only(&dir), Err(RelayUnavailable), "{mode:o}");
                assert!(
                    !dir.exists(),
                    "{mode:o}: the refused directory must be removed"
                );
            }
            let private = base.path().join("private");
            assert!(std::fs::create_dir(&private).is_ok());
            let set = std::fs::set_permissions(&private, Permissions::from_mode(0o700));
            assert!(set.is_ok(), "{set:?}");
            assert!(owner_only(&private).is_ok());
        }

        /// A symlink in place of the directory is refused, never followed.
        #[test]
        fn owner_only_refuses_a_symlink() {
            let base = Scratch::new("symlink");
            let real = base.path().join("real");
            assert!(std::fs::create_dir(&real).is_ok());
            let set = std::fs::set_permissions(&real, Permissions::from_mode(0o700));
            assert!(set.is_ok(), "{set:?}");
            let link = base.path().join("link");
            assert!(std::os::unix::fs::symlink(&real, &link).is_ok());
            assert_eq!(owner_only(&link), Err(RelayUnavailable));
            assert!(real.exists(), "the link target must be left alone");
        }

        /// A name already taken is skipped for the next number.
        #[test]
        fn a_taken_name_moves_on_to_the_next_number() {
            let base = Scratch::new("taken");
            let taken = base.path().join(relay_dir_name(0));
            assert!(std::fs::create_dir(&taken).is_ok());
            let mut numbers = 0_u64..;
            let made = create_private_dir_in(&[base.path().to_path_buf()], ".s.PGSQL.5432", || {
                numbers.next().unwrap_or(u64::MAX)
            });
            let Ok((dir, _owner)) = made else {
                assert!(made.is_ok(), "{made:?}");
                return;
            };
            assert_eq!(dir, base.path().join(relay_dir_name(1)));
        }

        /// A base whose socket path would overflow a `sockaddr_un` is passed
        /// over for the next base, and alone it is refused, creating nothing.
        #[test]
        fn a_base_too_long_for_the_socket_path_is_passed_over() {
            let base = Scratch::new("long");
            let long = base.path().join("d".repeat(SOCKET_PATH_MAX_BYTES));
            let short = base.path().to_path_buf();
            let alone = create_private_dir_in(std::slice::from_ref(&long), ".s.PGSQL.5432", || 0);
            assert_eq!(alone, Err(RelayUnavailable));
            assert!(!long.exists());
            let made = create_private_dir_in(&[long.clone(), short.clone()], ".s.PGSQL.5432", || 0);
            let Ok((dir, _owner)) = made else {
                assert!(made.is_ok(), "{made:?}");
                return;
            };
            assert_eq!(dir, short.join(relay_dir_name(0)));
            assert!(!long.exists());
        }

        /// Every name taken in every base, or a base that cannot hold the
        /// directory, leaves the relay unavailable.
        #[test]
        fn exhausted_names_leave_the_relay_unavailable() {
            let base = Scratch::new("exhausted");
            for n in 0..u64::from(RELAY_DIR_ATTEMPTS) {
                assert!(std::fs::create_dir(base.path().join(relay_dir_name(n))).is_ok());
            }
            let mut numbers = 0_u64..;
            let made = create_private_dir_in(&[base.path().to_path_buf()], ".s.PGSQL.5432", || {
                numbers.next().unwrap_or(u64::MAX)
            });
            assert_eq!(made, Err(RelayUnavailable));
            let missing = base.path().join("missing");
            let made = create_private_dir_in(&[missing], ".s.PGSQL.5432", || 0);
            assert_eq!(made, Err(RelayUnavailable));
        }

        /// An address no test server answers on.
        fn unroutable() -> VettedAddr {
            VettedAddr::assume_vetted_for_test(std::net::SocketAddr::from(([127, 0, 0, 1], 9)))
        }

        /// The relay directory name numbered `n` for this process.
        fn relay_dir_name(n: u64) -> String {
            format!("ipe-pg-relay-{}-{n}", std::process::id())
        }

        /// A test's own directory under `/tmp`, removed when dropped.
        struct Scratch(PathBuf);

        impl Scratch {
            fn new(label: &str) -> Self {
                let dir = PathBuf::from("/tmp")
                    .join(format!("ipe-relay-test-{}-{label}", std::process::id()));
                let _stale = std::fs::remove_dir_all(&dir);
                assert!(std::fs::create_dir(&dir).is_ok(), "{dir:?}");
                Self(dir)
            }

            fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Scratch {
            fn drop(&mut self) {
                let _removed = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}

/// A relay stands in for no platform without Unix sockets; a TLS dial there
/// that needs one is refused instead.
#[cfg(all(feature = "db", not(unix)))]
#[derive(Debug)]
pub(crate) enum PinnedRelay {}

#[cfg(all(feature = "db", not(unix)))]
impl PinnedRelay {
    /// Keep the relay running until `closed` completes.
    pub(crate) fn hold_until<F>(self, _closed: F) {
        match self {}
    }
}

/// Stub resolvers for tests of every SSRF-gated surface — no network.
#[cfg(test)]
pub(crate) mod test_resolvers {
    use super::HostResolver;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A resolver that must never be consulted: every lookup fails.
    pub struct NoDns;

    impl HostResolver for NoDns {
        async fn lookup(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    /// A rebinding resolver: the first lookup answers a public address, every
    /// later lookup answers a private one.
    #[derive(Default)]
    pub struct PublicThenPrivate {
        /// Lookups answered so far.
        pub calls: AtomicUsize,
    }

    impl PublicThenPrivate {
        /// The first answer.
        pub const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        /// Every later answer.
        pub const PRIVATE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

        /// A resolver that has answered nothing yet.
        pub const fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }

        /// Lookups answered so far.
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl HostResolver for PublicThenPrivate {
        async fn lookup(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            let ip = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Self::PUBLIC
            } else {
                Self::PRIVATE
            };
            Ok(vec![SocketAddr::new(ip, port)])
        }
    }

    /// A resolver that answers a fixed address list.
    pub struct Answers(pub Vec<IpAddr>);

    impl HostResolver for Answers {
        async fn lookup(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Ok(self.0.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
        }
    }

    /// A resolver that never answers.
    pub struct Stalls;

    impl HostResolver for Stalls {
        async fn lookup(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            std::future::pending().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_resolvers::{Answers, NoDns, PublicThenPrivate, Stalls};
    use super::*;

    /// `host` as a configuration field names it.
    fn configured(host: &str) -> ConfiguredHost {
        ConfiguredHost::from_config(host.to_owned())
    }

    /// A URL whose userinfo may run past its authority is never an
    /// `UnambiguousUrl`, so no host read from it becomes a `ConfiguredHost`.
    #[test]
    fn unambiguous_url_refuses_every_spilled_userinfo() {
        for url in [
            "postgres://admin:8/s3cr3t?pw@db.example/app",
            "postgres://admin:8/s3cr3t#pw@db.example/app",
            "postgres://admin:8/s3cr3t-pw@db.example/app",
            "http://admin\\s3cr3t@db.example/",
            "not a url with admin@s3cr3t",
        ] {
            assert!(
                matches!(
                    UnambiguousUrl::parse(url),
                    Err(UrlUnproven::AmbiguousUserinfo)
                ),
                "{url:?}"
            );
        }
        assert!(matches!(
            UnambiguousUrl::parse("not a url"),
            Err(UrlUnproven::Invalid)
        ));
        let host = UnambiguousUrl::parse("postgres://admin:s3cr3t@db.example/app")
            .ok()
            .and_then(|url| url.host());
        assert_eq!(host, Some(configured("db.example")));
    }

    /// `query_host` names only the value of a `host` or `hostaddr` parameter;
    /// `named_host` also names the authority host.
    #[test]
    fn named_host_reads_the_authority_and_host_parameters_only() {
        let url = UnambiguousUrl::parse(
            "postgres://db.example/app?host=other.example&hostaddr=10.0.0.5&evil=evil&x=db.example",
        );
        assert!(url.is_ok());
        let Ok(url) = url else {
            return;
        };
        assert_eq!(url.query_host("evil"), None);
        assert_eq!(url.query_host("db.example"), None);
        assert_eq!(
            url.query_host("other.example"),
            Some(configured("other.example"))
        );
        assert_eq!(url.query_host("10.0.0.5"), Some(configured("10.0.0.5")));
        assert_eq!(url.named_host("db.example"), Some(configured("db.example")));
        assert_eq!(
            url.named_host("other.example"),
            Some(configured("other.example"))
        );
        assert_eq!(url.named_host("10.0.0.5"), Some(configured("10.0.0.5")));
        assert_eq!(url.named_host("evil"), None);
        assert_eq!(url.named_host("app"), None);
        let bare = UnambiguousUrl::parse("postgres://db.example/app");
        assert!(bare.is_ok_and(|bare| bare.query_host("evil").is_none()));
    }

    const DEADLINE: Duration = Duration::from_secs(5);

    /// The URL gate's deny-private verdict, rendered as the `http:` surface shows it.
    async fn ssrf_check_url(url: &str) -> Result<VettedDial, String> {
        vet_url_with(DialPolicy::DenyPrivate, &NoDns, url, DEADLINE)
            .await
            .map_err(|refusal| format!("http: {refusal}"))
    }

    /// The redirect-hop guard's verdict, rendered as the `http:` surface shows it.
    fn nonblocking_hop(url: &str) -> Result<(), String> {
        ssrf_check_url_nonblocking(url).map_err(|refusal| format!("http: {refusal}"))
    }

    // -----------------------------------------------------------------------
    // vet_url_with — the WebSocket client's single gate
    // -----------------------------------------------------------------------

    /// DNS rebinding through the URL gate: the dial is pinned to the first
    /// answer with the URL's port, and a fresh vet meets the rebound answer
    /// and is refused, so the private address is never handed to a dialler.
    #[tokio::test]
    async fn vet_url_pins_the_first_answer_against_rebinding() {
        let resolver = PublicThenPrivate::new();
        let url = "ws://rebind.example:9000/socket";
        let first = vet_url_with(DialPolicy::DenyPrivate, &resolver, url, DEADLINE).await;
        assert_eq!(
            first,
            Ok(VettedDial::Pinned(VettedAddr(SocketAddr::new(
                PublicThenPrivate::PUBLIC,
                9000
            ))))
        );
        assert_eq!(resolver.calls(), 1, "the name must be resolved once");
        let second = vet_url_with(DialPolicy::DenyPrivate, &resolver, url, DEADLINE).await;
        assert_eq!(
            second,
            Err(UrlRefusal::Host(SsrfRefusal::Blocked {
                host: BlockedHost::Named {
                    host: "rebind.example".to_owned(),
                    ip: PublicThenPrivate::PRIVATE,
                },
                range: BlockedRange::Private,
            }))
        );
    }

    /// A mixed public and private answer refuses the whole URL.
    #[tokio::test]
    async fn vet_url_refuses_a_mixed_answer() {
        let mixed = Answers(vec![
            PublicThenPrivate::PUBLIC,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        ]);
        let refused = vet_url_with(
            DialPolicy::DenyPrivate,
            &mixed,
            "wss://mixed.example/",
            DEADLINE,
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(UrlRefusal::Host(SsrfRefusal::Blocked {
                    range: BlockedRange::Loopback,
                    ..
                }))
            ),
            "{refused:?}"
        );
    }

    /// A stalled resolver is cut off with a typed timeout.
    #[tokio::test]
    async fn vet_url_times_out_a_stalled_resolver() {
        let deadline = Duration::from_millis(20);
        let refused = vet_url_with(
            DialPolicy::DenyPrivate,
            &Stalls,
            "ws://slow.example/",
            deadline,
        )
        .await;
        assert_eq!(
            refused,
            Err(UrlRefusal::Host(SsrfRefusal::Timeout {
                host: HostShown::Named("slow.example".to_owned()),
                after: deadline,
            }))
        );
    }

    /// Each malformed URL is refused with its own typed reason.
    #[tokio::test]
    async fn vet_url_refuses_each_malformed_url() {
        let scheme = vet_url_with(
            DialPolicy::DenyPrivate,
            &NoDns,
            "ftp://x.example/",
            DEADLINE,
        )
        .await;
        assert_eq!(
            scheme,
            Err(UrlRefusal::Scheme {
                scheme: SchemeShown::Known("ftp"),
                admitted: GatedSchemes::HttpAndWebSocket,
            })
        );
        let invalid = vet_url_with(DialPolicy::DenyPrivate, &NoDns, "not a url", DEADLINE).await;
        assert!(
            matches!(invalid, Err(UrlRefusal::Invalid { .. })),
            "{invalid:?}"
        );
    }

    /// An unparseable URL's refusal never carries its userinfo.
    #[tokio::test]
    async fn vet_url_invalid_refusal_redacts_userinfo() {
        let url = "http://admin:s3cr3t-pw@exa mple.com/";
        let refused = vet_url_with(DialPolicy::DenyPrivate, &NoDns, url, DEADLINE).await;
        assert!(
            matches!(refused, Err(UrlRefusal::Invalid { .. })),
            "{refused:?}"
        );
        let shown = format!(
            "{refused:?} {}",
            refused
                .as_ref()
                .map_or_else(ToString::to_string, |_| String::new())
        );
        assert!(!shown.contains("s3cr3t-pw"), "password leaked: {shown}");
        assert!(!shown.contains("admin"), "user leaked: {shown}");
    }

    /// With the policy off, the URL is dialled as given and no lookup runs.
    #[tokio::test]
    async fn vet_url_is_unrestricted_when_the_policy_allows_all() {
        let resolver = PublicThenPrivate::new();
        for url in ["ws://127.0.0.1/", "ws://internal.example/", "not a url"] {
            let vetted = vet_url_with(DialPolicy::AllowAll, &resolver, url, DEADLINE).await;
            assert_eq!(vetted, Ok(VettedDial::Unrestricted), "{url:?}");
        }
        assert_eq!(resolver.calls(), 0);
    }

    /// Every vetted address comes back, each carrying the caller's port.
    #[tokio::test]
    async fn vet_host_addrs_returns_every_public_answer() {
        let second = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let vetted = vet_host_addrs_with(
            &Answers(vec![PublicThenPrivate::PUBLIC, second]),
            "multi.example",
            HostDisclosure::Named,
            443,
            DEADLINE,
        )
        .await
        .map(VettedAddrs::into_vec);
        assert_eq!(
            vetted,
            Ok(vec![
                SocketAddr::new(PublicThenPrivate::PUBLIC, 443),
                SocketAddr::new(second, 443)
            ])
        );
    }

    // -----------------------------------------------------------------------
    // VettedDial
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn vetted_dial_refuses_every_blocked_literal_under_deny_private() {
        for (host, range) in [
            ("127.0.0.1", BlockedRange::Loopback),
            ("::1", BlockedRange::Loopback),
            ("169.254.169.254", BlockedRange::LinkLocal),
            ("10.0.0.5", BlockedRange::Private),
            ("0.0.0.0", BlockedRange::Reserved),
        ] {
            let refused = VettedDial::for_configured_host_with(
                DialPolicy::DenyPrivate,
                &NoDns,
                &configured(host),
                5432,
            )
            .await;
            assert!(
                matches!(refused, Err(SsrfRefusal::Blocked { range: r, .. }) if r == range),
                "{host:?} must be refused as {range}: {refused:?}"
            );
        }
    }

    #[tokio::test]
    async fn vetted_dial_pins_a_public_literal_with_its_port() {
        let vetted = VettedDial::for_configured_host_with(
            DialPolicy::DenyPrivate,
            &NoDns,
            &configured("1.1.1.1"),
            5432,
        )
        .await;
        assert_eq!(
            vetted,
            Ok(VettedDial::Pinned(VettedAddr(SocketAddr::new(
                PublicThenPrivate::PUBLIC,
                5432
            ))))
        );
    }

    #[tokio::test]
    async fn vetted_dial_is_unrestricted_when_the_policy_allows_all() {
        for host in ["127.0.0.1", "10.0.0.1", "internal.example"] {
            let vetted = VettedDial::for_configured_host_with(
                DialPolicy::AllowAll,
                &NoDns,
                &configured(host),
                5432,
            )
            .await;
            assert_eq!(vetted, Ok(VettedDial::Unrestricted), "{host:?}");
            assert_eq!(VettedDial::Unrestricted.dial_host(host), host);
        }
    }

    /// DNS rebinding: the name is resolved once and the dial is pinned to that
    /// answer, so a later answer pointing at a private host is never dialled.
    /// A fresh vet (a new dial) sees the rebound answer and is refused.
    #[tokio::test]
    async fn vetted_dial_pins_the_first_answer_against_rebinding() {
        let resolver = PublicThenPrivate::new();
        let first = VettedDial::for_configured_host_with(
            DialPolicy::DenyPrivate,
            &resolver,
            &configured("rebind.example"),
            5432,
        )
        .await;
        assert_eq!(
            first,
            Ok(VettedDial::Pinned(VettedAddr(SocketAddr::new(
                PublicThenPrivate::PUBLIC,
                5432
            ))))
        );
        assert_eq!(
            first.map(|dial| dial.dial_host("rebind.example")),
            Ok(PublicThenPrivate::PUBLIC.to_string()),
            "the dialler must receive the vetted address, never the name"
        );
        assert_eq!(resolver.calls(), 1);

        let second = VettedDial::for_configured_host_with(
            DialPolicy::DenyPrivate,
            &resolver,
            &configured("rebind.example"),
            5432,
        )
        .await;
        assert_eq!(
            second,
            Err(SsrfRefusal::Blocked {
                host: BlockedHost::Named {
                    host: "rebind.example".to_owned(),
                    ip: PublicThenPrivate::PRIVATE,
                },
                range: BlockedRange::Private,
            })
        );
    }

    /// A multi-record answer mixing public and private addresses is refused
    /// whole rather than trusting whichever one a dialler would pick.
    #[tokio::test]
    async fn vet_host_refuses_a_mixed_public_private_answer() {
        let mixed = Answers(vec![
            PublicThenPrivate::PUBLIC,
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        ]);
        let refused = vet_host_with(
            &mixed,
            "mixed.example",
            HostDisclosure::Named,
            443,
            DEADLINE,
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(SsrfRefusal::Blocked {
                    range: BlockedRange::LinkLocal,
                    ..
                })
            ),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn vet_host_refuses_an_empty_answer() {
        let refused = vet_host_with(
            &Answers(Vec::new()),
            "empty.example",
            HostDisclosure::Named,
            443,
            DEADLINE,
        )
        .await;
        assert_eq!(
            refused,
            Err(SsrfRefusal::NoAddresses {
                host: HostShown::Named("empty.example".to_owned())
            })
        );
    }

    #[tokio::test]
    async fn vet_host_refuses_an_unresolvable_name() {
        let refused = vet_host_with(
            &NoDns,
            "nowhere.example",
            HostDisclosure::Named,
            443,
            DEADLINE,
        )
        .await;
        assert_eq!(
            refused,
            Err(SsrfRefusal::Unresolvable {
                host: HostShown::Named("nowhere.example".to_owned()),
                kind: std::io::ErrorKind::NotFound,
            })
        );
    }

    /// A resolver that never answers is cut off at the deadline with a typed
    /// refusal instead of holding the task.
    #[tokio::test]
    async fn vet_host_times_out_a_stalled_resolver() {
        let deadline = Duration::from_millis(20);
        let refused = vet_host_with(
            &Stalls,
            "slow.example",
            HostDisclosure::Named,
            443,
            deadline,
        )
        .await;
        assert_eq!(
            refused,
            Err(SsrfRefusal::Timeout {
                host: HostShown::Named("slow.example".to_owned()),
                after: deadline,
            })
        );
    }

    #[tokio::test]
    async fn vet_host_returns_the_first_public_answer_with_the_callers_port() {
        let resolved = vet_host_with(
            &Answers(vec![PublicThenPrivate::PUBLIC]),
            "public.example",
            HostDisclosure::Named,
            8443,
            DEADLINE,
        )
        .await;
        assert_eq!(
            resolved,
            Ok(SocketAddr::new(PublicThenPrivate::PUBLIC, 8443))
        );
    }

    /// Every refusal names what was refused and the policy that refused it,
    /// with no caller prefix of its own.
    #[test]
    fn every_ssrf_refusal_displays_its_reason_without_a_caller_prefix() {
        let cases = [
            (
                SsrfRefusal::Blocked {
                    host: BlockedHost::Named {
                        host: "127.0.0.1".to_owned(),
                        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    },
                    range: BlockedRange::Loopback,
                },
                "loopback host 127.0.0.1",
            ),
            (
                SsrfRefusal::Blocked {
                    host: BlockedHost::Named {
                        host: "meta.example".to_owned(),
                        ip: IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
                    },
                    range: BlockedRange::LinkLocal,
                },
                "resolved to link-local address 169.254.169.254",
            ),
            (
                SsrfRefusal::Unresolvable {
                    host: HostShown::Named("nowhere.example".to_owned()),
                    kind: std::io::ErrorKind::NotFound,
                },
                "could not resolve host \"nowhere.example\"",
            ),
            (
                SsrfRefusal::NoAddresses {
                    host: HostShown::Named("empty.example".to_owned()),
                },
                "resolved to no addresses",
            ),
            (
                SsrfRefusal::Timeout {
                    host: HostShown::Named("slow.example".to_owned()),
                    after: Duration::from_millis(250),
                },
                "timed out after 250 ms",
            ),
            (SsrfRefusal::LocalSocket, "local socket"),
            (SsrfRefusal::UnprovenTarget, "names no host"),
            (
                SsrfRefusal::UnpinnableTlsName {
                    host: configured("db.example"),
                },
                "verify-full",
            ),
        ];
        for (refusal, reason) in cases {
            let shown = refusal.to_string();
            assert!(shown.starts_with("blocked: "), "{shown}");
            assert!(shown.contains(reason), "{shown} must contain {reason:?}");
            assert!(shown.ends_with("(IPE_HTTP_DENY_PRIVATE)"), "{shown}");
            for prefix in ["http:", "db:", "ws:"] {
                assert!(!shown.contains(prefix), "{shown} carries a caller prefix");
            }
        }
    }

    #[test]
    fn blocked_range_classifies_each_class() {
        let class = |ip: &str| blocked_range(ip.parse().unwrap());
        assert_eq!(class("127.0.0.1"), Some(BlockedRange::Loopback));
        assert_eq!(class("::1"), Some(BlockedRange::Loopback));
        assert_eq!(class("::ffff:127.0.0.1"), Some(BlockedRange::Loopback));
        assert_eq!(class("169.254.169.254"), Some(BlockedRange::LinkLocal));
        assert_eq!(class("fe80::1"), Some(BlockedRange::LinkLocal));
        assert_eq!(class("64:ff9b::a9fe:a9fe"), Some(BlockedRange::LinkLocal));
        assert_eq!(class("10.0.0.1"), Some(BlockedRange::Private));
        assert_eq!(class("100.64.0.1"), Some(BlockedRange::Private));
        assert_eq!(class("fd00::1"), Some(BlockedRange::Private));
        assert_eq!(class("2002:c0a8:101::1"), Some(BlockedRange::Private));
        assert_eq!(class("0.0.0.0"), Some(BlockedRange::Reserved));
        assert_eq!(class("::"), Some(BlockedRange::Reserved));
        assert_eq!(class("198.18.0.1"), Some(BlockedRange::Reserved));
        assert_eq!(class("255.255.255.255"), Some(BlockedRange::Reserved));
        assert_eq!(class("1.1.1.1"), None);
        assert_eq!(class("2606:4700:4700::1111"), None);
    }

    // -----------------------------------------------------------------------
    // is_private_ip
    // -----------------------------------------------------------------------

    #[test]
    fn is_private_ip_loopback_v4() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_rfc1918() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("172.31.255.255".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_link_local_v4() {
        assert!(is_private_ip("169.254.0.1".parse().unwrap()));
        assert!(is_private_ip("169.254.169.254".parse().unwrap())); // AWS IMDS
    }

    #[test]
    fn is_private_ip_unspecified_v4() {
        assert!(is_private_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_loopback_v6() {
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_link_local_v6() {
        assert!(is_private_ip("fe80::1".parse().unwrap()));
        assert!(is_private_ip("fe80::dead:beef".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_ula_v6() {
        assert!(is_private_ip("fc00::1".parse().unwrap()));
        assert!(is_private_ip("fd00::1".parse().unwrap()));
        assert!(is_private_ip("fdff:ffff:ffff::1".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_v4mapped_private() {
        // ::ffff:192.168.1.1 — v4-mapped RFC-1918
        assert!(is_private_ip("::ffff:192.168.1.1".parse().unwrap()));
        // ::ffff:127.0.0.1 — v4-mapped loopback
        assert!(is_private_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_this_network_v4() {
        // 0.0.0.0/8 "this host on this network" (RFC 1122) — whole /8, not just 0.0.0.0.
        assert!(is_private_ip("0.0.0.0".parse().unwrap()));
        assert!(is_private_ip("0.0.0.1".parse().unwrap()));
        assert!(is_private_ip("0.255.255.255".parse().unwrap()));
        // Boundary just above the /8 must stay public.
        assert!(!is_private_ip("1.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_private_ip_nat64_embedded_private() {
        // 64:ff9b::/96 embeds the destination IPv4 in the low 32 bits.
        assert!(is_private_ip("64:ff9b::7f00:1".parse().unwrap())); // → 127.0.0.1
        assert!(is_private_ip("64:ff9b::a9fe:a9fe".parse().unwrap())); // → 169.254.169.254 (AWS IMDS)
        assert!(is_private_ip("64:ff9b::c0a8:101".parse().unwrap())); // → 192.168.1.1
        // NAT64 wrapping a public v4 stays public.
        assert!(!is_private_ip("64:ff9b::101:101".parse().unwrap())); // → 1.1.1.1
    }

    #[test]
    fn is_private_ip_6to4_embedded_private() {
        // 2002::/16 embeds the IPv4 in segments 1..=2 (2002:V4HI:V4LO::).
        assert!(is_private_ip("2002:7f00:1::1".parse().unwrap())); // → 127.0.0.1
        assert!(is_private_ip("2002:a9fe:a9fe::1".parse().unwrap())); // → 169.254.169.254
        assert!(is_private_ip("2002:c0a8:101::1".parse().unwrap())); // → 192.168.1.1
        // 6to4 wrapping a public v4 stays public.
        assert!(!is_private_ip("2002:101:101::1".parse().unwrap())); // → 1.1.1.1
    }

    #[test]
    fn is_private_ip_public_is_allowed() {
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("2606:4700:4700::1111".parse().unwrap())); // Cloudflare v6
    }

    #[test]
    fn is_private_ip_extra_reserved_ranges_blocked() {
        // audit L1: non-RFC-1918 ranges that std's is_private misses.
        assert!(is_private_ip("100.64.0.1".parse().unwrap())); // CGNAT lo
        assert!(is_private_ip("100.127.255.255".parse().unwrap())); // CGNAT hi
        assert!(is_private_ip("192.0.0.192".parse().unwrap())); // IETF protocol
        assert!(is_private_ip("198.18.0.1".parse().unwrap())); // benchmarking lo
        assert!(is_private_ip("198.19.255.255".parse().unwrap())); // benchmarking hi
        assert!(is_private_ip("240.0.0.1".parse().unwrap())); // reserved
        assert!(is_private_ip("255.255.255.255".parse().unwrap())); // broadcast
        // Boundaries that must STAY public (no over-block):
        assert!(!is_private_ip("100.63.255.255".parse().unwrap())); // just below CGNAT
        assert!(!is_private_ip("100.128.0.0".parse().unwrap())); // just above CGNAT
        assert!(!is_private_ip("192.0.1.1".parse().unwrap())); // 192.0.1/24 is public
        assert!(!is_private_ip("198.20.0.0".parse().unwrap())); // just above benchmarking
        assert!(!is_private_ip("239.255.255.255".parse().unwrap())); // just below reserved (multicast, routable-ish)
    }

    #[tokio::test]
    async fn ssrf_check_url_rejects_non_http_scheme() {
        let err = ssrf_check_url("ftp://example.com/file").await.unwrap_err();
        assert!(
            err.contains("scheme"),
            "expected scheme rejection, got: {err}"
        );
        let err2 = ssrf_check_url("file:///etc/passwd").await.unwrap_err();
        assert!(
            err2.contains("scheme") || err2.contains("invalid"),
            "got: {err2}"
        );
    }

    #[tokio::test]
    async fn ssrf_check_url_rejects_private_ip_literal() {
        let err = ssrf_check_url("http://192.168.1.1/secret")
            .await
            .unwrap_err();
        assert!(
            err.starts_with("http: blocked"),
            "expected blocked, got: {err}"
        );
    }

    #[tokio::test]
    async fn ssrf_check_url_rejects_loopback_ip_literal() {
        let err = ssrf_check_url("http://127.0.0.1:8080/admin")
            .await
            .unwrap_err();
        assert!(err.contains("blocked"), "expected blocked, got: {err}");
    }

    #[tokio::test]
    async fn ssrf_check_url_rejects_aws_imds() {
        let err = ssrf_check_url("http://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(err.contains("blocked"), "expected blocked, got: {err}");
    }

    #[tokio::test]
    async fn ssrf_check_url_rejects_invalid_url() {
        let err = ssrf_check_url("not a url at all").await.unwrap_err();
        assert!(!err.is_empty());
    }

    /// Every internal redirect-hop target is refused by the URL gate.
    #[tokio::test]
    async fn redirect_hop_revalidation_blocks_internal_targets() {
        for hop in [
            "http://127.0.0.1/admin",             // loopback
            "http://10.0.0.5/internal",           // RFC-1918 private
            "http://169.254.169.254/latest/meta", // AWS IMDS link-local
            "http://[::1]/",                      // v6 loopback
            "http://192.168.1.1/",                // RFC-1918 private
        ] {
            let err = ssrf_check_url(hop)
                .await
                .expect_err("a redirect hop to an internal address must be blocked");
            assert!(err.contains("blocked"), "hop {hop:?} → got: {err}");
        }
        // A redirect hop with a non-http(s) scheme is blocked at the same floor.
        let err = ssrf_check_url("ftp://example.com/x")
            .await
            .expect_err("a non-http(s) redirect hop must be blocked");
        assert!(err.contains("scheme"), "got: {err}");
    }

    #[tokio::test]
    async fn ssrf_check_url_allows_public_ip() {
        // 1.1.1.1 is public — should pass (no DNS needed for IP literals)
        assert!(ssrf_check_url("https://1.1.1.1/").await.is_ok());
    }

    // -----------------------------------------------------------------------
    // vet_host_with — IP literals are decided without the resolver
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn vet_host_returns_socket_addr_for_public_ip_literal() {
        let sa = vet_host_with(&NoDns, "1.1.1.1", HostDisclosure::Named, 0, DEADLINE)
            .await
            .unwrap();
        assert_eq!(sa, SocketAddr::new(PublicThenPrivate::PUBLIC, 0));
    }

    #[tokio::test]
    async fn vet_host_rejects_blocked_ip_literals() {
        for host in ["192.168.1.1", "127.0.0.1", "::ffff:127.0.0.1"] {
            let refused = vet_host_with(&NoDns, host, HostDisclosure::Named, 0, DEADLINE).await;
            assert!(
                matches!(refused, Err(SsrfRefusal::Blocked { .. })),
                "{host:?}: {refused:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Bracketed IPv6-literal hosts (as returned by `Url::host_str()`) must be
    // decided by `blocked_range`, never reach the resolver: `NoDns` would turn
    // a resolver fallthrough into `Unresolvable`, not `Blocked`.
    // -----------------------------------------------------------------------

    async fn assert_blocked_by_range(host: &str) {
        let refused = vet_host_with(&NoDns, host, HostDisclosure::Named, 0, DEADLINE).await;
        assert!(
            matches!(refused, Err(SsrfRefusal::Blocked { .. })),
            "host {host:?} must be blocked by blocked_range (literal path), got: {refused:?}"
        );
    }

    #[test]
    fn strip_ipv6_brackets_unwraps_only_a_matched_pair() {
        assert_eq!(strip_ipv6_brackets("[::1]"), "::1");
        assert_eq!(strip_ipv6_brackets("[fd00::1]"), "fd00::1");
        // No brackets / bare v4 / hostname pass through untouched.
        assert_eq!(strip_ipv6_brackets("::1"), "::1");
        assert_eq!(strip_ipv6_brackets("127.0.0.1"), "127.0.0.1");
        assert_eq!(strip_ipv6_brackets("example.com"), "example.com");
        // A lone bracket is not a pair — left as-is (still fails IpAddr::parse).
        assert_eq!(strip_ipv6_brackets("[::1"), "[::1");
        assert_eq!(strip_ipv6_brackets("::1]"), "::1]");
    }

    #[tokio::test]
    async fn vet_host_blocks_bracketed_private_v6_literals() {
        for host in [
            "[::1]",
            "[fd00::1]",
            "[fe80::1]",
            "[::ffff:127.0.0.1]",
            // 64:ff9b::7f00:1 → 127.0.0.1 (NAT64-wrapped loopback).
            "[64:ff9b::7f00:1]",
        ] {
            assert_blocked_by_range(host).await;
        }
    }

    #[tokio::test]
    async fn vet_host_allows_bracketed_public_v6() {
        // Cloudflare public v6, bracketed as a URL host would present it.
        let sa = vet_host_with(
            &NoDns,
            "[2606:4700:4700::1111]",
            HostDisclosure::Named,
            0,
            DEADLINE,
        )
        .await
        .expect("public bracketed v6 literal must be allowed");
        assert_eq!(
            sa.ip(),
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            "the vetted addr must be the unbracketed parsed literal"
        );
    }

    #[tokio::test]
    async fn ssrf_check_url_blocks_bracketed_v6_loopback_and_ula() {
        // The URL entrypoint (host_str returns the bracketed form) must block.
        for url in [
            "http://[::1]/admin",
            "http://[fd00::1]/x",
            "https://[fe80::1]/",
        ] {
            let err = ssrf_check_url(url)
                .await
                .expect_err("bracketed private v6 URL must be blocked");
            assert!(err.contains("blocked"), "url {url:?} → got: {err}");
        }
    }

    #[tokio::test]
    async fn ssrf_check_url_allows_bracketed_public_v6() {
        assert!(
            ssrf_check_url("https://[2606:4700:4700::1111]/")
                .await
                .is_ok()
        );
    }

    // -----------------------------------------------------------------------
    // #2536 item 1 — the non-blocking redirect-hop guard. It decides IP
    // literals (incl. bracketed v6) purely and defers named hosts to the
    // connect-time resolver (so a hostname is NOT rejected here for lack of DNS).
    // -----------------------------------------------------------------------

    #[test]
    fn nonblocking_check_blocks_private_ip_literals() {
        for url in [
            "http://127.0.0.1/admin",
            "http://10.0.0.5/x",
            "http://169.254.169.254/latest/meta",
            "http://[::1]/",
            "http://[fd00::1]/",
            "http://[64:ff9b::7f00:1]/", // NAT64 → 127.0.0.1
        ] {
            let err = nonblocking_hop(url)
                .expect_err("private IP-literal hop must be blocked without DNS");
            assert!(err.contains("blocked"), "url {url:?} → got: {err}");
        }
    }

    #[test]
    fn nonblocking_check_rejects_non_http_scheme() {
        let err = nonblocking_hop("ftp://example.com/x").unwrap_err();
        assert!(err.contains("scheme"), "got: {err}");
    }

    #[test]
    fn nonblocking_check_allows_public_ip_and_defers_hostnames() {
        // Public IP literal: allowed. Hostname: deferred (no DNS here) → Ok.
        assert!(nonblocking_hop("https://1.1.1.1/").is_ok());
        assert!(nonblocking_hop("https://[2606:4700:4700::1111]/").is_ok());
        assert!(nonblocking_hop("https://example.com/path").is_ok());
    }

    // -----------------------------------------------------------------------
    // Parse-parity: prove `url::Url::parse` (used here) extracts the same
    // scheme/host/port as `reqwest::Url::parse` (the pre-refactor parser) for
    // the SSRF-relevant cases. reqwest::Url IS url::Url (pub use), so these are
    // a belt-and-braces regression against an accidental parser divergence.
    // Only compiled when reqwest is linked (http_client/email/live builds).
    #[cfg(feature = "http_client")]
    #[test]
    fn url_parse_parity_with_reqwest_for_ssrf_extractions() {
        let cases = [
            "http://user:pass@example.com:8080/path?q=1",
            "https://xn--n3h.example/", // punycode/IDN host
            "http://0x7f.0.0.1/",       // hex-ish IPv4-looking host
            "http://0177.0.0.1/",       // octal-ish IPv4-looking host
            "http://[::ffff:127.0.0.1]/",
            "wss://[::1]:8443/socket",
            "ws://example.com./",   // trailing-dot host
            "https://例え.テスト/", // raw IDN
            "http://127.0.0.1:8080/admin",
            "https://1.1.1.1/",
        ];
        for c in cases {
            let a = reqwest::Url::parse(c);
            let b = Url::parse(c);
            assert_eq!(a.is_ok(), b.is_ok(), "parse-ok divergence for {c:?}");
            if let (Ok(ua), Ok(ub)) = (a, b) {
                assert_eq!(ua.scheme(), ub.scheme(), "scheme divergence for {c:?}");
                assert_eq!(ua.host_str(), ub.host_str(), "host divergence for {c:?}");
                assert_eq!(
                    ua.port_or_known_default(),
                    ub.port_or_known_default(),
                    "port divergence for {c:?}"
                );
            }
        }
    }

    /// URLs whose credentials an error message must never show, each with the
    /// secret substrings it holds: userinfo the parser reads, userinfo cut
    /// short by a `/`, `?`, `#`, or `\`, and a user name parsed as the scheme.
    const CREDENTIAL_URLS: [(&str, &[&str]); 14] = [
        (
            "ws://alice:s3cr3t@example.com:9000/feed",
            &["alice", "s3cr3t"],
        ),
        ("http://admin\\s3cr3t@public.example/", &["admin", "s3cr3t"]),
        ("ftp://admin\\s3cr3t@public.example/", &["admin", "s3cr3t"]),
        ("admin:s3cr3t@host", &["admin", "s3cr3t"]),
        ("admin:s3cr3t@host/x", &["admin", "s3cr3t"]),
        ("apikey123:x@api.example", &["apikey123"]),
        ("ws://admin:5432/s3cr3t@db.example", &["admin", "s3cr3t"]),
        ("http://admin@s3cr3t/-pw@host/x", &["admin", "s3cr3t"]),
        ("https://admin:s3cr3t?pw@host", &["admin", "s3cr3t"]),
        ("wss://admin#s3cr3t@host", &["admin", "s3cr3t"]),
        ("ws://bob:s3cr3t@@@host/a@b", &["bob", "s3cr3t"]),
        ("admin/s3cr3t@host", &["admin", "s3cr3t"]),
        ("http://admin:s3cr3t@[bad/x", &["admin", "s3cr3t"]),
        ("http://127.0.0.1/admin@s3cr3t", &["admin", "s3cr3t"]),
    ];

    /// Asserts neither `Display` nor `Debug` of `value` holds any of `secrets`.
    fn assert_shows_none_of<T: std::fmt::Display + std::fmt::Debug>(value: &T, secrets: &[&str]) {
        for shown in [value.to_string(), format!("{value:?}")] {
            for secret in secrets {
                assert!(!shown.contains(secret), "{secret:?} leaked into {shown}");
            }
        }
    }

    /// No rendering of a displayable URL holds its credentials.
    #[test]
    fn displayable_url_never_shows_credentials() {
        for (url, secrets) in CREDENTIAL_URLS {
            assert_shows_none_of(&DisplayableUrl::of(url), secrets);
        }
    }

    /// A URL whose userinfo the parser reads unambiguously shows only its
    /// scheme, host, and explicit port: the userinfo, path, query, and
    /// fragment, where tokens travel, are never shown.
    #[test]
    fn displayable_url_shows_only_scheme_host_and_port() {
        for (url, shown, secrets) in [
            (
                "ws://alice:s3cr3t@example.com:9000/feed?token=abc",
                "ws://example.com:9000",
                &["alice", "s3cr3t", "feed", "token", "abc"][..],
            ),
            ("wss://admin@host/x", "wss://host", &["admin", "/x"][..]),
            ("ws://example.com/feed", "ws://example.com", &["feed"][..]),
            ("http://u:p@@@host", "http://host", &["u:p", "@"][..]),
            (
                "wss://api.example/ws/s3ss10n#fr4gment",
                "wss://api.example",
                &["s3ss10n", "fr4gment"][..],
            ),
            (
                "http://[::1]:8080/a?access_token=t0k3n",
                "http://[::1]:8080",
                &["access_token", "t0k3n"][..],
            ),
            (
                "https://api.example:443/v1?key=k3y",
                "https://api.example",
                &["v1", "key", "k3y"][..],
            ),
        ] {
            let displayable = DisplayableUrl::of(url);
            assert_eq!(displayable.to_string(), shown, "{url:?}");
            assert!(displayable.shows_host(), "{url:?}");
            assert_shows_none_of(&displayable, secrets);
        }
    }

    /// A credential cut short by a `/`, `?`, `#`, or `\` leaves an `@` or `\`
    /// the parser did not read as the userinfo's end, so only the scheme is
    /// shown; an unparseable URL or an unnameable scheme shows nothing.
    #[test]
    fn displayable_url_withholds_an_ambiguous_url() {
        for (url, scheme) in [
            ("http://admin\\s3cr3t@public.example/", "http"),
            ("ftp://admin\\s3cr3t@public.example/", "ftp"),
            ("http://admin\\no-at.example/", "http"),
            ("ws://admin:5432/s3cr3t@db.example", "ws"),
            ("http://admin@s3cr3t/-pw@host/x", "http"),
            ("wss://admin#s3cr3t@host", "wss"),
            ("ws://bob:s3cr3t@@@host/a@b", "ws"),
            ("http://127.0.0.1/admin@s3cr3t", "http"),
            ("https://public.example/?user=admin@s3cr3t", "https"),
        ] {
            let displayable = DisplayableUrl::of(url);
            assert_eq!(
                displayable.to_string(),
                format!("{scheme}:{WITHHELD_URL_TAIL}"),
                "{url:?}"
            );
            assert!(!displayable.shows_host(), "{url:?}");
        }
        for url in [
            "admin:s3cr3t@host",
            "apikey123:x@api.example",
            "admin/s3cr3t@host",
            "https://admin:s3cr3t?pw@host",
            "not a url",
        ] {
            let displayable = DisplayableUrl::of(url);
            assert_eq!(displayable.to_string(), WITHHELD_URL_TAIL, "{url:?}");
            assert!(!displayable.shows_host(), "{url:?}");
        }
    }

    /// A user name or token parsed as the scheme is refused without being
    /// named; a well-known scheme is named with the schemes the surface dials.
    #[test]
    fn scheme_refusal_names_only_a_well_known_scheme() {
        for (url, secrets) in [
            ("admin:s3cr3t@host", ["admin", "s3cr3t"]),
            ("admin:s3cr3t@host/x", ["admin", "s3cr3t"]),
            ("apikey123:x@api.example", ["apikey123", "api.example"]),
        ] {
            for admitted in [GatedSchemes::Http, GatedSchemes::HttpAndWebSocket] {
                let refused = parse_gated_url_within(url, admitted).err();
                assert_eq!(
                    refused,
                    Some(UrlRefusal::Scheme {
                        scheme: SchemeShown::Withheld,
                        admitted,
                    }),
                    "{url:?}"
                );
                if let Some(refused) = refused {
                    assert_shows_none_of(&refused, &secrets);
                }
            }
        }
        let ws = parse_gated_url_within("ws://example.com/", GatedSchemes::Http).err();
        assert_eq!(
            ws.as_ref().map(ToString::to_string),
            Some("blocked: scheme \"ws\" is not http/https (IPE_HTTP_DENY_PRIVATE)".to_owned())
        );
        let ftp = parse_gated_url("ftp://example.com/").err();
        assert_eq!(
            ftp.as_ref().map(ToString::to_string),
            Some(
                "blocked: scheme \"ftp\" is not http/https/ws/wss (IPE_HTTP_DENY_PRIVATE)"
                    .to_owned()
            )
        );
    }

    /// No refusal of a gated URL holds its credentials, whether the parser
    /// rejects it, refuses its scheme, or refuses its host.
    #[tokio::test]
    async fn url_refusals_never_show_credentials() {
        for (url, secrets) in CREDENTIAL_URLS {
            let vetted = vet_url_with(DialPolicy::DenyPrivate, &NoDns, url, DEADLINE).await;
            if let Err(refused) = vetted {
                assert_shows_none_of(&refused, secrets);
            }
            if let Err(refused) = ssrf_check_url_nonblocking(url) {
                assert_shows_none_of(&refused, secrets);
            }
        }
    }

    /// An unparseable URL is refused naming only the parser's reason.
    #[test]
    fn invalid_url_refusal_never_echoes_userinfo() {
        for url in ["http://admin:s3cr3t@[bad/x", "http://admin:s3cr3t/@[bad"] {
            let refused = parse_gated_url(url).err();
            assert!(
                matches!(refused, Some(UrlRefusal::Invalid { .. })),
                "{url:?}: {refused:?}"
            );
            if let Some(refused) = refused {
                assert_shows_none_of(&refused, &["admin", "s3cr3t"]);
            }
        }
    }

    /// When the URL's userinfo is ambiguous, the host the parser read may be
    /// part of a credential, so a host refusal withholds it and every address
    /// it resolved to.
    #[tokio::test]
    async fn host_refusal_withholds_a_host_that_may_be_a_credential() {
        for url in [
            "http://admin?s3cr3t@public.example/",
            "wss://admin?s3cr3t@public.example/",
        ] {
            let refused = vet_url_with(DialPolicy::DenyPrivate, &NoDns, url, DEADLINE).await;
            assert_eq!(
                refused,
                Err(UrlRefusal::Host(SsrfRefusal::Unresolvable {
                    host: HostShown::Withheld,
                    kind: std::io::ErrorKind::NotFound,
                })),
                "{url:?}"
            );
            if let Err(refused) = refused {
                assert!(refused.to_string().contains(WITHHELD_HOST), "{refused}");
                assert_shows_none_of(&refused, &["admin", "s3cr3t"]);
            }
        }
        for (hop, secrets) in [
            (
                "http://127.0.0.1/admin@s3cr3t",
                ["127.0.0.1", "admin", "s3cr3t"],
            ),
            (
                "http://10.0.0.1\\s3cr3t@public.example/",
                ["10.0.0.1", "s3cr3t", "public.example"],
            ),
        ] {
            let refused = ssrf_check_url_nonblocking(hop);
            assert!(
                matches!(
                    refused,
                    Err(UrlRefusal::Host(SsrfRefusal::Blocked {
                        host: BlockedHost::Withheld,
                        ..
                    }))
                ),
                "{hop:?}: {refused:?}"
            );
            if let Err(refused) = refused {
                assert!(refused.to_string().contains(WITHHELD_HOST), "{refused}");
                assert_shows_none_of(&refused, &secrets);
            }
        }
    }

    /// An IP-literal host read from a credential is never shown, neither as
    /// written nor as the address it re-encodes to: `1234567` parses as
    /// `0.18.214.135`, so showing the blocked address would show the secret.
    #[tokio::test]
    async fn ip_literal_credential_never_shows_its_address() {
        let decimal: &[&str] = &["1234567", "0.18.214.135", "pin", "api.example"];
        let dotted: &[&str] = &["10.0.0.1", "s3cr3t", "public.example"];
        for (url, secrets) in [
            ("http://1234567\\pin@api.example/", decimal),
            ("http://10.0.0.1\\s3cr3t@public.example/", dotted),
            ("http://1234567?pin@api.example/", decimal),
            ("http://10.0.0.1?s3cr3t@public.example/", dotted),
            (
                "ws://1234567890\\pw@x.example/",
                &["1234567890", "73.150.2.210", "pw@", "x.example"],
            ),
        ] {
            for policy in [DialPolicy::DenyPrivate, DialPolicy::AllowAll] {
                if let Err(refused) = vet_url_with(policy, &NoDns, url, DEADLINE).await {
                    assert_shows_none_of(&refused, secrets);
                }
            }
            if let Err(refused) = ssrf_check_url_nonblocking(url) {
                assert_shows_none_of(&refused, secrets);
            }
            assert_shows_none_of(&DisplayableUrl::of(url), secrets);
        }
        let blocked = vet_url_with(
            DialPolicy::DenyPrivate,
            &NoDns,
            "http://1234567?pin@api.example/",
            DEADLINE,
        )
        .await;
        assert_eq!(
            blocked,
            Err(UrlRefusal::Host(SsrfRefusal::Blocked {
                host: BlockedHost::Withheld,
                range: BlockedRange::Reserved,
            }))
        );
        let hop = ssrf_check_url_nonblocking("http://1234567\\pin@api.example/");
        assert_eq!(
            hop,
            Err(UrlRefusal::Host(SsrfRefusal::Blocked {
                host: BlockedHost::Withheld,
                range: BlockedRange::Reserved,
            }))
        );
    }

    /// A dial URL whose credential may run into its host or path is refused
    /// under every policy, before any lookup; one whose `@` sits only in the
    /// query, or is percent-encoded, is dialled.
    #[tokio::test]
    async fn dial_url_with_misplaced_userinfo_is_refused_under_every_policy() {
        for url in [
            "http://admin\\s3cr3t@public.example/",
            "http://admin:80/s3cr3t@public.example/",
            "ws://admin:5432/s3cr3t@db.example",
            "http://admin@s3cr3t/-pw@host/x",
            "wss://admin#s3cr3t@host",
            "ws://bob:s3cr3t@@@host/a@b",
            "https://public.example/a\\b",
            "http://public.example/@user",
            "http://adm in\\s3cr3t@public.example/",
        ] {
            for policy in [DialPolicy::DenyPrivate, DialPolicy::AllowAll] {
                let resolver = PublicThenPrivate::new();
                let refused = vet_url_with(policy, &resolver, url, DEADLINE).await;
                assert_eq!(refused, Err(UrlRefusal::MisplacedUserinfo), "{url:?}");
                assert_eq!(
                    resolver.calls(),
                    0,
                    "{url:?} must be refused before a lookup"
                );
                if let Err(refused) = refused {
                    assert_shows_none_of(&refused, &["admin", "s3cr3t", "bob"]);
                }
            }
        }
        for url in [
            "https://public.example/?user=admin@example.com",
            "https://registry.example/%40scope%2Fpkg",
            "wss://public.example/feed?acct=alice@example.com",
        ] {
            assert_eq!(refuse_misplaced_userinfo(url), Ok(()), "{url:?}");
            let dialled = vet_url_with(DialPolicy::AllowAll, &NoDns, url, DEADLINE).await;
            assert_eq!(dialled, Ok(VettedDial::Unrestricted), "{url:?}");
        }
    }

    /// A refused host is named only when the URL's userinfo is unambiguous,
    /// and a blocked address only beside a named host.
    #[test]
    fn withheld_host_refusals_show_neither_host_nor_address() {
        for refusal in [
            SsrfRefusal::Blocked {
                host: BlockedHost::Withheld,
                range: BlockedRange::Private,
            },
            SsrfRefusal::Unresolvable {
                host: HostShown::Withheld,
                kind: std::io::ErrorKind::NotFound,
            },
            SsrfRefusal::NoAddresses {
                host: HostShown::Withheld,
            },
            SsrfRefusal::Timeout {
                host: HostShown::Withheld,
                after: Duration::from_millis(250),
            },
        ] {
            let shown = refusal.to_string();
            assert!(shown.contains(WITHHELD_HOST), "{shown}");
            assert!(!shown.contains('"'), "{shown} quotes a host");
        }
    }

    /// A URL with unambiguous userinfo keeps naming the refused host.
    #[tokio::test]
    async fn host_refusal_names_a_host_read_from_a_clean_url() {
        for url in [
            "http://nowhere.example/path",
            "http://alice:s3cr3t@nowhere.example/path",
        ] {
            let refused = ssrf_check_url(url).await;
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|e| e.contains("nowhere.example")),
                "{refused:?}"
            );
        }
    }
}
