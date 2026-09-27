//! Canonical HTTP header-name casing, shared by Ipe.Web and Ipe.Http.Server.
//!
//! Canonical MIME case: `content-type` → `Content-Type`, `x-ipe-web` →
//! `X-Ipe-Web`. hyper/axum expose request header names lower-cased, so the
//! runtime re-derives the canonical form at the request boundary for both
//! storage and lookup. This module is the single source of truth for that
//! transformation so the Web and Server request builders never drift apart.

/// Canonicalise a `-`-separated header name (`content-type` -> `Content-Type`).
///
/// Upper-cases the first ASCII letter of each `-`-separated segment and
/// lower-cases the rest. Only `-` triggers the next-uppercase; `_`/`.`/digits
/// are non-triggers.
///
/// Accepted divergence: a name containing bytes outside the header-token set
/// (e.g. a space or non-ASCII byte) is always title-cased per segment, rather
/// than returned unchanged. Such names cannot reach the request boundary —
/// hyper/axum reject invalid header names on parse — so the divergence is
/// unobservable in practice.
pub(crate) fn canonical_header(k: &str) -> String {
    let mut out = String::with_capacity(k.len());
    let mut at_segment_start = true;
    for c in k.chars() {
        if c == '-' {
            out.push('-');
            at_segment_start = true;
        } else if at_segment_start {
            out.push(c.to_ascii_uppercase());
            at_segment_start = false;
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// Strip a scheme's IMPLICIT default port (`:443` for `https`, `:80` for
/// `http`) from a `host[:port]` authority string, if present. Any other
/// scheme (or an authority without that exact suffix) passes through
/// unchanged.
#[cfg(feature = "server")]
fn strip_default_port<'a>(authority: &'a str, scheme: &str) -> &'a str {
    let suffix = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return authority,
    };
    authority.strip_suffix(suffix).unwrap_or(authority)
}

/// Whether an `Origin` header's host disagrees with a `Host` header, once
/// each side's scheme-implied default port is normalized away. Returns
/// `true` when they are CROSS-origin (a mismatch); `false` when same-origin
/// OR when `host` is empty (nothing to compare against — every existing call
/// site treats an empty `Host` as "don't reject").
///
/// Shared by every "compare Origin's host against Host" call site in the
/// runtime (`live/csrf.rs::origin_mismatch`, `live/console.rs::
/// is_cross_origin_ingest`, `server.rs::ws_cross_origin`) so the three never
/// drift to different normalization behavior. Browsers omit the default
/// port from BOTH the `Origin` and `Host` headers they send, so a raw string
/// compare is right in the overwhelming common case — but a reverse proxy or
/// non-browser client that sets an EXPLICIT `:443`/`:80` (e.g. `Origin:
/// https://example.com` vs `Host: example.com:443`) would otherwise trip a
/// false-positive cross-origin rejection. This is an availability nit (every
/// caller fails CLOSED on a mismatch — over-rejecting, never under-
/// rejecting), not a vulnerability; still worth normalizing correctly rather
/// than leaving three copies of the same raw-string-compare gap.
#[cfg(feature = "server")]
pub(crate) fn origin_host_mismatch(origin: &str, host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    let (scheme, origin_authority) = origin.split_once("://").unwrap_or(("", origin));
    let origin_host = strip_default_port(origin_authority, scheme);
    let host_host = strip_default_port(host, scheme);
    origin_host != host_host
}

#[cfg(test)]
mod tests {
    use super::canonical_header;
    #[cfg(feature = "server")]
    use super::origin_host_mismatch;

    /// Well-formed header names — byte-identical to
    /// `textproto.CanonicalMIMEHeaderKey`.
    #[test]
    fn canonical_header_matches_go_canonical_mime_key() {
        for (input, want) in [
            ("content-type", "Content-Type"),
            ("CONTENT-TYPE", "Content-Type"),
            ("Content-Type", "Content-Type"),
            ("x-forwarded-for", "X-Forwarded-For"),
            ("x-ipe-web", "X-Ipe-Web"),
            ("etag", "Etag"),
            ("www-authenticate", "Www-Authenticate"),
            ("host", "Host"),
            ("a", "A"),
            ("", ""),
            ("MiXeD-cAsE", "Mixed-Case"),
            ("x_custom", "X_custom"),
            ("123-abc", "123-Abc"),
            ("x--y", "X--Y"),
            ("-x", "-X"),
            ("x-", "X-"),
        ] {
            assert_eq!(canonical_header(input), want, "input {input:?}");
        }
    }

    /// Invalid-token names are the accepted divergence: title-cased here.
    /// These names cannot reach the request boundary (hyper/axum reject them
    /// on parse), so the divergence is unobservable in practice; this test
    /// pins the behaviour so any future change to the canonicaliser is caught.
    #[test]
    fn canonical_header_invalid_token_is_accepted_divergence() {
        assert_eq!(canonical_header("foo bar"), "Foo bar");
        assert_eq!(canonical_header("über-key"), "über-Key");
    }

    /// Baseline: same host, no port anywhere — same-origin (browsers'
    /// common case for both headers).
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_same_origin_no_ports() {
        assert!(!origin_host_mismatch("https://example.com", "example.com"));
    }

    /// Cross-origin host — must still be flagged regardless of the port
    /// normalization added by this fix.
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_different_host_is_flagged() {
        assert!(origin_host_mismatch(
            "https://evil.example",
            "victim.example"
        ));
    }

    /// The bug this fix closes: `https://example.com` (implicit :443) vs
    /// `Host: example.com:443` (explicit) is the SAME origin. Pre-fix (raw
    /// string compare) this was a false-positive mismatch.
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_normalizes_explicit_default_https_port() {
        assert!(!origin_host_mismatch(
            "https://example.com",
            "example.com:443"
        ));
    }

    /// Same bug, `http`/`:80` side.
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_normalizes_explicit_default_http_port() {
        assert!(!origin_host_mismatch(
            "http://example.com",
            "example.com:80"
        ));
    }

    /// A NON-default explicit port must still compare as a mismatch when the
    /// other side omits it — normalization only strips the SCHEME-IMPLIED
    /// default port, not arbitrary ports.
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_nondefault_port_still_flagged() {
        assert!(origin_host_mismatch(
            "https://example.com",
            "example.com:8443"
        ));
        assert!(!origin_host_mismatch(
            "https://example.com:8443",
            "example.com:8443"
        ));
    }

    /// Empty Host header → never a mismatch (matches every call site's own
    /// pre-existing `!host.is_empty()` guard — nothing to compare against).
    #[cfg(feature = "server")]
    #[test]
    fn origin_host_mismatch_empty_host_is_never_flagged() {
        assert!(!origin_host_mismatch("https://evil.example", ""));
    }
}
