//! Compare the running `ipe` against the latest published release.
//!
//! The single source both `ipe upgrade` and `ipe health` read. A fetch or parse
//! failure yields `reached_feed = false` — never a panic, never a false "up to
//! date".

use semver::Version;

/// The GitHub releases API for the published `ipe` binaries — the same repo the
/// installer (`INSTALL_SH_URL`) resolves against.
const RELEASES_LATEST_API: &str = "https://api.github.com/repos/ipe-lang/compiler/releases/latest";

/// The running binary vs. the latest release.
pub struct VersionCheck {
    /// The running binary's version.
    pub current: Version,
    /// The latest published version; `None` when the feed was unreachable or
    /// returned a malformed tag.
    pub latest: Option<Version>,
    /// `latest > current`.
    pub upgrade_available: bool,
    /// `false` ⇒ offline / feed error / malformed tag (fail closed).
    pub reached_feed: bool,
}

/// What the caller should surface.
pub enum UpgradeAction {
    UpToDate,
    Available,
    Unreachable,
}

impl VersionCheck {
    #[must_use]
    pub const fn action(&self) -> UpgradeAction {
        if !self.reached_feed {
            UpgradeAction::Unreachable
        } else if self.upgrade_available {
            UpgradeAction::Available
        } else {
            UpgradeAction::UpToDate
        }
    }
}

/// The running binary's version.
///
/// `CARGO_PKG_VERSION` is a valid semver by construction (the workspace enforces
/// it), so a parse failure here is a build bug, not a runtime condition — fall
/// back to `0.0.0` rather than panic.
#[must_use]
pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| Version::new(0, 0, 0))
}

/// Parse a release tag into a semver; `None` on junk.
///
/// Release-please tags the `ipe` package as `ipe-v0.1.82`; the bare forms
/// `v0.1.82` and `0.1.82` are also accepted. A semver core always begins at the
/// first ASCII digit, so parse from there — format-agnostic to any leading
/// component or `v` prefix — while a tag carrying no version (`latest`) still
/// yields `None`. Anchoring on the first digit (not a hard-coded `ipe-`) keeps
/// this from re-hard-mirroring the release-please package name.
fn parse_tag(tag: &str) -> Option<Version> {
    let trimmed = tag.trim();
    let start = trimmed.find(|c: char| c.is_ascii_digit())?;
    Version::parse(&trimmed[start..]).ok()
}

/// The pure comparison — the test surface.
fn evaluate(current: Version, fetched: Option<Version>) -> VersionCheck {
    match fetched {
        Some(latest) => {
            let upgrade_available = latest > current;
            VersionCheck {
                current,
                latest: Some(latest),
                upgrade_available,
                reached_feed: true,
            }
        }
        None => VersionCheck {
            current,
            latest: None,
            upgrade_available: false,
            reached_feed: false,
        },
    }
}

/// Fetch the latest release tag over HTTPS and parse it. Any failure (network,
/// non-2xx, non-JSON body, missing/blank/malformed tag) ⇒ `None`.
fn fetch_latest_tag() -> Option<Version> {
    let body = crate::net::get(&crate::net::HttpsUrl::parse(RELEASES_LATEST_API).ok()?)?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    parse_tag(json.get("tag_name")?.as_str()?)
}

/// Compare the running binary to the latest release, doing the network fetch.
#[must_use]
pub fn version_check() -> VersionCheck {
    evaluate(current_version(), fetch_latest_tag())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).expect("test version literal is valid semver")
    }

    #[test]
    fn the_releases_feed_is_an_https_url() {
        assert!(crate::net::HttpsUrl::parse(RELEASES_LATEST_API).is_ok());
    }

    #[test]
    fn newer_latest_means_upgrade_available() {
        let c = evaluate(v("0.1.72"), Some(v("0.1.75")));
        assert!(c.reached_feed);
        assert_eq!(c.latest, Some(v("0.1.75")));
        assert!(c.upgrade_available);
        assert!(matches!(c.action(), UpgradeAction::Available));
    }

    #[test]
    fn equal_latest_means_up_to_date() {
        let c = evaluate(v("0.1.72"), Some(v("0.1.72")));
        assert!(c.reached_feed);
        assert!(!c.upgrade_available);
        assert!(matches!(c.action(), UpgradeAction::UpToDate));
    }

    #[test]
    fn older_latest_is_not_an_upgrade() {
        let c = evaluate(v("0.2.0"), Some(v("0.1.99")));
        assert!(!c.upgrade_available);
        assert!(matches!(c.action(), UpgradeAction::UpToDate));
    }

    #[test]
    fn no_fetched_tag_is_unreachable_never_up_to_date() {
        let c = evaluate(v("0.1.72"), None);
        assert!(!c.reached_feed);
        assert_eq!(c.latest, None);
        assert!(!c.upgrade_available);
        assert!(matches!(c.action(), UpgradeAction::Unreachable));
    }

    #[test]
    fn parse_tag_accepts_release_please_prefix_and_rejects_junk() {
        // The live scheme: release-please tags the `ipe` package this way.
        assert_eq!(parse_tag("ipe-v0.1.82"), Some(v("0.1.82")));
        // Bare forms stay valid.
        assert_eq!(parse_tag("v0.1.75"), Some(v("0.1.75")));
        assert_eq!(parse_tag("0.1.75"), Some(v("0.1.75")));
        // A prerelease core is preserved after the prefix.
        assert_eq!(parse_tag("ipe-v0.2.0-rc.1"), Some(v("0.2.0-rc.1")));
        // Version-less / empty tags are still rejected (fail closed).
        assert_eq!(parse_tag("latest"), None);
        assert_eq!(parse_tag(""), None);
    }
}
