//! The registry Pages read-path: an HTTP fast-path over the static
//! `ipe-registry` GitHub Pages API, with a git-checkout fallback.
//!
//! The authoritative registry is a git repository (`arthurmaciel/ipe-registry`)
//! holding one `packages/<name>.toml` per package and one advisory TOML per
//! advisory. A `pages.yml` Action mirrors that tree to a static JSON read API at
//! `IPE_REGISTRY_URL` (default `https://arthurmaciel.github.io/ipe-registry`):
//! `/packages/<name>.json`, `/advisories/index.json`, `/advisories/<id>.json`.
//!
//! # The fast-path is an optimisation, never the trust root
//!
//! Reading the per-package JSON lets `ipe add` discover an entry without cloning
//! the whole index. But the resolved entry's pinned `rev` + `sha256` remain the
//! trust root: the resolver still git-fetches the pinned revision and verifies
//! the fetched tree's content hash before anything is written
//! ([`crate::resolve::resolve_and_add`]). The Pages JSON only decides *which*
//! version to fetch; it cannot make the resolver trust bytes it did not hash.
//!
//! # Fall back, never trust a partial
//!
//! Any network failure (offline, air-gapped, DNS, TLS, non-2xx, timeout) OR a
//! malformed/partial JSON response falls back to the git-checkout reader
//! ([`crate::index::read_entry`] against [`crate::resolve::index_root`], the
//! `IPE_INDEX_DIR` path). A partial Pages response is NEVER trusted as a complete
//! entry — the JSON is parsed through the same typed constructors as the TOML
//! path, so a missing or injection-shaped field is a hard error that triggers the
//! fallback rather than a silently-truncated entry.

use std::path::Path;

use crate::CliError;
use crate::advisory::Advisory;
use crate::index::{self, IndexEntry};
use crate::net::{HttpsUrl, UrlError};

/// The environment variable naming the registry's static Pages read API base URL.
const REGISTRY_URL_ENV: &str = "IPE_REGISTRY_URL";

/// The default registry Pages read API base URL when [`REGISTRY_URL_ENV`] is
/// unset — the GitHub Pages site generated from `arthurmaciel/ipe-registry`.
const DEFAULT_REGISTRY_URL: &str = "https://arthurmaciel.github.io/ipe-registry";

/// The `Accept` media type for the static JSON read API.
const JSON_ACCEPT: &str = "application/json";

/// Where the registry Pages read API is read from, parsed once from
/// [`REGISTRY_URL_ENV`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrySource {
    /// [`REGISTRY_URL_ENV`] is set to empty: the HTTP fast-path is off and the
    /// git checkout is read directly — the air-gapped opt-out that keeps
    /// `ipe add` working with no network attempt.
    Disabled,
    /// The `https://` base every request URL is built from.
    Pages(RegistryBase),
}

impl RegistrySource {
    /// Parse a [`REGISTRY_URL_ENV`] value: empty is [`Self::Disabled`], anything
    /// else must be an `https://` base.
    ///
    /// # Errors
    /// The [`RegistryUrlError`] of a non-empty value that is not an `https://`
    /// base URL.
    pub fn parse(value: &str) -> Result<Self, RegistryUrlError> {
        if value.is_empty() {
            return Ok(Self::Disabled);
        }
        RegistryBase::parse(value).map(Self::Pages)
    }
}

/// An `https://` registry base URL: an [`HttpsUrl`] with no trailing slash
/// and no query, so a request path appended to it stays a path on that host.
///
/// Built only by [`RegistryBase::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryBase(HttpsUrl);

impl RegistryBase {
    /// Parse `value` as an `https://` base URL: the scheme is matched without
    /// regard to ASCII case and written back lower-case, and trailing slashes
    /// are trimmed.
    ///
    /// # Errors
    /// [`RegistryUrlError::NoScheme`] for a value without `://`,
    /// [`RegistryUrlError::NotHttps`] for any scheme but `https`,
    /// [`RegistryUrlError::ForbiddenChar`] for a query, fragment, space or
    /// control character, [`RegistryUrlError::NoHost`] for an empty host, and
    /// the [`UrlError`] of any other value that is not an [`HttpsUrl`].
    pub fn parse(value: &str) -> Result<Self, RegistryUrlError> {
        let Some((scheme, rest)) = value.split_once("://") else {
            return Err(RegistryUrlError::NoScheme);
        };
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(RegistryUrlError::NotHttps);
        }
        if rest
            .chars()
            .any(|c| c == '?' || c == '#' || c.is_whitespace() || c.is_control())
        {
            return Err(RegistryUrlError::ForbiddenChar);
        }
        let rest = rest.trim_end_matches('/');
        let host = rest.split_once('/').map_or(rest, |(host, _)| host);
        if host.is_empty() {
            return Err(RegistryUrlError::NoHost);
        }
        HttpsUrl::parse(&format!("https://{rest}"))
            .map(Self)
            .map_err(RegistryUrlError::from)
    }

    /// The absolute URL of `path` (no leading slash) under this base, or
    /// `None` when `path` does not keep it an [`HttpsUrl`].
    fn url(&self, path: &str) -> Option<HttpsUrl> {
        HttpsUrl::parse(&format!("{}/{path}", self.0.as_str())).ok()
    }
}

/// Why a [`REGISTRY_URL_ENV`] value is not an `https://` base URL.
///
/// Its text never repeats the value, which may carry a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryUrlError {
    /// The value is not valid UTF-8.
    NotText,
    /// The value names no scheme (no `://`).
    NoScheme,
    /// The value names a scheme other than `https`.
    NotHttps,
    /// The value carries a query, fragment, space, or control character.
    ForbiddenChar,
    /// The value names no host after `https://`.
    NoHost,
    /// The value carries userinfo before its host.
    Userinfo,
    /// The value writes a port that is not a number from 1 to 65535.
    BadPort,
    /// The value is not a well-formed URL.
    Malformed,
}

impl From<UrlError> for RegistryUrlError {
    fn from(fault: UrlError) -> Self {
        match fault {
            UrlError::Malformed => Self::Malformed,
            UrlError::NotHttps => Self::NotHttps,
            UrlError::NoHost => Self::NoHost,
            UrlError::Userinfo => Self::Userinfo,
            UrlError::BadPort => Self::BadPort,
            UrlError::ForbiddenChar => Self::ForbiddenChar,
        }
    }
}

impl std::fmt::Display for RegistryUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotText => "the value is not valid UTF-8",
            Self::NoScheme => "the value names no scheme",
            Self::NotHttps => "the value names a scheme other than https",
            Self::ForbiddenChar => {
                "the value carries a query, fragment, space or control character"
            }
            Self::NoHost => "the value names no host",
            Self::Userinfo => "the value carries userinfo before its host",
            Self::BadPort => "the value names a port that is not a number from 1 to 65535",
            Self::Malformed => "the value is not a well-formed URL",
        })
    }
}

impl From<RegistryUrlError> for CliError {
    fn from(fault: RegistryUrlError) -> Self {
        Self::Usage(crate::text::msg::cli_registry_url_not_https(
            &REGISTRY_URL_ENV,
            &fault,
        ))
    }
}

/// The registry source [`REGISTRY_URL_ENV`] names, else the
/// [`DEFAULT_REGISTRY_URL`] base when it is unset.
///
/// # Errors
/// The [`CliError::Usage`] of a value that is neither empty nor an `https://`
/// base URL: an explicit override is refused, never silently replaced by the
/// default or by the git checkout.
pub fn registry_source() -> Result<RegistrySource, CliError> {
    match ipe_env::var(REGISTRY_URL_ENV) {
        Ok(value) => RegistrySource::parse(&value).map_err(CliError::from),
        Err(std::env::VarError::NotPresent) => RegistryBase::parse(DEFAULT_REGISTRY_URL)
            .map(RegistrySource::Pages)
            .map_err(CliError::from),
        Err(std::env::VarError::NotUnicode(_)) => Err(RegistryUrlError::NotText.into()),
    }
}

/// A fetcher: given an absolute `https://` URL, return the response body, or
/// `None`.
///
/// `None` signals any failure (offline, DNS, TLS, non-2xx, timeout). The
/// production fetcher is [`net_fetch`]; tests inject a stub so the read-path and
/// fallback logic are exercised without real HTTP.
pub type Fetch<'a> = &'a dyn Fn(&HttpsUrl) -> Option<String>;

/// The production fetcher: a blocking JSON GET through [`crate::net`].
#[must_use]
pub fn net_fetch(url: &HttpsUrl) -> Option<String> {
    crate::net::get_with_accept(url, JSON_ACCEPT)
}

/// Read the index entry for `name`, preferring the Pages HTTP fast-path and
/// falling back to the git-checkout reader on any network failure, air-gap, or
/// malformed response.
///
/// This is the resolver's entry read-path. The returned [`IndexEntry`] carries
/// pinned `rev` + `sha256` per version — the trust root the resolver
/// hash-verifies after fetching, unchanged by which source produced the entry.
///
/// # Errors
/// [`CliError::Resolve`] when BOTH the fast-path declines (or is malformed) AND
/// the git-checkout reader cannot produce the entry — the same error the
/// git-only reader would have returned, so an absent package is still an honest
/// "not in the index". [`CliError::Usage`] when [`REGISTRY_URL_ENV`] is neither
/// empty nor an `https://` base URL.
pub fn read_entry_via_pages(name: &str, index_root: &Path) -> Result<IndexEntry, CliError> {
    read_entry_via_pages_with(name, index_root, &registry_source()?, &net_fetch)
}

/// The testable core of [`read_entry_via_pages`].
///
/// The registry source and fetcher are injected so a stub can exercise the fast-path,
/// the malformed-response fallback, and the network-failure fallback without
/// real HTTP.
///
/// # Errors
/// [`CliError::Resolve`] when the fast-path declines (or is malformed) AND the
/// git-checkout reader cannot produce the entry.
pub fn read_entry_via_pages_with(
    name: &str,
    index_root: &Path,
    source: &RegistrySource,
    fetch: Fetch<'_>,
) -> Result<IndexEntry, CliError> {
    if let RegistrySource::Pages(base) = source
        && let Some(entry) = try_pages_entry(name, base, fetch)
    {
        return Ok(entry);
    }
    // Fall back to the reproducible git-checkout source of truth. A partial or
    // absent Pages response never short-circuits this — the checkout reader's
    // verdict (Present / absent-is-error) is authoritative on the fallback path.
    index::read_entry(index_root, name)
}

/// Attempt the Pages fast-path for `name`, returning the parsed entry only when
/// the fetch succeeds AND the JSON parses through the typed constructors.
///
/// `None` on a fetch failure or a malformed/partial response — every case a
/// fallback trigger, never a partial trusted as complete.
fn try_pages_entry(name: &str, base: &RegistryBase, fetch: Fetch<'_>) -> Option<IndexEntry> {
    let body = fetch(&base.url(&format!("packages/{name}.json"))?)?;
    // A malformed/partial JSON is discarded (→ fallback), never trusted.
    index::parse_entry_json(name, &body).ok()
}

/// The outcome of fetching advisories for one package over the Pages read-path.
///
/// The three variants keep "clean", "vulnerable-or-warned", and "DB unreachable"
/// distinct so the caller can enforce the fail-closed policy: an unreachable DB
/// is a loud WARN, never a silent all-clear.
#[derive(Debug)]
pub enum PagesAdvisoryOutcome {
    /// The advisory DB was reachable and every fetched advisory for the package
    /// was parsed. The vector holds the advisories whose range must still be
    /// tested against the locked version (possibly empty = no advisories).
    Fetched(Vec<Advisory>),
    /// The advisory index could not be fetched (offline, air-gapped, non-2xx).
    /// The caller WARNs and falls back to the git-checkout DB; it is NEVER
    /// treated as "no advisories → clean".
    Unreachable,
}

/// Fetch the advisories affecting `pkg_name` from the Pages advisory read-path.
///
/// Fetches `/advisories/index.json` (the id → package catalogue), selects the
/// ids whose `package` equals `pkg_name`, fetches each `/advisories/<id>.json`,
/// and parses it through [`crate::advisory::parse_advisory_json`].
///
/// **Fail-closed:** a malformed advisory index or a malformed per-advisory record
/// is a hard [`CliError::AdvisoryDbMalformed`] — a corrupt DB is never treated as
/// "clean". An unreachable index (network failure) returns
/// [`PagesAdvisoryOutcome::Unreachable`] so the caller can WARN and fall back,
/// rather than silently passing.
///
/// # Errors
/// [`CliError::AdvisoryDbMalformed`] when the index or an advisory record is
/// present but malformed; [`CliError::Usage`] when [`REGISTRY_URL_ENV`] is
/// neither empty nor an `https://` base URL.
pub fn fetch_advisories_via_pages(pkg_name: &str) -> Result<PagesAdvisoryOutcome, CliError> {
    fetch_advisories_via_pages_with(pkg_name, &registry_source()?, &net_fetch)
}

/// The testable core of [`fetch_advisories_via_pages`].
///
/// The registry source and fetcher are injected so the reachable, unreachable, and
/// malformed paths are exercised without real HTTP.
///
/// # Errors
/// [`CliError::AdvisoryDbMalformed`] when the advisory index or a per-advisory
/// record is present but malformed.
pub fn fetch_advisories_via_pages_with(
    pkg_name: &str,
    source: &RegistrySource,
    fetch: Fetch<'_>,
) -> Result<PagesAdvisoryOutcome, CliError> {
    let RegistrySource::Pages(base) = source else {
        return Ok(PagesAdvisoryOutcome::Unreachable);
    };
    let Some(index_body) = base
        .url("advisories/index.json")
        .and_then(|url| fetch(&url))
    else {
        // Network failure / air-gap: unreachable, NOT clean.
        return Ok(PagesAdvisoryOutcome::Unreachable);
    };

    // A present-but-malformed index is fail-closed: refuse, never treat as empty.
    let ids = crate::advisory::parse_advisory_index_json(&index_body, pkg_name)?;

    let mut advisories = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(record_body) = base
            .url(&format!("advisories/{id}.json"))
            .and_then(|url| fetch(&url))
        else {
            // The index named this advisory but the record is unreachable. The
            // index proved an advisory exists, so we cannot claim the dep clean:
            // fail closed (unreachable), not silent-pass.
            return Ok(PagesAdvisoryOutcome::Unreachable);
        };
        advisories.push(crate::advisory::parse_advisory_json(&record_body, &id)?);
    }
    Ok(PagesAdvisoryOutcome::Fetched(advisories))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::Severity;

    const FIXTURE_REV: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    /// A well-formed 64-char lowercase-hex content hash for the fixtures.
    const FIXTURE_SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn temp_index(tag: &str) -> std::path::PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-registry-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("packages")).expect("packages dir");
        dir
    }

    fn write_git_entry(root: &Path, name: &str, version: &str) {
        let text = format!(
            "name = \"{name}\"\npublisher = \"git-source\"\n\n[[version]]\n\
             version = \"{version}\"\nsource = \"https://example.invalid/{name}\"\n\
             rev = \"{FIXTURE_REV}\"\nsha256 = \"{FIXTURE_SHA}\"\ncapabilities = [\"network\"]\n"
        );
        std::fs::write(root.join("packages").join(format!("{name}.toml")), text)
            .expect("write git entry");
    }

    fn pages_entry_json(name: &str, publisher: &str, version: &str) -> String {
        format!(
            r#"{{ "name": "{name}", "publisher": "{publisher}",
                  "versions": [ {{ "version": "{version}",
                                   "source": "https://example.invalid/{name}",
                                   "rev": "{FIXTURE_REV}", "sha256": "{FIXTURE_SHA}",
                                   "capabilities": ["network"] }} ] }}"#
        )
    }

    /// The registry source the fast-path tests read from.
    fn reg() -> RegistrySource {
        RegistrySource::parse("https://reg.example").expect("an https base")
    }

    // ── Registry URL parse ────────────────────────────────────────────────────

    #[test]
    fn a_non_https_registry_url_is_refused() {
        for (value, fault) in [
            ("http://host", RegistryUrlError::NotHttps),
            ("host/path", RegistryUrlError::NoScheme),
            ("ftp://host", RegistryUrlError::NotHttps),
            ("https:host", RegistryUrlError::NoScheme),
            ("https://", RegistryUrlError::NoHost),
            ("https:///path", RegistryUrlError::NoHost),
            ("/", RegistryUrlError::NoScheme),
            ("https://host/?q", RegistryUrlError::ForbiddenChar),
            ("https://host#f", RegistryUrlError::ForbiddenChar),
            ("https://host /p", RegistryUrlError::ForbiddenChar),
            ("https://host\r\n", RegistryUrlError::ForbiddenChar),
            ("https://host\u{1b}/reg", RegistryUrlError::ForbiddenChar),
            ("https://host:99999", RegistryUrlError::BadPort),
            ("https://host:0/reg", RegistryUrlError::BadPort),
            ("https://host:/reg", RegistryUrlError::BadPort),
            ("https://:443/reg", RegistryUrlError::NoHost),
            ("https://user@host", RegistryUrlError::Userinfo),
            ("https://user:pw@host/reg", RegistryUrlError::Userinfo),
            ("https://user@", RegistryUrlError::Malformed),
            ("https://h\u{e9}/reg", RegistryUrlError::Malformed),
        ] {
            assert_eq!(RegistrySource::parse(value), Err(fault), "{value:?}");
        }
    }

    #[test]
    fn the_scheme_is_matched_without_regard_to_case() {
        // Schemes are case-insensitive: upper-case HTTP is still refused as
        // plain http, and upper-case HTTPS parses to the lower-case base.
        assert_eq!(
            RegistrySource::parse("HTTP://host"),
            Err(RegistryUrlError::NotHttps)
        );
        assert_eq!(
            RegistrySource::parse("HTTPS://Host/reg//"),
            Ok(RegistrySource::Pages(RegistryBase(
                HttpsUrl::parse("https://Host/reg").expect("an https URL")
            )))
        );
    }

    #[test]
    fn an_empty_registry_url_disables_and_the_default_parses() {
        assert_eq!(RegistrySource::parse(""), Ok(RegistrySource::Disabled));
        assert_eq!(
            RegistryBase::parse(DEFAULT_REGISTRY_URL).map(|base| base.0.as_str().to_owned()),
            Ok(DEFAULT_REGISTRY_URL.to_owned())
        );
    }

    #[test]
    fn a_refused_registry_url_names_the_variable_and_https_not_the_value() {
        let err = CliError::from(RegistryUrlError::NotHttps);
        let text = err.to_string();
        assert!(text.contains(REGISTRY_URL_ENV), "{text}");
        assert!(text.contains("https://"), "{text}");
        let err = CliError::from(
            RegistrySource::parse("http://user:secret@host").expect_err("plain http"),
        );
        assert!(!err.to_string().contains("secret"), "{err}");
        for value in [
            "https://user:secret@host:99999",
            "https://host:99999/secret",
        ] {
            let err = CliError::from(RegistrySource::parse(value).expect_err("bad authority"));
            let text = err.to_string();
            assert!(text.contains(REGISTRY_URL_ENV), "{text}");
            assert!(
                !text.contains("secret") && !text.contains("99999"),
                "{text}"
            );
        }
    }

    #[test]
    fn request_urls_stay_under_the_base() {
        let seen = std::cell::RefCell::new(Vec::new());
        let fetch = |url: &HttpsUrl| {
            seen.borrow_mut().push(url.as_str().to_owned());
            None
        };
        let source = RegistrySource::parse("https://reg.example/mirror/").expect("https base");
        let outcome = fetch_advisories_via_pages_with("p", &source, &fetch).expect("unreachable");
        assert!(matches!(outcome, PagesAdvisoryOutcome::Unreachable));
        assert_eq!(
            *seen.borrow(),
            ["https://reg.example/mirror/advisories/index.json".to_owned()]
        );
    }

    // ── Pages read-path ───────────────────────────────────────────────────────

    #[test]
    fn pages_fast_path_resolves_from_http() {
        // A healthy Pages response resolves without touching the git checkout.
        let root = temp_index("pages-ok");
        // No git entry on disk — proving the fast-path did the work.
        let body = pages_entry_json("http-extras", "pages-source", "1.2.0");
        let fetch = move |url: &HttpsUrl| {
            assert!(
                url.as_str().ends_with("/packages/http-extras.json"),
                "url: {url:?}"
            );
            Some(body.clone())
        };
        let entry = read_entry_via_pages_with("http-extras", &root, &reg(), &fetch)
            .expect("fast-path resolves");
        assert_eq!(entry.publisher, "pages-source");
        assert_eq!(entry.versions.len(), 1);
        let first = entry.versions.first().expect("one version");
        assert_eq!(first.version.to_string(), "1.2.0");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn network_failure_falls_back_to_git() {
        // The fetcher returns None (offline). The git-checkout entry is used.
        let root = temp_index("net-fail");
        write_git_entry(&root, "http-extras", "0.9.0");
        let fetch = |_url: &HttpsUrl| None;
        let entry = read_entry_via_pages_with("http-extras", &root, &reg(), &fetch)
            .expect("git fallback resolves");
        assert_eq!(entry.publisher, "git-source");
        let first = entry.versions.first().expect("one version");
        assert_eq!(first.version.to_string(), "0.9.0");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_pages_json_falls_back_to_git_not_trusted() {
        // A partial/truncated Pages response is NOT trusted as complete: the
        // git-checkout entry is used instead of a half-parsed one.
        let root = temp_index("malformed");
        write_git_entry(&root, "http-extras", "0.9.0");
        // Missing `versions` — a partial mirror the fast-path must discard.
        let fetch = |_url: &HttpsUrl| {
            Some(r#"{ "name": "http-extras", "publisher": "attacker" }"#.to_owned())
        };
        let entry = read_entry_via_pages_with("http-extras", &root, &reg(), &fetch)
            .expect("git fallback resolves");
        assert_eq!(
            entry.publisher, "git-source",
            "the malformed Pages entry must not be trusted; git is authoritative"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn injection_shaped_pages_rev_is_rejected_and_falls_back() {
        // A Pages JSON with a non-immutable `rev` fails the typed constructor and
        // triggers the fallback — the JSON path enforces the same trust boundary
        // as the TOML path.
        let root = temp_index("bad-rev");
        write_git_entry(&root, "http-extras", "0.9.0");
        // A non-immutable `rev` ("main") the typed `PinnedRev` constructor rejects.
        let body = r#"{ "name": "http-extras", "publisher": "attacker",
                  "versions": [ { "version": "1.0.0",
                                   "source": "https://example.invalid/x",
                                   "rev": "main", "sha256": "00" } ] }"#;
        let fetch = move |_url: &HttpsUrl| Some(body.to_owned());
        let entry = read_entry_via_pages_with("http-extras", &root, &reg(), &fetch)
            .expect("git fallback resolves");
        assert_eq!(entry.publisher, "git-source");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_base_url_disables_fast_path() {
        // An explicitly-empty base URL skips HTTP entirely (air-gapped opt-out)
        // and reads straight from the git checkout.
        let root = temp_index("empty-base");
        write_git_entry(&root, "http-extras", "0.9.0");
        // Record whether the fetcher was ever consulted: with an empty base URL
        // the fast-path must be skipped entirely, so this stays false.
        let called = std::cell::Cell::new(false);
        let fetch = |_url: &HttpsUrl| {
            called.set(true);
            None
        };
        let entry =
            read_entry_via_pages_with("http-extras", &root, &RegistrySource::Disabled, &fetch)
                .expect("git fallback resolves");
        assert!(
            !called.get(),
            "fetch must not run when the base URL is empty"
        );
        assert_eq!(entry.publisher, "git-source");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_everywhere_is_an_honest_error() {
        // No Pages, no git entry — the same "not in the index" error the git-only
        // reader returns, not a spurious success.
        let root = temp_index("absent");
        let fetch = |_url: &HttpsUrl| None;
        let err = read_entry_via_pages_with("ghost", &root, &reg(), &fetch)
            .expect_err("absent everywhere is an error");
        assert!(format!("{err}").contains("ghost"));
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── Advisory fetch ────────────────────────────────────────────────────────

    fn advisory_record_json(id: &str, pkg: &str, severity: &str, affected: &str) -> String {
        format!(
            r#"{{ "id": "{id}", "package": "{pkg}", "severity": "{severity}",
                  "affected": "{affected}", "description": "Test advisory." }}"#
        )
    }

    #[test]
    fn advisory_in_range_is_fetched_and_flagged() {
        // The index names one advisory for the package; its record is fetched and
        // its range covers the locked version → surfaced to the caller.
        let index_json =
            r#"{ "advisories": [ { "id": "IPE-2024-0001", "package": "http-client" } ] }"#;
        let record =
            advisory_record_json("IPE-2024-0001", "http-client", "high", ">=1.0.0, <1.2.0");
        let fetch = move |url: &HttpsUrl| {
            if url.as_str().ends_with("/advisories/index.json") {
                Some(index_json.to_owned())
            } else if url.as_str().ends_with("/advisories/IPE-2024-0001.json") {
                Some(record.clone())
            } else {
                None
            }
        };
        let outcome = fetch_advisories_via_pages_with("http-client", &reg(), &fetch)
            .expect("advisory fetch succeeds");
        let advisories = fetched(outcome);
        assert_eq!(advisories.len(), 1);
        let adv = advisories.first().expect("one advisory");
        assert_eq!(adv.severity, Severity::High);
        let locked = semver::Version::parse("1.1.0").expect("valid version");
        assert!(adv.affected.matches(&locked), "1.1.0 must be in range");
    }

    #[test]
    fn advisory_index_unreachable_is_warn_not_clean() {
        // The index fetch fails (offline). The outcome is Unreachable so the
        // caller WARNs and falls back — never a silent all-clear.
        let fetch = |_url: &HttpsUrl| None;
        let outcome = fetch_advisories_via_pages_with("http-client", &reg(), &fetch)
            .expect("unreachable is not an error");
        assert!(
            matches!(outcome, PagesAdvisoryOutcome::Unreachable),
            "an unreachable advisory DB must be Unreachable, not Fetched(empty)"
        );
    }

    #[test]
    fn malformed_advisory_index_is_fail_closed() {
        // A present-but-malformed index is a hard error, never treated as empty.
        let fetch = |url: &HttpsUrl| {
            if url.as_str().ends_with("/advisories/index.json") {
                Some("this is not json ===".to_owned())
            } else {
                None
            }
        };
        let err = fetch_advisories_via_pages_with("http-client", &reg(), &fetch)
            .expect_err("malformed index must be an error");
        assert!(
            matches!(err, CliError::AdvisoryDbMalformed { .. }),
            "expected AdvisoryDbMalformed, got {err:?}"
        );
    }

    #[test]
    fn advisory_record_unreachable_after_index_is_fail_closed() {
        // The index proves an advisory exists but the record cannot be fetched.
        // We cannot claim the dep clean → Unreachable (fail closed), not empty.
        let index_json =
            r#"{ "advisories": [ { "id": "IPE-2024-0001", "package": "http-client" } ] }"#;
        let fetch = move |url: &HttpsUrl| {
            if url.as_str().ends_with("/advisories/index.json") {
                Some(index_json.to_owned())
            } else {
                None
            }
        };
        let outcome = fetch_advisories_via_pages_with("http-client", &reg(), &fetch)
            .expect("record-unreachable is not an error");
        assert!(
            matches!(outcome, PagesAdvisoryOutcome::Unreachable),
            "a named-but-unreachable record must be Unreachable, not Fetched(empty)"
        );
    }

    #[test]
    fn advisory_index_omits_other_packages() {
        // The index lists advisories for another package only; ours is clean.
        let index_json =
            r#"{ "advisories": [ { "id": "IPE-2024-0009", "package": "other-pkg" } ] }"#;
        let fetch = move |url: &HttpsUrl| {
            if url.as_str().ends_with("/advisories/index.json") {
                Some(index_json.to_owned())
            } else {
                None
            }
        };
        let outcome = fetch_advisories_via_pages_with("http-client", &reg(), &fetch)
            .expect("advisory fetch succeeds");
        let advisories = fetched(outcome);
        assert!(
            advisories.is_empty(),
            "no advisory for our package → empty, and the reachable index proves it clean"
        );
    }

    /// Extract the [`PagesAdvisoryOutcome::Fetched`] payload, failing the test
    /// with a readable assertion on any other variant. The `else` arm is dead
    /// after the assert; it returns an empty vec purely to satisfy the type
    /// without a `panic!`/`unreachable!` macro (the workspace forbids both).
    fn fetched(outcome: PagesAdvisoryOutcome) -> Vec<Advisory> {
        assert!(
            matches!(outcome, PagesAdvisoryOutcome::Fetched(_)),
            "expected Fetched, got Unreachable"
        );
        let PagesAdvisoryOutcome::Fetched(advisories) = outcome else {
            return Vec::new();
        };
        advisories
    }
}
