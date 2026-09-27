//! The version of a package release as the index records it.
//!
//! A [`PublishedVersion`] is a [`semver::Version`] with no build metadata.
//! Semver precedence ignores build metadata (§10), so `1.0.0+b` and `1.0.0`
//! would name one release twice and order ambiguously against each other; the
//! index refuses the suffix outright. Every index version is parsed into this
//! type once — at `ipe package publish`, at admission, and when an entry file
//! is read — so the index, resolution, and enforced-semver logic only ever see
//! an unambiguous version whose derived `Ord` IS semver precedence.

use std::fmt;

/// A semver version with no build metadata: one release, one identity.
///
/// Construct it with [`PublishedVersion::parse`] or
/// [`PublishedVersion::from_semver`]; both refuse build metadata, so the
/// derived ordering equals semver precedence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublishedVersion(semver::Version);

impl PublishedVersion {
    /// Parse a raw version string, refusing malformed input and build metadata.
    ///
    /// # Errors
    /// [`VersionRefusal::Malformed`] when `raw` is not a semantic version;
    /// [`VersionRefusal::BuildMetadata`] when it carries a `+…` suffix.
    pub fn parse(raw: &str) -> Result<Self, VersionRefusal> {
        let version = semver::Version::parse(raw).map_err(|e| VersionRefusal::Malformed {
            raw: raw.to_owned(),
            reason: e.to_string(),
        })?;
        Self::from_semver(version)
    }

    /// The release `major.minor.patch`, with no prerelease and no build metadata.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self(semver::Version::new(major, minor, patch))
    }

    /// Admit an already-parsed [`semver::Version`], refusing build metadata.
    ///
    /// # Errors
    /// [`VersionRefusal::BuildMetadata`] when `version` carries a `+…` suffix.
    pub fn from_semver(version: semver::Version) -> Result<Self, VersionRefusal> {
        if version.build.is_empty() {
            Ok(Self(version))
        } else {
            Err(VersionRefusal::BuildMetadata { version })
        }
    }

    /// The underlying semver version, for requirement matching and API diffs.
    #[must_use]
    pub const fn as_semver(&self) -> &semver::Version {
        &self.0
    }

    /// Whether this is a prerelease (`X.Y.Z-<pre>`).
    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        !self.0.pre.is_empty()
    }
}

impl fmt::Display for PublishedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Require `candidate` to be strictly greater than the greatest version in
/// `published`.
///
/// Comparing against the maximum alone suffices: exceeding the greatest version
/// exceeds every one. Callers pass the baseline (already-published) versions and
/// call this once per version new to the submission, release or prerelease
/// alike. An empty `published` (a first publish) admits any candidate.
///
/// # Errors
/// [`VersionRefusal::NotAboveGreatest`] naming the greatest published version
/// when `candidate` does not exceed it.
pub fn require_successor<'a>(
    published: impl IntoIterator<Item = &'a PublishedVersion>,
    candidate: &PublishedVersion,
) -> Result<(), VersionRefusal> {
    match published.into_iter().max() {
        Some(greatest) if candidate <= greatest => Err(VersionRefusal::NotAboveGreatest {
            candidate: candidate.clone(),
            greatest: greatest.clone(),
        }),
        _ => Ok(()),
    }
}

/// Why a version cannot enter the package index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionRefusal {
    /// The value is not a semantic version.
    Malformed { raw: String, reason: String },
    /// The version carries build metadata, which semver precedence ignores, so
    /// it would not name a release unambiguously.
    BuildMetadata { version: semver::Version },
    /// The version does not exceed the greatest version already published.
    NotAboveGreatest {
        candidate: PublishedVersion,
        greatest: PublishedVersion,
    },
}

impl VersionRefusal {
    /// Lift this refusal into the driver error for package `package`.
    #[must_use]
    pub fn for_package(self, package: &str) -> crate::CliError {
        crate::CliError::VersionRefused {
            package: package.to_owned(),
            refusal: Box::new(self),
        }
    }
}

impl fmt::Display for VersionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&match self {
            // `{raw:?}` escapes control bytes: the raw value is untrusted input.
            Self::Malformed { raw, reason } => {
                crate::text::version_refused_malformed(&format!("{raw:?}"), reason)
            }
            Self::BuildMetadata { version } => {
                crate::text::version_refused_build_metadata(version, &version.build)
            }
            Self::NotAboveGreatest {
                candidate,
                greatest,
            } => crate::text::version_refused_not_above(candidate, greatest),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{PublishedVersion, VersionRefusal, require_successor};

    #[allow(clippy::expect_used)] // test fixture: the literal is a valid version
    fn v(raw: &str) -> PublishedVersion {
        PublishedVersion::parse(raw).expect("valid published version")
    }

    #[test]
    fn build_metadata_is_refused() {
        let refusal = PublishedVersion::parse("1.0.0+b").unwrap_err();
        assert!(
            matches!(refusal, VersionRefusal::BuildMetadata { .. }),
            "{refusal:?}"
        );
        assert!(refusal.to_string().contains("build metadata"), "{refusal}");
    }

    #[test]
    fn build_metadata_is_refused_from_a_parsed_version() {
        let parsed = semver::Version::parse("1.0.0-rc.1+sha.abc").unwrap();
        let refusal = PublishedVersion::from_semver(parsed).unwrap_err();
        assert!(
            matches!(refusal, VersionRefusal::BuildMetadata { .. }),
            "{refusal:?}"
        );
    }

    #[test]
    fn a_malformed_version_is_refused_with_its_input_escaped() {
        let refusal = PublishedVersion::parse("1.0\u{1b}[31m").unwrap_err();
        assert!(
            matches!(refusal, VersionRefusal::Malformed { .. }),
            "{refusal:?}"
        );
        assert!(!refusal.to_string().contains('\u{1b}'), "{refusal}");
    }

    #[test]
    fn a_release_and_a_prerelease_are_admitted() {
        assert_eq!(v("1.2.3").to_string(), "1.2.3");
        assert!(v("1.2.3-rc.1").is_prerelease());
        assert!(!v("1.2.3").is_prerelease());
    }

    #[test]
    fn a_first_publish_admits_any_successor() {
        assert!(require_successor([], &v("0.0.1")).is_ok());
    }

    #[test]
    fn the_greatest_successor_is_admitted() {
        let published = [v("1.0.0"), v("1.1.0"), v("0.9.0")];
        assert!(require_successor(&published, &v("1.1.1")).is_ok());
        assert!(require_successor(&published, &v("2.0.0-rc.1")).is_ok());
    }

    #[test]
    fn a_non_greatest_successor_is_refused() {
        let published = [v("1.0.0"), v("2.0.0")];
        let refusal = require_successor(&published, &v("1.5.0")).unwrap_err();
        assert_eq!(
            refusal,
            VersionRefusal::NotAboveGreatest {
                candidate: v("1.5.0"),
                greatest: v("2.0.0"),
            }
        );
    }

    #[test]
    fn an_equal_successor_is_refused() {
        let refusal = require_successor(&[v("1.0.0")], &v("1.0.0")).unwrap_err();
        assert!(
            matches!(refusal, VersionRefusal::NotAboveGreatest { .. }),
            "{refusal:?}"
        );
    }

    #[test]
    fn a_prerelease_below_its_published_release_is_refused() {
        // `1.0.0-rc.1` precedes `1.0.0` (semver §11): publishing it after the
        // release would go backwards.
        let refusal = require_successor(&[v("1.0.0")], &v("1.0.0-rc.1")).unwrap_err();
        assert!(
            matches!(refusal, VersionRefusal::NotAboveGreatest { .. }),
            "{refusal:?}"
        );
    }
}
