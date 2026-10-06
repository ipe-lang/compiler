//! The `ipe.lock` lockfile: exact resolved dependencies, pinned for a
//! reproducible build.
//!
//! Each locked dependency records the resolved version, where it came from (the
//! source and its exact revision), and the sha256 of the fetched source tree. A
//! build reads these pins rather than re-resolving through the index, so it is
//! reproducible even when the index is unreachable, and the pinned hash lets a
//! later build re-verify the source it fetches.
//!
//! The lockfile is untrusted input (a hand edit or a hostile checkout can put
//! anything in it), so [`Lockfile::read`] parses every field into its typed form
//! once: the name into a [`PackageName`], the hash into a [`Sha256Hex`], and the
//! `source`/`rev`/`kind` triple into one [`LockedOrigin`] whose variants admit
//! only the pairings the resolver writes. Nothing downstream re-encounters a raw
//! lockfile string.
//!
//! Serialization is deterministic: packages are always written sorted by name,
//! so two runs that resolve the same set produce byte-identical lockfiles (a
//! stable diff, no spurious churn).

use std::path::{Path, PathBuf};

use crate::CliError;
use crate::index::{PinnedRev, Sha256Hex, SourceUrl};
use crate::package_name::PackageName;
use crate::published_version::PublishedVersion;

/// The lockfile's filename at a project root.
const LOCKFILE_NAME: &str = "ipe.lock";

/// Why `ipe.lock` cannot record or admit a dependency.
///
/// Rendered through the message catalog; boxed inside
/// [`CliError::LockRefused`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockRefusal {
    /// A `[[package]]` table lacks a required field.
    MissingField {
        /// The absent field's key.
        field: &'static str,
    },
    /// A package's `kind` is neither `index` nor `escape`.
    UnknownKind {
        /// The package carrying the value.
        package: PackageName,
        /// The unrecognised `kind` value, verbatim.
        kind: String,
    },
    /// An index dependency records the `local` rev only a path dependency carries.
    IndexDepLocalRev {
        /// The index dependency.
        package: PackageName,
    },
    /// A path dependency's `source` cannot be written into a quoted lockfile line.
    UnrecordableLocalSource {
        /// The path dependency.
        package: PackageName,
        /// The refused `source` value, verbatim.
        raw: String,
    },
    /// A path dependency's manifest path is not valid UTF-8.
    NonUtf8LocalPath {
        /// The path dependency.
        package: PackageName,
        /// The path as the manifest named it.
        path: PathBuf,
    },
}

impl std::fmt::Display for LockRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            Self::MissingField { field } => crate::text::lock_missing_field(field),
            Self::UnknownKind { package, kind } => {
                crate::text::lock_unknown_kind(package, &kind.escape_debug())
            }
            Self::IndexDepLocalRev { package } => crate::text::lock_index_dep_local_rev(package),
            Self::UnrecordableLocalSource { package, raw } => {
                crate::text::lock_unrecordable_local_source(
                    package,
                    &MAX_LOCAL_SOURCE_LEN,
                    &raw.escape_debug(),
                )
            }
            Self::NonUtf8LocalPath { package, path } => crate::text::lock_non_utf8_local_path(
                package,
                &path.to_string_lossy().escape_debug(),
            ),
        })
    }
}

impl From<LockRefusal> for CliError {
    fn from(refusal: LockRefusal) -> Self {
        Self::LockRefused(Box::new(refusal))
    }
}

/// The on-disk `rev` of a local-path dependency, which has no commit to pin.
const LOCAL_REV: &str = "local";

/// The longest recorded local path, in bytes.
const MAX_LOCAL_SOURCE_LEN: usize = 4096;

/// The recorded location of a `{path=}` dependency, as the author wrote it.
///
/// A path dep's integrity rests on its sha256 alone; the path is provenance. It
/// is still written into a quoted, line-oriented lockfile, so the only
/// inhabitants are non-empty, bounded, UTF-8 strings free of control characters
/// and `"` — a value that could break out of its line or its quotes cannot be
/// recorded or read back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSource(String);

impl LocalSource {
    /// Parse a recorded local path.
    ///
    /// # Errors
    /// [`CliError::LockRefused`] when `raw` is empty, longer than
    /// [`MAX_LOCAL_SOURCE_LEN`] bytes, or contains a control character or `"`.
    pub fn parse(pkg: &PackageName, raw: &str) -> Result<Self, CliError> {
        let recordable = !raw.is_empty()
            && raw.len() <= MAX_LOCAL_SOURCE_LEN
            && !raw.chars().any(|c| c.is_control() || c == '"');
        if !recordable {
            return Err(LockRefusal::UnrecordableLocalSource {
                package: pkg.clone(),
                raw: raw.to_owned(),
            }
            .into());
        }
        Ok(Self(raw.to_owned()))
    }

    /// Record a manifest path, refusing one that is not valid UTF-8.
    ///
    /// # Errors
    /// [`CliError::LockRefused`] when the path is not UTF-8 (a lossy rendering
    /// would record a different path than the one resolved) or fails
    /// [`Self::parse`].
    pub fn from_path(pkg: &PackageName, path: &Path) -> Result<Self, CliError> {
        let raw = path.to_str().ok_or_else(|| LockRefusal::NonUtf8LocalPath {
            package: pkg.clone(),
            path: path.to_path_buf(),
        })?;
        Self::parse(pkg, raw)
    }

    /// The recorded path string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where a locked dependency came from, and the revision that pins it.
///
/// Folds the on-disk `source`, `rev`, and `kind` fields into one value so an
/// impossible pairing — an index dep with no commit, a path dep with a SHA, a
/// URL recorded as a local path — has no representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockedOrigin {
    /// Resolved through the package index at a published, pinned commit.
    Index {
        /// The source repository the index names.
        source: SourceUrl,
        /// The immutable commit the index pins.
        rev: PinnedRev,
    },
    /// A `{git=}` escape, bypassing the index, pinned to its resolved commit.
    Git {
        /// The repository the author named.
        source: SourceUrl,
        /// The immutable commit the requested ref resolved to.
        rev: PinnedRev,
    },
    /// A `{path=}` escape: no commit to pin, integrity is the sha256 alone.
    Path {
        /// The path the author named.
        source: LocalSource,
    },
}

impl LockedOrigin {
    /// The pinned commit, when the origin has one.
    #[must_use]
    pub const fn pinned_rev(&self) -> Option<&PinnedRev> {
        match self {
            Self::Index { rev, .. } | Self::Git { rev, .. } => Some(rev),
            Self::Path { .. } => None,
        }
    }

    /// The on-disk `(source, rev, kind)` fields for this origin.
    fn fields(&self) -> (&str, &str, &str) {
        match self {
            Self::Index { source, rev } => (source.as_str(), rev.as_str(), "index"),
            Self::Git { source, rev } => (source.as_str(), rev.as_str(), "escape"),
            Self::Path { source } => (source.as_str(), LOCAL_REV, "escape"),
        }
    }

    /// Parse the on-disk `source`/`rev`/`kind` fields into an origin.
    ///
    /// Only the pairings the resolver writes are admitted. `kind` is optional
    /// for lockfiles written before it existed: absent, it is inferred from
    /// `version` (escape deps always carry `0.0.0`). Present, it is trusted
    /// directly so an index dep published at `0.0.0` stays an index dep.
    fn parse(
        pkg: &PackageName,
        version: &PublishedVersion,
        source: &str,
        rev: &str,
        kind: Option<&str>,
    ) -> Result<Self, CliError> {
        let escape = match kind {
            Some("index") => false,
            Some("escape") => true,
            Some(other) => {
                return Err(LockRefusal::UnknownKind {
                    package: pkg.clone(),
                    kind: other.to_owned(),
                }
                .into());
            }
            None => *version == PublishedVersion::new(0, 0, 0),
        };
        if rev == LOCAL_REV {
            if !escape {
                return Err(LockRefusal::IndexDepLocalRev {
                    package: pkg.clone(),
                }
                .into());
            }
            return LocalSource::parse(pkg, source).map(|source| Self::Path { source });
        }
        // Fail closed: a non-SHA rev (a legacy "HEAD" or branch) is refused.
        let rev = PinnedRev::from_full_sha(pkg, rev)?;
        let source = SourceUrl::parse(pkg, source)?;
        Ok(if escape {
            Self::Git { source, rev }
        } else {
            Self::Index { source, rev }
        })
    }
}

/// One locked dependency: its exact version, origin, and content hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedDep {
    /// The package name (the lockfile's sort key).
    pub name: PackageName,
    /// The exact resolved version, as the index records it (no build metadata).
    pub version: PublishedVersion,
    /// Where the source came from and the revision that pins it.
    pub origin: LockedOrigin,
    /// The sha256 of the fetched source tree, verified on fetch and re-verifiable
    /// on a later build.
    pub sha256: Sha256Hex,
}

/// The parsed `ipe.lock`: the set of locked dependencies, held sorted by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lockfile {
    packages: Vec<LockedDep>,
}

impl Lockfile {
    /// Read the lockfile at `project_root/ipe.lock`.
    ///
    /// A missing lockfile is an empty lockfile (a project with no locked
    /// dependencies yet), not an error. The file is opened beneath
    /// `project_root` without following a symlink or blocking on a FIFO.
    ///
    /// # Errors
    /// [`CliError::Io`] if the file exists but cannot be read;
    /// [`CliError::SourceRefused`] if it is a symlink or not a regular file;
    /// [`CliError::VersionRefused`] if a `version` is malformed or carries build
    /// metadata; [`CliError::LockRefused`] if a field is missing, a `kind` is
    /// unrecognised, or `source`/`rev`/`kind` pair impossibly;
    /// [`CliError::Resolve`] if a name, source URL, rev, or sha256 is malformed.
    pub fn read(project_root: &Path) -> Result<Self, CliError> {
        let text = match crate::io_bounded::read_named_in(
            project_root,
            &[LOCKFILE_NAME],
            crate::io_bounded::SMALL_FILE_CAP,
        ) {
            Ok(text) => text,
            Err(CliError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(e),
        };
        parse(&text)
    }

    /// Write the lockfile to `project_root/ipe.lock`, packages sorted by name.
    ///
    /// The write is atomic, so an interrupted write never leaves a truncated
    /// lockfile.
    ///
    /// # Errors
    /// [`CliError::Io`] if the file cannot be written.
    pub fn write(&self, project_root: &Path) -> Result<(), CliError> {
        crate::driver::write_atomic(&Self::path(project_root), &self.render())
    }

    /// Insert `dep`, replacing any existing entry with the same name.
    pub fn upsert(&mut self, dep: LockedDep) {
        match self.packages.binary_search_by(|p| p.name.cmp(&dep.name)) {
            Ok(at) => {
                if let Some(slot) = self.packages.get_mut(at) {
                    *slot = dep;
                }
            }
            Err(at) => self.packages.insert(at, dep),
        }
    }

    /// Remove the entry named `name`, returning whether one was present.
    pub fn remove(&mut self, name: &str) -> bool {
        match self
            .packages
            .binary_search_by(|p| p.name.as_str().cmp(name))
        {
            Ok(at) => {
                self.packages.remove(at);
                true
            }
            Err(_) => false,
        }
    }

    /// The locked dependencies, sorted by name.
    #[must_use]
    pub fn packages(&self) -> &[LockedDep] {
        &self.packages
    }

    /// The lockfile path for a project root.
    fn path(project_root: &Path) -> PathBuf {
        project_root.join(LOCKFILE_NAME)
    }

    /// Render the lockfile as deterministic TOML, one table per dependency.
    ///
    /// Every field is a typed value whose alphabet excludes `"` and control
    /// characters, so no rendered value can leave its quotes or its line.
    fn render(&self) -> String {
        use std::fmt::Write as _;
        // Rendered from an already-sorted invariant; sort defensively so a
        // hand-constructed `Lockfile` still writes deterministically.
        let mut packages = self.packages.clone();
        packages.sort_by(|a, b| a.name.cmp(&b.name));
        let mut out = String::from(
            "# ipe.lock — resolved dependencies, pinned for a reproducible build.\n\
             # Generated by `ipe add`; do not edit by hand.\n",
        );
        for dep in &packages {
            let (source, rev, kind) = dep.origin.fields();
            let _ = write!(
                out,
                "\n[[package]]\nname = \"{}\"\nversion = \"{}\"\nsource = \"{source}\"\n\
                 rev = \"{rev}\"\nsha256 = \"{}\"\nkind = \"{kind}\"\n",
                dep.name, dep.version, dep.sha256,
            );
        }
        out
    }
}

/// Parse `ipe.lock` text into a [`Lockfile`], sorted by name.
fn parse(text: &str) -> Result<Lockfile, CliError> {
    let mut packages: Vec<LockedDep> = Vec::new();
    let mut current: Option<RawLocked> = None;

    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[package]]" {
            if let Some(raw) = current.take() {
                packages.push(raw.into_dep()?);
            }
            current = Some(RawLocked::default());
            continue;
        }
        if line.starts_with('[') {
            if let Some(raw) = current.take() {
                packages.push(raw.into_dep()?);
            }
            continue;
        }
        let Some((key, raw_val)) = line.split_once('=') else {
            continue;
        };
        let Some(record) = current.as_mut() else {
            continue;
        };
        let value = unquote(raw_val.trim()).to_owned();
        match key.trim() {
            "name" => record.name = Some(value),
            "version" => record.version = Some(value),
            "source" => record.source = Some(value),
            "rev" => record.rev = Some(value),
            "sha256" => record.sha256 = Some(value),
            "kind" => record.kind = Some(value),
            _ => {}
        }
    }
    if let Some(raw) = current.take() {
        packages.push(raw.into_dep()?);
    }

    packages.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Lockfile { packages })
}

/// The raw per-`[[package]]` fields collected during the line scan.
#[derive(Default)]
struct RawLocked {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    rev: Option<String>,
    sha256: Option<String>,
    kind: Option<String>,
}

impl RawLocked {
    /// Turn the collected fields into a typed [`LockedDep`].
    ///
    /// The name is parsed first, into a [`PackageName`], so every later refusal
    /// names a value already proven free of control bytes and path separators.
    /// The `version` is parsed as a [`PublishedVersion`]: a hand-edited `1.0.0+b`
    /// is refused, since no index entry can carry build metadata. The
    /// `source`/`rev`/`kind` triple is parsed by [`LockedOrigin::parse`], and the
    /// hash by [`Sha256Hex::parse`].
    fn into_dep(self) -> Result<LockedDep, CliError> {
        let missing = |field: &'static str| CliError::from(LockRefusal::MissingField { field });
        let name = PackageName::parse(&self.name.ok_or_else(|| missing("name"))?)?;
        let version_str = self.version.ok_or_else(|| missing("version"))?;
        let version = PublishedVersion::parse(&version_str)
            .map_err(|refusal| refusal.for_package(name.as_str()))?;
        let source = self.source.ok_or_else(|| missing("source"))?;
        let rev = self.rev.ok_or_else(|| missing("rev"))?;
        let origin = LockedOrigin::parse(&name, &version, &source, &rev, self.kind.as_deref())?;
        let raw_sha256 = self.sha256.ok_or_else(|| missing("sha256"))?;
        let sha256 = Sha256Hex::parse(&name, &raw_sha256)?;
        Ok(LockedDep {
            name,
            version,
            origin,
            sha256,
        })
    }
}

/// Strip one layer of surrounding double quotes from a scalar value.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::{
        LocalSource, LockRefusal, LockedDep, LockedOrigin, Lockfile, MAX_LOCAL_SOURCE_LEN,
    };
    use crate::CliError;
    use crate::index::{PinnedRev, Sha256Hex, SourceUrl};
    use crate::package_name::PackageName;
    use crate::published_version::{PublishedVersion, VersionRefusal};
    use std::path::PathBuf;

    /// A valid 40-hex commit SHA used in fixtures.
    const FIXTURE_SHA: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    /// A valid 64-hex content hash used in fixtures.
    const FIXTURE_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn name(raw: &str) -> PackageName {
        PackageName::parse(raw).expect("valid name")
    }

    fn sha256() -> Sha256Hex {
        Sha256Hex::parse(&name("fixture"), FIXTURE_SHA256).expect("valid sha256")
    }

    fn pinned(raw: &str) -> (SourceUrl, PinnedRev) {
        (
            SourceUrl::parse(&name(raw), &format!("https://example.invalid/{raw}"))
                .expect("valid url"),
            PinnedRev::from_full_sha(&name(raw), FIXTURE_SHA).expect("valid sha"),
        )
    }

    fn dep(raw: &str, version: &str) -> LockedDep {
        let (source, rev) = pinned(raw);
        LockedDep {
            name: name(raw),
            version: PublishedVersion::parse(version).expect("valid version"),
            origin: LockedOrigin::Index { source, rev },
            sha256: sha256(),
        }
    }

    fn escape_dep(raw: &str) -> LockedDep {
        let (source, rev) = pinned(raw);
        LockedDep {
            name: name(raw),
            version: PublishedVersion::new(0, 0, 0),
            origin: LockedOrigin::Git { source, rev },
            sha256: sha256(),
        }
    }

    fn path_dep(raw: &str) -> LockedDep {
        let pkg = name(raw);
        let source = LocalSource::parse(&pkg, &format!("../local path/{raw}")).expect("valid");
        LockedDep {
            name: pkg,
            version: PublishedVersion::new(0, 0, 0),
            origin: LockedOrigin::Path { source },
            sha256: sha256(),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-lockfile-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Read `text` as a project's `ipe.lock`.
    fn read_text(tag: &str, text: &str) -> Result<Lockfile, CliError> {
        let root = temp_dir(tag);
        std::fs::write(root.join("ipe.lock"), text).expect("write");
        let read = Lockfile::read(&root);
        let _ = std::fs::remove_dir_all(&root);
        read
    }

    /// A one-package lockfile with the given raw field values.
    fn one_package(name: &str, version: &str, source: &str, rev: &str, kind: &str) -> String {
        format!(
            "# ipe.lock\n\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n\
             source = \"{source}\"\nrev = \"{rev}\"\nsha256 = \"{FIXTURE_SHA256}\"\n{kind}"
        )
    }

    /// Read a one-package lockfile, returning its only dep.
    fn read_one(tag: &str, text: &str) -> LockedDep {
        let lock = read_text(tag, text).expect("read");
        lock.packages().first().expect("one package").clone()
    }

    #[test]
    fn write_then_read_round_trips() {
        let root = temp_dir("roundtrip");
        let mut lock = Lockfile::default();
        lock.upsert(dep("http-extras", "1.2.0"));
        lock.upsert(dep("json-tools", "0.4.1"));
        lock.upsert(escape_dep("myescape"));
        lock.upsert(path_dep("mylocal"));
        lock.write(&root).expect("write");

        let read = Lockfile::read(&root).expect("read");
        assert_eq!(read, lock);
        assert_eq!(read.packages().len(), 4);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn output_is_deterministic_and_sorted() {
        // Insert out of order; both the in-memory order and the rendered text
        // are sorted by name, so a second write is byte-identical.
        let root_a = temp_dir("det-a");
        let root_b = temp_dir("det-b");
        let mut a = Lockfile::default();
        a.upsert(dep("zeta", "1.0.0"));
        a.upsert(dep("alpha", "2.0.0"));
        let mut b = Lockfile::default();
        b.upsert(dep("alpha", "2.0.0"));
        b.upsert(dep("zeta", "1.0.0"));
        a.write(&root_a).expect("write a");
        b.write(&root_b).expect("write b");
        let text_a = std::fs::read_to_string(root_a.join("ipe.lock")).expect("read a");
        let text_b = std::fs::read_to_string(root_b.join("ipe.lock")).expect("read b");
        assert_eq!(text_a, text_b);
        let alpha_at = text_a.find("alpha").expect("alpha present");
        let zeta_at = text_a.find("zeta").expect("zeta present");
        assert!(alpha_at < zeta_at, "packages must be name-sorted");
        let _ = std::fs::remove_dir_all(&root_a);
        let _ = std::fs::remove_dir_all(&root_b);
    }

    #[test]
    fn upsert_replaces_an_existing_entry() {
        let mut lock = Lockfile::default();
        lock.upsert(dep("http-extras", "1.0.0"));
        lock.upsert(dep("http-extras", "1.2.0"));
        assert_eq!(lock.packages().len(), 1);
        let only = lock.packages().first().expect("one package");
        assert_eq!(
            only.version,
            PublishedVersion::parse("1.2.0").expect("valid")
        );
    }

    #[test]
    fn remove_deletes_and_reports_presence() {
        let mut lock = Lockfile::default();
        lock.upsert(dep("http-extras", "1.0.0"));
        assert!(lock.remove("http-extras"));
        assert!(lock.packages().is_empty());
        assert!(
            !lock.remove("http-extras"),
            "removing an absent dep is false"
        );
    }

    #[test]
    fn a_missing_lockfile_reads_as_empty() {
        let root = temp_dir("absent");
        let lock = Lockfile::read(&root).expect("absent lockfile is empty, not an error");
        assert!(lock.packages().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn path_dep_is_written_with_a_local_rev() {
        let root = temp_dir("path-local-rev");
        let mut lock = Lockfile::default();
        lock.upsert(path_dep("mylocal"));
        lock.write(&root).expect("write");
        let text = std::fs::read_to_string(root.join("ipe.lock")).expect("read");
        assert!(text.contains("rev = \"local\"\n"), "{text}");
        assert!(text.contains("kind = \"escape\"\n"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    fn read_with_version(tag: &str, version: &str) -> Result<Lockfile, CliError> {
        read_text(
            tag,
            &one_package(
                "mylib",
                version,
                "https://example.invalid/mylib",
                FIXTURE_SHA,
                "kind = \"index\"\n",
            ),
        )
    }

    #[test]
    fn build_metadata_version_fails_closed_on_read() {
        // No index entry carries build metadata, so a hand-edited `1.0.0+b`
        // would pin a release the index can never serve.
        let err = read_with_version("build-meta", "1.0.0+b").unwrap_err();
        assert!(
            matches!(
                &err,
                CliError::VersionRefused { package, refusal }
                    if package == "mylib"
                        && matches!(**refusal, VersionRefusal::BuildMetadata { .. })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn malformed_version_fails_closed_on_read() {
        let err = read_with_version("malformed", "1.0").unwrap_err();
        assert!(
            matches!(
                &err,
                CliError::VersionRefused { refusal, .. }
                    if matches!(**refusal, VersionRefusal::Malformed { .. })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn prerelease_version_is_read() {
        let read = read_with_version("prerelease", "1.0.0-rc.1").expect("prerelease is valid");
        let only = read.packages().first().expect("one package");
        assert_eq!(only.version.to_string(), "1.0.0-rc.1");
    }

    #[test]
    fn moving_revs_fail_closed_on_read() {
        for rev in ["HEAD", "main", "deadbeef"] {
            let text = one_package("mylib", "1.0.0", "https://example.invalid/mylib", rev, "");
            let msg = read_text("moving-rev", &text).unwrap_err().to_string();
            assert!(
                msg.contains("immutable commit SHA"),
                "rev {rev:?} must be refused as not a SHA, got: {msg}"
            );
        }
    }

    #[test]
    fn origins_read_back_by_kind() {
        let index = read_one(
            "origin-index",
            &one_package(
                "mypkg",
                "1.2.0",
                "https://example.invalid/mypkg",
                FIXTURE_SHA,
                "kind = \"index\"\n",
            ),
        );
        assert!(matches!(index.origin, LockedOrigin::Index { .. }));
        let git = read_one(
            "origin-git",
            &one_package(
                "myescape",
                "0.0.0",
                "https://example.invalid/myescape",
                FIXTURE_SHA,
                "kind = \"escape\"\n",
            ),
        );
        assert!(matches!(git.origin, LockedOrigin::Git { .. }));
        assert_eq!(
            git.origin.pinned_rev().map(PinnedRev::as_str),
            Some(FIXTURE_SHA)
        );
        let path = read_one(
            "origin-path",
            &one_package(
                "mylocal",
                "0.0.0",
                "../libs/mylocal",
                "local",
                "kind = \"escape\"\n",
            ),
        );
        assert!(matches!(path.origin, LockedOrigin::Path { .. }));
        assert_eq!(path.origin.pinned_rev(), None);
    }

    #[test]
    fn pathological_index_dep_at_0_0_0_is_not_misclassified() {
        // An index dep published at exactly 0.0.0 stays an index dep when the
        // `kind` tag says so.
        let entry = read_one(
            "pathological-index",
            &one_package(
                "weirdpkg",
                "0.0.0",
                "https://example.invalid/weirdpkg",
                FIXTURE_SHA,
                "kind = \"index\"\n",
            ),
        );
        assert!(matches!(entry.origin, LockedOrigin::Index { .. }));
    }

    #[test]
    fn legacy_lockfile_without_kind_infers_from_version() {
        // Without a `kind` line: version 0.0.0 infers an escape, anything else
        // an index dep.
        let escape = read_one(
            "legacy-escape",
            &one_package(
                "oldescape",
                "0.0.0",
                "https://example.invalid/oldescape",
                FIXTURE_SHA,
                "",
            ),
        );
        assert!(matches!(escape.origin, LockedOrigin::Git { .. }));
        let index = read_one(
            "legacy-index",
            &one_package(
                "oldindex",
                "1.2.0",
                "https://example.invalid/oldindex",
                FIXTURE_SHA,
                "",
            ),
        );
        assert!(matches!(index.origin, LockedOrigin::Index { .. }));
        let path = read_one(
            "legacy-path",
            &one_package("oldlocal", "0.0.0", "/abs/oldlocal", "local", ""),
        );
        assert!(matches!(path.origin, LockedOrigin::Path { .. }));
    }

    #[test]
    fn unrecognised_kind_value_fails_closed() {
        let text = one_package(
            "mypkg",
            "1.0.0",
            "https://example.invalid/mypkg",
            FIXTURE_SHA,
            "kind = \"frobnicator\"\n",
        );
        let err = read_text("bad-kind", &text).unwrap_err();
        assert!(
            matches!(&err, CliError::LockRefused(r) if matches!(**r, LockRefusal::UnknownKind { .. })),
            "{err:?}"
        );
        assert_eq!(err.machine_kind(), "lock-refused");
        let msg = err.to_string();
        assert!(
            msg.contains("unrecognised `kind` value \"frobnicator\""),
            "{msg}"
        );
    }

    #[test]
    fn an_index_dep_with_a_local_rev_is_refused() {
        for kind in ["kind = \"index\"\n", ""] {
            let text = one_package("mypkg", "1.0.0", "/abs/mypkg", "local", kind);
            let msg = read_text("index-local", &text).unwrap_err().to_string();
            assert!(msg.contains("index dependency"), "{kind:?}: {msg}");
        }
    }

    #[test]
    fn a_hostile_name_is_refused_on_read() {
        for hostile in ["..", "../../evil", "/abs", "a/b", "Evil", "a\u{1b}[2Jb", ""] {
            let text = one_package(
                hostile,
                "1.0.0",
                "https://example.invalid/x",
                FIXTURE_SHA,
                "",
            );
            let err = read_text("hostile-name", &text).unwrap_err();
            assert!(matches!(err, CliError::Resolve(_)), "{hostile:?}: {err:?}");
            assert!(
                !err.to_string().contains('\u{1b}'),
                "a refusal must not echo a raw control byte: {err:?}"
            );
        }
    }

    #[test]
    fn a_malformed_sha256_is_refused_on_read() {
        let too_short = FIXTURE_SHA256.get(..63).expect("63 chars");
        let upper = FIXTURE_SHA256.to_uppercase();
        let non_hex = "g".repeat(64);
        for bad in ["", "abc", too_short, upper.as_str(), non_hex.as_str()] {
            let text = format!(
                "[[package]]\nname = \"mylib\"\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/mylib\"\nrev = \"{FIXTURE_SHA}\"\n\
                 sha256 = \"{bad}\"\n"
            );
            let msg = read_text("bad-sha256", &text).unwrap_err().to_string();
            assert!(msg.contains("sha256"), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn a_missing_sha256_is_refused_on_read() {
        let text = format!(
            "[[package]]\nname = \"mylib\"\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/mylib\"\nrev = \"{FIXTURE_SHA}\"\n"
        );
        let err = read_text("no-sha256", &text).unwrap_err();
        assert!(
            matches!(&err, CliError::LockRefused(r)
                if **r == LockRefusal::MissingField { field: "sha256" }),
            "{err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("missing `sha256`"), "{msg}");
    }

    #[test]
    fn an_unsafe_git_source_is_refused_on_read() {
        for bad in [
            "",
            "relative/repo",
            "-uhack",
            "ext::sh -c evil",
            "https://example.invalid/a\"b",
            "https://example.invalid/a\u{7}b",
        ] {
            let text = one_package("mylib", "1.0.0", bad, FIXTURE_SHA, "");
            let msg = read_text("bad-source", &text).unwrap_err().to_string();
            assert!(msg.contains("source"), "{bad:?}: {msg}");
        }
    }

    #[test]
    fn an_unsafe_local_source_is_refused_on_read() {
        let long = "a".repeat(MAX_LOCAL_SOURCE_LEN + 1);
        for bad in ["", "a\"b", "a\u{7}b", "a\tb", long.as_str()] {
            let text = one_package("mylib", "0.0.0", bad, "local", "kind = \"escape\"\n");
            let msg = read_text("bad-local", &text).unwrap_err().to_string();
            assert!(msg.contains("path dependency"), "{msg}");
        }
    }

    #[test]
    fn local_source_refuses_a_line_break() {
        // A newline could forge a following lockfile field; it never becomes a
        // recorded path.
        let pkg = name("mylib");
        assert!(LocalSource::parse(&pkg, "dir\"\nsha256 = \"0").is_err());
        assert!(LocalSource::parse(&pkg, "dir\nrev = \"x\"").is_err());
        assert!(LocalSource::parse(&pkg, "../ok dir/lib").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn local_source_refuses_a_non_utf8_path() {
        use std::os::unix::ffi::OsStrExt as _;
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(b"lib\xff"));
        let err = LocalSource::from_path(&name("mylib"), path).unwrap_err();
        assert!(
            matches!(&err, CliError::LockRefused(r) if matches!(**r, LockRefusal::NonUtf8LocalPath { .. })),
            "{err:?}"
        );
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_local_path_refusal_escapes_control_characters() {
        use std::os::unix::ffi::OsStrExt as _;
        // A terminal escape in the refused path must not reach the rendered
        // diagnostic raw, or it would drive the user's terminal.
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(b"lib\x1b[2J\n\xff"));
        let msg = LocalSource::from_path(&name("mylib"), path)
            .unwrap_err()
            .to_string();
        assert!(!msg.contains('\x1b'), "{msg:?}");
        assert!(!msg.contains("[2J\n"), "{msg:?}");
        assert!(msg.contains("\\u{1b}[2J\\n"), "{msg:?}");
    }

    /// A FIFO planted as `ipe.lock` is refused at once, never waited on for a writer.
    #[cfg(unix)]
    #[test]
    fn a_fifo_ipe_lock_is_refused_not_hung() {
        let root = temp_dir("fifo-lock");
        let made = std::process::Command::new("mkfifo")
            .arg(root.join("ipe.lock"))
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
        let (tx, rx) = std::sync::mpsc::channel();
        let reader_root = root.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Lockfile::read(&reader_root));
        });
        let outcome = rx.recv_timeout(std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(
                outcome,
                Ok(Err(CliError::SourceRefused {
                    reason: crate::io_bounded::SourceRefusal::NotRegularFile,
                    ..
                }))
            ),
            "a FIFO lockfile is refused without blocking: {outcome:?}"
        );
    }

    /// A symlinked `ipe.lock` is refused by name, never read through.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_ipe_lock_is_refused() {
        let root = temp_dir("link-lock");
        let elsewhere = root.join("elsewhere.lock");
        std::fs::write(&elsewhere, "").expect("write target");
        std::os::unix::fs::symlink(&elsewhere, root.join("ipe.lock")).expect("link lockfile");
        let read = Lockfile::read(&root);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(
                read,
                Err(CliError::SourceRefused {
                    reason: crate::io_bounded::SourceRefusal::Symlink,
                    ..
                })
            ),
            "a symlinked lockfile is refused: {read:?}"
        );
    }
}
