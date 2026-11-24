//! The one dependency set every emitted crate's `Cargo.lock` derives from.
//!
//! The set is the workspace `Cargo.lock` this `ipe` binary was built and
//! tested with, embedded at build time and parsed once into a closed type:
//! every package is a crates.io `name version checksum` triple, and any other
//! source or a missing checksum refuses the set. A crate's own lock is parsed
//! by the same grammar and judged against the set: every registry package it
//! locks must be one pin exactly, so a build can never link a crate version
//! ipe was not tested with without an [`LockDrift`] refusal at ipe time.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::OnceLock;

use ipe_fs_open::ByteCap;
use semver::Version;

use crate::text;

/// The embedded workspace lock: the dependency set CI built and tested.
const SEED: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));

/// The only registry source a pin may name.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// The lockfile format version the grammar reads.
const LOCK_FORMAT: i64 = 4;

/// The longest crate name the grammar accepts.
const NAME_MAX: usize = 64;

/// The most characters of a foreign source or an unknown key a refusal keeps.
const SHOWN_MAX: usize = 128;

/// The bytes of [`LOCK_CAP`].
const LOCK_READ_BYTES: u64 = 8 * 1024 * 1024;

/// The most bytes a `Cargo.lock` read for judging may hold.
pub const LOCK_CAP: ByteCap =
    ByteCap::from_nonzero(const { NonZeroU64::MIN.saturating_add(LOCK_READ_BYTES - 1) });

/// A crate name the lock grammar accepts: ASCII alphanumerics, `-` and `_`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CrateName(String);

impl CrateName {
    /// The name `raw`, when it is one the grammar accepts.
    fn parse(raw: &str) -> Option<Self> {
        let legal = (1..=NAME_MAX).contains(&raw.len())
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        legal.then(|| Self(raw.to_owned()))
    }

    /// The name as written in the lock.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CrateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A registry checksum: 64 lowercase hexadecimal digits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// The checksum `raw`, when it is 64 lowercase hexadecimal digits.
    fn parse(raw: &str) -> Option<Self> {
        let legal = raw.len() == 64
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        legal.then(|| Self(raw.to_owned()))
    }
}

/// The registry a pin comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrySource {
    /// The crates.io index.
    CratesIo,
}

/// One package of the pinned set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The pinned version.
    pub version: Version,
    /// The registry it comes from.
    pub source: RegistrySource,
    /// The checksum of its published archive.
    pub checksum: Sha256Hex,
}

/// Where one package of a parsed lock comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A path package: a workspace member or the crate itself.
    Local,
    /// The crates.io index, with the checksum the lock records, if any.
    CratesIo {
        /// The recorded checksum.
        checksum: Option<Sha256Hex>,
    },
    /// Any other source: a git repository, another registry, a local registry.
    Foreign {
        /// The source string, at most [`SHOWN_MAX`] characters of it.
        source: String,
    },
}

/// One dependency edge of a locked package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepRef {
    /// The depended-on package's name.
    pub name: CrateName,
    /// Its version, when the lock names one (only when several are locked).
    pub version: Option<Version>,
}

/// One `[[package]]` of a parsed lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    /// The package name.
    pub name: CrateName,
    /// The locked version.
    pub version: Version,
    /// Where it comes from.
    pub origin: Origin,
    /// The packages it depends on.
    pub dependencies: Vec<DepRef>,
}

/// A `Cargo.lock` parsed by the closed grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockFile {
    /// Every package, in lock order.
    pub packages: Vec<LockedPackage>,
}

/// The lock field a malformed value was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockField {
    /// The top-level `version`.
    FormatVersion,
    /// The `package` array or one of its tables.
    Package,
    /// A package's `name`.
    Name,
    /// A package's `version`.
    Version,
    /// A package's `source`.
    Source,
    /// A package's `checksum`.
    Checksum,
    /// A package's `dependencies` array.
    Dependencies,
    /// One entry of a package's `dependencies`.
    Dependency,
}

impl LockField {
    /// The key as the lock spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FormatVersion | Self::Version => "version",
            Self::Package => "package",
            Self::Name => "name",
            Self::Source => "source",
            Self::Checksum => "checksum",
            Self::Dependencies | Self::Dependency => "dependencies",
        }
    }
}

/// Why a lock text is not one the closed grammar reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockParseError {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// The text is not TOML.
    NotToml,
    /// The format `version` is absent or not [`LOCK_FORMAT`].
    FormatVersion,
    /// A key the grammar does not know, at most [`SHOWN_MAX`] characters of it.
    UnknownKey(String),
    /// A known key holds a value of the wrong shape.
    Malformed(LockField),
}

impl fmt::Display for LockParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str(text::lock_parse_not_utf8()),
            Self::NotToml => f.write_str(text::lock_parse_not_toml()),
            Self::FormatVersion => f.write_str(&text::lock_parse_format_version(&LOCK_FORMAT)),
            Self::UnknownKey(key) => f.write_str(&text::lock_parse_unknown_key(key)),
            Self::Malformed(field) => f.write_str(&text::lock_parse_malformed(&field.as_str())),
        }
    }
}

/// Why the embedded set is not a pinned set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinnedSetError {
    /// The embedded lock does not parse.
    Parse(LockParseError),
    /// A package comes from a source other than crates.io.
    ForeignSource {
        /// The package.
        name: CrateName,
        /// Its source.
        source: String,
    },
    /// A registry package records no checksum.
    MissingChecksum {
        /// The package.
        name: CrateName,
        /// Its version.
        version: Version,
    },
}

impl fmt::Display for PinnedSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(reason) => reason.fmt(f),
            Self::ForeignSource { name, source } => {
                f.write_str(&text::pinned_set_foreign_source(name, source))
            }
            Self::MissingChecksum { name, version } => {
                f.write_str(&text::pinned_set_missing_checksum(name, version))
            }
        }
    }
}

/// The crate that asks a moved package for its locked version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requester {
    /// A path package: the project's own crate.
    Project {
        /// Its package name.
        name: CrateName,
    },
    /// A registry or foreign package the lock holds.
    Crate {
        /// Its name.
        name: CrateName,
        /// Its locked version.
        version: Version,
    },
}

/// How a crate's lock disagrees with the pinned set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockDrift {
    /// A registry package whose name the set does not hold at any compatible version.
    Unpinned {
        /// The package.
        name: CrateName,
        /// Its locked version.
        version: Version,
    },
    /// A package the set pins at a semver-compatible version other than the locked one.
    Moved {
        /// The package.
        name: CrateName,
        /// The locked version.
        locked: Version,
        /// The compatible version the set pins.
        pinned: Version,
        /// The crate whose requirement forced the locked version, when one is found.
        requested_by: Option<Requester>,
    },
    /// A pinned version locked with another checksum, or with none.
    ChecksumDiffers {
        /// The package.
        name: CrateName,
        /// Its version.
        version: Version,
    },
    /// A package from a source other than crates.io.
    ForeignSource {
        /// The package.
        name: CrateName,
        /// Its source.
        source: String,
    },
    /// The lock is not one the closed grammar reads.
    Unparsable(LockParseError),
    /// The wrapper workspace lock's bytes are not the embedded set's.
    WrapperDiffers,
    /// The embedded set itself does not parse.
    SetUnreadable(PinnedSetError),
}

impl fmt::Display for LockDrift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unpinned { name, version } => {
                f.write_str(&text::lock_drift_unpinned(name, version))
            }
            Self::Moved {
                name,
                locked,
                pinned,
                requested_by,
            } => match requested_by {
                Some(Requester::Project { name: project }) => f.write_str(
                    &text::lock_drift_moved_by_project(name, locked, pinned, project),
                ),
                Some(Requester::Crate {
                    name: requester,
                    version,
                }) => f.write_str(&text::lock_drift_moved_by_crate(
                    name, locked, pinned, requester, version,
                )),
                None => f.write_str(&text::lock_drift_moved_unrequested(name, locked, pinned)),
            },
            Self::ChecksumDiffers { name, version } => {
                f.write_str(&text::lock_drift_checksum(name, version))
            }
            Self::ForeignSource { name, source } => {
                f.write_str(&text::lock_drift_foreign_source(name, source))
            }
            Self::Unparsable(reason) => f.write_str(&text::lock_drift_unparsable(reason)),
            Self::WrapperDiffers => f.write_str(text::lock_drift_wrapper_differs()),
            Self::SetUnreadable(reason) => f.write_str(&text::lock_drift_set_unreadable(reason)),
        }
    }
}

/// Whether the crate a lock serves links user Rust crates through FFI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiPosture {
    /// ipe's own emitted graph only: every registry package must be a pin.
    FfiFree,
    /// The crate also depends on user crates: names the set lacks are the user's.
    FfiBearing,
}

/// Whether a posture lets one drift through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The drift is the user's own addition.
    Admit,
    /// The drift is refused.
    Refuse,
}

impl FfiPosture {
    /// Whether this posture admits `drift`.
    ///
    /// Only an FFI-bearing crate admits anything, and only a name the set
    /// does not hold: a pin never moves, under any posture.
    #[must_use]
    pub const fn admits(self, drift: &LockDrift) -> Admission {
        match (self, drift) {
            (Self::FfiBearing, LockDrift::Unpinned { .. }) => Admission::Admit,
            (Self::FfiFree, LockDrift::Unpinned { .. })
            | (
                Self::FfiFree | Self::FfiBearing,
                LockDrift::Moved { .. }
                | LockDrift::ChecksumDiffers { .. }
                | LockDrift::ForeignSource { .. }
                | LockDrift::Unparsable(_)
                | LockDrift::WrapperDiffers
                | LockDrift::SetUnreadable(_),
            ) => Admission::Refuse,
        }
    }
}

/// A lock refused against the pinned set: which lock, under which posture, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockRefusal {
    /// The refused `Cargo.lock`.
    pub lock: PathBuf,
    /// The posture it was judged under.
    pub posture: FfiPosture,
    /// The disagreement.
    pub drift: LockDrift,
}

impl LockRefusal {
    /// Who the refusal belongs to.
    ///
    /// A drift in ipe's own graph, or a lock or set ipe cannot read, is ipe's;
    /// a drift a user crate brings, or a wrapper checkout edited after `ipe`
    /// was built, is the user's.
    #[must_use]
    pub const fn fault(&self) -> crate::screen::Fault {
        use crate::screen::Fault::{Internal, User};
        match (self.posture, &self.drift) {
            (_, LockDrift::Unparsable(_) | LockDrift::SetUnreadable(_))
            | (
                FfiPosture::FfiFree,
                LockDrift::Unpinned { .. }
                | LockDrift::Moved { .. }
                | LockDrift::ChecksumDiffers { .. }
                | LockDrift::ForeignSource { .. },
            ) => Internal,
            (_, LockDrift::WrapperDiffers)
            | (
                FfiPosture::FfiBearing,
                LockDrift::Unpinned { .. }
                | LockDrift::Moved { .. }
                | LockDrift::ChecksumDiffers { .. }
                | LockDrift::ForeignSource { .. },
            ) => User,
        }
    }
}

impl fmt::Display for LockRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&text::cli_lock_drift(&self.lock.display(), &self.drift))
    }
}

/// Proof that a lock holds only pins, or additions its posture admits.
///
/// Only [`PinnedSet::judge`] constructs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct Agrees(());

/// The pinned dependency set: every crates.io package the workspace lock holds.
#[derive(Debug)]
pub struct PinnedSet {
    by_name: BTreeMap<CrateName, Vec<Pin>>,
    seed: &'static [u8],
}

/// The embedded set, parsed on first use.
static PINNED: OnceLock<Result<PinnedSet, PinnedSetError>> = OnceLock::new();

/// The embedded pinned set.
///
/// # Errors
/// [`LockDrift::SetUnreadable`] when the embedded lock is not a pinned set.
pub fn pinned_set() -> Result<&'static PinnedSet, LockDrift> {
    PINNED
        .get_or_init(|| PinnedSet::from_seed(SEED))
        .as_ref()
        .map_err(|e| LockDrift::SetUnreadable(e.clone()))
}

impl PinnedSet {
    /// The set `seed` pins.
    ///
    /// # Errors
    /// [`PinnedSetError`] when `seed` does not parse, names a non-crates.io
    /// source, or locks a registry package without a checksum.
    pub fn from_seed(seed: &'static [u8]) -> Result<Self, PinnedSetError> {
        let text = std::str::from_utf8(seed)
            .map_err(|_| PinnedSetError::Parse(LockParseError::NotUtf8))?;
        let lock = LockFile::parse(text).map_err(PinnedSetError::Parse)?;
        let mut by_name: BTreeMap<CrateName, Vec<Pin>> = BTreeMap::new();
        for package in lock.packages {
            let checksum = match package.origin {
                Origin::Local => continue,
                Origin::Foreign { source } => {
                    return Err(PinnedSetError::ForeignSource {
                        name: package.name,
                        source,
                    });
                }
                Origin::CratesIo { checksum: None } => {
                    return Err(PinnedSetError::MissingChecksum {
                        name: package.name,
                        version: package.version,
                    });
                }
                Origin::CratesIo {
                    checksum: Some(checksum),
                } => checksum,
            };
            by_name.entry(package.name).or_default().push(Pin {
                version: package.version,
                source: RegistrySource::CratesIo,
                checksum,
            });
        }
        Ok(Self { by_name, seed })
    }

    /// The embedded lock's bytes, exactly as CI tested them.
    #[must_use]
    pub const fn seed_bytes(&self) -> &'static [u8] {
        self.seed
    }

    /// Whether the set pins `name` at any version.
    #[must_use]
    pub fn holds(&self, name: &str) -> bool {
        CrateName::parse(name).is_some_and(|name| self.by_name.contains_key(&name))
    }

    /// Judge the lock text `text` under `posture`.
    ///
    /// # Errors
    /// [`LockDrift::Unparsable`] when `text` is not a lock the grammar reads;
    /// otherwise as [`Self::judge`].
    pub fn judge_text(&self, text: &str, posture: FfiPosture) -> Result<Agrees, LockDrift> {
        let lock = LockFile::parse(text).map_err(LockDrift::Unparsable)?;
        self.judge(&lock, posture)
    }

    /// Judge `lock` under `posture`: every registry package must be one pin.
    ///
    /// Path packages are the crate's own. The first package `posture` does
    /// not admit, in lock order, is the verdict.
    ///
    /// # Errors
    /// The first [`LockDrift`] `posture` refuses.
    pub fn judge(&self, lock: &LockFile, posture: FfiPosture) -> Result<Agrees, LockDrift> {
        for package in &lock.packages {
            let drift = match &package.origin {
                Origin::Local => None,
                Origin::Foreign { source } => Some(LockDrift::ForeignSource {
                    name: package.name.clone(),
                    source: source.clone(),
                }),
                Origin::CratesIo { checksum } => {
                    self.registry_drift(lock, package, checksum.as_ref())
                }
            };
            if let Some(drift) = drift {
                match posture.admits(&drift) {
                    Admission::Admit => {}
                    Admission::Refuse => return Err(drift),
                }
            }
        }
        Ok(Agrees(()))
    }

    /// How the crates.io `package` of `lock`, recorded with `checksum`, disagrees with its pin.
    fn registry_drift(
        &self,
        lock: &LockFile,
        package: &LockedPackage,
        checksum: Option<&Sha256Hex>,
    ) -> Option<LockDrift> {
        let unpinned = || LockDrift::Unpinned {
            name: package.name.clone(),
            version: package.version.clone(),
        };
        let Some(pins) = self.by_name.get(&package.name) else {
            return Some(unpinned());
        };
        if let Some(pin) = pins.iter().find(|pin| pin.version == package.version) {
            return (checksum != Some(&pin.checksum)).then(|| LockDrift::ChecksumDiffers {
                name: package.name.clone(),
                version: package.version.clone(),
            });
        }
        pins.iter()
            .find(|pin| compatible(&pin.version, &package.version))
            .map_or_else(
                || Some(unpinned()),
                |pin| {
                    Some(LockDrift::Moved {
                        name: package.name.clone(),
                        locked: package.version.clone(),
                        pinned: pin.version.clone(),
                        requested_by: self.requester(lock, package),
                    })
                },
            )
    }

    /// Whether `package` is exactly one pin by name and version.
    fn pins_exactly(&self, package: &LockedPackage) -> bool {
        matches!(package.origin, Origin::CratesIo { .. })
            && self
                .by_name
                .get(&package.name)
                .is_some_and(|pins| pins.iter().any(|pin| pin.version == package.version))
    }

    /// The crate of `lock` whose requirement locked `moved`.
    ///
    /// A dependent that is not itself a pin is preferred: a pinned dependent
    /// accepts the pinned version too, so the user crate beside it forced the
    /// move.
    fn requester(&self, lock: &LockFile, moved: &LockedPackage) -> Option<Requester> {
        let mut dependents = lock.packages.iter().filter(|package| {
            package.dependencies.iter().any(|dep| {
                dep.name == moved.name
                    && dep
                        .version
                        .as_ref()
                        .is_none_or(|version| *version == moved.version)
            })
        });
        let first = dependents.clone().next();
        dependents
            .find(|package| !self.pins_exactly(package))
            .or(first)
            .map(|package| match package.origin {
                Origin::Local => Requester::Project {
                    name: package.name.clone(),
                },
                Origin::CratesIo { .. } | Origin::Foreign { .. } => Requester::Crate {
                    name: package.name.clone(),
                    version: package.version.clone(),
                },
            })
    }
}

/// Whether one caret requirement admits both `a` and `b`.
///
/// The cargo compatibility buckets: the same major from `1.0.0` on, the same
/// minor below it, the exact patch below `0.1.0`.
fn compatible(a: &Version, b: &Version) -> bool {
    match (a.major, a.minor) {
        (0, 0) => b.major == 0 && b.minor == 0 && a.patch == b.patch,
        (0, minor) => b.major == 0 && b.minor == minor,
        (major, _) => b.major == major,
    }
}

impl LockFile {
    /// Parse `text` by the closed lockfile grammar.
    ///
    /// The top level holds exactly `version = 4` and the `package` array;
    /// a package holds `name`, `version`, and optionally `source`,
    /// `checksum` and `dependencies`. Any other key is refused.
    ///
    /// # Errors
    /// [`LockParseError`] naming the first defect.
    pub fn parse(text: &str) -> Result<Self, LockParseError> {
        let table = text
            .parse::<toml::Table>()
            .map_err(|_| LockParseError::NotToml)?;
        let mut format = None;
        let mut packages = Vec::new();
        for (key, value) in &table {
            match key.as_str() {
                "version" => format = value.as_integer(),
                "package" => {
                    let array = value
                        .as_array()
                        .ok_or(LockParseError::Malformed(LockField::Package))?;
                    packages = array.iter().map(parse_package).collect::<Result<_, _>>()?;
                }
                other => return Err(LockParseError::UnknownKey(shown(other))),
            }
        }
        if format != Some(LOCK_FORMAT) {
            return Err(LockParseError::FormatVersion);
        }
        Ok(Self { packages })
    }
}

/// At most [`SHOWN_MAX`] characters of `raw`.
fn shown(raw: &str) -> String {
    raw.chars().take(SHOWN_MAX).collect()
}

/// The string `value` of `field`.
fn string_of(value: &toml::Value, field: LockField) -> Result<&str, LockParseError> {
    value.as_str().ok_or(LockParseError::Malformed(field))
}

/// The version string `raw` of `field`, parsed.
fn version_of(raw: &str, field: LockField) -> Result<Version, LockParseError> {
    Version::parse(raw).map_err(|_| LockParseError::Malformed(field))
}

/// The fields of one `[[package]]` table as read, before they are proven whole.
#[derive(Default)]
struct PackageFields {
    name: Option<CrateName>,
    version: Option<Version>,
    source: Option<String>,
    checksum: Option<Sha256Hex>,
    dependencies: Vec<DepRef>,
}

/// One `[[package]]` table of a lock.
fn parse_package(value: &toml::Value) -> Result<LockedPackage, LockParseError> {
    let table = value
        .as_table()
        .ok_or(LockParseError::Malformed(LockField::Package))?;
    let mut fields = PackageFields::default();
    for (key, value) in table {
        match key.as_str() {
            "name" => {
                fields.name = Some(
                    CrateName::parse(string_of(value, LockField::Name)?)
                        .ok_or(LockParseError::Malformed(LockField::Name))?,
                );
            }
            "version" => {
                fields.version = Some(version_of(
                    string_of(value, LockField::Version)?,
                    LockField::Version,
                )?);
            }
            "source" => fields.source = Some(string_of(value, LockField::Source)?.to_owned()),
            "checksum" => {
                fields.checksum = Some(
                    Sha256Hex::parse(string_of(value, LockField::Checksum)?)
                        .ok_or(LockParseError::Malformed(LockField::Checksum))?,
                );
            }
            "dependencies" => {
                fields.dependencies = value
                    .as_array()
                    .ok_or(LockParseError::Malformed(LockField::Dependencies))?
                    .iter()
                    .map(parse_dependency)
                    .collect::<Result<_, _>>()?;
            }
            other => return Err(LockParseError::UnknownKey(shown(other))),
        }
    }
    let name = fields
        .name
        .ok_or(LockParseError::Malformed(LockField::Name))?;
    let version = fields
        .version
        .ok_or(LockParseError::Malformed(LockField::Version))?;
    let origin = match (fields.source, fields.checksum) {
        (None, None) => Origin::Local,
        (None, Some(_)) => return Err(LockParseError::Malformed(LockField::Checksum)),
        (Some(source), checksum) if source == CRATES_IO => Origin::CratesIo { checksum },
        (Some(source), Some(_) | None) => Origin::Foreign {
            source: shown(&source),
        },
    };
    Ok(LockedPackage {
        name,
        version,
        origin,
        dependencies: fields.dependencies,
    })
}

/// One `dependencies` entry: `name`, `name version`, or `name version (source)`.
fn parse_dependency(value: &toml::Value) -> Result<DepRef, LockParseError> {
    let raw = string_of(value, LockField::Dependency)?;
    let (name, rest) = raw
        .split_once(' ')
        .map_or((raw, None), |(name, rest)| (name, Some(rest)));
    let name = CrateName::parse(name).ok_or(LockParseError::Malformed(LockField::Dependency))?;
    let version = rest
        .map(|rest| {
            let version = rest
                .split_once(' ')
                .map_or(rest, |(version, _source)| version);
            version_of(version, LockField::Dependency)
        })
        .transpose()?;
    Ok(DepRef { name, version })
}

#[cfg(test)]
mod tests {
    use super::{
        Admission, FfiPosture, LockDrift, LockField, LockParseError, LockRefusal, PinnedSet,
        PinnedSetError, Requester, SEED, pinned_set,
    };

    /// A checksum of 64 `a`s.
    const SUM_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A small pinned set: `serde_json` 1.0.140 and `itoa` 1.0.15, plus a path member.
    const SET: &[u8] = b"version = 4\n\n\
        [[package]]\nname = \"member\"\nversion = \"0.1.0\"\ndependencies = [\"serde_json\"]\n\n\
        [[package]]\nname = \"itoa\"\nversion = \"1.0.15\"\n\
        source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
        checksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\n\
        [[package]]\nname = \"serde_json\"\nversion = \"1.0.140\"\n\
        source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
        checksum = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n\
        dependencies = [\"itoa\"]\n";

    /// The small set, parsed.
    fn set() -> Option<PinnedSet> {
        PinnedSet::from_seed(SET).ok()
    }

    /// One crates.io `[[package]]` table.
    fn registry(name: &str, version: &str, sum: &str, deps: &str) -> String {
        format!(
            "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{sum}\"\ndependencies = [{deps}]\n\n"
        )
    }

    /// A lock whose root `app` depends on `deps`, then `packages`.
    fn lock(deps: &str, packages: &str) -> String {
        format!(
            "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [{deps}]\n\n{packages}"
        )
    }

    #[test]
    fn the_embedded_set_parses_and_holds_every_emitted_crate() {
        use ipe_backend_rust::crate_specs as specs;
        let set = pinned_set();
        assert!(set.is_ok(), "the workspace lock is a pinned set: {set:?}");
        let Ok(set) = set else { return };
        assert_eq!(set.seed_bytes(), SEED);
        assert!(
            u64::try_from(SEED.len()).is_ok_and(|len| len <= super::LOCK_CAP.get()),
            "the seed fits the lock read cap"
        );
        let emitted = [
            specs::TOKIO,
            specs::SQLX.spec,
            specs::AXUM.spec,
            specs::TOWER_HTTP.spec,
            specs::TOWER,
            specs::ASYNC_TRAIT,
            specs::RUSTIX,
            specs::CROSSTERM,
            specs::UNICODE_WIDTH,
            specs::WRY,
            specs::TAO,
            specs::GTK,
            specs::TOKIO_TUNGSTENITE.spec,
            specs::TOKIO_RUSTLS.spec,
            specs::RUSTLS.spec,
            specs::WEBPKI_ROOTS.spec,
            specs::LETTRE.spec,
            specs::ICU_CASEMAP,
            specs::ICU_LOCALE_CORE,
            specs::REQWEST.spec,
            specs::TOML,
            specs::SERDE_SAPHYR.spec,
            specs::FLATE2,
            specs::ZSTD,
            specs::CSV,
            specs::SHA1,
            specs::MD5,
            specs::AES_GCM,
            specs::CHACHA20POLY1305,
            specs::PBKDF2,
            specs::JSONWEBTOKEN,
            specs::URL,
            specs::RSA.spec,
            specs::FUTURES_UTIL,
            specs::CHRONO,
            specs::RUST_DECIMAL,
            specs::UNICODE_GENERAL_CATEGORY,
            specs::SERDE_JSON.spec,
            specs::INDEXMAP,
        ];
        let missing: Vec<&str> = emitted
            .iter()
            .map(|spec| spec.name)
            .filter(|name| !set.holds(name))
            .collect();
        assert!(
            missing.is_empty(),
            "every crate the emitter names is pinned: {missing:?}"
        );
    }

    #[test]
    fn a_strict_subset_of_the_set_agrees() {
        let Some(set) = set() else {
            assert!(set().is_some(), "the small set parses");
            return;
        };
        let text = lock("\"itoa\"", &registry("itoa", "1.0.15", SUM_A, ""));
        assert!(set.judge_text(&text, FfiPosture::FfiFree).is_ok());
    }

    #[test]
    fn an_unpinned_name_is_refused_unless_ffi_brings_it() {
        let Some(set) = set() else {
            assert!(set().is_some(), "the small set parses");
            return;
        };
        let text = lock("\"extra\"", &registry("extra", "2.0.0", SUM_A, ""));
        assert!(matches!(
            set.judge_text(&text, FfiPosture::FfiFree),
            Err(LockDrift::Unpinned { name, .. }) if name.as_str() == "extra"
        ));
        assert!(set.judge_text(&text, FfiPosture::FfiBearing).is_ok());
        let other_major = lock("\"itoa\"", &registry("itoa", "2.0.0", SUM_A, ""));
        assert!(matches!(
            set.judge_text(&other_major, FfiPosture::FfiFree),
            Err(LockDrift::Unpinned { .. })
        ));
    }

    #[test]
    fn a_moved_pin_is_refused_naming_the_pin_the_requester_and_the_fix() {
        let Some(set) = set() else {
            assert!(set().is_some(), "the small set parses");
            return;
        };
        let text = lock(
            "\"user_crate\"",
            &format!(
                "{}{}",
                registry("user_crate", "3.1.0", SUM_A, "\"serde_json\""),
                registry("serde_json", "1.0.100", SUM_A, ""),
            ),
        );
        for posture in [FfiPosture::FfiFree, FfiPosture::FfiBearing] {
            let verdict = set.judge_text(&text, posture);
            assert!(
                matches!(
                    &verdict,
                    Err(LockDrift::Moved { name, locked, pinned, requested_by: Some(Requester::Crate { name: by, .. }) })
                        if name.as_str() == "serde_json"
                            && locked.to_string() == "1.0.100"
                            && pinned.to_string() == "1.0.140"
                            && by.as_str() == "user_crate"
                ),
                "a moved pin is refused under {posture:?}: {verdict:?}"
            );
            let Err(drift) = verdict else { return };
            let shown = drift.to_string();
            assert!(
                shown.contains("serde_json 1.0.140"),
                "names the pin: {shown}"
            );
            assert!(shown.contains("user_crate"), "names the requester: {shown}");
            assert!(
                shown.contains("relax user_crate's `serde_json` requirement"),
                "names the fix: {shown}"
            );
        }
        let direct = lock(
            "\"serde_json\"",
            &registry("serde_json", "1.0.100", SUM_A, ""),
        );
        let verdict = set.judge_text(&direct, FfiPosture::FfiBearing);
        assert!(matches!(
            &verdict,
            Err(LockDrift::Moved { requested_by: Some(Requester::Project { name }), .. })
                if name.as_str() == "app"
        ));
        let Err(drift) = verdict else { return };
        let shown = drift.to_string();
        assert!(
            shown.contains("relax app's `serde_json` requirement") && shown.contains("1.0.140"),
            "names the project fix: {shown}"
        );
    }

    #[test]
    fn a_pinned_version_with_another_checksum_is_refused() {
        let Some(set) = set() else {
            assert!(set().is_some(), "the small set parses");
            return;
        };
        let text = lock("\"itoa\"", &registry("itoa", "1.0.15", &"c".repeat(64), ""));
        for posture in [FfiPosture::FfiFree, FfiPosture::FfiBearing] {
            assert!(matches!(
                set.judge_text(&text, posture),
                Err(LockDrift::ChecksumDiffers { name, .. }) if name.as_str() == "itoa"
            ));
        }
        let no_sum = lock(
            "\"itoa\"",
            "[[package]]\nname = \"itoa\"\nversion = \"1.0.15\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        );
        assert!(matches!(
            set.judge_text(&no_sum, FfiPosture::FfiBearing),
            Err(LockDrift::ChecksumDiffers { .. })
        ));
    }

    #[test]
    fn a_foreign_source_is_refused_under_every_posture() {
        let Some(set) = set() else {
            assert!(set().is_some(), "the small set parses");
            return;
        };
        let text = lock(
            "\"itoa\"",
            "[[package]]\nname = \"itoa\"\nversion = \"1.0.15\"\n\
             source = \"git+https://example.invalid/itoa#abc\"\n",
        );
        for posture in [FfiPosture::FfiFree, FfiPosture::FfiBearing] {
            assert!(matches!(
                set.judge_text(&text, posture),
                Err(LockDrift::ForeignSource { name, source })
                    if name.as_str() == "itoa" && source.starts_with("git+")
            ));
        }
    }

    #[test]
    fn a_lock_outside_the_grammar_is_unparsable() {
        let Some(set) = set() else {
            assert!(set().is_some(), "the small set parses");
            return;
        };
        for (text, reason) in [
            ("not toml [", LockParseError::NotToml),
            (
                "version = 4\n[metadata]\n",
                LockParseError::UnknownKey("metadata".to_owned()),
            ),
            (
                "version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\npatch = 1\n",
                LockParseError::UnknownKey("patch".to_owned()),
            ),
            (
                "version = 4\n[[package]]\nname = \"a b\"\nversion = \"1.0.0\"\n",
                LockParseError::Malformed(LockField::Name),
            ),
            (
                "version = 4\n[[package]]\nname = \"a\"\nversion = \"one\"\n",
                LockParseError::Malformed(LockField::Version),
            ),
        ] {
            assert_eq!(
                set.judge_text(text, FfiPosture::FfiBearing),
                Err(LockDrift::Unparsable(reason)),
                "{text}"
            );
        }
    }

    #[test]
    fn a_set_with_a_git_source_a_missing_checksum_or_format_3_is_refused() {
        let git: &[u8] = b"version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\
            source = \"git+https://example.invalid/a#abc\"\n";
        assert!(matches!(
            PinnedSet::from_seed(git),
            Err(PinnedSetError::ForeignSource { name, .. }) if name.as_str() == "a"
        ));
        let unsummed: &[u8] = b"version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n\
            source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        assert!(matches!(
            PinnedSet::from_seed(unsummed),
            Err(PinnedSetError::MissingChecksum { name, .. }) if name.as_str() == "a"
        ));
        let format_3: &[u8] = b"version = 3\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n";
        assert!(matches!(
            PinnedSet::from_seed(format_3),
            Err(PinnedSetError::Parse(LockParseError::FormatVersion))
        ));
        let unversioned: &[u8] = b"[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n";
        assert!(matches!(
            PinnedSet::from_seed(unversioned),
            Err(PinnedSetError::Parse(LockParseError::FormatVersion))
        ));
    }

    #[test]
    fn only_an_ffi_bearing_crate_admits_and_only_an_unpinned_name() {
        let Some(set) = set() else {
            assert!(set().is_some(), "the small set parses");
            return;
        };
        let text = lock("\"extra\"", &registry("extra", "2.0.0", SUM_A, ""));
        let verdict = set.judge_text(&text, FfiPosture::FfiFree);
        assert!(verdict.is_err(), "an unpinned name is refused without FFI");
        let Err(unpinned) = verdict else { return };
        assert_eq!(FfiPosture::FfiBearing.admits(&unpinned), Admission::Admit);
        assert_eq!(FfiPosture::FfiFree.admits(&unpinned), Admission::Refuse);
        assert_eq!(
            FfiPosture::FfiBearing.admits(&LockDrift::WrapperDiffers),
            Admission::Refuse
        );
        let refusal = LockRefusal {
            lock: "Cargo.lock".into(),
            posture: FfiPosture::FfiFree,
            drift: unpinned,
        };
        assert_eq!(refusal.fault(), crate::screen::Fault::Internal);
    }
}
