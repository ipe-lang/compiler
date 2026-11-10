//! The runtime crate source, embedded in the `ipe` binary, and the one locator
//! that picks the runtime an emit carries.
//!
//! A copied `ipe` binary must be able to build a program with nothing beside it
//! but a Rust toolchain — no separate runtime download, no version-mismatch
//! hazard. To make that true, the runtime crate SOURCE (`src/runtime/rust`: its
//! `Cargo.toml` + `src/**`) is compiled into this binary as a byte-tree and
//! bundled from memory into every emitted project that needs it, so the
//! runtime matches the compiler that emitted it by construction. Nothing is
//! written outside the emitted project.
//!
//! Only SOURCE is embedded; it is compiled locally by the user's toolchain. No
//! prebuilt object code ships (that would be an ABI/trust surface, not a source
//! distribution).
//!
//! [`RuntimeSource::resolve`] is the one reader of `IPE_RUNTIME_DIR` and
//! [`RuntimeEmit::from_env`] the one reader of `IPE_RUNTIME_VENDORED`.
//!
//! # `IPE_HOME`
//! The per-user data root, resolved once:
//! 1. `$IPE_HOME` — explicit override; refused unless absolute.
//! 2. `$XDG_DATA_HOME/ipe` — the XDG data root, when absolute.
//! 3. `$HOME/.ipe` — the default, when `HOME` is absolute.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use include_dir::{Dir, include_dir};
use ipe_backend_rust::RuntimeContentId;

use crate::CliError;

/// The runtime crate source tree, embedded at build time from the workspace
/// `src/runtime/rust` directory (the crate ROOT, so the materialized tree is a
/// self-contained buildable crate). `tests/` is present in the source tree but
/// is not needed to build the crate as a path dependency; it is skipped when
/// the tree is bundled (see [`bundled_runtime`]).
static RUNTIME_CRATE: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../runtime/rust");

/// The compiler's own version — the workspace-synced `version` field.
///
/// The embedded runtime crate is bundled WITH this version, so the bundled
/// runtime's version equals the compiler version by construction.
pub const COMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The runtime crate's package name.
///
/// This is the single token that identifies a directory as a valid runtime crate
/// root. A candidate whose `Cargo.toml` does not declare this package is rejected
/// — never walked past to a wrong runtime.
pub const RUNTIME_PACKAGE: &str = "ipe-runtime-rust";

/// A runtime crate root an operator named, proved by the override walk.
///
/// The only constructor is that walk: it found, within
/// [`RUNTIME_LOOKUP_CEILING`] ancestors of the named path, a `Cargo.toml`
/// declaring [`RUNTIME_PACKAGE`] at [`COMPILER_VERSION`]. An empty,
/// wrong-package or other-version directory has no `ProvenRoot`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenRoot {
    root: PathBuf,
}

impl ProvenRoot {
    /// The canonical crate root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Prove the runtime crate root at or above `path`.
    ///
    /// # Errors
    /// [`CliError::RuntimeDirInvalid`] when no runtime crate root lies within
    /// the ceiling at or above `path`; [`CliError::RuntimeVersionMismatch`]
    /// when the nearest one declares another version; [`CliError::Io`] when it
    /// cannot be canonicalized. Each refusal offers `remedy`.
    fn prove(path: &Path, remedy: RuntimeRemedy) -> Result<Self, CliError> {
        // The crate root itself or any path inside it (`…/rust/src`,
        // `…/src/ipe_runtime`) names the crate.
        for dir in RUNTIME_LOOKUP_CEILING.ancestors(path) {
            let Some(version) = runtime_version_at(dir) else {
                continue;
            };
            let root = dir.canonicalize().map_err(|e| CliError::Io {
                path: dir.to_path_buf(),
                source: e,
            })?;
            if version != COMPILER_VERSION {
                return Err(CliError::RuntimeVersionMismatch {
                    path: root,
                    found: version,
                    expected: COMPILER_VERSION.to_owned(),
                    remedy,
                });
            }
            return Ok(Self { root });
        }
        let points_at_inner = path.file_name() == Some(std::ffi::OsStr::new("ipe_runtime"))
            || path.ends_with("rust/src")
            || path.ends_with("runtime/rust/src");
        Err(CliError::RuntimeDirInvalid {
            path: path.to_path_buf(),
            points_at_inner,
            remedy,
        })
    }
}

/// The relative path, from a runtime crate root, of the manifest.
const MANIFEST: &str = "Cargo.toml";

/// Read a candidate crate root's manifest and return its declared version iff the
/// manifest declares the runtime package. `None` means "not a runtime crate
/// root" — the caller treats that as a hard refusal, never a walk-on.
fn runtime_version_at(root: &Path) -> Option<String> {
    let text =
        crate::io_bounded::read_named_in(root, &[MANIFEST], crate::io_bounded::SMALL_FILE_CAP)
            .ok()?;
    let declares_package = text
        .lines()
        .any(|l| l.trim() == format!("name = \"{RUNTIME_PACKAGE}\""));
    if !declares_package {
        return None;
    }
    // A standalone crate carries a concrete `version = "…"`; an in-repo crate
    // inherits it via `version.workspace = true`. In-repo, the version is the
    // compiler's own (both are the workspace version), so report that.
    let concrete = text.lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix("version = \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_owned)
    });
    Some(concrete.unwrap_or_else(|| COMPILER_VERSION.to_owned()))
}

/// Resolve `IPE_HOME` (see the module doc). The returned path is not created.
///
/// # Errors
/// - [`CliError::EnvDirNotAbsolute`] when `IPE_HOME` is set but not absolute.
/// - [`CliError::RuntimeHomeUnknown`] when no override, no absolute
///   `XDG_DATA_HOME`, and no absolute home are set.
pub fn ipe_home() -> Result<PathBuf, CliError> {
    ipe_home_from(
        ipe_env::var_os("IPE_HOME"),
        ipe_env::var_os("XDG_DATA_HOME"),
        crate::env_dir::home().ok().as_ref(),
    )
}

/// Resolve `IPE_HOME` from the raw override, raw `XDG_DATA_HOME`, and the home.
fn ipe_home_from(
    ipe_home: Option<std::ffi::OsString>,
    xdg_data_home: Option<std::ffi::OsString>,
    home: Option<&crate::env_dir::HomeDir>,
) -> Result<PathBuf, CliError> {
    if let Some(dir) = crate::env_dir::explicit_override("IPE_HOME", ipe_home)? {
        return Ok(dir);
    }
    crate::env_dir::absolute(xdg_data_home)
        .map(|xdg| xdg.join("ipe"))
        .or_else(|| home.map(|h| h.join(".ipe")))
        .ok_or(CliError::RuntimeHomeUnknown)
}

/// Which emission a bundled runtime copy serves, stamped into its version.
///
/// A scratch bundle (`ipe test`) and an `out/` bundle of the same bytes are two
/// cargo units, so a hand-edited `out/` copy built into a shared target can
/// never stand in for the scratch one. There is no default: every emission
/// names its role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleRole {
    /// A project's own output directory.
    Out,
    /// A private scratch directory created for one run.
    Scratch,
}

impl BundleRole {
    /// The role's token in the stamped version.
    const fn token(self) -> &'static str {
        match self {
            Self::Out => "out",
            Self::Scratch => "scratch",
        }
    }
}

/// Bytes of a [`RuntimeDigest`].
const RUNTIME_DIGEST_LEN: usize = 16;

/// The digest of every bundled runtime byte, the runtime unit's content identity.
///
/// SHA-256 over a length-framed encoding, truncated to 128 bits: a domain tag,
/// then for each file in path order the path and the text, each preceded by its
/// length as a little-endian `u64`, so no two file sets share an encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeDigest([u8; RUNTIME_DIGEST_LEN]);

/// The domain tag opening a [`RuntimeDigest`] input.
const RUNTIME_DIGEST_TAG: &[u8] = b"ipe-runtime-bundle\0";

impl RuntimeDigest {
    /// The digest of `files`, given in path order as (`/`-joined path, text).
    fn of<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(RUNTIME_DIGEST_TAG);
        for (path, text) in files {
            for part in [path.as_bytes(), text.as_bytes()] {
                hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_le_bytes());
                hasher.update(part);
            }
        }
        let full = hasher.finalize();
        let mut out = [0u8; RUNTIME_DIGEST_LEN];
        for (slot, byte) in out.iter_mut().zip(full.iter()) {
            *slot = *byte;
        }
        Self(out)
    }

    /// The digest as 32 lowercase hex digits.
    #[must_use]
    pub fn hex(self) -> String {
        hex::encode(self.0)
    }

    /// The digest's bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; RUNTIME_DIGEST_LEN] {
        self.0
    }
}

/// The embedded runtime crate prepared for one [`BundleRole`].
#[derive(Debug)]
pub struct BundledRuntime {
    /// Every bundled file, relative to the crate root, with its text.
    files: BTreeMap<PathBuf, String>,
    /// The digest of the files before the manifest was stamped.
    digest: RuntimeDigest,
}

impl BundledRuntime {
    /// Every bundled file, relative to the crate root, with its text.
    #[must_use]
    pub const fn files(&self) -> &BTreeMap<PathBuf, String> {
        &self.files
    }

    /// The content digest the manifest's version carries.
    #[must_use]
    pub const fn digest(&self) -> RuntimeDigest {
        self.digest
    }
}

/// Why the embedded runtime cannot be bundled, cached so every use fails alike.
#[derive(Debug, Clone)]
enum BundleFault {
    /// The embedded file at this bundle-relative path is not UTF-8.
    NotUtf8(PathBuf),
    /// The embedded manifest cannot be stamped.
    Manifest(ManifestFault),
}

/// Why the embedded runtime manifest cannot be stamped for bundling.
#[derive(Debug, Clone)]
pub enum ManifestFault {
    /// The manifest is not TOML.
    Unparsable(toml_edit::TomlError),
    /// The manifest has no `[package]` table.
    NoPackageTable,
    /// The bundle has no UTF-8 root manifest.
    NoUtf8Manifest,
}

impl std::fmt::Display for ManifestFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unparsable(e) => write!(f, "the manifest is not TOML: {e}"),
            Self::NoPackageTable => f.write_str("the manifest has no `[package]` table"),
            Self::NoUtf8Manifest => f.write_str("the bundle has no UTF-8 root manifest"),
        }
    }
}

impl BundleFault {
    /// The error this fault surfaces as.
    fn to_error(&self) -> CliError {
        match self {
            Self::NotUtf8(rel) => CliError::RuntimeMaterializeFailed {
                detail: format!("embedded runtime file {} is not valid UTF-8", rel.display()),
            },
            Self::Manifest(fault) => CliError::BundledManifest {
                fault: fault.clone(),
            },
        }
    }
}

/// The version a bundled manifest carries: `<COMPILER_VERSION>+ipe.<role>.<digest hex>`.
///
/// Semver build metadata, which cargo hashes into the unit's identity, so two
/// bundles differing in one byte or in role never share a compiled unit.
#[must_use]
pub fn stamped_version(role: BundleRole, digest: RuntimeDigest) -> String {
    format!("{COMPILER_VERSION}+ipe.{}.{}", role.token(), digest.hex())
}

/// Prepare the runtime manifest for bundling: set `package.version` to `version`
/// and remove every `dev-dependencies` table, `target.*` ones included.
///
/// Dev dependencies are never built for a non-root crate, and they may name
/// workspace-relative paths that do not resolve outside the workspace. The
/// manifest is parsed once as TOML, so a key that merely mentions
/// `dev-dependencies` is kept.
///
/// # Errors
/// [`BundleFault::Manifest`] when the manifest does not parse.
fn prepare_bundled_manifest(manifest: &str, version: &str) -> Result<String, BundleFault> {
    let mut doc = manifest
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| BundleFault::Manifest(ManifestFault::Unparsable(e)))?;
    let package = doc
        .get_mut("package")
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or(BundleFault::Manifest(ManifestFault::NoPackageTable))?;
    package.insert("version", toml_edit::value(version));
    doc.remove("dev-dependencies");
    if let Some(targets) = doc
        .get_mut("target")
        .and_then(toml_edit::Item::as_table_like_mut)
    {
        for (_, target) in targets.iter_mut() {
            if let Some(target) = target.as_table_like_mut() {
                target.remove("dev-dependencies");
            }
        }
    }
    Ok(doc.to_string())
}

/// The embedded runtime crate's files, keyed by path, with their digest.
type UnstampedBundle = (BTreeMap<PathBuf, String>, RuntimeDigest);

/// The embedded runtime crate's files and their digest, the manifest carrying
/// [`COMPILER_VERSION`]; the shared base both roles stamp.
fn unstamped_bundle() -> &'static Result<UnstampedBundle, BundleFault> {
    static BASE: LazyLock<Result<UnstampedBundle, BundleFault>> = LazyLock::new(|| {
        let mut files = BTreeMap::new();
        collect_dir_text_from_embedded(&RUNTIME_CRATE, Path::new(""), true, &mut files)?;
        let keys = files
            .iter()
            .map(|(path, text)| (digest_path(path), text.as_str()))
            .collect::<Vec<_>>();
        let digest = RuntimeDigest::of(keys.iter().map(|(path, text)| (path.as_str(), *text)));
        Ok((files, digest))
    });
    &BASE
}

/// `path`'s components joined with `/`, the form a [`RuntimeDigest`] reads on every host.
fn digest_path(path: &Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// The embedded runtime crate bundled for `role`: its manifest's version
/// stamped with the role and the content digest, dev dependencies removed,
/// `tests/` skipped.
///
/// Computed once per role and reused across every emit.
///
/// # Errors
/// [`CliError::RuntimeMaterializeFailed`] when an embedded file is not UTF-8;
/// [`CliError::BundledManifest`] when the embedded manifest does not parse.
pub fn bundled_runtime(role: BundleRole) -> Result<&'static BundledRuntime, CliError> {
    /// The bundle of `role`, stamped from the shared base.
    fn stamp(role: BundleRole) -> Result<BundledRuntime, BundleFault> {
        let (base, digest) = unstamped_bundle().as_ref().map_err(Clone::clone)?;
        let mut files = base.clone();
        let manifest = RUNTIME_CRATE
            .get_file(MANIFEST)
            .and_then(|file| std::str::from_utf8(file.contents()).ok())
            .ok_or(BundleFault::Manifest(ManifestFault::NoUtf8Manifest))?;
        let stamped = prepare_bundled_manifest(manifest, &stamped_version(role, *digest))?;
        files.insert(PathBuf::from(MANIFEST), stamped);
        Ok(BundledRuntime {
            files,
            digest: *digest,
        })
    }
    static OUT: LazyLock<Result<BundledRuntime, BundleFault>> =
        LazyLock::new(|| stamp(BundleRole::Out));
    static SCRATCH: LazyLock<Result<BundledRuntime, BundleFault>> =
        LazyLock::new(|| stamp(BundleRole::Scratch));
    match role {
        BundleRole::Out => &OUT,
        BundleRole::Scratch => &SCRATCH,
    }
    .as_ref()
    .map_err(BundleFault::to_error)
}

/// Recursive helper for [`unstamped_bundle`]: traverses `dir`, prepending
/// `prefix` to each entry's relative path; the root manifest carries
/// [`COMPILER_VERSION`].
fn collect_dir_text_from_embedded(
    dir: &include_dir::Dir<'_>,
    prefix: &std::path::Path,
    at_root: bool,
    out: &mut BTreeMap<PathBuf, String>,
) -> Result<(), BundleFault> {
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(sub) => {
                let name = sub.path().file_name().unwrap_or_default();
                if at_root && name == std::ffi::OsStr::new("tests") {
                    continue;
                }
                collect_dir_text_from_embedded(sub, &prefix.join(name), false, out)?;
            }
            include_dir::DirEntry::File(file) => {
                let name = file.path().file_name().unwrap_or_default();
                let rel = prefix.join(name);
                let text = std::str::from_utf8(file.contents())
                    .map_err(|_| BundleFault::NotUtf8(rel.clone()))?;
                let text = if at_root && name == std::ffi::OsStr::new(MANIFEST) {
                    prepare_bundled_manifest(text, COMPILER_VERSION)?
                } else {
                    text.to_owned()
                };
                out.insert(rel, text);
            }
        }
    }
    Ok(())
}

/// Who chooses the runtime crate an emitted project links.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RuntimeOrigin {
    /// A developer build: an explicit root, else `$IPE_RUNTIME_DIR`, else the
    /// embedded copy (see [`RuntimeSource::resolve`]).
    #[default]
    Developer,
    /// A gate judging a package: always the compiler's embedded copy.
    ///
    /// No override and no directory walk is consulted, so neither the
    /// environment nor a runtime tree the judged package ships can stand in for
    /// it.
    Gate,
}

/// The one runtime source a [`RuntimeOrigin::Gate`] admits.
static EMBEDDED_RUNTIME: RuntimeSource = RuntimeSource::Embedded;

impl RuntimeOrigin {
    /// The runtime source this origin lets an emit carry, given the `runtime`
    /// its caller resolved.
    ///
    /// A gate carries the embedded copy whatever it was handed, so a caller
    /// pairing gate options with an override root cannot steer a judged build;
    /// a developer build carries `runtime` as resolved.
    #[must_use]
    pub const fn admitted_runtime(self, runtime: &RuntimeSource) -> &RuntimeSource {
        match self {
            Self::Gate => &EMBEDDED_RUNTIME,
            Self::Developer => runtime,
        }
    }
}

/// The variable that selects the runtime source an emit carries.
pub const RUNTIME_VENDORED_VAR: &str = "IPE_RUNTIME_VENDORED";

/// What runtime source an emit carries.
///
/// Parsed once from [`RUNTIME_VENDORED_VAR`] by [`RuntimeEmit::from_env`], the
/// variable's one reader, so no second reader can give it another grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeEmit {
    /// The emitted project names the runtime crate as a path dependency and
    /// carries no vendored module tree.
    Linked,
    /// The emitted project carries the runtime module tree under `src/ipe_runtime/`.
    Vendored,
}

/// Every admitted spelling of [`RUNTIME_VENDORED_VAR`] and the emit it names.
///
/// The table is the whole grammar: a match is exact (no case folding, no
/// trimming), and a set value outside it is refused.
const RUNTIME_VENDORED_SPELLINGS: &[(&str, RuntimeEmit)] =
    &[("0", RuntimeEmit::Linked), ("1", RuntimeEmit::Vendored)];

impl RuntimeEmit {
    /// The emit the environment selects; unset is [`RuntimeEmit::Linked`].
    ///
    /// # Errors
    /// [`CliError::EnvSwitchNotRecognised`] for a set value outside
    /// [`RUNTIME_VENDORED_SPELLINGS`], the empty and the non-UTF-8 value included.
    pub fn from_env() -> Result<Self, CliError> {
        Self::parse(ipe_env::var_os(RUNTIME_VENDORED_VAR).as_deref())
    }

    /// The emit a raw [`RUNTIME_VENDORED_VAR`] value names; unset is `Linked`.
    ///
    /// # Errors
    /// [`CliError::EnvSwitchNotRecognised`] for a set value outside
    /// [`RUNTIME_VENDORED_SPELLINGS`].
    pub fn parse(raw: Option<&std::ffi::OsStr>) -> Result<Self, CliError> {
        let Some(raw) = raw else {
            return Ok(Self::Linked);
        };
        RUNTIME_VENDORED_SPELLINGS
            .iter()
            .find(|(spelling, _)| raw == std::ffi::OsStr::new(spelling))
            .map(|&(_, emit)| emit)
            .ok_or_else(|| CliError::EnvSwitchNotRecognised {
                var: RUNTIME_VENDORED_VAR,
                got: crate::style::TerminalSafe::sanitize(&raw.to_string_lossy()),
                admitted: RUNTIME_VENDORED_SPELLINGS
                    .iter()
                    .map(|&(spelling, _)| spelling)
                    .collect(),
            })
    }
}

/// The variable naming an operator's runtime crate root.
pub const RUNTIME_DIR_VAR: &str = "IPE_RUNTIME_DIR";

/// Which remedy a runtime refusal offers, by the surface that reached it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeRemedy {
    /// The command takes `--runtime <dir>`: the remedy names the flag beside
    /// `IPE_RUNTIME_DIR`.
    WithRuntimeFlag,
    /// The surface has no `--runtime`: the remedy names `IPE_RUNTIME_DIR` only.
    EnvOnly,
}

/// Where the runtime crate an emit carries comes from.
///
/// Resolved once per command by [`RuntimeSource::resolve`] and carried through
/// the compile chain; nothing else looks a runtime up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeSource {
    /// The runtime crate compiled into this binary.
    Embedded,
    /// An operator-named runtime crate root.
    Override(ProvenRoot),
}

/// The runtime crate's module tree: each file under its `src/`, keyed relative to `src/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeModuleTree(BTreeMap<PathBuf, String>);

impl RuntimeModuleTree {
    /// Every module file, keyed relative to the crate's `src/`, with its text.
    #[must_use]
    pub const fn files(&self) -> &BTreeMap<PathBuf, String> {
        &self.0
    }

    /// A tree holding exactly `files`.
    #[cfg(test)]
    #[must_use]
    pub const fn from_files(files: BTreeMap<PathBuf, String>) -> Self {
        Self(files)
    }
}

impl RuntimeSource {
    /// Resolve the runtime source `origin` admits.
    ///
    /// Precedence: a [`RuntimeOrigin::Gate`] takes [`Self::Embedded`] and reads
    /// neither `explicit` nor the environment. A developer build takes
    /// `explicit` (the `--runtime` root, or a library caller's root), else
    /// `$IPE_RUNTIME_DIR` (read as raw OS text, so a non-UTF-8 path is still a
    /// path), else [`Self::Embedded`]. A named root must be proved by
    /// [`ProvenRoot`]'s walk; it is never passed over for another source.
    ///
    /// # Errors
    /// The refusals of the override walk, each offering `remedy`.
    pub fn resolve(
        origin: RuntimeOrigin,
        explicit: Option<&Path>,
        remedy: RuntimeRemedy,
    ) -> Result<Self, CliError> {
        let ambient = ipe_env::var_os(RUNTIME_DIR_VAR);
        Self::resolve_from(origin, explicit, ambient.as_deref(), remedy)
    }

    /// [`Self::resolve`] over the environment's value `ambient`.
    fn resolve_from(
        origin: RuntimeOrigin,
        explicit: Option<&Path>,
        ambient: Option<&std::ffi::OsStr>,
        remedy: RuntimeRemedy,
    ) -> Result<Self, CliError> {
        match origin {
            RuntimeOrigin::Gate => Ok(Self::Embedded),
            RuntimeOrigin::Developer => explicit
                .or_else(|| ambient.map(Path::new))
                .map_or(Ok(Self::Embedded), |named| {
                    ProvenRoot::prove(named, remedy).map(Self::Override)
                }),
        }
    }

    /// The module tree a vendored emit copies into `src/ipe_runtime/`.
    ///
    /// # Errors
    /// [`CliError::RuntimeMaterializeFailed`] / [`CliError::BundledManifest`]
    /// when the embedded tree cannot be bundled; [`CliError::Io`] when an
    /// override's `src/` cannot be read.
    pub fn module_tree(&self) -> Result<RuntimeModuleTree, CliError> {
        match self {
            Self::Embedded => {
                let (files, _) = unstamped_bundle().as_ref().map_err(BundleFault::to_error)?;
                Ok(RuntimeModuleTree(
                    files
                        .iter()
                        .filter_map(|(path, text)| {
                            path.strip_prefix(RUNTIME_SRC_DIR)
                                .ok()
                                .map(|rel| (rel.to_path_buf(), text.clone()))
                        })
                        .collect(),
                ))
            }
            Self::Override(proven) => {
                let mut files = BTreeMap::new();
                crate::driver::collect_dir_text(
                    &proven.root().join(RUNTIME_SRC_DIR),
                    Path::new(""),
                    &mut files,
                )?;
                Ok(RuntimeModuleTree(files))
            }
        }
    }

    /// The content identity of the runtime a linked emit bundles.
    ///
    /// A linked emit bundles the embedded tree whatever the source, so the
    /// identity is the embedded tree's digest.
    ///
    /// # Errors
    /// As [`bundled_runtime`] when the embedded tree cannot be bundled.
    pub fn content_id(&self) -> Result<RuntimeContentId, CliError> {
        match self {
            Self::Embedded | Self::Override(_) => {
                let (_, digest) = unstamped_bundle().as_ref().map_err(BundleFault::to_error)?;
                Ok(RuntimeContentId::from_digest_bytes(digest.bytes()))
            }
        }
    }

    /// The source, for a health line or an error's context: `embedded <version>`
    /// or `override <path>`, terminal-safe.
    #[must_use]
    pub fn describe(&self) -> crate::style::TerminalSafe {
        crate::style::TerminalSafe::sanitize(&match self {
            Self::Embedded => format!("embedded {COMPILER_VERSION}"),
            Self::Override(proven) => format!("override {}", proven.root().display()),
        })
    }
}

/// The crate directory holding the runtime's module tree.
const RUNTIME_SRC_DIR: &str = "src";

/// The most directories a runtime lookup visits, its start included.
#[derive(Clone, Copy, Debug)]
struct AncestorCeiling(usize);

impl AncestorCeiling {
    /// `start` and its ancestors, nearest first, cut at the ceiling.
    fn ancestors(self, start: &Path) -> std::iter::Take<std::path::Ancestors<'_>> {
        start.ancestors().take(self.0)
    }
}

/// The ceiling of the override lookup, shared with the harness lookup.
const RUNTIME_LOOKUP_CEILING: AncestorCeiling =
    AncestorCeiling(ipe_env::artifact::RUNTIME_LOOKUP_CEILING);

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundled runtime manifest declares the compiler's version, so an
    /// emitted project can never link a mismatched embedded runtime.
    #[test]
    fn embedded_runtime_version_matches_compiler() {
        let (files, _) = unstamped_bundle()
            .as_ref()
            .expect("the embedded runtime bundles");
        let manifest = files
            .get(Path::new(MANIFEST))
            .expect("the bundle carries a Cargo.toml");
        let table: toml::Table = manifest.parse().expect("the bundled manifest parses");
        let version = table
            .get("package")
            .and_then(|package| package.get("version"))
            .and_then(toml::Value::as_str);
        assert_eq!(version, Some(COMPILER_VERSION));
    }

    /// The embedded tree declares the runtime package.
    #[test]
    fn embedded_runtime_declares_package() {
        let manifest = RUNTIME_CRATE
            .get_file("Cargo.toml")
            .expect("embedded runtime crate must carry a Cargo.toml");
        let text = std::str::from_utf8(manifest.contents()).expect("embedded manifest is UTF-8");
        assert!(
            text.lines()
                .any(|l| l.trim() == format!("name = \"{RUNTIME_PACKAGE}\""))
        );
    }

    /// A fresh scratch directory holding a runtime manifest at `version`.
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn runtime_root_at(tag: &str, version: &str) -> PathBuf {
        let dir = crate::scratch::ScratchDir::new(tag)
            .expect("scratch dir")
            .into_path();
        std::fs::write(
            dir.join(MANIFEST),
            format!("[package]\nname = \"{RUNTIME_PACKAGE}\"\nversion = \"{version}\"\n"),
        )
        .expect("write runtime manifest");
        dir
    }

    /// A named runtime declaring another version is refused with
    /// [`CliError::RuntimeVersionMismatch`], naming both versions and the
    /// remedy the surface offers.
    #[test]
    fn mismatched_runtime_version_is_rejected() {
        let bogus = "0.0.1";
        assert_ne!(bogus, COMPILER_VERSION, "the test version must differ");
        let dir = runtime_root_at("ipe-runtime-version-test", bogus);
        let err = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            Some(&dir),
            None,
            RuntimeRemedy::EnvOnly,
        );
        let ambient = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            None,
            Some(dir.as_os_str()),
            RuntimeRemedy::WithRuntimeFlag,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(
                &err,
                Err(CliError::RuntimeVersionMismatch { found, expected, remedy, .. })
                    if found == bogus
                        && expected == COMPILER_VERSION
                        && *remedy == RuntimeRemedy::EnvOnly
            ),
            "an explicit root of another version is refused, got {err:?}"
        );
        assert!(
            matches!(
                &ambient,
                Err(CliError::RuntimeVersionMismatch { remedy, .. })
                    if *remedy == RuntimeRemedy::WithRuntimeFlag
            ),
            "an IPE_RUNTIME_DIR of another version is refused, got {ambient:?}"
        );
    }

    /// A named runtime declaring the compiler's own version is an override.
    #[test]
    fn matching_runtime_version_is_accepted() {
        let dir = runtime_root_at("ipe-runtime-version-ok", COMPILER_VERSION);
        let resolved = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            Some(&dir),
            None,
            RuntimeRemedy::EnvOnly,
        );
        let canonical = dir.canonicalize().expect("scratch dir canonicalizes");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(&resolved, Ok(RuntimeSource::Override(proven)) if proven.root() == canonical),
            "got {resolved:?}"
        );
    }

    /// A parsed home over the absolute test path `path`.
    #[cfg(not(windows))]
    fn parsed_home(path: &str) -> crate::env_dir::HomeDir {
        crate::env_dir::HomeDir::try_parse(Some(path.into())).expect("an absolute test home")
    }

    #[test]
    #[cfg(not(windows))]
    fn ipe_home_uses_an_absolute_override() {
        let got = ipe_home_from(
            Some("/opt/ipe".into()),
            Some("/xdg".into()),
            Some(&parsed_home("/home/u")),
        );
        assert!(matches!(got, Ok(p) if p == std::path::Path::new("/opt/ipe")));
    }

    #[test]
    #[cfg(not(windows))]
    fn ipe_home_refuses_a_relative_or_empty_override() {
        for raw in ["", "ipe", "./ipe"] {
            let got = ipe_home_from(Some(raw.into()), None, Some(&parsed_home("/home/u")));
            assert!(
                matches!(got, Err(CliError::EnvDirNotAbsolute { var: "IPE_HOME" })),
                "IPE_HOME={raw:?} must be refused: {got:?}"
            );
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn ipe_home_skips_a_relative_xdg_data_home() {
        let home = parsed_home("/home/u");
        let got = ipe_home_from(None, Some("rel".into()), Some(&home));
        assert!(matches!(got, Ok(p) if p == std::path::Path::new("/home/u/.ipe")));
        let got = ipe_home_from(None, Some("/xdg".into()), Some(&home));
        assert!(matches!(got, Ok(p) if p == std::path::Path::new("/xdg/ipe")));
    }

    #[test]
    fn ipe_home_refuses_without_any_absolute_home() {
        let got = ipe_home_from(None, Some("rel".into()), None);
        assert!(matches!(got, Err(CliError::RuntimeHomeUnknown)));
    }

    /// The digest of one (path, text) pair.
    fn digest_of(path: &str, text: &str) -> RuntimeDigest {
        RuntimeDigest::of([(path, text)])
    }

    #[test]
    fn one_changed_byte_changes_the_digest_and_the_stamp() {
        let base = digest_of("src/lib.rs", "pub fn a() {}");
        let changed = digest_of("src/lib.rs", "pub fn b() {}");
        let renamed = digest_of("src/lic.rs", "pub fn a() {}");
        assert_ne!(base, changed);
        assert_ne!(base, renamed);
        assert_ne!(
            stamped_version(BundleRole::Scratch, base),
            stamped_version(BundleRole::Scratch, changed)
        );
    }

    #[test]
    fn a_byte_moved_across_the_path_text_boundary_changes_the_digest() {
        assert_ne!(digest_of("ab", "c"), digest_of("a", "bc"));
        assert_ne!(
            RuntimeDigest::of([("a", ""), ("b", "")]),
            RuntimeDigest::of([("ab", "")])
        );
    }

    #[test]
    fn out_and_scratch_stamps_differ_for_the_same_files() {
        let digest = digest_of("src/lib.rs", "");
        assert_ne!(
            stamped_version(BundleRole::Out, digest),
            stamped_version(BundleRole::Scratch, digest)
        );
        let out = bundled_runtime(BundleRole::Out).expect("out bundle");
        let scratch = bundled_runtime(BundleRole::Scratch).expect("scratch bundle");
        assert_eq!(out.digest(), scratch.digest());
        assert_ne!(
            out.files().get(Path::new(MANIFEST)),
            scratch.files().get(Path::new(MANIFEST))
        );
    }

    /// Whether `version` is `MAJOR.MINOR.PATCH+ipe.<role>.<32 lowercase hex>`.
    fn is_stamp_for(version: &str, role: &str) -> bool {
        let Some((core, meta)) = version.split_once('+') else {
            return false;
        };
        let numeric = core.split('.').collect::<Vec<_>>();
        let core_ok = numeric.len() == 3
            && numeric
                .iter()
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
        let Some(hex) = meta
            .strip_prefix("ipe.")
            .and_then(|rest| rest.strip_prefix(role))
            .and_then(|rest| rest.strip_prefix('.'))
        else {
            return false;
        };
        core_ok
            && hex.len() == 32
            && hex
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    }

    /// Whether `table` holds a `dev-dependencies` table at any depth.
    fn holds_dev_dependencies(table: &toml::Table) -> bool {
        table.iter().any(|(key, value)| {
            key == "dev-dependencies" || value.as_table().is_some_and(holds_dev_dependencies)
        })
    }

    #[test]
    fn the_stamped_manifest_carries_the_stamp_and_no_dev_dependencies() {
        for (role, token) in [(BundleRole::Out, "out"), (BundleRole::Scratch, "scratch")] {
            let bundle = bundled_runtime(role).expect("bundle");
            let manifest = bundle
                .files()
                .get(Path::new(MANIFEST))
                .expect("bundled manifest");
            let parsed = manifest
                .parse::<toml::Table>()
                .expect("stamped manifest parses");
            let version = parsed
                .get("package")
                .and_then(toml::Value::as_table)
                .and_then(|package| package.get("version"))
                .and_then(toml::Value::as_str)
                .expect("package.version");
            assert!(is_stamp_for(version, token), "{version}");
            assert!(semver::Version::parse(version).is_ok(), "{version}");
            assert_eq!(version, stamped_version(role, bundle.digest()));
            // The bundle a build links declares the version `resolve` admits and
            // `ipe health` reports, so a build and its health check never name
            // two runtimes.
            assert_eq!(
                version.split_once('+').map(|(core, _)| core),
                Some(COMPILER_VERSION),
                "{version}",
            );
            assert!(!holds_dev_dependencies(&parsed));
        }
        assert!(!is_stamp_for("0.1.0+ipe.out.ABCDEF", "out"));
        assert!(!is_stamp_for(
            "0.1+ipe.out.00000000000000000000000000000000",
            "out"
        ));
    }

    #[test]
    fn a_key_mentioning_dev_dependencies_is_kept_while_the_table_goes() {
        let fixture = "[package]\nname = \"r\"\nversion.workspace = true\n\n\
            [features]\nextra = [\"default-dev-dependencies\"]\n\n\
            [dependencies]\nserde = \"1\"\n\n\
            [target.'cfg(unix)'.dev-dependencies]\nlibc = \"0.2\"\n\n\
            [dev-dependencies]\ntempfile = \"3\"\n";
        let out = prepare_bundled_manifest(fixture, "1.2.3+ipe.out.x").expect("prepares");
        let parsed = out.parse::<toml::Table>().expect("parses");
        assert!(!holds_dev_dependencies(&parsed));
        assert!(out.contains("default-dev-dependencies"));
        assert!(out.contains("serde"));
        assert!(matches!(
            parsed
                .get("package")
                .and_then(|p| p.get("version"))
                .and_then(toml::Value::as_str),
            Some("1.2.3+ipe.out.x")
        ));
    }

    #[test]
    fn an_unparsable_manifest_is_a_typed_fault() {
        assert!(matches!(
            prepare_bundled_manifest("[package\n", "1.0.0"),
            Err(BundleFault::Manifest(ManifestFault::Unparsable(_)))
        ));
        assert!(matches!(
            prepare_bundled_manifest("[dependencies]\n", "1.0.0"),
            Err(BundleFault::Manifest(ManifestFault::NoPackageTable))
        ));
    }

    /// A gate takes the embedded copy and reads neither the explicit root nor
    /// the environment, even when both name invalid directories.
    #[test]
    fn a_gate_resolves_only_the_embedded_runtime() {
        let bogus = Path::new("/nonexistent/ipe-runtime-gate");
        let resolved = RuntimeSource::resolve_from(
            RuntimeOrigin::Gate,
            Some(bogus),
            Some(bogus.as_os_str()),
            RuntimeRemedy::EnvOnly,
        );
        assert!(matches!(resolved, Ok(RuntimeSource::Embedded)));
    }

    /// A gate admits only the embedded copy even when handed a proven
    /// override, so gate options paired with an override root cannot steer the
    /// judged emit; a developer build carries the override it resolved.
    #[test]
    fn a_gate_admits_only_the_embedded_runtime_whatever_it_is_handed() {
        let dir = runtime_root_at("ipe-runtime-gate-admit", COMPILER_VERSION);
        let proven = ProvenRoot::prove(&dir, RuntimeRemedy::EnvOnly);
        let _ = std::fs::remove_dir_all(&dir);
        let handed = RuntimeSource::Override(proven.expect("the override root proves"));
        assert_eq!(
            RuntimeOrigin::Gate.admitted_runtime(&handed),
            &RuntimeSource::Embedded
        );
        assert_eq!(RuntimeOrigin::Developer.admitted_runtime(&handed), &handed);
    }

    /// An explicit root beats `IPE_RUNTIME_DIR`: a valid explicit root wins
    /// over an invalid environment value, and with neither the source is
    /// embedded.
    #[test]
    fn an_explicit_root_takes_precedence_over_the_environment() {
        let dir = runtime_root_at("ipe-runtime-precedence", COMPILER_VERSION);
        let explicit_wins = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            Some(&dir),
            Some(Path::new("/nonexistent/ipe-runtime-env").as_os_str()),
            RuntimeRemedy::EnvOnly,
        );
        let env_refused = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            None,
            Some(Path::new("/nonexistent/ipe-runtime-env").as_os_str()),
            RuntimeRemedy::EnvOnly,
        );
        let neither = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            None,
            None,
            RuntimeRemedy::EnvOnly,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(explicit_wins, Ok(RuntimeSource::Override(_))));
        assert!(matches!(
            env_refused,
            Err(CliError::RuntimeDirInvalid { .. })
        ));
        assert!(matches!(neither, Ok(RuntimeSource::Embedded)));
    }

    /// No ambient selection: a runtime tree of another version above the
    /// current directory is never picked when nothing names a root.
    #[test]
    fn no_runtime_is_selected_from_the_surrounding_tree() {
        let resolved = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            None,
            None,
            RuntimeRemedy::EnvOnly,
        );
        assert!(matches!(resolved, Ok(RuntimeSource::Embedded)));
    }

    /// The embedded module tree is the in-repo `src/runtime/rust/src` tree,
    /// keyed relative to `src/`.
    #[test]
    fn the_embedded_module_tree_is_the_in_repo_source_tree() {
        let tree = RuntimeSource::Embedded
            .module_tree()
            .expect("the embedded tree bundles");
        let in_repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../runtime/rust/src");
        let mut on_disk = BTreeMap::new();
        crate::driver::collect_dir_text(&in_repo, Path::new(""), &mut on_disk)
            .expect("the in-repo runtime source reads");
        assert!(tree.files().contains_key(Path::new("lib.rs")));
        assert_eq!(tree.files(), &on_disk);
    }

    /// `root` with `levels` nested `d` directories below it.
    fn nested(root: &Path, levels: usize) -> PathBuf {
        (0..levels).fold(root.to_path_buf(), |path, _| path.join("d"))
    }

    /// The override lookup stops at its ceiling: a crate root one directory past
    /// the last one it visits is not found.
    #[test]
    fn the_override_lookup_stops_at_its_ceiling() {
        let root = runtime_root_at("ipe-runtime-ceiling-override", COMPILER_VERSION);
        let AncestorCeiling(ceiling) = RUNTIME_LOOKUP_CEILING;
        let within = ProvenRoot::prove(&nested(&root, ceiling - 1), RuntimeRemedy::EnvOnly);
        let past = ProvenRoot::prove(&nested(&root, ceiling), RuntimeRemedy::EnvOnly);
        let _ = std::fs::remove_dir_all(&root);
        assert!(within.is_ok(), "the last visited ancestor is found");
        assert!(
            matches!(past, Err(CliError::RuntimeDirInvalid { .. })),
            "a crate root past the ceiling is refused"
        );
    }

    /// An explicit override naming a directory that does not exist is refused,
    /// never walked past to the embedded copy.
    #[test]
    fn a_missing_override_dir_is_refused() {
        let root = crate::scratch::ScratchDir::new("ipe-runtime-missing-override")
            .expect("scratch dir")
            .into_path();
        let resolved = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            None,
            Some(root.join("no-such-runtime").as_os_str()),
            RuntimeRemedy::EnvOnly,
        );
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            matches!(resolved, Err(CliError::RuntimeDirInvalid { .. })),
            "a missing IPE_RUNTIME_DIR is refused",
        );
    }

    /// The admitted spellings of `IPE_RUNTIME_VENDORED`: unset and `0` link,
    /// `1` vendors.
    #[test]
    fn the_vendored_switch_admits_exactly_unset_zero_and_one() {
        assert_eq!(RuntimeEmit::parse(None).ok(), Some(RuntimeEmit::Linked));
        assert_eq!(
            RuntimeEmit::parse(Some(std::ffi::OsStr::new("0"))).ok(),
            Some(RuntimeEmit::Linked)
        );
        assert_eq!(
            RuntimeEmit::parse(Some(std::ffi::OsStr::new("1"))).ok(),
            Some(RuntimeEmit::Vendored)
        );
    }

    /// Every other set value of `IPE_RUNTIME_VENDORED` is refused, naming the
    /// variable and its admitted spellings; none falls back to a default.
    #[test]
    fn the_vendored_switch_refuses_every_other_value() {
        let refused = |raw: &std::ffi::OsStr| {
            let parsed = RuntimeEmit::parse(Some(raw));
            assert!(
                matches!(
                    &parsed,
                    Err(CliError::EnvSwitchNotRecognised { var, admitted, .. })
                        if *var == RUNTIME_VENDORED_VAR && *admitted == ["0", "1"]
                ),
                "{raw:?} must be refused, got {parsed:?}"
            );
        };
        for raw in ["true", "yes", " 1", "", "2", "1 ", "on", "false"] {
            refused(std::ffi::OsStr::new(raw));
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            refused(std::ffi::OsStr::from_bytes(b"1\xff"));
        }
    }
}
