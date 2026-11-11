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
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, OnceLock};

use include_dir::{Dir, include_dir};
use ipe_backend_rust::RuntimeContentId;
use ipe_fs_open::{ByteCap, EntryCap, EntryName, FileKind, HeldDir, OpenRefusal};

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

/// A runtime crate root an operator named, proved and captured by the override walk.
///
/// The only constructor is that walk: it found, within
/// [`RUNTIME_LOOKUP_CEILING`] ancestors of the named path, a `Cargo.toml`
/// declaring [`RUNTIME_PACKAGE`], captured the crate through held handles,
/// and read [`COMPILER_VERSION`] from the captured manifest. An empty,
/// wrong-package, other-version or unreadable directory has no `ProvenRoot`.
/// The capture is the proof and the payload: nothing rereads the root.
#[derive(Clone, Debug)]
pub struct ProvenRoot {
    /// The named root, made absolute, for display only.
    root: PathBuf,
    /// The captured crate and its per-role stamps.
    captured: Arc<CapturedRuntime>,
}

impl PartialEq for ProvenRoot {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.captured.tree.digest == other.captured.tree.digest
    }
}

impl Eq for ProvenRoot {}

/// One captured runtime crate and the stamps computed from it for this command.
#[derive(Debug)]
struct CapturedRuntime {
    /// The captured crate.
    tree: RuntimeTree,
    /// The capture stamped for [`BundleRole::Out`], computed on first use.
    out: OnceLock<Result<BundledRuntime, BundleFault>>,
    /// The capture stamped for [`BundleRole::Scratch`], computed on first use.
    scratch: OnceLock<Result<BundledRuntime, BundleFault>>,
}

impl CapturedRuntime {
    /// The capture stamped for `role`, computed once per command.
    fn bundled(&self, role: BundleRole) -> Result<&BundledRuntime, CliError> {
        let slot = match role {
            BundleRole::Out => &self.out,
            BundleRole::Scratch => &self.scratch,
        };
        slot.get_or_init(|| self.tree.stamp(role))
            .as_ref()
            .map_err(BundleFault::to_error)
    }
}

impl ProvenRoot {
    /// The named crate root, made absolute; a display name, never reopened.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The captured crate.
    #[must_use]
    pub fn tree(&self) -> &RuntimeTree {
        &self.captured.tree
    }

    /// Prove and capture the runtime crate root at or above `path`.
    ///
    /// # Errors
    /// [`CliError::RuntimeDirInvalid`] when no runtime crate root lies within
    /// the ceiling at or above `path`; [`CliError::RuntimeTreeRefused`] when the
    /// nearest one cannot be captured; [`CliError::RuntimeVersionMismatch`]
    /// when it declares another version; [`CliError::RuntimeVersionUnknown`]
    /// when its version cannot be read. Each refusal offers `remedy`.
    fn prove(path: &Path, remedy: RuntimeRemedy) -> Result<Self, CliError> {
        // The crate root itself or any path inside it (`…/rust/src`,
        // `…/src/ipe_runtime`) names the crate.
        for dir in RUNTIME_LOOKUP_CEILING.ancestors(path) {
            let Ok(held) = HeldDir::open_root(dir) else {
                continue;
            };
            let display = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
            let refused = |refusal: RuntimeTreeRefusal| CliError::RuntimeTreeRefused {
                path: display.clone(),
                refusal,
                remedy,
            };
            if !declares_runtime_package(&held).map_err(refused)? {
                continue;
            }
            let raw = capture_tree(&held).map_err(refused)?;
            return Self::from_capture(&held, raw, display, remedy);
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

    /// The proven root over the capture `raw` of `held`, its identity and
    /// version read from the captured manifest.
    fn from_capture(
        held: &HeldDir,
        raw: BTreeMap<PathBuf, String>,
        root: PathBuf,
        remedy: RuntimeRemedy,
    ) -> Result<Self, CliError> {
        let declared = raw
            .get(Path::new(MANIFEST))
            .and_then(|manifest| runtime_identity(manifest));
        let found = match declared {
            None => {
                return Err(CliError::RuntimeDirInvalid {
                    path: root,
                    points_at_inner: false,
                    remedy,
                });
            }
            Some(DeclaredVersion::Concrete(version)) => Some(version),
            Some(DeclaredVersion::Inherited) => workspace_version(held),
            Some(DeclaredVersion::Unknown) => None,
        };
        let Some(found) = found else {
            return Err(CliError::RuntimeVersionUnknown { path: root, remedy });
        };
        if found != COMPILER_VERSION {
            return Err(CliError::RuntimeVersionMismatch {
                path: root,
                found,
                expected: COMPILER_VERSION.to_owned(),
                remedy,
            });
        }
        let tree = RuntimeTree::from_raw(raw).map_err(|fault| fault.to_error())?;
        Ok(Self {
            root,
            captured: Arc::new(CapturedRuntime {
                tree,
                out: OnceLock::new(),
                scratch: OnceLock::new(),
            }),
        })
    }
}

/// The relative path, from a runtime crate root, of the manifest.
const MANIFEST: &str = "Cargo.toml";

/// The version a runtime manifest declares.
#[derive(Debug, PartialEq, Eq)]
enum DeclaredVersion {
    /// `version = "…"`.
    Concrete(String),
    /// `version.workspace = true`: the enclosing workspace's version.
    Inherited,
    /// No version key, or one of another shape.
    Unknown,
}

/// The version `manifest` declares when its `[package].name` is
/// [`RUNTIME_PACKAGE`]; `None` when it is not the runtime crate's manifest.
fn runtime_identity(manifest: &str) -> Option<DeclaredVersion> {
    let doc = manifest.parse::<toml_edit::DocumentMut>().ok()?;
    let package = doc.get("package")?.as_table_like()?;
    if package.get("name")?.as_str()? != RUNTIME_PACKAGE {
        return None;
    }
    let version = package.get("version");
    Some(match version {
        Some(item) => item.as_str().map_or_else(
            || {
                let inherited = item
                    .as_table_like()
                    .and_then(|table| table.get("workspace"))
                    .and_then(toml_edit::Item::as_bool)
                    == Some(true);
                if inherited {
                    DeclaredVersion::Inherited
                } else {
                    DeclaredVersion::Unknown
                }
            },
            |concrete| DeclaredVersion::Concrete(concrete.to_owned()),
        ),
        None => DeclaredVersion::Unknown,
    })
}

/// The entry name of the manifest.
fn manifest_name() -> Option<EntryName> {
    EntryName::new(std::ffi::OsStr::new(MANIFEST))
}

/// Whether `held` holds a manifest declaring [`RUNTIME_PACKAGE`].
///
/// An absent manifest is "not a runtime root"; a manifest present but not
/// readable as a regular file is refused, never walked past.
fn declares_runtime_package(held: &HeldDir) -> Result<bool, RuntimeTreeRefusal> {
    let refusal = |reason| RuntimeTreeRefusal {
        path: PathBuf::from(MANIFEST),
        reason,
    };
    let name = manifest_name().ok_or_else(|| refusal(RuntimeTreeReason::Unreadable))?;
    let file = match held.open_regular(&name) {
        Ok(file) => file,
        Err(OpenRefusal::Absent | OpenRefusal::NotRegular(FileKind::Dir)) => return Ok(false),
        Err(other) => return Err(refusal(RuntimeTreeReason::of(other))),
    };
    let text = file
        .read_utf8(crate::io_bounded::SMALL_FILE_CAP)
        .map_err(|e| refusal(RuntimeTreeReason::of(e)))?;
    Ok(runtime_identity(&text).is_some())
}

/// The `[workspace.package].version` of the first manifest above `root`
/// holding a `[workspace]` table, each level opened through the held parent
/// and never through a link; `None` when there is none within the ceiling or
/// a level cannot be read.
fn workspace_version(root: &HeldDir) -> Option<String> {
    let name = manifest_name()?;
    let AncestorCeiling(ceiling) = RUNTIME_LOOKUP_CEILING;
    let mut level = root.parent().ok()??;
    for _ in 1..ceiling {
        match level.open_regular(&name) {
            Ok(file) => {
                let text = file.read_utf8(crate::io_bounded::SMALL_FILE_CAP).ok()?;
                let doc = text.parse::<toml_edit::DocumentMut>().ok()?;
                if let Some(workspace) = doc.get("workspace") {
                    return workspace
                        .as_table_like()?
                        .get("package")?
                        .as_table_like()?
                        .get("version")?
                        .as_str()
                        .map(str::to_owned);
                }
            }
            Err(OpenRefusal::Absent) => {}
            Err(_) => return None,
        }
        level = level.parent().ok()??;
    }
    None
}

/// The root directories neither the embedded bundle nor a capture carries.
///
/// `tests/` is not needed to build the crate as a path dependency, and
/// `target/` is a build's output, never its source.
const SKIPPED_ROOT_DIRS: &[&str] = &["tests", "target"];

/// The deepest directory nesting a captured runtime tree may hold.
pub const RUNTIME_TREE_DEPTH: usize = 16;

/// The most entries, files and directories together, a captured runtime tree may hold.
pub const RUNTIME_TREE_ENTRIES: u32 = 4096;

/// The largest single file a captured runtime tree may hold, in bytes.
pub const RUNTIME_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The most bytes all files of a captured runtime tree may hold together.
pub const RUNTIME_TREE_BYTES: u64 = 64 * 1024 * 1024;

/// [`RUNTIME_FILE_BYTES`] as a [`ByteCap`].
const RUNTIME_FILE_CAP: ByteCap =
    ByteCap::from_nonzero(const { NonZeroU64::MIN.saturating_add(RUNTIME_FILE_BYTES - 1) });

/// Why a runtime tree was not captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeTreeReason {
    /// A link (or reparse point) stands below the root.
    Link,
    /// A FIFO, socket, device or other non-regular entry.
    NotRegular,
    /// A file with more than one hard link, so it may be shared with a path outside the tree.
    HardLinked,
    /// A file, or an entry name, that is not UTF-8.
    NotUtf8,
    /// The entry could not be opened or read.
    Unreadable,
    /// A directory nested deeper than [`RUNTIME_TREE_DEPTH`].
    TooDeep,
    /// More than [`RUNTIME_TREE_ENTRIES`] entries.
    TooManyEntries,
    /// A file larger than [`RUNTIME_FILE_BYTES`].
    FileTooLarge,
    /// Files larger than [`RUNTIME_TREE_BYTES`] together.
    TreeTooLarge,
    /// The root vanished, or holds no manifest.
    Absent,
}

impl RuntimeTreeReason {
    /// The reason an open or read refusal names.
    const fn of(refusal: OpenRefusal) -> Self {
        match refusal {
            OpenRefusal::Absent => Self::Absent,
            OpenRefusal::Link => Self::Link,
            OpenRefusal::NotRegular(_) => Self::NotRegular,
            OpenRefusal::NotUtf8 => Self::NotUtf8,
            OpenRefusal::TooLarge(_) => Self::FileTooLarge,
            OpenRefusal::TooManyEntries(_) => Self::TooManyEntries,
            OpenRefusal::Denied
            | OpenRefusal::InUse
            | OpenRefusal::BadName
            | OpenRefusal::Io(_) => Self::Unreadable,
        }
    }
}

/// A runtime tree refused by the capture: the entry, relative to the crate root, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeTreeRefusal {
    /// The refused entry, relative to the crate root.
    pub path: PathBuf,
    /// Why it was refused.
    pub reason: RuntimeTreeReason,
}

/// The running totals of one capture.
struct CaptureWalk {
    /// Every captured file, relative to the crate root, with its text.
    files: BTreeMap<PathBuf, String>,
    /// Entries listed so far.
    entries: u32,
    /// File bytes read so far.
    bytes: u64,
}

/// Capture every file of the runtime crate `root` holds, through held
/// handles, never following a link below it, under the tree ceilings.
///
/// The root directories [`SKIPPED_ROOT_DIRS`] names are not listed.
fn capture_tree(root: &HeldDir) -> Result<BTreeMap<PathBuf, String>, RuntimeTreeRefusal> {
    let mut walk = CaptureWalk {
        files: BTreeMap::new(),
        entries: 0,
        bytes: 0,
    };
    capture_dir(root, Path::new(""), 0, &mut walk)?;
    if !walk.files.contains_key(Path::new(MANIFEST)) {
        return Err(RuntimeTreeRefusal {
            path: PathBuf::from(MANIFEST),
            reason: RuntimeTreeReason::Absent,
        });
    }
    Ok(walk.files)
}

/// Capture `dir`, at `rel` and nesting `depth` below the root, into `walk`.
fn capture_dir(
    dir: &HeldDir,
    rel: &Path,
    depth: usize,
    walk: &mut CaptureWalk,
) -> Result<(), RuntimeTreeRefusal> {
    let refuse = |path: PathBuf, reason| RuntimeTreeRefusal { path, reason };
    // Each level lists at most the budget left, so the whole walk holds at
    // most the tree ceiling of names; the floor of one lets a full budget
    // still see that one more entry exists.
    let left = RUNTIME_TREE_ENTRIES.saturating_sub(walk.entries).max(1);
    let cap = EntryCap::new(left)
        .ok_or_else(|| refuse(rel.to_path_buf(), RuntimeTreeReason::TooManyEntries))?;
    let listing = dir
        .entries(cap)
        .map_err(|e| refuse(rel.to_path_buf(), RuntimeTreeReason::of(e)))?;
    for (name, kind) in listing {
        walk.entries = walk.entries.saturating_add(1);
        let Some(spelled) = name.as_os_str().to_str() else {
            return Err(refuse(
                rel.join(name.as_os_str()),
                RuntimeTreeReason::NotUtf8,
            ));
        };
        let child = rel.join(spelled);
        if walk.entries > RUNTIME_TREE_ENTRIES {
            return Err(refuse(child, RuntimeTreeReason::TooManyEntries));
        }
        if depth == 0 && SKIPPED_ROOT_DIRS.contains(&spelled) {
            continue;
        }
        match kind {
            FileKind::Dir => {
                if depth >= RUNTIME_TREE_DEPTH {
                    return Err(refuse(child, RuntimeTreeReason::TooDeep));
                }
                let sub = dir
                    .child_dir(&name)
                    .map_err(|e| refuse(child.clone(), RuntimeTreeReason::of(e)))?;
                capture_dir(&sub, &child, depth.saturating_add(1), walk)?;
            }
            FileKind::Regular => {
                let text = capture_file(dir, &name, walk.bytes)
                    .map_err(|reason| refuse(child.clone(), reason))?;
                walk.bytes = walk
                    .bytes
                    .saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX));
                if walk.bytes > RUNTIME_TREE_BYTES {
                    return Err(refuse(child, RuntimeTreeReason::TreeTooLarge));
                }
                walk.files.insert(child, text);
            }
            FileKind::Symlink => return Err(refuse(child, RuntimeTreeReason::Link)),
            FileKind::Fifo | FileKind::Socket | FileKind::Device | FileKind::Other => {
                return Err(refuse(child, RuntimeTreeReason::NotRegular));
            }
        }
    }
    Ok(())
}

/// Read the regular file `name` of `dir` as text, given `read` bytes already
/// captured; refused before any read when it would pass a ceiling.
fn capture_file(dir: &HeldDir, name: &EntryName, read: u64) -> Result<String, RuntimeTreeReason> {
    let file = dir.open_regular(name).map_err(RuntimeTreeReason::of)?;
    if file.link_count().map_err(RuntimeTreeReason::of)? != 1 {
        return Err(RuntimeTreeReason::HardLinked);
    }
    if file.len() > RUNTIME_FILE_BYTES {
        return Err(RuntimeTreeReason::FileTooLarge);
    }
    if read.saturating_add(file.len()) > RUNTIME_TREE_BYTES {
        return Err(RuntimeTreeReason::TreeTooLarge);
    }
    file.read_utf8(RUNTIME_FILE_CAP)
        .map_err(RuntimeTreeReason::of)
}

/// One runtime crate: every bundled file, the root manifest carrying
/// [`COMPILER_VERSION`], and the digest of them.
///
/// Built only from the embedded crate ([`RuntimeTree::embedded`]) or from a
/// proven capture ([`ProvenRoot`]), both through one file-set rule
/// ([`SKIPPED_ROOT_DIRS`]) and one normalization, so the same crate gives the
/// same digest whichever way it arrived.
#[derive(Debug)]
pub struct RuntimeTree {
    /// Every bundled file, relative to the crate root, with its text.
    files: BTreeMap<PathBuf, String>,
    /// The root manifest as read, the base every stamp rewrites.
    raw_manifest: String,
    /// The digest of `files`.
    digest: RuntimeDigest,
}

impl RuntimeTree {
    /// The tree over the raw files `raw`, its root manifest normalized to
    /// [`COMPILER_VERSION`] with no dev dependencies.
    ///
    /// # Errors
    /// [`BundleFault::Manifest`] when the root manifest is missing or does not parse.
    fn from_raw(mut raw: BTreeMap<PathBuf, String>) -> Result<Self, BundleFault> {
        let raw_manifest = raw
            .get(Path::new(MANIFEST))
            .cloned()
            .ok_or(BundleFault::Manifest(ManifestFault::NoUtf8Manifest))?;
        let normalized = prepare_bundled_manifest(&raw_manifest, COMPILER_VERSION)?;
        raw.insert(PathBuf::from(MANIFEST), normalized);
        let keys = raw
            .iter()
            .map(|(path, text)| (digest_path(path), text.as_str()))
            .collect::<Vec<_>>();
        let digest = RuntimeDigest::of(keys.iter().map(|(path, text)| (path.as_str(), *text)));
        Ok(Self {
            files: raw,
            raw_manifest,
            digest,
        })
    }

    /// The runtime crate compiled into this binary.
    ///
    /// # Errors
    /// [`CliError::RuntimeMaterializeFailed`] when an embedded file is not UTF-8;
    /// [`CliError::BundledManifest`] when the embedded manifest does not parse.
    pub fn embedded() -> Result<&'static Self, CliError> {
        unstamped_bundle().as_ref().map_err(BundleFault::to_error)
    }

    /// Every bundled file, relative to the crate root, with its text.
    #[must_use]
    pub const fn files(&self) -> &BTreeMap<PathBuf, String> {
        &self.files
    }

    /// The digest of every bundled byte.
    #[must_use]
    pub const fn digest(&self) -> RuntimeDigest {
        self.digest
    }

    /// The tree bundled for `role`: the manifest's version stamped with the
    /// role and the digest, dev dependencies removed.
    ///
    /// # Errors
    /// [`BundleFault::Manifest`] when the manifest does not parse.
    fn stamp(&self, role: BundleRole) -> Result<BundledRuntime, BundleFault> {
        let mut files = self.files.clone();
        let stamped =
            prepare_bundled_manifest(&self.raw_manifest, &stamped_version(role, self.digest))?;
        files.insert(PathBuf::from(MANIFEST), stamped);
        Ok(BundledRuntime {
            files,
            digest: self.digest,
        })
    }

    /// The module tree under the crate's `src/`, keyed relative to `src/`.
    fn module_tree(&self) -> RuntimeModuleTree {
        RuntimeModuleTree(
            self.files
                .iter()
                .filter_map(|(path, text)| {
                    path.strip_prefix(RUNTIME_SRC_DIR)
                        .ok()
                        .map(|rel| (rel.to_path_buf(), text.clone()))
                })
                .collect(),
        )
    }
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

/// The embedded runtime crate, the shared base both roles stamp.
fn unstamped_bundle() -> &'static Result<RuntimeTree, BundleFault> {
    static BASE: LazyLock<Result<RuntimeTree, BundleFault>> = LazyLock::new(|| {
        let mut files = BTreeMap::new();
        collect_dir_text_from_embedded(&RUNTIME_CRATE, Path::new(""), true, &mut files)?;
        RuntimeTree::from_raw(files)
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
/// [`SKIPPED_ROOT_DIRS`] skipped.
///
/// Computed once per role and reused across every emit.
///
/// # Errors
/// [`CliError::RuntimeMaterializeFailed`] when an embedded file is not UTF-8;
/// [`CliError::BundledManifest`] when the embedded manifest does not parse.
pub fn bundled_runtime(role: BundleRole) -> Result<&'static BundledRuntime, CliError> {
    /// The bundle of `role`, stamped from the shared base.
    fn stamp(role: BundleRole) -> Result<BundledRuntime, BundleFault> {
        unstamped_bundle()
            .as_ref()
            .map_err(Clone::clone)?
            .stamp(role)
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
/// `prefix` to each entry's relative path, skipping [`SKIPPED_ROOT_DIRS`] at the root.
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
                if at_root && SKIPPED_ROOT_DIRS.iter().any(|skipped| name == *skipped) {
                    continue;
                }
                collect_dir_text_from_embedded(sub, &prefix.join(name), false, out)?;
            }
            include_dir::DirEntry::File(file) => {
                let name = file.path().file_name().unwrap_or_default();
                let rel = prefix.join(name);
                let text = std::str::from_utf8(file.contents())
                    .map_err(|_| BundleFault::NotUtf8(rel.clone()))?;
                out.insert(rel, text.to_owned());
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
    /// A release build: the compiler's embedded runtime only.
    ///
    /// A named root is still proved and captured, and admitted only when its
    /// bytes are the embedded crate's; any other runtime is refused with
    /// [`CliError::ReleaseRuntimeOverride`], so a shipped artifact never links
    /// a runtime the compiler does not carry.
    Release,
}

/// The one runtime source a [`RuntimeOrigin::Gate`] or [`RuntimeOrigin::Release`] admits.
static EMBEDDED_RUNTIME: RuntimeSource = RuntimeSource::Embedded;

impl RuntimeOrigin {
    /// The runtime source this origin lets an emit carry, given the `runtime`
    /// its caller resolved.
    ///
    /// A gate or a release carries the embedded copy whatever it was handed,
    /// so a caller pairing their options with an override root cannot steer a
    /// judged or shipped build; a developer build carries `runtime` as resolved.
    #[must_use]
    pub const fn admitted_runtime(self, runtime: &RuntimeSource) -> &RuntimeSource {
        match self {
            Self::Gate | Self::Release => &EMBEDDED_RUNTIME,
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
    /// [`ProvenRoot`]'s walk; it is never passed over for another source. A
    /// [`RuntimeOrigin::Release`] names a root the same way and takes it only
    /// when its captured bytes are the embedded crate's, as [`Self::Embedded`].
    ///
    /// # Errors
    /// The refusals of the override walk, each offering `remedy`;
    /// [`CliError::ReleaseRuntimeOverride`] for a release naming a runtime
    /// other than the embedded one.
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
        let named = explicit.or_else(|| ambient.map(Path::new));
        match (origin, named) {
            (RuntimeOrigin::Gate, _)
            | (RuntimeOrigin::Developer | RuntimeOrigin::Release, None) => Ok(Self::Embedded),
            (RuntimeOrigin::Developer, Some(named)) => {
                ProvenRoot::prove(named, remedy).map(Self::Override)
            }
            (RuntimeOrigin::Release, Some(named)) => {
                let proven = ProvenRoot::prove(named, remedy)?;
                if proven.tree().digest() == RuntimeTree::embedded()?.digest() {
                    Ok(Self::Embedded)
                } else {
                    Err(CliError::ReleaseRuntimeOverride {
                        path: proven.root().to_path_buf(),
                    })
                }
            }
        }
    }

    /// The runtime crate this source bundles, captured once.
    ///
    /// # Errors
    /// As [`RuntimeTree::embedded`].
    pub fn tree(&self) -> Result<&RuntimeTree, CliError> {
        match self {
            Self::Embedded => RuntimeTree::embedded(),
            Self::Override(proven) => Ok(proven.tree()),
        }
    }

    /// The runtime crate a linked emit bundles for `role`, its manifest
    /// stamped with the role and the content digest.
    ///
    /// # Errors
    /// As [`bundled_runtime`].
    pub fn bundled(&self, role: BundleRole) -> Result<&BundledRuntime, CliError> {
        match self {
            Self::Embedded => bundled_runtime(role),
            Self::Override(proven) => proven.captured.bundled(role),
        }
    }

    /// The module tree a vendored emit copies into `src/ipe_runtime/`.
    ///
    /// # Errors
    /// As [`RuntimeTree::embedded`].
    pub fn module_tree(&self) -> Result<RuntimeModuleTree, CliError> {
        self.tree().map(RuntimeTree::module_tree)
    }

    /// The content identity of the runtime this source bundles: the digest of
    /// its captured bytes.
    ///
    /// # Errors
    /// As [`RuntimeTree::embedded`].
    pub fn content_id(&self) -> Result<RuntimeContentId, CliError> {
        self.tree()
            .map(|tree| RuntimeContentId::from_digest_bytes(tree.digest().bytes()))
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
        let embedded = RuntimeTree::embedded().expect("the embedded runtime bundles");
        let manifest = embedded
            .files()
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
        let absolute = std::path::absolute(&dir).expect("scratch dir is absolute");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(&resolved, Ok(RuntimeSource::Override(proven)) if proven.root() == absolute),
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

    /// The in-repo runtime crate root.
    fn in_repo_runtime() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../runtime/rust")
    }

    /// The embedded tree is the in-repo crate: capturing `src/runtime/rust`
    /// through the override walk gives the embedded digest, so both walkers
    /// share one file-set rule and one normalization.
    #[test]
    #[allow(clippy::expect_used)] // a refused in-repo capture is the test failure
    fn the_in_repo_capture_has_the_embedded_digest() {
        let captured = ProvenRoot::prove(&in_repo_runtime(), RuntimeRemedy::EnvOnly)
            .expect("the in-repo runtime proves");
        let embedded = RuntimeTree::embedded().expect("the embedded tree bundles");
        assert_eq!(captured.tree().files(), embedded.files());
        assert_eq!(captured.tree().digest(), embedded.digest());
        assert!(
            RuntimeSource::Embedded
                .module_tree()
                .expect("the embedded tree bundles")
                .files()
                .contains_key(Path::new("mod.rs"))
        );
    }

    /// Write `text` at `rel` under `root`, creating its parents.
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn plant(root: &Path, rel: &str, text: &[u8]) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create the parent");
        }
        std::fs::write(path, text).expect("write the planted file");
    }

    /// A scratch runtime crate at the compiler's version with one source file.
    fn valid_crate(tag: &str) -> PathBuf {
        let dir = runtime_root_at(tag, COMPILER_VERSION);
        plant(&dir, "src/lib.rs", b"pub fn probe() {}\n");
        dir
    }

    /// The capture refusal of the crate at `dir`, if the walk refused one.
    fn tree_refusal(dir: &Path) -> Option<RuntimeTreeRefusal> {
        match ProvenRoot::prove(dir, RuntimeRemedy::EnvOnly) {
            Err(CliError::RuntimeTreeRefused { refusal, .. }) => Some(refusal),
            _ => None,
        }
    }

    /// The reason the capture of `dir` names for the entry `rel`.
    fn refused_at(dir: &Path, rel: &str) -> Option<RuntimeTreeReason> {
        tree_refusal(dir)
            .filter(|refusal| refusal.path == Path::new(rel))
            .map(|refusal| refusal.reason)
    }

    /// A file link below the root is refused by name, never followed to its
    /// target outside the tree, and the source never resolves to an override.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn a_file_link_below_the_root_is_refused() {
        let dir = valid_crate("ipe-runtime-file-link");
        let outside = crate::scratch::ScratchDir::new("ipe-runtime-file-link-target")
            .expect("scratch dir")
            .into_path();
        plant(&outside, "secret.rs", b"pub const SECRET: u8 = 1;\n");
        std::os::unix::fs::symlink(outside.join("secret.rs"), dir.join("src/x.rs"))
            .expect("plant the link");
        let reason = refused_at(&dir, "src/x.rs");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
        assert_eq!(reason, Some(RuntimeTreeReason::Link));
    }

    /// A directory link below the root, and a link whose target stays inside
    /// the tree, are both refused: no link is ever followed.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn every_link_below_the_root_is_refused_wherever_it_points() {
        let dir = valid_crate("ipe-runtime-dir-link");
        let outside = crate::scratch::ScratchDir::new("ipe-runtime-dir-link-target")
            .expect("scratch dir")
            .into_path();
        plant(&outside, "inner.rs", b"pub fn inner() {}\n");
        std::os::unix::fs::symlink(&outside, dir.join("src/m")).expect("plant the dir link");
        let dir_link = refused_at(&dir, "src/m");
        let _ = std::fs::remove_file(dir.join("src/m"));
        std::os::unix::fs::symlink(dir.join("src/lib.rs"), dir.join("src/alias.rs"))
            .expect("plant the inner link");
        let inner_link = refused_at(&dir, "src/alias.rs");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
        assert_eq!(dir_link, Some(RuntimeTreeReason::Link));
        assert_eq!(inner_link, Some(RuntimeTreeReason::Link));
    }

    /// An unreadable manifest, and an unreadable source file, are refused by
    /// name. Under a privileged euid the read succeeds, and the test asserts
    /// that it ran privileged rather than passing without the refusal.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn an_unreadable_entry_is_refused_by_name() {
        use std::os::unix::fs::PermissionsExt as _;
        let locked = std::fs::Permissions::from_mode(0o000);
        let open = std::fs::Permissions::from_mode(0o644);
        let dir = valid_crate("ipe-runtime-unreadable");
        std::fs::set_permissions(dir.join(MANIFEST), locked.clone()).expect("lock the manifest");
        let privileged = std::fs::read(dir.join(MANIFEST)).is_ok();
        let manifest = tree_refusal(&dir);
        std::fs::set_permissions(dir.join(MANIFEST), open.clone()).expect("unlock the manifest");
        std::fs::set_permissions(dir.join("src/lib.rs"), locked).expect("lock the source");
        let source = refused_at(&dir, "src/lib.rs");
        std::fs::set_permissions(dir.join("src/lib.rs"), open).expect("unlock the source");
        let _ = std::fs::remove_dir_all(&dir);
        if privileged {
            assert!(
                rustix::process::geteuid().is_root() && manifest.is_none() && source.is_none(),
                "only a root euid reads a mode-000 file, and then nothing is refused"
            );
            return;
        }
        assert_eq!(
            manifest,
            Some(RuntimeTreeRefusal {
                path: PathBuf::from(MANIFEST),
                reason: RuntimeTreeReason::Unreadable,
            })
        );
        assert_eq!(source, Some(RuntimeTreeReason::Unreadable));
    }

    /// A FIFO below the root is refused as not regular, without blocking on
    /// an open no writer will ever answer.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn a_fifo_below_the_root_is_refused_without_blocking() {
        let dir = valid_crate("ipe-runtime-fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join("src/fifo.rs"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .expect("plant the FIFO");
        let (send, receive) = std::sync::mpsc::channel();
        let walked = dir.clone();
        std::thread::spawn(move || {
            let _ = send.send(refused_at(&walked, "src/fifo.rs"));
        });
        let reason = receive.recv_timeout(std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(reason, Ok(Some(RuntimeTreeReason::NotRegular)));
    }

    /// A file sharing its inode through a second hard link is refused: its
    /// bytes may be written through a path outside the tree.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn a_hard_linked_file_is_refused() {
        let dir = valid_crate("ipe-runtime-hard-link");
        std::fs::hard_link(dir.join("src/lib.rs"), dir.join("src/h.rs"))
            .expect("plant the hard link");
        let refusal = tree_refusal(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            refusal.map(|refusal| refusal.reason),
            Some(RuntimeTreeReason::HardLinked)
        );
    }

    /// A content change the mtime does not show changes the digest, the
    /// stamped version and the content identity: freshness keys on bytes,
    /// never on the root's path.
    #[test]
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn a_content_change_under_a_pinned_mtime_changes_every_key() {
        let dir = valid_crate("ipe-runtime-content-change");
        let lib = dir.join("src/lib.rs");
        let mtime = std::fs::metadata(&lib)
            .and_then(|meta| meta.modified())
            .expect("read the mtime");
        let keys = || {
            let source = RuntimeSource::resolve_from(
                RuntimeOrigin::Developer,
                Some(&dir),
                None,
                RuntimeRemedy::EnvOnly,
            )
            .expect("the scratch runtime proves");
            let stamp = source
                .bundled(BundleRole::Out)
                .expect("the scratch runtime stamps")
                .files()
                .get(Path::new(MANIFEST))
                .cloned();
            let content = source.content_id().expect("the content id derives");
            (source.tree().expect("the tree").digest(), stamp, content)
        };
        let before = keys();
        plant(&dir, "src/lib.rs", b"pub fn probe() { let _ = 2; }\n");
        std::fs::File::options()
            .write(true)
            .open(&lib)
            .and_then(|file| file.set_modified(mtime))
            .expect("pin the mtime back");
        let after = keys();
        let _ = std::fs::remove_dir_all(&dir);
        assert_ne!(before.0, after.0, "the digest follows the bytes");
        assert_ne!(before.1, after.1, "the stamped manifest follows the bytes");
        assert_ne!(before.2, after.2, "the content identity follows the bytes");
    }

    /// A scratch crate whose manifest is `manifest`, optionally under an outer
    /// directory holding `workspace` as its manifest; returns the outer
    /// directory and the crate root.
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn crate_with(tag: &str, manifest: &str, workspace: Option<&str>) -> (PathBuf, PathBuf) {
        let outer = crate::scratch::ScratchDir::new(tag)
            .expect("scratch dir")
            .into_path();
        if let Some(workspace) = workspace {
            plant(&outer, MANIFEST, workspace.as_bytes());
        }
        let root = outer.join("rt");
        plant(&root, MANIFEST, manifest.as_bytes());
        plant(&root, "src/lib.rs", b"pub fn probe() {}\n");
        (outer, root)
    }

    /// The developer resolution of `manifest` under `workspace`.
    fn resolve_crate(
        tag: &str,
        manifest: &str,
        workspace: Option<&str>,
    ) -> Result<RuntimeSource, CliError> {
        let (outer, root) = crate_with(tag, manifest, workspace);
        let resolved = RuntimeSource::resolve_from(
            RuntimeOrigin::Developer,
            Some(&root),
            None,
            RuntimeRemedy::EnvOnly,
        );
        let _ = std::fs::remove_dir_all(&outer);
        resolved
    }

    /// The version is read from the captured manifest's `[package]` table:
    /// an inherited version from the enclosing workspace, an unreadable one
    /// refused, and a package name outside `[package]` names no runtime.
    #[test]
    fn the_runtime_version_is_read_from_the_captured_manifest() {
        let package = format!("[package]\nname = \"{RUNTIME_PACKAGE}\"\n");
        let inherited = format!("{package}version.workspace = true\n");
        let workspace_at =
            |version: &str| format!("[workspace]\n[workspace.package]\nversion = \"{version}\"\n");
        let orphan = resolve_crate("ipe-runtime-orphan-inherit", &inherited, None);
        let other = resolve_crate(
            "ipe-runtime-other-workspace",
            &inherited,
            Some(&workspace_at("0.0.2")),
        );
        let own = resolve_crate(
            "ipe-runtime-own-workspace",
            &inherited,
            Some(&workspace_at(COMPILER_VERSION)),
        );
        let unversioned = resolve_crate("ipe-runtime-unversioned", &package, None);
        let dependency_only = resolve_crate(
            "ipe-runtime-dependency-only",
            &format!(
                "[package]\nname = \"app\"\nversion = \"{COMPILER_VERSION}\"\n\
                 [dependencies]\nname = \"{RUNTIME_PACKAGE}\"\n"
            ),
            None,
        );
        assert!(
            matches!(orphan, Err(CliError::RuntimeVersionUnknown { .. })),
            "{orphan:?}"
        );
        assert!(
            matches!(&other, Err(CliError::RuntimeVersionMismatch { found, .. }) if found == "0.0.2"),
            "{other:?}"
        );
        assert!(matches!(own, Ok(RuntimeSource::Override(_))), "{own:?}");
        assert!(
            matches!(unversioned, Err(CliError::RuntimeVersionUnknown { .. })),
            "{unversioned:?}"
        );
        assert!(
            matches!(dependency_only, Err(CliError::RuntimeDirInvalid { .. })),
            "{dependency_only:?}"
        );
    }

    /// The capture carries neither the crate's `tests/` nor its `target/`,
    /// the same file set the embedded bundle carries.
    #[test]
    fn the_capture_skips_tests_and_target() {
        let dir = valid_crate("ipe-runtime-skipped-dirs");
        plant(&dir, "tests/it.rs", b"#[test]\nfn it() {}\n");
        plant(&dir, "target/debug/out.rs", b"// build output\n");
        let proven = ProvenRoot::prove(&dir, RuntimeRemedy::EnvOnly);
        let _ = std::fs::remove_dir_all(&dir);
        let files = proven
            .map(|proven| proven.tree().files().keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        assert_eq!(
            files,
            vec![PathBuf::from(MANIFEST), PathBuf::from("src/lib.rs")]
        );
    }

    /// One directory past the depth ceiling is refused.
    #[test]
    fn a_tree_past_the_depth_ceiling_is_refused() {
        let dir = valid_crate("ipe-runtime-too-deep");
        let deep = (0..=RUNTIME_TREE_DEPTH).fold(String::from("src"), |path, _| path + "/d");
        plant(&dir, &format!("{deep}/x.rs"), b"\n");
        let refusal = tree_refusal(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            refusal.map(|refusal| refusal.reason),
            Some(RuntimeTreeReason::TooDeep)
        );
    }

    /// One entry past the entry ceiling is refused.
    #[test]
    fn a_tree_past_the_entry_ceiling_is_refused() {
        let dir = valid_crate("ipe-runtime-too-many");
        for index in 0..RUNTIME_TREE_ENTRIES {
            plant(&dir, &format!("src/many/f{index}.rs"), b"");
        }
        let refusal = tree_refusal(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            refusal.map(|refusal| refusal.reason),
            Some(RuntimeTreeReason::TooManyEntries)
        );
    }

    /// `len` bytes of `a`.
    fn filler(len: u64) -> Vec<u8> {
        vec![b'a'; usize::try_from(len).unwrap_or(usize::MAX)]
    }

    /// One file one byte past the file ceiling is refused by name.
    #[test]
    fn a_file_past_the_file_ceiling_is_refused() {
        let dir = valid_crate("ipe-runtime-file-too-large");
        plant(
            &dir,
            "src/big.rs",
            &filler(RUNTIME_FILE_BYTES.saturating_add(1)),
        );
        let reason = refused_at(&dir, "src/big.rs");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(reason, Some(RuntimeTreeReason::FileTooLarge));
    }

    /// Files one byte past the tree ceiling together are refused.
    #[test]
    fn files_past_the_tree_ceiling_together_are_refused() {
        let dir = valid_crate("ipe-runtime-tree-too-large");
        let whole = filler(RUNTIME_FILE_BYTES);
        for index in 0..RUNTIME_TREE_BYTES / RUNTIME_FILE_BYTES {
            plant(&dir, &format!("src/big{index}.rs"), &whole);
        }
        let refusal = tree_refusal(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            refusal.map(|refusal| refusal.reason),
            Some(RuntimeTreeReason::TreeTooLarge)
        );
    }

    /// The embedded crate fits every tree ceiling with a fourfold headroom.
    #[test]
    fn the_embedded_tree_fits_its_ceilings_with_headroom() {
        let embedded = RuntimeTree::embedded().expect("the embedded tree bundles");
        let files = embedded.files();
        let mut dirs = std::collections::BTreeSet::new();
        for path in files.keys() {
            dirs.extend(
                path.ancestors()
                    .skip(1)
                    .filter(|dir| !dir.as_os_str().is_empty()),
            );
        }
        let entries = files.len() + dirs.len();
        let depth = files
            .keys()
            .map(|path| path.components().count().saturating_sub(1))
            .max()
            .unwrap_or_default();
        let sizes = files
            .values()
            .map(|text| u64::try_from(text.len()).unwrap_or(u64::MAX));
        let largest = sizes.clone().max().unwrap_or_default();
        let total = sizes.sum::<u64>();
        let entry_ceiling = usize::try_from(RUNTIME_TREE_ENTRIES).unwrap_or(usize::MAX);
        assert!(
            entries.saturating_mul(4) <= entry_ceiling,
            "{entries} entries"
        );
        assert!(
            depth.saturating_mul(4) <= RUNTIME_TREE_DEPTH,
            "{depth} levels"
        );
        assert!(
            largest.saturating_mul(4) <= RUNTIME_FILE_BYTES,
            "{largest}-byte file"
        );
        assert!(
            total.saturating_mul(4) <= RUNTIME_TREE_BYTES,
            "{total} bytes"
        );
    }

    /// A release takes the embedded crate: a named runtime with the embedded
    /// bytes resolves as the embedded copy, any other is refused, and a gate
    /// or a release admits only the embedded copy whatever it is handed.
    #[test]
    #[allow(clippy::expect_used)] // a failed scratch setup is the test failure
    fn a_release_admits_only_the_embedded_runtime() {
        let dir = valid_crate("ipe-runtime-release-override");
        let differing = RuntimeSource::resolve_from(
            RuntimeOrigin::Release,
            None,
            Some(dir.as_os_str()),
            RuntimeRemedy::WithRuntimeFlag,
        );
        let handed = ProvenRoot::prove(&dir, RuntimeRemedy::EnvOnly).map(RuntimeSource::Override);
        let _ = std::fs::remove_dir_all(&dir);
        let same = RuntimeSource::resolve_from(
            RuntimeOrigin::Release,
            Some(&in_repo_runtime()),
            None,
            RuntimeRemedy::WithRuntimeFlag,
        );
        let unnamed = RuntimeSource::resolve_from(
            RuntimeOrigin::Release,
            None,
            None,
            RuntimeRemedy::WithRuntimeFlag,
        );
        assert!(
            matches!(differing, Err(CliError::ReleaseRuntimeOverride { .. })),
            "{differing:?}"
        );
        assert!(matches!(same, Ok(RuntimeSource::Embedded)), "{same:?}");
        assert!(
            matches!(unnamed, Ok(RuntimeSource::Embedded)),
            "{unnamed:?}"
        );
        let handed = handed.expect("the scratch runtime proves");
        assert_eq!(
            RuntimeOrigin::Release.admitted_runtime(&handed),
            &RuntimeSource::Embedded
        );
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
