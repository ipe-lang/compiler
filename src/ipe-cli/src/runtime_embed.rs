//! The runtime crate source, embedded in the `ipe` binary and materialized on
//! demand.
//!
//! A copied `ipe` binary must be able to build a program with nothing beside it
//! but a Rust toolchain — no separate runtime download, no version-mismatch
//! hazard. To make that true, the runtime crate SOURCE (`src/runtime/rust`: its
//! `Cargo.toml` + `src/**`) is compiled into this binary as a byte-tree and
//! written to `<IPE_HOME>/runtime/<version>/rust` the first time a build needs
//! it. Because the binary materializes its OWN embedded source, the runtime the
//! emitted project links against matches the compiler that emitted it by
//! construction — there is no cross-machine version to drift.
//!
//! Only SOURCE is embedded; it is compiled locally by the user's toolchain. No
//! prebuilt object code ships (that would be an ABI/trust surface, not a source
//! distribution).
//!
//! # `IPE_HOME`
//! The materialized runtime lives under `IPE_HOME`, resolved once:
//! 1. `$IPE_HOME` — explicit override; refused unless absolute.
//! 2. `$XDG_DATA_HOME/ipe` — the XDG data root, when absolute.
//! 3. `$HOME/.ipe` — the default, when `HOME` is absolute.
//!
//! Nothing is ever written outside the resolved `IPE_HOME`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use include_dir::{Dir, include_dir};

use crate::CliError;

/// The runtime crate source tree, embedded at build time from the workspace
/// `src/runtime/rust` directory (the crate ROOT, so the materialized tree is a
/// self-contained buildable crate). `tests/` is present in the source tree but
/// is not needed to build the crate as a path dependency; it is skipped on
/// materialize (see [`materialize`]) so the on-disk runtime is the minimal
/// buildable crate.
static RUNTIME_CRATE: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../runtime/rust");

/// The compiler's own version — the workspace-synced `version` field.
///
/// The embedded runtime crate is materialized WITH this version (see
/// [`concretize_manifest`]), so the on-disk runtime version equals the compiler
/// version by construction.
pub const COMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The runtime crate's package name.
///
/// This is the single token that identifies a directory as a valid runtime crate
/// root. A candidate whose `Cargo.toml` does not declare this package is rejected
/// — never walked past to a wrong runtime.
pub const RUNTIME_PACKAGE: &str = "ipe-runtime-rust";

/// A resolved, verified runtime crate root: the directory holding the runtime
/// `Cargo.toml` an emitted project names as its path dependency, paired with the
/// version that root declares.
///
/// The only way to obtain one is through [`resolve`], which constructs it solely
/// from a candidate that has been checked to hold a `Cargo.toml` declaring the
/// [`RUNTIME_PACKAGE`]. An empty, half-present, or wrong-package directory can
/// never be represented as a `ResolvedRuntime` — a wrong runtime is
/// unrepresentable, not merely unlikely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRuntime {
    root: PathBuf,
    version: String,
}

impl ResolvedRuntime {
    /// The verified, absolute crate root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The version the resolved crate's `Cargo.toml` declares.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// The relative path, from a runtime crate root, of the manifest.
const MANIFEST: &str = "Cargo.toml";

/// The `version.workspace = true` line the embedded manifest carries (it inherits
/// the version from the workspace at build time). A standalone materialized crate
/// has no parent workspace, so this line is rewritten to a concrete version.
const WORKSPACE_VERSION_LINE: &str = "version.workspace = true";

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
    // A materialized crate carries a concrete `version = "…"`; an in-repo crate
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

/// Verify that `root` is a runtime crate root and, if so, canonicalize it into a
/// [`ResolvedRuntime`]. A non-runtime directory yields `Ok(None)`; the caller
/// decides whether that is a hard error (an explicit override) or a fall-through
/// (an in-repo probe).
fn verify(root: &Path) -> Result<Option<ResolvedRuntime>, CliError> {
    let Some(version) = runtime_version_at(root) else {
        return Ok(None);
    };
    let canonical = root.canonicalize().map_err(|e| CliError::Io {
        path: root.to_path_buf(),
        source: e,
    })?;
    Ok(Some(ResolvedRuntime {
        root: canonical,
        version,
    }))
}

/// Resolve `IPE_HOME` (see the module doc). The returned path is not created;
/// [`materialize`] creates it under the runtime subdirectory as needed.
///
/// # Errors
/// - [`CliError::EnvDirNotAbsolute`] when `IPE_HOME` is set but not absolute.
/// - [`CliError::RuntimeHomeUnknown`] when no override, no absolute
///   `XDG_DATA_HOME`, and no absolute home are set — there is no directory to
///   materialize into.
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

/// Rewrite the embedded manifest's `version.workspace = true` into a concrete
/// `version = "<COMPILER_VERSION>"`, so the materialized crate builds standalone
/// (it has no parent workspace to inherit from) AND declares exactly the
/// compiler's version. Every other line is preserved verbatim.
fn concretize_manifest(manifest: &str) -> String {
    manifest
        .lines()
        .map(|line| {
            if line.trim() == WORKSPACE_VERSION_LINE {
                format!("version = \"{COMPILER_VERSION}\"")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if manifest.ends_with('\n') { "\n" } else { "" }
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

/// Write the embedded crate tree under `dest` (a fresh directory), rewriting the
/// root manifest's version and skipping the `tests/` subtree. Fails closed on the
/// first filesystem error — a partially written tree under `dest` is a temp dir
/// the caller discards, never the live runtime.
fn write_tree(dir: &Dir<'_>, dest: &Path, at_root: bool) -> Result<(), CliError> {
    std::fs::create_dir_all(dest).map_err(|e| CliError::Io {
        path: dest.to_path_buf(),
        source: e,
    })?;
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(sub) => {
                let name = sub.path().file_name().unwrap_or_default();
                // `tests/` is not part of the buildable dependency and carries a
                // nested proof crate; skip it so the on-disk runtime is minimal.
                if at_root && name == std::ffi::OsStr::new("tests") {
                    continue;
                }
                write_tree(sub, &dest.join(name), false)?;
            }
            include_dir::DirEntry::File(file) => {
                let name = file.path().file_name().unwrap_or_default();
                let target = dest.join(name);
                if at_root && name == std::ffi::OsStr::new(MANIFEST) {
                    let text = std::str::from_utf8(file.contents()).map_err(|_| {
                        CliError::RuntimeMaterializeFailed {
                            detail: "embedded runtime manifest is not valid UTF-8".to_owned(),
                        }
                    })?;
                    std::fs::write(&target, concretize_manifest(text)).map_err(|e| {
                        CliError::Io {
                            path: target,
                            source: e,
                        }
                    })?;
                } else {
                    std::fs::write(&target, file.contents()).map_err(|e| CliError::Io {
                        path: target,
                        source: e,
                    })?;
                }
            }
        }
    }
    Ok(())
}

/// Materialize the embedded runtime source to `<IPE_HOME>/runtime/<version>/rust`
/// and return the verified root.
///
/// Atomic: the whole tree is written to a sibling temp directory under the same
/// `runtime/` parent, then renamed into place — a build never sees a
/// half-written runtime. Idempotent: if `<version>/rust` already exists and
/// verifies as a runtime crate root, the write is skipped (the fast path). Every
/// path is under `IPE_HOME`; nothing is written elsewhere.
///
/// # Errors
/// - [`CliError::RuntimeHomeUnknown`] if no `IPE_HOME` can be resolved.
/// - [`CliError::Io`] / [`CliError::RuntimeMaterializeFailed`] on any filesystem
///   failure — a disk-full or permission error is a loud, fail-closed refusal,
///   never a wrong or empty runtime.
pub fn materialize() -> Result<ResolvedRuntime, CliError> {
    let home = ipe_home()?;
    let runtime_parent = home.join("runtime");
    let version_dir = runtime_parent.join(COMPILER_VERSION);
    let final_root = version_dir.join("rust");

    // Fast path: an already-materialized, valid runtime for this version.
    if let Some(resolved) = verify(&final_root)? {
        return Ok(resolved);
    }

    std::fs::create_dir_all(&runtime_parent).map_err(|e| CliError::Io {
        path: runtime_parent.clone(),
        source: e,
    })?;

    // Stage the whole `<version>` directory in a sibling temp, then rename it
    // into place: the observable `<version>/rust` appears atomically and fully
    // formed. The temp name carries the pid so concurrent `ipe` processes do not
    // collide on the staging directory.
    let staging = runtime_parent.join(format!(
        ".staging-{COMPILER_VERSION}-{}",
        std::process::id()
    ));
    // A leftover staging dir from a crashed prior run would poison the write; the
    // remove is best-effort and only ever touches our own staging path.
    let _ = std::fs::remove_dir_all(&staging);
    let staged_root = staging.join("rust");

    let write_result = write_tree(&RUNTIME_CRATE, &staged_root, true);
    if let Err(e) = write_result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

    // Verify the staged tree BEFORE it becomes the live runtime — a staged tree
    // that does not verify is a bug in the embed, surfaced loudly here.
    let staged_ok = verify(&staged_root)?.is_some();
    if !staged_ok {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(CliError::RuntimeMaterializeFailed {
            detail: "the staged runtime tree did not verify as a runtime crate root".to_owned(),
        });
    }

    // Rename the staged `<version>` into place. If a concurrent process won the
    // race and created `<version>` first, treat an existing valid target as
    // success (idempotent) and discard our staging copy.
    if std::fs::rename(&staging, &version_dir).is_err() {
        let _ = std::fs::remove_dir_all(&staging);
        if verify(&final_root)?.is_none() {
            return Err(CliError::RuntimeMaterializeFailed {
                detail: format!("could not place the runtime at {}", version_dir.display()),
            });
        }
    }

    verify(&final_root)?.ok_or_else(|| CliError::RuntimeMaterializeFailed {
        detail: format!(
            "materialized runtime at {} did not verify",
            final_root.display()
        ),
    })
}

/// Resolve the runtime crate root for the dependency-model emit. The resolution
/// chain, in order:
///
/// 1. `$IPE_RUNTIME_DIR` — an explicit override (dev / advanced). It may name the
///    runtime crate root (`Cargo.toml` declaring [`RUNTIME_PACKAGE`]) or any path
///    inside it (e.g. the historical `…/rust/src` source-tree location); the crate
///    root is found by walking up. A path with no runtime crate root at or above
///    it is a loud error.
/// 2. In-repo `src/runtime/rust` — an upward walk from the current directory, so
///    a repository checkout builds against the live source (dev workflow and
///    goldens unchanged).
/// 3. Otherwise materialize the embedded source to `<IPE_HOME>/runtime/<version>/rust`
///    and use that (the normal installed path).
///
/// Whichever branch resolves, the result must declare the compiler's own
/// version: emitting against a differently-versioned runtime is unrepresentable,
/// so a stale override or drifted in-repo crate is refused here rather than
/// linked into a `cargo` build that fails opaquely.
///
/// # Errors
/// - [`CliError::RuntimeDirInvalid`] when `$IPE_RUNTIME_DIR` is set but has no
///   runtime crate root at or above it.
/// - [`CliError::RuntimeVersionMismatch`] when the resolved runtime's declared
///   version is not the compiler's.
/// - Any error from [`materialize`] when the embedded fallback is taken.
pub fn resolve() -> Result<ResolvedRuntime, CliError> {
    let resolved = if let Some(dir) = ipe_env::var_os("IPE_RUNTIME_DIR") {
        resolve_override(&PathBuf::from(dir))?
    } else if let Some(in_repo) = resolve_in_repo()? {
        in_repo
    } else {
        materialize()?
    };
    check_version(resolved)
}

/// Refuse a resolved runtime whose declared version is not the compiler's own.
/// The emitted project pins features against the compiler's runtime, so linking
/// a differently-versioned crate fails deep inside `cargo`; this catches the
/// drift at resolution time and refuses loudly instead. A [`materialize`]d
/// runtime declares [`COMPILER_VERSION`] by construction and always passes; the
/// guard bites a stale `IPE_RUNTIME_DIR` override or an in-repo crate whose
/// manifest has drifted.
fn check_version(resolved: ResolvedRuntime) -> Result<ResolvedRuntime, CliError> {
    if resolved.version() == COMPILER_VERSION {
        Ok(resolved)
    } else {
        Err(CliError::RuntimeVersionMismatch {
            path: resolved.root().to_path_buf(),
            found: resolved.version().to_owned(),
            expected: COMPILER_VERSION.to_owned(),
        })
    }
}

/// Resolve the `$IPE_RUNTIME_DIR` override: verify it names a runtime crate root,
/// else a loud, typed refusal (with a targeted hint when it points at the inner
/// module directory).
fn resolve_override(path: &Path) -> Result<ResolvedRuntime, CliError> {
    // Accept the crate root directly, or any path inside the crate — the
    // historical source-tree locations (`…/rust/src`, `…/src/ipe_runtime`) — by
    // walking up to the crate root that holds `Cargo.toml`. This keeps every
    // existing `IPE_RUNTIME_DIR` setting working across the meaning change from
    // "source tree" to "crate root".
    let mut here: Option<&Path> = Some(path);
    while let Some(dir) = here {
        if let Some(resolved) = verify(dir)? {
            return Ok(resolved);
        }
        here = dir.parent();
    }
    // Nothing at or above the given path names a runtime crate root.
    let points_at_inner = path.file_name() == Some(std::ffi::OsStr::new("ipe_runtime"))
        || path.ends_with("rust/src")
        || path.ends_with("runtime/rust/src");
    Err(CliError::RuntimeDirInvalid {
        path: path.to_path_buf(),
        points_at_inner,
    })
}

/// Upward walk from the current directory for the in-repo `src/runtime/rust`
/// crate root. `Ok(None)` means no in-repo runtime is above the current
/// directory (the normal case for an installed binary run outside a checkout).
fn resolve_in_repo() -> Result<Option<ResolvedRuntime>, CliError> {
    let cwd = std::env::current_dir().map_err(|e| CliError::Io {
        path: PathBuf::from("."),
        source: e,
    })?;
    let mut here: Option<&Path> = Some(cwd.as_path());
    while let Some(dir) = here {
        let candidate = dir.join("src").join("runtime").join("rust");
        if let Some(resolved) = verify(&candidate)? {
            return Ok(Some(resolved));
        }
        here = dir.parent();
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded runtime crate's declared version equals the compiler
    /// version. This is the version guarantee: the binary materializes its own
    /// embedded source, and that source names the compiler's version, so an
    /// emitted project can never link a mismatched runtime (barring the explicit
    /// `IPE_RUNTIME_DIR` override).
    #[test]
    fn embedded_runtime_version_matches_compiler() {
        let manifest = RUNTIME_CRATE
            .get_file("Cargo.toml")
            .expect("embedded runtime crate must carry a Cargo.toml");
        let text = std::str::from_utf8(manifest.contents()).expect("embedded manifest is UTF-8");
        // The in-repo manifest inherits the version from the workspace; the
        // concretized form names it literally. Either way the effective version
        // is the compiler's.
        assert!(
            text.contains(WORKSPACE_VERSION_LINE),
            "embedded runtime manifest must inherit the workspace version"
        );
        let concretized = concretize_manifest(text);
        assert!(
            concretized.contains(&format!("version = \"{COMPILER_VERSION}\"")),
            "concretized runtime manifest must declare the compiler version {COMPILER_VERSION}"
        );
        assert!(
            !concretized.contains(WORKSPACE_VERSION_LINE),
            "concretized manifest must not keep the workspace-inherit line"
        );
    }

    /// The embedded tree declares the runtime package — a materialize would
    /// verify.
    #[test]
    fn embedded_runtime_declares_package() {
        let manifest = RUNTIME_CRATE
            .get_file("Cargo.toml")
            .expect("embedded runtime crate must carry a Cargo.toml");
        let text = std::str::from_utf8(manifest.contents()).unwrap();
        assert!(
            text.lines()
                .any(|l| l.trim() == format!("name = \"{RUNTIME_PACKAGE}\""))
        );
    }

    /// A resolved runtime whose manifest declares a version other than the
    /// compiler's is refused by [`check_version`] with the typed
    /// [`CliError::RuntimeVersionMismatch`], naming the resolved path and both
    /// versions. This is the guard that keeps a stale runtime from being emitted
    /// against.
    #[test]
    fn mismatched_runtime_version_is_rejected() {
        let sd = crate::scratch::ScratchDir::new("ipe-runtime-version-test").expect("scratch dir");
        let dir = sd.into_path(); // the test's explicit remove_dir_all cleans up
        let bogus = "0.0.0-stale";
        assert_ne!(bogus, COMPILER_VERSION, "the test version must differ");
        std::fs::write(
            dir.join(MANIFEST),
            format!("[package]\nname = \"{RUNTIME_PACKAGE}\"\nversion = \"{bogus}\"\n"),
        )
        .expect("write bogus manifest");

        let resolved = verify(&dir)
            .expect("verify does not error on a well-formed manifest")
            .expect("a manifest declaring the package verifies");
        assert_eq!(resolved.version(), bogus);

        let err = check_version(resolved).expect_err("a mismatched version must be rejected");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(
                &err,
                CliError::RuntimeVersionMismatch { found, expected, path }
                    if found == bogus
                        && expected == COMPILER_VERSION
                        && path.ends_with(dir.file_name().expect("temp dir has a name"))
            ),
            "expected a RuntimeVersionMismatch naming {bogus} vs {COMPILER_VERSION}, got {err:?}"
        );
    }

    /// A resolved runtime declaring the compiler's own version passes
    /// [`check_version`] unchanged — the materialized path is exactly this case.
    #[test]
    fn matching_runtime_version_is_accepted() {
        let sd = crate::scratch::ScratchDir::new("ipe-runtime-version-ok").expect("scratch dir");
        let dir = sd.into_path(); // the test's explicit remove_dir_all cleans up
        std::fs::write(
            dir.join(MANIFEST),
            format!("[package]\nname = \"{RUNTIME_PACKAGE}\"\nversion = \"{COMPILER_VERSION}\"\n"),
        )
        .expect("write matching manifest");
        let resolved = verify(&dir).expect("verify ok").expect("verifies");
        assert!(check_version(resolved).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `concretize_manifest` touches only the version line and preserves the rest
    /// verbatim (including a trailing newline).
    #[test]
    fn concretize_preserves_other_lines() {
        let input = "[package]\nname = \"ipe-runtime-rust\"\nversion.workspace = true\nedition = \"2024\"\n";
        let out = concretize_manifest(input);
        assert_eq!(
            out,
            format!(
                "[package]\nname = \"ipe-runtime-rust\"\nversion = \"{COMPILER_VERSION}\"\nedition = \"2024\"\n"
            )
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
}
