//! The one build directory every cargo child of a command writes to.
//!
//! The host linker opens every object a build links, build scripts included,
//! and rustc writes those objects inside the target directory, so each linker
//! input path carries the target directory's bytes. A linker family that
//! cannot open some paths (GNU ld on a `*-windows-gnu` host opens files through
//! the ANSI code page, so a non-ASCII path is unopenable) must never be handed
//! one. [`LinkableTargetDir::resolve`] parses the target directory once, before
//! any cargo child starts, into a value the host's linker family can open;
//! every cargo child sets `CARGO_TARGET_DIR` from that one value, and every
//! artifact locator reads it back.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ipe_path_core::Regime;

use crate::CliError;
use crate::style::TerminalSafe;

/// The operating system of a host triple, as the linker family reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOs {
    /// The third triple component is `windows`.
    Windows,
    /// Any other operating system.
    Other,
}

/// The environment (ABI) component of a host triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEnv {
    /// `gnu`: the MinGW toolchain on Windows, glibc elsewhere.
    Gnu,
    /// `gnullvm`: MinGW headers linked by LLVM's `lld`.
    GnuLlvm,
    /// `msvc`: Microsoft's `link.exe`.
    Msvc,
    /// A fourth component with any other value.
    Other,
    /// The triple has no fourth component.
    Absent,
}

/// A target triple split into the parts that pick a linker family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostTriple {
    /// The operating system component.
    pub os: HostOs,
    /// The environment component.
    pub env: HostEnv,
}

impl HostTriple {
    /// Split `triple` on `-` and read its operating system and environment exactly.
    #[must_use]
    pub fn parse(triple: &str) -> Self {
        let mut parts = triple.split('-');
        let os = match parts.nth(2) {
            Some("windows") => HostOs::Windows,
            _ => HostOs::Other,
        };
        let env = match parts.next() {
            Some("gnu") => HostEnv::Gnu,
            Some("gnullvm") => HostEnv::GnuLlvm,
            Some("msvc") => HostEnv::Msvc,
            Some(_) => HostEnv::Other,
            None => HostEnv::Absent,
        };
        Self { os, env }
    }
}

/// Which paths the host linker family can open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLinker {
    /// GNU ld on a `*-windows-gnu` host: it opens files through the ANSI code
    /// page, so only an all-ASCII path is sure to open.
    AsciiOnly,
    /// A linker that opens any path: MSVC `link.exe`, `lld`, or a non-Windows ld.
    Unicode,
}

impl HostLinker {
    /// The linker family of the host `host`.
    ///
    /// A Windows host whose environment is not one known to link through a
    /// Unicode-aware linker is [`Self::AsciiOnly`]: the unknown case fails closed.
    #[must_use]
    pub const fn of_triple(host: HostTriple) -> Self {
        match (host.os, host.env) {
            (HostOs::Windows, HostEnv::Gnu | HostEnv::Other | HostEnv::Absent) => Self::AsciiOnly,
            (HostOs::Windows, HostEnv::Msvc | HostEnv::GnuLlvm) | (HostOs::Other, _) => {
                Self::Unicode
            }
        }
    }

    /// The linker family of the host `rustc` reported, or of a platform under `regime` when the query failed.
    ///
    /// A failed query under Windows is [`Self::AsciiOnly`] (fail closed); under
    /// any other regime every linker opens any path.
    #[must_use]
    pub fn of_query(host: Option<&str>, regime: Regime) -> Self {
        match host {
            Some(triple) => Self::of_triple(HostTriple::parse(triple)),
            None if regime.is_windows() => Self::AsciiOnly,
            None => Self::Unicode,
        }
    }

    /// The linker family of the active toolchain's host.
    #[must_use]
    pub fn active() -> Self {
        Self::of_query(
            crate::toolchain::RustcVersion::active()
                .ok()
                .map(crate::toolchain::RustcVersion::host),
            ipe_path_core::HOST,
        )
    }

    /// Whether this linker family can open `path`.
    ///
    /// The path must be absolute; an ASCII-only linker also needs every
    /// component to be valid Unicode made of ASCII characters alone. Length is
    /// not checked.
    #[must_use]
    pub fn can_open(self, path: &Path) -> bool {
        path.is_absolute()
            && match self {
                Self::Unicode => true,
                Self::AsciiOnly => path
                    .components()
                    .all(|part| part.as_os_str().to_str().is_some_and(str::is_ascii)),
            }
    }

    /// The linker family, named for a refusal message.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::AsciiOnly => crate::text::cli_host_linker_ascii_only(),
            Self::Unicode => crate::text::cli_host_linker_unicode(),
        }
    }
}

/// Where a build directory came from, in the order [`LinkableTargetDir::resolve`] reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetDirOrigin {
    /// The embedding caller named it (a watch session's override, a test harness).
    Embedder,
    /// The `CARGO_TARGET_DIR` environment variable.
    Env,
    /// The `[build] target-dir` key of `$IPE_HOME/config.toml`.
    IpeHomePin,
    /// A Cargo config `build.target-dir`, read through `cargo metadata`.
    CargoConfigPin,
    /// The crate's own `target` directory, the default.
    CrateLocal,
    /// The per-user build cache, used when the crate's own `target` cannot be opened.
    UserCache,
    /// The compiler's shared test build directory in the per-user cache.
    ScratchCache,
}

impl TargetDirOrigin {
    /// Whether the user chose this directory, so ipe never moves or removes it.
    #[must_use]
    pub const fn is_pin(self) -> bool {
        match self {
            Self::Embedder | Self::Env | Self::IpeHomePin | Self::CargoConfigPin => true,
            Self::CrateLocal | Self::UserCache | Self::ScratchCache => false,
        }
    }
}

/// The directory a [`CliError::TargetDirUnlinkable`] refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkablePath {
    /// A build directory from this origin.
    Target(TargetDirOrigin),
    /// The active toolchain's sysroot, whose libraries every link reads.
    Sysroot,
}

impl UnlinkablePath {
    /// The directory, named for a refusal message.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Target(TargetDirOrigin::Embedder) => crate::text::cli_target_dir_from_embedder(),
            Self::Target(TargetDirOrigin::Env) => crate::text::cli_target_dir_from_env(),
            Self::Target(TargetDirOrigin::IpeHomePin) => {
                crate::text::cli_target_dir_from_ipe_home()
            }
            Self::Target(TargetDirOrigin::CargoConfigPin) => {
                crate::text::cli_target_dir_from_cargo_config()
            }
            Self::Target(TargetDirOrigin::CrateLocal) => crate::text::cli_target_dir_crate_local(),
            Self::Target(TargetDirOrigin::UserCache) => crate::text::cli_target_dir_user_cache(),
            Self::Target(TargetDirOrigin::ScratchCache) => {
                crate::text::cli_target_dir_scratch_cache()
            }
            Self::Sysroot => crate::text::cli_target_dir_sysroot(),
        }
    }

    /// How to fix a refusal of this directory.
    #[must_use]
    pub const fn guidance(self) -> &'static str {
        match self {
            Self::Target(_) => crate::text::cli_target_dir_guidance(),
            Self::Sysroot => crate::text::cli_sysroot_guidance(),
        }
    }
}

/// Every place a build directory can be named, gathered before [`LinkableTargetDir::resolve`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetDirSources {
    /// The embedding caller's override.
    pub embedder: Option<PathBuf>,
    /// The `CARGO_TARGET_DIR` value; an empty value counts as unset.
    pub env: Option<OsString>,
    /// The `$IPE_HOME/config.toml` `[build] target-dir` pin, made absolute against `$IPE_HOME`.
    pub ipe_home_pin: Option<PathBuf>,
    /// The `target_directory` `cargo metadata` reports with `CARGO_TARGET_DIR`
    /// removed, when it is not the crate's own `target`.
    pub cargo_config_pin: Option<PathBuf>,
    /// The per-user cache base, when one resolves.
    pub cache_base: Option<PathBuf>,
    /// The active toolchain's sysroot, read on an ASCII-only linker host only.
    pub sysroot: Option<PathBuf>,
}

impl TargetDirSources {
    /// Read every source for `crate_dir`, stopping at the first pin.
    ///
    /// `cargo metadata` runs only when no earlier source pins the directory,
    /// and the sysroot is read only for an ASCII-only `linker`.
    ///
    /// # Errors
    /// The refusal of an unreadable `$IPE_HOME/config.toml`, or of the
    /// `cargo metadata` query.
    pub fn gather(
        cargo: &Path,
        crate_dir: &Path,
        embedder: Option<&Path>,
        linker: HostLinker,
    ) -> Result<Self, CliError> {
        let mut sources = Self {
            embedder: embedder.map(Path::to_path_buf),
            env: ipe_env::var_os("CARGO_TARGET_DIR").filter(|value| !value.is_empty()),
            ..Self::default()
        };
        if sources.embedder.is_none() && sources.env.is_none() {
            sources.ipe_home_pin = crate::health::shared_target_pin()?;
        }
        if sources.embedder.is_none() && sources.env.is_none() && sources.ipe_home_pin.is_none() {
            let reported = crate::cargo_step::target_directory(cargo, crate_dir)?;
            if !is_crate_local(&reported, crate_dir) {
                sources.cargo_config_pin = Some(reported);
            }
        }
        sources.cache_base = crate::resolve::default_cache_base().ok();
        if linker == HostLinker::AsciiOnly {
            sources.sysroot = crate::toolchain::RustcSysroot::active()
                .ok()
                .map(|sysroot| sysroot.path().to_path_buf());
        }
        Ok(sources)
    }
}

/// Whether `reported` is `crate_dir`'s own `target` directory.
fn is_crate_local(reported: &Path, crate_dir: &Path) -> bool {
    let same_dir = |parent: &Path| {
        std::fs::canonicalize(parent)
            .ok()
            .zip(std::fs::canonicalize(crate_dir).ok())
            .map_or(parent == crate_dir, |(a, b)| a == b)
    };
    reported.file_name().is_some_and(|name| name == "target")
        && reported.parent().is_some_and(same_dir)
}

/// A build directory the host's linker family can open, resolved once per command.
///
/// The only constructor is [`Self::resolve`], so holding one is proof the
/// directory passed the host linker's parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkableTargetDir {
    path: PathBuf,
    origin: TargetDirOrigin,
}

impl LinkableTargetDir {
    /// Resolve `crate_dir`'s build directory for `linker` from `sources`.
    ///
    /// The first source present wins: the embedder override, then
    /// `CARGO_TARGET_DIR`, then the `$IPE_HOME` pin, then a Cargo config pin.
    /// A relative pin is read against `crate_dir`, where cargo runs. A pin the
    /// linker cannot open is refused, never overridden. Without a pin the
    /// directory is `crate_dir/target`, or, when the linker cannot open that,
    /// `<cache base>/ipe/t/<project key>` keyed by the canonical crate path.
    ///
    /// # Errors
    /// - [`CliError::TargetDirUnlinkable`] when the sysroot, a pin, or the
    ///   relocated cache path is one `linker` cannot open.
    /// - [`CliError::CacheHomeUnknown`] when the crate's own `target` cannot be
    ///   opened and no per-user cache base resolves.
    pub fn resolve(
        linker: HostLinker,
        crate_dir: &Path,
        sources: &TargetDirSources,
    ) -> Result<Self, CliError> {
        check_sysroot(linker, sources)?;
        let crate_dir = std::path::absolute(crate_dir).unwrap_or_else(|_| crate_dir.to_path_buf());
        if let Some(pinned) = Self::pinned(linker, &crate_dir, sources) {
            return pinned;
        }
        let local = crate_dir.join("target");
        if linker.can_open(&local) {
            return Ok(Self {
                path: local,
                origin: TargetDirOrigin::CrateLocal,
            });
        }
        let cache_base = sources
            .cache_base
            .as_deref()
            .ok_or(CliError::CacheHomeUnknown)?;
        let path = user_cache_target(cache_base, &crate_dir);
        if linker.can_open(&path) {
            Ok(Self {
                path,
                origin: TargetDirOrigin::UserCache,
            })
        } else {
            Err(unlinkable(
                UnlinkablePath::Target(TargetDirOrigin::UserCache),
                &path,
                linker,
            ))
        }
    }

    /// The first pin of `sources`, read against `crate_dir`; `None` without one.
    ///
    /// A pin `linker` cannot open is refused, never overridden.
    fn pinned(
        linker: HostLinker,
        crate_dir: &Path,
        sources: &TargetDirSources,
    ) -> Option<Result<Self, CliError>> {
        let pin = sources
            .embedder
            .clone()
            .map(|path| (path, TargetDirOrigin::Embedder))
            .or_else(|| {
                sources
                    .env
                    .clone()
                    .map(|value| (PathBuf::from(value), TargetDirOrigin::Env))
            })
            .or_else(|| {
                sources
                    .ipe_home_pin
                    .clone()
                    .map(|path| (path, TargetDirOrigin::IpeHomePin))
            })
            .or_else(|| {
                sources
                    .cargo_config_pin
                    .clone()
                    .map(|path| (path, TargetDirOrigin::CargoConfigPin))
            });
        pin.map(|(path, origin)| {
            let path = crate_dir.join(path);
            if linker.can_open(&path) {
                Ok(Self { path, origin })
            } else {
                Err(unlinkable(UnlinkablePath::Target(origin), &path, linker))
            }
        })
    }

    /// Resolve the build directory of the scratch test crate in `crate_dir` for `linker` from `sources`.
    ///
    /// A pin wins as in [`Self::resolve`]. Without one the directory is the
    /// compiler's shared [`scratch_cache_target`]; when no cache base
    /// resolves, the linker cannot open it, or it is not a private directory
    /// of the effective user, it is `crate_dir/target`, a fresh private
    /// directory. The per-project user cache is never read: it is keyed by a
    /// crate path that is fresh every run.
    ///
    /// # Errors
    /// [`CliError::TargetDirUnlinkable`] when the sysroot, a pin, or
    /// `crate_dir/target` is one `linker` cannot open.
    pub fn resolve_scratch(
        linker: HostLinker,
        crate_dir: &Path,
        sources: &TargetDirSources,
    ) -> Result<Self, CliError> {
        check_sysroot(linker, sources)?;
        let crate_dir = std::path::absolute(crate_dir).unwrap_or_else(|_| crate_dir.to_path_buf());
        if let Some(pinned) = Self::pinned(linker, &crate_dir, sources) {
            return pinned;
        }
        let shared = sources
            .cache_base
            .as_deref()
            .filter(|base| linker.can_open(&scratch_cache_target(base)))
            .and_then(prepare_scratch_cache);
        if let Some(path) = shared {
            return Ok(Self {
                path,
                origin: TargetDirOrigin::ScratchCache,
            });
        }
        let local = crate_dir.join("target");
        if linker.can_open(&local) {
            Ok(Self {
                path: local,
                origin: TargetDirOrigin::CrateLocal,
            })
        } else {
            Err(unlinkable(
                UnlinkablePath::Target(TargetDirOrigin::CrateLocal),
                &local,
                linker,
            ))
        }
    }

    /// Resolve and lock the build directory of the scratch test crate `scratch`
    /// that `cargo` builds, for the active toolchain's host linker.
    ///
    /// The directory comes from [`Self::resolve_scratch`]. A shared scratch
    /// directory first prunes its stale siblings ([`prune_scratch_siblings`]).
    /// The lock is then held ([`TargetLock`] under
    /// [`crate::cargo_step::CARGO_BUILD_WALL`]) for as long as the returned
    /// [`ScratchTarget`] lives, pinned directory or not.
    ///
    /// # Errors
    /// The refusals of [`TargetDirSources::gather`], [`Self::resolve_scratch`],
    /// [`prune_scratch_siblings`] and [`TargetLock`]; [`CliError::Io`]
    /// when the directory cannot be created.
    pub fn for_scratch(
        cargo: &Path,
        scratch: &crate::scratch::ScratchDir,
    ) -> Result<ScratchTarget, CliError> {
        let linker = HostLinker::active();
        let sources = TargetDirSources::gather(cargo, scratch.path(), None, linker)?;
        let dir = Self::resolve_scratch(linker, scratch.path(), &sources)?;
        Self::lock_scratch(dir, crate::cargo_step::CARGO_BUILD_WALL)
    }

    /// Prune `dir`'s stale siblings when it is the shared scratch directory, then lock it within `wall`.
    ///
    /// Every attempt at the lock brings the directory into being again
    /// ([`DirPrep`]): the shared one is re-proven private, so one a pruner
    /// removed is recreated owner-only, never with the default mode.
    fn lock_scratch(
        dir: Self,
        wall: crate::remote_ingest::LocalWall,
    ) -> Result<ScratchTarget, CliError> {
        let prep = DirPrep::of(dir.origin);
        prep.apply(&dir.path)
            .map_err(|e| crate::io_err(&dir.path, e))?;
        if let (DirPrep::Private, Some(root)) = (prep, dir.path.parent()) {
            prune_scratch_siblings(root, &dir.path, SCRATCH_RETENTION)?;
        }
        let lock = TargetLock::acquire_in(&dir.path, prep, wall)?;
        Ok(ScratchTarget { dir, lock })
    }

    /// Resolve the build directory of the crate `cargo` builds in `crate_dir`
    /// for the active toolchain's host linker.
    ///
    /// # Errors
    /// The refusal of [`TargetDirSources::gather`] or of [`Self::resolve`].
    pub fn for_crate(
        cargo: &Path,
        crate_dir: &Path,
        embedder: Option<&Path>,
    ) -> Result<Self, CliError> {
        let linker = HostLinker::active();
        let sources = TargetDirSources::gather(cargo, crate_dir, embedder, linker)?;
        Self::resolve(linker, crate_dir, &sources)
    }

    /// A build directory taken as resolved, for tests that hand a build its directory.
    #[cfg(test)]
    pub fn assume(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            origin: TargetDirOrigin::Embedder,
        }
    }

    /// The build directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the build directory came from.
    #[cfg(test)]
    #[must_use]
    pub const fn origin(&self) -> TargetDirOrigin {
        self.origin
    }
}

/// The per-user cache directory standing in for the crate at `crate_dir`'s own `target`.
///
/// Keyed by the first 16 hex digits of the canonical crate path's digest
/// ([`ipe_backend_rust::identity_hex`]), so one project keeps one warm
/// directory across builds and two projects never share one.
#[must_use]
pub fn user_cache_target(cache_base: &Path, crate_dir: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(crate_dir).unwrap_or_else(|_| crate_dir.to_path_buf());
    let digest = ipe_backend_rust::identity_hex(&canonical);
    let key = digest.get(..USER_CACHE_KEY_LEN).unwrap_or(&digest);
    user_cache_root(cache_base).join(key)
}

/// The directory holding every relocated build directory: `<cache base>/ipe/t`.
#[must_use]
pub fn user_cache_root(cache_base: &Path) -> PathBuf {
    cache_base.join("ipe").join("t")
}

/// Hex digits of a relocated build directory's project key.
const USER_CACHE_KEY_LEN: usize = 16;

/// Refuse a sysroot of `sources` that `linker` cannot open.
fn check_sysroot(linker: HostLinker, sources: &TargetDirSources) -> Result<(), CliError> {
    match &sources.sysroot {
        Some(sysroot) if !linker.can_open(sysroot) => {
            Err(unlinkable(UnlinkablePath::Sysroot, sysroot, linker))
        }
        Some(_) | None => Ok(()),
    }
}
/// The prefix of a shared scratch build directory's name under [`user_cache_root`].
///
/// Disjoint from the 16-hex keys of [`user_cache_target`], so no project's
/// relocated directory and no scratch directory share a name.
const SCRATCH_PREFIX: &str = "scratch-";

/// The lock file every `ipe test` run holds while it uses a build directory.
pub const TEST_LOCK_FILE: &str = ".ipe-test.lock";

/// How long a shared scratch build directory unused by every run is kept.
pub const SCRATCH_RETENTION: std::time::Duration = std::time::Duration::from_hours(30 * 24);

/// The most entries a prune lists under [`user_cache_root`].
const SCRATCH_SIBLING_CAP: u32 = 4096;

/// How many times a lock is taken again after its file was replaced under it.
const LOCK_ATTEMPTS: u32 = 3;

/// The domain tag of a scratch build directory's key.
const SCRATCH_KEY_TAG: &[u8] = b"ipe-scratch-target\0";

/// The shared scratch build directory of this compiler: `<cache base>/ipe/t/scratch-<k>`.
///
/// `k` is the first 16 hex digits of a length-framed SHA-256 of the compiler
/// version, so every run of one compiler shares one directory and two
/// compilers never do.
#[must_use]
pub fn scratch_cache_target(cache_base: &Path) -> PathBuf {
    use sha2::Digest as _;
    let version = crate::runtime_embed::COMPILER_VERSION.as_bytes();
    let mut hasher = sha2::Sha256::new();
    hasher.update(SCRATCH_KEY_TAG);
    hasher.update(
        u64::try_from(version.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(version);
    let digest = hex::encode(hasher.finalize());
    let key = digest.get(..USER_CACHE_KEY_LEN).unwrap_or(&digest);
    user_cache_root(cache_base).join(format!("{SCRATCH_PREFIX}{key}"))
}

/// The owner and permission bits of an entry, and the effective user.
///
/// All three are `None` on a host without user ids, where only an entry's
/// kind decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// The entry's owner.
    pub owner: Option<u32>,
    /// The entry's permission bits.
    pub mode: Option<u32>,
    /// The effective user of this process.
    pub euid: Option<u32>,
}

impl Access {
    /// The access the entry `meta` describes grants, judged for this process.
    #[cfg(unix)]
    fn of(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;
        Self {
            owner: Some(meta.uid()),
            mode: Some(meta.mode() & 0o7777),
            euid: Some(rustix::process::geteuid().as_raw()),
        }
    }

    /// The access the entry `meta` describes grants: none known on this host.
    #[cfg(not(unix))]
    const fn of(_meta: &std::fs::Metadata) -> Self {
        Self {
            owner: None,
            mode: None,
            euid: None,
        }
    }

    /// Whether the entry belongs to the effective user.
    #[must_use]
    pub fn owned(self) -> bool {
        self.owner == self.euid
    }

    /// Whether no permission bit in `bits` is set.
    fn lacks(self, bits: u32) -> bool {
        self.mode.is_none_or(|mode| mode & bits == 0)
    }
}

/// Whether an entry of kind `kind` may serve as the shared scratch build
/// directory of the effective user.
///
/// Only a real directory (never a link) that the effective user owns and no
/// other user may enter, so no other user reads or writes a build in it.
#[must_use]
pub fn is_private_dir(kind: ipe_fs_open::FileKind, access: Access) -> bool {
    kind == ipe_fs_open::FileKind::Dir && access.owned() && access.lacks(0o077)
}

/// Whether a directory of kind `kind` may hold the shared scratch build directory.
///
/// Only a directory the effective user owns and no other user may write, so no
/// other user can rename the scratch directory away and plant one in its place.
#[must_use]
pub fn is_private_root(kind: ipe_fs_open::FileKind, access: Access) -> bool {
    kind == ipe_fs_open::FileKind::Dir && access.owned() && access.lacks(0o022)
}

/// Whether a prune may judge a sibling of kind `kind`: a real directory of the
/// effective user, never another user's, whose lock this process cannot take.
#[must_use]
pub fn is_prunable(kind: ipe_fs_open::FileKind, access: Access) -> bool {
    kind == ipe_fs_open::FileKind::Dir && access.owned()
}

/// The shared scratch build directory under `cache_base`, created owner-only
/// when absent; `None` when it cannot be created or is not private
/// ([`ensure_private_scratch`]).
fn prepare_scratch_cache(cache_base: &Path) -> Option<PathBuf> {
    let path = scratch_cache_target(cache_base);
    ensure_private_scratch(&path).ok().map(|()| path)
}

/// Create the shared scratch build directory `path` owner-only when absent,
/// then prove it an [`is_private_dir`] under an [`is_private_root`].
///
/// Both are read through handles opened without following a final link, so
/// the kind, owner and mode are the entries' own. The directory is created
/// only once its parent is proven.
///
/// # Errors
/// The I/O error of a creation or a read; `PermissionDenied` when either
/// directory is not private; `NotFound` when the directory vanished.
fn ensure_private_scratch(path: &Path) -> std::io::Result<()> {
    let refused = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
    let root = path.parent().ok_or_else(invalid)?;
    let name = path
        .file_name()
        .and_then(ipe_fs_open::EntryName::new)
        .ok_or_else(invalid)?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o755);
    }
    builder.create(root)?;
    let parent =
        ipe_fs_open::HeldDir::open_root(root).map_err(ipe_fs_open::OpenRefusal::into_io)?;
    let root_kind =
        ipe_fs_open::kind_of_file(parent.handle()).map_err(ipe_fs_open::OpenRefusal::into_io)?;
    #[cfg(unix)]
    drop_shared_write(parent.handle(), Access::of(&parent.handle().metadata()?))?;
    if !is_private_root(root_kind, Access::of(&parent.handle().metadata()?)) {
        return Err(refused());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let kind = parent
        .kind_of(&name)
        .map_err(ipe_fs_open::OpenRefusal::into_io)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let held = parent
        .child_dir(&name)
        .map_err(ipe_fs_open::OpenRefusal::into_io)?;
    if is_private_dir(kind, Access::of(&held.handle().metadata()?)) {
        Ok(())
    } else {
        Err(refused())
    }
}

/// Clear the group and other write bits of the effective user's own directory
/// `dir`, the cache root a group-writable umask created.
///
/// Another user's directory is left as it is, and refused by [`is_private_root`].
///
/// # Errors
/// The I/O error of the mode change.
#[cfg(unix)]
fn drop_shared_write(dir: &std::fs::File, access: Access) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    match access.mode {
        Some(mode) if access.owned() && mode & 0o022 != 0 => {
            dir.set_permissions(std::fs::Permissions::from_mode(mode & !0o022))
        }
        Some(_) | None => Ok(()),
    }
}

/// How a run brings its build directory into being before each attempt at its lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirPrep {
    /// Created as needed, the directory a pin or the crate names.
    Plain,
    /// Created owner-only and proven private ([`ensure_private_scratch`]).
    Private,
}

impl DirPrep {
    /// The preparation of a build directory from `origin`.
    const fn of(origin: TargetDirOrigin) -> Self {
        match origin {
            TargetDirOrigin::ScratchCache => Self::Private,
            TargetDirOrigin::Embedder
            | TargetDirOrigin::Env
            | TargetDirOrigin::IpeHomePin
            | TargetDirOrigin::CargoConfigPin
            | TargetDirOrigin::CrateLocal
            | TargetDirOrigin::UserCache => Self::Plain,
        }
    }

    /// Bring `dir` into being.
    fn apply(self, dir: &Path) -> std::io::Result<()> {
        match self {
            Self::Plain => std::fs::create_dir_all(dir),
            Self::Private => ensure_private_scratch(dir),
        }
    }
}

/// A build directory an `ipe test` run holds the lock of.
///
/// The only constructor is [`LinkableTargetDir::for_scratch`], so a test build
/// into a directory another run may be using has no representation.
#[derive(Debug)]
pub struct ScratchTarget {
    /// The build directory.
    dir: LinkableTargetDir,
    /// The held lock of the directory.
    lock: TargetLock,
}

impl ScratchTarget {
    /// The build directory.
    #[must_use]
    pub const fn dir(&self) -> &LinkableTargetDir {
        &self.dir
    }

    /// Release the lock, keeping the directory's path for what runs after.
    #[must_use]
    pub fn release(self) -> PathBuf {
        drop(self.lock);
        self.dir.path
    }
}

/// The exclusive lock of a build directory's [`TEST_LOCK_FILE`], held while open.
#[derive(Debug)]
pub struct TargetLock {
    /// The locked file; closing it releases the lock.
    _file: std::fs::File,
}

impl TargetLock {
    /// Lock `dir`'s [`TEST_LOCK_FILE`], creating `dir` as needed, waiting up to
    /// `wall` for another holder.
    ///
    /// # Errors
    /// The refusals of [`Self::acquire_in`].
    #[cfg(test)]
    pub fn acquire(dir: &Path, wall: crate::remote_ingest::LocalWall) -> Result<Self, CliError> {
        Self::acquire_in(dir, DirPrep::Plain, wall)
    }

    /// Lock `dir`'s [`TEST_LOCK_FILE`], waiting up to `wall` for another holder.
    ///
    /// Each attempt first brings `dir` into being through `prep`, then opens
    /// the file without following a link ([`open_lock_file`]). After the lock
    /// is held, `dir`'s name must still name the locked file: one a pruner
    /// unlinked meanwhile, or whose directory it removed, is dropped and the
    /// lock taken again, at most [`LOCK_ATTEMPTS`] times. The file's mtime is
    /// then set to now, the directory's last-use stamp.
    ///
    /// # Errors
    /// [`CliError::TestTargetBusy`] when another holder keeps the lock past
    /// `wall`, or the file keeps being replaced; [`CliError::Io`] when `dir`
    /// cannot be prepared, or the file cannot be opened, is not a regular file
    /// of the effective user named once, or cannot be locked.
    fn acquire_in(
        dir: &Path,
        prep: DirPrep,
        wall: crate::remote_ingest::LocalWall,
    ) -> Result<Self, CliError> {
        Self::acquire_with(dir, prep, wall, || {})
    }

    /// [`Self::acquire_in`], calling `between` after each open and before its lock.
    fn acquire_with(
        dir: &Path,
        prep: DirPrep,
        wall: crate::remote_ingest::LocalWall,
        mut between: impl FnMut(),
    ) -> Result<Self, CliError> {
        let path = dir.join(TEST_LOCK_FILE);
        let busy = || CliError::TestTargetBusy {
            path: TerminalSafe::sanitize(&path.to_string_lossy()),
            wall,
        };
        let name = lock_entry_name()
            .ok_or_else(|| crate::io_err(&path, std::io::ErrorKind::InvalidInput.into()))?;
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(wall.secs()))
            .ok_or_else(busy)?;
        for _ in 0..LOCK_ATTEMPTS {
            prep.apply(dir).map_err(|e| crate::io_err(dir, e))?;
            let file = match open_lock_file(&path, LockOpen::OpenOrCreate) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(crate::io_err(&path, e)),
            };
            between();
            lock_until(&file, &path, deadline).map_err(|e| e.unwrap_or_else(busy))?;
            let held = ipe_fs_open::FileId::of_file(&file)
                .map_err(|refusal| crate::io_err(&path, refusal.into_io()))?;
            let named = match ipe_fs_open::HeldDir::open_root(dir)
                .and_then(|parent| parent.entry_id(&name))
            {
                Ok(named) => named,
                Err(ipe_fs_open::OpenRefusal::Absent) => continue,
                Err(refusal) => return Err(crate::io_err(dir, refusal.into_io())),
            };
            if named == Some(held) {
                file.set_modified(std::time::SystemTime::now())
                    .map_err(|e| crate::io_err(&path, e))?;
                return Ok(Self { _file: file });
            }
        }
        Err(busy())
    }
}

/// [`TEST_LOCK_FILE`] as an entry name.
fn lock_entry_name() -> Option<ipe_fs_open::EntryName> {
    ipe_fs_open::EntryName::new(std::ffi::OsStr::new(TEST_LOCK_FILE))
}

/// Poll `file`'s exclusive lock until it is held or `deadline` passes.
///
/// `Err(None)` is the deadline passing; `Err(Some(_))` a lock failure.
fn lock_until(
    file: &std::fs::File,
    path: &Path,
    deadline: std::time::Instant,
) -> Result<(), Option<CliError>> {
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    return Err(None);
                }
                std::thread::sleep(crate::cargo_step::BUILD_POLL);
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(Some(crate::io_err(path, e))),
        }
    }
}

/// Whether an open of a lock file may create it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockOpen {
    /// Open the file, creating it owner-only when absent.
    OpenOrCreate,
    /// Open the file only when it exists.
    Existing,
    /// Create the file owner-only, refusing one that exists.
    CreateNew,
}

/// Open the lock file at `path` as `how` says, never through a link, and prove
/// on the opened handle that it is a regular file of the effective user that
/// no other entry names.
///
/// # Errors
/// The open's I/O error (`NotFound` when `path`'s directory or, for
/// [`LockOpen::Existing`], the file is absent); `InvalidInput` for a
/// non-regular or hard-linked file; `PermissionDenied` for another user's.
fn open_lock_file(path: &Path, how: LockOpen) -> std::io::Result<std::fs::File> {
    let file = open_no_follow(path, how)?;
    let kind = ipe_fs_open::kind_of_file(&file).map_err(ipe_fs_open::OpenRefusal::into_io)?;
    let links = ipe_fs_open::link_count(&file).map_err(ipe_fs_open::OpenRefusal::into_io)?;
    if kind != ipe_fs_open::FileKind::Regular || links != 1 {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    if !Access::of(&file.metadata()?).owned() {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(file)
}

/// Open `path` to read and write as `how` says, creating owner-only, never
/// following a final link.
#[cfg(unix)]
fn open_no_follow(path: &Path, how: LockOpen) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};
    let create = match how {
        LockOpen::OpenOrCreate => OFlags::CREATE,
        LockOpen::Existing => OFlags::empty(),
        LockOpen::CreateNew => OFlags::CREATE | OFlags::EXCL,
    };
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | create;
    let fd = rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR)?;
    Ok(std::fs::File::from(fd))
}

/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a reparse point as itself, never its target.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Open `path` to read and write as `how` says, never following a final reparse point.
#[cfg(windows)]
fn open_no_follow(path: &Path, how: LockOpen) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    match how {
        LockOpen::OpenOrCreate => {
            options.create(true).truncate(false);
        }
        LockOpen::Existing => {}
        LockOpen::CreateNew => {
            options.create_new(true);
        }
    }
    options.open(path)
}

/// Remove every shared scratch build directory under `root` but `keep` that
/// the effective user owns, no run has used within `retention`, and no run
/// holds now.
///
/// Another user's directory is never judged, so it can neither be removed nor
/// stop a prune. A directory is removed only while this process holds its
/// lock ([`prune_if_stale`]).
///
/// # Errors
/// [`CliError::Io`] when `root` cannot be listed (more than
/// [`SCRATCH_SIBLING_CAP`] entries included) or a stale directory's lock or
/// removal fails.
pub fn prune_scratch_siblings(
    root: &Path,
    keep: &Path,
    retention: std::time::Duration,
) -> Result<(), CliError> {
    let entries = ipe_fs_open::HeldDir::open_root(root)
        .and_then(|dir| dir.entries(sibling_cap()))
        .map_err(|refusal| crate::io_err(root, refusal.into_io()))?;
    let now = std::time::SystemTime::now();
    for (name, kind) in entries {
        let is_scratch = name
            .as_os_str()
            .to_str()
            .is_some_and(|text| text.starts_with(SCRATCH_PREFIX));
        let sibling = root.join(name.as_os_str());
        if !is_scratch || kind != ipe_fs_open::FileKind::Dir || sibling == keep {
            continue;
        }
        let access = match std::fs::symlink_metadata(&sibling) {
            Ok(meta) => Access::of(&meta),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(crate::io_err(&sibling, e)),
        };
        if is_prunable(kind, access) {
            prune_if_stale(&sibling, now, retention)?;
        }
    }
    Ok(())
}

/// The last use a prune judged a scratch build directory by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LastUse {
    /// Its lock file's mtime.
    Locked(std::time::SystemTime),
    /// Its own mtime: no run ever made its lock file.
    Unlocked,
}

/// Remove the scratch build directory `dir` when its last use is older than
/// `retention` at `now` and its lock is free.
///
/// # Errors
/// The refusals of [`prune_if_stale_with`].
fn prune_if_stale(
    dir: &Path,
    now: std::time::SystemTime,
    retention: std::time::Duration,
) -> Result<(), CliError> {
    prune_if_stale_with(dir, now, retention, || {})
}

/// [`prune_if_stale`], calling `between` after the staleness is judged and
/// before the lock file is opened.
///
/// The judgement is re-read under the lock: the held file must still be the
/// one `dir` names and its mtime the one judged, so a run that took and freed
/// the lock since the judgement keeps its directory. The lock file is never
/// created over one a run made meanwhile, and a directory a concurrent pruner
/// removed, or a run re-entered, is left alone.
///
/// # Errors
/// [`CliError::Io`] when a stat, the lock, or the removal fails.
fn prune_if_stale_with(
    dir: &Path,
    now: std::time::SystemTime,
    retention: std::time::Duration,
    between: impl FnOnce(),
) -> Result<(), CliError> {
    let lock_path = dir.join(TEST_LOCK_FILE);
    let is_stale =
        |at: std::time::SystemTime| now.duration_since(at).is_ok_and(|age| age > retention);
    let last_use = match std::fs::symlink_metadata(&lock_path) {
        Ok(meta) => LastUse::Locked(meta.modified().map_err(|e| crate::io_err(&lock_path, e))?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::symlink_metadata(dir) {
                Ok(meta) if is_stale(meta.modified().map_err(|e| crate::io_err(dir, e))?) => {
                    LastUse::Unlocked
                }
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(crate::io_err(dir, e)),
            }
        }
        Err(e) => return Err(crate::io_err(&lock_path, e)),
    };
    if let LastUse::Locked(at) = last_use
        && !is_stale(at)
    {
        return Ok(());
    }
    between();
    let how = match last_use {
        LastUse::Locked(_) => LockOpen::Existing,
        LastUse::Unlocked => LockOpen::CreateNew,
    };
    let lock = match open_lock_file(&lock_path, how) {
        Ok(lock) => lock,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::AlreadyExists
            ) =>
        {
            return Ok(());
        }
        Err(e) => return Err(crate::io_err(&lock_path, e)),
    };
    let judged = match last_use {
        LastUse::Locked(at) => at,
        LastUse::Unlocked => lock
            .metadata()
            .and_then(|meta| meta.modified())
            .map_err(|e| crate::io_err(&lock_path, e))?,
    };
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
        Err(std::fs::TryLockError::Error(e)) => return Err(crate::io_err(&lock_path, e)),
    }
    if !still_judged(dir, &lock, judged)? {
        return Ok(());
    }
    remove_locked_dir(dir, || {})
}

/// Remove the scratch build directory `dir` whose lock this process holds,
/// calling `after_contents` once everything but the lock file is gone.
///
/// The lock file is unlinked last, so a run that opens it meanwhile waits on
/// the held lock until nothing is left to remove under it, then finds the
/// name gone and starts afresh. A run that makes a new lock file after the
/// unlink keeps the directory: the final removal of a non-empty directory is
/// no error, and nothing else is removed after it.
///
/// # Errors
/// [`CliError::Io`] when `dir` cannot be listed (more than
/// [`SCRATCH_SIBLING_CAP`] entries included) or an entry cannot be removed.
fn remove_locked_dir(dir: &Path, after_contents: impl FnOnce()) -> Result<(), CliError> {
    let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let entries =
        match ipe_fs_open::HeldDir::open_root(dir).and_then(|held| held.entries(sibling_cap())) {
            Ok(entries) => entries,
            Err(ipe_fs_open::OpenRefusal::Absent) => return Ok(()),
            Err(refusal) => return Err(crate::io_err(dir, refusal.into_io())),
        };
    for (name, kind) in entries {
        if name.as_os_str() == TEST_LOCK_FILE {
            continue;
        }
        let entry = dir.join(name.as_os_str());
        let removed = match kind {
            ipe_fs_open::FileKind::Dir => std::fs::remove_dir_all(&entry),
            ipe_fs_open::FileKind::Regular
            | ipe_fs_open::FileKind::Symlink
            | ipe_fs_open::FileKind::Fifo
            | ipe_fs_open::FileKind::Socket
            | ipe_fs_open::FileKind::Device
            | ipe_fs_open::FileKind::Other => std::fs::remove_file(&entry),
        };
        match removed {
            Ok(()) => {}
            Err(e) if gone(&e) => {}
            Err(e) => return Err(crate::io_err(&entry, e)),
        }
    }
    after_contents();
    let lock_path = dir.join(TEST_LOCK_FILE);
    match std::fs::remove_file(&lock_path) {
        Ok(()) => {}
        Err(e) if gone(&e) => {}
        Err(e) => return Err(crate::io_err(&lock_path, e)),
    }
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok(()),
        Err(e) if gone(&e) || e.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(e) => Err(crate::io_err(dir, e)),
    }
}

/// The most entries a prune lists in one directory: [`SCRATCH_SIBLING_CAP`].
fn sibling_cap() -> ipe_fs_open::EntryCap {
    ipe_fs_open::EntryCap::from_nonzero(
        std::num::NonZeroU32::new(SCRATCH_SIBLING_CAP).unwrap_or(std::num::NonZeroU32::MIN),
    )
}

/// Whether the held lock file `lock` is still the one `dir` names, last used at `judged`.
///
/// # Errors
/// [`CliError::Io`] when the handle or `dir` cannot be read.
fn still_judged(
    dir: &Path,
    lock: &std::fs::File,
    judged: std::time::SystemTime,
) -> Result<bool, CliError> {
    let lock_path = dir.join(TEST_LOCK_FILE);
    let name = lock_entry_name()
        .ok_or_else(|| crate::io_err(&lock_path, std::io::ErrorKind::InvalidInput.into()))?;
    let held_at = lock
        .metadata()
        .and_then(|meta| meta.modified())
        .map_err(|e| crate::io_err(&lock_path, e))?;
    let held = ipe_fs_open::FileId::of_file(lock)
        .map_err(|refusal| crate::io_err(&lock_path, refusal.into_io()))?;
    match ipe_fs_open::HeldDir::open_root(dir).and_then(|parent| parent.entry_id(&name)) {
        Ok(named) => Ok(held_at == judged && named == Some(held)),
        Err(ipe_fs_open::OpenRefusal::Absent) => Ok(false),
        Err(refusal) => Err(crate::io_err(dir, refusal.into_io())),
    }
}

/// The refusal of `path`, which `linker` cannot open.
fn unlinkable(origin: UnlinkablePath, path: &Path, linker: HostLinker) -> CliError {
    CliError::TargetDirUnlinkable {
        origin,
        path: TerminalSafe::sanitize(&path.to_string_lossy()),
        linker,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GNU: HostLinker = HostLinker::AsciiOnly;

    /// `rooted` as an absolute path on this host: on Windows a rooted path
    /// without a drive is relative to the current drive, so it gains `C:`.
    fn abs(rooted: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:{rooted}"))
        } else {
            PathBuf::from(rooted)
        }
    }

    fn sources() -> TargetDirSources {
        TargetDirSources {
            cache_base: Some(abs("/home/ana/.cache")),
            ..TargetDirSources::default()
        }
    }

    /// The refused origin and path of `resolved`, when it is a linkability refusal.
    fn refusal(resolved: &Result<LinkableTargetDir, CliError>) -> Option<(UnlinkablePath, String)> {
        match resolved {
            Err(CliError::TargetDirUnlinkable { origin, path, .. }) => {
                Some((*origin, path.as_str().to_owned()))
            }
            _ => None,
        }
    }

    #[test]
    fn host_triples_parse_exactly() {
        let windows_gnu = HostTriple::parse("x86_64-pc-windows-gnu");
        assert_eq!(windows_gnu.os, HostOs::Windows);
        assert_eq!(windows_gnu.env, HostEnv::Gnu);
        assert_eq!(
            HostTriple::parse("aarch64-pc-windows-gnullvm").env,
            HostEnv::GnuLlvm
        );
        assert_eq!(
            HostTriple::parse("x86_64-pc-windows-msvc").env,
            HostEnv::Msvc
        );
        assert_eq!(
            HostTriple::parse("x86_64-pc-windows-gnux").env,
            HostEnv::Other
        );
        assert_eq!(HostTriple::parse("x86_64-pc-windows").env, HostEnv::Absent);
        assert_eq!(
            HostTriple::parse("x86_64-unknown-linux-gnu").os,
            HostOs::Other
        );
    }

    #[test]
    fn windows_gnu_and_unknown_windows_hosts_are_ascii_only() {
        for triple in [
            "x86_64-pc-windows-gnu",
            "i686-pc-windows-gnu",
            "x86_64-pc-windows-gnux",
            "x86_64-pc-windows",
        ] {
            assert_eq!(
                HostLinker::of_triple(HostTriple::parse(triple)),
                HostLinker::AsciiOnly,
                "{triple}"
            );
        }
    }

    #[test]
    fn msvc_and_gnullvm_are_unicode() {
        for triple in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-gnullvm"] {
            assert_eq!(
                HostLinker::of_triple(HostTriple::parse(triple)),
                HostLinker::Unicode,
                "{triple}"
            );
        }
    }

    #[test]
    fn linux_unchanged() {
        let linker = HostLinker::of_triple(HostTriple::parse("x86_64-unknown-linux-gnu"));
        assert_eq!(linker, HostLinker::Unicode);
        let resolved = LinkableTargetDir::resolve(linker, &abs("/srv/ipé/out/rust"), &sources());
        assert_eq!(
            resolved.ok(),
            Some(LinkableTargetDir {
                path: abs("/srv/ipé/out/rust/target"),
                origin: TargetDirOrigin::CrateLocal,
            })
        );
    }

    #[test]
    fn of_query_none_is_ascii_only_under_windows() {
        assert_eq!(
            HostLinker::of_query(None, Regime::Windows),
            HostLinker::AsciiOnly
        );
    }

    #[test]
    fn of_query_none_is_unicode_under_unix() {
        assert_eq!(
            HostLinker::of_query(None, Regime::Unix),
            HostLinker::Unicode
        );
    }

    #[test]
    fn of_query_reported_host_ignores_the_regime() {
        for regime in [Regime::Unix, Regime::Windows] {
            assert_eq!(
                HostLinker::of_query(Some("x86_64-unknown-linux-gnu"), regime),
                HostLinker::Unicode
            );
            assert_eq!(
                HostLinker::of_query(Some("x86_64-pc-windows-gnu"), regime),
                HostLinker::AsciiOnly
            );
        }
    }

    #[test]
    fn gnu_host_non_ascii_pin_refused() {
        let pinned = TargetDirSources {
            env: Some(abs("/home/ana/ipé-t").into_os_string()),
            ..sources()
        };
        let resolved = LinkableTargetDir::resolve(GNU, &abs("/home/ana/p/out/rust"), &pinned);
        assert_eq!(
            refusal(&resolved),
            Some((
                UnlinkablePath::Target(TargetDirOrigin::Env),
                abs("/home/ana/ipé-t").to_string_lossy().into_owned()
            ))
        );
    }

    #[test]
    fn every_unlinkable_pin_is_refused_with_its_origin() {
        let crate_dir = &abs("/home/ana/p/out/rust");
        let bad = abs("/home/ana/Público/t");
        let cases = [
            (
                TargetDirSources {
                    embedder: Some(bad.clone()),
                    ..sources()
                },
                TargetDirOrigin::Embedder,
            ),
            (
                TargetDirSources {
                    ipe_home_pin: Some(bad.clone()),
                    ..sources()
                },
                TargetDirOrigin::IpeHomePin,
            ),
            (
                TargetDirSources {
                    cargo_config_pin: Some(bad),
                    ..sources()
                },
                TargetDirOrigin::CargoConfigPin,
            ),
        ];
        for (pinned, origin) in cases {
            let resolved = LinkableTargetDir::resolve(GNU, crate_dir, &pinned);
            assert_eq!(
                refusal(&resolved).map(|(refused, _)| refused),
                Some(UnlinkablePath::Target(origin)),
                "{origin:?}"
            );
        }
    }

    #[test]
    fn an_ascii_pin_is_kept_and_a_relative_one_is_read_against_the_crate() {
        let pinned = TargetDirSources {
            env: Some(OsString::from("shared")),
            ..sources()
        };
        let resolved = LinkableTargetDir::resolve(GNU, &abs("/home/ana/p/out/rust"), &pinned);
        assert_eq!(
            resolved.ok(),
            Some(LinkableTargetDir {
                path: abs("/home/ana/p/out/rust/shared"),
                origin: TargetDirOrigin::Env,
            })
        );
    }

    #[test]
    fn the_embedder_outranks_the_environment() {
        let pinned = TargetDirSources {
            embedder: Some(abs("/w/t")),
            env: Some(abs("/e/t").into_os_string()),
            ..sources()
        };
        let resolved = LinkableTargetDir::resolve(GNU, &abs("/p"), &pinned);
        assert_eq!(resolved.ok().map(|dir| dir.path), Some(abs("/w/t")));
    }

    #[test]
    fn gnu_host_non_ascii_crate_relocates_to_cache() {
        let crate_dir = abs("/home/ana/Ministério Público/counter/out/rust");
        let resolved = LinkableTargetDir::resolve(GNU, &crate_dir, &sources());
        // The key digests the absolute crate path the resolver reads.
        let absolute = std::path::absolute(&crate_dir).expect("absolute crate dir");
        let digest = ipe_backend_rust::identity_hex(&absolute);
        let key = digest.get(..16).unwrap_or_default();
        assert_eq!(key.len(), 16);
        assert_eq!(
            resolved.ok(),
            Some(LinkableTargetDir {
                path: abs("/home/ana/.cache/ipe/t").join(key),
                origin: TargetDirOrigin::UserCache,
            })
        );
    }

    #[test]
    fn gnu_host_ascii_crate_stays_local() {
        let resolved = LinkableTargetDir::resolve(GNU, &abs("/home/ana/p"), &sources());
        assert_eq!(
            resolved.ok().map(|dir| dir.origin),
            Some(TargetDirOrigin::CrateLocal)
        );
    }

    #[test]
    fn gnu_host_non_ascii_cache_base_refused() {
        let homeless = TargetDirSources {
            cache_base: Some(abs("/home/joão/.cache")),
            ..TargetDirSources::default()
        };
        let resolved = LinkableTargetDir::resolve(GNU, &abs("/home/joão/p"), &homeless);
        assert_eq!(
            refusal(&resolved).map(|(refused, _)| refused),
            Some(UnlinkablePath::Target(TargetDirOrigin::UserCache))
        );
    }

    #[test]
    fn gnu_host_without_a_cache_base_is_refused() {
        let resolved =
            LinkableTargetDir::resolve(GNU, &abs("/home/joão/p"), &TargetDirSources::default());
        assert!(
            matches!(resolved, Err(CliError::CacheHomeUnknown)),
            "{resolved:?}"
        );
    }

    #[test]
    fn gnu_host_non_ascii_sysroot_refused() {
        let toolchain = TargetDirSources {
            sysroot: Some(abs("/home/joão/.rustup/toolchains/stable")),
            ..sources()
        };
        let resolved = LinkableTargetDir::resolve(GNU, &abs("/home/ana/p"), &toolchain);
        assert_eq!(
            refusal(&resolved).map(|(refused, _)| refused),
            Some(UnlinkablePath::Sysroot)
        );
    }

    #[test]
    fn unicode_host_ignores_a_non_ascii_sysroot() {
        let toolchain = TargetDirSources {
            sysroot: Some(abs("/home/joão/.rustup/toolchains/stable")),
            ..sources()
        };
        let resolved =
            LinkableTargetDir::resolve(HostLinker::Unicode, &abs("/home/ana/p"), &toolchain);
        assert!(resolved.is_ok(), "{resolved:?}");
    }

    #[test]
    fn the_cache_key_is_deterministic_per_crate() {
        let base = Path::new("/c");
        let a = user_cache_target(base, Path::new("/nonexistent/ipé/a"));
        assert_eq!(a, user_cache_target(base, Path::new("/nonexistent/ipé/a")));
        assert_ne!(a, user_cache_target(base, Path::new("/nonexistent/ipé/b")));
    }

    #[test]
    fn only_user_chosen_origins_are_pins() {
        assert!(TargetDirOrigin::Env.is_pin());
        assert!(TargetDirOrigin::Embedder.is_pin());
        assert!(TargetDirOrigin::IpeHomePin.is_pin());
        assert!(TargetDirOrigin::CargoConfigPin.is_pin());
        assert!(!TargetDirOrigin::CrateLocal.is_pin());
        assert!(!TargetDirOrigin::UserCache.is_pin());
        assert!(!TargetDirOrigin::ScratchCache.is_pin());
    }

    #[cfg(unix)]
    mod stubbed {
        //! Source gathering driven through a stub `cargo metadata`.

        use super::super::{TargetDirSources, is_crate_local};
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::{Path, PathBuf};

        /// A fresh scratch crate directory for `tag`.
        fn scratch(tag: &str) -> PathBuf {
            let base = ipe_test_temp::temp_root()
                .join(format!("ipe-target-dir-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).expect("scratch base");
            base
        }

        /// A stub `cargo` under `base` that runs `body`.
        fn stub(base: &Path, body: &str) -> PathBuf {
            let path = base.join("cargo");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write stub");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("stub executable");
            path
        }

        #[test]
        fn cargo_config_pin_detected_with_env_removed() {
            let base = scratch("config-pin");
            let cargo = stub(
                &base,
                "if [ -n \"${CARGO_TARGET_DIR+x}\" ]; then \
                 echo '{\"target_directory\":\"/leaked\"}'; \
                 else echo '{\"target_directory\":\"/pinned\"}'; fi",
            );
            let reported = crate::cargo_step::target_directory(&cargo, &base);
            assert_eq!(reported.ok(), Some(PathBuf::from("/pinned")));
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn the_crate_own_target_is_not_a_pin() {
            let base = scratch("crate-local");
            assert!(is_crate_local(&base.join("target"), &base));
            assert!(!is_crate_local(&base.join("elsewhere"), &base));
            assert!(!is_crate_local(Path::new("/pinned/target"), &base));
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn an_embedder_override_skips_cargo_metadata() {
            let base = scratch("embedder");
            let cargo = stub(&base, "touch ran; exit 3");
            let gathered = TargetDirSources::gather(
                &cargo,
                &base,
                Some(Path::new("/w/t")),
                super::HostLinker::Unicode,
            );
            assert!(gathered.is_ok(), "{gathered:?}");
            assert!(!base.join("ran").exists(), "no metadata query ran");
            let _ = std::fs::remove_dir_all(&base);
        }
    }
    /// The shared scratch build directory, its lock and its pruning.
    mod scratch_target {
        use super::super::*;

        const LINKER: HostLinker = HostLinker::Unicode;

        /// A fresh directory under the test temp root.
        fn temp(label: &str) -> PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = ipe_test_temp::temp_root().join(format!(
                "ipe-scratch-target-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            dir
        }

        fn cache(base: &Path) -> TargetDirSources {
            TargetDirSources {
                cache_base: Some(base.to_path_buf()),
                ..TargetDirSources::default()
            }
        }

        /// Set `path`'s mtime `age` before now, for a file or a directory.
        fn age(path: &Path, age: std::time::Duration) {
            let then = std::time::SystemTime::now()
                .checked_sub(age)
                .expect("representable");
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(windows)]
            {
                options.write(true);
                std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, 0x0200_0000);
            }
            options
                .open(path)
                .and_then(|file| file.set_modified(then))
                .expect("set mtime");
        }

        const OLD: std::time::Duration = std::time::Duration::from_hours(31 * 24);

        /// A sibling scratch directory under `root` whose lock was last used `last_use` ago.
        fn sibling(root: &Path, name: &str, last_use: std::time::Duration) -> PathBuf {
            let dir = root.join(name);
            std::fs::create_dir_all(dir.join("debug")).expect("sibling");
            let lock = dir.join(TEST_LOCK_FILE);
            std::fs::write(&lock, "").expect("lock file");
            age(&lock, last_use);
            dir
        }

        #[test]
        fn without_a_pin_the_scratch_crate_builds_in_the_shared_cache_dir() {
            let base = temp("shared");
            let crate_dir = base.join("crate");
            let resolved = LinkableTargetDir::resolve_scratch(LINKER, &crate_dir, &cache(&base))
                .expect("resolves");
            assert_eq!(resolved.origin(), TargetDirOrigin::ScratchCache);
            assert_eq!(resolved.path(), scratch_cache_target(&base));
            assert!(resolved.path().is_dir());
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_cargo_target_dir_pin_wins_over_the_shared_cache_dir() {
            let base = temp("env-pin");
            let crate_dir = base.join("crate");
            let pinned = base.join("pinned");
            let sources = TargetDirSources {
                env: Some(pinned.clone().into_os_string()),
                ..cache(&base)
            };
            let resolved =
                LinkableTargetDir::resolve_scratch(LINKER, &crate_dir, &sources).expect("resolves");
            assert_eq!(resolved.origin(), TargetDirOrigin::Env);
            assert_eq!(resolved.path(), pinned);
            assert!(
                !scratch_cache_target(&base).exists(),
                "the cache dir is untouched"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        /// The access of an entry `owner` owns with `mode`, seen by `euid`.
        const fn access(owner: Option<u32>, mode: Option<u32>, euid: Option<u32>) -> Access {
            Access { owner, mode, euid }
        }

        #[test]
        fn only_a_real_directory_of_the_effective_user_is_shared() {
            use ipe_fs_open::FileKind;
            let mine = access(Some(1000), Some(0o700), Some(1000));
            assert!(is_private_dir(FileKind::Dir, mine));
            assert!(is_private_dir(FileKind::Dir, access(None, None, None)));
            assert!(!is_private_dir(
                FileKind::Dir,
                access(Some(0), Some(0o700), Some(1000))
            ));
            assert!(!is_private_dir(
                FileKind::Dir,
                access(None, None, Some(1000))
            ));
            assert!(!is_private_dir(FileKind::Symlink, mine));
            assert!(!is_private_dir(FileKind::Regular, mine));
            assert!(!is_private_dir(FileKind::Other, access(None, None, None)));
        }

        #[test]
        fn a_directory_another_user_may_enter_is_never_shared() {
            use ipe_fs_open::FileKind;
            for mode in [0o710, 0o701, 0o750, 0o755, 0o770, 0o777, 0o1777] {
                assert!(
                    !is_private_dir(FileKind::Dir, access(Some(7), Some(mode), Some(7))),
                    "mode {mode:o} is shared with another user"
                );
            }
            assert!(is_private_dir(
                FileKind::Dir,
                access(Some(7), Some(0o700), Some(7))
            ));
        }

        #[test]
        fn only_a_root_no_other_user_may_write_holds_the_shared_dir() {
            use ipe_fs_open::FileKind;
            for mode in [0o700, 0o750, 0o755] {
                assert!(is_private_root(
                    FileKind::Dir,
                    access(Some(7), Some(mode), Some(7))
                ));
            }
            for mode in [0o770, 0o757, 0o777, 0o1777] {
                assert!(
                    !is_private_root(FileKind::Dir, access(Some(7), Some(mode), Some(7))),
                    "mode {mode:o} lets another user replace the shared dir"
                );
            }
            assert!(!is_private_root(
                FileKind::Dir,
                access(Some(0), Some(0o755), Some(7))
            ));
            assert!(!is_private_root(
                FileKind::Symlink,
                access(Some(7), Some(0o755), Some(7))
            ));
        }

        #[test]
        fn a_prune_judges_only_a_directory_of_the_effective_user() {
            use ipe_fs_open::FileKind;
            assert!(is_prunable(
                FileKind::Dir,
                access(Some(7), Some(0o755), Some(7))
            ));
            assert!(is_prunable(FileKind::Dir, access(None, None, None)));
            assert!(!is_prunable(
                FileKind::Dir,
                access(Some(0), Some(0o700), Some(7))
            ));
            assert!(!is_prunable(
                FileKind::Symlink,
                access(Some(7), Some(0o700), Some(7))
            ));
        }

        #[cfg(unix)]
        #[test]
        fn a_shared_path_other_users_may_enter_falls_to_the_crate_local_dir() {
            use std::os::unix::fs::PermissionsExt as _;
            let base = temp("open-mode");
            let crate_dir = base.join("crate");
            let shared = scratch_cache_target(&base);
            ensure_private_scratch(&shared).expect("shared dir");
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777))
                .expect("open the shared dir");
            let resolved = LinkableTargetDir::resolve_scratch(LINKER, &crate_dir, &cache(&base))
                .expect("resolves");
            assert_eq!(resolved.origin(), TargetDirOrigin::CrateLocal);
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn a_shared_root_of_the_user_loses_its_shared_write_before_use() {
            use std::os::unix::fs::PermissionsExt as _;
            let base = temp("open-root");
            let crate_dir = base.join("crate");
            let root = user_cache_root(&base);
            std::fs::create_dir_all(&root).expect("cache root");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o1777))
                .expect("open the cache root");
            let resolved = LinkableTargetDir::resolve_scratch(LINKER, &crate_dir, &cache(&base))
                .expect("resolves");
            assert_eq!(resolved.origin(), TargetDirOrigin::ScratchCache);
            let mode = std::fs::symlink_metadata(&root)
                .expect("cache root")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o022,
                0,
                "no other user may write the root: {mode:o}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn a_shared_dir_opened_after_resolution_is_refused_at_its_lock() {
            use std::os::unix::fs::PermissionsExt as _;
            let base = temp("opened-late");
            let crate_dir = base.join("crate");
            let resolved = LinkableTargetDir::resolve_scratch(LINKER, &crate_dir, &cache(&base))
                .expect("resolves");
            assert_eq!(resolved.origin(), TargetDirOrigin::ScratchCache);
            std::fs::set_permissions(resolved.path(), std::fs::Permissions::from_mode(0o755))
                .expect("open the shared dir");
            let locked = LinkableTargetDir::lock_scratch(
                resolved,
                crate::remote_ingest::LocalWall::of_secs::<1>(),
            );
            assert!(
                matches!(locked, Err(CliError::Io { .. })),
                "the shared dir is re-proven at its lock: {locked:?}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn a_pruned_shared_dir_is_recreated_owner_only_by_its_waiter() {
            use std::os::unix::fs::PermissionsExt as _;
            let base = temp("recreated");
            let shared = scratch_cache_target(&base);
            ensure_private_scratch(&shared).expect("private dir");
            let mut opens = 0_u32;
            let held = TargetLock::acquire_with(
                &shared,
                DirPrep::Private,
                crate::remote_ingest::LocalWall::of_secs::<1>(),
                || {
                    opens += 1;
                    if opens == 1 {
                        std::fs::remove_dir_all(&shared).expect("pruned");
                    }
                },
            )
            .expect("the waiter takes the recreated dir");
            assert_eq!(opens, 2, "one retry after the removal");
            let mode = std::fs::symlink_metadata(&shared)
                .expect("recreated")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "recreated owner-only: {mode:o}");
            drop(held);
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn the_lock_file_is_created_owner_only() {
            use std::os::unix::fs::PermissionsExt as _;
            let base = temp("lock-mode");
            let held = TargetLock::acquire(&base, crate::remote_ingest::LocalWall::of_secs::<1>())
                .expect("locks");
            let mode = std::fs::symlink_metadata(base.join(TEST_LOCK_FILE))
                .expect("lock file")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "no other user may open the lock: {mode:o}");
            drop(held);
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn a_hard_linked_lock_file_is_refused_and_left_untouched() {
            let base = temp("linked-lock");
            let victim = base.join("victim");
            std::fs::write(&victim, "kept").expect("victim");
            age(&victim, OLD);
            let before = std::fs::metadata(&victim)
                .and_then(|meta| meta.modified())
                .expect("mtime");
            std::fs::hard_link(&victim, base.join(TEST_LOCK_FILE)).expect("planted link");
            let held = TargetLock::acquire(&base, crate::remote_ingest::LocalWall::of_secs::<1>());
            assert!(
                matches!(held, Err(CliError::Io { .. })),
                "a lock file another entry names is refused: {held:?}"
            );
            let after = std::fs::metadata(&victim)
                .and_then(|meta| meta.modified())
                .expect("mtime");
            assert_eq!(before, after, "the linked file's stamp is never written");
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_busy_refusal_names_the_lock_and_its_removal() {
            let path = std::path::Path::new("/cache/ipe/t/scratch-0/.ipe-test.lock");
            let shown = CliError::TestTargetBusy {
                path: TerminalSafe::sanitize(&path.to_string_lossy()),
                wall: crate::remote_ingest::LocalWall::of_secs::<1>(),
            }
            .to_string();
            assert!(shown.contains(".ipe-test.lock"), "{shown}");
            assert!(shown.contains("remove"), "{shown}");
        }

        #[test]
        fn a_lock_taken_and_freed_after_the_staleness_check_keeps_its_dir() {
            let base = temp("prune-retaken");
            let root = user_cache_root(&base);
            let old = sibling(&root, "scratch-old", OLD);
            prune_if_stale_with(
                &old,
                std::time::SystemTime::now(),
                SCRATCH_RETENTION,
                || {
                    drop(
                        TargetLock::acquire(&old, crate::remote_ingest::LocalWall::of_secs::<1>())
                            .expect("a run takes the lock"),
                    );
                },
            )
            .expect("prunes");
            assert!(old.exists(), "a dir used since the check is kept");
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_lockless_dir_a_run_enters_after_the_staleness_check_is_kept() {
            let base = temp("prune-entered");
            let root = user_cache_root(&base);
            let dir = root.join("scratch-lockless");
            std::fs::create_dir_all(&dir).expect("dir");
            age(&dir, OLD);
            prune_if_stale_with(
                &dir,
                std::time::SystemTime::now(),
                SCRATCH_RETENTION,
                || {
                    drop(
                        TargetLock::acquire(&dir, crate::remote_ingest::LocalWall::of_secs::<1>())
                            .expect("a run takes and frees the lock"),
                    );
                },
            )
            .expect("prunes");
            assert!(dir.exists(), "a dir a run entered is kept");
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_pruned_dir_loses_its_lock_file_only_after_its_contents() {
            let base = temp("prune-order");
            let root = user_cache_root(&base);
            let old = sibling(&root, "scratch-old", OLD);
            std::fs::write(old.join("debug").join("unit.rlib"), "unit").expect("unit");
            std::fs::write(old.join("ipe-test-run-1"), "runner").expect("runner");
            let lock_path = old.join(TEST_LOCK_FILE);
            let mut seen = None;
            remove_locked_dir(&old, || {
                let left = std::fs::read_dir(&old)
                    .expect("dir kept")
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name())
                    .collect::<Vec<_>>();
                seen = Some((left, lock_path.is_file()));
            })
            .expect("removes");
            let (left, locked) = seen.expect("called once");
            assert_eq!(left, vec![std::ffi::OsString::from(TEST_LOCK_FILE)]);
            assert!(locked, "the lock file is the last entry left");
            assert!(!old.exists(), "the dir is removed");
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn an_entry_made_after_the_contents_went_keeps_the_dir() {
            let base = temp("prune-reentered");
            let root = user_cache_root(&base);
            let old = sibling(&root, "scratch-old", OLD);
            let late = old.join("late");
            let removed = remove_locked_dir(&old, || {
                std::fs::write(&late, "").expect("a run's late entry");
            });
            assert!(removed.is_ok(), "{removed:?}");
            assert!(
                late.exists(),
                "nothing made after the contents went is removed"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_dir_another_pruner_removed_is_no_error() {
            let base = temp("prune-raced");
            let root = user_cache_root(&base);
            let old = sibling(&root, "scratch-old", OLD);
            let pruned = prune_if_stale_with(
                &old,
                std::time::SystemTime::now(),
                SCRATCH_RETENTION,
                || {
                    std::fs::remove_dir_all(&old).expect("the other pruner");
                },
            );
            assert!(pruned.is_ok(), "{pruned:?}");
            assert!(!old.exists(), "the lock file is never recreated");
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_non_directory_at_the_shared_path_falls_to_the_crate_local_dir() {
            let base = temp("not-a-dir");
            let crate_dir = base.join("crate");
            let shared = scratch_cache_target(&base);
            std::fs::create_dir_all(shared.parent().expect("parent")).expect("cache root");
            std::fs::write(&shared, "planted").expect("planted file");
            let resolved = LinkableTargetDir::resolve_scratch(LINKER, &crate_dir, &cache(&base))
                .expect("resolves");
            assert_eq!(resolved.origin(), TargetDirOrigin::CrateLocal);
            assert_eq!(resolved.path(), crate_dir.join("target"));
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn a_link_at_the_shared_path_falls_to_the_crate_local_dir_and_is_never_built_in() {
            let base = temp("link");
            let crate_dir = base.join("crate");
            let elsewhere = base.join("elsewhere");
            std::fs::create_dir_all(&elsewhere).expect("link target");
            let shared = scratch_cache_target(&base);
            std::fs::create_dir_all(shared.parent().expect("parent")).expect("cache root");
            std::os::unix::fs::symlink(&elsewhere, &shared).expect("planted link");
            let resolved = LinkableTargetDir::resolve_scratch(LINKER, &crate_dir, &cache(&base))
                .expect("resolves");
            assert_eq!(resolved.origin(), TargetDirOrigin::CrateLocal);
            let locked = LinkableTargetDir::lock_scratch(
                resolved,
                crate::remote_ingest::LocalWall::of_secs::<1>(),
            )
            .expect("locks the crate-local dir");
            assert_eq!(locked.dir().path(), crate_dir.join("target"));
            assert!(
                std::fs::read_dir(&elsewhere)
                    .expect("link target")
                    .next()
                    .is_none(),
                "nothing is written through the link"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn no_cache_base_falls_to_the_crate_local_dir() {
            let base = temp("no-cache");
            let crate_dir = base.join("crate");
            let resolved = LinkableTargetDir::resolve_scratch(
                LINKER,
                &crate_dir,
                &TargetDirSources::default(),
            )
            .expect("resolves");
            assert_eq!(resolved.origin(), TargetDirOrigin::CrateLocal);
            assert_eq!(resolved.path(), crate_dir.join("target"));
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn two_scratch_runs_share_one_dir_outside_the_project_key_space() {
            let base = temp("two-runs");
            let first = base.join("run-a");
            let second = base.join("run-b");
            let a = LinkableTargetDir::resolve_scratch(LINKER, &first, &cache(&base))
                .expect("first run");
            let b = LinkableTargetDir::resolve_scratch(LINKER, &second, &cache(&base))
                .expect("second run");
            assert_eq!(a.origin(), TargetDirOrigin::ScratchCache);
            assert_eq!(a.path(), b.path());
            for crate_dir in [&first, &second] {
                assert_ne!(a.path(), user_cache_target(&base, crate_dir));
            }
            let name = a
                .path()
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .expect("utf-8 name");
            let key = name.strip_prefix(SCRATCH_PREFIX).expect("scratch prefix");
            assert_eq!(key.len(), USER_CACHE_KEY_LEN);
            assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_ne!(name.len(), USER_CACHE_KEY_LEN, "never a project key");
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn prune_removes_only_an_old_unheld_sibling() {
            let base = temp("prune");
            let root = user_cache_root(&base);
            let own = sibling(&root, "scratch-own", OLD);
            let old = sibling(&root, "scratch-old", OLD);
            let young = sibling(&root, "scratch-young", std::time::Duration::from_secs(60));
            let held = sibling(&root, "scratch-held", OLD);
            let project = sibling(&root, "0123456789abcdef", OLD);
            let holder = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(held.join(TEST_LOCK_FILE))
                .expect("holder");
            holder.try_lock().expect("held elsewhere");

            prune_scratch_siblings(&root, &own, SCRATCH_RETENTION).expect("prunes");

            assert!(!old.exists(), "an old unheld sibling is removed");
            assert!(own.exists(), "the run's own dir is kept");
            assert!(young.exists(), "a sibling used within retention is kept");
            assert!(held.exists(), "a sibling another run holds is kept");
            assert!(
                project.exists(),
                "a project's relocated dir is never pruned"
            );
            drop(holder);
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn prune_over_an_unreadable_sibling_is_a_typed_error() {
            use std::os::unix::fs::PermissionsExt as _;
            if rustix::process::geteuid().is_root() {
                return;
            }
            let base = temp("prune-unreadable");
            let root = user_cache_root(&base);
            let own = sibling(&root, "scratch-own", OLD);
            let sealed = sibling(&root, "scratch-sealed", OLD);
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000))
                .expect("seal");
            let pruned = prune_scratch_siblings(&root, &own, SCRATCH_RETENTION);
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700))
                .expect("unseal");
            assert!(
                matches!(pruned, Err(CliError::Io { .. })),
                "an unreadable sibling is an error, never a skip: {pruned:?}"
            );
            assert!(sealed.exists());
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_lock_held_past_the_wall_is_refused_as_busy() {
            let base = temp("busy");
            let wall = crate::remote_ingest::LocalWall::of_secs::<1>();
            let first = TargetLock::acquire(&base, wall).expect("first holder");
            let second = TargetLock::acquire(&base, wall);
            assert!(
                matches!(second, Err(CliError::TestTargetBusy { .. })),
                "a held lock refuses as busy: {second:?}"
            );
            drop(first);
            assert!(
                TargetLock::acquire(&base, wall).is_ok(),
                "a released lock is free"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn a_lock_file_replaced_before_its_lock_is_taken_again() {
            let base = temp("replaced");
            let lock_path = base.join(TEST_LOCK_FILE);
            let mut opens = 0_u32;
            let held = TargetLock::acquire_with(
                &base,
                DirPrep::Plain,
                crate::remote_ingest::LocalWall::of_secs::<1>(),
                || {
                    opens += 1;
                    if opens == 1 {
                        std::fs::remove_file(&lock_path).expect("unlink");
                        std::fs::write(&lock_path, "").expect("recreate");
                    }
                },
            )
            .expect("holds the new file");
            assert_eq!(opens, 2, "one retry after the replacement");
            let named = std::fs::File::open(&lock_path).expect("the named file opens");
            assert!(
                matches!(named.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
                "the file the name holds is the locked one"
            );
            drop(held);
            let _ = std::fs::remove_dir_all(&base);
        }

        #[cfg(unix)]
        #[test]
        fn a_lock_file_replaced_on_every_attempt_is_refused_as_busy() {
            let base = temp("always-replaced");
            let lock_path = base.join(TEST_LOCK_FILE);
            let held = TargetLock::acquire_with(
                &base,
                DirPrep::Plain,
                crate::remote_ingest::LocalWall::of_secs::<1>(),
                || {
                    std::fs::remove_file(&lock_path).expect("unlink");
                    std::fs::write(&lock_path, "").expect("recreate");
                },
            );
            assert!(
                matches!(held, Err(CliError::TestTargetBusy { .. })),
                "a lock that never settles is refused: {held:?}"
            );
            let _ = std::fs::remove_dir_all(&base);
        }

        #[test]
        fn a_released_scratch_target_keeps_its_path() {
            let base = temp("release");
            let crate_dir = base.join("crate");
            let resolved = LinkableTargetDir::resolve_scratch(LINKER, &crate_dir, &cache(&base))
                .expect("resolves");
            let locked = LinkableTargetDir::lock_scratch(
                resolved,
                crate::remote_ingest::LocalWall::of_secs::<1>(),
            )
            .expect("locks");
            assert!(locked.dir().path().join(TEST_LOCK_FILE).is_file());
            let path = locked.release();
            assert_eq!(path, scratch_cache_target(&base));
            assert!(
                TargetLock::acquire(&path, crate::remote_ingest::LocalWall::of_secs::<1>()).is_ok(),
                "the release frees the lock"
            );
            let _ = std::fs::remove_dir_all(&base);
        }
    }
}
