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

    /// The linker family of the host `rustc` reported, or of this platform when the query failed.
    ///
    /// A failed query on Windows is [`Self::AsciiOnly`] (fail closed); on any
    /// other platform every linker opens any path.
    #[must_use]
    pub fn of_query(host: Option<&str>) -> Self {
        host.map_or(
            if cfg!(windows) {
                Self::AsciiOnly
            } else {
                Self::Unicode
            },
            |triple| Self::of_triple(HostTriple::parse(triple)),
        )
    }

    /// The linker family of the active toolchain's host.
    #[must_use]
    pub fn active() -> Self {
        Self::of_query(
            crate::toolchain::RustcVersion::active()
                .ok()
                .map(crate::toolchain::RustcVersion::host),
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
}

impl TargetDirOrigin {
    /// Whether the user chose this directory, so ipe never moves or removes it.
    #[must_use]
    pub const fn is_pin(self) -> bool {
        match self {
            Self::Embedder | Self::Env | Self::IpeHomePin | Self::CargoConfigPin => true,
            Self::CrateLocal | Self::UserCache => false,
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
        if let Some(sysroot) = &sources.sysroot
            && !linker.can_open(sysroot)
        {
            return Err(unlinkable(UnlinkablePath::Sysroot, sysroot, linker));
        }
        let crate_dir = std::path::absolute(crate_dir).unwrap_or_else(|_| crate_dir.to_path_buf());
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
        if let Some((path, origin)) = pin {
            let path = crate_dir.join(path);
            return if linker.can_open(&path) {
                Ok(Self { path, origin })
            } else {
                Err(unlinkable(UnlinkablePath::Target(origin), &path, linker))
            };
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

    fn sources() -> TargetDirSources {
        TargetDirSources {
            cache_base: Some(PathBuf::from("/home/ana/.cache")),
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
        let resolved =
            LinkableTargetDir::resolve(linker, Path::new("/srv/ipé/out/rust"), &sources());
        assert_eq!(
            resolved.ok(),
            Some(LinkableTargetDir {
                path: PathBuf::from("/srv/ipé/out/rust/target"),
                origin: TargetDirOrigin::CrateLocal,
            })
        );
    }

    #[cfg(windows)]
    #[test]
    fn unknown_host_on_windows_is_ascii_only() {
        assert_eq!(HostLinker::of_query(None), HostLinker::AsciiOnly);
    }

    #[cfg(not(windows))]
    #[test]
    fn unknown_host_off_windows_is_unicode() {
        assert_eq!(HostLinker::of_query(None), HostLinker::Unicode);
    }

    #[test]
    fn gnu_host_non_ascii_pin_refused() {
        let pinned = TargetDirSources {
            env: Some(OsString::from("/home/ana/ipé-t")),
            ..sources()
        };
        let resolved = LinkableTargetDir::resolve(GNU, Path::new("/home/ana/p/out/rust"), &pinned);
        assert_eq!(
            refusal(&resolved),
            Some((
                UnlinkablePath::Target(TargetDirOrigin::Env),
                "/home/ana/ipé-t".to_owned()
            ))
        );
    }

    #[test]
    fn every_unlinkable_pin_is_refused_with_its_origin() {
        let crate_dir = Path::new("/home/ana/p/out/rust");
        let bad = PathBuf::from("/home/ana/Público/t");
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
        let resolved = LinkableTargetDir::resolve(GNU, Path::new("/home/ana/p/out/rust"), &pinned);
        assert_eq!(
            resolved.ok(),
            Some(LinkableTargetDir {
                path: PathBuf::from("/home/ana/p/out/rust/shared"),
                origin: TargetDirOrigin::Env,
            })
        );
    }

    #[test]
    fn the_embedder_outranks_the_environment() {
        let pinned = TargetDirSources {
            embedder: Some(PathBuf::from("/w/t")),
            env: Some(OsString::from("/e/t")),
            ..sources()
        };
        let resolved = LinkableTargetDir::resolve(GNU, Path::new("/p"), &pinned);
        assert_eq!(
            resolved.ok().map(|dir| dir.path),
            Some(PathBuf::from("/w/t"))
        );
    }

    #[test]
    fn gnu_host_non_ascii_crate_relocates_to_cache() {
        let crate_dir = Path::new("/home/ana/Ministério Público/counter/out/rust");
        let resolved = LinkableTargetDir::resolve(GNU, crate_dir, &sources());
        let digest = ipe_backend_rust::identity_hex(crate_dir);
        let key = digest.get(..16).unwrap_or_default();
        assert_eq!(key.len(), 16);
        assert_eq!(
            resolved.ok(),
            Some(LinkableTargetDir {
                path: PathBuf::from("/home/ana/.cache/ipe/t").join(key),
                origin: TargetDirOrigin::UserCache,
            })
        );
    }

    #[test]
    fn gnu_host_ascii_crate_stays_local() {
        let resolved = LinkableTargetDir::resolve(GNU, Path::new("/home/ana/p"), &sources());
        assert_eq!(
            resolved.ok().map(|dir| dir.origin),
            Some(TargetDirOrigin::CrateLocal)
        );
    }

    #[test]
    fn gnu_host_non_ascii_cache_base_refused() {
        let homeless = TargetDirSources {
            cache_base: Some(PathBuf::from("/home/joão/.cache")),
            ..TargetDirSources::default()
        };
        let resolved = LinkableTargetDir::resolve(GNU, Path::new("/home/joão/p"), &homeless);
        assert_eq!(
            refusal(&resolved).map(|(refused, _)| refused),
            Some(UnlinkablePath::Target(TargetDirOrigin::UserCache))
        );
    }

    #[test]
    fn gnu_host_without_a_cache_base_is_refused() {
        let resolved = LinkableTargetDir::resolve(
            GNU,
            Path::new("/home/joão/p"),
            &TargetDirSources::default(),
        );
        assert!(
            matches!(resolved, Err(CliError::CacheHomeUnknown)),
            "{resolved:?}"
        );
    }

    #[test]
    fn gnu_host_non_ascii_sysroot_refused() {
        let toolchain = TargetDirSources {
            sysroot: Some(PathBuf::from("/home/joão/.rustup/toolchains/stable")),
            ..sources()
        };
        let resolved = LinkableTargetDir::resolve(GNU, Path::new("/home/ana/p"), &toolchain);
        assert_eq!(
            refusal(&resolved).map(|(refused, _)| refused),
            Some(UnlinkablePath::Sysroot)
        );
    }

    #[test]
    fn unicode_host_ignores_a_non_ascii_sysroot() {
        let toolchain = TargetDirSources {
            sysroot: Some(PathBuf::from("/home/joão/.rustup/toolchains/stable")),
            ..sources()
        };
        let resolved =
            LinkableTargetDir::resolve(HostLinker::Unicode, Path::new("/home/ana/p"), &toolchain);
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
}
