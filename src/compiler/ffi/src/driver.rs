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
    /// TRUSTED source `load_catalog` re-derives `_bindings.rs` from: the
    /// stored `_bindings.rs` text is never trusted, only regenerated.
    pub pkg_json: PathBuf,
}

/// The per-project namespace directory ipe keeps its caches in.
///
/// Every consumer (reserved-name refusal, audit symlink walk, cache
/// discovery) derives from this one constant.
pub const CACHE_NAMESPACE_DIR: &str = ".ipe";

/// The project-relative FFI cache path components, namespace first.
///
/// [`FfiCache::at_project_root`] joins exactly these, so a no-follow walk over
/// them visits every component the cache's writes and deletes traverse.
pub const FFI_CACHE_COMPONENTS: [&str; 4] = [CACHE_NAMESPACE_DIR, "cache", "ffi", "rust"];

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
            root: FFI_CACHE_COMPONENTS
                .iter()
                .fold(project_root.to_path_buf(), |dir, c| dir.join(c)),
        }
    }

    /// The cache directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The artifact paths for a slug.
    #[must_use]
    pub fn artifact_paths(&self, slug: &str) -> ArtifactPaths {
        ArtifactPaths {
            ipei: self.root.join(format!("{slug}.ipei")),
            kernel_json: self.root.join(format!("{slug}.kernel.json")),
            bindings: self.root.join(format!("{slug}_bindings.rs")),
            coverage: self.root.join(format!("{slug}.coverage.md")),
            interface: self.root.join(format!("{slug}.ipe")),
            consumer: self.root.join(format!("{slug}.consumer.json")),
            pkg_json: self.root.join(format!("{slug}.pkg.json")),
        }
    }

    /// Emit and write all artifacts for a validated package. `inspection_json`
    /// is the raw inspector wire text that decoded into `pkg`; it is persisted
    /// as `<slug>.pkg.json`, the sole source `load_catalog` re-derives the
    /// whole consumer-side view from through the validated decode gate. The
    /// other six artifacts are debug/watch projections the loader never
    /// trusts.
    ///
    /// # Errors
    ///
    /// `IPE-F4412` naming the first path that could not be written.
    pub fn write_package(
        &self,
        pkg: &PkgInfo,
        inspection_json: &str,
    ) -> Result<ArtifactPaths, Diagnostic> {
        let io_err = |path: &Path, e: &std::io::Error| Diagnostic::ArtifactIo {
            path: path.to_string_lossy().into_owned(),
            detail: e.to_string(),
        };
        std::fs::create_dir_all(&self.root).map_err(|e| io_err(&self.root, &e))?;
        let paths = self.artifact_paths(&slugify(pkg.name()));
        let iface = crate::interface::crate_interface(pkg);
        let consumer_json = emit_consumer_json(pkg, &iface)?;
        let writes: [(&Path, String); 7] = [
            (
                &paths.ipei,
                crate::emit::emit_ipei(pkg, &iface.transparent_types),
            ),
            (&paths.kernel_json, crate::emit::emit_kernel_json(pkg)),
            (&paths.bindings, crate::bindings::emit_bindings(pkg)),
            (&paths.coverage, emit_coverage(pkg, &iface.skipped)),
            (&paths.interface, iface.source),
            (&paths.consumer, consumer_json),
            (&paths.pkg_json, inspection_json.to_owned()),
        ];
        for (path, contents) in &writes {
            std::fs::write(path, contents).map_err(|e| io_err(path, &e))?;
        }
        Ok(paths)
    }

    /// Delete a slug's four artifacts (`ipe remove`). Already-absent files
    /// are fine — removal is idempotent.
    ///
    /// # Errors
    ///
    /// `IPE-F4412` naming the first path that exists but cannot be deleted.
    pub fn remove_package(&self, slug: &str) -> Result<(), Diagnostic> {
        let paths = self.artifact_paths(slug);
        for path in [
            &paths.ipei,
            &paths.kernel_json,
            &paths.bindings,
            &paths.coverage,
            &paths.interface,
            &paths.consumer,
            &paths.pkg_json,
        ] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Diagnostic::ArtifactIo {
                        path: path.to_string_lossy().into_owned(),
                        detail: e.to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

// ── pkg-config missing-library detection ────────────────────────────────────

/// A parsed pkg-config "not found" failure: the missing system library and
/// the Rust crate whose build script reported it.
///
/// Parse-don't-validate: callers receive a typed value, never a raw string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingSystemLib {
    /// The `pkg-config` library name (e.g. `wayland-client`).
    pub system_lib: String,
    /// The Rust `-sys` crate that required it (e.g. `wayland-sys`).
    pub crate_name: String,
}

/// Trim and strip control characters from a name extracted out of raw
/// build-script stderr. A system-library or crate name is rendered into a styled
/// diagnostic; an ANSI escape or other control byte carried in the raw stderr
/// must not reach the terminal and forge markup, so it is removed at the parse
/// boundary (the typed value downstream is always terminal-safe).
fn sanitize_extracted_name(raw: &str) -> String {
    raw.trim().chars().filter(|c| !c.is_control()).collect()
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
/// different cause).
#[must_use]
pub fn detect_missing_system_lib(errors: &[String]) -> Option<MissingSystemLib> {
    for line in errors {
        // Primary form emitted by `pkg_config` crate build scripts:
        // "The system library `<lib>` required by crate `<crate>` was not found."
        if let Some(rest) = line.strip_prefix("The system library `")
            && let Some((sys_lib, rest)) = rest.split_once("` required by crate `")
            && let Some((crate_name, _)) = rest.split_once("` was not found")
        {
            return Some(MissingSystemLib {
                system_lib: sanitize_extracted_name(sys_lib),
                crate_name: sanitize_extracted_name(crate_name),
            });
        }
        // Secondary form from pkg-config itself:
        // "Package '<lib>' was not found in the pkg-config search path."
        // or "Package '<lib>', required by 'virtual:world', not found"
        if (line.contains("was not found in the pkg-config search path")
            || (line.contains("not found") && line.starts_with("Package '")))
            && let Some(rest) = line.strip_prefix("Package '")
            && let Some((sys_lib, _)) = rest.split_once('\'')
        {
            return Some(MissingSystemLib {
                system_lib: sanitize_extracted_name(sys_lib),
                // No crate name in this form — leave empty; the caller
                // fills it from context when available.
                crate_name: String::new(),
            });
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
/// library is not in the table.
#[must_use]
pub fn install_hint_for(sys_lib: &str) -> String {
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

/// Summarise the raw inspector error strings into a short human-readable
/// message for the `--verbose`-less case.
///
/// Keeps at most a few lines of context from the raw log. The full log is
/// available under `--verbose` (the CLI layer adds that escape hatch around
/// the call site).
#[must_use]
/// Strip ANSI escape sequences and non-printable control characters from a
/// foreign string (rustc/build-script stderr) before interpolating it into a
/// diagnostic. A length-capped but un-stripped foreign string can carry
/// terminal control codes that forge markup or corrupt a structured output
/// consumer. Two passes:
///
/// 1. Remove ANSI CSI sequences (`ESC [ … <letter>`) and OSC sequences
///    (`ESC ] … BEL/ST`) via a small state machine — the two sequence families
///    that rustc's colour output uses.
/// 2. Filter out remaining control characters except tab (`\t`), which is
///    printable in a terminal context.
fn strip_foreign_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Consume the escape sequence body without emitting it.
            match chars.peek() {
                Some('[') => {
                    // CSI sequence: ESC [ <params> <final-byte> (final byte in 0x40–0x7E).
                    let _ = chars.next(); // consume '['
                    for inner in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&inner) {
                            break; // final byte consumed
                        }
                    }
                }
                Some(']') => {
                    // OSC sequence: ESC ] <body> BEL or ESC \.
                    let _ = chars.next(); // consume ']'
                    loop {
                        match chars.next() {
                            None | Some('\x07') => break,
                            Some('\x1b') if chars.peek() == Some(&'\\') => {
                                let _ = chars.next();
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                _ => {
                    // Unknown escape: consume only the ESC itself (already done).
                }
            }
        } else if c == '\t' || !c.is_control() {
            out.push(c);
        }
        // Other control chars (NUL, BEL, BS, CR, DEL, …) are dropped.
    }
    out
}

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
            let crate_name = if missing.crate_name.is_empty() {
                pkg.name().to_owned()
            } else {
                missing.crate_name
            };
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
            if b.transparent_params.iter().any(Option::is_some) {
                o.insert(
                    "transparentParams".into(),
                    serde_json::json!(b.transparent_params),
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
        "cargoDeps": cargo_dep_lines(pkg)?,
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
    /// Pinned `[dependencies]` lines.
    pub cargo_deps: Vec<String>,
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

/// Load every installed crate from a project's FFI artifact cache.
///
/// An absent cache directory is an empty catalog (a project with no FFI).
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
/// wrapper.
pub fn load_catalog(cache_root: &Path) -> Result<Vec<InstalledCrate>, Diagnostic> {
    if !cache_root.is_dir() {
        return Ok(Vec::new());
    }
    let io_err = |path: &Path, detail: String| Diagnostic::ArtifactIo {
        path: path.to_string_lossy().into_owned(),
        detail,
    };
    let mut slugs: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(cache_root).map_err(|e| io_err(cache_root, e.to_string()))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_err(cache_root, e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(slug) = name.strip_suffix(".consumer.json") {
            slugs.push(slug.to_owned());
        }
    }
    slugs.sort();
    let mut out = Vec::with_capacity(slugs.len());
    for slug in slugs {
        out.push(load_installed_crate(cache_root, slug)?);
    }
    Ok(out)
}

/// Load and validate ONE installed crate's artifacts (see [`load_catalog`]).
///
/// # Errors
///
/// As [`load_catalog`], scoped to this slug's artifacts.
#[allow(clippy::too_many_lines)] // one linear artifact decode-and-cross-check cascade
fn load_installed_crate(cache_root: &Path, slug: String) -> Result<InstalledCrate, Diagnostic> {
    let io_err = |path: &Path, detail: String| Diagnostic::ArtifactIo {
        path: path.to_string_lossy().into_owned(),
        detail,
    };
    {
        let cache = FfiCache {
            root: cache_root.to_path_buf(),
        };
        let paths = cache.artifact_paths(&slug);
        let read = |p: &Path| -> Result<String, Diagnostic> {
            std::fs::read_to_string(p).map_err(|e| io_err(p, e.to_string()))
        };
        // RE-DERIVE the whole consumer-side view from the validated
        // inspection document — no on-disk projection is trusted as text
        // (see [`load_catalog`]). A legacy cache written before the
        // `pkg.json` artifact existed has no document to re-derive from; it
        // falls back to the stored projections, whose trust then rests on
        // the discovery-time ownership/write-boundary gate
        // (`find_cache_root`) plus the injection-free-by-construction
        // emitter.
        if paths.pkg_json.is_file() {
            let pkg_text = read(&paths.pkg_json)?;
            let pkg = PkgInfo::decode_json(&pkg_text)?;
            return installed_crate_from_pkg(slug, &pkg);
        }
        let consumer_text = read(&paths.consumer)?;
        let interface_source = read(&paths.interface)?;
        let dep_versions: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let bindings_source = read(&paths.bindings)?;
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
        let cargo_deps: Vec<String> = doc
            .get("cargoDeps")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
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
            ));
        }
        let bindings: Vec<crate::interface::InterfaceBinding> = doc
            .get("bindings")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|b| {
                        let get = |k: &str| b.get(k).and_then(serde_json::Value::as_str);
                        let transparent_params: Vec<Option<String>> = b
                            .get("transparentParams")
                            .and_then(serde_json::Value::as_array)
                            .map(|ps| ps.iter().map(|p| p.as_str().map(str::to_owned)).collect())
                            .unwrap_or_default();
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
                        Some(crate::interface::InterfaceBinding {
                            ref_name: get("refName")?.to_owned(),
                            wrapper_ident: get("wrapperIdent")?.to_owned(),
                            arity: usize::try_from(
                                b.get("arity").and_then(serde_json::Value::as_u64)?,
                            )
                            .ok()?,
                            sig: get("sig")?.to_owned(),
                            transparent_params,
                            transparent_result,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
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
                )));
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
pub fn installed_crate_from_pkg(slug: String, pkg: &PkgInfo) -> Result<InstalledCrate, Diagnostic> {
    let mut dep_versions: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for dep in pkg.transitive_deps() {
        dep_versions.insert(
            dep.ident.as_str().to_owned(),
            dep.version.as_str().to_owned(),
        );
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
        cargo_deps: cargo_dep_lines(pkg)?,
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

/// The `[dependencies]` lines a program using this crate's bindings needs.
///
/// One exact pinned version per resolved crate — never a guessed name,
/// never `"*"` — with the effective feature set on the primary crate.
///
/// # Errors
///
/// A dep with no resolved version fails loudly (an unpinned line would be
/// an under-bind waiting to happen).
pub fn cargo_dep_lines(pkg: &PkgInfo) -> Result<Vec<String>, Diagnostic> {
    let missing_version = |name: &str| Diagnostic::WireMalformed {
        context: format!("transitive dep `{name}`"),
        defect: crate::diag::WireDefect::Json {
            detail: "missing resolved version (an unpinned dependency line is forbidden)"
                .to_owned(),
        },
    };
    let mut lines = Vec::new();
    // An author-supplied wrapper crate is bound by PATH, never a registry pin:
    // the emitted app crate depends on the local wrapper directory. Its own
    // transitive deps resolve through the wrapper's `Cargo.toml`, so the single
    // path line is the whole dependency surface the app needs to add.
    if !pkg.wrapper_path().is_empty() {
        // The Cargo `[dependencies]` KEY is the charset-gated package NAME, never
        // the weakly gated `pkg_path` (which may even be a `--manifest` filesystem
        // path): the type forbids any ungated string reaching the TOML key.
        lines.push(render_path_dep_line(
            pkg.name_pkg(),
            pkg.wrapper_path().as_str(),
            pkg.features(),
        ));
        return Ok(lines);
    }
    if pkg.transitive_deps().is_empty() {
        // No probe metadata: pin the primary crate from the package header. The
        // dependency KEY is the charset-gated package name, never `pkg_path`.
        if pkg.version().is_empty() {
            return Err(missing_version(pkg.name()));
        }
        lines.push(render_dep_line(
            pkg.name_pkg(),
            pkg.crate_version(),
            pkg.features(),
        ));
        return Ok(lines);
    }
    for dep in pkg.transitive_deps() {
        // The probe scaffold is dropped at the `PkgInfo` decode boundary, so
        // every `TransitiveDep` reaching here is a real registry package.
        if dep.version.is_empty() {
            return Err(missing_version(dep.name.as_str()));
        }
        // The primary crate carries the effective feature set rustdoc
        // succeeded with. Matched on the REGISTRY package NAME, not the lib
        // ident: a crate whose lib renames its target (`async-stripe` → lib
        // `stripe`) has `dep.ident = "stripe"` but `dep.name = "async-stripe"
        // = pkg.name()`, and the `Cargo.toml` key is the package name — so
        // matching on ident would drop the feature set and ship a manifest
        // missing a mandatory runtime feature (a cargo build-script failure).
        let features: &[FeatureName] = if dep.name.as_str() == pkg.name() {
            pkg.features()
        } else {
            &[]
        };
        lines.push(render_dep_line(&dep.name, &dep.version, features));
    }
    lines.sort();
    Ok(lines)
}

/// Render one pinned `[dependencies]` line. Every value spliced here is a
/// decode-validated newtype whose charset gate excludes TOML metacharacters:
/// `name` is a [`PackageName`] (`[A-Za-z0-9_-]+`, alphabetic-first), `version`
/// a [`CrateVersion`], and each feature a [`FeatureName`]. A raw unchecked
/// string cannot reach any of the three splice positions, so no
/// `"`-and-newline payload can break out of its TOML string and inject manifest
/// content — the types, not a runtime escape, close the injection class.
fn render_dep_line(name: &PackageName, version: &CrateVersion, features: &[FeatureName]) -> String {
    let name = name.as_str();
    let version = version.as_str();
    if features.is_empty() {
        format!("{name} = \"={version}\"")
    } else {
        let quoted: Vec<String> = features
            .iter()
            .map(|f| format!("\"{}\"", f.as_str()))
            .collect();
        format!(
            "{name} = {{ version = \"={version}\", features = [{}] }}",
            quoted.join(", ")
        )
    }
}

/// Render a `path` `[dependencies]` line for an author-supplied wrapper crate.
///
/// `path` is a [`crate::pkginfo::WrapperCratePath`], decode-gated to
/// `[A-Za-z0-9._/-]` (plus space) so it carries no `"`-and-newline payload that
/// could close its TOML string and inject manifest content; `name` and each
/// feature are the same decode-validated newtypes `render_dep_line` splices, so
/// no raw string reaches a TOML position.
fn render_path_dep_line(name: &PackageName, path: &str, features: &[FeatureName]) -> String {
    let name = name.as_str();
    if features.is_empty() {
        format!("{name} = {{ path = \"{path}\" }}")
    } else {
        let quoted: Vec<String> = features
            .iter()
            .map(|f| format!("\"{}\"", f.as_str()))
            .collect();
        format!(
            "{name} = {{ path = \"{path}\", features = [{}] }}",
            quoted.join(", ")
        )
    }
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

    /// The cache root is exactly the project root joined with
    /// [`FFI_CACHE_COMPONENTS`], which begins with the cache namespace — so
    /// every consumer deriving from those components names the same directory
    /// the driver writes and deletes.
    #[test]
    fn ffi_cache_root_is_the_components_path() {
        let project = Path::new("/project");
        let expected: PathBuf = std::iter::once(project.as_os_str())
            .chain(FFI_CACHE_COMPONENTS.iter().map(std::ffi::OsStr::new))
            .collect();
        assert_eq!(FfiCache::at_project_root(project).root(), expected);
        assert_eq!(expected, Path::new("/project/.ipe/cache/ffi/rust"));
        assert_eq!(FFI_CACHE_COMPONENTS.first(), Some(&CACHE_NAMESPACE_DIR));
    }

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

    #[test]
    fn cache_round_trip_writes_and_removes_the_four_artifacts() {
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-cache-test-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-refuse-test-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-warm-test-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-legacy-test-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-torn-enum-{}", std::process::id()));
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
        let tmp =
            std::env::temp_dir().join(format!("ipe-ffi-define-legacy-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-torn-define-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-plant-test-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-diverge-test-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-badpkg-test-{}", std::process::id()));
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
        let lines = cargo_dep_lines(&semver_pkg()).expect("renders");
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
        assert!(cargo_dep_lines(&pkg).is_err());
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
            cargo_dep_lines(&pkg).expect("renders"),
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
            cargo_dep_lines(&pkg).expect("renders"),
            vec!["handle-demo = \"=0.1.0\""]
        );
    }

    #[test]
    fn an_injection_bearing_version_never_reaches_a_manifest_line() {
        // An inspection whose resolved version carries a TOML-string-breakout
        // payload must be REFUSED at decode — the version can never reach
        // `render_dep_line`, so no emitted `Cargo.toml` line can carry the
        // injection. (The type-level guarantee: `render_dep_line` takes a
        // `&CrateVersion`, and the only constructor is the decode-boundary
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
        // reach `render_dep_line`, so no emitted `Cargo.toml` line can carry
        // the injection. (`render_dep_line` takes `&[FeatureName]`, whose only
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
        let lines = cargo_dep_lines(&pkg).expect("renders");
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
        let lines = cargo_dep_lines(&pkg).expect("renders a manifest line");
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
        assert_eq!(got.system_lib, "wayland-client");
        assert_eq!(got.crate_name, "wayland-sys");
    }

    #[test]
    fn detect_missing_system_lib_parses_pkg_config_form() {
        // The secondary form from pkg-config itself.
        let errors = vec![
            "Package 'wayland-client' was not found in the pkg-config search path.".to_owned(),
        ];
        let got = detect_missing_system_lib(&errors).expect("must detect");
        assert_eq!(got.system_lib, "wayland-client");
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
        let hint = install_hint_for("wayland-client");
        assert!(hint.contains("wayland"), "{hint}");
        assert!(hint.contains("apt"), "{hint}");
    }

    #[test]
    fn install_hint_for_returns_generic_fallback_for_unknown_lib() {
        let hint = install_hint_for("some-obscure-lib-xyz");
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
    fn strip_foreign_str_drops_control_chars_except_tab() {
        // NUL (\x00), BEL (\x07), and US (\x1f) are stripped; tab and printable
        // chars pass through unchanged.
        let s = "a\x00b\x07c\td\x1fe";
        assert_eq!(strip_foreign_str(s), "abc\tde");
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
        let tmp = std::env::temp_dir().join(format!("ipe-ffi-syslib-test-{}", std::process::id()));
        let cache = FfiCache::at_project_root(&tmp);
        let err = install_from_inspection(&cache, &json).expect_err("must fail");
        match err {
            crate::diag::Diagnostic::SystemLibraryNotFound {
                system_lib,
                crate_name,
                ..
            } => {
                assert_eq!(system_lib, "wayland-client");
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
        assert_eq!(got.system_lib, "wayland");
        assert_eq!(got.crate_name, "wlsys");
        assert!(!got.system_lib.contains('\u{1b}'));
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
        let root =
            std::env::temp_dir().join(format!("ipe-ffi-legacy-{test_name}-{}", std::process::id()));
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
}
