//! Multi-module project manifest parsing, module discovery, import graph, and topological sort.
//!
//! `package.ipe` is the sole project manifest the toolchain discovers and
//! builds. A legacy `ipe.toml` is not accepted as a project manifest;
//! [`has_only_legacy_toml`] detects that case so callers can surface
//! [`text::legacy_toml_hint`] instead of a silent fallback.
//!
//! # Discovery
//!
//! Given a project directory (containing `package.ipe`), the driver:
//!
//! 1. Reads `package.ipe` to obtain the project name and confirm the source root
//!    exists (`src/` by default).
//! 2. Walks `src/` recursively, collecting every `*.ipe` file.
//! 3. Maps each file path to a module name by:
//!    - Stripping the `src/` prefix and `.ipe` suffix.
//!    - Splitting on the OS path separator to obtain segment strings.
//!    - Rejecting any segment that is not a valid Ipê module segment
//!      (`[A-Z][A-Za-z0-9_]*`).
//! 4. The entry module is always `Main` (`src/Main.ipe`).
//!
//! # Topological sort
//!
//! A three-colour DFS (White / Gray / Black) produces a stable dep-first
//! ordering of all discovered modules. A Gray → Gray back-edge is an import
//! cycle ([`CycleError`]).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use crate::CliError;
use crate::text;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The parsed, validated content of a `package.ipe` manifest.
#[derive(Clone, Debug)]
pub struct ProjectManifest {
    /// The project name (from the manifest's `name` field).
    pub name: String,
    /// The package version (from the manifest's `version` field), parsed into a
    /// typed [`semver::Version`]. `None` when the manifest declares no version — the
    /// package gate's enforced-semver check needs one, so `ipe package audit`
    /// rejects a versionless manifest rather than inventing a version.
    pub version: Option<semver::Version>,
    /// Absolute path to the project root directory (where `package.ipe` lives).
    pub root: PathBuf,
    /// Absolute path to the source root (`<root>/src` by default).
    pub src_root: PathBuf,
    /// The optional source icon (the manifest's `icon` field), an absolute path
    /// resolved and contained against the project root at parse time. The
    /// desktop packager derives the per-OS icon formats from this single source;
    /// `None` when the manifest declares no icon (the packager then omits the
    /// bundle icon rather than inventing one).
    pub icon: Option<PathBuf>,
    /// The SQL driver the emitted project targets (from `build.database`).
    /// Defaults to [`ipe_backend_rust::DbDriver::Sqlite`] when absent — the
    /// documented default in `AGENTS.md`'s `package.ipe` schema table.
    pub driver: ipe_backend_rust::DbDriver,
    /// The `[rust]` static-build request layer (`static` / `target` /
    /// `allocator` / `cFree`) — the lowest-precedence layer
    /// (CLI > env > `package.ipe`) of `crate::build_plan::resolve`'s input.
    /// Every field defaults to unset when the section (or key) is absent.
    /// Malformed values (a bad bool, an unknown allocator) are refused at
    /// parse time, never silently ignored.
    pub static_request: crate::build_plan::StaticRequestLayer,
    /// The `[wasm]` section (M5: `mode`/`entry`/`mount`/`publicEnv`/
    /// `optLevel`) — `WasmConfig::default()` (mode "off") when the section is
    /// absent.
    pub wasm: WasmConfig,
    /// The `[dependencies]` section: Ipê packages by name. Empty when the
    /// section is absent (back-compat). Resolution (fetch / download / lockfile)
    /// is SP3; this is the parsed schema only.
    pub dependencies: BTreeMap<String, IpeDep>,
    /// The `[rust.dependencies]` section: crates.io crates bound as
    /// foreign-function dependencies. Empty when the section is absent.
    pub rust_dependencies: BTreeMap<String, RustDep>,
    /// The `[capabilities] declared = […]` set: the security capabilities the
    /// author declares the program exercises. Empty when the section is absent.
    /// Verifying this against the compiler's inferred set is SP4.
    pub capabilities: BTreeSet<Capability>,
    /// The `[capabilities] accept = […]` set: durable, reviewable pre-acceptance
    /// of a disclosed risk. Distinct from `declared` (a package's *own* effects):
    /// `accept` records that the author has taken responsibility for a hazard the
    /// build would otherwise ask about. Only `unsafe` is meaningful today — its
    /// presence pre-accepts the `.Unsafe`-import acknowledgment so a repeatedly
    /// built project never re-prompts and CI needs no flag. Empty when absent.
    pub capabilities_accept: BTreeSet<Capability>,
    /// The `[capabilities] acceptsControl = […]` set: the elevated control models
    /// (see [`crate::delivery::ControlModel`]) the consumer has reviewed and
    /// accepted. The managed models (`tea`/`server`) run under the runtime's loop
    /// and need no accept; only the self-driving `direct` model must appear here,
    /// or the control-model consent gate refuses the build fail-closed. Empty when
    /// the section is absent — the strict default that admits only managed models.
    pub control_models_accept: BTreeSet<crate::delivery::ControlModel>,
    /// Whether the manifest contains a `[rust.wrapper]` section. The audit gate
    /// reads this to detect author-asserted wrapper bindings that it cannot
    /// regenerate from an independent pinned source (there is no registry pin,
    /// rev, or hash for a local wrapper path — only the author's local source).
    pub has_rust_wrapper: bool,
    /// The `programs` list: named build targets, each with its entry module file
    /// and an optional declared shape. Empty when the manifest declares no
    /// `programs` field — the entry then defaults to `Main` and the shape
    /// is entirely compiler-inferred (`resolved_entry` returns `["Main"]`).
    ///
    /// A declared shape is VALIDATED against the compiler's inferred shape, never
    /// used to override it (see `misc/docs/package-programs-design.md`).
    pub programs: Vec<Program>,
    /// The `exposedModules` list: a library package's public surface — the
    /// modules a downstream consumer may import. Empty for an application
    /// package (one that declares no `exposedModules` field).
    pub exposed_modules: Vec<String>,
    /// The `delivery` section: per-host build configuration.
    ///
    /// All three sub-sections are always present; the active one is chosen at
    /// build time from the resolved shape+runtime+host. Defaults to
    /// [`DeliveryConfig::default()`] when the manifest omits the field.
    pub delivery: DeliveryConfig,
}

/// Per-host delivery configuration, parsed from the `delivery = { … }` field.
///
/// All three sections are present and live: every project's manifest carries
/// defaults for all hosts, and `ipe build` reads only the one matching the
/// resolved target. There is no `active` selector — that is the CLI.
#[derive(Clone, Debug, Default)]
pub struct DeliveryConfig {
    /// The declared delivery set — which deliveries `ipe release` produces.
    /// Empty when the manifest omits the `ships` field, meaning the implicit
    /// `[ binary ]` singleton (resolved by
    /// [`crate::delivery_set::DeliverySet::resolve`]). The `ships` list declares
    /// *what* ships; the sections below configure *how* each looks.
    pub ships: Vec<crate::delivery_set::ShipEntry>,
    /// Window title, width, and height for the `web desktop`
    /// (webview-native) host.
    pub desktop: DesktopDelivery,
    /// Bundle identifier and orientation for `web solo ios` / `web solo android`.
    pub mobile: MobileDelivery,
    /// Base path for the `web solo` browser host.
    pub browser: BrowserDelivery,
}

/// `delivery.desktop` — webview-native window settings.
#[derive(Clone, Debug)]
pub struct DesktopDelivery {
    /// The native window title shown in the OS title bar.
    pub title: String,
    /// Initial inner width in logical pixels.
    pub width: u32,
    /// Initial inner height in logical pixels.
    pub height: u32,
}

impl Default for DesktopDelivery {
    fn default() -> Self {
        Self {
            title: String::new(),
            width: 1024,
            height: 768,
        }
    }
}

/// `delivery.mobile` — mobile-host shell settings.
#[derive(Clone, Debug, Default)]
pub struct MobileDelivery {
    /// Reverse-DNS application identifier (`com.example.myapp`).
    pub bundle_id: String,
    /// Locked launch orientation.
    pub orientation: ScreenOrientation,
}

/// The allowed screen orientations for a mobile host launch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScreenOrientation {
    /// Portrait-only; the shell refuses landscape rotation.
    #[default]
    Portrait,
    /// Landscape-only; the shell refuses portrait rotation.
    Landscape,
    /// Unrestricted: the shell follows the device sensor.
    Any,
}

/// `delivery.browser` — browser-SPA host settings.
#[derive(Clone, Debug)]
pub struct BrowserDelivery {
    /// The URL base path the SPA is served from (`"/"` for root).
    pub base_path: String,
}

impl Default for BrowserDelivery {
    fn default() -> Self {
        Self {
            base_path: "/".to_owned(),
        }
    }
}

impl ProjectManifest {
    /// The entry module path the build should compile, derived from `programs`.
    ///
    /// A manifest with no `programs` (or one whose sole/default program does not
    /// override the entry) uses `["Main"]`. A single-program manifest routes that
    /// program's declared entry-file through to a module path. A multi-program
    /// manifest builds its first program's entry; named selection of the others is
    /// not yet wired, so [`Self::multi_program_notice`] surfaces which one was
    /// chosen and how many were declared.
    ///
    /// # Errors
    /// [`CliError::UsageOwned`] when a program's entry file does not map to a
    /// valid module path (a non-module path segment).
    pub fn resolved_entry(&self) -> Result<Vec<String>, CliError> {
        let Some(program) = self.default_program() else {
            return Ok(vec!["Main".to_owned()]);
        };
        entry_file_to_module_path(&program.entry)
    }

    /// The default program: the sole program of a single-program manifest, or the
    /// first of a multi-program one. `None` when `programs` is empty.
    #[must_use]
    pub fn default_program(&self) -> Option<&Program> {
        self.programs.first()
    }

    /// A one-line notice naming which program a multi-program build compiled and
    /// how many were declared, so the silently-unreachable programs 2..N are not
    /// an unsurfaced surprise.
    ///
    /// `None` for a zero- or one-program manifest (nothing to disambiguate); a
    /// framed sentence otherwise, naming the built program and its position in the
    /// declared list. The caller prints it once at build start.
    #[must_use]
    pub fn multi_program_notice(&self) -> Option<String> {
        let total = self.programs.len();
        if total <= 1 {
            return None;
        }
        let built = self.default_program()?;
        Some(format!(
            "building program `{}` (1 of {total} — named selection of the other \
             {} is not yet supported)",
            built.name,
            total - 1,
        ))
    }
}

/// One `programs` entry: a named build target with its entry module file and an
/// optional declared shape.
///
/// Modelled so an invalid combination is unrepresentable at the type level: the
/// `shape` is a closed [`EntryShape`] enum (never a free string), and the entry
/// is always present (defaulting to `Main.ipe` at read time when the record
/// omits it), so a program can never name a shape outside the vocabulary nor lack
/// an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// The program's target name (the program record's `name` field).
    pub name: String,
    /// The entry module's source file, relative to the source root
    /// (the program record's `entry` field; defaults to `Main.ipe`).
    pub entry: String,
    /// The declared shape, when the author asserts one (the program record's
    /// `shape` field). `None` means "trust the compiler's inference". A declared
    /// shape is validated against inference, never used to override it.
    pub shape: Option<EntryShape>,
}

/// The closed set of program shapes an author may declare in a `package.ipe`
/// program record's `shape` field.
///
/// The four-shape model: a `Web` server, a `WebView` desktop app, a `Terminal`
/// app, or a plain `Program`.
///
/// Declared syntactically as a closed-union constructor (`Web` / `WebView` /
/// `Terminal` / `Program`), so a typo is not a writable manifest at all rather
/// than a runtime rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryShape {
    /// A `Web` server app (`Web.tea` / `Web.appRouted` / `Web.appWith`).
    Web,
    /// A `WebView` desktop app.
    WebView,
    /// A `Terminal` app (`Tui.tea` / `Console.app`).
    Terminal,
    /// A plain `Program` (a non-shape `main`).
    Program,
}

impl EntryShape {
    /// The stable lowercase wire spelling of this shape (used to compare a
    /// declared shape against the compiler's inferred shape).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::WebView => "webView",
            Self::Terminal => "terminal",
            Self::Program => "program",
        }
    }
}

/// Map an entry-file string (relative to the source root, e.g. `Main.ipe` or
/// `Client/App.ipe`) to its module path (`["Main"]`, `["Client", "App"]`).
///
/// The `.ipe` extension is stripped; each remaining path segment must be a valid
/// Ipê module segment (`[A-Z][A-Za-z0-9_]*`). A path with a non-module segment or
/// no segments at all is a manifest error, never a silently-dropped entry.
///
/// # Errors
/// [`CliError::UsageOwned`] naming the offending entry file.
fn entry_file_to_module_path(entry: &str) -> Result<Vec<String>, CliError> {
    let rel = Path::new(entry);
    let without_ext = rel.with_extension("");
    let mut segments: Vec<String> = Vec::new();
    for component in without_ext.components() {
        let seg = match component {
            std::path::Component::Normal(s) => s.to_str(),
            _ => None,
        };
        let seg = seg.ok_or_else(|| {
            CliError::UsageOwned(text::manifest_entry_invalid(&format!("{entry:?}")))
        })?;
        if !is_module_segment(seg) {
            return Err(CliError::UsageOwned(text::manifest_entry_segment_invalid(
                &format!("{entry:?}"),
                &format!("{seg:?}"),
            )));
        }
        segments.push(seg.to_owned());
    }
    if segments.is_empty() {
        return Err(CliError::UsageOwned(text::manifest_entry_no_module(
            &format!("{entry:?}"),
        )));
    }
    Ok(segments)
}

/// `[wasm]` section of a `package.ipe` manifest (spec: `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md` Q6
/// "Opt-in mechanism").
///
/// ```toml
/// [wasm]
/// mode      = "solo"             # solo (MVP) | hydrate (MVP+1) | off (default)
/// entry     = "src/Client.ipe"   # client entry; its reachability closure is the bundle
/// mount     = "#app"             # SPA mount node
/// publicEnv = ["API_BASE_URL"]   # default-deny allowlist; rejects IPE_* / secret patterns
/// optLevel  = "z"
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WasmConfig {
    /// `"solo"` / `"hydrate"` / `"off"` (default when the key or section is
    /// absent — `--target wasm` still works without a `[wasm]` section; this
    /// field is metadata for the eventual SSR+hydration/SPA-shell split, not
    /// a gate on `ipe build --target wasm` itself).
    pub mode: Option<String>,
    /// The client entry module's file, relative to the project root
    /// (defaults to the build's own entry file when absent — see M6).
    pub entry: Option<String>,
    /// The SPA mount selector (e.g. `"#app"`).
    pub mount: Option<String>,
    /// The `Ipe.Env.public` default-deny allowlist: environment variable
    /// names the wasm bundle may read at build time. Validated against the
    /// secret-name denylist at PARSE time (below) — listing a denylisted
    /// name here is a build error, never a runtime refusal.
    pub public_env: Vec<String>,
    /// `wasm-opt` optimisation level (`"z"`/`"s"`/`"0"`..`"3"`).
    pub opt_level: Option<String>,
}

impl WasmConfig {
    /// Whether this config's `mode` implies the `WasmClient` compilation
    /// target.
    ///
    /// `true` for any active mode (`"solo"`, `"hydrate"`, or any future on-value).
    /// `false` for the explicit opt-out (`"off"`) and for the absent default
    /// (no `[wasm]` section / no `mode` key — both leave `mode` as `None`).
    #[must_use]
    pub fn implies_wasm_target(&self) -> bool {
        match self.mode.as_deref() {
            None | Some("off") => false,
            Some(_) => true,
        }
    }
}

/// The `[wasm].publicEnv` secret-name denylist (spec Q5 "Config: default-deny
/// allowlist (+ layered secret denylist)").
///
/// Denies `DATABASE_URL`, the internal `IPE_*` namespace, and any name whose
/// underscore-delimited components — or whose bare (single-component) name —
/// carry a secret word: `SECRET`, `TOKEN`, `KEY`, `PASSWORD`, `PASSWD`,
/// `CREDENTIAL`, `AUTH`, or `APIKEY`. An allowlisted name matching this is a
/// BUILD error (parse time), forcing the author to confirm — never a silent
/// drop, never a runtime-only refusal.
///
/// The gate matches on word boundaries (each `_`-delimited component), not raw
/// substring: `SECRET`, `APIKEY`, and `STRIPE_SECRET_KEY` all reject, while a
/// name that merely embeds a secret word inside a larger word — `AUTHOR`,
/// `KEYBOARD`, `TOKENIZER` — stays allowed. This fails closed on the secret
/// word regardless of separator (bare `SECRET` and `_SECRET` alike) while not
/// over-blocking a legitimate public name.
///
/// Case-insensitive (manifest authors may write either case; the runtime
/// env-var namespace itself is case-sensitive POSIX convention, but a
/// same-name-different-case entry is exactly the kind of "did they mean the
/// secret" ambiguity this gate exists to catch).
#[must_use]
pub fn is_denylisted_public_env_name(name: &str) -> bool {
    /// The secret words whose presence as a whole `_`-delimited component (or
    /// as the bare name) marks a name as secret-bearing.
    const SECRET_WORDS: [&str; 8] = [
        "SECRET",
        "TOKEN",
        "KEY",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "AUTH",
        "APIKEY",
    ];
    let upper = name.to_ascii_uppercase();
    upper == "DATABASE_URL"
        || upper.starts_with("IPE_")
        || upper
            .split('_')
            .any(|component| SECRET_WORDS.contains(&component))
}

/// A discovered Ipê source file with its resolved module path.
///
/// Built only through [`DiscoveredModule::user`] or the crate-internal stdlib
/// constructor, so the [`EntryProvenance`] cannot be set outside this crate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredModule {
    /// Absolute path to the `.ipe` source file.
    pub path: PathBuf,
    /// Module path segments, e.g. `Lib/Utils.ipe` → `["Lib", "Utils"]`.
    pub module_path: Vec<String>,
    /// Where the module's source comes from, fixed when it enters the graph.
    provenance: EntryProvenance,
}

impl DiscoveredModule {
    /// A user-authored module; its [`EntryRole`] derives from `module_path`.
    #[must_use]
    pub fn user(path: PathBuf, module_path: Vec<String>) -> Self {
        let role = EntryRole::of_module_path(&module_path);
        Self {
            path,
            module_path,
            provenance: EntryProvenance::User(role),
        }
    }

    /// A compiled-source stdlib module: inserted by the injection closure, or
    /// extracted for the API surface of an embedded stdlib module.
    pub(crate) const fn embedded_stdlib(path: PathBuf, module_path: Vec<String>) -> Self {
        Self {
            path,
            module_path,
            provenance: EntryProvenance::EmbeddedStdlib,
        }
    }

    /// Where the module's source comes from.
    #[must_use]
    pub const fn provenance(&self) -> EntryProvenance {
        self.provenance
    }
}

/// The provenance of a [`DiscoveredModule`] in the source graph.
///
/// Only ranks which capability-inference refusal is surfaced; it never gates
/// trust — the trust tag the resolver checks is [`ipe_canon::ModuleOrigin`].
/// Only a user module carries an [`EntryRole`]: an injected stdlib module is
/// never a package's `Main`, so that combination has no representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryProvenance {
    /// A module the package author wrote, discovered under the source root.
    User(EntryRole),
    /// A compiled-source stdlib module injected from `ipe`'s embed table.
    ///
    /// Only [`inject_compiled_std_closure`] mints this provenance, and only for
    /// a module it actually inserted, so a user file squatting on a stdlib path
    /// stays [`EntryProvenance::User`].
    EmbeddedStdlib,
}

/// The role a user module plays when lowered as its own entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EntryRole {
    /// A module whose last path segment is `Main` — the program entry.
    Main,
    /// Any other user module.
    Library,
}

impl EntryRole {
    /// The role implied by a module path.
    #[must_use]
    pub fn of_module_path(module_path: &[String]) -> Self {
        if module_path.last().is_some_and(|last| last == "Main") {
            Self::Main
        } else {
            Self::Library
        }
    }
}

/// An import edge: the importing module's path and the imported module's path.
#[derive(Clone, Debug)]
pub struct ImportEdge {
    pub from: Vec<String>,
    pub to: Vec<String>,
}

/// An import cycle detected during topological sort. The single definition
/// lives in [`ipe_db`] (beside the shared topo algorithm); re-exported here
/// for the driver and existing callers.
pub use ipe_db::CycleError;

/// The capability vocabulary, re-exported from the kernel registry so the
/// manifest's `[capabilities]` set and the compiler's inferred set are the same
/// type.
pub use ipe_ir::Capability;

/// One `package.ipe` dependency entry: an Ipê package pulled from the index by
/// version, or one of the two escapes (a git repo, a local path).
///
/// Modelled as a sum, not three optional fields, so an entry can never be both a
/// git and a path dependency at once (make-invalid-states-unrepresentable). The
/// index case carries a parsed [`semver::VersionReq`], so a malformed version is
/// a manifest-parse error, never a resolution-time surprise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpeDep {
    /// Resolved from the package index by a semver requirement (`http = "^1.2"`).
    Index(semver::VersionReq),
    /// A git repository escape (`{ git = "…", rev = "…" }`); `rev` is optional.
    Git {
        /// The repository URL.
        url: String,
        /// A pinned revision (commit / tag / branch), when given.
        rev: Option<String>,
    },
    /// A local path escape (`{ path = "../local" }`), relative to the manifest.
    Path(PathBuf),
}

/// One `package.ipe` Rust-dependency entry: a crates.io crate bound as a
/// foreign-function dependency, with its version requirement and feature list.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RustDep {
    /// The version requirement string (empty when unspecified). Left as the raw
    /// string the crate ecosystem's own resolver consumes, not a parsed
    /// [`semver::VersionReq`] — it is handed verbatim to cargo.
    pub version: String,
    /// The requested crate features (empty when unspecified).
    pub features: Vec<String>,
}

/// Whether a manifest section-header line names the `[rust.wrapper]` table.
///
/// Both the bare and the quoted spellings are accepted. This is the single
/// source of truth for the accepted header spellings — used by every reader
/// that needs to detect the wrapper table, so the two cannot drift apart.
pub(crate) fn is_rust_wrapper_header(line: &str) -> bool {
    line == "[rust.wrapper]" || line == "[\"rust.wrapper\"]"
}

/// The filename of the legacy TOML manifest (`ipe.toml`).
pub const IPE_TOML: &str = "ipe.toml";

/// Locate a project's `package.ipe` manifest inside `dir`.
///
/// `package.ipe` is the sole project manifest the toolchain discovers. A bare
/// `ipe.toml` is not a manifest — [`has_only_legacy_toml`] detects that case so a
/// caller can surface [`text::legacy_toml_hint`] instead of a silent fallback.
///
/// Returns the `package.ipe` path when the directory carries one, else `None`.
#[must_use]
pub fn manifest_in_dir(dir: &Path) -> Option<PathBuf> {
    let package_ipe = dir.join(crate::package_manifest::PACKAGE_IPE);
    if package_ipe.is_file() {
        return Some(package_ipe);
    }
    None
}

/// Whether `dir` carries a legacy `ipe.toml` but no `package.ipe`.
///
/// The case where a caller should report [`text::legacy_toml_hint`] rather than
/// treat the directory as manifest-free.
#[must_use]
pub fn has_only_legacy_toml(dir: &Path) -> bool {
    !dir.join(crate::package_manifest::PACKAGE_IPE).is_file() && dir.join(IPE_TOML).is_file()
}

/// Parse a project `package.ipe` manifest into a [`ProjectManifest`].
///
/// `package.ipe` is read syntactically (never evaluated) by the Ipê-native
/// reader. A path to a legacy `ipe.toml` is rejected with [`text::legacy_toml_hint`].
///
/// # Errors
/// [`CliError::Io`] if the file cannot be read; [`CliError::Usage`] /
/// [`CliError::UsageOwned`] for a malformed or invalid manifest (an unsupported
/// driver, a bad version or dependency, an unknown capability, a denylisted
/// `publicEnv` name, a missing source root); [`CliError::Pipeline`] when the
/// source does not parse; and [`CliError::UsageOwned`] when the path is not a
/// `package.ipe`.
pub fn parse_manifest(manifest_path: &Path) -> Result<ProjectManifest, CliError> {
    if manifest_path.file_name().and_then(|n| n.to_str())
        == Some(crate::package_manifest::PACKAGE_IPE)
    {
        return crate::package_manifest::parse_package_manifest(manifest_path);
    }
    Err(CliError::UsageOwned(text::manifest_not_package_ipe(
        &manifest_path.display(),
        &text::legacy_toml_hint(),
    )))
}

// ---------------------------------------------------------------------------
// Module discovery
// ---------------------------------------------------------------------------

/// The maximum directory depth the module-discovery walk will descend before
/// returning a typed [`CliError::DiscoveryLimitReached`] error. A legitimate
/// Ipê source tree is never this deep; an adversarial or accidentally unbounded
/// tree is refused rather than spinning indefinitely.
const MAX_DISCOVERY_DEPTH: usize = 64;

/// Walk `src_root` recursively, collecting every `*.ipe` file as a
/// [`DiscoveredModule`].
///
/// Files whose path contains a non-module-segment (e.g. lowercase first char
/// or characters outside `[A-Za-z0-9_]`) are silently skipped — they may be
/// build artefacts or editor swap files.
///
/// The walk carries a canonicalised visited-set to detect symlink cycles and a
/// depth ceiling to bound pathologically deep trees. Both conditions produce a
/// typed [`CliError::DiscoveryLimitReached`] rather than an infinite loop or
/// stack overflow.
///
/// # Errors
/// [`CliError::Io`] if the directory cannot be read.
/// [`CliError::DiscoveryLimitReached`] on a symlink cycle or a tree deeper
/// than [`MAX_DISCOVERY_DEPTH`].
pub fn discover_modules(src_root: &Path) -> Result<Vec<DiscoveredModule>, CliError> {
    use std::collections::HashSet;

    let mut result: Vec<DiscoveredModule> = Vec::new();
    // Stack entries carry the directory path and its depth from src_root.
    let mut stack: VecDeque<(PathBuf, usize)> = VecDeque::new();
    // Visited set of canonicalised paths breaks symlink cycles.
    let mut visited: HashSet<PathBuf> = HashSet::new();

    stack.push_back((src_root.to_path_buf(), 0));

    while let Some((dir, depth)) = stack.pop_front() {
        if depth > MAX_DISCOVERY_DEPTH {
            return Err(CliError::DiscoveryLimitReached {
                detail: format!(
                    "directory tree exceeded the {MAX_DISCOVERY_DEPTH}-level depth ceiling \
                     at `{}`",
                    dir.display()
                ),
            });
        }

        // Canonicalise to detect symlink cycles: two different dir-paths that
        // resolve to the same inode are a cycle and the second visit is skipped.
        let canon = fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        if !visited.insert(canon.clone()) {
            // Already visited this real directory — symlink cycle detected.
            return Err(CliError::DiscoveryLimitReached {
                detail: format!(
                    "symlink cycle detected: `{}` resolves to an already-visited \
                     directory `{}`",
                    dir.display(),
                    canon.display()
                ),
            });
        }

        let entries = fs::read_dir(&dir).map_err(|e| CliError::Io {
            path: dir.clone(),
            source: e,
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| CliError::Io {
                path: dir.clone(),
                source: e,
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| CliError::Io {
                path: path.clone(),
                source: e,
            })?;
            if file_type.is_dir() {
                stack.push_back((path, depth + 1));
            } else if file_type.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("ipe")
                && let Some(m) = file_to_module(src_root, &path)
            {
                result.push(m);
            }
        }
    }

    result.sort();
    Ok(result)
}

/// Map a `.ipe` file path to a [`DiscoveredModule`], or `None` when the path
/// contains a non-module segment.
fn file_to_module(src_root: &Path, path: &Path) -> Option<DiscoveredModule> {
    // Strip the src_root prefix and the .ipe extension.
    let rel = path.strip_prefix(src_root).ok()?;
    let without_ext = rel.with_extension("");
    // Split into segments using the OS path separator.
    let mut segments: Vec<String> = Vec::new();
    for component in without_ext.components() {
        let s = component.as_os_str().to_str()?;
        if !is_module_segment(s) {
            return None;
        }
        segments.push(s.to_owned());
    }
    if segments.is_empty() {
        return None;
    }
    Some(DiscoveredModule::user(path.to_path_buf(), segments))
}

/// A Ipê module path segment must start with an ASCII uppercase letter and
/// contain only ASCII alphanumerics and `_`.
pub(crate) fn is_module_segment(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Import graph + topological sort
// ---------------------------------------------------------------------------

/// Build a dependency-first topological order of `modules`, given a function
/// `imports_of(module_path) -> Vec<Vec<String>>` that returns the modules each
/// source module imports.
///
/// Only modules whose path appears in the module set are followed; stdlib /
/// kernel imports (e.g. `List`, `String`) are silently ignored.
///
/// Returns the modules in dep-first order (i.e. a module's deps come before
/// it in the returned slice). The entry module (`["Main"]`) is always last.
///
/// Delegates to [`ipe_db::topological_order_paths`] — the single topo-sort
/// algorithm, shared with the memoized `ipe_db::topo_order` query so the
/// two orders can never drift.
///
/// # Errors
/// Returns [`CycleError`] when an import cycle is detected.
pub fn topological_order<F>(
    modules: &[DiscoveredModule],
    entry_path: &[String],
    imports_of: F,
) -> Result<Vec<DiscoveredModule>, CycleError>
where
    F: Fn(&[String]) -> Vec<Vec<String>>,
{
    let paths: Vec<Vec<String>> = modules.iter().map(|m| m.module_path.clone()).collect();
    let order = ipe_db::topological_order_paths(&paths, entry_path, imports_of)?;

    // Map each ordered path back to its DiscoveredModule (last claimant wins
    // on a duplicate module path, matching the pre-delegation collect()).
    let mut module_map: BTreeMap<&[String], &DiscoveredModule> = BTreeMap::new();
    for m in modules {
        module_map.insert(m.module_path.as_slice(), m);
    }
    Ok(order
        .iter()
        .filter_map(|p| module_map.get(p.as_slice()).map(|&m| m.clone()))
        .collect())
}

// ---------------------------------------------------------------------------
// Compiled-source stdlib injection
// ---------------------------------------------------------------------------

/// Transitively inject every compiled-source stdlib module the graph imports.
///
/// For each compiled-source module (`Ipe.Palette`, later `Ipe.Css` /
/// `Ipe.Error`) reachable from the current `sources`, seed a synthetic
/// source entry + [`DiscoveredModule`] so the EXISTING topo → dep-first
/// canonicalise → link path handles it unchanged.
///
/// Returns the set of module paths that were **actually injected from the embed
/// table** — the driver's unforgeable record of which modules are trusted
/// `EmbeddedStdlib` source. A path is added to this set ONLY when a NEW synthetic
/// entry is inserted; if `sources` already holds the key (a user file squatting
/// on `Ipe.Palette`, or an earlier injection), injection is skipped and the path
/// is NOT tagged trusted. So a hostile `src/Std/Palette.ipe` is canonicalised as
/// `ipe_canon::ModuleOrigin::User` and stays IPE-N0025-rejected.
///
/// Efficiency (design §7): the worklist is seeded only from imports that match a
/// compiled-source module, so a build that imports none does zero work.
pub fn inject_compiled_std_closure(
    sources: &mut BTreeMap<Vec<String>, (PathBuf, String)>,
    discovered: &mut Vec<DiscoveredModule>,
) -> BTreeSet<Vec<String>> {
    // One shared closure + squat-guard lives in `ipe_stdlib` (the SSOT both the
    // native and wasm frontends call); the native driver additionally records a
    // `DiscoveredModule` per injected node via the callback.
    ipe_stdlib::inject_compiled_std_closure(
        sources,
        extract_imports_from_source,
        |module_path, synth_path| {
            discovered.push(DiscoveredModule::embedded_stdlib(
                synth_path.to_path_buf(),
                module_path.to_vec(),
            ));
        },
    )
}

// ---------------------------------------------------------------------------
// Import extraction from source text (pre-parse)
// ---------------------------------------------------------------------------

/// Extract the module paths named by `import` declarations from raw Ipê source
/// text, without a full parse.
///
/// This is a token-level scan (real lexer — its edge set is a
/// superset-or-equal of the AST's import edges, so the IPE-N0021 cycle gate
/// cannot be bypassed by lexer-legal-but-unusual spelling such as
/// `import\tB`) used by the topo-sort driver to build the import graph
/// before any canonicalisation runs. It recognises:
///
/// ```ipe
/// import Lib.Utils
/// import Lib.Utils as U
/// import Lib.Utils exposing (..)
/// import Lib.Utils exposing (foo, Bar)
/// ```
///
/// Kernel / stdlib imports (`import String`, `import List.Extra`) whose first
/// segment is lowercase or does not correspond to a discovered local module are
/// harmlessly included in the returned set — the topo-sort driver filters them
/// against the `module_set`.
///
/// The single implementation lives in [`ipe_db`] (it also backs the memoized
/// `ipe_db::imports` query the topo sort consumes) — re-exported here so the
/// scan used for stdlib-closure injection and the scan used for topo ordering
/// can never drift apart.
pub use ipe_db::extract_imports_from_source;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_module_segment_rules() {
        assert!(is_module_segment("Main"));
        assert!(is_module_segment("Lib"));
        assert!(is_module_segment("Utils2"));
        assert!(is_module_segment("My_Module"));
        assert!(!is_module_segment("main"));
        assert!(!is_module_segment("123"));
        assert!(!is_module_segment(""));
        assert!(!is_module_segment("_Foo"));
    }

    #[test]
    fn extract_imports_parses_all_forms() {
        let src = "
module Main exposing (main)
import Lib.Utils
import Lib.Other as O
import Lib.Fmt exposing (..)
import Lib.Str exposing (fmt)
import String
";
        let imports = extract_imports_from_source(src);
        assert!(imports.contains(&vec!["Lib".to_owned(), "Utils".to_owned()]));
        assert!(imports.contains(&vec!["Lib".to_owned(), "Other".to_owned()]));
        assert!(imports.contains(&vec!["Lib".to_owned(), "Fmt".to_owned()]));
        assert!(imports.contains(&vec!["Lib".to_owned(), "Str".to_owned()]));
        assert!(imports.contains(&vec!["String".to_owned()]));
        assert!(!imports.contains(&vec!["main".to_owned()]));
    }

    #[test]
    fn topological_order_two_modules() {
        let modules = vec![
            DiscoveredModule::user(PathBuf::from("src/Main.ipe"), vec!["Main".to_owned()]),
            DiscoveredModule::user(
                PathBuf::from("src/Lib/Utils.ipe"),
                vec!["Lib".to_owned(), "Utils".to_owned()],
            ),
        ];
        let order = topological_order(&modules, &["Main".to_owned()], |path| {
            if path == ["Main".to_owned()] {
                vec![vec!["Lib".to_owned(), "Utils".to_owned()]]
            } else {
                vec![]
            }
        });
        assert!(order.is_ok(), "no cycle expected");
        let order = order.expect("checked above");
        // Lib.Utils must come before Main.
        let lib_pos = order
            .iter()
            .position(|m| m.module_path == vec!["Lib".to_owned(), "Utils".to_owned()]);
        let main_pos = order
            .iter()
            .position(|m| m.module_path == vec!["Main".to_owned()]);
        assert!(
            lib_pos < main_pos,
            "Lib.Utils must precede Main in topo order"
        );
    }

    #[test]
    fn inject_closure_seeds_compiled_source_module() {
        // A Main importing Ipe.Palette gets the embedded source injected + a
        // DiscoveredModule pushed, and the path is recorded as trusted.
        let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
        sources.insert(
            vec!["Main".to_owned()],
            (
                PathBuf::from("src/Main.ipe"),
                "module Main exposing (main)\nimport Ipe.Palette exposing (..)\nmain = 0\n"
                    .to_owned(),
            ),
        );
        let mut discovered = vec![DiscoveredModule::user(
            PathBuf::from("src/Main.ipe"),
            vec!["Main".to_owned()],
        )];

        let injected = super::inject_compiled_std_closure(&mut sources, &mut discovered);

        let palette = vec!["Ipe".to_owned(), "Palette".to_owned()];
        assert!(injected.contains(&palette), "Ipe.Palette must be injected");
        assert!(sources.contains_key(&palette), "source seeded");
        assert!(
            discovered.iter().any(|m| m.module_path == palette),
            "DiscoveredModule pushed"
        );
    }

    #[test]
    fn inject_closure_short_circuits_when_no_compiled_import() {
        // Efficiency: a build importing no compiled-source module does zero work.
        let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
        sources.insert(
            vec!["Main".to_owned()],
            (
                PathBuf::from("src/Main.ipe"),
                "module Main exposing (main)\nmain = 0\n".to_owned(),
            ),
        );
        let mut discovered = vec![DiscoveredModule::user(
            PathBuf::from("src/Main.ipe"),
            vec!["Main".to_owned()],
        )];

        let injected = super::inject_compiled_std_closure(&mut sources, &mut discovered);
        assert!(
            injected.is_empty(),
            "no compiled-source import → nothing injected"
        );
        assert_eq!(sources.len(), 1, "sources untouched");
    }

    #[test]
    fn inject_closure_does_not_tag_user_squat_as_trusted() {
        // SECURITY: a user file already occupying the Ipe.Palette key is NOT
        // overwritten and NOT tagged trusted — it will canonicalise as User and
        // hit IPE-N0025.
        let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
        sources.insert(
            vec!["Main".to_owned()],
            (
                PathBuf::from("src/Main.ipe"),
                "module Main exposing (main)\nimport Ipe.Palette exposing (..)\nmain = 0\n"
                    .to_owned(),
            ),
        );
        let palette = vec!["Ipe".to_owned(), "Palette".to_owned()];
        sources.insert(
            palette.clone(),
            (
                PathBuf::from("src/Std/Palette.ipe"),
                "module Ipe.Palette exposing (..)\ntoHex = 0\n".to_owned(),
            ),
        );
        let mut discovered = vec![
            DiscoveredModule::user(PathBuf::from("src/Main.ipe"), vec!["Main".to_owned()]),
            DiscoveredModule::user(PathBuf::from("src/Std/Palette.ipe"), palette.clone()),
        ];

        let injected = super::inject_compiled_std_closure(&mut sources, &mut discovered);
        assert!(
            !injected.contains(&palette),
            "a user file squatting on Ipe.Palette must NOT be tagged trusted"
        );
        // The user's source is preserved (not clobbered by the embed).
        let (_, src) = sources.get(&palette).expect("user source kept");
        assert!(
            src.contains("toHex = 0"),
            "user file preserved (injection skipped it)"
        );
    }

    #[test]
    fn topological_order_detects_cycle() {
        let modules = vec![
            DiscoveredModule::user(PathBuf::from("src/A.ipe"), vec!["A".to_owned()]),
            DiscoveredModule::user(PathBuf::from("src/B.ipe"), vec!["B".to_owned()]),
        ];
        let result = topological_order(&modules, &["A".to_owned()], |path| {
            if path == ["A".to_owned()] {
                vec![vec!["B".to_owned()]]
            } else if path == ["B".to_owned()] {
                vec![vec!["A".to_owned()]]
            } else {
                vec![]
            }
        });
        assert!(result.is_err(), "A ↔ B cycle must be detected");
    }

    #[test]
    fn public_env_rejects_every_denylisted_pattern() {
        for denied in [
            "DATABASE_URL",
            "STRIPE_SECRET_KEY",
            "SESSION_TOKEN",
            "API_KEY",
            "ADMIN_PASSWORD",
            "IPE_ANYTHING",
            // Bare / no-underscore secret words: the separator-less forms the
            // old `ends_with("_…")` gate let slip through.
            "SECRET",
            "TOKEN",
            "PASSWORD",
            "PASSWD",
            "APIKEY",
            "AUTH",
            "CREDENTIAL",
        ] {
            assert!(
                is_denylisted_public_env_name(denied),
                "{denied} must match the secret-name denylist"
            );
        }
    }

    #[test]
    fn public_env_allows_ordinary_config_names() {
        for allowed in [
            "API_BASE_URL",
            "APP_VERSION",
            "FEATURE_FLAG_X",
            "PUBLIC_API_BASE_URL",
            "APP_REGION",
            // Words that merely embed a secret word as a substring stay
            // allowed — the gate matches whole `_`-delimited components.
            "AUTHOR",
            "KEYBOARD",
            "TOKENIZER",
        ] {
            assert!(
                !is_denylisted_public_env_name(allowed),
                "{allowed} must NOT match the secret-name denylist"
            );
        }
    }

    // ── WasmConfig::implies_wasm_target ──────────────────────────────────────

    #[test]
    fn implies_wasm_target_solo_and_hydrate_are_on() {
        assert!(
            WasmConfig {
                mode: Some("solo".to_owned()),
                ..Default::default()
            }
            .implies_wasm_target(),
            "mode=solo must imply wasm target"
        );
        assert!(
            WasmConfig {
                mode: Some("hydrate".to_owned()),
                ..Default::default()
            }
            .implies_wasm_target(),
            "mode=hydrate must imply wasm target"
        );
    }

    #[test]
    fn implies_wasm_target_off_and_absent_are_native() {
        assert!(
            !WasmConfig {
                mode: Some("off".to_owned()),
                ..Default::default()
            }
            .implies_wasm_target(),
            "mode=off must not imply wasm target"
        );
        assert!(
            !WasmConfig::default().implies_wasm_target(),
            "absent mode (None) must not imply wasm target"
        );
    }

    /// `is_rust_wrapper_header` is the single source of truth for accepted
    /// `[rust.wrapper]` spellings. This test pins the full acceptance corpus
    /// so any change to accepted spellings is explicit and reviewed here.
    #[test]
    fn rust_wrapper_header_spelling_corpus() {
        let accepted = ["[rust.wrapper]", "[\"rust.wrapper\"]"];
        let rejected = [
            "[rust]",
            "[rust.dependencies]",
            "[\"rust.dependencies\"]",
            "[project]",
            "",
            "rust.wrapper",
            "[RUST.WRAPPER]",
            "[rust.wrapper] ",
        ];
        for s in &accepted {
            assert!(
                is_rust_wrapper_header(s),
                "expected {s:?} to be accepted as a rust.wrapper header"
            );
        }
        for s in &rejected {
            assert!(
                !is_rust_wrapper_header(s),
                "expected {s:?} to be rejected as a rust.wrapper header"
            );
        }
    }

    /// Both readers (`scan_raw_manifest` in project.rs, `rust_wrapper_from_manifest`
    /// in ffi.rs) must agree on every spelling in the corpus. This test fails if
    /// ffi.rs's reader drifts from the shared predicate.
    #[test]
    fn rust_wrapper_header_ssot_both_readers_agree() {
        use crate::ffi::rust_wrapper_header_accepted_by_ffi_reader;

        let corpus = [
            "[rust.wrapper]",
            "[\"rust.wrapper\"]",
            "[rust.dependencies]",
            "[project]",
            "",
            "[RUST.WRAPPER]",
        ];
        for s in &corpus {
            assert_eq!(
                is_rust_wrapper_header(s),
                rust_wrapper_header_accepted_by_ffi_reader(s),
                "project.rs and ffi.rs disagree on spelling {s:?}"
            );
        }
    }

    // ── Discovery (package.ipe is the sole project manifest) ──────────────────

    /// A temp project dir seeded with a `src/Main.ipe` (so any manifest reader's
    /// source-root check passes) plus whichever manifest files the caller writes.
    fn discovery_dir(
        test_name: &str,
        package_ipe: Option<&str>,
        ipe_toml: Option<&str>,
    ) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ipe_discovery_{test_name}"));
        let _ = fs::remove_dir_all(&root);
        let src = root.join("src");
        fs::create_dir_all(&src).expect("create src/");
        fs::write(
            src.join("Main.ipe"),
            "module Main exposing (main)\nmain = 0\n",
        )
        .expect("write Main.ipe");
        if let Some(body) = package_ipe {
            fs::write(root.join("package.ipe"), body).expect("write package.ipe");
        }
        if let Some(body) = ipe_toml {
            fs::write(root.join("ipe.toml"), body).expect("write ipe.toml");
        }
        root
    }

    #[test]
    fn discovery_finds_package_ipe_ignoring_any_ipe_toml() {
        let root = discovery_dir(
            "finds_package",
            Some(
                "module Package exposing (package)\n\npackage =\n    { name = \"from-package\" }\n",
            ),
            Some("[project]\nname = \"from-toml\"\n"),
        );
        let manifest = manifest_in_dir(&root).expect("a manifest is found");
        assert_eq!(
            manifest.file_name().and_then(|n| n.to_str()),
            Some("package.ipe"),
            "package.ipe is the discovered manifest; a co-located ipe.toml is ignored"
        );
        assert!(
            !has_only_legacy_toml(&root),
            "a package.ipe present means the legacy-toml hint does not apply"
        );
        let m = parse_manifest(&manifest).expect("package.ipe reads");
        assert_eq!(m.name, "from-package");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ipe_toml_only_is_not_discovered_and_gets_the_legacy_hint() {
        let root = discovery_dir("toml_only", None, Some("[project]\nname = \"from-toml\"\n"));
        assert!(
            manifest_in_dir(&root).is_none(),
            "a bare ipe.toml is not a project manifest"
        );
        assert!(
            has_only_legacy_toml(&root),
            "an ipe.toml with no package.ipe gets the legacy-toml hint"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn discovery_returns_none_without_a_manifest() {
        let root = discovery_dir("no_manifest", None, None);
        assert!(
            manifest_in_dir(&root).is_none(),
            "an empty project has no manifest"
        );
        assert!(
            !has_only_legacy_toml(&root),
            "an empty project gets no legacy-toml hint"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn multi_program_manifest_surfaces_which_program_is_built() {
        let root = discovery_dir(
            "multi_program_notice",
            Some(
                "module Package exposing (package)\n\n\
                 package =\n    \
                 { name = \"multi\"\n    \
                 , programs =\n        \
                 [ { name = \"server\", entry = \"Main.ipe\", shape = Web }\n        \
                 , { name = \"cli\", entry = \"Cli/Main.ipe\", shape = Terminal }\n        \
                 ]\n    \
                 }\n",
            ),
            None,
        );
        let manifest = parse_manifest(&root.join("package.ipe")).expect("manifest must parse");
        let notice = manifest
            .multi_program_notice()
            .expect("a multi-program manifest surfaces its selection");
        assert!(
            notice.contains("server") && notice.contains("1 of 2"),
            "the notice names the built program and the count: {notice}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn single_program_manifest_has_no_selection_notice() {
        let root = discovery_dir(
            "single_program_notice",
            Some(
                "module Package exposing (package)\n\n\
                 package =\n    \
                 { name = \"solo\"\n    \
                 , programs = [ { name = \"app\", entry = \"Main.ipe\" } ]\n    \
                 }\n",
            ),
            None,
        );
        let manifest = parse_manifest(&root.join("package.ipe")).expect("manifest must parse");
        assert!(
            manifest.multi_program_notice().is_none(),
            "a single-program manifest has nothing to disambiguate"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_manifest_rejects_a_legacy_ipe_toml_path() {
        let root = discovery_dir(
            "reject_toml",
            None,
            Some(
                "[project]\nname = \"legacy\"\nversion = \"2.1.0\"\n[database]\ndriver = \"postgres\"\n",
            ),
        );
        let err = parse_manifest(&root.join("ipe.toml"))
            .expect_err("an ipe.toml path is not a package.ipe manifest");
        assert!(
            err.to_string().contains("legacy ipe.toml"),
            "the refusal must mention legacy ipe.toml: {err}"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
