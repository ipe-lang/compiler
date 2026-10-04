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
    /// chosen and how many were declared. Every program's entry goes through
    /// [`parse_entry`], so a malformed entry on any program refuses the manifest,
    /// not only on the one built.
    ///
    /// # Errors
    /// [`CliError::Usage`] when any program's entry file is refused by
    /// [`parse_entry`].
    pub fn resolved_entry(&self) -> Result<Vec<String>, CliError> {
        let mut entries = self.programs.iter().map(|program| {
            parse_entry(&program.entry)
                .map_err(|refusal| CliError::manifest_entry_refused(&program.entry, &refusal))
        });
        let Some(built) = entries.next() else {
            return Ok(vec!["Main".to_owned()]);
        };
        let built = built?;
        for other in entries {
            other?;
        }
        Ok(built)
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

/// Why a raw entry-file string is not an entry module path.
///
/// One variant per refused spelling, so every refusal is a distinct, testable
/// case and no spelling is silently normalised into a different module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryRefusal {
    /// The entry string is empty.
    Empty,
    /// A leading, trailing, or doubled `/` leaves an empty segment.
    EmptySegment,
    /// A `.` or `..` segment.
    DotSegment,
    /// A `\` byte: the separator is `/` on every platform.
    Backslash,
    /// A drive prefix (`C:`): an entry is relative to the source root.
    DrivePrefix,
    /// The final segment does not end in exactly `.ipe`.
    Extension,
    /// A segment that is not an Ipê module segment (`[A-Z][A-Za-z0-9_]*`, no
    /// Windows device name).
    NotModuleSegment {
        /// The refused segment, with any `.ipe` suffix already stripped.
        segment: String,
    },
}

/// Parse an entry-file string relative to the source root into its module path.
///
/// `Main.ipe` maps to `["Main"]` and `Client/App.ipe` to `["Client", "App"]`.
/// The raw string is split on `/` bytes and never passed through
/// [`Path::components`], which would silently drop a `.` segment, a doubled
/// or trailing `/`, and accept any extension; each of those is refused here, so
/// the module path is the one reading of the string every consumer shares.
///
/// # Errors
/// The [`EntryRefusal`] naming the first refused spelling.
pub fn parse_entry(raw: &str) -> Result<crate::api_surface::ModulePath, EntryRefusal> {
    if raw.is_empty() {
        return Err(EntryRefusal::Empty);
    }
    if raw.contains('\\') {
        return Err(EntryRefusal::Backslash);
    }
    if has_drive_prefix(raw) {
        return Err(EntryRefusal::DrivePrefix);
    }
    let segments: Vec<&str> = raw.split('/').collect();
    for segment in &segments {
        match *segment {
            "" => return Err(EntryRefusal::EmptySegment),
            "." | ".." => return Err(EntryRefusal::DotSegment),
            _ => {}
        }
    }
    let Some((last, dirs)) = segments.split_last() else {
        return Err(EntryRefusal::Empty);
    };
    let stem = last.strip_suffix(".ipe").ok_or(EntryRefusal::Extension)?;
    dirs.iter()
        .copied()
        .chain(std::iter::once(stem))
        .map(|segment| {
            if is_module_segment(segment) {
                Ok(segment.to_owned())
            } else {
                Err(EntryRefusal::NotModuleSegment {
                    segment: segment.to_owned(),
                })
            }
        })
        .collect()
}

/// Whether `raw` opens with a drive prefix (an ASCII letter then `:`).
fn has_drive_prefix(raw: &str) -> bool {
    let mut bytes = raw.bytes();
    matches!(
        (bytes.next(), bytes.next()),
        (Some(letter), Some(b':')) if letter.is_ascii_alphabetic()
    )
}

/// `[wasm]` section of a `package.ipe` manifest (spec: `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md` Q6
/// "Opt-in mechanism").
///
/// ```toml
/// [wasm]
/// mode      = "solo"             # solo (MVP) | hydrate (MVP+1) | off (default)
/// entry     = "src/Client.ipe"   # client entry; its reachability closure is the bundle
/// mount     = "#app"             # SPA mount node
/// publicEnv = ["API_BASE_URL"]   # default-deny allowlist; see `PublicEnvName`
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
    /// names the wasm bundle may read at build time. Parsed at manifest read
    /// time into [`PublicEnvName`]s — a refused name is a build error, never
    /// a runtime refusal.
    pub public_env: PublicEnvAllowlist,
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

/// Whether `name` is a portable environment variable name.
///
/// The portable grammar is ASCII letters, digits and `_`, not starting with a
/// digit (POSIX `name`): every such name survives the emitted `option_env!`
/// literal and the native `std::env::var` lookup unchanged.
fn is_portable_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// One `[wasm] publicEnv` entry, parsed once at the manifest boundary.
///
/// A held value is a portable environment variable name that is neither
/// secret-bearing ([`is_denylisted_public_env_name`]) nor a name the
/// compiler's audited environment reader refuses ([`ipe_env::is_refused_key`]:
/// a temp-root or home variable). [`PublicEnvName::parse`] is the only mint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicEnvName(String);

impl PublicEnvName {
    /// Parse one allowlist entry.
    ///
    /// # Errors
    ///
    /// A [`PublicEnvRefusal`] naming `raw` and the rule it breaks.
    pub fn parse(raw: &str) -> Result<Self, PublicEnvRefusal> {
        let held = || raw.to_owned();
        if !is_portable_env_name(raw) {
            return Err(PublicEnvRefusal::IllFormed(held()));
        }
        if is_denylisted_public_env_name(raw) {
            return Err(PublicEnvRefusal::Secret(held()));
        }
        let key = std::ffi::OsStr::new(raw);
        if ipe_env::is_temp_root_key(key) {
            return Err(PublicEnvRefusal::TempRoot(held()));
        }
        if ipe_env::is_refused_key(key) {
            return Err(PublicEnvRefusal::Home(held()));
        }
        Ok(Self(held()))
    }

    /// The variable name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a `[wasm] publicEnv` entry was refused; each arm carries the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicEnvRefusal {
    /// Not a portable environment variable name (empty, a leading digit, or a
    /// character outside ASCII letters, digits and `_`).
    IllFormed(String),
    /// Matches the secret-name denylist ([`is_denylisted_public_env_name`]).
    Secret(String),
    /// Names the process temp root ([`ipe_env::TEMP_ROOT_NAMES`]).
    TempRoot(String),
    /// Names the user's home directory ([`ipe_env::HOME_NAMES`]).
    Home(String),
    /// Repeats an earlier entry, compared ignoring ASCII case.
    Duplicate {
        /// The repeated entry.
        name: String,
        /// The earlier entry it repeats.
        first: String,
    },
}

impl PublicEnvRefusal {
    /// The author-facing reason: the offending entry, the rule, and the fix.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::IllFormed(name) => format!(
                "`publicEnv` lists {name:?}, which is not an environment variable name \
                 — a name is ASCII letters, digits and `_`, and does not start with a digit"
            ),
            Self::Secret(name) => format!(
                "`publicEnv` lists {name:?}, which matches the secret-name denylist \
                 (a SECRET / TOKEN / KEY / PASSWORD / PASSWD / CREDENTIAL / AUTH / APIKEY \
                 word, DATABASE_URL, or the internal IPE_* namespace) — a secret \
                 environment variable can never be allowlisted into the public wasm bundle"
            ),
            Self::TempRoot(name) => format!(
                "`publicEnv` lists {name:?}, which names the process temp root ({}, any case) \
                 — it steers where the runtime creates scratch directories, so it can never \
                 be allowlisted into the public wasm bundle; remove it from `publicEnv`",
                ipe_env::TEMP_ROOT_NAMES.join(" / ")
            ),
            Self::Home(name) => format!(
                "`publicEnv` lists {name:?}, which names the user's home directory ({}, any \
                 case) — it steers where caches live and would publish a build-machine path, \
                 so it can never be allowlisted into the public wasm bundle; remove it from \
                 `publicEnv`",
                ipe_env::HOME_NAMES.join(" / ")
            ),
            Self::Duplicate { name, first } => format!(
                "`publicEnv` lists {name:?}, which repeats {first:?} (names are compared \
                 ignoring ASCII case) — list each variable once"
            ),
        }
    }
}

/// The `[wasm] publicEnv` allowlist: distinct [`PublicEnvName`]s in manifest
/// order.
///
/// No two entries are equal ignoring ASCII case: [`Self::insert`] refuses the
/// repeat, so the emitted lookup never carries a second arm for one name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicEnvAllowlist {
    names: Vec<PublicEnvName>,
    folded: BTreeMap<String, usize>,
}

impl PublicEnvAllowlist {
    /// Append `name`.
    ///
    /// # Errors
    ///
    /// [`PublicEnvRefusal::Duplicate`] when an entry equal to `name` ignoring
    /// ASCII case is already held; the allowlist is then unchanged.
    pub fn insert(&mut self, name: PublicEnvName) -> Result<(), PublicEnvRefusal> {
        let folded = name.as_str().to_ascii_uppercase();
        if let Some(first) = self.folded.get(&folded) {
            let first = self
                .names
                .get(*first)
                .map_or_else(String::new, |held| held.0.clone());
            return Err(PublicEnvRefusal::Duplicate {
                name: name.0,
                first,
            });
        }
        self.folded.insert(folded, self.names.len());
        self.names.push(name);
        Ok(())
    }

    /// Whether no name is allowlisted.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The entries in manifest order.
    pub fn iter(&self) -> impl Iterator<Item = &PublicEnvName> {
        self.names.iter()
    }

    /// The names as plain text, for the compile pipeline outside this crate.
    #[must_use]
    pub fn to_names(&self) -> Vec<String> {
        self.names.iter().map(|n| n.0.clone()).collect()
    }
}

/// A discovered Ipê source file with its resolved module path.
///
/// Fields are private: [`DiscoveredModule::user`] and the stdlib injection are
/// the only mints, so a module's [`ModuleProvenance`] always matches how it
/// entered the graph.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredModule {
    path: PathBuf,
    module_path: Vec<String>,
    provenance: ModuleProvenance,
}

impl DiscoveredModule {
    /// A user-authored module; its [`EntryRole`] derives from `module_path`.
    #[must_use]
    pub fn user(path: PathBuf, module_path: Vec<String>) -> Self {
        let role = EntryRole::of_module_path(&module_path);
        Self {
            path,
            module_path,
            provenance: ModuleProvenance::User(role),
        }
    }

    /// A compiled-source stdlib module taken from the embed table.
    ///
    /// Crate-private: a module minted here is trusted to declare into the
    /// reserved `Ipe.*` namespace (see [`embedded_stdlib_modules`]).
    #[must_use]
    pub(crate) const fn embedded_stdlib(path: PathBuf, module_path: Vec<String>) -> Self {
        Self {
            path,
            module_path,
            provenance: ModuleProvenance::EmbeddedStdlib,
        }
    }

    /// Path to the `.ipe` source file (synthetic for an embedded stdlib module).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Module path segments, e.g. `Lib/Utils.ipe` → `["Lib", "Utils"]`.
    #[must_use]
    pub fn module_path(&self) -> &[String] {
        &self.module_path
    }

    /// Where the module's source comes from, fixed when it entered the graph.
    #[must_use]
    pub const fn provenance(&self) -> ModuleProvenance {
        self.provenance
    }

    /// The source file path and module path, consuming the record.
    #[must_use]
    pub fn into_paths(self) -> (PathBuf, Vec<String>) {
        (self.path, self.module_path)
    }
}

/// The provenance of a [`DiscoveredModule`] in the source graph.
///
/// Only a user module carries an [`EntryRole`]: an injected stdlib module is
/// never a package's `Main`, so that combination has no representation. The
/// canonicaliser's trust tag (`ipe_db::ModuleOrigin`) for a stdlib module is
/// derived from this record by [`embedded_stdlib_modules`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ModuleProvenance {
    /// A module the package author wrote, discovered under the source root.
    User(EntryRole),
    /// A compiled-source stdlib module taken from `ipe`'s embed table.
    ///
    /// Only [`inject_compiled_std_closure`] (and API extraction of a stdlib
    /// module) mints this provenance, and injection only for a module it
    /// actually inserted, so a user file squatting on a stdlib path stays
    /// [`ModuleProvenance::User`].
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
/// [`CliError::Usage`] for a malformed or invalid manifest (an unsupported
/// driver, a bad version or dependency, an unknown capability, a denylisted
/// `publicEnv` name, a missing source root); [`CliError::Pipeline`] when the
/// source does not parse; and [`CliError::Usage`] when the path is not a
/// `package.ipe`.
pub fn parse_manifest(manifest_path: &Path) -> Result<ProjectManifest, CliError> {
    if manifest_path.file_name().and_then(|n| n.to_str())
        == Some(crate::package_manifest::PACKAGE_IPE)
    {
        return crate::package_manifest::parse_package_manifest(manifest_path);
    }
    Err(CliError::Usage(text::msg::manifest_not_package_ipe(
        &manifest_path.display(),
        &text::legacy_toml_hint(),
    )))
}

// ---------------------------------------------------------------------------
// Module discovery
// ---------------------------------------------------------------------------

/// The maximum directory depth the module-discovery walk will descend.
///
/// Past it the walk returns a typed [`CliError::DiscoveryLimitReached`]. A legitimate
/// Ipê source tree is never this deep; an adversarial or accidentally unbounded
/// tree is refused rather than spinning indefinitely.
pub const MAX_DISCOVERY_DEPTH: usize = 64;

/// The most `.ipe` modules the module-discovery walk collects.
///
/// The same bound `ipe watch` holds its watched source files to, so the one
/// walk that feeds both a build and a watch session refuses a pathological
/// tree once, with one limit.
pub const MAX_DISCOVERED_MODULES: usize = ipe_watch::MAX_WATCHED_FILES;

/// The most directory entries the module-discovery walk examines.
///
/// Bounds a walk through a huge tree that holds few modules (a vendored
/// dependency directory under the source root).
pub const MAX_DISCOVERY_ENTRIES: usize = 1_000_000;

/// Walk `src_root` recursively, collecting every `*.ipe` file as a
/// [`DiscoveredModule`].
///
/// Files whose path contains a non-module-segment (e.g. lowercase first char
/// or characters outside `[A-Za-z0-9_]`) are silently skipped — they may be
/// build artefacts or editor swap files. A well-formed segment that is a
/// Windows reserved device name (`Aux.ipe`) is refused instead: the parser
/// accepts `module Aux`, so skipping it would silently drop a real module.
/// Symlinks are never followed: a
/// symlinked file or directory is skipped, and each module found is read
/// later by [`crate::io_bounded::read_walked_source`], which refuses a final
/// symlink swapped in since.
///
/// The walk carries a canonicalised visited-set to detect symlink cycles, a
/// depth ceiling to bound pathologically deep trees, and ceilings on the
/// modules collected and the entries examined. Each produces a typed
/// [`CliError::DiscoveryLimitReached`] rather than an unbounded walk.
///
/// # Errors
/// [`CliError::SourceRefused`] with [`SourceRefusal::AccessDenied`] when a
/// directory under `src_root` may not be listed, or with
/// [`SourceRefusal::NotRegularFile`] when a module path names a FIFO,
/// device or socket.
/// [`CliError::Io`] if a directory cannot otherwise be read.
/// [`CliError::DiscoveryLimitReached`] on a symlink cycle, a tree deeper
/// than [`MAX_DISCOVERY_DEPTH`], more than [`MAX_DISCOVERED_MODULES`]
/// modules or more than [`MAX_DISCOVERY_ENTRIES`] entries.
/// [`CliError::DeviceNamedModule`] when a module path uses a device name.
///
/// [`SourceRefusal::AccessDenied`]: crate::io_bounded::SourceRefusal::AccessDenied
/// [`SourceRefusal::NotRegularFile`]: crate::io_bounded::SourceRefusal::NotRegularFile
pub fn discover_modules(src_root: &Path) -> Result<Vec<DiscoveredModule>, CliError> {
    use std::collections::HashSet;

    let mut result: Vec<DiscoveredModule> = Vec::new();
    // Stack entries carry the directory path and its depth from src_root.
    let mut stack: VecDeque<(PathBuf, usize)> = VecDeque::new();
    // Visited set of canonicalised paths breaks symlink cycles.
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut examined = 0usize;

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

        let entries = fs::read_dir(&dir).map_err(|e| crate::io_bounded::access_error(&dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| crate::io_bounded::access_error(&dir, e))?;
            examined = examined.saturating_add(1);
            if examined > MAX_DISCOVERY_ENTRIES {
                return Err(CliError::DiscoveryLimitReached {
                    detail: format!(
                        "source tree holds more than {MAX_DISCOVERY_ENTRIES} entries at `{}`",
                        dir.display()
                    ),
                });
            }
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|e| crate::io_bounded::access_error(&path, e))?;
            if file_type.is_dir() {
                stack.push_back((path, depth + 1));
                continue;
            }
            if file_type.is_symlink() || path.extension().and_then(|e| e.to_str()) != Some("ipe") {
                continue;
            }
            let Some(m) = file_to_module(src_root, &path)? else {
                continue;
            };
            if !file_type.is_file() {
                return Err(crate::io_bounded::source_refused(
                    &path,
                    crate::io_bounded::SourceRefusal::NotRegularFile,
                ));
            }
            if result.len() >= MAX_DISCOVERED_MODULES {
                return Err(CliError::DiscoveryLimitReached {
                    detail: format!(
                        "source tree holds more than {MAX_DISCOVERED_MODULES} modules at `{}`",
                        dir.display()
                    ),
                });
            }
            result.push(m);
        }
    }

    result.sort();
    Ok(result)
}

/// Map a `.ipe` file path to a [`DiscoveredModule`].
///
/// `Ok(None)` when the path is no module path at all (an artefact the walk
/// skips), per [`module_path_shape`].
///
/// # Errors
/// [`CliError::DeviceNamedModule`] when the path is well formed but a
/// segment is a Windows reserved device name.
fn file_to_module(src_root: &Path, path: &Path) -> Result<Option<DiscoveredModule>, CliError> {
    let Ok(rel) = path.strip_prefix(src_root) else {
        return Ok(None);
    };
    let without_ext = rel.with_extension("");
    let Some(segments) = without_ext
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<Vec<&str>>>()
    else {
        return Ok(None);
    };
    match module_path_shape(&segments) {
        ModulePathShape::NotModule => Ok(None),
        ModulePathShape::DeviceNamed(segment) => Err(CliError::DeviceNamedModule {
            path: path.to_path_buf(),
            segment: segment.to_owned(),
        }),
        ModulePathShape::Module => Ok(Some(DiscoveredModule::user(
            path.to_path_buf(),
            segments.iter().copied().map(str::to_owned).collect(),
        ))),
    }
}

/// What a candidate module path is, the one rule package discovery and loose-file imports share.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ModulePathShape<'s> {
    /// Non-empty, and every segment is a module segment.
    Module,
    /// Empty, or some segment is not well formed: no user module at all.
    NotModule,
    /// Every segment is well formed, but this one is a Windows reserved device name.
    DeviceNamed(&'s str),
}

/// Classify `segments` as a module path.
///
/// Well-formedness is decided over every segment before any device name,
/// so a path that is no module at all (`Aux/notes`) is never refused for a
/// device-named segment.
pub(crate) fn module_path_shape<S: AsRef<str>>(segments: &[S]) -> ModulePathShape<'_> {
    if segments.is_empty()
        || !segments
            .iter()
            .all(|segment| is_well_formed_segment(segment.as_ref()))
    {
        return ModulePathShape::NotModule;
    }
    segments
        .iter()
        .map(AsRef::<str>::as_ref)
        .find(|segment| is_windows_device_name(segment))
        .map_or(ModulePathShape::Module, ModulePathShape::DeviceNamed)
}

/// Whether `s` is a legal Ipê module path segment.
///
/// It must be well formed ([`is_well_formed_segment`]) and not a Windows
/// reserved device name: a segment names a file or directory, and the same
/// source tree must map to the same module set on every platform.
pub(crate) fn is_module_segment(s: &str) -> bool {
    is_well_formed_segment(s) && !is_windows_device_name(s)
}

/// Whether `s` starts with an ASCII uppercase letter and holds only ASCII alphanumerics and `_`.
fn is_well_formed_segment(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
        _ => false,
    }
}

/// Whether `name` is a Windows reserved device name, with or without extension.
///
/// Windows resolves `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9` and
/// `LPT0`–`LPT9` to devices case-insensitively and regardless of any
/// extension, so `con.ipe` opens the console rather than a file.
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split_once('.').map_or(name, |(stem, _)| stem);
    let upper = stem.to_ascii_uppercase();
    match upper.as_bytes() {
        b"CON" | b"PRN" | b"AUX" | b"NUL" => true,
        [b'C', b'O', b'M', digit] | [b'L', b'P', b'T', digit] => digit.is_ascii_digit(),
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
/// Returns [`embedded_stdlib_modules`] of the resulting `discovered` — the
/// driver's record of which modules are trusted `EmbeddedStdlib` source,
/// derived from the provenance records rather than kept beside them. A record
/// is minted ONLY when a NEW synthetic entry is inserted; if `sources` already
/// holds the key (a user file squatting on `Ipe.Palette`, or an earlier
/// injection), injection is skipped and the path is NOT tagged trusted. So a
/// hostile `src/Std/Palette.ipe` is canonicalised as `ModuleOrigin::User` and
/// stays IPE-N0025-rejected.
///
/// Efficiency (design §7): the worklist is seeded only from imports that match a
/// compiled-source module, so a build that imports none does zero work.
pub fn inject_compiled_std_closure(
    sources: &mut BTreeMap<Vec<String>, (PathBuf, String)>,
    discovered: &mut Vec<DiscoveredModule>,
) -> BTreeSet<Vec<String>> {
    // One shared closure + squat-guard lives in `ipe_stdlib` (the SSOT both the
    // native and wasm frontends call); the native driver records a
    // `DiscoveredModule` per injected node via the callback and derives the
    // trusted set from those records.
    ipe_stdlib::inject_compiled_std_closure(
        sources,
        extract_imports_from_source,
        |module_path, synth_path| {
            discovered.push(DiscoveredModule::embedded_stdlib(
                synth_path.to_path_buf(),
                module_path.to_vec(),
            ));
        },
    );
    embedded_stdlib_modules(discovered)
}

/// The module paths trusted as embedded stdlib source.
///
/// A path is trusted only when some record for it has
/// [`ModuleProvenance::EmbeddedStdlib`] AND no record claims it as
/// [`ModuleProvenance::User`]: a user claimant on the same path fails closed
/// to untrusted, so a squat never inherits the stdlib's reserved-namespace
/// exemption.
#[must_use]
pub fn embedded_stdlib_modules(discovered: &[DiscoveredModule]) -> BTreeSet<Vec<String>> {
    let user_claimed: BTreeSet<&[String]> = discovered
        .iter()
        .filter(|m| matches!(m.provenance, ModuleProvenance::User(_)))
        .map(DiscoveredModule::module_path)
        .collect();
    discovered
        .iter()
        .filter(|m| m.provenance == ModuleProvenance::EmbeddedStdlib)
        .filter(|m| !user_claimed.contains(m.module_path()))
        .map(|m| m.module_path.clone())
        .collect()
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

    fn module(segments: &[&str]) -> Vec<String> {
        segments.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parse_entry_accepts_a_root_and_a_nested_module_file() {
        assert_eq!(parse_entry("Main.ipe"), Ok(module(&["Main"])));
        assert_eq!(parse_entry("Cli/Main.ipe"), Ok(module(&["Cli", "Main"])));
    }

    #[test]
    fn parse_entry_refuses_an_empty_string() {
        assert_eq!(parse_entry(""), Err(EntryRefusal::Empty));
    }

    #[test]
    fn parse_entry_refuses_every_empty_segment() {
        for raw in [
            "/Main.ipe",
            "Cli//Main.ipe",
            "Cli/Main.ipe/",
            "//host/Main.ipe",
        ] {
            assert_eq!(parse_entry(raw), Err(EntryRefusal::EmptySegment), "{raw}");
        }
    }

    #[test]
    fn parse_entry_refuses_a_dot_segment() {
        for raw in [
            "Cli/./Main.ipe",
            "./Main.ipe",
            "../Main.ipe",
            "Cli/../Main.ipe",
        ] {
            assert_eq!(parse_entry(raw), Err(EntryRefusal::DotSegment), "{raw}");
        }
    }

    #[test]
    fn parse_entry_refuses_a_backslash() {
        for raw in ["Cli\\Main.ipe", "\\\\host\\share\\Main.ipe"] {
            assert_eq!(parse_entry(raw), Err(EntryRefusal::Backslash), "{raw}");
        }
    }

    #[test]
    fn parse_entry_refuses_a_drive_prefix() {
        for raw in ["C:Main.ipe", "c:/Main.ipe"] {
            assert_eq!(parse_entry(raw), Err(EntryRefusal::DrivePrefix), "{raw}");
        }
    }

    #[test]
    fn parse_entry_refuses_any_extension_but_ipe() {
        for raw in [
            "Main.rs",
            "Main.txt",
            "Main",
            "Main.IPE",
            "Cli/Main.ipe.bak",
        ] {
            assert_eq!(parse_entry(raw), Err(EntryRefusal::Extension), "{raw}");
        }
    }

    #[test]
    fn parse_entry_refuses_a_non_module_segment() {
        for (raw, segment) in [
            ("lower/App.ipe", "lower"),
            ("Cli/main.ipe", "main"),
            (".ipe", ""),
            ("Main.ipe.ipe", "Main.ipe"),
            ("Con.ipe", "Con"),
            ("Cli/My Mod.ipe", "My Mod"),
        ] {
            assert_eq!(
                parse_entry(raw),
                Err(EntryRefusal::NotModuleSegment {
                    segment: segment.to_owned()
                }),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_refused_entry_names_the_entry_escaped() {
        let err = CliError::manifest_entry_refused("Cli/\u{1b}[31m.ipe", &EntryRefusal::Extension);
        let rendered = err.to_string();
        assert!(
            rendered.contains("\"Cli/\\u{1b}[31m.ipe\"") && !rendered.contains('\u{1b}'),
            "the entry renders escaped, never raw: {rendered}"
        );
    }

    #[test]
    fn each_entry_refusal_renders_its_own_teaching_message() {
        let cases = [
            (EntryRefusal::Empty, "names no module"),
            (EntryRefusal::EmptySegment, "empty path segment"),
            (EntryRefusal::DotSegment, "`..` path segment"),
            (EntryRefusal::Backslash, "contains a backslash"),
            (EntryRefusal::DrivePrefix, "drive prefix"),
            (EntryRefusal::Extension, "does not end in `.ipe`"),
            (
                EntryRefusal::NotModuleSegment {
                    segment: "lower".to_owned(),
                },
                "segment \"lower\" that is not a valid module name",
            ),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (refusal, phrase) in cases {
            let rendered = CliError::manifest_entry_refused("X", &refusal).to_string();
            assert!(
                rendered.contains(phrase),
                "{refusal:?} must say {phrase:?}: {rendered}"
            );
            assert!(
                seen.insert(rendered),
                "{refusal:?} shares another refusal's message"
            );
        }
    }

    #[test]
    fn windows_device_names_are_not_module_segments() {
        for name in ["CON", "Con", "PRN", "Prn", "AUX", "Aux", "NUL", "Nul"] {
            assert!(!is_module_segment(name), "{name} names a device");
        }
        for n in 0..=9 {
            for prefix in ["COM", "Com", "LPT", "Lpt"] {
                let name = format!("{prefix}{n}");
                assert!(!is_module_segment(&name), "{name} names a device");
            }
        }
    }

    #[test]
    fn windows_device_names_match_any_case_and_extension() {
        for name in [
            "con",
            "CON.ipe",
            "nul.txt",
            "Aux.tar.gz",
            "prn",
            "com1.ipe",
            "LPT9.x",
            "lpt5",
            "com0",
            "LPT0.ipe",
        ] {
            assert!(is_windows_device_name(name), "{name} names a device");
        }
    }

    #[test]
    fn device_name_near_misses_are_module_segments() {
        for name in [
            "CONSOLE",
            "Console",
            "Conn",
            "Nulls",
            "Auxiliary",
            "Printer",
            "COM",
            "COM10",
            "LPT",
            "LPT10",
            "Com1x",
        ] {
            assert!(is_module_segment(name), "{name} is an ordinary segment");
        }
    }

    /// An empty source root unique to this test process.
    #[allow(clippy::expect_used)] // test fixture: an unwritable temp dir IS the failure
    fn device_walk_root(name: &str) -> PathBuf {
        let root =
            ipe_test_temp::temp_root().join(format!("ipe_device_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create source root");
        root
    }

    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn a_device_named_module_file_is_refused_not_skipped() {
        let root = device_walk_root("file");
        fs::write(root.join("Main.ipe"), "module Main exposing (..)\n").expect("write Main");
        fs::write(root.join("Aux.ipe"), "module Aux exposing (..)\n").expect("write Aux");
        let found = discover_modules(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(
            matches!(
                &found,
                Err(CliError::DeviceNamedModule { path, segment })
                    if segment == "Aux" && *path == root.join("Aux.ipe")
            ),
            "a device-named module must be refused: {found:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn a_device_named_module_directory_is_refused_not_skipped() {
        let root = device_walk_root("dir");
        fs::create_dir_all(root.join("Com0")).expect("mk device dir");
        fs::write(
            root.join("Com0").join("Port.ipe"),
            "module Com0.Port exposing (..)\n",
        )
        .expect("write Port");
        let found = discover_modules(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(
            matches!(
                &found,
                Err(CliError::DeviceNamedModule { segment, .. }) if segment == "Com0"
            ),
            "a device-named directory segment must be refused: {found:?}"
        );
    }

    /// The module paths `discover_modules` finds under `root`, `None` on a refusal.
    fn discovered_paths(root: &Path) -> Option<Vec<Vec<String>>> {
        discover_modules(root)
            .ok()
            .map(|found| found.into_iter().map(|m| m.module_path).collect())
    }

    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn a_non_module_file_is_still_skipped() {
        let root = device_walk_root("skip");
        fs::write(root.join("Main.ipe"), "module Main exposing (..)\n").expect("write Main");
        fs::write(root.join("scratch.ipe"), "junk").expect("write artefact");
        let paths = discovered_paths(&root);
        let _ = fs::remove_dir_all(&root);
        assert_eq!(paths, Some(vec![vec!["Main".to_owned()]]));
    }

    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn a_non_module_file_under_a_device_named_directory_is_skipped() {
        let root = device_walk_root("device-dir-artefact");
        fs::write(root.join("Main.ipe"), "module Main exposing (..)\n").expect("write Main");
        fs::create_dir_all(root.join("Aux")).expect("mk device dir");
        fs::write(root.join("Aux").join("notes.ipe"), "junk").expect("write artefact");
        let paths = discovered_paths(&root);
        let _ = fs::remove_dir_all(&root);
        assert_eq!(paths, Some(vec![vec!["Main".to_owned()]]));
    }

    #[test]
    fn well_formedness_is_decided_before_device_names() {
        assert_eq!(module_path_shape(&["Main"]), ModulePathShape::Module);
        assert_eq!(module_path_shape(&["Lib", "Util"]), ModulePathShape::Module);
        assert_eq!(module_path_shape::<&str>(&[]), ModulePathShape::NotModule);
        assert_eq!(
            module_path_shape(&["Aux", "notes"]),
            ModulePathShape::NotModule
        );
        assert_eq!(
            module_path_shape(&["notes", "Aux"]),
            ModulePathShape::NotModule
        );
        assert_eq!(
            module_path_shape(&["Lib", ".."]),
            ModulePathShape::NotModule
        );
        assert_eq!(
            module_path_shape(&["Aux"]),
            ModulePathShape::DeviceNamed("Aux")
        );
        assert_eq!(
            module_path_shape(&["Lib", "Com0", "Nul"]),
            ModulePathShape::DeviceNamed("Com0")
        );
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
    fn injected_trust_set_is_derived_from_provenance_records() {
        // SSOT: the returned trusted set is exactly the embedded-stdlib records
        // pushed into `discovered`, never a second hand-kept record.
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

        let from_records: BTreeSet<Vec<String>> = discovered
            .iter()
            .filter(|m| m.provenance() == ModuleProvenance::EmbeddedStdlib)
            .map(|m| m.module_path().to_vec())
            .collect();
        assert!(!injected.is_empty(), "Ipe.Palette closure injected");
        assert_eq!(injected, from_records);
        assert_eq!(injected, embedded_stdlib_modules(&discovered));
    }

    #[test]
    fn user_squat_record_keeps_user_provenance() {
        // A user file on a stdlib path gets no embedded record at all, so its
        // provenance stays User and it ranks as a user entry.
        let palette = vec!["Ipe".to_owned(), "Palette".to_owned()];
        let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
        sources.insert(
            vec!["Main".to_owned()],
            (
                PathBuf::from("src/Main.ipe"),
                "module Main exposing (main)\nimport Ipe.Palette exposing (..)\nmain = 0\n"
                    .to_owned(),
            ),
        );
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

        super::inject_compiled_std_closure(&mut sources, &mut discovered);

        let claims: Vec<ModuleProvenance> = discovered
            .iter()
            .filter(|m| m.module_path() == palette.as_slice())
            .map(DiscoveredModule::provenance)
            .collect();
        assert_eq!(
            claims,
            vec![ModuleProvenance::User(EntryRole::Library)],
            "the squat keeps its single User record"
        );
    }

    #[test]
    fn user_claimant_revokes_embedded_stdlib_trust() {
        // SECURITY (fail closed): an embedded record does not confer trust on
        // a path a user record also claims, whatever the record order.
        let palette = vec!["Ipe".to_owned(), "Palette".to_owned()];
        let embedded =
            DiscoveredModule::embedded_stdlib(PathBuf::from("<embedded-stdlib>"), palette.clone());
        let squat = DiscoveredModule::user(PathBuf::from("src/Std/Palette.ipe"), palette.clone());

        for records in [
            vec![embedded.clone(), squat.clone()],
            vec![squat, embedded.clone()],
        ] {
            assert!(
                !embedded_stdlib_modules(&records).contains(&palette),
                "a user-claimed path must not be trusted"
            );
        }
        assert!(
            embedded_stdlib_modules(std::slice::from_ref(&embedded)).contains(&palette),
            "an unclaimed embedded record is trusted"
        );
    }

    #[test]
    fn user_module_role_derives_from_its_path() {
        let main = DiscoveredModule::user(PathBuf::from("src/Main.ipe"), vec!["Main".to_owned()]);
        let lib = DiscoveredModule::user(
            PathBuf::from("src/Lib/Main2.ipe"),
            vec!["Lib".to_owned(), "Main2".to_owned()],
        );
        assert_eq!(main.provenance(), ModuleProvenance::User(EntryRole::Main));
        assert_eq!(lib.provenance(), ModuleProvenance::User(EntryRole::Library));
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

    #[test]
    fn public_env_name_parse_classifies_each_refusal() {
        /// Whether a refusal is the expected arm for its entry.
        type RefusalCheck = fn(&PublicEnvRefusal) -> bool;
        let cases: [(&str, RefusalCheck); 6] = [
            (
                "TMPDIR",
                |r| matches!(r, PublicEnvRefusal::TempRoot(n) if n == "TMPDIR"),
            ),
            (
                "tmp",
                |r| matches!(r, PublicEnvRefusal::TempRoot(n) if n == "tmp"),
            ),
            (
                "TEMP",
                |r| matches!(r, PublicEnvRefusal::TempRoot(n) if n == "TEMP"),
            ),
            (
                "HOME",
                |r| matches!(r, PublicEnvRefusal::Home(n) if n == "HOME"),
            ),
            (
                "API_TOKEN",
                |r| matches!(r, PublicEnvRefusal::Secret(n) if n == "API_TOKEN"),
            ),
            (
                "",
                |r| matches!(r, PublicEnvRefusal::IllFormed(n) if n.is_empty()),
            ),
        ];
        for (raw, expected) in cases {
            let refusal = PublicEnvName::parse(raw).err();
            assert!(
                refusal.as_ref().is_some_and(expected),
                "{raw:?} refused as {refusal:?}"
            );
        }
        assert_eq!(
            PublicEnvName::parse("API_BASE_URL").map(|n| n.as_str().to_owned()),
            Ok("API_BASE_URL".to_owned())
        );
    }

    #[test]
    fn public_env_allowlist_refuses_a_repeat_and_stays_unchanged() {
        let mut allowlist = PublicEnvAllowlist::default();
        let first = PublicEnvName::parse("APP_VERSION").expect("benign name parses");
        assert_eq!(allowlist.insert(first), Ok(()));
        let repeat = PublicEnvName::parse("App_Version").expect("benign name parses");
        assert_eq!(
            allowlist.insert(repeat),
            Err(PublicEnvRefusal::Duplicate {
                name: "App_Version".to_owned(),
                first: "APP_VERSION".to_owned(),
            })
        );
        assert_eq!(allowlist.to_names(), vec!["APP_VERSION"]);
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
        let root = ipe_test_temp::temp_root().join(format!("ipe_discovery_{test_name}"));
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
    fn a_malformed_entry_on_a_program_not_built_still_refuses_the_manifest() {
        let manifest_with_second_entry = |name: &str, second: &str| {
            let root = discovery_dir(
                name,
                Some(&format!(
                    "module Package exposing (package)\n\n\
                     package =\n    \
                     {{ name = \"multi\"\n    \
                     , programs =\n        \
                     [ {{ name = \"server\", entry = \"Main.ipe\" }}\n        \
                     , {{ name = \"cli\", entry = \"{second}\" }}\n        \
                     ]\n    \
                     }}\n"
                )),
                None,
            );
            let manifest = parse_manifest(&root.join("package.ipe")).expect("manifest must parse");
            let _ = fs::remove_dir_all(&root);
            manifest
        };
        let legal = manifest_with_second_entry("second_entry_legal", "Cli/Main.ipe");
        assert_eq!(legal.resolved_entry().ok(), Some(module(&["Main"])));
        let refused = manifest_with_second_entry("second_entry_refused", "Cli/./Main.ipe");
        let expected =
            CliError::manifest_entry_refused("Cli/./Main.ipe", &EntryRefusal::DotSegment)
                .to_string();
        assert_eq!(
            refused.resolved_entry().map_err(|err| err.to_string()),
            Err(expected),
            "the second program's `./` entry refuses the manifest as a dot segment"
        );
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

    // ── Module discovery refusals ─────────────────────────────────────────────

    /// An empty source root unique to this test process.
    #[allow(clippy::expect_used)] // test fixture: an unwritable temp dir IS the failure
    fn walk_root(name: &str) -> PathBuf {
        let root =
            ipe_test_temp::temp_root().join(format!("ipe_walk_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create source root");
        root
    }

    /// Whether `result` is the typed refusal for `reason`.
    fn is_refused<T>(
        result: &Result<T, CliError>,
        reason: crate::io_bounded::SourceRefusal,
    ) -> bool {
        matches!(result, Err(CliError::SourceRefused { reason: got, .. }) if *got == reason)
    }

    /// A FIFO named as a module is refused by the walk, and by the walked read, without blocking.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write or `mkfifo` IS the failure
    fn fifo_module_is_refused_without_blocking() {
        let root = walk_root("fifo");
        fs::write(root.join("Main.ipe"), "module Main exposing (..)\n").expect("write Main");
        let fifo = root.join("Pipe.ipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
        let walked = discover_modules(&root);
        let read = crate::io_bounded::read_walked_source(&fifo);
        let _ = fs::remove_dir_all(&root);
        for refused in [
            is_refused(&walked, crate::io_bounded::SourceRefusal::NotRegularFile),
            is_refused(&read, crate::io_bounded::SourceRefusal::NotRegularFile),
        ] {
            assert!(
                refused,
                "a FIFO module is not a regular file: {walked:?} / {read:?}"
            );
        }
    }

    /// A FIFO whose name is no module path is skipped, like any other non-module file.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write or `mkfifo` IS the failure
    fn fifo_outside_the_module_namespace_is_skipped() {
        let root = walk_root("fifo_skip");
        fs::write(root.join("Main.ipe"), "module Main exposing (..)\n").expect("write Main");
        let made = std::process::Command::new("mkfifo")
            .arg(root.join("scratch.ipe"))
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
        let walked = discover_modules(&root);
        let _ = fs::remove_dir_all(&root);
        let modules: Option<Vec<Vec<String>>> = walked
            .ok()
            .map(|found| found.into_iter().map(|m| m.module_path).collect());
        assert_eq!(modules, Some(vec![vec!["Main".to_owned()]]));
    }

    /// A directory under the source root the process may not list is refused as access denied.
    ///
    /// Skipped when the process can list it anyway (running as root).
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn unreadable_module_directory_is_refused_as_access_denied() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = walk_root("noread");
        let locked = root.join("Locked");
        fs::create_dir_all(&locked).expect("create Locked/");
        fs::write(
            locked.join("Hidden.ipe"),
            "module Locked.Hidden exposing (..)\n",
        )
        .expect("write Hidden");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))
            .expect("drop the directory's permissions");
        let privileged = fs::read_dir(&locked).is_ok();
        let walked = discover_modules(&root);
        let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&root);
        if privileged {
            return;
        }
        assert!(
            is_refused(&walked, crate::io_bounded::SourceRefusal::AccessDenied),
            "an unlistable module directory must be refused as access denied, got: {walked:?}"
        );
    }

    /// A module file without the read bit is refused by the walked read as access denied.
    ///
    /// Skipped when the process can read it anyway (running as root).
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: an unwritable scratch dir IS the failure
    fn unreadable_module_file_is_refused_as_access_denied() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = walk_root("noread_file");
        let module = root.join("Main.ipe");
        fs::write(&module, "module Main exposing (..)\n").expect("write Main");
        fs::set_permissions(&module, fs::Permissions::from_mode(0o000)).expect("drop the read bit");
        let privileged = fs::File::open(&module).is_ok();
        let walked = discover_modules(&root);
        let read = crate::io_bounded::read_walked_source(&module);
        let _ = fs::remove_dir_all(&root);
        if privileged {
            return;
        }
        assert!(walked.is_ok(), "the walk lists the file: {walked:?}");
        assert!(
            is_refused(&read, crate::io_bounded::SourceRefusal::AccessDenied),
            "an unreadable module must be refused as access denied, got: {read:?}"
        );
    }

    // ── Symlink non-descent ─────────────────────────────────────────────────

    /// `discover_modules` classifies each entry with
    /// [`std::fs::DirEntry::file_type`], which reports the entry's own type
    /// without following a symlink (`lstat`, not `stat`). A symlinked
    /// directory is therefore neither `is_dir()` nor `is_file()` to the walk
    /// and is never pushed onto the descent stack, so a link cycle through it
    /// is unrepresentable: its modules go undiscovered rather than being
    /// walked into.
    #[cfg(unix)]
    #[test]
    fn discover_modules_does_not_descend_a_symlinked_directory() {
        let root = ipe_test_temp::temp_root()
            .join(format!("ipe_discover_symlink_skip_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let src = root.join("src");
        fs::create_dir_all(&src).expect("create src/");
        fs::write(
            src.join("Local.ipe"),
            "module Local exposing (x)\n\nx = 0\n",
        )
        .expect("write Local.ipe");

        // `External` sits outside src/ and holds a module that would only be
        // found if the walk followed the symlink into it.
        let external = root.join("External");
        fs::create_dir_all(&external).expect("create External/");
        fs::write(
            external.join("Util.ipe"),
            "module Util exposing (x)\n\nx = 0\n",
        )
        .expect("write External/Util.ipe");
        std::os::unix::fs::symlink(&external, src.join("Link")).expect("plant Link -> External");

        let discovered =
            discover_modules(&src).expect("a symlinked directory is skipped, not a cycle");
        assert!(
            discovered
                .iter()
                .all(|m| m.module_path.last().map(String::as_str) != Some("Util")),
            "the module behind the symlink must not be discovered: {discovered:?}"
        );
        assert!(
            discovered
                .iter()
                .any(|m| m.module_path.last().map(String::as_str) == Some("Local")),
            "the ordinary top-level module must still be discovered: {discovered:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }
}
