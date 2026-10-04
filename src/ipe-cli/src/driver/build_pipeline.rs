use super::{CliError, diag_span, io_err};
use crate::env_dir::{HomeDir, HomeRefusal};
#[cfg(not(unix))]
use crate::output_dir::OutputRefusal;
use crate::output_dir::{EmitTarget, OwnedDir, OwnedPath, ProjectPaths};
use crate::{
    BTreeMap, BTreeSet, Diagnostic, Interner, Path, PathBuf, build_plan, cache, contained_path,
    ffi, fs, project, render, runtime_embed, text,
};
use ipe_backend_rust::rust_str_lit;

/// Options modifying a build beyond plain source compilation — some (the
/// static plan) apply post-emit at write time; others (`target`,
/// `wasm_public_env`) feed the compile/emit pipeline itself.
///
/// The static plan is applied post-emit at write time — the compile pipeline
/// and its on-disk caches stay untouched (their keys deliberately exclude
/// the plan; the transform is a deterministic function of the plan applied
/// on cache-hit and cache-miss paths alike).
// The three `bool` fields (`wasm_hydrate_mode`, `runtime_dep`,
// `tree_shake_vendored`) are genuinely independent, orthogonal build toggles —
// any combination is valid (a dep-model hydrate build, a vendored tree-shaken
// build, …). They are not the states of one machine, so collapsing them into
// a two-variant enum or a state enum would obscure their independence rather than
// clarify it; the clippy heuristic's usual remedy does not apply here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Default)]
pub struct BuildOptions {
    /// `Some` — staticize the emitted project (activate the planned
    /// allocator feature, add the generated `.cargo/config.toml`). `None` —
    /// normal dynamic build; also removes a stale generated static config.
    pub static_plan: Option<ipe_backend_rust::static_build::StaticPlan>,
    /// The compilation target (`Native` default; `WasmClient` under
    /// `ipe build --target wasm`) — threaded into kernel resolution (the
    /// Layer-1 wasm gate), the emitted manifest, and both cache keys.
    pub target: ipe_ir::Target,
    /// The `[wasm] publicEnv` allowlist from `package.ipe`, already validated
    /// against the secret-name denylist at parse time. Empty when the
    /// project has no `[wasm]` section (or no manifest — the
    /// sibling-discovery single-file path). Threaded into
    /// [`ipe_backend_rust::RustBackend::with_wasm_public_env`] /
    /// [`ipe_db::BuildConfig::wasm_public_env`].
    pub wasm_public_env: Vec<String>,
    /// `true` when `[wasm] mode = "hydrate"` in the project's `package.ipe`.
    /// Causes the backend to emit a `#[wasm_bindgen] pub fn hydrate(model_json: &str)`
    /// export in addition to the `#[wasm_bindgen(start)] pub fn ipe_start()` entry.
    /// The emitted `hydrate` function parses the island JSON as the user's declared
    /// `HydrationState` type, converts to `Model` via `fromHydrationState`, and
    /// calls `ipe_runtime::wasm::wasm_adopt_app`. On parse failure it falls back
    /// to clean `ipe_main()` with a console warning (fault-tolerant hydrate — see
    /// spec Q6 §"Fault-tolerant hydrate — parse, don't unwrap").
    pub wasm_hydrate_mode: bool,
    /// The verb family this build serves, threaded into
    /// [`ipe_db::BuildConfig::intent`].
    ///
    /// `Release` (the default) rejects any development-only `Debug.*` escape
    /// hatch (IPE-L0140) and omits the runtime `dev-posture` feature, so the
    /// console stays closed until `IPE_CONSOLE_AUTH` is set. Only a dev verb
    /// (`ipe build` / `run` / `test` / `watch`) states `Development`.
    pub intent: ipe_backend_rust::BuildIntent,
    /// `true` (the DEFAULT) selects the dependency-model emit: the emitted
    /// project declares the runtime as a path dependency with a
    /// `runtime_features`-selected feature list and vendors no runtime source.
    /// Applies to BOTH targets — a native project selects the reached native
    /// features; a wasm project selects the `wasm-client` floor plus any
    /// browser-admissible surface it reaches, built for
    /// `wasm32-unknown-unknown`. `false` opts back into the byte-identical
    /// vendored-source emit — the fallback for debugging / a machine without an
    /// installed runtime crate — set via `IPE_RUNTIME_VENDORED=1` (or directly by
    /// a test).
    pub runtime_dep: bool,
    /// `true` tree-shakes the vendored runtime tree to only the modules the
    /// program reaches — the `ipe eject` shape. The emitted `ipe_runtime/mod.rs`
    /// already declares `pub mod X;` for exactly the reached top-level modules,
    /// so [`build_emit_manifest`] vendors only those source files instead of the
    /// whole runtime tree. Ignored unless the emit is the vendored shape (it has
    /// no effect on a dependency-model emit, which carries no vendored source at
    /// all). Default `false`: a plain vendored build copies the whole tree
    /// (rustc drops the undeclared files itself, so the emitted binary is
    /// identical either way — trimming only changes what source lands on disk).
    pub tree_shake_vendored: bool,
    /// The sanitized Cargo package name for the emitted crate, derived from
    /// `package.ipe`'s name via
    /// [`ipe_backend_rust::sanitize_cargo_name`]. The emitted `Cargo.toml`
    /// carries `[package] name = "<cargo_name>"` and the built binary is
    /// named accordingly. Empty string uses the safe `"ipe-app"` default
    /// (single-file builds with no manifest).
    pub cargo_name: String,
    /// `true` when `ipe build --debugger` / `ipe run --debugger` was passed.
    /// Threaded through [`ipe_db::BuildConfig`] to
    /// [`ipe_backend_rust::RustBackend::with_debugger`], which adds the
    /// `debugger` feature to the emitted project's runtime dependency so the TEA
    /// driver instantiates the recorder. NEVER set for `ipe release` builds — the
    /// release command does not expose this flag, so no production artifact can
    /// carry recorder code.
    pub debugger: bool,
    /// `true` routes style-value literals through a per-view `LiteralTable` and
    /// emits the `/_ipe/hot-appearance` endpoint, so an appearance-only source
    /// edit hot-swaps in the running app instead of forcing a recompile. Set
    /// ONLY by the `ipe watch` entry (from [`hot_appearance_enabled`]); the
    /// `ipe build` / `ipe run` / `ipe release` entries leave it `false` so a
    /// release artifact never carries hot-swap scaffolding. Default `false`.
    pub hot_appearance: bool,
    /// `true` when the resolved delivery is `web desktop` (webview-native).
    /// Threaded through [`ipe_db::BuildConfig`] and the emit fast-path to
    /// [`ipe_backend_rust::RustBackend::with_webview_host`], forcing the
    /// `uses_webview` signal so the emitted project selects the webview executor
    /// and promotes `webview` to the default feature list. The webview delivery
    /// is a resolved HOST decision (from the CLI's shape × runtime × host), not a
    /// source entry. Default `false` (a served `web`, or any non-web shape).
    pub webview_host: bool,
    /// The webview-native desktop window, sourced from the manifest
    /// `delivery.desktop` block. Threaded to
    /// [`ipe_backend_rust::RustBackend::with_webview_window`] and consulted only
    /// when [`Self::webview_host`]. Filled in `build_project_with_options` once
    /// the manifest is parsed; `None` selects the built-in fallback window.
    pub webview_window: Option<ipe_backend_rust::WebViewWindow>,
}

/// Where a build writes its emitted crate.
///
/// A bare path is proven disjoint from the build's own project before the
/// build writes anything; a proven target carries its proof already.
#[derive(Debug, Clone, Copy)]
pub enum OutTarget<'a> {
    /// A target proven by the caller (a CLI output area, a claimed directory).
    Proven(&'a EmitTarget),
    /// A bare path, proven against the project being built.
    Path(&'a Path),
}

impl OutTarget<'_> {
    /// The proven target, proving a bare path against `project`.
    fn prove(self, project: &ProjectPaths) -> Result<EmitTarget, CliError> {
        match self {
            Self::Proven(target) => Ok(target.clone()),
            Self::Path(out_dir) => EmitTarget::at(out_dir, project),
        }
    }
}

/// Select the emit model from the environment.
///
/// The dependency model is the DEFAULT; `IPE_RUNTIME_VENDORED=1` opts back into
/// the vendored-source emit (debugging / a machine that cannot resolve the
/// runtime crate). The legacy `IPE_RUNTIME_DEP=1` remains an explicit no-op
/// affirmation of the default. A [`BuildOptions::runtime_dep`] already set by a
/// caller (a test) is what is threaded; this function only computes the
/// env-derived default.
#[must_use]
pub fn runtime_dep_from_env() -> bool {
    !ipe_env::var("IPE_RUNTIME_VENDORED").is_ok_and(|v| v == "1")
}

/// The emitted-crate package name for a no-manifest (single-file) build, read
/// from `IPE_EMIT_PACKAGE_NAME` when set, empty (the `"ipe-app"` default)
/// otherwise.
///
/// A single-file build carries no `package.ipe`, so its emitted crate is always
/// named `ipe-app`. When many single-file builds share ONE cargo target dir
/// (the coverage harness driving a per-symbol emit into a warm shared dep
/// target) that constant name makes their app-crate cargo fingerprints collide:
/// cargo could reuse a prior probe's compiled `ipe-app` and mask a genuinely
/// broken emit, defeating the seal the coverage sweep exists to hold. Setting a
/// UNIQUE name per build gives each app crate its own fingerprint, so a broken
/// emit still fails to build even against a warm target. Unset (every ordinary
/// `ipe run` / `ipe build`), the name is empty and the emit keeps the `ipe-app`
/// default — this lever changes nothing for a normal build.
#[must_use]
pub fn single_file_cargo_name_from_env() -> String {
    ipe_env::var("IPE_EMIT_PACKAGE_NAME")
        .ok()
        .map(|name| ipe_backend_rust::sanitize_cargo_name(&name))
        .unwrap_or_default()
}

/// The canonical directory that owns a project's manifest — the seed for the
/// per-project crate identity ([`ipe_backend_rust::crate_identity`]).
///
/// Canonicalising resolves symlinks and `..` so two spellings of the same
/// directory hash to the SAME crate identity (one cache slot, no needless
/// rebuild); different real directories stay distinct (the anti-thrash key).
/// Every fallback is total — a manifest with no parent, or an un-canonicalisable
/// path (e.g. a not-yet-created dir), degrades to the plain parent then the
/// manifest path itself, so this never panics and always yields a deterministic
/// seed for a fixed input.
fn canonical_project_dir(manifest_path: &Path) -> PathBuf {
    let dir = manifest_path.parent().unwrap_or(manifest_path);
    std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
}

/// Whether the dev-only appearance hot-swap emit is enabled for `ipe watch`.
///
/// Default ON: `ipe watch` hot-swaps appearance-only edits (e.g. `Ui.spacing`)
/// without a recompile out of the box. Opt out with `IPE_WATCH_NO_HOT_APPEARANCE`
/// (set to any non-empty value other than `0`), which forces the plain
/// direct-literal emit. `IPE_WATCH_HOT_APPEARANCE`, when set, is honoured
/// explicitly (`0` or empty = off, anything else = on) and overrides the
/// default; the opt-out takes precedence over it.
///
/// This lever exists ONLY in `ipe watch`. `ipe build` / `ipe run` / `ipe release`
/// thread [`BuildOptions::hot_appearance`] `= false`, so a release artifact never
/// carries hot-swap scaffolding regardless of these variables.
#[must_use]
pub fn hot_appearance_enabled() -> bool {
    hot_appearance_from_env(
        ipe_env::var("IPE_WATCH_NO_HOT_APPEARANCE").ok().as_deref(),
        ipe_env::var("IPE_WATCH_HOT_APPEARANCE").ok().as_deref(),
    )
}

/// Pure decision for [`hot_appearance_enabled`], over the two raw variable
/// values (`None` = unset). Opt-out (`no_var`) wins; then an explicit
/// `hot_var`; otherwise the default is on.
#[must_use]
pub fn hot_appearance_from_env(no_var: Option<&str>, hot_var: Option<&str>) -> bool {
    let set = |v: Option<&str>| v.is_some_and(|s| !s.is_empty() && s != "0");
    if set(no_var) {
        return false;
    }
    hot_var.is_none_or(|v| !v.is_empty() && v != "0")
}

/// Whether the dev-only browser build-status banner is enabled for `ipe watch`.
///
/// Enabled unless `IPE_WEB_BANNER` is explicitly `off`/`0`/`false`. Mirrors the
/// runtime's `watch_banner_active` disable semantics so the CLI-side poster and
/// the server-side endpoint agree on when the banner is live. Distinct from
/// [`hot_appearance_enabled`]: the failure banner must surface a red compile
/// error whenever the banner is on, even with appearance hot-swap off.
#[must_use]
pub fn watch_banner_enabled() -> bool {
    ipe_env::var("IPE_WEB_BANNER").map_or(true, |v| {
        let v = v.trim().to_ascii_lowercase();
        !(v == "off" || v == "0" || v == "false")
    })
}

/// Whether the DEV-ONLY blue-green front proxy is enabled for `ipe watch`.
///
/// Default ON: `ipe watch` puts a persistent proxy on the user's port and cuts
/// each rebuilt binary over behind it once it passes readiness, so a rebuild
/// never drops the browser's connection (no "Reconnecting…" flash — the client
/// gets a brief "updated ✓" toast instead). Opt out with `IPE_WATCH_NO_BLUEGREEN`
/// (set to any non-empty value other than `0`) to fall back to the direct-bind,
/// kill-old-then-spawn-new path. The legacy `IPE_WATCH_BLUEGREEN` still forces a
/// choice when set (`0`/empty ⇒ off, anything else ⇒ on) and takes precedence
/// over the default but yields to the opt-out. This lever exists ONLY in
/// `ipe watch`; it is never compiled into a release binary or an emitted app.
#[must_use]
pub fn bluegreen_enabled() -> bool {
    bluegreen_from_env_values(
        ipe_env::var("IPE_WATCH_NO_BLUEGREEN").ok().as_deref(),
        ipe_env::var("IPE_WATCH_BLUEGREEN").ok().as_deref(),
    )
}

/// The pure default-resolution behind [`bluegreen_enabled`], separated from the
/// process-env read so it is unit-testable without mutating global state.
///
/// `no_bluegreen` / `bluegreen` are the respective env values (`None` = unset).
/// Precedence: opt-out wins, then an explicit legacy choice, else default on.
#[must_use]
pub fn bluegreen_from_env_values(no_bluegreen: Option<&str>, bluegreen: Option<&str>) -> bool {
    // Opt-out wins: a hard "never proxy" for a user who needs the direct bind.
    if no_bluegreen.is_some_and(|v| !v.is_empty() && v != "0") {
        return false;
    }
    // Then an explicit legacy choice, if any: `0`/empty off, else on.
    if let Some(v) = bluegreen {
        return !v.is_empty() && v != "0";
    }
    // Default on.
    true
}

impl BuildOptions {
    /// The default build options with the emit model resolved from the
    /// environment (dependency-model by default; vendored under
    /// `IPE_RUNTIME_VENDORED=1`). The zero-configuration entrypoints
    /// ([`build`], [`build_loose_file`], [`build_project`]) seed
    /// this so a library caller gets the same default emit model a `ipe build`
    /// invocation does, rather than the raw `Default` (which is vendored — the
    /// fallback shape).
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            runtime_dep: runtime_dep_from_env(),
            cargo_name: single_file_cargo_name_from_env(),
            ..Self::default()
        }
    }
}

/// Build `entry` into a Rust Cargo project under `out_dir`, vendoring the
/// runtime module tree from `runtime_dir`.
///
/// # Errors
/// Returns [`CliError::Pipeline`] when the compiler rejects the program,
/// [`CliError::Io`] on any filesystem failure.
pub fn build(entry: &Path, out_dir: &Path, runtime_dir: &Path) -> Result<(), CliError> {
    build_with_options(entry, out_dir, runtime_dir, BuildOptions::from_env())
}

/// [`build`] with explicit [`BuildOptions`] (the static-plan-aware variant).
///
/// # Errors
/// As [`build`], plus [`CliError::StaticRefusal`] when the emitted app shape
/// cannot be static (an `Ipe.WebView` app under a static plan).
pub fn build_with_options(
    entry: &Path,
    out_dir: &Path,
    runtime_dir: &Path,
    options: BuildOptions,
) -> Result<(), CliError> {
    build_with_options_into(entry, OutTarget::Path(out_dir), runtime_dir, options).map(drop)
}

/// [`build_with_options`] into `out`, returning the claimed crate directory.
///
/// # Errors
/// As [`build_with_options`], plus [`CliError::OutputRefused`] when `out`
/// overlaps the entry's directory.
pub fn build_with_options_into(
    entry: &Path,
    out: OutTarget<'_>,
    runtime_dir: &Path,
    options: BuildOptions,
) -> Result<OwnedDir, CliError> {
    let target = out.prove(&ProjectPaths::of_file(entry))?;
    let source =
        crate::io_bounded::read_to_string_capped(entry, crate::io_bounded::SOURCE_READ_CAP)?;

    // Parse ONCE with a throwaway interner to learn the entry's declared module
    // path. Using the declared name as the entry's `module_path` means the shared
    // graph core's N0023 (path mismatch) can never fire for a single-file build
    // (expected == declared by construction), while still routing a single-file
    // program through the SAME injection-aware pipeline as a project — so a
    // single file importing `Ipe.Palette` injects the compiled source instead of
    // 404-ing (design §2.6). For a program with no compiled-source import the
    // core is emit-byte-identical to a plain single-module path (link over one
    // module is the identity — regression-covered by the golden suite).
    let mut name_interner = Interner::new();
    let pipeline_err = |diag: Diagnostic| CliError::Pipeline {
        file: entry.to_path_buf(),
        src: source.clone(),
        diag: Box::new(diag),
    };
    let parsed = ipe_parse::parse_module(&source, &mut name_interner).map_err(&pipeline_err)?;
    let entry_path: Vec<String> = parsed
        .name
        .value
        .iter()
        .map(|s| name_interner.resolve(*s).unwrap_or_default().to_owned())
        .collect();

    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(entry_path.clone(), (entry.to_path_buf(), source.clone()));
    let discovered = vec![project::DiscoveredModule::user(
        entry.to_path_buf(),
        entry_path.clone(),
    )];

    // No manifest on the single-file path — default to sqlite, matching the
    // documented `package.ipe` default for a project that has no database
    // setting.
    compile_modules(
        sources,
        discovered,
        &entry_path,
        &target,
        runtime_dir,
        entry,
        ipe_backend_rust::DbDriver::Sqlite,
        options,
    )
}

/// Build a loose `.ipe` entry file plus the sibling modules it imports.
///
/// When no manifest is present, an import `A.B` resolves to `A/B.ipe` under
/// the entry file's directory, so a multi-file program builds via the
/// file-path shorthand (`ipe build src/Main.ipe`).
///
/// The module set is the entry plus the sibling modules its imports reach,
/// resolved by [`crate::loose_file::resolve_loose_file`] (see
/// [`collect_entry_and_siblings`]); the entry's directory is never listed.
///
/// When the entry imports no sibling this function is byte-identical to
/// `build` (single-module pipeline is the identity over `link`).
///
/// # Errors
/// [`CliError::Pipeline`] when the compiler rejects the program.
/// [`CliError::Io`] on any filesystem failure.
/// [`CliError::DiscoveryLimitReached`] when the import closure exceeds
/// [`crate::loose_file::LooseFileLimits::DEFAULT`].
pub fn build_loose_file(entry: &Path, out_dir: &Path, runtime_dir: &Path) -> Result<(), CliError> {
    build_loose_file_with_options(entry, out_dir, runtime_dir, BuildOptions::from_env())
}

/// [`build_loose_file`] with explicit [`BuildOptions`] (the
/// static-plan-aware variant).
///
/// # Errors
/// As [`build_loose_file`], plus [`CliError::StaticRefusal`]
/// when the emitted app shape cannot be static.
pub fn build_loose_file_with_options(
    entry: &Path,
    out_dir: &Path,
    runtime_dir: &Path,
    options: BuildOptions,
) -> Result<(), CliError> {
    build_loose_file_into(entry, OutTarget::Path(out_dir), runtime_dir, options).map(drop)
}

/// [`build_loose_file_with_options`] into `out`, returning the
/// claimed crate directory.
///
/// # Errors
/// As [`build_loose_file`], plus [`CliError::OutputRefused`] when
/// `out` overlaps the entry's directory.
pub fn build_loose_file_into(
    entry: &Path,
    out: OutTarget<'_>,
    runtime_dir: &Path,
    options: BuildOptions,
) -> Result<OwnedDir, CliError> {
    let target = out.prove(&ProjectPaths::of_file(entry))?;
    let collected = collect_entry_and_siblings(entry)?;

    // No manifest on this path either (the loose-file closure is the "no manifest
    // found" fallback) — default to sqlite, same rationale as `build`.
    compile_modules(
        collected.sources,
        collected.discovered,
        &collected.entry_module_path,
        &target,
        runtime_dir,
        entry,
        ipe_backend_rust::DbDriver::Sqlite,
        options,
    )
}

/// Build `ipe verify`'s test entry against the project's `src/` sources.
///
/// Unlike [`build_loose_file`], which follows the entry's
/// imports within its own directory, this roots the code under test at `project_src_root`
/// (the `src/` tree) and additionally discovers the test entry's own directory
/// (the `tests/` tree) — so a `tests/Main.ipe` that imports `Lib.Foo` from
/// `src/Lib/Foo.ipe` resolves. See [`collect_test_sources`] for the source-set
/// model.
///
/// Returns the claimed crate directory.
///
/// # Errors
/// [`CliError::Pipeline`] when the compiler rejects the program; [`CliError::Io`]
/// on any filesystem failure; [`CliError::StaticRefusal`] when the emitted app
/// shape cannot be static; [`CliError::OutputRefused`] when `out` overlaps the
/// test entry's directory or `project_src_root`.
pub fn build_test_into(
    project_src_root: &Path,
    tests_root: &Path,
    test_entry: &Path,
    out: OutTarget<'_>,
    runtime_dir: &Path,
) -> Result<OwnedDir, CliError> {
    let project = ProjectPaths::of_file(test_entry).with_sources(project_src_root);
    let target = out.prove(&project)?;
    let collected = collect_test_sources(project_src_root, tests_root, test_entry)?;

    // No manifest driver is threaded here (the test stage mirrors the sibling
    // build's "no manifest" fallback) — default to sqlite, same rationale as
    // `build_loose_file`.
    compile_modules(
        collected.sources,
        collected.discovered,
        &collected.entry_module_path,
        &target,
        runtime_dir,
        test_entry,
        ipe_backend_rust::DbDriver::Sqlite,
        BuildOptions {
            intent: ipe_backend_rust::BuildIntent::Development,
            ..BuildOptions::from_env()
        },
    )
}

/// A loose entry plus the sibling modules its imports reach, ready to feed the shared compile core.
pub struct CollectedSources {
    pub(crate) sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    pub(crate) discovered: Vec<project::DiscoveredModule>,
    pub(crate) entry_module_path: Vec<String>,
}

/// Collect a loose entry plus the transitive closure of sibling modules it imports.
///
/// This is the file-path shorthand's source-collection step, shared by the
/// build path ([`build_loose_file_with_options`]) and the
/// single-entry analysis paths ([`lower_entry_via_graph`], [`emit_ir_text`]) so all
/// three see the SAME module set. It delegates to
/// [`crate::loose_file::resolve_loose_file`] — the one loose-file resolver
/// `ipe watch` and `ipe lsp` also use — so every surface compiles the same
/// bounded closure: one probed path per import, regular files contained in
/// the entry's directory only, within
/// [`crate::loose_file::LooseFileLimits::DEFAULT`], and no directory
/// listing. The compiled-source stdlib closure is injected downstream (in
/// [`compile_modules_observed`] / [`lower_entry_via_graph`]), not here, so
/// the injection routine stays single-sourced.
///
/// # Errors
/// [`CliError::Pipeline`] when the entry does not parse; [`CliError::Io`] when
/// the entry or an imported sibling cannot be read;
/// [`CliError::DiscoveryLimitReached`] when the import closure is too large.
pub fn collect_entry_and_siblings(entry: &Path) -> Result<CollectedSources, CliError> {
    let loaded = crate::loose_file::resolve_loose_file(
        entry,
        None,
        crate::loose_file::LooseFileLimits::DEFAULT,
    )?;
    Ok(CollectedSources {
        sources: loaded.sources,
        discovered: loaded.discovered,
        entry_module_path: loaded.entry_module,
    })
}

/// Collect the sources for a manifest-governed file analysed by itself (e.g.
/// `ipe type-check src/Api/Handlers.ipe`): the WHOLE `src_root` tree — the
/// same [`project::discover_modules`] set `ipe build` compiles — rather than
/// the loose closure rooted at the file's own directory.
///
/// The loose closure ([`collect_entry_and_siblings`]) resolves an import
/// relative to the ENTRY's directory, which is only correct when the entry's
/// directory IS the project's source root (as for the default `<src_root>/Main.ipe`
/// entry). A nested file's own directory
/// is a subdirectory of `src_root`, not `src_root` itself, so the same closure
/// would look for `Api.Types` at `<entry-dir>/Api/Types.ipe` instead of
/// `src_root/Api/Types.ipe`. Discovering the whole `src_root` tree side-steps
/// this: every module's path is relativised against `src_root`, matching what
/// the emitted build sees.
///
/// # Errors
/// [`CliError::Pipeline`] when the entry does not parse; [`CliError::Io`] on
/// any filesystem failure reading a discovered module;
/// [`CliError::DiscoveryLimitReached`] when the `src_root` tree is too large.
pub fn collect_manifest_rooted_entry(
    src_root: &Path,
    entry: &Path,
) -> Result<CollectedSources, CliError> {
    let entry_source =
        crate::io_bounded::read_to_string_capped(entry, crate::io_bounded::SOURCE_READ_CAP)?;
    let entry_module_path = parse_entry_module_path(entry, &entry_source)?;

    let mut discovered = project::discover_modules(src_root)?;
    ensure_entry_present(&mut discovered, entry, &entry_module_path);

    let sources = read_discovered_sources(&discovered, entry, &entry_module_path, &entry_source)?;

    Ok(CollectedSources {
        sources,
        discovered,
        entry_module_path,
    })
}

/// Collect the sources for `ipe verify`'s test stage: the project's `src/`
/// tree (the code under test) unioned with the `tests/` tree (the test entry
/// and any test-only siblings).
///
/// A test entry lives in a sibling directory from the code it exercises
/// (`tests/Main.ipe` importing `Lib.Db` under `src/Lib/`), so a single-root
/// discovery cannot see both: `src/` and `tests/` must be relativised against
/// their OWN roots for module paths to resolve (`src/Lib/Foo.ipe` → `Lib.Foo`,
/// `tests/Main.ipe` → `Main`). This resolves both rooted discoveries into one
/// well-typed [`CollectedSources`] whose entry is the test module, so a test
/// module can import the code under test AND its test-only siblings.
///
/// When a module path is defined in both trees, the `src/` definition wins for
/// non-entry modules — the code under test is authoritative — while the entry
/// module is always the test entry itself.
///
/// # Errors
/// [`CliError::Pipeline`] when the test entry does not parse; [`CliError::Io`]
/// on any filesystem failure reading a discovered module.
pub fn collect_test_sources(
    project_src_root: &Path,
    tests_root: &Path,
    test_entry: &Path,
) -> Result<CollectedSources, CliError> {
    let entry_source =
        crate::io_bounded::read_to_string_capped(test_entry, crate::io_bounded::SOURCE_READ_CAP)?;
    let entry_module_path = parse_entry_module_path(test_entry, &entry_source)?;

    // The `tests/` tree is rooted at `tests_root` (the caller's, e.g. the
    // manifest-governed project's `<project_root>/tests`) rather than
    // re-derived from the test entry's own parent — a nested test file
    // (`tests/Support/Helpers.ipe`) must still widen against the WHOLE
    // `tests/` tree, not just its own directory, so
    // `tests/Support/Helpers.ipe` → `Support.Helpers`.

    // The code under test: the `src/` tree, rooted at itself so
    // `src/Lib/Foo.ipe` → `Lib.Foo` — the SAME relativisation the build stage
    // uses. Union the two rooted discoveries; a `src/` module masks a `tests/`
    // module of the same path (code under test wins), and the test entry is
    // always added last so it is never masked.
    let mut discovered = project::discover_modules(project_src_root)?;
    let src_paths: std::collections::BTreeSet<Vec<String>> = discovered
        .iter()
        .map(|m| m.module_path().to_vec())
        .collect();
    for m in project::discover_modules(tests_root)? {
        if !src_paths.contains(m.module_path()) {
            discovered.push(m);
        }
    }
    ensure_entry_present(&mut discovered, test_entry, &entry_module_path);

    let sources =
        read_discovered_sources(&discovered, test_entry, &entry_module_path, &entry_source)?;

    Ok(CollectedSources {
        sources,
        discovered,
        entry_module_path,
    })
}

/// Parse a `.ipe` entry file's already-read source to learn its declared
/// module path (e.g. `["Lib", "Db"]`).
///
/// # Errors
/// [`CliError::Pipeline`] when the source does not parse.
pub fn parse_entry_module_path(entry: &Path, source: &str) -> Result<Vec<String>, CliError> {
    let pipeline_err = |diag: Diagnostic| CliError::Pipeline {
        file: entry.to_path_buf(),
        src: source.to_owned(),
        diag: Box::new(diag),
    };
    let mut name_interner = Interner::new();
    let parsed = ipe_parse::parse_module(source, &mut name_interner).map_err(&pipeline_err)?;
    Ok(parsed
        .name
        .value
        .iter()
        .map(|s| name_interner.resolve(*s).unwrap_or_default().to_owned())
        .collect())
}

/// Ensure the entry itself is in the discovered set, even when its file name
/// does not match the module-segment validation (e.g. a temp path). This
/// prevents the entry from being silently dropped.
pub fn ensure_entry_present(
    discovered: &mut Vec<project::DiscoveredModule>,
    entry: &Path,
    entry_module_path: &[String],
) {
    if !discovered
        .iter()
        .any(|m| m.module_path() == entry_module_path)
    {
        discovered.push(project::DiscoveredModule::user(
            entry.to_path_buf(),
            entry_module_path.to_vec(),
        ));
    }
}

/// Read every discovered module into the module-path-keyed source map. The
/// entry's source is already in memory (`entry_source`), so it is inserted
/// without a second read.
///
/// # Errors
/// [`CliError::Io`] on any filesystem failure reading a discovered module.
pub fn read_discovered_sources(
    discovered: &[project::DiscoveredModule],
    entry: &Path,
    entry_module_path: &[String],
    entry_source: &str,
) -> Result<BTreeMap<Vec<String>, (PathBuf, String)>, CliError> {
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    for m in discovered {
        if m.module_path() == entry_module_path {
            sources.insert(
                entry_module_path.to_vec(),
                (entry.to_path_buf(), entry_source.to_owned()),
            );
        } else {
            let src = crate::io_bounded::read_walked_source(m.path())?;
            sources.insert(m.module_path().to_vec(), (m.path().to_path_buf(), src));
        }
    }
    Ok(sources)
}

/// The most directories [`find_manifest_for_ipe_file`] examines on its way up.
pub const MAX_MANIFEST_WALK_DEPTH: usize = 64;

/// Entries whose presence marks a directory as a version-control root.
const VCS_ROOT_MARKERS: [&str; 3] = [".git", ".hg", ".jj"];

/// The identity of a directory, independent of the path spelling that reached it.
///
/// On Unix the device and inode pair; elsewhere the canonical path. Two
/// spellings of one directory (a symlinked home, an aliased mount) compare
/// equal, and two directories never do.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirIdentity(DirIdentityKey);

#[cfg(unix)]
type DirIdentityKey = (u64, u64);
#[cfg(not(unix))]
type DirIdentityKey = PathBuf;

impl DirIdentity {
    /// The identity of the directory `dir` resolves to.
    ///
    /// # Errors
    ///
    /// The I/O error that kept `dir` from being inspected.
    pub fn read(dir: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(dir).map(|meta| Self((meta.dev(), meta.ino())))
        }
        #[cfg(not(unix))]
        {
            std::fs::canonicalize(dir).map(Self)
        }
    }
}

/// Whether `err` shows that no directory exists at the inspected path.
fn names_no_directory(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// How the user's home bounds a manifest walk.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HomeCeiling {
    /// The home variable is unset, or no directory exists at the home it names.
    ///
    /// A directory that does not exist is no ancestor of any file, so only
    /// version-control roots and the depth cap bound the walk.
    Absent,
    /// The walk stops at the directory with this identity.
    At(DirIdentity),
    /// A home exists but its identity cannot be read, or the home variable is
    /// set to a value the parser refuses.
    ///
    /// No directory above the start can be shown to lie below the home, so
    /// the walk examines the start directory alone.
    Unreadable,
}

impl HomeCeiling {
    /// The ceiling the parsed `home` sets, read once.
    ///
    /// Only an unset home widens the walk to [`Self::Absent`]: a home that is
    /// set but refused may still name the user's tree, so it fails closed to
    /// [`Self::Unreadable`] rather than letting the walk climb past it.
    #[must_use]
    pub fn of(home: Result<&HomeDir, HomeRefusal>) -> Self {
        match home {
            Ok(dir) => match DirIdentity::read(dir.as_path()) {
                Ok(identity) => Self::At(identity),
                Err(err) if names_no_directory(&err) => Self::Absent,
                Err(_) => Self::Unreadable,
            },
            Err(HomeRefusal::Unset) => Self::Absent,
            Err(
                HomeRefusal::NotUtf8
                | HomeRefusal::ContainsNul
                | HomeRefusal::NotAbsolute
                | HomeRefusal::ParentComponent
                | HomeRefusal::WindowsDeviceOrVerbatim
                | HomeRefusal::WindowsUnc,
            ) => Self::Unreadable,
        }
    }

    /// Whether the walk ends at `here` once its manifest has been looked for.
    ///
    /// A directory that exists but whose identity cannot be read may be the
    /// home, so it ends the walk.
    fn stops_at(&self, here: &Path) -> bool {
        match self {
            Self::Absent => false,
            Self::Unreadable => true,
            Self::At(home) => match DirIdentity::read(here) {
                Ok(identity) => identity == *home,
                Err(err) => !names_no_directory(&err),
            },
        }
    }
}

/// Walk up from a `.ipe` file's parent to the nearest `package.ipe`.
///
/// When given a file entry, the driver locates the project root (where
/// `package.ipe` lives) before building, so the full module graph is compiled
/// instead of just the single entry file. The user never named the manifest
/// this finds, so it is obeyed only once it passes the owner rule
/// ([`crate::owner_trust::admit_discovered_manifest`]).
///
/// The walk stops at a ceiling: the first version-control root or the user's
/// home directory. A manifest in the ceiling directory itself is still found;
/// one above it lies outside the user's tree and is never consulted, so
/// `None` (a loose file) is returned instead. See [`find_manifest_bounded`].
///
/// # Errors
///
/// As [`find_manifest_bounded`].
pub fn find_manifest_for_ipe_file(ipe_file: &Path) -> Result<Option<PathBuf>, CliError> {
    let home = HomeCeiling::of(crate::env_dir::home().as_ref().map_err(|refusal| *refusal));
    find_manifest_bounded(ipe_file, &home, MAX_MANIFEST_WALK_DEPTH)
}

/// Walk up from `ipe_file`'s parent to the nearest `package.ipe`, below a ceiling.
///
/// At each directory a manifest is looked for first; the walk then ends with
/// `None` when that directory holds a version-control root marker, is
/// `home`, or is the filesystem root. At most `max_depth` directories are
/// examined.
///
/// The walk steps up the path as given, so a found manifest keeps the
/// spelling the caller used. The `home` ceiling is matched by the
/// [`DirIdentity`] of each directory stepped through, never by its
/// spelling, so a home reached through any alias still stops the walk.
///
/// # Errors
///
/// [`CliError::TrustRefused`] when the nearest manifest is a link, or another
/// user owns it or could write or replace it; [`CliError::Io`] when it cannot
/// be inspected; [`CliError::DiscoveryLimitReached`] when `max_depth`
/// directories pass with neither a manifest nor a ceiling.
pub fn find_manifest_bounded(
    ipe_file: &Path,
    home: &HomeCeiling,
    max_depth: usize,
) -> Result<Option<PathBuf>, CliError> {
    let mut dir = ipe_file.parent();
    for _ in 0..max_depth {
        let Some(here) = dir else {
            return Ok(None);
        };
        if let Some(manifest) = project::manifest_in_dir(here) {
            crate::owner_trust::admit_discovered_manifest(&manifest)?;
            return Ok(Some(manifest));
        }
        let at_ceiling = home.stops_at(here)
            || VCS_ROOT_MARKERS
                .iter()
                .any(|marker| here.join(marker).symlink_metadata().is_ok());
        if at_ceiling {
            return Ok(None);
        }
        dir = here.parent();
    }
    if dir.is_none() {
        return Ok(None);
    }
    Err(CliError::DiscoveryLimitReached {
        detail: format!(
            "the search for `package.ipe` above `{}` passed the {max_depth}-directory ceiling",
            ipe_file.display()
        ),
    })
}

/// Whether [`compile_modules_observed`] served an on-disk build-cache
/// hit or ran the full compile pipeline. Exists for tests and future CLI
/// verbosity — [`compile_modules`] (used by every stable entry point) does
/// not need it and discards it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CacheOutcome {
    /// A matching, same-epoch [`ipe_backend::EmittedProject`] entry was
    /// found on disk; the whole compile pipeline (parse through emit) was
    /// skipped.
    Hit,
    /// No `EmittedProject`-tier entry existed, but a matching, same-epoch
    /// lowered-[`ipe_ir::Program`] entry was — parse through
    /// lower were skipped; only `RustBackend::emit` ran over the relocated
    /// IR (see `crate::cache`'s lowered-IR module doc section).
    IrHit,
    /// No usable entry existed at either tier (cache disabled, epoch
    /// undeterminable, key miss, or corrupt entry) — the full pipeline ran.
    Miss,
}

/// The shared multi-module compile core: inject the compiled-source stdlib
/// closure, topologically order the graph, canonicalise each module dep-first
/// (with its unforgeable [`ipe_canon::ModuleOrigin`]), link, then infer → lower →
/// emit → write. Both [`build`] and [`build_project`] route through this so the
/// injection seam is identical on the single-file and project paths.
///
/// `blame_path` is the file a cross-file diagnostic with no single owner (an
/// import cycle) is rendered against.
///
/// # Errors
/// [`CliError::Pipeline`] carrying the first compiler diagnostic; [`CliError::Io`]
/// on any filesystem failure.
#[allow(clippy::too_many_arguments)]
pub fn compile_modules(
    sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    discovered: Vec<project::DiscoveredModule>,
    entry_path: &[String],
    target: &EmitTarget,
    runtime_dir: &Path,
    blame_path: &Path,
    db_driver: ipe_backend_rust::DbDriver,
    options: BuildOptions,
) -> Result<OwnedDir, CliError> {
    let cache_site = cache::env_cache_dir(&target.path()?);
    compile_modules_observed(
        sources,
        discovered,
        entry_path,
        target,
        runtime_dir,
        blame_path,
        db_driver,
        cache_site.as_ref(),
        options,
    )
    .0
}

/// [`compile_modules`]'s full implementation, with the on-disk build
/// cache's root made an EXPLICIT parameter (`None` disables the cache
/// entirely) rather than read from the environment internally — the
/// dependency-injection seam this module's tests use instead of
/// `std::env::set_var` (which is `unsafe` as of the standard library's
/// current signature, and this crate is `#![forbid(unsafe_code)]`; a
/// same-process env mutation would also be a cross-test race under a
/// shared-process runner, though `cargo nextest` avoids that specific
/// hazard by isolating tests into their own processes — the explicit
/// parameter avoids both concerns at once).
///
/// Cache flow (see `crate::cache`'s module doc for the full design): the
/// content-address key and version-epoch are computed
/// BEFORE any salsa database exists (driver-boundary only — INV-1: no
/// `std::fs` on a tracked path). On a hit, the ENTIRE compile pipeline
/// (parse through emit) is skipped; only [`write_emitted_project`] runs,
/// materialising the cached [`ipe_backend::EmittedProject`] verbatim. On a
/// miss, the full pipeline runs, and a successful
/// result is best-effort stored for the next invocation.
// `options` is threaded onward by value into the cache-hit / full-pipeline
// branches below (mirroring every sibling `BuildOptions` consumer in this
// file); a `&BuildOptions` parameter would just push the clone this struct's
// `Vec<String>` field (`wasm_public_env`) now needs onto every call site
// instead of the one place that actually reads it.
#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::needless_pass_by_value
)]
pub fn compile_modules_observed(
    mut sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    mut discovered: Vec<project::DiscoveredModule>,
    entry_path: &[String],
    target: &EmitTarget,
    runtime_dir: &Path,
    blame_path: &Path,
    db_driver: ipe_backend_rust::DbDriver,
    cache_site: Option<&cache::CacheSite>,
    options: BuildOptions,
) -> (Result<OwnedDir, CliError>, CacheOutcome) {
    // Inject the transitive compiled-source stdlib closure. `injected` is the
    // driver's unforgeable record of which module paths are trusted stdlib
    // source — the ONLY inputs that earn `ModuleOrigin::EmbeddedStdlib` below.
    let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);

    // The FFI seam: the SAME catalog-load → nominal-unification →
    // interface-inject → emit-assemble sequence `watch` and `lsp` use
    // (`prepare_ffi`) — a divergent copy here once skipped the unification
    // step entirely.
    let ffi_prep = match ffi::prepare_ffi(&mut sources, blame_path) {
        Ok(p) => p,
        Err(e) => return (Err(e), CacheOutcome::Miss),
    };
    let ffi_injected = ffi_prep.injected;
    let ffi_emit = ffi_prep.emit;

    // Resolve the dependency-model runtime crate ONCE, fail-closed: if the
    // opt-in is set but no verified `ipe-runtime-rust` crate root is found, the
    // build refuses loudly here rather than falling back to a vendored — or
    // worse, a wrong — runtime. Native and wasm share the ONE dependency model
    // (the wasm emit selects the crate's `wasm-client` floor + reached surface,
    // built for `wasm32-unknown-unknown`).
    let runtime_dep = if options.runtime_dep {
        match runtime_embed::resolve() {
            Ok(resolved) => Some(ipe_backend_rust::RuntimeDep {
                root: resolved.root().to_path_buf(),
            }),
            Err(e) => return (Err(e), CacheOutcome::Miss),
        }
    } else {
        None
    };

    // The on-disk build caches key only the Ipê sources — the FFI bindings
    // text and opaque map live OUTSIDE that key, so a cache hit could serve a
    // stale emitted project after `ipe add`/`ipe remove`. Disable both cache
    // tiers for FFI-using builds (correctness over warm-start speed).
    // The dependency-model flag also changes emit shape without changing the
    // Ipê sources, so a cache keyed only on sources must not serve a
    // cross-model artifact: disable the caches when the dep model is active.
    let cache_site = if ffi_emit.is_some() || runtime_dep.is_some() {
        None
    } else {
        cache_site
    };

    // The on-disk build cache. `epoch` folds in BOTH the running
    // `ipe` binary's own content hash and the active `rustc`'s fingerprint
    // (see `cache::derive_epoch`'s doc for why this makes
    // "refuse, don't guess" structural rather than a runtime check).
    let cache_key = cache::compute_project_key(
        &sources,
        &injected,
        entry_path,
        db_driver,
        options.target,
        &options.wasm_public_env,
        options.intent,
        options.debugger,
        options.hot_appearance,
        options.webview_host,
        options.webview_window.as_ref(),
    );
    let epoch = cache_site.and_then(|_| cache::derive_epoch());
    if let (Some(site), Some(epoch)) = (cache_site, epoch.as_deref())
        && let Some(emitted) = cache::try_load(site, epoch, &cache_key)
    {
        return (
            write_emitted_project(
                &emitted,
                target,
                runtime_dir,
                options.static_plan.as_ref(),
                options.tree_shake_vendored,
            ),
            CacheOutcome::Hit,
        );
    }

    // The lowered-IR cache tier (see `crate::cache`'s module doc
    // section for the full design). A hit here skips parse -> canon -> link
    // -> infer -> lower ENTIRELY — no `IpeDatabase` is constructed at all —
    // running only `RustBackend::emit` over the relocated `Program` before
    // falling through to the SAME disk-write + tier-1-warming path a full
    // pipeline run uses. The `ir_key` deliberately excludes `db_driver`
    // (`compute_ir_key`'s own doc explains why), so this tier can still hit
    // when the `EmittedProject` tier just missed on a `db_driver`-only edit.
    if let (Some(site), Some(epoch)) = (cache_site, epoch.as_deref()) {
        let ir_key = cache::compute_ir_key(&sources, &injected, entry_path, options.target);
        let fresh_interner: std::sync::Arc<std::sync::Mutex<ipe_intern::Interner>> =
            std::sync::Arc::new(std::sync::Mutex::new(ipe_intern::Interner::new()));
        if let Some(program) = cache::try_load_ir(site, epoch, &ir_key, &fresh_interner) {
            use ipe_backend::Backend as _;
            // Production gate on the IR-cache fast path: this path bypasses
            // `emit_project` (the DB layer where the gate normally runs), so a
            // cached IR that uses a development-only `Debug.*` escape hatch must
            // be rejected here too (IPE-L0140) — otherwise a cached dev artifact
            // could slip through a release build that hits this tier.
            if options.intent == ipe_backend_rust::BuildIntent::Release
                && program.modules.iter().any(|m| m.uses_debug)
            {
                let diag = Diagnostic::Lower {
                    span: ipe_diagnostics::Span::DUMMY,
                    msg: ipe_diagnostics::LowerError::DevOnlyKernelInProduction {
                        kernel: "Debug.*".into(),
                    },
                };
                let (file, src) = entry_blame_source(&sources, entry_path, blame_path);
                return (
                    Err(CliError::Pipeline {
                        file,
                        src,
                        diag: Box::new(diag),
                    }),
                    CacheOutcome::IrHit,
                );
            }
            let emit_result = {
                let guard = fresh_interner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                ipe_backend_rust::RustBackend::new(&guard)
                    .with_db_driver(db_driver)
                    .with_target(options.target)
                    .with_wasm_public_env(options.wasm_public_env.clone())
                    .with_wasm_hydrate_mode(options.wasm_hydrate_mode)
                    .with_runtime_dep(runtime_dep.clone())
                    .with_debugger(options.debugger)
                    .with_project_name(&options.cargo_name)
                    .with_hot_appearance(options.hot_appearance)
                    .with_webview_host(options.webview_host)
                    .with_webview_window(options.webview_window.clone())
                    .with_build_intent(options.intent)
                    .emit(&program)
            };
            if let Ok(emitted) = emit_result {
                let written = write_emitted_project(
                    &emitted,
                    target,
                    runtime_dir,
                    options.static_plan.as_ref(),
                    options.tree_shake_vendored,
                );
                // Warm the (cheaper-to-hit) EmittedProject tier for the
                // next build too — advisory, best-effort, and rooted in the
                // claim the write returned.
                if let Ok(claimed) = &written
                    && let Some(root) = site.root(claimed)
                {
                    cache::store(&root, epoch, &cache_key, &emitted);
                }
                return (written, CacheOutcome::IrHit);
            }
            // A relocated Program that fails to emit is never a build
            // failure from this fast path — fall through to the full
            // pipeline exactly as a tier-2 miss would. This should not
            // happen for a genuinely-cached (not tampered, not epoch-
            // mismatched) entry, but the advisory contract holds
            // regardless of why.
        }
    }

    // Salsa database (see
    // docs/architecture/salsa-incremental-compilation-2026-07-11.md). The
    // driver parses external state ONCE into typed inputs here (`SourceFile`
    // per module + the `SourceRoot` file set); the front-end stages are
    // demanded as memoized queries inside `compile_prepared`. The database is
    // cold and per-invocation, and queries are demanded in the fixed topo
    // order, so the interning sequence — and therefore emitted bytes — is
    // deterministic across runs (golden-suite-enforced).
    let db = ipe_db::IpeDatabase::new();
    let source_root = create_source_root(&db, &sources, &injected, &ffi_injected);
    // The config input (see `ipe_db::BuildConfig`'s doc for why this
    // is narrowed to `db_driver` rather than the full manifest shape). A
    // fresh `BuildConfig` per one-shot invocation is fine here — unlike the
    // clean-vs-incremental parity gate's warm sequence, this driver never
    // re-demands `emit_project` against a second config instance.
    let config = ipe_db::BuildConfig::new(
        &db,
        db_driver,
        ffi_emit,
        options.target,
        options.wasm_public_env.clone(),
        options.wasm_hydrate_mode,
        options.intent,
        runtime_dep,
        options.debugger,
        options.cargo_name.clone(),
        options.hot_appearance,
        options.webview_host,
    );

    let emitted = match compile_prepared(&db, source_root, &sources, entry_path, blame_path, config)
    {
        Ok(emitted) => emitted,
        Err(e) => return (Err(e), CacheOutcome::Miss),
    };

    let written = write_emitted_project(
        &emitted,
        target,
        runtime_dir,
        options.static_plan.as_ref(),
        options.tree_shake_vendored,
    );

    // A writable cache root comes only from the claim the write above
    // returned, so the default in-output cache is never written before
    // the target is proven ipe's.
    if let Ok(claimed) = &written
        && let (Some(site), Some(epoch)) = (cache_site, epoch.as_deref())
        && let Some(root) = site.root(claimed)
    {
        cache::store(&root, epoch, &cache_key, &emitted);
        // Also store the lowered `Program` at the IR tier.
        // `ipe_db::lower_program` is a PURE MEMO HIT here — it already ran
        // (transitively, via `compile_prepared`'s `emit_project` demand
        // chain) inside the salsa database above, so this costs nothing
        // beyond the lookup + relocation-pass serialize. Best-effort: an
        // entry-file lookup failure or a serialize failure never turns a
        // successful build into a reported failure (same advisory contract
        // as the `EmittedProject` tier's own store).
        if let Some(entry_file) = source_root.files(&db).get(entry_path).copied()
            && let Ok(program) = ipe_db::lower_program(&db, source_root, entry_file)
        {
            let ir_key = cache::compute_ir_key(&sources, &injected, entry_path, options.target);
            cache::store_ir(
                &root,
                epoch,
                &ir_key,
                program,
                ipe_db::Db::interner(&db).as_arc(),
            );
        }
    }

    (written, CacheOutcome::Miss)
}

/// Create the salsa inputs for one build: a [`ipe_db::SourceFile`] per module
/// plus the [`ipe_db::SourceRoot`] file set.
///
/// The trust tag: `EmbeddedStdlib` IFF the module path is in `injected` (the
/// driver's unforgeable record from [`project::inject_compiled_std_closure`]).
/// A user file squatting on `Ipe.Foo` is NOT in `injected` (injection skipped
/// it on the pre-existing-key guard), so it is `User` and stays
/// IPE-N0025-rejected.
#[must_use]
pub fn create_source_root(
    db: &ipe_db::IpeDatabase,
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    injected: &std::collections::BTreeSet<Vec<String>>,
    ffi_injected: &std::collections::BTreeSet<Vec<String>>,
) -> ipe_db::SourceRoot {
    let file_handles: BTreeMap<Vec<String>, ipe_db::SourceFile> = sources
        .iter()
        .map(|(mod_path, (_, src))| {
            let origin = if injected.contains(mod_path) {
                ipe_canon::ModuleOrigin::EmbeddedStdlib
            } else if ffi_injected.contains(mod_path) {
                ipe_canon::ModuleOrigin::FfiInterface
            } else {
                ipe_canon::ModuleOrigin::User
            };
            (
                mod_path.clone(),
                ipe_db::SourceFile::new(db, mod_path.clone(), src.clone(), origin),
            )
        })
        .collect();
    ipe_db::SourceRoot::new(db, file_handles)
}

/// Intern each module path in `sources` to build the module-home →
/// `(file, src)` blame map every span-attribution step reads. The lookups run
/// against symbols `canonicalize` already interned, so this cannot append a new
/// symbol and cannot perturb interning order (the golden byte-identity SEAL).
pub fn home_to_source_map(
    interner: &ipe_db::SharedInterner,
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
) -> BTreeMap<Vec<ipe_intern::Symbol>, (PathBuf, String)> {
    let mut guard = interner.lock();
    let mut map = BTreeMap::new();
    for (str_path, (file, src)) in sources {
        let sym_path: Result<Vec<_>, _> = str_path.iter().map(|s| guard.intern(s)).collect();
        if let Ok(sym_path) = sym_path {
            map.insert(sym_path, (file.clone(), src.clone()));
        }
    }
    map
}

/// Map a diagnostic span (byte offsets into its *home* module's source) to the
/// `(file, src)` pair that source is rendered against.
///
/// Every span in a def's body is a byte offset into that def's home module —
/// preserved across `link`. Among all defs whose `body_span` contains the
/// target span, prefer the one whose `body_span.lo` is *closest* to `span.lo`
/// (the def starting nearest the failing expression); width is the secondary
/// tiebreaker (narrower body wins on a tie). Union constructor spans live in
/// the union's home byte-namespace, outside any def body, so they are scanned
/// too — without this a `lower_enum` error (IPE-L0102 / IPE-L0114) would fall
/// back to the entry file at a coincidental byte offset.
///
/// The closest-lo criterion is what keeps this from picking a numerically
/// narrower def in a *different* module (a different byte namespace): same-module
/// defs share a byte namespace, so the intended def almost always has the
/// smaller distance from its own `lo`. Falls back to `entry` when no def or
/// constructor encloses the span (e.g. a `CompilerBug` with `Span::DUMMY`).
///
/// Determinism: both loops walk ORDERED structures (`linked.defs` and
/// `linked.unions` are `Vec`s in dependency-first link order), and the winner is
/// chosen by a total order — `(lo_dist, width, home)` — whose final `home` key
/// breaks a `(lo_dist, width)` tie so two enclosers in different modules always
/// resolve to the same file, byte-stably across runs. Without the `home`
/// tie-break the first-seen encloser would win, making attribution depend on
/// `defs` order for a genuinely homeless (`home.is_empty()`) diagnostic.
pub fn source_for_span_in_linked(
    linked: &ipe_canon::ast::Module,
    home_to_source: &BTreeMap<Vec<ipe_intern::Symbol>, (PathBuf, String)>,
    entry: &(PathBuf, String),
    span: ipe_diagnostics::Span,
) -> (PathBuf, String) {
    if span == ipe_diagnostics::Span::DUMMY {
        return entry.clone();
    }
    // (lo_dist, width, home)
    let mut best: Option<(u32, u32, &[ipe_intern::Symbol])> = None;
    for def in &linked.defs {
        let body_span = match def {
            ipe_canon::ast::Def::Untyped { body, .. } | ipe_canon::ast::Def::Typed { body, .. } => {
                body.span
            }
        };
        if body_span.lo <= span.lo && span.hi <= body_span.hi {
            let lo_dist = span.lo.saturating_sub(body_span.lo);
            let width = body_span.hi.saturating_sub(body_span.lo);
            let home = def.home();
            if best.is_none_or(|(prev_dist, prev_w, prev_home)| {
                (lo_dist, width, home) < (prev_dist, prev_w, prev_home)
            }) {
                best = Some((lo_dist, width, home));
            }
        }
    }
    for union in &linked.unions {
        for ctor in &union.ctors {
            if ctor.span.lo <= span.lo && span.hi <= ctor.span.hi {
                let lo_dist = span.lo.saturating_sub(ctor.span.lo);
                let width = ctor.span.hi.saturating_sub(ctor.span.lo);
                let home = union.home.as_slice();
                if best.is_none_or(|(prev_dist, prev_w, prev_home)| {
                    (lo_dist, width, home) < (prev_dist, prev_w, prev_home)
                }) {
                    best = Some((lo_dist, width, home));
                }
            }
        }
    }
    best.and_then(|(_, _, home)| home_to_source.get(home))
        .cloned()
        .unwrap_or_else(|| entry.clone())
}

/// Attribute a post-link pipeline error to the source file that OWNS it.
///
/// A type-checker error is framed by [`frame_infer_error`]: its typed home
/// names the file exactly, and no byte offset is consulted. A link or lowering
/// error with a non-empty `home` resolves DIRECTLY via `home_to_source`; only
/// one with an empty home falls back to the byte-offset heuristic over the
/// linked program. This is the single attribution rule every post-link
/// pipeline error shares, so `ipe build` and `ipe type-check` frame the
/// identical diagnostic against the identical source.
pub fn attribute_post_link_error(
    linked: &ipe_canon::ast::Module,
    home_to_source: &BTreeMap<Vec<ipe_intern::Symbol>, (PathBuf, String)>,
    entry: &(PathBuf, String),
    err: ipe_db::PipelineError,
) -> CliError {
    match err {
        ipe_db::PipelineError::Infer(infer) => frame_infer_error(home_to_source, entry, infer),
        ipe_db::PipelineError::Lower(diag, home) => {
            let (file, src) = if home.is_empty() {
                source_for_span_in_linked(linked, home_to_source, entry, diag_span(&diag))
            } else {
                home_to_source.get(&home).cloned().unwrap_or_else(|| {
                    source_for_span_in_linked(linked, home_to_source, entry, diag_span(&diag))
                })
            };
            CliError::Pipeline {
                file,
                src,
                diag: Box::new(diag),
            }
        }
    }
}

/// Frame a type-checker error against the file its typed home names.
///
/// A sited error resolves exactly through `home_to_source`. A home naming no
/// module there is refused as [`Diagnostic::CompilerBug`] blamed on `entry`,
/// never handed to a byte-offset guess. A whole-program error is framed against
/// the entry with no snippet, since it belongs to no single source.
pub fn frame_infer_error(
    home_to_source: &BTreeMap<Vec<ipe_intern::Symbol>, (PathBuf, String)>,
    entry: &(PathBuf, String),
    err: ipe_types::InferError,
) -> CliError {
    match err {
        ipe_types::InferError::Sited { diag, home } => home_to_source.get(home.path()).map_or_else(
            || CliError::Pipeline {
                file: entry.0.clone(),
                src: entry.1.clone(),
                diag: Box::new(Diagnostic::CompilerBug {
                    where_: "driver.frame_infer_error",
                    detail: "a type-checker error names a module with no source file".to_owned(),
                }),
            },
            |(file, src)| CliError::Pipeline {
                file: file.clone(),
                src: src.clone(),
                diag: Box::new(diag),
            },
        ),
        ipe_types::InferError::Program(program) => CliError::Pipeline {
            file: entry.0.clone(),
            src: String::new(),
            diag: Box::new(program.into_diagnostic()),
        },
    }
}

/// Render each type-checker warning against the source file of its home module.
///
/// A [`ipe_types::HomedWarning`] always names its owning module, so the file is
/// looked up exactly in `home_to_source`; no span-based guess is involved.
///
/// # Errors
/// [`CliError::Pipeline`] carrying [`Diagnostic::CompilerBug`] (blamed on
/// `entry`) when a warning's home names no module in `home_to_source`: the
/// warning cannot be framed against its own file, so the build fails closed.
pub fn render_homed_warnings(
    home_to_source: &BTreeMap<Vec<ipe_intern::Symbol>, (PathBuf, String)>,
    entry: &(PathBuf, String),
    warnings: &[ipe_types::HomedWarning],
) -> Result<Vec<String>, CliError> {
    warnings
        .iter()
        .map(|warning| {
            let (file, src) =
                home_to_source
                    .get(warning.home())
                    .ok_or_else(|| CliError::Pipeline {
                        file: entry.0.clone(),
                        src: entry.1.clone(),
                        diag: Box::new(Diagnostic::CompilerBug {
                            where_: "driver.render_homed_warnings",
                            detail: "a type-checker warning names a module with no source file"
                                .to_owned(),
                        }),
                    })?;
            Ok(render(warning.diagnostic(), &file.to_string_lossy(), src))
        })
        .collect()
}

/// Run the canon decoder-pipeline direction gate (IPE-N0040) over the linked
/// program, returning the rejection in the post-link [`ipe_db::PipelineError`]
/// shape both the build and the type-check surfaces attribute through.
///
/// The gate rejects the reverse-associated hand-nested spelling of the
/// `required` / `optional` / `requiredAt` / `custom` decoder combinators, which
/// silently swaps two same-typed fields with no type error. It runs on the
/// LINKED module so a decoder split across modules is still seen whole. Both
/// [`compile_prepared`] (the build/lower/emit path) and the `ipe type-check`
/// flow call THIS one helper, so the two surfaces cannot drift on whether the
/// footgun is caught. The returned `home` is empty: the diagnostic's own span
/// carries the offending source location, resolved by the byte-offset heuristic
/// the other homeless post-link errors already use.
pub fn gate_decoder_pipelines(
    linked: &ipe_canon::ast::Module,
) -> Result<(), ipe_db::PipelineError> {
    ipe_canon::decoder_pipeline_gate::check_decoder_pipelines(linked)
        .map_err(|diag| ipe_db::PipelineError::Lower(diag, Vec::new()))
}

/// Demand `canonicalize` for every module in dep-first order, attributing a
/// canon error (e.g. IPE-N0020 module-not-found) to the source file of the
/// module that produced it. A canon error fires *before* `link`, so there is no
/// linked program to run the byte-offset heuristic against; the module whose
/// `canonicalize` fails IS the owner, so blaming that module's `(path, src)` is
/// exact.
///
/// On the build path these demands are the memoized inputs `linked_program`
/// re-uses; running the loop here first (also on the `check`/analysis paths)
/// makes a canon-error diagnostic frame against its own file on every surface.
///
/// # Errors
/// [`CliError::Pipeline`] carrying the first module's canon error;
/// [`CliError::Usage`] if a topo-ordered module is absent from the source map.
pub fn attribute_canon_errors(
    db: &ipe_db::IpeDatabase,
    source_root: ipe_db::SourceRoot,
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    entry_file: ipe_db::SourceFile,
    blame_path: &Path,
) -> Result<(), CliError> {
    let topo = ipe_db::topo_order(db, source_root, entry_file)
        .clone()
        .map_err(|diag| CliError::Pipeline {
            file: blame_path.to_path_buf(),
            src: String::new(),
            diag: Box::new(diag),
        })?;
    for mod_path in topo.iter() {
        let Some((path, src)) = sources.get(mod_path) else {
            return Err(CliError::Usage(
                text::msg::internal_module_not_in_source_map(),
            ));
        };
        let Some(file_handle) = source_root.files(db).get(mod_path).copied() else {
            return Err(CliError::Usage(
                text::msg::internal_module_not_in_source_map(),
            ));
        };
        ipe_db::canonicalize(db, source_root, file_handle)
            .clone()
            .map_err(|diag| CliError::Pipeline {
                file: path.clone(),
                src: src.clone(),
                diag: Box::new(diag),
            })?;
    }
    Ok(())
}

/// The project root a `customElement "<js-path>"` literal resolves against: the
/// directory holding the entry file, the same root sibling module discovery uses.
///
/// Canon refuses a `..`-escaping literal (IPE-P0063) and an absolute/rooted one
/// (IPE-N0044), so the joined path is lexically inside this root. That is
/// necessary but NOT sufficient: a symlink UNDER the root can still point outside
/// it, so the caller additionally canonicalises the join and asserts containment
/// (`starts_with` the canonical root) before trusting it — the lexical seals and
/// the resolved-path containment check are independent layers.
pub fn widget_file_root(entry_src_path: &Path) -> &Path {
    entry_src_path
        .parent()
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| Path::new("."))
}

/// Two distinct widget-hook paths that hashed to one custom-element tag.
pub struct WidgetTagCollision {
    pub existing_path: String,
    pub new_path: String,
}

/// Record `cleaned_path` as the origin of `tag`, or report a collision.
///
/// The custom-element tag is a 64-bit FNV-1a digest, which is not collision-free.
/// Two DISTINCT hook paths hashing to one tag must fail the build closed rather
/// than let a tag-keyed manifest silently serve one widget's code under the
/// other's element name. Re-recording the SAME path for a tag is the legitimate
/// dedup of two view nodes of one widget and is accepted.
pub fn record_widget_tag_origin(
    origins: &mut BTreeMap<String, String>,
    tag: &str,
    cleaned_path: &str,
) -> Result<(), WidgetTagCollision> {
    match origins.get(tag) {
        Some(existing) if existing != cleaned_path => Err(WidgetTagCollision {
            existing_path: existing.clone(),
            new_path: cleaned_path.to_owned(),
        }),
        Some(_) => Ok(()),
        None => {
            origins.insert(tag.to_owned(), cleaned_path.to_owned());
            Ok(())
        }
    }
}

/// The entry module's path and text, which an entry-blamed diagnostic renders against.
///
/// The text comes from the source map the build already read under its
/// bounds, never from a second disk read. An entry absent from `sources`
/// yields `blame_path` with empty text.
fn entry_blame_source(
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    entry_path: &[String],
    blame_path: &Path,
) -> (PathBuf, String) {
    sources.get(entry_path).map_or_else(
        || (blame_path.to_path_buf(), String::new()),
        |(path, text)| (path.clone(), text.clone()),
    )
}

/// The in-memory compile core over an already-populated database.
///
/// topo order → per-module canonicalisation (memoized, blame-attributed) →
/// [`ipe_db::linked_program`] (the coarse whole-program spine) → infer → lower →
/// emit. Returns the emitted project without touching the filesystem.
///
/// This is THE production pipeline — [`compile_modules`] wraps it with input
/// creation and disk writes, and the clean-vs-incremental parity gate
/// drives it against both cold and warm databases, so the gate can
/// never test a divergent copy of the pipeline.
///
/// `sources` is consulted for diagnostic blame only (module path → file/src).
///
/// `config` is the [`ipe_db::BuildConfig`] handle — callers that
/// re-demand `compile_prepared` across a warm sequence (the parity
/// gate) MUST hold one stable `BuildConfig` across the sequence rather than
/// constructing a fresh one per call, or `emit_project`'s memo key never
/// matches between calls and the seam's memoization is silently defeated.
///
/// # Errors
/// [`CliError::Pipeline`] carrying the first compiler diagnostic.
#[allow(clippy::too_many_lines)]
pub fn compile_prepared(
    db: &ipe_db::IpeDatabase,
    source_root: ipe_db::SourceRoot,
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    entry_path: &[String],
    blame_path: &Path,
    config: ipe_db::BuildConfig,
) -> Result<ipe_backend::EmittedProject, CliError> {
    // The build-wide interner is owned by the database (Option 3a) so the
    // parse query and the non-salsa passes share one symbol table. NEVER hold
    // a lock guard across a salsa query demand (the mutex is not reentrant).
    let shared_interner = ipe_db::Db::interner(db).clone();

    let Some(entry_file) = source_root.files(db).get(entry_path).copied() else {
        return Err(CliError::Usage(
            text::msg::internal_entry_not_in_source_map(),
        ));
    };

    // Canonicalise each module in dep-first order, attributing a canon error
    // (e.g. IPE-N0020) to its own module's file — the SAME blame loop the
    // `check`/analysis surfaces reuse (`attribute_canon_errors`), so a
    // canon-error diagnostic frames against its own file on every surface.
    // `linked_program` below re-demands these memos.
    attribute_canon_errors(db, source_root, sources, entry_file, blame_path)?;

    // Link → infer → lower → emit on the merged module. Blame link/lower/emit
    // errors on the entry file; infer errors and warnings are attributed to the
    // dep module that owns the failing span.
    let (entry_src_path, entry_src) = entry_blame_source(sources, entry_path, blame_path);
    let pipeline_err = |diag: ipe_diagnostics::Diagnostic| CliError::Pipeline {
        file: entry_src_path.clone(),
        src: entry_src.clone(),
        diag: Box::new(diag),
    };

    // The coarse whole-program spine: every per-module canonical result
    // assembled + linked inside salsa. All
    // `canonicalize` demands above are memo hits here. The link step gates
    // cross-module type-identity duplicates `(home, name)`, blamed on
    // the entry file like every other post-link diagnostic.
    let linked_program = ipe_db::linked_program(db, source_root, entry_file)
        .clone()
        .map_err(&pipeline_err)?;
    let linked = &linked_program.module;

    // The fresh-name collision universe for this build: the identifier words
    // of the CURRENT program — a pure function of the source inputs, so the
    // lowering pools (`eta_*`, `cap_*`, …) mint the SAME names on a warm
    // (reused) database as on a cold one. Interner-membership minting would
    // skip the previous build's pool names and drift the emitted bytes — the
    // exact divergence the clean-vs-incremental parity gate guards against.
    let mut fresh_avoid: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for file in source_root.files(db).values() {
        fresh_avoid.extend(ipe_db::identifier_words(db, *file).iter().cloned());
    }

    // Set the fresh-name avoid-set (must happen before `lower_program` may
    // execute below). Short lock scope: the guard is dropped before any further
    // salsa query is demanded — the interner mutex is not reentrant, and
    // `typecheck`/`lower_program` each take their own lock internally.
    {
        let mut interner = shared_interner.lock();
        interner.set_fresh_avoid(fresh_avoid);
    }

    // The module-home → (file, src) blame map, and the span-attribution helper
    // built on it — the SAME resolution the `check`/analysis surfaces reuse (via
    // `attribute_post_link_error`), so every surface frames a given diagnostic
    // against the identical source.
    let home_to_source = home_to_source_map(&shared_interner, sources);
    let entry = (entry_src_path.clone(), entry_src.clone());
    let source_for_span = |span: ipe_diagnostics::Span| -> (PathBuf, String) {
        source_for_span_in_linked(linked, &home_to_source, &entry, span)
    };

    // Widget-file gate (IPE-N0044, Security #1). The `customElement` constructor's
    // shape + lexical path seals (traversal IPE-P0063, absolute/rooted IPE-N0044)
    // already ran in canon; here — the one stage that owns the project root — two
    // FILESYSTEM invariants are enforced, defence-in-depth against the lexical
    // seals:
    //   1. Containment: the resolved path must lie strictly INSIDE the project
    //      root. `ContainedRelPath::parse` canonicalises the join and asserts it
    //      is a descendant of the canonical root, so a symlink UNDER the root that
    //      points OUTSIDE it (which the lexical seals cannot see) is refused. A
    //      bare `Path::join`/`is_file` would instead FOLLOW that symlink and stat
    //      an out-of-project file — the escape this check closes.
    //   2. Existence: the contained path must name a real file, so a widget never
    //      registers against a file that is not there.
    // Both fail closed with IPE-N0044; the widget seam never reaches emission on
    // an out-of-project or absent file.
    let widget_root = widget_file_root(&entry_src_path);
    // The program's widget manifest: one entry per DISTINCT reached
    // `customElement "<path>"`, carrying the lowerer-minted `ipe-ce-<hex>` tag
    // (so the served-glue registration targets the SAME tag the view node
    // renders) and the author hook file's verbatim content (WP5 serves it
    // content-addressed + SRI). Populated as the containment/existence gate
    // proves each file; deduplicated by tag so two views of one widget register
    // once. Empty for a program that uses no `CustomElement.node`.
    let mut widget_manifest: BTreeMap<String, String> = BTreeMap::new();
    // The cleaned path that first minted each tag. The tag is a 64-bit FNV-1a
    // digest, so two DISTINCT hook paths can collide onto one tag; keying the
    // manifest by tag alone would then silently drop the second widget's JS and
    // serve the first's code under both view nodes. Recording the origin path
    // lets a collision from a distinct path fail the build closed instead.
    let mut tag_origin: BTreeMap<String, String> = BTreeMap::new();
    for widget in ipe_canon::custom_element_gate::collect_widget_files(linked) {
        let reject = |detail: String| {
            let (file, src) = source_for_span(widget.span);
            CliError::Pipeline {
                file,
                src,
                diag: Box::new(ipe_diagnostics::Diagnostic::Name {
                    span: widget.span,
                    msg: ipe_diagnostics::NameError::CustomElementCtorMalformed {
                        detail: detail.into_boxed_str(),
                    },
                }),
            }
        };
        let contained = contained_path::ContainedRelPath::parse(widget_root, &widget.cleaned_path)
            .map_err(|_| {
                reject(format!(
                    "the widget-hook file `{}` resolves outside the project directory \
                         (an absolute path, a `..` climb, or a symlink pointing above the \
                         project root) and is refused",
                    widget.cleaned_path
                ))
            })?;
        if !contained.resolved().is_file() {
            return Err(reject(format!(
                "the widget-hook file `{}` does not exist in the project",
                widget.cleaned_path
            )));
        }
        // Read the verified in-project file's content for content-addressed +
        // SRI serving. `resolved()` is the containment-checked canonical path, so
        // this read stays strictly inside the project root. A read failure (a
        // race that removed the file between the `is_file` check and here, or a
        // permission fault) fails the build closed — the widget seam never
        // reaches emission on a file we could not read whole.
        let content = std::fs::read_to_string(contained.resolved()).map_err(|e| {
            reject(format!(
                "the widget-hook file `{}` could not be read: {e}",
                widget.cleaned_path
            ))
        })?;
        // The tag is the SINGLE lowerer definition, keyed on the same cleaned
        // path the view node hashed — never a second, drift-prone hash here.
        let tag = ipe_lower::custom_element_tag(&widget.cleaned_path);
        if let Err(collision) =
            record_widget_tag_origin(&mut tag_origin, &tag, &widget.cleaned_path)
        {
            return Err(reject(format!(
                "the widget-hook files `{}` and `{}` hash to the same \
                 custom-element tag `{tag}`; register one under a distinct \
                 path so their element names cannot collide",
                collision.existing_path, collision.new_path
            )));
        }
        widget_manifest.entry(tag).or_insert(content);
    }

    // Layer-2 wasm security gate (IPE-N0030, M5): the client entry's
    // reachability closure must not transitively reach a server-classified
    // module. Runs BEFORE Layer 1 so a reachability violation gets the
    // friendlier exact-chain message; Layer 1 remains the flat,
    // defense-in-depth backstop for everything this closure does not cover
    // (e.g. a server kernel named directly in the entry's own module).
    // `linked.name` is the client entry's module path for today's
    // single-entry `--target wasm` build (a distinct `[wasm].entry` module
    // takes the same role once the M6 integration wires a separate client
    // entry through).
    if *config.target(db) == ipe_ir::Target::WasmClient {
        let gate_result = {
            let interner = shared_interner.lock();
            ipe_canon::module_classify::check_client_reachability(linked, &linked.name, &interner)
        };
        gate_result.map_err(|diag| {
            let span = diag_span(&diag);
            let (file, src) = source_for_span(span);
            CliError::Pipeline {
                file,
                src,
                diag: Box::new(diag),
            }
        })?;
    }

    // Layer-1 wasm security gate (IPE-N0029): under `--target wasm`, every
    // kernel named anywhere in the linked program must be on the WasmClient
    // allowlist. Runs on the LINKED module (everything linked is emitted, so
    // a denied kernel anywhere would otherwise become a cargo failure — THE
    // SEAL — or a secret consumer in a public bundle). Blame via the same
    // span→file heuristic the type errors use.
    if *config.target(db) == ipe_ir::Target::WasmClient {
        let gate_result = {
            let interner = shared_interner.lock();
            ipe_canon::target_gate::check_wasm_client(linked, &interner)
        };
        gate_result.map_err(|diag| {
            let span = diag_span(&diag);
            let (file, src) = source_for_span(span);
            CliError::Pipeline {
                file,
                src,
                diag: Box::new(diag),
            }
        })?;
    }

    // Co-located WASI (`wasm32-wasip1`) sealed-floor gate: the build-boundary
    // backstop to the delivery matrix's shape gate. Every kernel named anywhere
    // in the linked program must be on the WASI-viable sealed floor
    // (`available_on(WasmWasi)`); a kernel outside it has no wasip1 runtime
    // symbol, so this refusal replaces a `cargo build --target wasm32-wasip1`
    // failure (THE SEAL). Defense in depth: even a kernel reached through a path
    // the shape gate does not model is turned back here at `ipe` time.
    if *config.target(db) == ipe_ir::Target::WasmWasi {
        let gate_result = {
            let interner = shared_interner.lock();
            ipe_canon::target_gate::check_wasm_wasi(linked, &interner)
        };
        gate_result.map_err(|diag| {
            let span = diag_span(&diag);
            let (file, src) = source_for_span(span);
            CliError::Pipeline {
                file,
                src,
                diag: Box::new(diag),
            }
        })?;
    }

    // Every type-checker error names its owning module by construction, so it
    // is framed by an exact `home_to_source` lookup; a span's byte offsets are
    // shared by every linked module and never select its file.
    //
    // `ipe_db::typecheck` is the memoized
    // SEAM over `ipe_types::infer_attributed`: same whole-program computation,
    // skippable on a warm no-op rebuild. No interner guard is held across
    // this demand — the query takes its own lock internally.
    let types = ipe_db::typecheck(db, source_root, entry_file)
        .clone()
        .map_err(|err| attribute_post_link_error(linked, &home_to_source, &entry, err.into()))?;
    // Print non-fatal warnings (e.g. IPE-T0011 RedundantCaseBranch) to stderr,
    // each framed against its home module's file. These are Severity::Warning:
    // the build continues and exit code stays 0.
    for rendered in render_homed_warnings(&home_to_source, &entry, &types.warnings)? {
        crate::screen::chatter_styled(crate::screen::Stream::Stderr, &rendered);
    }
    // Attribute lower / backend diagnostics to the source file that OWNS the
    // failing span, not blindly to the entry file. After link, every module's
    // defs keep their original `home` byte-namespace, so a bare `pipeline_err`
    // (which always blames the entry file) mis-renders a dep-module diagnostic
    // against the entry file at a coincidental byte offset — e.g. a State.ipe
    // IPE-L0115 shown at an unrelated Main.ipe line. `source_for_span` maps the
    // span back to its owning def's file, the same heuristic already used for
    // homeless constraint-gen type errors.
    // Lowering (and emit) errors carry the owning def's `home`,
    // exactly like `typecheck` above. When `home` is non-empty we resolve the
    // source file DIRECTLY via `home_to_source` (O(log N), exact) — this is what
    // makes a Server.ipe IPE-L0126 render against Server.ipe, not against a
    // Main.ipe def whose byte range coincidentally overlaps the failing span.
    // An empty `home` (homeless backend diagnostic, or a pre-def lowering
    // error) falls back to the byte-offset heuristic `source_for_span`.
    let span_attributed_err = |err: ipe_db::PipelineError| {
        attribute_post_link_error(linked, &home_to_source, &entry, err)
    };
    let homed_err = |(diag, home): (Diagnostic, Vec<ipe_intern::Symbol>)| {
        span_attributed_err(ipe_db::PipelineError::Lower(diag, home))
    };

    // Decoder-pipeline direction gate (IPE-N0040): reject the hand-nested
    // `required`/`optional`/`requiredAt`/`custom` spelling that silently
    // reverses field→constructor binding. Runs on the linked module, framed
    // against the owning source like every other post-link diagnostic. The
    // IDENTICAL gate runs on the `ipe type-check` path (both call
    // `gate_decoder_pipelines`), so the footgun is caught on every pre-ship
    // surface, not just the build.
    gate_decoder_pipelines(linked).map_err(span_attributed_err)?;

    // `ipe_db::program_metadata` — the whole-program DCE-reachability seam
    // over `lower_program`.
    // Its own dependency on `lower_program` is what forces the lowering pass
    // to execute here; a standalone `lower_program` demand alongside this one
    // would be a redundant duplicate of the SAME memoized query (its error
    // maps through the same `span_attributed_err` closure either way).
    // Demanded here, on the production path, purely as a FORWARD SEAM:
    // nothing downstream consumes its value yet (no pruning pass exists —
    // see the query's own doc for the honestly-recorded scope), matching the
    // `kernel_types` precedent (materialized and proven memoized
    // before it has a real consumer). The demand costs nothing observable in
    // emitted bytes — the point is to put the query on the same path the
    // clean-vs-incremental parity gate drives, so a future divergence in this
    // analysis cannot go undetected.
    ipe_db::program_metadata(db, source_root, entry_file)
        .clone()
        .map_err(homed_err)?;

    // `ipe_db::emit_manifest` (design doc §4.4) — the top-level
    // emit demand, assembled from the per-`RustFileId` query graph:
    // `program_rust_file_ids` + `emit_spine_file` + one `emit_rust_file` per
    // home. For a single-module program it routes straight to `emit_project`
    // (byte-identical Spine-collapse); for a genuine 2+-home program it
    // assembles the split from those per-file memos, so a body edit to an
    // UNRELATED module early-cuts that module's `emit_rust_file` (byte-identical
    // value → salsa backdate → the on-disk write skips, §4.3). The
    // `EmitResult` SHAPE matches a plain `emit_project` demand, so
    // `build_emit_manifest`/`reconcile_emitted_project`/`prune_orphaned_files`
    // need zero changes (§4.4). The no-op-rebuild + `db_driver`-only
    // memoization properties `phase6_build_config.rs` proves hold — the
    // config field flows through unchanged.
    let emitted = ipe_db::emit_manifest(db, source_root, entry_file, config)
        .clone()
        .map_err(homed_err)?;
    let mut emitted = (*emitted).clone();

    // Thread the widget manifest into the emitted program. The emit query is a
    // pure function of the source text and cannot read the widget files off disk
    // (INV-1: no salsa query touches the filesystem); this stage owns the project
    // root and already read each file above, so it wires the transport here.
    //
    // Two transports, one manifest:
    //  * Native (server-driven Web) — inject the one-time `widget_assets::register`
    //    into `main`, so the runtime serves each asset content-addressed + SRI and
    //    generates the attribute/POST glue at process start.
    //  * WasmClient (browser client) — there is no server to serve routes, so the
    //    static bundle carries the assets: write each author file + the generated
    //    property/CustomEvent glue into `www/`, SRI-pinned, and reference them from
    //    the static `index.html`. The in-process wasm sink delivers down-state as a
    //    decoded property and folds up-`CustomEvent`s into `update`.
    //
    // A widget-free program injects nothing under either target (byte-identical
    // emit).
    if !widget_manifest.is_empty() {
        match config.target(db) {
            // Co-located WASI carries no widget surface (a `Direct` script has no
            // `Web`/DOM shape), so it shares the native (no browser bundle) arm.
            ipe_ir::Target::Native | ipe_ir::Target::WasmWasi => {
                inject_widget_registration(&mut emitted, &widget_manifest)?;
            }
            ipe_ir::Target::WasmClient => {
                inject_wasm_widget_bundle(&mut emitted, &widget_manifest)?;
            }
        }
    }
    Ok(emitted)
}

/// Inject the process-start `CustomElement.node` asset registration into the emitted
/// `main.rs`, so the served app registers its widget assets before the web
/// server binds.
///
/// The registration is a single `ipe_runtime::web::widget_assets::register(&[…])`
/// call spliced in right after `install_panic_classifier();` in the generated
/// `main()` — the first line of the entry point, before any task runs. Each
/// `(tag, content)` is rendered as a Rust string-literal pair through the
/// backend's one literal owner, `rust_str_lit`, which escapes every scalar the
/// literal grammar cannot carry raw (`"`, `\`, a lone CR, a bidi override), so
/// arbitrary JS is a valid literal rustc accepts and no author byte can break
/// out of the string into code (the content is DATA in the emitted program,
/// exactly as it is data in the browser).
///
/// # Errors
/// [`CliError`] carrying a [`Diagnostic::CompilerBug`] if `src/main.rs` is absent
/// from the emitted file set or the `install_panic_classifier();` anchor the
/// splice keys on is missing — a drifted emit template, surfaced loudly rather
/// than silently emitting a program that never registers its widgets.
pub fn inject_widget_registration(
    emitted: &mut ipe_backend::EmittedProject,
    manifest: &BTreeMap<String, String>,
) -> Result<(), CliError> {
    // The splice point: the first line of the generated `main()`, before any task
    // runs, so the registry is populated before the web server binds.
    const ANCHOR: &str = "install_panic_classifier();";
    let bug = |detail: &str| CliError::Pipeline {
        file: PathBuf::from("src/main.rs"),
        src: String::new(),
        diag: Box::new(ipe_diagnostics::Diagnostic::CompilerBug {
            where_: "ipe_cli::inject_widget_registration",
            detail: detail.to_owned(),
        }),
    };
    let main = emitted
        .files
        .get_mut("src/main.rs")
        .ok_or_else(|| bug("no src/main.rs in the emitted file set for widget registration"))?;

    // Build the `register(&[(tag, content), …])` argument list. Deterministic
    // order (BTreeMap iteration) keeps the emit byte-stable across builds.
    let mut entries = String::new();
    for (tag, content) in manifest {
        entries.push_str("        (");
        entries.push_str(&rust_str_lit(tag));
        entries.push_str(", ");
        entries.push_str(&rust_str_lit(content));
        entries.push_str("),\n");
    }
    let call = format!("\n    ipe_runtime::web::widget_assets::register(&[\n{entries}    ]);\n");

    let Some(pos) = main.find(ANCHOR) else {
        return Err(bug(
            "the emitted main() is missing the `install_panic_classifier();` anchor the widget \
             registration splices after — the emit template drifted",
        ));
    };
    let insert_at = pos + ANCHOR.len();
    main.insert_str(insert_at, &call);
    Ok(())
}

/// Assemble the browser-client widget bundle into the emitted static SPA.
///
/// The `WasmClient` target has no server to mount asset routes, so the assets
/// ride the static `www/` tree. This writes, for the widget manifest:
///
///  * each author hook file at `www/_ipe/widget.<hex16>.js` (content-addressed,
///    so a page pinning its SRI can never be served different bytes);
///  * the generated registration glue at `www/_ipe/widget-glue.<hex16>.js`
///    (the `WasmClient` transport: down as a decoded property, up as a typed
///    `CustomEvent`) — produced by the SAME `ipe_runtime::widget_assets` generator
///    the server path serves, so there is one glue, not a drift-prone twin;
///  * SRI-pinned `<link rel="modulepreload">` + glue `<script type="module">`
///    references spliced into `www/index.html` before `</head>`.
///
/// The hash the page pins is `sha256` over the served bytes (§ `widget_assets`),
/// so page integrity == served bytes for the static target exactly as for the
/// server. `base` is empty: the static SPA is root-mounted, so the absolute
/// `/_ipe/…` asset URLs resolve against the `www/` document root.
///
/// # Errors
/// [`CliError`] carrying a [`Diagnostic::CompilerBug`] if `www/index.html` is
/// absent from the emitted file set or lacks the `</head>` anchor — a drifted
/// wasm emit template, surfaced loudly.
pub fn inject_wasm_widget_bundle(
    emitted: &mut ipe_backend::EmittedProject,
    manifest: &BTreeMap<String, String>,
) -> Result<(), CliError> {
    use ipe_runtime_rust::widget_assets::{
        WidgetAsset, WidgetTransport, glue_js_for, glue_path_for, page_scripts_for,
        widget_asset_path,
    };

    // The static SPA is root-mounted; the `/_ipe/…` asset URLs are document-root
    // absolute, so the `www/`-relative file path drops the leading slash.
    const BASE: &str = "";
    const TRANSPORT: WidgetTransport = WidgetTransport::WasmClient;
    const HEAD_CLOSE: &str = "</head>";

    let bug = |detail: String| CliError::Pipeline {
        file: PathBuf::from("www/index.html"),
        src: String::new(),
        diag: Box::new(ipe_diagnostics::Diagnostic::CompilerBug {
            where_: "ipe_cli::inject_wasm_widget_bundle",
            detail,
        }),
    };
    let rel = |p: &str| -> Result<ipe_backend::RelPath, CliError> {
        ipe_backend::RelPath::new(p.to_owned()).map_err(|_| {
            bug(format!(
                "the generated widget asset path `{p}` is not a valid in-project relative path"
            ))
        })
    };

    // Rebuild the explicit asset slice (deterministic BTreeMap order → byte-stable
    // emit) the registry-free generator consumes.
    let assets: Vec<WidgetAsset> = manifest
        .iter()
        .map(|(tag, content)| WidgetAsset {
            tag: tag.clone(),
            content: content.clone(),
        })
        .collect();

    // Write each author hook file content-addressed under `www/`. `widget_asset_path`
    // yields the absolute URL path `/_ipe/widget.<hex16>.js`; strip the leading
    // `/` for the `www/`-relative file key.
    for asset in &assets {
        let url_path = widget_asset_path(&asset.content);
        let file_path = format!("www{url_path}");
        emitted
            .files
            .insert(rel(&file_path)?, asset.content.clone());
    }

    // Write the generated glue (WasmClient transport) content-addressed under `www/`.
    let glue_url = glue_path_for(&assets, BASE, TRANSPORT);
    let glue_body = glue_js_for(&assets, BASE, TRANSPORT);
    emitted
        .files
        .insert(rel(&format!("www{glue_url}"))?, glue_body);

    // Splice the SRI-pinned preload + glue script references into `index.html`
    // before `</head>` (external + SRI + crossorigin — no inline script, so the
    // static shell's CSP `script-src 'self' 'wasm-unsafe-eval'` is unchanged).
    let scripts = page_scripts_for(&assets, BASE, TRANSPORT);
    let index = emitted
        .files
        .get_mut("www/index.html")
        .ok_or_else(|| bug("no www/index.html in the emitted wasm file set".to_owned()))?;
    let Some(pos) = index.find(HEAD_CLOSE) else {
        return Err(bug(
            "the emitted www/index.html is missing the `</head>` anchor the widget bundle \
             splices before — the wasm emit template drifted"
                .to_owned(),
        ));
    };
    index.insert_str(pos, &scripts);
    Ok(())
}

/// Write an emitted project to `target`, vendoring the runtime module tree
/// from `runtime_dir`.
///
/// The emit→cargo bridge (design doc H7/H8):
/// assembles the COMPLETE intended project (`build_emit_manifest`) — the
/// vendored runtime tree, `Cargo.toml`, and every backend-emitted file — then
/// [`reconcile_emitted_project`] writes only what changed (content-gated,
/// atomic tmp-then-rename) and deletes anything under the target's `src` the
/// manifest no longer names (manifest-driven prune). On an unchanged rebuild
/// this writes NOTHING; `cargo` therefore sees no mtime churn and does not
/// invalidate its own build cache. This is a pure driver-boundary filesystem
/// operation — no salsa query touches disk (INV-1).
///
/// Under a static plan (see `docs/architecture/static-compilation.md`) the
/// intended project additionally gets the planned allocator feature spliced
/// into `Cargo.toml` and a generated `.cargo/config.toml` — and an
/// `Ipe.WebView` shape is refused BEFORE any file is written (a webview app
/// links the system webview; a "static" artifact would be a lie). A
/// non-static build removes a stale generated config so `+crt-static` can
/// never leak from an earlier static build into later ones.
///
/// Returns the claimed target, the only source of a writable in-output
/// build-cache root. An area target is claimed with its root's disjointness
/// from the project proven again; a claimed target is proven still the
/// directory it claimed.
///
/// # Errors
/// [`CliError::Io`] on any filesystem failure; [`CliError::StaticRefusal`]
/// for a webview shape under a static plan; [`CliError::Pipeline`] on a
/// backend-invariant breach (manifest anchor drift);
/// [`CliError::OutputRefused`] when the target cannot be claimed or was
/// replaced since it was claimed.
pub fn write_emitted_project(
    emitted: &ipe_backend::EmittedProject,
    target: &EmitTarget,
    runtime_dir: &Path,
    static_plan: Option<&ipe_backend_rust::static_build::StaticPlan>,
    tree_shake_vendored: bool,
) -> Result<OwnedDir, CliError> {
    use ipe_backend_rust::static_build;

    let mut manifest = build_emit_manifest(emitted, runtime_dir, tree_shake_vendored)?;
    if let Some(plan) = static_plan {
        // The webview-under-static refusal reads the backend's typed
        // `uses_webview` signal (set from the resolved runtime/host), never a
        // re-parse of the emitted `cargo_toml` default-feature list.
        if emitted.uses_webview {
            return Err(CliError::StaticRefusal(build_plan::Refusal::WebviewStatic));
        }
        let cargo_toml = static_build::staticize_manifest(&emitted.cargo_toml, plan.allocator())
            .map_err(backend_invariant_err)?;
        manifest.insert(PathBuf::from("Cargo.toml"), cargo_toml);
        manifest.insert(
            PathBuf::from(".cargo/config.toml"),
            static_build::cargo_config(plan),
        );
    }
    // The reconcile below prunes and overwrites, so it runs only in a directory
    // proven ipe-owned and disjoint from the project.
    let crate_dir = target.claim()?;
    reconcile_emitted_project(&manifest, &crate_dir)?;
    if static_plan.is_none() {
        remove_stale_static_config(&crate_dir)?;
    }
    Ok(crate_dir)
}

/// Map a backend-invariant [`Diagnostic`] (a `CompilerBug` from manifest
/// surgery — no owning source file) onto the pipeline error channel, blamed
/// on the emitted manifest.
pub fn backend_invariant_err(diag: Diagnostic) -> CliError {
    CliError::Pipeline {
        file: PathBuf::from("Cargo.toml"),
        src: String::new(),
        diag: Box::new(diag),
    }
}

/// Remove a stale generated `.cargo/config.toml` from the emitted crate.
///
/// Only a generated one goes: the file is deleted solely when it starts with
/// [`ipe_backend_rust::static_build::CARGO_CONFIG_MARKER`]. Needed because the
/// reconciler's prune pass is scoped to `src/` and cannot own root-level files.
///
/// # Errors
/// [`CliError::OutputRefused`] for a symlink on the way; [`CliError::Io`] on a
/// filesystem failure.
pub fn remove_stale_static_config(crate_dir: &OwnedDir) -> Result<(), CliError> {
    let config = crate_dir.path_to(Path::new(".cargo").join("config.toml"))?;
    let path = config.path();
    match fs::read_to_string(&path) {
        Ok(text) if text.starts_with(ipe_backend_rust::static_build::CARGO_CONFIG_MARKER) => {
            config.remove()
        }
        _ => Ok(()),
    }
}

/// Assemble the complete intended on-disk project, relative to `out_dir`.
///
/// Every path this build produces, mapped to its exact text.
///
/// Every file this driver ever writes is UTF-8 Rust/TOML source, so `String`
/// (not raw bytes) is the honest content type (see
/// [`reconcile_emitted_project`]).
///
/// Three sources, in the same precedence `write_emitted_project` has always
/// used ("vendor first, emit second" — the backend's trimmed
/// `ipe_runtime/mod.rs` / `config.rs` must win over the fuller copies from
/// the source tree):
///   1. The vendored runtime module tree (`runtime_dir`, read recursively
///      under `src/ipe_runtime/`) — a driver-boundary filesystem read, the
///      same discipline as reading the entry file (never inside a
///      salsa-tracked query). For the dependency model this step is replaced
///      by bundling the embedded runtime source under `ipe_runtime_dep/` so
///      the relative path dep in the emitted `Cargo.toml` is always satisfied.
///   2. `Cargo.toml` at the project root.
///   3. Every backend-emitted file (`emitted.files`; each key is already a
///      validated [`ipe_backend::RelPath`] — relative and `..`-free — so no
///      entry here can escape `out_dir`).
///
/// # Errors
/// [`CliError::Io`] on any filesystem failure reading `runtime_dir` (including
/// a non-UTF-8 file, surfaced as an I/O error rather than a panic — the
/// runtime tree is trusted in-repo source, so this is not expected to fire in
/// practice). [`CliError::RuntimeMaterializeFailed`] when the embedded runtime
/// crate contains non-UTF-8 files (unexpected for in-repo source).
pub fn build_emit_manifest(
    emitted: &ipe_backend::EmittedProject,
    runtime_dir: &Path,
    tree_shake_vendored: bool,
) -> Result<BTreeMap<PathBuf, String>, CliError> {
    let mut manifest = BTreeMap::new();
    // The emit shape is self-describing: a vendored emit always writes
    // `src/ipe_runtime/mod.rs`; the dep-model emit never does. Use this to
    // branch between the two materialization strategies.
    let emitted_mod_rs = emitted
        .files
        .iter()
        .find(|(rel, _)| rel.as_str() == "src/ipe_runtime/mod.rs")
        .map(|(_, contents)| contents.as_str());
    if let Some(mod_rs) = emitted_mod_rs {
        // Vendored model: copy the runtime source tree into `src/ipe_runtime/`.
        if tree_shake_vendored {
            // Eject shape: vendor only the runtime source the program reaches.
            // The emitted `mod.rs` declares `pub mod X;` for exactly the reached
            // top-level modules; a source file whose module is never declared is
            // one rustc would drop anyway, so omitting it from the tree is
            // behaviour-preserving and shrinks the shippable, auditable artifact.
            collect_reachable_runtime_text(
                runtime_dir,
                Path::new("src/ipe_runtime"),
                mod_rs,
                &mut manifest,
            )?;
        } else {
            collect_dir_text(runtime_dir, Path::new("src/ipe_runtime"), &mut manifest)?;
        }
    } else {
        // Dependency model: the emitted `Cargo.toml` declares the runtime via
        // a relative path dep (`path = "ipe_runtime_dep"`). Bundle the embedded
        // runtime source under that directory so the dep resolves in any
        // environment — cross-compiler container, offline, CI — without a
        // host-absolute path. The embedded source is the binary's own version,
        // identical to the in-repo tree by construction.
        let embedded = runtime_embed::collect_embedded_crate_text()?;
        for (rel, text) in embedded {
            manifest.insert(PathBuf::from("ipe_runtime_dep").join(rel), text.clone());
        }
    }
    manifest.insert(PathBuf::from("Cargo.toml"), emitted.cargo_toml.clone());
    for (rel, contents) in &emitted.files {
        manifest.insert(PathBuf::from(rel.as_str()), contents.clone());
    }
    refuse_unlexable_rust(&manifest)?;
    Ok(manifest)
}

/// Refuse a manifest whose `.rs` text holds a character the Rust lexer refuses raw.
///
/// The scan covers the FINAL manifest — vendored runtime, backend emit, post-emit
/// injections and a cache-deserialized project alike — so no text reaches
/// `cargo` that would make it fail a program `ipe` accepted. The detail names the
/// file, byte offset and code point through the hazard's own rendering, never the
/// raw character.
///
/// # Errors
/// [`CliError::Pipeline`] carrying [`Diagnostic::CompilerBug`] on the first hit.
fn refuse_unlexable_rust(manifest: &BTreeMap<PathBuf, String>) -> Result<(), CliError> {
    let hit = manifest
        .iter()
        .filter(|(path, _)| {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
        })
        .find_map(|(path, text)| ipe_intern::find_lexer_hazard(text).map(|hazard| (path, hazard)));
    hit.map_or(Ok(()), |(path, hazard)| {
        let shown = path.to_string_lossy();
        Err(CliError::Pipeline {
            file: path.clone(),
            src: String::new(),
            diag: Box::new(Diagnostic::CompilerBug {
                where_: ipe_intern::EMIT_LEXABLE,
                detail: format!(
                    "emitted {shown:?} holds {hazard}, which the Rust lexer refuses raw"
                ),
            }),
        })
    })
}

/// Vendor only the runtime source files the emitted `mod.rs` reaches.
///
/// The emitted `ipe_runtime/mod.rs` is a flat, non-`cfg`-gated list of `pub mod
/// X;` for exactly the top-level modules the program reaches. For each declared
/// name this copies either the single file `X.rs` or, when `X` is a directory
/// module, the ENTIRE `X/` subtree — never parsing the subtree's own nested
/// `mod` declarations. Copying a reached directory whole is the fail-closed
/// choice the eject contract requires: it can only ever include a file, never
/// omit one a nested `mod` needs, so the vendored tree always compiles. The
/// modules a directory does not reach are already excluded at the top level
/// (an unreached `web`/`db`/`tui`/… directory is never declared, so its whole
/// subtree is dropped) — where the large size wins come from.
///
/// `mod.rs` itself is always copied (it IS the emitted file, overlaid verbatim
/// by the caller's `emitted.files` pass afterwards); the loop only resolves the
/// modules it names.
///
/// # Errors
/// [`CliError::Io`] on any filesystem failure reading `runtime_dir`.
pub fn collect_reachable_runtime_text(
    runtime_dir: &Path,
    dst_prefix: &Path,
    emitted_mod_rs: &str,
    manifest: &mut BTreeMap<PathBuf, String>,
) -> Result<(), CliError> {
    for name in declared_modules(emitted_mod_rs) {
        let file = runtime_dir.join(format!("{name}.rs"));
        let dir = runtime_dir.join(&name);
        if dir.is_dir() {
            collect_dir_text(&dir, &dst_prefix.join(&name), manifest)?;
        } else if file.is_file() {
            let text = fs::read_to_string(&file).map_err(|e| io_err(&file, e))?;
            manifest.insert(dst_prefix.join(format!("{name}.rs")), text);
        }
        // A `pub mod X;` with neither `X.rs` nor `X/` on disk is an inline
        // module (a `pub mod web { pub mod route; }` block) — it has no separate
        // source file to vendor, so there is nothing to copy for it here.
    }
    Ok(())
}

/// The module names a runtime `mod.rs` declares with `pub mod X;` / `mod X;`.
///
/// A parse-free line scan sufficient for the emitted `mod.rs`, whose module
/// declarations are one-per-line `pub mod <name>;` with no attributes, braces,
/// or trailing content. A declaration that opens an inline module body (`pub
/// mod web {`) is deliberately excluded — it has no separate source file — by
/// requiring the statement to end in `;`.
pub fn declared_modules(mod_rs: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in mod_rs.lines() {
        let line = line.trim();
        let rest = line
            .strip_prefix("pub mod ")
            .or_else(|| line.strip_prefix("mod "));
        if let Some(rest) = rest
            && let Some(name) = rest.strip_suffix(';')
            && !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            names.insert(name.to_owned());
        }
    }
    names
}

/// Recursively read every file under `src_dir` as UTF-8 text, inserting
/// `(dst_prefix.join(rel), contents)` into `manifest`.
pub fn collect_dir_text(
    src_dir: &Path,
    dst_prefix: &Path,
    manifest: &mut BTreeMap<PathBuf, String>,
) -> Result<(), CliError> {
    let entries = fs::read_dir(src_dir).map_err(|e| io_err(src_dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_err(src_dir, e))?;
        let from = entry.path();
        let dst = dst_prefix.join(entry.file_name());
        let file_type = entry.file_type().map_err(|e| io_err(&from, e))?;
        if file_type.is_dir() {
            collect_dir_text(&from, &dst, manifest)?;
        } else {
            let text = fs::read_to_string(&from).map_err(|e| io_err(&from, e))?;
            manifest.insert(dst, text);
        }
    }
    Ok(())
}

/// Reconcile the owned crate directory against `manifest`.
///
/// Only files whose content differs from what is on disk are written
/// (content-gated, so an unchanged rebuild bumps no mtime and `cargo` keeps its
/// cache), each through [`OwnedPath::write`]'s temp-then-rename. Then every
/// file under `src/` that is NOT a manifest key is deleted (manifest-driven
/// prune: a stale `.rs` from a deleted module cannot survive).
///
/// Scope discipline: the prune walk is confined to `src/` and never touches the
/// crate root — `Cargo.lock`, a `target/` build-cache directory, or any other
/// file `cargo` itself manages there. Every path is an [`OwnedPath`], so a
/// symlink planted anywhere in the owned tree is refused, never followed.
///
/// # Errors
/// [`CliError::OutputRefused`] for a symlink on the way; [`CliError::Io`] on
/// any filesystem failure.
pub fn reconcile_emitted_project(
    manifest: &BTreeMap<PathBuf, String>,
    crate_dir: &OwnedDir,
) -> Result<(), CliError> {
    for (rel, contents) in manifest {
        write_if_changed(&crate_dir.path_to(rel)?, contents)?;
    }
    prune_orphaned_files(crate_dir, manifest)
}

/// Write `contents` to `target` only when the existing content differs.
///
/// A differing byte length proves a difference without reading; an equal length
/// falls through to the exact compare, which keeps an identical rewrite a no-op.
///
/// # Errors
/// As [`OwnedPath::write`].
pub fn write_if_changed(target: &OwnedPath, contents: &str) -> Result<(), CliError> {
    if target.holds(contents.as_bytes())? {
        return Ok(());
    }
    target.write(contents.as_bytes())
}

/// Delete every file under the crate's `src/` that is not a key of `manifest`.
///
/// The walk starts at an [`OwnedPath`] (a symlinked `src/` is refused) and
/// classifies entries without following links, so a symlink inside the tree is
/// removed as the link it is, never traversed. On Unix each level is listed and
/// unlinked through its held handle ([`OwnedPath::prune_files`]), so a level
/// swapped for a link mid-walk is refused, never followed. Directories are kept (empty ones are harmless to `cargo`), which
/// keeps the pass's blast radius minimal.
///
/// # Errors
/// [`CliError::OutputRefused`] when `src/` is a symlink, or with
/// [`OutputRefusal::TooDeep`] when the tree nests deeper than
/// [`MAX_PRUNE_DEPTH`]; [`CliError::Io`] on a filesystem failure.
pub fn prune_orphaned_files(
    crate_dir: &OwnedDir,
    manifest: &BTreeMap<PathBuf, String>,
) -> Result<(), CliError> {
    let src = crate_dir.path_to("src")?;
    prune_src(&src, manifest, crate_dir)
}

/// Prune `src` through held directory handles.
#[cfg(unix)]
fn prune_src(
    src: &OwnedPath,
    manifest: &BTreeMap<PathBuf, String>,
    _crate_dir: &OwnedDir,
) -> Result<(), CliError> {
    src.prune_files(|rel| manifest.contains_key(rel), MAX_PRUNE_DEPTH)
}

/// Prune `src` level by level.
#[cfg(not(unix))]
fn prune_src(
    src: &OwnedPath,
    manifest: &BTreeMap<PathBuf, String>,
    crate_dir: &OwnedDir,
) -> Result<(), CliError> {
    prune_dir(&src.path(), manifest, crate_dir, 0)
}

/// Deepest directory nesting under the crate's `src/` that
/// [`prune_orphaned_files`] descends.
pub const MAX_PRUNE_DEPTH: usize = 128;

/// One level of [`prune_orphaned_files`], at nesting `depth` below `src/`;
/// `dir` was reached without following a link.
#[cfg(not(unix))]
fn prune_dir(
    dir: &Path,
    manifest: &BTreeMap<PathBuf, String>,
    crate_dir: &OwnedDir,
    depth: usize,
) -> Result<(), CliError> {
    if depth > MAX_PRUNE_DEPTH {
        return Err(OutputRefusal::TooDeep {
            path: dir.to_path_buf(),
            limit: MAX_PRUNE_DEPTH,
        }
        .into());
    }
    // A directory that is absent, or vanishes before this read (a concurrent
    // external cleanup), trivially has nothing left to prune.
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err(dir, e)),
    };
    for entry in entries {
        // Likewise: a file this same walk is iterating over can disappear
        // mid-loop (a sibling process finished its OWN rebuild and deleted
        // its temp state). Skip rather than fail — there is nothing left to
        // prune at a path that no longer exists.
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(dir, e)),
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(&path, e)),
        };
        if file_type.is_dir() {
            prune_dir(&path, manifest, crate_dir, depth.saturating_add(1))?;
        } else {
            // `path` was built from `dir`, itself a child of the crate
            // directory by construction, so `strip_prefix` fails only when that
            // path is relative and the working directory changed mid-walk.
            let Ok(rel) = path.strip_prefix(crate_dir.path()) else {
                continue;
            };
            // An orphan a concurrent deleter already removed counts as pruned.
            if !manifest.contains_key(rel) {
                crate_dir.unlink(rel)?;
            }
        }
    }
    Ok(())
}

/// Build a multi-module Ipe project rooted at `manifest_path` (`package.ipe`)
/// into a Rust Cargo project under `out_dir`, vendoring the runtime from
/// `runtime_dir`.
///
/// The build pipeline:
/// 1. Parse `package.ipe` to locate the source root.
/// 2. Discover every `*.ipe` file under `src/`.
/// 3. Scan each file for `import` declarations (token-level lexer scan) to
///    build the import graph.
/// 4. Topological sort — fail closed on a cycle (IPE-N0021).
/// 5. Canonicalise each module in dep-first order (IPE-N0020 / N0022 / N0023 /
///    N0024 / N0025 gate).
/// 6. Link (merge) all canonical modules into one.
/// 7. Infer → lower → emit as a single-module program (byte-identical to the
///    single-file pipeline on the entry module).
///
/// # Errors
/// [`CliError::Io`] on any filesystem failure.
/// [`CliError::Pipeline`] carrying the first compiler diagnostic.
pub fn build_project(
    manifest_path: &Path,
    out_dir: &Path,
    runtime_dir: &Path,
) -> Result<(), CliError> {
    build_project_with_options(
        manifest_path,
        out_dir,
        runtime_dir,
        &BuildOptions::from_env(),
    )
}

/// [`build_project`] with explicit [`BuildOptions`] (the static-plan-aware
/// variant).
///
/// # Errors
/// As [`build_project`], plus [`CliError::StaticRefusal`] when the emitted
/// app shape cannot be static.
pub fn build_project_with_options(
    manifest_path: &Path,
    out_dir: &Path,
    runtime_dir: &Path,
    options: &BuildOptions,
) -> Result<(), CliError> {
    build_project_into(
        manifest_path,
        OutTarget::Path(out_dir),
        runtime_dir,
        options,
    )
    .map(drop)
}

/// [`build_project_with_options`] into `out`, returning the claimed crate
/// directory.
///
/// # Errors
/// As [`build_project`], plus [`CliError::OutputRefused`] when `out` overlaps
/// the project or its sources.
pub fn build_project_into(
    manifest_path: &Path,
    out: OutTarget<'_>,
    runtime_dir: &Path,
    options: &BuildOptions,
) -> Result<OwnedDir, CliError> {
    let manifest = project::parse_manifest(manifest_path)?;
    let discovered = project::discover_modules(&manifest.src_root)?;

    // For each module, read its source and extract imports.
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    for m in &discovered {
        let src = crate::io_bounded::read_walked_source(m.path())?;
        sources.insert(m.module_path().to_vec(), (m.path().to_path_buf(), src));
    }

    // A library package (declares `exposedModules`, has no runnable entry —
    // neither a `programs` stage nor a `src/Main.ipe`) has nothing to emit. Refuse
    // with a clean, honest message directing the author to `ipe type-check`
    // (which analyses the public surface) rather than the internal
    // missing-entry error a bogus `["Main"]` entry would raise downstream.
    let entry_path = manifest.resolved_entry()?;
    if manifest.default_program().is_none()
        && !manifest.exposed_modules.is_empty()
        && !sources.contains_key(&entry_path)
    {
        return Err(CliError::Usage(text::msg::library_package_no_entry()));
    }
    // The emit epilogue's fixed `fn main` calls `ipe_main`, which the backend
    // names only for a `main` in module `Main`. A `programs`-declared entry in a
    // non-`Main` module type-checks (analysis honours the declared entry) but the
    // emit's main-symbol naming does not yet thread through a per-program entry,
    // so emitting a non-`Main` program entry would miscompile. Refuse cleanly and
    // point at the working analysis path rather than emit a broken crate.
    if entry_path != ["Main".to_owned()] {
        return Err(CliError::Usage(text::msg::build_entry_not_main(
            &entry_path.join("."),
        )));
    }

    // Fold in the manifest-derived fields: `[wasm] publicEnv`, hydrate mode,
    // and the project name (sanitized to a valid Cargo package name). The
    // caller's `options` carries no manifest-derived data — it is built before
    // the manifest is parsed — so these three fields are completed here, the
    // same way `manifest.driver` bypasses `options` as its own positional arg.
    // The webview window is a manifest-derived HOST setting: read the
    // `delivery.desktop` block only for a webview-native (`web desktop`) build.
    let webview_window = options.webview_host.then(|| {
        let d = &manifest.delivery.desktop;
        ipe_backend_rust::WebViewWindow {
            title: d.title.clone(),
            width: i64::from(d.width),
            height: i64::from(d.height),
        }
    });
    // The emitted crate identity is uniquified per project so two projects that
    // share a friendly name but live at different paths own SEPARATE slots in a
    // shared CARGO_TARGET_DIR (no cross-project cargo-fingerprint thrash). The
    // FRIENDLY name (`manifest.name`) is untouched — only this internal crate
    // identity carries the path-derived suffix. The seed is the CANONICAL project
    // directory so the identity is stable across runs (deterministic) yet distinct
    // per real project location; a symlink/`..` alias resolves to the same slot.
    let cargo_name = ipe_backend_rust::crate_identity(
        &ipe_backend_rust::sanitize_cargo_name(&manifest.name),
        &canonical_project_dir(manifest_path),
    );
    let options = BuildOptions {
        wasm_public_env: manifest.wasm.public_env.clone(),
        wasm_hydrate_mode: manifest.wasm.mode.as_deref() == Some("hydrate"),
        cargo_name,
        webview_window,
        ..*options
    };

    // The manifest is the blame location for an import cycle (no single file
    // owns it); post-link errors are blamed on the entry file inside the core.
    let target = out.prove(&ProjectPaths::from_manifest(&manifest))?;
    compile_modules(
        sources,
        discovered,
        &entry_path,
        &target,
        runtime_dir,
        manifest_path,
        manifest.driver,
        options,
    )
}

/// Locate the Ipê runtime module tree (`src/runtime/rust/src/`).
///
/// Delegates to [`ipe_env::artifact::resolve_runtime_src`], the one runtime
/// module-tree resolver: `$IPE_RUNTIME_DIR` when set (authoritative — a value
/// that is not a directory is refused, never walked past), else the upward walk
/// from the current directory.
///
/// # Errors
/// Returns [`CliError::RuntimeNotFound`] when the override is not a directory or
/// no walk candidate exists, or [`CliError::Io`] if the current directory cannot
/// be read.
pub fn resolve_runtime() -> Result<PathBuf, CliError> {
    let cwd = std::env::current_dir().map_err(|e| io_err(Path::new("."), e))?;
    ipe_env::artifact::resolve_runtime_src(
        ipe_env::var_os(ipe_env::artifact::RUNTIME_DIR_VAR),
        &cwd,
    )
    .map(ipe_env::artifact::ProvenRuntime::into_path_buf)
    .map_err(|_| CliError::RuntimeNotFound)
}

/// Resolve the vendored runtime MODULE tree the emit copies into the project,
/// but only when that emit shape actually needs it.
///
/// The dependency-model native emit (the default) carries no vendored
/// `src/ipe_runtime/` tree — it names the runtime as a path dependency, resolved
/// separately by [`runtime_embed::resolve`] — so requiring a vendored tree up
/// front would fail a perfectly valid build run outside a repo checkout. The
/// vendored tree is needed only when the vendored shape is emitted: the wasm
/// target (which still vendors) or a build with the dependency model turned off.
///
/// `cli_override` is the explicit `--runtime <dir>` value, honoured verbatim when
/// present. When the vendored tree is not needed, an empty sentinel path is
/// returned; the dep-model native emit never reads it.
///
/// # Errors
/// [`CliError::RuntimeNotFound`] / [`CliError::Io`] from [`resolve_runtime`] when
/// a vendored tree is required but cannot be located.
pub fn resolve_vendored_runtime_dir(
    cli_override: Option<String>,
    needs_vendored: bool,
) -> Result<PathBuf, CliError> {
    match cli_override {
        Some(r) => Ok(PathBuf::from(r)),
        None if needs_vendored => resolve_runtime(),
        None => Ok(PathBuf::new()),
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;
    use crate::output_dir::OutputRefusal;

    /// A widget's JS reaches the emitted `main.rs` with every bidi override and
    /// lone CR escaped, since rustc refuses either raw inside any string literal.
    #[test]
    fn widget_registration_escapes_bidi_and_lone_cr_in_content() {
        let mut files = BTreeMap::new();
        let rel = ipe_backend::RelPath::new("src/main.rs").expect("valid rel path");
        files.insert(
            rel,
            "fn main() {\n    install_panic_classifier();\n}\n".to_owned(),
        );
        let mut emitted = ipe_backend::EmittedProject {
            files,
            cargo_toml: String::new(),
            uses_webview: false,
        };
        let manifest = BTreeMap::from([(
            "x-w\u{202E}".to_owned(),
            "/* \u{202E}evil\u{2066} */ a\rb \"#\"## c\\d".to_owned(),
        )]);
        assert!(inject_widget_registration(&mut emitted, &manifest).is_ok());
        let main = emitted.files.get("src/main.rs").map_or("", String::as_str);
        assert!(
            !main.contains(['\u{202E}', '\u{2066}', '\r']),
            "a raw bidi override or lone CR reached the emitted literal: {main}"
        );
        assert!(
            main.contains(
                r###"("x-w\u{202e}", "/* \u{202e}evil\u{2066} */ a\rb \"#\"## c\\d"),"###
            ),
            "the widget pair is not the Debug-escaped literal pair: {main}"
        );
    }

    /// An emitted project for the manifest: a vendored `mod.rs` that declares
    /// no runtime module, so the scan sees only `files` and reads no disk.
    fn vendored_project(files: &[(&str, &str)]) -> ipe_backend::EmittedProject {
        let mut map = BTreeMap::new();
        for (path, body) in files.iter().chain(&[("src/ipe_runtime/mod.rs", "")]) {
            let rel = ipe_backend::RelPath::new(*path).expect("valid rel path");
            map.insert(rel, (*body).to_owned());
        }
        ipe_backend::EmittedProject {
            files: map,
            cargo_toml: String::new(),
            uses_webview: false,
        }
    }

    /// The manifest refuses `.rs` text holding a raw bidi control or a bare CR,
    /// past every renderer, and names the hazard without echoing it.
    #[test]
    fn manifest_refuses_a_raw_lexer_hazard() {
        let missing = Path::new("/nonexistent-runtime-dir");
        for (path, body) in [
            ("src/main.rs", "fn main() { let _ = \"a\u{202E}b\"; }\n"),
            ("src/ipe_runtime/x.rs", "// a\rb\n"),
            ("src/ipe_mods/upper.RS", "// a\u{2066}b\n"),
        ] {
            let refused = build_emit_manifest(&vendored_project(&[(path, body)]), missing, true);
            assert!(
                matches!(&refused, Err(CliError::Pipeline { .. })),
                "a raw hazard in {path} passed the manifest"
            );
            let Err(CliError::Pipeline { file, diag, .. }) = refused else {
                return;
            };
            assert_eq!(file, PathBuf::from(path));
            assert!(
                matches!(
                    &*diag,
                    Diagnostic::CompilerBug {
                        where_: ipe_intern::EMIT_LEXABLE,
                        ..
                    }
                ),
                "not the lexability refusal: {diag:?}"
            );
            let Diagnostic::CompilerBug { detail, .. } = *diag else {
                return;
            };
            assert!(
                !detail.contains(['\u{202E}', '\r']),
                "the refusal echoed the raw hazard: {detail:?}"
            );
        }
        for (path, body) in [
            ("src/main.rs", "fn main() {}\r\n// \u{200E}\u{FEFF} é 𝄞\r\n"),
            ("www/index.html", "<p>\u{202E}\r</p>"),
        ] {
            assert!(
                build_emit_manifest(&vendored_project(&[(path, body)]), missing, true).is_ok(),
                "lexable or non-Rust text in {path} was refused"
            );
        }
    }

    /// A build whose caller states no intent is a release build.
    #[test]
    fn unstated_build_intent_is_release() {
        assert_eq!(
            BuildOptions::default().intent,
            ipe_backend_rust::BuildIntent::Release
        );
        assert_eq!(
            BuildOptions::from_env().intent,
            ipe_backend_rust::BuildIntent::Release
        );
    }

    /// A `src/` tree nested past [`MAX_PRUNE_DEPTH`] is refused with a typed
    /// refusal, while one exactly at the ceiling is pruned.
    #[test]
    fn prune_refuses_a_tree_deeper_than_the_ceiling() {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe_prune_depth_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let owned = OwnedDir::claim(&dir).expect("claim temp dir");
        let manifest = BTreeMap::new();

        let mut at_ceiling = dir.join("src");
        for _ in 0..MAX_PRUNE_DEPTH {
            at_ceiling.push("d");
        }
        fs::create_dir_all(&at_ceiling).expect("make tree at the ceiling");
        fs::write(at_ceiling.join("orphan.rs"), "").expect("write orphan");
        let pruned = prune_orphaned_files(&owned, &manifest);
        assert!(
            pruned.is_ok(),
            "a tree at the ceiling is pruned, got {pruned:?}"
        );
        assert!(
            !at_ceiling.join("orphan.rs").exists(),
            "the orphan at the ceiling is removed"
        );

        let past = at_ceiling.join("d");
        fs::create_dir_all(&past).expect("make tree past the ceiling");
        fs::write(past.join("orphan.rs"), "").expect("write orphan");
        let refused = prune_orphaned_files(&owned, &manifest);
        assert!(
            matches!(
                refused,
                Err(CliError::OutputRefused(OutputRefusal::TooDeep {
                    limit: MAX_PRUNE_DEPTH,
                    ..
                }))
            ),
            "a tree past the ceiling is refused, got {refused:?}"
        );
        assert!(
            past.join("orphan.rs").is_file(),
            "nothing past the ceiling is touched"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A same-length, same-content file is left untouched (no rewrite, mtime
    /// preserved) while a differing-length file is rewritten — the two branches
    /// of the length pre-check in [`write_if_changed`].
    #[test]
    fn write_if_changed_length_precheck() {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe_write_if_changed_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let owned = OwnedDir::claim(&dir).expect("claim temp dir");

        // Same content: the write is skipped, so mtime does not advance.
        let same = owned.path_to("same.txt").expect("owned path");
        write_if_changed(&same, "hello").expect("initial write");
        let mtime_before = fs::metadata(same.path())
            .and_then(|m| m.modified())
            .expect("mtime");
        write_if_changed(&same, "hello").expect("no-op write");
        let mtime_after = fs::metadata(same.path())
            .and_then(|m| m.modified())
            .expect("mtime");
        assert_eq!(
            mtime_before, mtime_after,
            "identical content must not rewrite the file"
        );

        // Differing length: content is overwritten.
        let changed = owned.path_to("changed.txt").expect("owned path");
        write_if_changed(&changed, "abc").expect("initial write");
        write_if_changed(&changed, "abcdef").expect("length-changed write");
        assert_eq!(
            fs::read_to_string(changed.path()).expect("read back"),
            "abcdef",
            "a differing-length write must land"
        );

        // Same length, different bytes: still rewritten (falls through to the
        // exact compare, which reports a difference).
        let flip = owned.path_to("flip.txt").expect("owned path");
        write_if_changed(&flip, "aaa").expect("initial write");
        write_if_changed(&flip, "bbb").expect("same-length differing write");
        assert_eq!(
            fs::read_to_string(flip.path()).expect("read back"),
            "bbb",
            "a same-length differing-byte write must land"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fresh scratch directory unique to this test run.
    fn loose_scratch(tag: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe_loose_build_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn collected_modules(collected: &CollectedSources) -> Vec<Vec<String>> {
        collected.sources.keys().cloned().collect()
    }

    /// A loose build compiles the import closure only, beside an unreadable directory.
    ///
    /// An unimported sibling and a `chmod 000` directory next to the entry are
    /// never touched.
    #[cfg(unix)]
    #[test]
    fn loose_build_loads_the_import_closure_beside_an_unreadable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = loose_scratch("closure");
        let entry = dir.join("Main.ipe");
        fs::write(
            &entry,
            "module Main exposing (main)\n\nimport Helper\n\nmain = Helper.h\n",
        )
        .expect("write entry");
        fs::write(
            dir.join("Helper.ipe"),
            "module Helper exposing (h)\n\nh = 1\n",
        )
        .expect("write helper");
        fs::write(
            dir.join("Stray.ipe"),
            "module Stray exposing (s)\n\ns = ???\n",
        )
        .expect("write stray");
        let locked = dir.join("locked");
        fs::create_dir_all(&locked).expect("create locked dir");
        fs::write(
            locked.join("Hidden.ipe"),
            "module Hidden exposing (x)\n\nx = 1\n",
        )
        .expect("write hidden");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).expect("chmod 000");

        let collected = collect_entry_and_siblings(&entry);
        let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&dir);
        let collected = collected.expect("closure loads beside an unreadable dir");
        assert_eq!(
            collected_modules(&collected),
            vec![vec!["Helper".to_owned()], vec!["Main".to_owned()]],
            "only Main and the Helper it imports are compiled"
        );
        assert_eq!(collected.entry_module_path, vec!["Main".to_owned()]);
    }

    /// A loose build whose import closure passes the module ceiling is refused.
    #[test]
    fn loose_build_past_the_module_limit_is_refused() {
        let dir = loose_scratch("limit");
        let count = crate::loose_file::MAX_LOOSE_FILE_MODULES;
        let imports = (0..count).fold(String::new(), |mut acc, i| {
            let _ = writeln!(acc, "import M{i}");
            acc
        });
        let entry = dir.join("Main.ipe");
        fs::write(
            &entry,
            format!("module Main exposing (main)\n\n{imports}\nmain = 1\n"),
        )
        .expect("write entry");
        for i in 0..count {
            fs::write(
                dir.join(format!("M{i}.ipe")),
                format!("module M{i} exposing (v)\n\nv = 1\n"),
            )
            .expect("write sibling");
        }

        let collected = collect_entry_and_siblings(&entry);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            matches!(collected, Err(CliError::DiscoveryLimitReached { .. })),
            "the entry plus {count} imported siblings exceeds the ceiling"
        );
    }

    /// A loose build refuses an imported sibling that is a symlink out of the entry's directory.
    #[cfg(unix)]
    #[test]
    fn loose_build_does_not_follow_an_escaping_symlink() {
        let outside = loose_scratch("escape-outside");
        fs::write(
            outside.join("Out.ipe"),
            "module Out exposing (o)\n\no = 1\n",
        )
        .expect("write outside module");
        let dir = loose_scratch("escape");
        let entry = dir.join("Main.ipe");
        fs::write(
            &entry,
            "module Main exposing (main)\n\nimport Out\n\nmain = Out.o\n",
        )
        .expect("write entry");
        std::os::unix::fs::symlink(outside.join("Out.ipe"), dir.join("Out.ipe"))
            .expect("plant symlink");

        let collected = collect_entry_and_siblings(&entry);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        assert!(
            matches!(
                collected,
                Err(CliError::SourceRefused {
                    reason: crate::io_bounded::SourceRefusal::Symlink,
                    ..
                })
            ),
            "an imported symlink sibling is refused, never followed"
        );
    }
}
