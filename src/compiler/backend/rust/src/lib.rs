#![forbid(unsafe_code)]
//! The Rust backend for the Ipê compiler.
//!
//! Consumes the backend-agnostic typed [`ipe_ir::Program`] and emits a Rust
//! Cargo project. The crate is split into the fixed templates emitted for every
//! program ([`preamble`] / [`epilogue`] / the kernel-wrapper prelude in
//! [`project`]) and the genuinely type-directed emission of the user's types
//! ([`emit_types`]) and functions ([`emit_expr`]). [`naming`] holds the
//! Ipê → Rust identifier rules.
//!
//! The single correctness gate is byte-equality against the golden program
//! (`tests/golden/basics/main.rs`).
//!
//! The [`ipe_ir`] boundary carries [`ipe_intern::Symbol`]s, not strings, so the
//! backend resolves them through the [`ipe_intern::Interner`] it is constructed
//! with. The [`ipe_backend::Backend`] trait stays string-free.

mod capabilities;
mod const_fold;
pub use const_fold::fold_program;
pub use emit_expr::rust_str_lit;
mod crate_specs;
mod doc;
mod emit_console;
mod emit_doc;
mod emit_expr;
mod emit_model_gate;
mod emit_model_schema;
mod emit_template;
mod emit_tui;
mod emit_types;
mod emit_ui_plan;
mod emit_ui_template;
mod emit_web;
mod emit_webview;
mod emit_worker;
mod items;
mod layout_sweep;
mod naming;
mod preamble;
mod project;
mod render;
mod route_grammar;
mod runtime_features;
mod rust_file;
pub mod static_build;
// The `update`-arm → transition-datum classifier: the compile-time half of the
// dev-loop's logic hot-swap (the counterpart of `emit_template`'s static
// partition). Public API — consumed by the `hot_appearance` update emitter and
// the `ipe dev watch` transition classifier; its dev == prod conformance to the
// runtime `apply_transition` is pinned in-module.
pub mod transition_classify;
// The `Msg`-enum → schema-tagged set-descriptor classifier: the compile-time
// half of the additive-`Msg`-variant hot-swap. Public API — consumed by the
// `ipe dev watch` loop to bake and diff the program's `Msg` variant surface; its
// dev == prod conformance to the runtime `web::msg_set` proof is pinned
// in-module.
pub mod msg_set_classify;

// The `subscriptions`-entry sub-description partition: reduces a data-describable
// tick subscription (`Time.every 1000 Tick`) to an inert `CompileSubDescription`
// consumed by the emit hook and mirrored by the `ipe dev watch` subs classifier; its
// dev == prod conformance to the runtime `sub_every_hot` is pinned in-module.
pub mod sub_classify;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use ipe_backend::{Backend, EmittedProject};
use ipe_diagnostics::{DResult, Diagnostic, NameError, RustNameFoldKind, Span};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    Callee, EnumTraits, Expr, FuncId, IrType, KernelFn, ModPath, Program, RuntimeBridgedEnum,
    TypeDef,
};

pub use emit_doc::{SweepDivergence, native_vs_legacy_sweep};
pub use layout_sweep::{BodyLayoutBudget, LAYOUT_FUEL, body_layout_budgets};
pub use preamble::{epilogue, preamble};

/// Which `ipe` verb family an emit serves.
///
/// The verb, never the cargo profile, decides it. `Development` (`ipe dev build`,
/// `ipe dev run`, `ipe test`, `ipe dev watch`) turns on the runtime `dev-posture`
/// feature, the one input that lets the operator console default open, and only
/// on a loopback bind. `Release` is the default, so an emit whose caller states
/// no intent is a release emit: the console stays closed until
/// `IPE_CONSOLE_AUTH` names a credential mode, and `Debug.*` is refused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum BuildIntent {
    /// A dev-loop verb: the runtime carries the `dev-posture` feature.
    Development,
    /// A shipped artifact (`ipe release`, `ipe release eject`, the desktop bundle).
    #[default]
    Release,
}

/// Which SQL database driver the emitted project targets.
///
/// Selected by `package.ipe`'s database driver setting
/// (`crates/ipe/src/project.rs::DbDriver`, converted at the `ipe` →
/// `ipe_backend_rust` boundary via [`RustBackend::with_db_driver`]) — drives
/// the `ipe_runtime/config.rs` template and `Cargo.toml` sqlx feature
/// [`crate::project::emit_program`] selects. `Sqlite` is the default: a
/// program with no database setting, or one built via the single-file
/// `ipe dev build` path (no manifest at all), emits byte-identical output to
/// pre-driver-selection backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DbDriver {
    #[default]
    Sqlite,
    Postgres,
}

/// The consumer-side FFI emission inputs.
///
/// Assembled by the driver from the project's installed FFI artifact cache
/// and threaded in via [`RustBackend::with_ffi`]. Ignored entirely when the
/// program lowers no [`ipe_ir::Callee::Ffi`] call (`uses_ffi` stays false).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FfiEmit {
    /// `"Rust.<Crate>.<TypeName>"` → absolute Rust path
    /// (`"Rust.Semver.Version"` → `"::semver::Version"`) for every opaque
    /// foreign type an installed interface module declares.
    pub foreign_types: BTreeMap<String, String>,
    /// Pinned `[dependencies]` lines for the bound crates (exact versions +
    /// effective feature sets — never `"*"`), pre-merged and de-duplicated by
    /// the driver.
    pub dep_lines: Vec<String>,
    /// The full `src/ffi.rs` content: every installed crate's wrapper module
    /// (`pub mod <slug> { … }` + `pub use <slug>::*;`).
    pub bindings_source: String,
    /// The dotted interface-module name (`"Rust.Firestore"`) of every
    /// installed crate — the compiler-generated forwarder modules the
    /// used-set shake may slice (user modules are never listed here, so a
    /// user fn can never be shaken).
    pub interface_modules: Vec<String>,
    /// Per-wrapper conversion glue for TRANSPARENT foreign types, keyed by
    /// the `_bindings.rs` wrapper fn identifier (the [`ipe_ir::Callee::Ffi`]
    /// ident). A wrapper absent here passes every value through unchanged —
    /// the opaque-handle baseline.
    pub wrapper_glue: BTreeMap<String, FfiWrapperGlue>,
}

/// Where one FFI wrapper's transparent conversions apply: which argument
/// positions convert Ipê→foreign, and whether the result converts back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfiWrapperGlue {
    /// One entry per Ipê argument position; `Some` marks a transparent value
    /// the call site converts to the foreign type.
    pub params: Vec<Option<FfiGlueType>>,
    /// The result conversion, when the wrapper returns a transparent type.
    pub result: Option<FfiResultGlue>,
}

/// A transparent result and where it sits in the wrapper's return type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfiResultGlue {
    /// `true` when the foreign value is the Ok payload of the wrapper's
    /// `IpeResult<IpeError, T>`; `false` for a bare `T` (infallible accessor).
    pub in_result: bool,
    /// The transparent shape to convert from.
    pub ty: FfiGlueType,
}

/// One transparent foreign type's conversion shape.
///
/// Enough to name both sides of the seam and move every member across.
/// Members are identity carriers by classification, so no coercion ever hides
/// inside a conversion — each field/payload is a plain move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FfiGlueType {
    /// A Rust struct surfacing as an Ipê record: the emitted app-side value
    /// is the synthesised record struct for `fields`.
    Record {
        /// The foreign path: absolute for an imported crate type
        /// (`::tm::Point`), crate-local for a define-defined type
        /// (`crate::ffi::<slug>::<Name>`).
        rust_path: String,
        /// The field names, in declaration order. Validated non-keyword
        /// lowercase identifiers, so the record-struct field ident and the
        /// foreign field ident are both the name itself.
        fields: Vec<String>,
    },
    /// A Rust enum surfacing as an Ipê closed union: the emitted app-side
    /// value is the enum the lowerer emitted for the interface module's
    /// union declaration.
    Union {
        /// The interface module segments (`["Rust", "Tm"]`) — the app enum's
        /// home, resolved through the interner at emission.
        module: Vec<String>,
        /// The Ipê-visible nominal (`"Shade"`).
        name: String,
        /// The foreign path: absolute for an imported crate type
        /// (`::tm::Shade`), crate-local for a define-defined type
        /// (`crate::ffi::<slug>::<Name>`).
        rust_path: String,
        /// The variant set, in declaration order.
        variants: Vec<FfiGlueVariant>,
    },
}

/// One variant of a transparent enum, as the conversion glue renders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfiGlueVariant {
    /// The variant name — identical on both sides by classification.
    pub name: String,
    /// The payload shape.
    pub payload: FfiGluePayload,
}

/// A transparent enum variant's payload shape.
///
/// The app-side enum is always positional (tuple) — the Ipê union constructor
/// surface — while the foreign side keeps its declared shape, so a
/// struct-variant conversion re-attaches the member names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FfiGluePayload {
    /// No payload.
    Unit,
    /// `n` positional carriers.
    Tuple(usize),
    /// Named members, in declaration order.
    Struct(Vec<String>),
}

/// The Rust code-generation backend.
///
/// Holds a reference to the [`Interner`] used to build the program, so it can
/// resolve the [`Symbol`]s carried by the IR without widening the
/// [`Backend::emit`] signature.
// Each boolean is an independent emit-shape switch (production gate, debugger,
// hot-appearance, webview-host) set by its own `with_*` builder; a bit-flags
// enum would obscure that each is toggled in isolation.
#[allow(clippy::struct_excessive_bools)]
pub struct RustBackend<'a> {
    interner: &'a Interner,
    db_driver: DbDriver,
    ffi: Option<FfiEmit>,
    target: ipe_ir::Target,
    wasm_public_env: Vec<String>,
    wasm_hydrate_mode: bool,
    runtime_dep: Option<RuntimeDep>,
    /// `true` when `ipe dev build --debugger` / `ipe dev run --debugger` was passed. Adds
    /// the runtime `debugger` feature to the emitted project's dependency feature
    /// list so the TEA driver instantiates the recorder. Never set for
    /// `ipe release` (the release command does not expose the flag), so no
    /// production artifact carries recorder code. Set via [`Self::with_debugger`].
    debugger: bool,
    /// The verb family this emit serves; selects the `dev-posture` runtime
    /// feature. Set via [`Self::with_build_intent`]; default `Release`.
    build_intent: BuildIntent,
    /// The project name from `package.ipe`, sanitized into a valid Cargo package
    /// name via [`sanitize_cargo_name`]. Becomes the emitted crate's
    /// `[package] name`. Empty string signals "use the safe fallback
    /// `ipe-app`" — set via [`Self::with_project_name`].
    cargo_name: String,
    /// `true` when the dev-only `IPE_WATCH_HOT_APPEARANCE` flag is set. Routes
    /// style-value literals through a per-view `LiteralTable` for appearance
    /// hot-swap. Set via [`Self::with_hot_appearance`]; default off.
    hot_appearance: bool,
    /// `true` when the resolved delivery is `web desktop` — webview-native. The
    /// webview delivery is a HOST decision (from the CLI's resolved
    /// shape × runtime × host), not a distinct `main` entry, so it is threaded in
    /// here rather than read from a source leaf. It forces `uses_webview` on,
    /// which selects the webview executor and the `default = ["webview"]` feature.
    /// Set via [`Self::with_webview_host`]; default off (served `web`).
    webview_host: bool,
    /// The desktop window configuration for a webview-native (`web desktop`)
    /// delivery, resolved from the manifest `delivery.desktop` block. `None`
    /// (the default, and always for a served `web`) selects the built-in
    /// fallback window. Set via [`Self::with_webview_window`].
    webview_window: Option<WebViewWindow>,
}

/// The desktop window configuration for a webview-native (`web desktop`)
/// delivery, resolved by the CLI from the manifest `delivery.desktop` block.
///
/// The webview is the delivery HOST of the DOM `Web` shape, so the window is a
/// host decision carried in the backend options, never a source `main` field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WebViewWindow {
    /// The native window title.
    pub title: String,
    /// The initial window width in logical pixels.
    pub width: i64,
    /// The initial window height in logical pixels.
    pub height: i64,
}

/// Exact names Cargo rejects outright.
///
/// Independent of the character-class steps in [`CargoPackageName::sanitize`]
/// — verified against Cargo's own `validate_package_name` (pinned toolchain
/// 1.98.1, checked with `cargo new`/`cargo build` against the emitted
/// project's exact template):
///
/// * every strict/reserved [Rust keyword][reserved];
/// * the toolchain binary name `ipe` (a crate so named would shadow the CLI
///   on `$PATH`) and the weak keyword `union`, kept conservative for a crate
///   name;
/// * `build`, `deps`, `examples`, `incremental` — Cargo's own build-directory
///   names, forbidden as a binary target (the emitted crate has no `[[bin]]`
///   override, so the bin target is inferred from the package name);
/// * `test` — collides with Rust's built-in test harness, confirmed to fail
///   `cargo build` with "package name `test` conflicts with Rust's built-in
///   test library";
/// * the bare `_` — the Rust underscore token, not a legal identifier, even
///   though Cargo's grammar check alone happens to accept it as a package
///   name; guarded here as defense in depth rather than a proven build
///   failure.
///
/// [reserved]: https://doc.rust-lang.org/reference/keywords.html
fn is_reserved_cargo_name(name: &str) -> bool {
    const EXTRA_SUFFIXED: &[&str] = &["ipe", "union", "test", "_"];
    const CARGO_FORBIDDEN_BIN: &[&str] = &["build", "deps", "examples", "incremental"];

    ipe_intern::is_rust_keyword(name)
        || EXTRA_SUFFIXED.contains(&name)
        || CARGO_FORBIDDEN_BIN.contains(&name)
}

/// A Cargo package name Cargo is guaranteed to accept.
///
/// The only way to build one is [`Self::sanitize`], a total function: every
/// input, however hostile (empty, all-symbols, a reserved name, non-ASCII),
/// yields a valid name. No other constructor exists, so an unsanitized
/// string can never reach a manifest through this type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CargoPackageName(String);

impl CargoPackageName {
    /// Convert an arbitrary `package.ipe` name value into a valid Cargo
    /// package name and binary name.
    ///
    /// Cargo package names must be non-empty, start with a letter or `_`,
    /// contain only ASCII alphanumerics, `-`, and `_`, fit in 64 bytes, and
    /// not be one of the names `is_reserved_cargo_name` rejects outright.
    /// This applies a total, deterministic sanitization that never panics
    /// and never produces an invalid name:
    ///
    /// 1. Lowercase the input.
    /// 2. Replace every run of characters that are not `[a-z0-9_-]` with `-`.
    /// 3. Strip leading and trailing `-`.
    /// 4. If the result starts with a digit, prepend `app-`.
    /// 5. If the result is empty (input was all-invalid chars, or was the
    ///    empty string), use the fallback `ipe-app`.
    /// 6. If the result is a name Cargo rejects outright, append `-app`.
    /// 7. Truncate to 64 characters (Cargo's practical limit).
    ///
    /// Examples: `"my-app"` → `"my-app"`, `"My App"` → `"my-app"`,
    /// `"1game"` → `"app-1game"`, `""` → `"ipe-app"`, `"mod"` → `"mod-app"`,
    /// `"build"` → `"build-app"`, `"test"` → `"test-app"`, `"_"` → `"_-app"`.
    #[must_use]
    pub fn sanitize(name: &str) -> Self {
        // Step 1: lowercase.
        let lower = name.to_ascii_lowercase();

        // Step 2: replace runs of invalid chars with `-`.
        let mut out = String::with_capacity(lower.len());
        let mut in_run = false;
        for ch in lower.chars() {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                out.push(ch);
                in_run = false;
            } else if !in_run {
                out.push('-');
                in_run = true;
            }
        }

        // Step 3: strip leading/trailing `-`.
        let trimmed = out.trim_matches('-');

        // Step 4: if the first char is a digit, prepend `app-`.
        let mut result = if trimmed.starts_with(|c: char| c.is_ascii_digit()) {
            format!("app-{trimmed}")
        } else {
            trimmed.to_owned()
        };

        // Step 5: empty → fallback.
        if result.is_empty() {
            return Self("ipe-app".to_owned());
        }

        // Step 6: any name Cargo rejects outright gets `-app` appended to
        // keep the emitted crate buildable.
        if is_reserved_cargo_name(&result) {
            result.push_str("-app");
        }

        // Step 7: truncate to 64 chars at an ASCII boundary.
        if result.len() > 64 {
            result.truncate(64);
            // Ensure we don't end on a `-` after truncation.
            let trimmed_len = result.trim_end_matches('-').len();
            result.truncate(trimmed_len);
            if result.is_empty() {
                return Self("ipe-app".to_owned());
            }
        }

        Self(result)
    }

    /// Borrow the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the owned, validated `String`.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Convert an arbitrary `package.ipe` name value into a valid Cargo package
/// name and binary name.
///
/// A thin `String`-returning wrapper over [`CargoPackageName::sanitize`] for
/// callers that only ever splice the result into a manifest string and don't
/// need the typed wrapper.
#[must_use]
pub fn sanitize_cargo_name(name: &str) -> String {
    CargoPackageName::sanitize(name).into_inner()
}

/// The number of lowercase-hex characters of the path digest appended as the
/// per-project crate-identity suffix. Four bytes (eight hex chars) give 2^32
/// distinct slots — collision-negligible for the handful of same-named projects
/// a single shared target dir ever holds, while keeping the emitted name short.
const CRATE_IDENTITY_HEX_LEN: usize = 8;

/// Derive the emitted crate's unique identity from its sanitized friendly name
/// and the canonical project directory.
///
/// Ipê recommends a shared `CARGO_TARGET_DIR` for build speed. Cargo keys its
/// build-cache fingerprints by crate name, so two projects that share a friendly
/// name (both `test`) would occupy the SAME `<target>/<profile>/test` slot and
/// thrash each other's fingerprints — forcing a full rebuild on every project
/// switch, silently defeating the shared cache. Appending a stable suffix derived
/// from the canonical project path gives each project its own slot:
///
/// * **Deterministic** — the suffix is a pure function of `canonical_dir`; the
///   same project path yields the same crate name on every build.
/// * **Distinct** — two projects sharing a friendly name but living at different
///   canonical paths get different suffixes, so they never share a cache slot.
///
/// `base` is the already-[`sanitize_cargo_name`]d friendly name; the returned
/// value is `"<base>_<hex>"`, re-truncated so it never exceeds Cargo's 64-char
/// name limit. The suffix uses only `[0-9a-f]`, all Cargo-valid.
///
/// The FRIENDLY name is never derived from this — user-facing artifact names and
/// messages keep the plain project name; only the internal crate identity carries
/// the suffix.
#[must_use]
pub fn crate_identity(base: &str, canonical_dir: &std::path::Path) -> String {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(canonical_dir.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(CRATE_IDENTITY_HEX_LEN);
    for byte in digest.iter().take(CRATE_IDENTITY_HEX_LEN / 2) {
        // `{byte:02x}` is exactly two lowercase-hex chars per byte — total width
        // is `CRATE_IDENTITY_HEX_LEN`, both Cargo-valid.
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }

    // Reserve room for `_<hex>` under the 64-char ceiling so the join never
    // produces an over-long (Cargo-rejected) name; trim the base, never the hash.
    let max_base = 64usize.saturating_sub(CRATE_IDENTITY_HEX_LEN + 1);
    let mut base_trunc = base;
    if base_trunc.len() > max_base {
        base_trunc = base_trunc.get(..max_base).unwrap_or(base_trunc);
    }
    let base_trunc = base_trunc.trim_end_matches('-');
    format!("{base_trunc}_{hex}")
}

/// The dependency-model emit selector.
///
/// When present, the emitted project declares the runtime as a cargo dependency
/// with a relative path (`ipe_runtime_dep/`) and a [`runtime_features`]-selected
/// feature list; it vendors no runtime source into `src/ipe_runtime/`. The driver
/// bundles the embedded runtime source tree under `ipe_runtime_dep/` alongside the
/// emitted crate so the relative path dep resolves in any environment (cross-
/// compiler container, offline, CI) without a host-absolute path. Absent (the
/// default) emits the byte-identical vendored-source project.
///
/// The `root` field identifies the resolved runtime crate root. It is resolved
/// by the driver (fail-closed — a missing or wrong-package root is a loud
/// refusal) and retained for diagnostics and cache-key purposes; the emitter no
/// longer embeds it in the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeDep {
    /// The absolute, canonical runtime crate root (the directory holding the
    /// runtime `Cargo.toml`), retained for diagnostics and cache keying.
    pub root: std::path::PathBuf,
}

impl<'a> RustBackend<'a> {
    /// Construct a backend that resolves IR symbols through `interner`.
    /// Defaults to [`DbDriver::Sqlite`] — call [`Self::with_db_driver`] to
    /// target Postgres.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // String::new() is not const-stable
    pub fn new(interner: &'a Interner) -> Self {
        Self {
            interner,
            db_driver: DbDriver::Sqlite,
            ffi: None,
            target: ipe_ir::Target::Native,
            wasm_public_env: Vec::new(),
            wasm_hydrate_mode: false,
            runtime_dep: None,
            debugger: false,
            build_intent: BuildIntent::Release,
            cargo_name: String::new(),
            hot_appearance: false,
            webview_host: false,
            webview_window: None,
        }
    }

    /// Set the emitted crate's package name from the `package.ipe` name field.
    /// The value is sanitized via [`sanitize_cargo_name`] before use, so any
    /// valid (or invalid) name produces a valid Cargo package name.
    /// When not called (or called with an empty string), the emitted crate is
    /// named `ipe-app` — the safe default.
    #[must_use]
    pub fn with_project_name(mut self, name: &str) -> Self {
        self.cargo_name = sanitize_cargo_name(name);
        self
    }

    /// Select the dependency-model emit: the emitted project declares the runtime
    /// as a path dependency with a [`runtime_features`]-selected feature list and
    /// vendors no runtime source. `None` keeps the vendored-source emit.
    ///
    /// Applies to BOTH targets. The native project selects the reached native
    /// features; the wasm project selects the `wasm-client` floor (which pulls
    /// the whole closed browser module set + its glue crates transitively) plus
    /// any browser-admissible surface it reaches — one emit model, no vendored
    /// subtree on either target.
    #[must_use]
    pub fn with_runtime_dep(mut self, runtime_dep: Option<RuntimeDep>) -> Self {
        self.runtime_dep = runtime_dep;
        self
    }

    /// Enable the development-only time-travelling debugger: the emitted
    /// project's runtime dependency gains the `debugger` feature so the TEA
    /// driver records each `(msg, model)` step. `ipe release` never calls this
    /// (the flag is a `build`/`run`-only opt-in), so a production artifact never
    /// carries recorder code.
    #[must_use]
    pub const fn with_debugger(mut self, debugger: bool) -> Self {
        self.debugger = debugger;
        self
    }

    /// State the verb family this emit serves.
    ///
    /// `Development` adds the runtime `dev-posture` feature (dependency model)
    /// or promotes it into the vendored manifest's default list; `Release`
    /// emits neither, so the shipped binary has no development console default.
    #[must_use]
    pub const fn with_build_intent(mut self, intent: BuildIntent) -> Self {
        self.build_intent = intent;
        self
    }

    /// Mark the emit as a webview-native (`web desktop`) delivery. This is the
    /// single source of the `uses_webview` signal: it is a resolved host
    /// decision from the CLI, not a source-level entry. When set, the emitted
    /// project selects the webview executor and promotes `webview` to the default
    /// feature list; a served `web` (the default host) leaves it unset.
    #[must_use]
    pub const fn with_webview_host(mut self, webview_host: bool) -> Self {
        self.webview_host = webview_host;
        self
    }

    /// Set the desktop window configuration for a webview-native (`web desktop`)
    /// delivery. Sourced from the manifest `delivery.desktop` block by the CLI.
    /// Only consulted when [`Self::with_webview_host`] is set; a served `web`
    /// leaves it `None`.
    #[must_use]
    pub fn with_webview_window(mut self, window: Option<WebViewWindow>) -> Self {
        self.webview_window = window;
        self
    }

    /// Enable the dev-only appearance hot-swap emit: style-value literals passed
    /// directly to an allowlisted `Ui.*` style kernel are hoisted into a per-view
    /// `LiteralTable` (baked defaults = the source values) and emitted as
    /// `__ipe_lit.get(N)` reads. Set from `IPE_WATCH_HOT_APPEARANCE`. Default off,
    /// in which case the emit is byte-identical to the direct-literal form.
    #[must_use]
    pub const fn with_hot_appearance(mut self, hot_appearance: bool) -> Self {
        self.hot_appearance = hot_appearance;
        self
    }

    /// Select the compilation target the emitted project is built for
    /// (`Native` by default; `WasmClient` under `ipe dev build --target wasm`).
    #[must_use]
    pub const fn with_target(mut self, target: ipe_ir::Target) -> Self {
        self.target = target;
        self
    }

    /// Select the SQL driver the emitted project targets (from `package.ipe`'s
    /// database setting). No-op on programs that don't use any Db kernel.
    #[must_use]
    pub const fn with_db_driver(mut self, driver: DbDriver) -> Self {
        self.db_driver = driver;
        self
    }

    /// Supply the consumer-side FFI emission inputs (from the project's
    /// installed FFI artifact cache). No-op on programs that lower no
    /// foreign-wrapper call.
    #[must_use]
    pub fn with_ffi(mut self, ffi: Option<FfiEmit>) -> Self {
        self.ffi = ffi;
        self
    }

    /// Supply the `[wasm] publicEnv` allowlist (from `package.ipe`, already
    /// validated against the secret-name denylist at parse time — see
    /// `ipe_cli::project::is_denylisted_public_env_name`). No-op on programs
    /// that call no `Env.public`. Threaded through regardless of
    /// [`Self::target`] so a shared module compiling under both `Native` and
    /// `WasmClient` gets the SAME allowlist on each.
    #[must_use]
    pub fn with_wasm_public_env(mut self, names: Vec<String>) -> Self {
        self.wasm_public_env = names;
        self
    }

    /// Enable the `[wasm] mode = "hydrate"` emission path (M7 SSR + hydration).
    /// When set, the emitted wasm crate exports a `#[wasm_bindgen] pub fn
    /// hydrate(model_json: &str)` in addition to the `#[wasm_bindgen(start)]`
    /// `ipe_start` entry. The `hydrate` export parses the island JSON,
    /// calls `ipe_runtime::wasm::wasm_adopt_app` on success, and falls back to
    /// `ipe_main()` with a console warning on parse failure (fault-tolerant
    /// hydrate — spec Q6 §"Fault-tolerant hydrate — parse, don't unwrap").
    #[must_use]
    pub const fn with_wasm_hydrate_mode(mut self, enabled: bool) -> Self {
        self.wasm_hydrate_mode = enabled;
        self
    }

    /// Render the `Spine` tier's Rust text for `program` — the program-wide
    /// entry file content (see [`project::emit_spine`] for the full
    /// specification). ADDITIVE entry point: NOT on the public
    /// emission path ([`Backend::emit`] still produces a single file). Builds
    /// the [`EmitCtx`] the same way [`Backend::emit`] does, then delegates.
    ///
    /// # Errors
    ///
    /// Propagates any [`Diagnostic`] from [`EmitCtx::build`] or
    /// [`project::emit_spine`].
    pub fn emit_spine(&self, program: &Program) -> DResult<String> {
        let ctx = EmitCtx::build(
            self.interner,
            program,
            self.db_driver,
            self.ffi.clone(),
            self.target,
            self.wasm_public_env.clone(),
            self.wasm_hydrate_mode,
            self.runtime_dep.clone(),
            self.debugger,
            self.build_intent,
            self.cargo_name.clone(),
            self.hot_appearance,
            self.webview_host,
            self.webview_window.clone(),
        )?;
        project::emit_spine(&ctx, program)
    }

    /// Build the [`EmitCtx`] for `program` exactly as [`Backend::emit`] does,
    /// exposed for the `runtime_features` unit tests so they can exercise the
    /// SSOT through the real ctx (with its `uses_*` derivation, `db_driver`
    /// selection, and async-spine folding) rather than a hand-built stand-in.
    ///
    /// # Errors
    ///
    /// Propagates any [`Diagnostic`] from [`EmitCtx::build`].
    #[cfg(test)]
    pub(crate) fn emit_ctx_for_tests(&self, program: &Program) -> DResult<EmitCtx<'a>> {
        EmitCtx::build(
            self.interner,
            program,
            self.db_driver,
            self.ffi.clone(),
            self.target,
            self.wasm_public_env.clone(),
            self.wasm_hydrate_mode,
            self.runtime_dep.clone(),
            self.debugger,
            self.build_intent,
            self.cargo_name.clone(),
            self.hot_appearance,
            self.webview_host,
            self.webview_window.clone(),
        )
    }

    /// The runtime-crate cargo features `program` selects — the SSOT
    /// ([`runtime_features::runtime_features`]) image for this program, as the
    /// canonical `features = [...]` name list. NOT yet wired into emit; exposed
    /// so the featureset-closure SEAL can validate the SSOT against the runtime
    /// crate's `[features]` universe and the emitted `ipe_runtime::<mod>::`
    /// references, without leaking the crate-private [`EmitCtx`].
    ///
    /// # Errors
    ///
    /// Propagates any [`Diagnostic`] from [`EmitCtx::build`].
    pub fn runtime_feature_names(&self, program: &Program) -> DResult<Vec<&'static str>> {
        let ctx = EmitCtx::build(
            self.interner,
            program,
            self.db_driver,
            self.ffi.clone(),
            self.target,
            self.wasm_public_env.clone(),
            self.wasm_hydrate_mode,
            self.runtime_dep.clone(),
            self.debugger,
            self.build_intent,
            self.cargo_name.clone(),
            self.hot_appearance,
            self.webview_host,
            self.webview_window.clone(),
        )?;
        Ok(runtime_features::runtime_features(&ctx).as_feature_names())
    }

    /// Render one `IpeModule(home)` file's Rust text for `program` (see
    /// [`project::emit_module_file`]). ADDITIVE entry point: NOT
    /// on the public emission path. Builds the [`EmitCtx`] the same way
    /// [`Backend::emit`] does, then delegates.
    ///
    /// # Errors
    ///
    /// Propagates any [`Diagnostic`] from [`EmitCtx::build`] or
    /// [`project::emit_module_file`].
    pub fn emit_module_file(&self, program: &Program, home: &ModPath) -> DResult<String> {
        let ctx = EmitCtx::build(
            self.interner,
            program,
            self.db_driver,
            self.ffi.clone(),
            self.target,
            self.wasm_public_env.clone(),
            self.wasm_hydrate_mode,
            self.runtime_dep.clone(),
            self.debugger,
            self.build_intent,
            self.cargo_name.clone(),
            self.hot_appearance,
            self.webview_host,
            self.webview_window.clone(),
        )?;
        project::emit_module_file(
            &ctx,
            program,
            &rust_file::RustFileId::IpeModule(home.clone()),
        )
    }

    /// Assemble the full split [`EmittedProject`] from already-rendered per-file
    /// texts — `spine_text` (from [`Self::emit_spine`]) plus `module_texts`
    /// (`home` → [`Self::emit_module_file`] output). The
    /// file-count-AGNOSTIC manifest/runtime block is shared verbatim with
    /// [`Backend::emit`]'s single-file path, so the result is byte-identical to
    /// [`Backend::emit`]'s output for the same multi-module program (design doc
    /// §4.4 — the `ipe_db::emit_manifest` assembly seam). NOT on the
    /// single-file path; the caller ([`ipe_db::emit_manifest`]) invokes it ONLY
    /// when 2+ distinct homes are present.
    ///
    /// # Errors
    ///
    /// Propagates any [`Diagnostic`] from [`EmitCtx::build`] or
    /// [`project::assemble_split_manifest`] (`mod_ident` gates, `RelPath`
    /// validation, a missing per-home text, the manifest/runtime construction).
    pub fn assemble_split_manifest(
        &self,
        program: &Program,
        spine_text: &str,
        module_texts: &BTreeMap<ModPath, String>,
    ) -> DResult<EmittedProject> {
        let ctx = EmitCtx::build(
            self.interner,
            program,
            self.db_driver,
            self.ffi.clone(),
            self.target,
            self.wasm_public_env.clone(),
            self.wasm_hydrate_mode,
            self.runtime_dep.clone(),
            self.debugger,
            self.build_intent,
            self.cargo_name.clone(),
            self.hot_appearance,
            self.webview_host,
            self.webview_window.clone(),
        )?;
        project::assemble_split_manifest(&ctx, program, spine_text, module_texts)
    }
}

/// The DISTINCT Ipê-module `home`s the backend would emit an OWN Rust file for.
///
/// Every [`rust_file::RustFileId::IpeModule`] bucket [`rust_file::
/// partition_items`] produces, `Spine` excluded (`Spine` is not a per-module
/// home — it is the always-present entry file). This is the `home`-set
/// quantifier `ipe_db::program_rust_file_ids` wraps in a
/// tracked query (spec §4.2): a Ipê-module add/delete changes this set, making
/// "which files exist" a first-class, salsa-observable value.
///
/// Order-agnostic by construction (`BTreeSet`) — callers that need the
/// warm/cold-stable EMISSION order use [`rust_file::partition_items`]'s
/// `type_order`/`func_order` directly ([`project::emit_program`] does); this
/// set answers only the membership question.
#[must_use]
pub fn rust_file_homes(program: &Program, interner: &Interner) -> BTreeSet<ModPath> {
    rust_file::partition_items(program, interner)
        .buckets
        .into_keys()
        .filter_map(|id| match id {
            rust_file::RustFileId::IpeModule(home) => Some(home),
            rust_file::RustFileId::Spine => None,
        })
        .collect()
}

impl Backend for RustBackend<'_> {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn emit(&self, program: &Program) -> DResult<EmittedProject> {
        let ctx = EmitCtx::build(
            self.interner,
            program,
            self.db_driver,
            self.ffi.clone(),
            self.target,
            self.wasm_public_env.clone(),
            self.wasm_hydrate_mode,
            self.runtime_dep.clone(),
            self.debugger,
            self.build_intent,
            self.cargo_name.clone(),
            self.hot_appearance,
            self.webview_host,
            self.webview_window.clone(),
        )?;
        project::emit_program(&ctx, program)
    }
}

/// One enum's variants as `(variant name, payload field types)`, in
/// declaration order — the value shape of [`EmitCtx::enum_variants`] (an
/// [`ipe_ir::EnumPayloadTable`]).
type VariantList = Vec<(Symbol, Vec<IrType>)>;

/// A canonical record field list: `(Ipê field name, field type)` pairs sorted by
/// field name. The order is the struct's declaration / `IpeStringify` read order.
type RecordFields = Vec<(String, IrType)>;

/// Every DISTINCT field-type shape observed for one field-name set, in
/// first-occurrence order — a generic template and/or its concrete
/// instantiations, reconciled by [`canonicalise_shape`].
type ShapeOccurrences = Vec<RecordFields>;

/// A synthesised struct's reconciled form: its canonical field template and its
/// generic parameter symbols (empty for a monomorphic record).
type CanonicalShape = (RecordFields, Vec<Symbol>);

/// A synthesised Rust struct for one distinct CLOSED record shape.
///
/// `fields` is the field set in canonical (field-name ascending) order — the
/// order the struct is declared in and the order its `IpeStringify` body reads.
pub(crate) struct RecordStruct {
    /// The deduplicated, collision-free Rust struct name (e.g. `RecXY`).
    pub name: String,
    /// The fields as `(Ipê field name, field type)`, sorted by field name. The
    /// Rust field identifier is the keyword-mangled field name.
    ///
    /// For a GENERIC record shape, a field's type may be an
    /// [`IrType::Generic`]; the carried [`Symbol`] is the canonical template's
    /// source type-variable, resolved to its Rust generic name (`T1`, `T2`, …)
    /// through a [`crate::emit_types::GenericScope`] over [`Self::type_params`].
    pub fields: Vec<(String, IrType)>,
    /// The struct's generic type parameters: the distinct
    /// [`IrType::Generic`] symbols appearing in [`Self::fields`], in
    /// first-occurrence field order. Empty for a monomorphic record — that path
    /// emits no generic clause.
    ///
    /// The order is load-bearing: a parameter's Rust name (`T1`, `T2`, …) is its
    /// *position* here, exactly as for [`ipe_ir::Func::type_params`], so struct
    /// declaration, field types, and every use-site instantiation agree.
    pub type_params: Vec<Symbol>,
    /// `true` iff every field's type renders to a Rust type supporting the full
    /// `#[derive(Clone, Debug, PartialEq)]` set (see
    /// [`ipe_ir::ir_type_is_derivable`]). Computed once at [`EmitCtx::build`]
    /// against the whole-program enum-derivability fixpoint. The emitter reads
    /// this flag to choose the `CDPeq` derive set, so a record holding a first-class
    /// function / opaque wrapper can never reach the unconditional derive by
    /// construction (upholds the SEAL).
    pub is_derivable: bool,
    /// `true` iff every field's type renders to a Rust type that ALSO derives
    /// `serde::Serialize` + `serde::Deserialize` (see [`ipe_ir::ir_type_is_serde`]).
    /// Computed once at [`EmitCtx::build`] against the whole-program enum-serde
    /// fixpoint. STRICTLY implies [`Self::is_derivable`] (serde-OK leaves are a
    /// subset of derivable leaves). The emitter reads this flag — NOT
    /// `is_derivable` — to gate the serde derive under `uses_web`, so a
    /// `CDPeq`-but-not-serde record (a view-helper holding `Html` / `Element` /
    /// `Color` / a `UiPlain` value) in a Ipe.Web program never gets serde forced
    /// onto it and therefore never exit-0-then-cargo-fails on `E0277` (upholds
    /// the SEAL).
    pub is_serde: bool,
    /// `true` iff every field's DEFAULT emitted carrier is `Clone` (see
    /// [`ipe_ir::carrier_is_clone`]) — a strictly WEAKER property than
    /// [`Self::is_derivable`], because the promoted `Arc<dyn Fn>` fn carrier
    /// ([`ipe_ir::IrType::SharedFun`]) is `Clone` but neither `Debug` nor
    /// `PartialEq`. A record that is `is_clone` but not `is_derivable` gets a
    /// HAND-WRITTEN `impl Clone` (never the `CDPeq` derive), which is what lets
    /// the fn-value-reuse promotion duplicate a reused record-of-functions —
    /// without it, `c.clone()` would be an `ipe`-0-then-cargo-fail `E0599`
    /// (SEAL break). `is_derivable ⇒ is_clone` (a `CDPeq` type is `Clone`), so
    /// the two flags never disagree in the derivable direction.
    pub is_clone: bool,
}

/// Per-function scratch for the dev appearance hot-swap emit (Step 1).
///
/// A function body is emitted with a fresh accumulator: each hoisted style
/// literal appends its source value to `defaults` and takes the returned index
/// as its `LiteralTable` slot. After the body is rendered, a non-empty
/// `defaults` triggers a `let __ipe_lit = LiteralTable::from_defaults(&[…]);`
/// prologue whose baked defaults are exactly those source values — so a read of
/// `__ipe_lit.get(N)` is indistinguishable from the direct literal (dev == prod).
///
/// `closure_depth` fences the hoist to the function body's top emission level:
/// a `move` closure captures `__ipe_lit` by move, so hoisting inside one would
/// contend with the binding's other uses. Literals inside a lambda body emit
/// directly (unchanged) — conservative and sound, covering the dominant
/// top-level view-style case.
#[derive(Default)]
struct LiteralAccum {
    /// Whether a function body is currently being emitted with hoisting armed.
    active: bool,
    /// Emission nesting inside `move` closures; hoisting fires only at depth 0.
    closure_depth: u32,
    /// Nesting inside a discard-only *probe* emit (the shape/width predicate that
    /// re-runs an emitter to decide a layout, throwing the result away). A probe
    /// must not append to the table — the real emit does that — or the literal
    /// would be counted twice. Hoisting is suppressed while this is non-zero.
    probe_depth: u32,
    /// The hoisted literals' source values, in emit order — the table defaults.
    defaults: Vec<String>,
}

/// The transient, per-scope emit state — everything whose value depends on
/// *where in the emission* we currently are, not on the immutable program-wide
/// configuration held by the rest of [`EmitCtx`]. Kept apart from that config by
/// construction so a scope field can never be mistaken for (or leak into) a
/// configuration flag: this is the only mutable surface of [`EmitCtx`], reachable
/// solely through the balanced `enter`/`exit` (and `begin`/`end`) methods below.
///
/// Every field is interior-mutable so the emit — which threads a shared
/// `&EmitCtx` — can arm and disarm a scope without an added parameter on every
/// emit function.
#[derive(Default)]
struct ScopeState {
    /// Per-function accumulator for hoisted style literals, reset at the start of
    /// each function body (see [`LiteralAccum`]).
    lit_accum: RefCell<LiteralAccum>,
    /// The `Model` parameter symbol of the `update` function currently being
    /// emitted, set only while emitting a TEA `update` lambda body under
    /// [`EmitCtx::hot_appearance`]. `Some` there arms
    /// [`crate::emit_expr::emit_match`] to reduce a data-describable arm to an
    /// `apply_transition_hot` call (the logic counterpart of the appearance
    /// literal-table hoist); `None` everywhere else, so no other `case` is ever
    /// transition-rewritten.
    transition_model_param: RefCell<Option<ipe_intern::Symbol>>,
    /// Whether a TEA `subscriptions` body is currently being emitted under
    /// [`EmitCtx::hot_appearance`]. `true` only while emitting a
    /// `Model -> Sub Msg` function body under the flag; arms
    /// [`crate::emit_expr`]'s `Sub.every` / `Time.every` kernel emit to reduce a
    /// data-describable tick entry to a `sub_every_hot("<baked datum>")` call.
    /// `false` everywhere else, so no other `Sub.every`/`Time.every` is ever
    /// sub-rewritten.
    subs_hot_active: RefCell<bool>,
}

impl ScopeState {
    /// Arm the per-function literal accumulator for a fresh function body and
    /// return the previous accumulator state so the caller can restore it after
    /// the body is emitted. Only meaningful under
    /// [`EmitCtx::hot_appearance`]; when the flag is off it is a cheap no-op
    /// reset that stays inert (nothing ever hoists), keeping the emit
    /// byte-identical to the direct-literal form.
    fn begin_function_literals(&self, hot_appearance: bool) -> LiteralAccum {
        std::mem::replace(
            &mut *self.lit_accum.borrow_mut(),
            LiteralAccum {
                active: hot_appearance,
                closure_depth: 0,
                probe_depth: 0,
                defaults: Vec::new(),
            },
        )
    }

    /// Finish the current function body: take its accumulated style-literal
    /// defaults (in emit order) and restore the previous accumulator. An empty
    /// vector means nothing was hoisted, so the caller emits no table prologue.
    fn end_function_literals(&self, previous: LiteralAccum) -> Vec<String> {
        let finished = std::mem::replace(&mut *self.lit_accum.borrow_mut(), previous);
        finished.defaults
    }

    /// Enter a `move`-closure body: hoisting is fenced off inside a closure
    /// because it captures `__ipe_lit` by move. Balanced by [`Self::exit_closure`].
    fn enter_closure(&self) {
        self.lit_accum.borrow_mut().closure_depth += 1;
    }

    /// Leave a `move`-closure body, re-enabling top-level hoisting once every
    /// enclosing closure has been left. Saturating so an unbalanced call can
    /// never underflow (it would only, at worst, leave hoisting fenced off).
    fn exit_closure(&self) {
        let mut accum = self.lit_accum.borrow_mut();
        accum.closure_depth = accum.closure_depth.saturating_sub(1);
    }

    /// Arm the `update`-arm transition rewrite for the duration of the `update`
    /// lambda body. Returns the previous value so the caller can restore it.
    fn begin_transition_update(
        &self,
        model_param: Option<ipe_intern::Symbol>,
    ) -> Option<ipe_intern::Symbol> {
        std::mem::replace(&mut *self.transition_model_param.borrow_mut(), model_param)
    }

    /// Restore the transition-update arming saved by [`Self::begin_transition_update`].
    fn end_transition_update(&self, prev: Option<ipe_intern::Symbol>) {
        *self.transition_model_param.borrow_mut() = prev;
    }

    /// The `Model` parameter of the `update` lambda currently being emitted, when
    /// the transition rewrite is armed; `None` otherwise.
    fn transition_model_param(&self) -> Option<ipe_intern::Symbol> {
        *self.transition_model_param.borrow()
    }

    /// Arm the `subscriptions`-entry sub-description rewrite for the duration of a
    /// TEA `subscriptions` lambda body. Returns the previous value so the caller
    /// can restore it.
    fn begin_subs_hot(&self, active: bool) -> bool {
        std::mem::replace(&mut *self.subs_hot_active.borrow_mut(), active)
    }

    /// Restore the subscriptions arming saved by [`Self::begin_subs_hot`].
    fn end_subs_hot(&self, prev: bool) {
        *self.subs_hot_active.borrow_mut() = prev;
    }

    /// Whether the `subscriptions`-entry sub-description rewrite is currently armed.
    fn subs_hot_active(&self) -> bool {
        *self.subs_hot_active.borrow()
    }

    /// Enter a discard-only probe emit: hoisting is suppressed so the probe does
    /// not append a literal the real emit will append again. Balanced by
    /// [`Self::exit_probe`].
    fn enter_probe(&self) {
        self.lit_accum.borrow_mut().probe_depth += 1;
    }

    /// Leave a probe emit, re-enabling hoisting once every enclosing probe has
    /// been left. Saturating against an unbalanced call.
    fn exit_probe(&self) {
        let mut accum = self.lit_accum.borrow_mut();
        accum.probe_depth = accum.probe_depth.saturating_sub(1);
    }

    /// Hoist a style-value literal into the current function's table, returning
    /// its slot index. `None` when hoisting is not armed (flag off, no active
    /// body, or inside a `move` closure) — the caller then emits the literal
    /// directly. The baked default is exactly `value`, so a read of the returned
    /// slot renders identically to the direct literal (dev == prod).
    fn hoist_style_literal(&self, value: &str) -> Option<usize> {
        let mut accum = self.lit_accum.borrow_mut();
        if !accum.active || accum.closure_depth != 0 || accum.probe_depth != 0 {
            return None;
        }
        let idx = accum.defaults.len();
        accum.defaults.push(value.to_owned());
        Some(idx)
    }
}

/// Shared emission context: the interner plus the precomputed Ipê → Rust name
/// maps so each emit site is a `O(log n)` lookup rather than recomputing the
/// naming rules. Built once per [`RustBackend::emit`].
// The `uses_*` bools are frozen reachability inputs, computed once in `build`
// and read-only thereafter; the `reaches_*` unions over them are the gates the
// real interface — [`crate::capabilities::CAPABILITIES`] — reads to drive the
// runtime feature-set walks. The bool count is incidental, not a design smell.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct EmitCtx<'a> {
    interner: &'a Interner,
    /// `true` when the lowerer injected synthetic `SqlValue` / `SqlField`
    /// `EnumDef`s — i.e. the program uses at least one Db kernel. When set,
    /// [`crate::project::emit_program`]:
    ///
    /// * emits a db-enabled `Cargo.toml` (adds `db` to default features +
    ///   adds the `sqlx` dependency);
    /// * emits a db-enabled `ipe_runtime/mod.rs` (adds `pub mod db; pub use
    ///   db::*;`);
    /// * emits a db-enabled `ipe_runtime/config.rs` (full DbPool/DbRow/…
    ///   aliases gated on `#[cfg(feature = "db")]`);
    /// * appends `into_sql_param` / `into_field_param` impl blocks after the
    ///   user type declarations, so the Db call sites can project Ipê ADT
    ///   values to the runtime's `SqlParam`.
    pub(crate) uses_db: bool,
    /// Which SQL driver the emitted `Cargo.toml` / `ipe_runtime/config.rs`
    /// target when [`Self::uses_db`] is set (from `package.ipe`'s database
    /// setting, threaded in via [`RustBackend::with_db_driver`]). Meaningless /
    /// ignored when `uses_db` is `false`.
    pub(crate) db_driver: DbDriver,
    /// The compilation target (`Native` | `WasmClient`) — selects the manifest
    /// template, the vendored runtime module set, and the entry shape.
    pub(crate) target: ipe_ir::Target,
    /// `true` when the program uses at least one TEA (`Cmd` / `Sub` /
    /// `Time.every`) kernel. When set,
    /// [`crate::project::emit_program`]:
    ///
    /// * appends `pub mod tea; pub use tea::*;` to the emitted
    ///   `ipe_runtime/mod.rs`, making `cmd_none` / `sub_every` / … available;
    /// * adds `pub type IpeCmd<M> = ipe_runtime::tea::IpeCmd<M>;` and
    ///   `pub type IpeSub<M> = ipe_runtime::tea::IpeSub<M>;` to `main.rs`.
    ///
    /// `tea.rs` is ungated (no `live` cargo feature needed); the only
    /// dependency is `tokio`, which is already in the default feature set.
    pub(crate) uses_tea: bool,
    /// `true` when the program uses at least one Ipe.Http.Server kernel.
    /// When set, [`crate::project::emit_program`]:
    ///
    /// * adds `"server"` to the default features of the emitted `Cargo.toml`
    ///   and appends `axum` + `tower-http` dependencies;
    /// * extends the `tokio` dependency with `"net"` and `"sync"` features;
    /// * appends `pub mod server; pub use server::*; pub mod server_stream;
    ///   pub use server_stream::*;` to the emitted `ipe_runtime/mod.rs`.
    ///   (`http_stream` is declared separately under `reaches_http_client`.)
    pub(crate) uses_server: bool,
    /// `true` when the program uses at least one outbound `Ipe.Http` client
    /// kernel (`Http.get` / `post` / `request`, the pure request/method
    /// builders, `Http.parseQuery`) or mentions an `HttpRequest` / `HttpMethod`
    /// in a signature. When set, [`crate::project::assemble_project_files`]:
    ///
    /// * declares `pub mod http_client; pub use http_client::*;` in the emitted
    ///   `ipe_runtime/mod.rs` (shared with `uses_email` via `reaches_http_client`);
    /// * declares `pub mod http_stream; pub use http_stream::*;` in the emitted
    ///   `ipe_runtime/mod.rs` (exclusive to `uses_http` — NOT pulled in by
    ///   `uses_email` alone, which only needs `http_client::ssrf_apply`);
    /// * adds the `reqwest` dependency to the emitted `Cargo.toml`;
    /// * keeps the `http_client` kernel-wrapper bindings in the emitted prelude.
    ///
    /// The `url` crate stays unconditional (it backs the always-present
    /// `Ipe.Url` and `ssrf` surfaces), so only the reqwest HTTP stack is gated.
    /// `uses_email` also forces `http_client` on (`email.rs` calls `ssrf_apply`),
    /// but does NOT force `http_stream` (no streaming surface in email).
    /// Server/web/webview shapes without an outbound HTTP kernel omit reqwest.
    pub(crate) uses_http: bool,
    /// `true` when the program uses at least one `Ipe.Config` decoder that emits
    /// into the `config_decode` runtime module (`Config.decodeToml` /
    /// `decodeYaml` / `decodeJson` / `loadFromFile`, or the `config_decode`-own
    /// `nullable` / `maybe` / `dict`). When set,
    /// [`crate::project::assemble_project_files`]:
    ///
    /// * declares `pub mod config_decode; pub use config_decode::*;` in the
    ///   emitted `ipe_runtime/mod.rs`;
    /// * adds the `toml` + `serde_yaml` dependencies to the emitted `Cargo.toml`.
    ///
    /// The JSON-backed `Config.*` combinators (`string` / `field` / `map` / …)
    /// emit into the `json` module, so a program that only decodes
    /// JSON never sets this and pulls neither crate. `config_decode` is a leaf
    /// module — no other runtime surface reaches it — so no other `uses_*` flag
    /// forces it on.
    pub(crate) uses_config: bool,
    /// `true` when the program uses at least one `Ipe.Compression` kernel
    /// (`Compression.gzip` / `gunzip` / `zstdCompress` / `zstdDecompress`). When
    /// set, [`crate::project::assemble_project_files`]:
    ///
    /// * declares `pub mod compression; pub use compression::*;` in the emitted
    ///   `ipe_runtime/mod.rs`;
    /// * adds the `flate2` + `zstd` dependencies to the emitted `Cargo.toml`.
    ///
    /// `compression` is a leaf module — no other runtime surface reaches it — so
    /// no other `uses_*` flag forces it on.
    pub(crate) uses_compression: bool,
    /// `true` when the program uses at least one `Ipe.Csv` kernel (`Csv.parse` /
    /// `parseWithDelimiter` / `encode` / `encodeWithDelimiter` /
    /// `parseStreamFromFile`) or a signature mentioning `CsvDoc`. When set,
    /// [`crate::project::assemble_project_files`]:
    ///
    /// * declares `pub mod csv; pub use csv::*;` in the emitted
    ///   `ipe_runtime/mod.rs`;
    /// * adds the `csv` dependency to the emitted `Cargo.toml`.
    ///
    /// `csv` is a leaf module — no other runtime surface reaches it — so no other
    /// `uses_*` flag forces it on.
    pub(crate) uses_csv: bool,
    /// `true` when the program uses at least one `Ipe.Cache` kernel (`Cache.new` /
    /// `get` / `put` / `remove` / `clear` / `size` / `stats`) or a
    /// signature/record/enum mentioning the folded `CacheCfg` / `CacheStats`
    /// records. When set, [`crate::project::assemble_project_files`]:
    ///
    /// * declares `pub mod cache; pub use cache::*;` in the emitted
    ///   `ipe_runtime/mod.rs` (the vendored path);
    /// * selects the `cache_kernel` runtime feature (the dependency-model path),
    ///   so the runtime crate compiles `cache.rs` (its `cache_new_raw` /
    ///   `cache_get` / `cache_put` / … functions, the `CacheCfg` / `CacheStats`
    ///   structs, and the `IpeCacheHandle` enum the emitted code references).
    ///
    /// `cache` is a leaf module — no other runtime surface reaches it — so no other
    /// `uses_*` flag forces it on.
    pub(crate) uses_cache: bool,
    /// `true` when the program reaches an `Ipe.Encoding` / `Ipe.Bytes` kernel. The
    /// `encoding` runtime feature — the `base64`, `hex`, and `percent-encoding`
    /// crates plus the `encoding.rs` / `bytes.rs` modules — is selected under
    /// [`Self::reaches_encoding`]: this flag unioned with the `crypto`, `db`,
    /// `server`, `email`, `jwt`, and `web` surfaces, whose runtime modules use the
    /// raw codec crates directly.
    pub(crate) uses_encoding: bool,
    /// `true` when the program reaches an `Ipe.Regex` kernel or `String.isUrl`.
    /// The `regex` runtime feature — the `regex` crate (and its `aho-corasick` /
    /// `regex-automata` / `regex-syntax` subtree) plus the `regex_kernel.rs`
    /// module — is selected on this flag alone: `regex` is a standalone leaf, no
    /// other surface reaches it.
    pub(crate) uses_regex: bool,
    /// `true` when the program reaches an `Ipe.Uuid` kernel. The `uuid` runtime
    /// feature — the `uuid` crate plus the `uuid_kernel.rs` module — is selected
    /// under [`Self::reaches_uuid`]: this flag unioned with the `server` and `web`
    /// surfaces, whose runtime modules mint session/CSRF ids via `uuid::new_v4`.
    pub(crate) uses_uuid: bool,
    /// `true` when the program reaches an `Ipe.Random` kernel. The `random`
    /// runtime feature gates the `random.rs` module declaration; this flag alone
    /// selects it (`random` is a standalone leaf). It does NOT gate the
    /// `getrandom` crate, which every runtime carries.
    pub(crate) uses_random: bool,
    /// `true` when the program reaches an `Ipe.Log` kernel. The `log` runtime
    /// feature gates the `log.rs` module and — via `log = ["dep:chrono"]` — the
    /// base `chrono` crate. This flag alone selects `log` (a standalone leaf);
    /// `chrono` itself is selected under [`Self::reaches_time_core`] (`log` OR any
    /// Time/Db/Web/WebView surface). `Debug.log` does NOT set this (`debug.rs` is
    /// a pure, always-compiled passthrough with no `chrono`).
    pub(crate) uses_log: bool,
    /// `true` when the program reaches an `Ipe.Decimal` or `Ipe.Money` kernel. The
    /// `decimal` runtime feature gates the `decimal.rs` / `money.rs` modules and
    /// the `rust_decimal` crate. `chrono`-style implication: the `Db` surface also
    /// decodes numeric columns through `rust_decimal`, so [`Self::reaches_decimal`]
    /// is `uses_decimal || uses_db`. A program that reaches neither drops the crate.
    pub(crate) uses_decimal: bool,
    /// `true` when the program reaches an `Ipe.Char` `General_Category` predicate
    /// (`isAlpha`/`isDigit`/`isLower`/`isUpper`/`isAlphaNum`). The `char-category`
    /// runtime feature gates the `char_category.rs` module and the
    /// `unicode-general-category` crate. A standalone leaf: only such a predicate
    /// reaches it ([`Self::reaches_char_category`] is exactly this flag). The
    /// std-only `Ipe.Char` kernels stay in the always-compiled `char_kernel.rs`.
    pub(crate) uses_char_category: bool,
    /// `true` when the program uses at least one HEAVY `Ipe.Crypto` kernel
    /// (legacy SHA-1/MD5, AES-GCM / ChaCha20-Poly1305 AEAD, or PBKDF2 key
    /// derivation). When set, [`crate::project::assemble_project_files`]:
    ///
    /// * declares `pub mod crypto; pub use crypto::*;` in the emitted
    ///   `ipe_runtime/mod.rs`;
    /// * adds the `sha1` + `md-5` + `aes-gcm` + `chacha20poly1305` + `pbkdf2`
    ///   dependencies to the emitted `Cargo.toml`.
    ///
    /// The `crypto` runtime feature implies `crypto-core`, so the floor rides
    /// along transitively (see [`Self::reaches_crypto_core`]).
    pub(crate) uses_crypto: bool,
    /// `true` when the program uses at least one crypto-FLOOR kernel (SHA-2 hash,
    /// the HMAC family, RSA sign/verify, constant-time compare, the entropy pair,
    /// or a `Key`/`Mac` newtype kernel). Folded with the heavy-crypto / jwt / db /
    /// web / webview / email / server surfaces in [`Self::reaches_crypto_core`],
    /// which selects the `crypto-core` runtime feature (`crypto_core.rs` plus
    /// `sha2` + `hmac` + `subtle`). A program reaching none of these drops the
    /// module and those crates.
    pub(crate) uses_crypto_core: bool,
    /// `true` when the program uses at least one `Ipe.Secret` kernel or holds a
    /// `Secret`-typed value. Selects the `secret` runtime feature (`secret.rs`
    /// plus `zeroize`); `secret` implies `crypto-core` for the shared `subtle`
    /// compare (see [`Self::reaches_crypto_core`]).
    pub(crate) uses_secret: bool,
    /// `true` when the program names the `Value` (`JsonVal`) or `Decoder<T>` type
    /// — set by the lowerer as the union of a `Json`-building kernel call and a
    /// `Json`/`Decoder` type-mention scan (see [`ipe_ir::Module::uses_json`]).
    /// Folded with the db / config / jwt surfaces (whose emitted decoders and
    /// crate-feature implications also reach `json`) in [`Self::reaches_json`],
    /// which keeps the two prelude aliases and selects the `json` runtime feature.
    pub(crate) uses_json: bool,
    /// `true` when the program uses at least one `Ipe.Jwt` kernel. When set,
    /// [`crate::project::assemble_project_files`]:
    ///
    /// * declares `pub mod jwt; pub use jwt::*;` in the emitted
    ///   `ipe_runtime/mod.rs`;
    /// * adds the `jsonwebtoken` dependency to the emitted `Cargo.toml`.
    ///
    /// `auth.rs` also reaches `crate::jwt`, so the backend force-declares `jwt`
    /// under `uses_jwt || uses_auth` (see [`Self::reaches_jwt`]).
    pub(crate) uses_jwt: bool,
    /// `true` when the program uses at least one `Ipe.Url` kernel. When set,
    /// [`crate::project::assemble_project_files`]:
    ///
    /// * declares `pub mod url; pub use url::*;` in the emitted
    ///   `ipe_runtime/mod.rs`;
    /// * adds the `url` crate (with its `idna` → ICU4X subtree) to the emitted
    ///   `Cargo.toml`.
    ///
    /// The `http_client` and `ws_client` modules (and the shared `ssrf`
    /// validators) also parse with the `url` crate, so the backend
    /// force-declares `url` under
    /// `uses_url || reaches_http_client || uses_websocket` (see
    /// [`Self::reaches_url`]).
    pub(crate) uses_url: bool,
    /// `true` when the program uses at least one `Ipe.Ui` / `Ipe.Html` kernel.
    /// When set, [`crate::project::emit_program`] appends
    /// `pub mod ui;` to the emitted `ipe_runtime/mod.rs`.
    pub(crate) uses_ui: bool,
    /// `true` when the program uses at least one `Ipe.Web` / `Ipe.Web`
    /// app-entry kernel.  When set, the emitted project gains the `"live"`
    /// Cargo feature, serde derives on all emitted types, and
    /// `ipe_runtime::web` wired into the runtime module set.
    pub(crate) uses_web: bool,
    /// `true` when the program uses at least one `Ipe.Tui` / `Ipe.Tui`
    /// app-entry kernel.  When set, the emitted project gains the `"tui"`
    /// Cargo feature and the tui module is wired into `ipe_runtime/mod.rs`.
    pub(crate) uses_tui: bool,
    /// `true` when the program uses the `Ipe.Terminal` line-oriented app-entry
    /// (`Cli.tea`). When set, the guard in `emit_ui_plan` rejects
    /// `Ui.cells` with IPE-L0153 (a terminal cell grid has no string
    /// denotation in a line-oriented Cli view).
    pub(crate) uses_console: bool,
    /// The app surface the program's entry `main` pins, read from its return type.
    ///
    /// Unlike the `uses_*` usage flags (set by ANY module that names an app
    /// entry), this is the one surface whose loop actually runs, so a shape-owned
    /// kernel is checked against it.
    pub(crate) entry_surface: ipe_ir::AppSurface,
    /// `true` when the program uses at least one `Ipe.WebView` app-entry kernel.
    /// When set, the emitted project gains the `"webview"` Cargo feature
    /// (which transitively pulls `"live"`) and the main entry is switched to
    /// `block_on_current_thread` (tao/Cocoa requires the process main thread).
    pub(crate) uses_webview: bool,
    /// The desktop window configuration for a webview-native delivery, threaded
    /// from the CLI's resolved `delivery.desktop`. `None` selects the runtime's
    /// built-in fallback window; only consulted when [`Self::uses_webview`].
    pub(crate) webview_window: Option<WebViewWindow>,
    /// `true` when the program uses at least one `Ipe.CssSafety` leaf
    /// security kernel (the `Ipe.Css` backing).  When set (independently of
    /// [`Self::uses_ui`]), [`crate::project::emit_program`] declares
    /// `css_safety` / `css` (`pub use css::*`) in the emitted
    /// `ipe_runtime/mod.rs` so the bare `safe_value` / `safe_prop_name` /
    /// `safe_selector` / `strip_style_close_kernel` names are in scope — a pure
    /// `Ipe.Css` program never sets `uses_ui`, so the UI append alone would leave
    /// those names undeclared (E0425).
    pub(crate) uses_css: bool,
    /// `true` when the program uses at least one `Ipe.Auth` kernel
    /// (`Auth.hashPassword`, `Auth.verifyPassword`, `Auth.signToken`,
    /// `Auth.verifyToken`, `Auth.register`, `Auth.login`, `Auth.setRole`, etc.).
    /// When set, [`crate::project::emit_program`] appends
    /// `pub mod auth; pub use auth::*;` to the emitted `ipe_runtime/mod.rs`.
    pub(crate) uses_auth: bool,
    /// `true` when the program uses `Ipe.Auth.subject` (touches the opaque
    /// `Principal`). When set, [`crate::project::emit_program`] appends
    /// `pub mod principal;` to the emitted `ipe_runtime/mod.rs`.
    pub(crate) uses_principal: bool,
    /// `true` when the program uses at least one outbound `Ipe.WebSocket`
    /// client kernel (`WebSocket.connect` / `send` / `close` / … or an `on*`
    /// subscription).  When set, [`crate::project::assemble_project_files`] adds
    /// the `websocket_client` feature (+ `tokio-tungstenite` dep) to the emitted
    /// `Cargo.toml` and appends `pub mod ws_client; pub use ws_client::*;` to the
    /// emitted `ipe_runtime/mod.rs` — the `ws_client` module is feature-gated and
    /// NOT part of the base module set.
    pub(crate) uses_websocket: bool,
    /// `true` when the program uses the `Ipe.Email` `Email.send` kernel. When
    /// set, [`crate::project::emit_program`] appends `pub mod email; pub use
    /// email::*;` to the emitted `ipe_runtime/mod.rs` and adds the `lettre`
    /// dependency to the emitted `Cargo.toml`.
    pub(crate) uses_email: bool,
    /// `true` when the program uses at least one `Ipe.Locale` kernel
    /// (`Locale.fromTag`, `Locale.toTag`, `String.toUpperIn`,
    /// `String.toLowerIn`), or any emittable type position mentions
    /// `IrType::Locale`. When set,
    /// [`crate::project::assemble_project_files`] appends `pub mod locale; pub
    /// use locale::*;` to the emitted `ipe_runtime/mod.rs` and enables the
    /// `locale` Cargo feature (`icu_casemap` + `icu_locale_core`) so
    /// `locale_from_tag` uses the ICU4X parse path.
    pub(crate) uses_locale: bool,
    /// `true` when the program uses at least one non-TEA `Ipe.Time` kernel
    /// (`Time.now` / `unixMillis` / `sleep` / `timeString` / `isLeapYear` /
    /// `daysInMonth`). When set, [`crate::project::assemble_project_files`]
    /// enables the `time` Cargo feature in the emitted manifest (promoting it
    /// into the `default` list) and adds the `chrono-tz` dependency — the
    /// IANA-zone calendar surface of the always-declared `time` runtime module,
    /// gated behind that feature. A program that reaches no `Ipe.Time` kernel
    /// drops the crate. The `chrono` core crate is gated by `time-core`/`log`.
    pub(crate) uses_time: bool,
    /// `true` when the program lowers at least one [`ipe_ir::Callee::Ffi`]
    /// foreign-wrapper call. When set,
    /// [`crate::project::assemble_project_files`] writes `src/ffi.rs` (from
    /// [`Self::ffi`]), declares `mod ffi;` in `src/main.rs`, and appends the
    /// bound crates' pinned `[dependencies]` lines to the emitted `Cargo.toml`.
    pub(crate) uses_ffi: bool,
    /// The driver-supplied FFI emission inputs. Required (fail-closed) when
    /// [`Self::uses_ffi`] is set; ignored otherwise.
    pub(crate) ffi: Option<FfiEmit>,
    /// `true` when the program uses the `Ipe.Env` `Env.public` kernel. When
    /// set, [`crate::project::assemble_project_files`] emits the per-project
    /// `ipe_runtime/env_public.rs` (built from [`Self::wasm_public_env`]) and
    /// appends `pub mod env_public; pub use env_public::*;` to the emitted
    /// `ipe_runtime/mod.rs`, on EITHER target.
    pub(crate) uses_env_public: bool,
    /// `true` when the program reaches at least one reactor-requiring kernel
    /// (async IO, timer, spawn, network, database, or any FFI call). Selects
    /// the emitted entry point and manifest floor:
    ///
    /// * `false` — [`crate::project::emit_program`] emits a synchronous
    ///   `fn main` that drives `ipe_main()` on a std-only executor
    ///   (`ipe_runtime::task::block_on`'s `#[cfg(not(feature = "tokio"))]`
    ///   park/unpark variant), and [`crate::project::assemble_project_files`]
    ///   drops `tokio` + `futures-util` from the emitted `Cargo.toml` and the
    ///   `"tokio"` default feature. A pure program (only `Io.println`, string /
    ///   list / math / json computation, the pure `Task` monad ops) sheds the
    ///   whole tokio subtree.
    /// * `true` — the tokio `block_on` entry and the full base manifest are
    ///   emitted unchanged; every existing async surface composes on top as
    ///   before.
    ///
    /// FAIL-CLOSED: the lowerer marks every unknown kernel (and every FFI call)
    /// reactor-requiring, so the synchronous entry is emitted only for a program
    /// proven to need no reactor. Wasm targets ignore this (their entry is
    /// `#[wasm_bindgen(start)]`, their runtime already tokio-free).
    pub(crate) uses_async_runtime: bool,
    /// The `[wasm] publicEnv` allowlist from `package.ipe`, threaded in via
    /// [`RustBackend::with_wasm_public_env`] — already validated against the
    /// secret-name denylist at manifest parse time. Meaningless / ignored
    /// when [`Self::uses_env_public`] is `false`.
    pub(crate) wasm_public_env: Vec<String>,
    /// `true` when `[wasm] mode = "hydrate"` was set in `package.ipe`. When set,
    /// the emitted wasm epilogue includes a `#[wasm_bindgen] pub fn hydrate(…)`
    /// export in addition to the `#[wasm_bindgen(start)] ipe_start` entry —
    /// the fault-tolerant island parse + `wasm_adopt_app` fallback path (M7).
    pub(crate) wasm_hydrate_mode: bool,
    /// The dependency-model emit selector ([`RustBackend::with_runtime_dep`]).
    /// `Some` — [`crate::project::assemble_project_files`] emits the native
    /// project with the runtime as a path dependency (features from
    /// [`crate::runtime_features::runtime_features`]) and no vendored runtime
    /// source; `None` (the default) emits the byte-identical vendored project.
    /// Ignored on the wasm target (which keeps its closed vendoring template).
    pub(crate) runtime_dep: Option<RuntimeDep>,
    /// `true` when `ipe dev build/run --debugger` selected the development-only
    /// time-travelling debugger. When set, [`crate::runtime_features`] adds the
    /// `debugger` feature to the emitted runtime dependency's feature list on
    /// both targets, so the TEA driver records each `(msg, model)` step. Never
    /// set for `ipe release`, so no production artifact carries recorder code.
    pub(crate) debugger: bool,
    /// The verb family this emit serves. `Development` selects the runtime
    /// `dev-posture` feature ([`crate::runtime_features`] on the dependency
    /// model; the vendored manifest's default list otherwise).
    pub(crate) build_intent: BuildIntent,
    /// The Rust type name for the emitted `SqlValue` enum (e.g. `MainSqlValue`).
    /// `None` when `uses_db` is `false`.
    pub(crate) sqlvalue_rust_name: Option<String>,
    /// The Rust type name for the emitted `SqlField` enum (e.g. `MainSqlField`).
    /// `None` when `uses_db` is `false`.
    pub(crate) sqlfield_rust_name: Option<String>,
    /// The Rust type the `[wasm] mode = "hydrate"` glue must name as the island
    /// parse target — the `HydrationState` type the user's `fromHydrationState`
    /// projection takes. Resolved through the SAME [`emit_types::render_type`]
    /// the emitted `main_from_hydration_state` signature uses, so the glue and
    /// the signature reference one identical type name and cannot drift (a record
    /// alias `{ count : Int }` resolves to its synthesised `RecCount`, a named
    /// ADT to `MainHydrationState`, etc.). `None` when the program declares no
    /// `fromHydrationState` (a hydrate-mode program with no explicit projection);
    /// the glue then falls back to a clean `ipe_main()` init.
    pub(crate) hydration_state_rust_name: Option<String>,
    /// Type nominal identity `(home, name)` → Rust type name (e.g.
    /// `(["Main"], Msg)` → `MainMsg`, `(["Lib"], Color)` → `LibColor`). Keyed by
    /// `(home, name)` — not `name` alone — so two modules each declaring `type
    /// Color` map to distinct Rust enums instead of colliding.
    enum_names: BTreeMap<(ModPath, Symbol), String>,
    /// `((enum home, enum name), variant symbol)` → that variant's declared
    /// payload field types, in source (positional) order. Empty vector for a
    /// nullary variant. Used at construction / pattern sites to box (and un-box) a
    /// recursive field so the emitted Rust enum stays finite-sized.
    variant_fields: BTreeMap<(ModPath, Symbol, Symbol), Vec<IrType>>,
    /// Type identity `(home, name)` → every variant's `(name, field types)`,
    /// in declaration order. The whole-enum view that
    /// [`Self::is_cyclic_self_field`] walks to decide whether a payload field
    /// sits on a type-size cycle back to its own enum — direct (`Node Tree …`)
    /// or indirect (mutual recursion, or a self-edge routed through a tuple /
    /// record / another generic's type argument) — and that the Model schema
    /// tag ([`emit_model_schema`]) folds variant NAMES from at their declared
    /// positions (the serialized discriminant is assigned by declaration
    /// index, so a variant rename AND a reorder are both wire-format-relevant).
    enum_variants: ipe_ir::EnumPayloadTable,
    /// Registered enum `(home, name)` → the traits its emitted Rust type implements.
    ///
    /// Each trait is a monotone whole-program fixpoint computed at
    /// [`EmitCtx::build`] (see [`enum_trait_fixpoint`]): an enum loses a trait
    /// iff some variant payload reaches a leaf without it (a function, an opaque
    /// effect or FFI handle, or an enum already known to lack it). `derivable`
    /// is the full `Clone + Debug + PartialEq` derive set; `serde` additionally
    /// excludes the `Clone`-only UI value/carrier types; `clone` admits the
    /// `Arc<dyn Fn>` `SharedFun` carrier, so a `clone`-but-not-`derivable` enum
    /// gets a hand-written `impl Clone` in [`emit_enum`]. Every other named enum
    /// is classified by [`unregistered_enum_facts`]; read through
    /// [`Self::enum_facts`].
    enum_traits: BTreeMap<(ModPath, Symbol), EnumTraits>,
    /// Function id → Rust function name (e.g. `update` → `main_update`).
    func_names: BTreeMap<FuncId, String>,
    /// Function id → the 0-based indices of its parameters whose `Box<dyn Fn>`
    /// carrier was monomorphized to a `FN{i}: Fn(..)` generic
    /// ([`crate::emit_expr::impl_fn_param_indices`]). The call-site emitter reads
    /// this to pass the caller's closure UNBOXED into those positions, realising
    /// the inlined `impl Fn` fast path rather than a wasted heap allocation. A
    /// function with no such params carries no entry (the common case).
    impl_fn_params: BTreeMap<FuncId, Vec<usize>>,
    /// Every distinct record shape synthesised for the program, in emission
    /// order (sorted by field-name set).
    record_structs: Vec<RecordStruct>,
    /// Sorted field-name set → the struct(s) synthesised for it, as indices into
    /// [`Self::record_structs`] in registration order. A set maps to more than
    /// one struct exactly when two structurally-distinct records share only their
    /// field names; the resolver then disambiguates by the record's full shape.
    /// Every `IrType::Record` and every record literal resolves through this map.
    record_by_fieldset: BTreeMap<Vec<String>, Vec<usize>>,
    /// The sanitized Cargo package name for the emitted crate. Derived from
    /// the `package.ipe` name field via [`sanitize_cargo_name`] and threaded in
    /// through [`RustBackend::with_project_name`]. Used by
    /// [`crate::project::assemble_project_files`] to write `[package] name =
    /// "<cargo_name>"` into the emitted `Cargo.toml`. Defaults to `"ipe-app"`
    /// when no project name is supplied.
    pub(crate) cargo_name: String,
    /// `true` when `IPE_WATCH_HOT_APPEARANCE` is set — the dev-only flag that
    /// routes style-value literals through a per-view [`ipe_runtime::literal_table::LiteralTable`]
    /// so a `view` appearance edit can hot-swap without recompiling. Default off:
    /// with the flag unset the emit is byte-identical to the direct-literal form.
    pub(crate) hot_appearance: bool,
    /// `Ipe.Ui` structural wrapper functions — pure, single-kernel layout builders
    /// (`el` / `row` / `column` / `wrappedRow` / `grid` / `paragraph` /
    /// `textColumn` / `form` / `input`) whose bodies are a single `UiNode` or
    /// `UiTaggedNode` (or `UiText` / `UiNone`) call over their parameters and
    /// static descriptions. The partition pass inlines these at a call site whose
    /// arguments are all literal, templatizing them identically to a raw kernel
    /// call.
    ///
    /// Populated at build time by scanning the `Ipe.Ui` module. An id absent from
    /// this map at the call site falls through to the ordinary emit, conservative
    /// by construction.
    pub(crate) ui_structural_wrappers: BTreeMap<FuncId, crate::emit_ui_template::WrapperBody>,
    /// The route items of every nullary function whose body is a list literal
    /// of `Web.route` calls, so a routed app's `routes = table` reference
    /// recovers the same table an inline list carries. An id absent here is
    /// an opaque table, refused by the routed-app emit.
    pub(crate) route_tables: BTreeMap<FuncId, Vec<Expr>>,
    /// The transient, per-scope emit state (literal accumulator, transition-arm
    /// and subscriptions arming). Kept apart from the immutable config above so a
    /// scope field cannot leak into a config flag; reachable only through the
    /// balanced `enter`/`exit` (and `begin`/`end`) delegating methods, never as a
    /// bare field. See [`ScopeState`].
    scope: ScopeState,
    /// The `Ipe.Browser.*` web capabilities the program was GRANTED (disclosed
    /// by importing the reserved browser modules; the resolver derives the set
    /// and the linker unions it onto the [`Program`]). A served web app emits a
    /// one-time `register_granted_web_features(&[…])` call from its web-app
    /// entry so the runtime's `Permissions-Policy` opens exactly these axes'
    /// directives to `(self)` and denies every other. Empty for a non-browser
    /// program, whose served policy then stays fully denied (fail-closed).
    web_capabilities: BTreeSet<ipe_kernels::WebCapability>,
}

/// How a named enum's Rust type is provided, and so which traits it implements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EnumFacts {
    /// A registered `EnumDef` the emitted crate declares, with its fixpoint traits.
    Registered(EnumTraits),
    /// An opaque `Rust.*` FFI handle: the foreign crate's type, assumed to implement nothing.
    OpaqueForeign,
    /// An enum the runtime defines, with the runtime type's own traits.
    RuntimeBridged(RuntimeBridgedEnum),
}

impl EnumFacts {
    /// The traits the enum's Rust type implements.
    pub(crate) const fn traits(self) -> EnumTraits {
        match self {
            Self::Registered(traits) => traits,
            Self::OpaqueForeign => EnumTraits::NONE,
            Self::RuntimeBridged(bridged) => bridged.traits(),
        }
    }
}

/// Is `home` a driver-generated FFI interface module (`Rust.*`)?
///
/// The `Rust.*` namespace is origin-reserved at canonicalisation, so the home
/// prefix IS the provenance.
fn home_is_foreign_interface(interner: &Interner, home: &ModPath) -> bool {
    home.0
        .first()
        .and_then(|s| interner.resolve(*s))
        .is_some_and(|s| s == "Rust")
}

/// The facts of a named enum with no registered `EnumDef`.
///
/// A `Rust.*` home is an opaque FFI handle (a transparent import has a
/// registered `EnumDef` and never reaches here). Otherwise the enum must be a
/// [`RuntimeBridgedEnum`].
///
/// # Errors
///
/// [`Diagnostic::CompilerBug`] for any other enum: the backend cannot render
/// it, so no trait can be claimed for it.
fn unregistered_enum_facts(
    interner: &Interner,
    home: &ModPath,
    name: Symbol,
) -> DResult<EnumFacts> {
    let name_str = resolve_sym(interner, name)?;
    let segs = home
        .0
        .iter()
        .map(|s| resolve_sym(interner, *s))
        .collect::<DResult<Vec<&str>>>()?;
    if home_is_foreign_interface(interner, home) {
        return Ok(EnumFacts::OpaqueForeign);
    }
    RuntimeBridgedEnum::classify(&segs, name_str)
        .map(EnumFacts::RuntimeBridged)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::unregistered_enum_facts",
            detail: format!(
                "enum `{}.{name_str}` has no EnumDef and is neither an opaque FFI handle \
                 nor a runtime-bridged enum",
                segs.join(".")
            ),
        })
}

/// The facts of named enum `(home, name)`: registered traits first, else [`unregistered_enum_facts`].
///
/// # Errors
///
/// [`Diagnostic::CompilerBug`] when the enum is unregistered and unclassified.
fn enum_facts_in(
    enum_traits: &BTreeMap<(ModPath, Symbol), EnumTraits>,
    interner: &Interner,
    home: &ModPath,
    name: Symbol,
) -> DResult<EnumFacts> {
    enum_traits.get(&(home.clone(), name)).map_or_else(
        || unregistered_enum_facts(interner, home, name),
        |traits| Ok(EnumFacts::Registered(*traits)),
    )
}

/// The greatest fixpoint of one trait over every registered enum.
///
/// Every registered enum starts with the trait and is demoted once some variant
/// payload field fails `field_ok`, which consults the current estimate for
/// referenced registered enums and `unregistered` for every other enum. The
/// lattice only descends, so each pass demotes at least one enum or stops: at
/// most one pass per enum plus the final one.
fn enum_trait_fixpoint(
    enum_variants: &ipe_ir::EnumPayloadTable,
    unregistered: impl Fn(&ModPath, Symbol) -> bool,
    field_ok: impl Fn(&IrType, &dyn Fn(&ModPath, Symbol) -> bool) -> bool,
) -> BTreeMap<(ModPath, Symbol), bool> {
    let mut facts: BTreeMap<(ModPath, Symbol), bool> =
        enum_variants.keys().map(|k| (k.clone(), true)).collect();
    loop {
        let demote: Vec<(ModPath, Symbol)> = {
            let lookup = |home: &ModPath, name: Symbol| {
                facts
                    .get(&(home.clone(), name))
                    .map_or_else(|| unregistered(home, name), |held| *held)
            };
            enum_variants
                .iter()
                .filter(|(key, _)| facts.get(*key).copied() == Some(true))
                .filter(|(_, variants)| {
                    !variants
                        .iter()
                        .all(|(_, fields)| fields.iter().all(|f| field_ok(f, &lookup)))
                })
                .map(|(key, _)| key.clone())
                .collect()
        };
        if demote.is_empty() {
            return facts;
        }
        for key in demote {
            facts.insert(key, false);
        }
    }
}

/// Refuse a named enum reachable from `ty` whose trait facts are unknown.
///
/// Walks `ty`'s held components without expanding registered payloads (every
/// registered enum's payload is checked on its own), so each enum named in a
/// payload or record field is classified before any trait is read for it.
///
/// # Errors
///
/// [`Diagnostic::CompilerBug`] from [`unregistered_enum_facts`] for the first
/// unclassified enum.
fn refuse_unclassified_enum(
    enum_traits: &BTreeMap<(ModPath, Symbol), EnumTraits>,
    interner: &Interner,
    ty: &IrType,
) -> DResult<()> {
    let offender: Cell<Option<(ModPath, Symbol)>> = Cell::new(None);
    let leaf = |t: &IrType| {
        if let IrType::Enum { home, name, .. } = t
            && enum_facts_in(enum_traits, interner, home, *name).is_err()
        {
            offender.set(Some((home.clone(), *name)));
            return true;
        }
        false
    };
    if !ipe_ir::ir_type_holds(ty, &ipe_ir::EnumPayloadTable::new(), &leaf) {
        return Ok(());
    }
    match offender.into_inner() {
        Some((home, name)) => enum_facts_in(enum_traits, interner, &home, name).map(|_| ()),
        None => Ok(()),
    }
}

/// Is an enum variant payload or record field type `Clone`?
///
/// Transparent carriers recurse; a referenced named enum consults `enum_clone`
/// (the fixpoint being computed, or the classified facts of an unregistered
/// enum) and its type arguments, so a mutually-referential enum's
/// `Clone`-ness converges monotonically; every other leaf defers to
/// [`ipe_ir::payload_leaf_is_clone`], the leaf rule the frontend's clone
/// classifier shares. A record field and an enum payload field share these
/// semantics under the emitted `impl<Tn: Clone> Clone`, which bounds every
/// type parameter and so makes a bare type variable `Clone`.
fn field_is_clone(ty: &IrType, enum_clone: &dyn Fn(&ModPath, Symbol) -> bool) -> bool {
    clone_under(ty, enum_clone, &ipe_ir::payload_leaf_is_clone)
}

/// Is a value of type `ty` inside an emitted function body `Clone`?
///
/// The same walk as [`field_is_clone`], plus a row witness: an emitted
/// function bounds every type parameter and every row witness by `Clone`, so
/// both are `Clone` there at any depth.
pub(crate) fn fn_value_is_clone(
    ty: &IrType,
    enum_clone: &dyn Fn(&ModPath, Symbol) -> bool,
) -> bool {
    clone_under(ty, enum_clone, &|t| {
        matches!(t, IrType::RowGeneric(_)) || ipe_ir::payload_leaf_is_clone(t)
    })
}

/// The `Clone` walk shared by [`field_is_clone`] and [`fn_value_is_clone`];
/// `leaf` decides every type that is neither a named enum nor a carrier.
fn clone_under(
    ty: &IrType,
    enum_clone: &dyn Fn(&ModPath, Symbol) -> bool,
    leaf: &dyn Fn(&IrType) -> bool,
) -> bool {
    let go = |t: &IrType| clone_under(t, enum_clone, leaf);
    match ty {
        IrType::Enum { home, name, args } => enum_clone(home, *name) && args.iter().all(go),
        IrType::Maybe(e) | IrType::List(e) | IrType::Set(e) => go(e),
        IrType::Result(a, b) | IrType::Dict(a, b) => go(a) && go(b),
        IrType::Tuple(es) => es.iter().all(go),
        IrType::Record(fields) => fields.values().all(go),
        IrType::Ui { msg, .. } => go(msg),
        IrType::WebRoute(page) => go(page),
        other => leaf(other),
    }
}

impl<'a> EmitCtx<'a> {
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::similar_names)] // `uses_ui` / `uses_tui` are intentionally similar
    #[allow(clippy::too_many_arguments)] // the backend-config thread-through (driver, ffi, target, wasm, runtime-dep, debugger, cargo_name)
    #[allow(clippy::fn_params_excessive_bools)] // each bool is an independent emit-shape switch threaded from BuildConfig
    fn build(
        interner: &'a Interner,
        program: &Program,
        db_driver: DbDriver,
        ffi: Option<FfiEmit>,
        target: ipe_ir::Target,
        wasm_public_env: Vec<String>,
        wasm_hydrate_mode: bool,
        runtime_dep: Option<RuntimeDep>,
        debugger: bool,
        build_intent: BuildIntent,
        cargo_name: String,
        hot_appearance: bool,
        webview_host: bool,
        webview_window: Option<WebViewWindow>,
    ) -> DResult<Self> {
        // Every emission entry builds its context here, so a malformed literal
        // route path is refused whether or not emission reaches the route.
        route_grammar::refuse_malformed_literals(program)?;
        let mut enum_names: BTreeMap<(ModPath, Symbol), String> = BTreeMap::new();
        // Generated Rust type name -> the first Ipê type (dotted) that claimed
        // it. Keyed by the emitted name so a fold collision is an O(1) lookup
        // (not a scan of `enum_names`), and so the loser of a collision can be
        // disambiguated to a free name instead of the whole program being
        // rejected.
        let mut enum_rust_names: BTreeMap<String, String> = BTreeMap::new();
        let mut variant_fields: BTreeMap<(ModPath, Symbol, Symbol), Vec<IrType>> = BTreeMap::new();
        let mut enum_variants: BTreeMap<(ModPath, Symbol), VariantList> = BTreeMap::new();
        let mut func_names = BTreeMap::new();
        // Generated Rust fn name -> the first Ipê function (dotted) that claimed
        // it, so the fold gate below can name BOTH colliding definitions in an
        // IPE-N0048 diagnostic. `func_names` is keyed by `FuncId`, which does not
        // recover a source spelling on its own.
        let mut func_ipe_names: BTreeMap<String, String> = BTreeMap::new();
        let mut impl_fn_params: BTreeMap<FuncId, Vec<usize>> = BTreeMap::new();
        for module in &program.modules {
            let segs = module
                .name
                .0
                .iter()
                .map(|s| resolve_sym(interner, *s))
                .collect::<DResult<Vec<&str>>>()?;
            for ty in &module.types {
                let TypeDef::Enum(def) = ty;
                // The emitted Rust type name is derived from the type's HOME
                // module (its defining module), NOT the merged entry module the
                // linker pooled it into — so `Ipe.Palette.Shade` → `StdPaletteShade`
                // and `Lib.Color` → `LibColor`, while a single-module program
                // (home == entry) stays byte-identical (`Main.Msg` → `MainMsg`).
                // When `def.home` is empty (IR built directly in backend unit
                // tests, not through the full pipeline), fall back to the merged
                // module path — always correct for single-module programs.
                let home_segs: Vec<&str> = if def.home.0.is_empty() {
                    segs.clone()
                } else {
                    def.home
                        .0
                        .iter()
                        .map(|s| resolve_sym(interner, *s))
                        .collect::<DResult<Vec<&str>>>()?
                };
                // Ipe.WebSocket's `WebSocketMessage` / `CloseCode` ADTs are
                // BRIDGED to the runtime enums `WsClientMessage` / `WsCloseCode`
                // (the `sub_subscribe_ws_*` fns take/produce those). Overriding the
                // emitted enum name here makes every reference — the type in a
                // handler's `WebSocketMessage -> msg` param, a `Text s` / `Normal`
                // constructor, a `case … of Text t ->` pattern — resolve to the
                // runtime enum, whose variant names + field types match 1:1. The
                // Ipê enum DECL is suppressed in `emit_enum` (a bridged type has no
                // user-emitted body). Same intent as the reference `Types.hs` map.
                let def_name = resolve_sym(interner, def.name)?;
                let rust_name = websocket_bridge_rust_name(&home_segs, def_name)
                    .map_or_else(|| naming::enum_name(&home_segs, def_name), str::to_owned);
                // A type's nominal identity is `(home, name)`. Two modules each
                // declaring `type Color` share the bare `name` `Symbol` but differ
                // in `home`, so they do not collide — each keys a distinct Rust
                // enum. A genuine duplicate `(home, name)` (the SAME type
                // declared twice) is caught upstream by the link-level gate; this
                // stays as a fail-closed defence-in-depth backstop (IPE-I0202).
                let key = (def.home.clone(), def.name);
                if enum_names.contains_key(&key) {
                    return Err(Diagnostic::Name {
                        span: Span::DUMMY,
                        msg: NameError::DuplicateType {
                            name: rust_name.into_boxed_str(),
                            first: Span::DUMMY,
                        },
                    });
                }
                // Guard the emitted-name space too: `naming::enum_name`'s camel-case
                // fold is not injective over the (home, name) split (`["Std",
                // "Palette"]/Color` and `["Std"]/PaletteColor` both fold to
                // `StdPaletteColor`), so two DISTINCT identities would otherwise
                // emit the same Rust enum and trip `rustc` E0428. Disambiguate the
                // loser to a free name so the legal program still emits; only a
                // degenerate name space with no free suffix fails closed with the
                // fold diagnostic (IPE-N0048) naming both Ipê types.
                let this_dotted = ipe_dotted_name(&home_segs, def_name);
                let Some(rust_name) = disambiguated_rust_name(&rust_name, "", &enum_rust_names)
                else {
                    let first_dotted = enum_rust_names.get(&rust_name).cloned().unwrap_or_default();
                    return Err(Diagnostic::Name {
                        span: Span::DUMMY,
                        msg: NameError::RustNameFold {
                            first: first_dotted.into_boxed_str(),
                            second: this_dotted.into_boxed_str(),
                            rust_name: rust_name.into_boxed_str(),
                            kind: RustNameFoldKind::Type,
                        },
                    });
                };
                enum_rust_names.insert(rust_name.clone(), this_dotted);
                enum_names.insert(key.clone(), rust_name.clone());
                let mut all_fields = Vec::with_capacity(def.variants.len());
                for variant in &def.variants {
                    variant_fields.insert(
                        (def.home.clone(), def.name, variant.name),
                        variant.fields.clone(),
                    );
                    all_fields.push((variant.name, variant.fields.clone()));
                }
                enum_variants.insert(key, all_fields);
            }
            for func in &module.funcs {
                // Use the function's own home module path for naming so that two
                // functions with the same bare name from different source modules
                // emit distinct Rust names (e.g. `lib_helper` vs `main_helper`).
                // When `func.home` is empty (IR built directly in backend unit
                // tests, not through the full pipeline), fall back to the
                // containing merged module's path — the pre-Defect-2 behaviour —
                // which is always correct for single-module programs.
                let effective_home: &[_] = if func.home.0.is_empty() {
                    &module.name.0
                } else {
                    &func.home.0
                };
                let func_segs = effective_home
                    .iter()
                    .map(|s| resolve_sym(interner, *s))
                    .collect::<DResult<Vec<&str>>>()?;
                let rust_name = naming::module_value(&func_segs, resolve_sym(interner, func.name)?);
                // Mirror the enum guard above. `naming::module_value`'s snake_case
                // fold is not injective over the (home, name) split —
                // `["Std", "Ui"]/borderRounded` and `["Std", "Ui", "Border"]/rounded`
                // both fold to `std_ui_border_rounded` — so two DISTINCT functions
                // would otherwise emit the same Rust fn and trip `rustc` E0428.
                // Disambiguate the loser to a free name so the legal program still
                // emits; a degenerate name space fails closed with the fold
                // diagnostic (IPE-N0048) naming both Ipê values.
                let this_dotted = ipe_dotted_name(&func_segs, resolve_sym(interner, func.name)?);
                let Some(rust_name) = disambiguated_rust_name(&rust_name, "_", &func_ipe_names)
                else {
                    let first_dotted = func_ipe_names.get(&rust_name).cloned().unwrap_or_default();
                    return Err(Diagnostic::Name {
                        span: Span::DUMMY,
                        msg: NameError::RustNameFold {
                            first: first_dotted.into_boxed_str(),
                            second: this_dotted.into_boxed_str(),
                            rust_name: rust_name.into_boxed_str(),
                            kind: RustNameFoldKind::Value,
                        },
                    });
                };
                func_ipe_names.insert(rust_name.clone(), this_dotted);
                func_names.insert(func.id, rust_name);
                // Record which of this function's `Fn`-typed params were
                // monomorphized to `impl Fn` so the call-site emitter passes the
                // caller's closure unboxed into exactly those positions. Computed
                // ONCE here (from the same `Func`) so signature and call site can
                // never disagree on the carrier.
                let idxs = crate::emit_expr::impl_fn_param_indices(func);
                if !idxs.is_empty() {
                    impl_fn_params.insert(func.id, idxs);
                }
            }
        }

        // Prepass: collect every distinct CLOSED record shape the program uses
        // (recursing into nested records / tuples), so each gets one synthesised
        // struct, declared before any use. Two sources feed it: function
        // signatures (params / return), and the lowerer-surfaced `module.records`
        // — the shapes of record literals that live inside function bodies, where
        // the type appears in no signature. A record literal resolves to its
        // struct through this table by its field-name set; a literal whose set is
        // absent is an internal invariant violation (surfaced as a `CompilerBug`,
        // never a silent mis-emit).
        //
        // Each field-name set maps to the LIST of distinct field-type shapes seen
        // for it. A set may carry both a generic template (`{ value : a }`, from a
        // parametric signature) and concrete instantiations (`{ value : Int }`):
        // [`canonicalise_shape`] reconciles them into a single struct.
        let mut shapes: BTreeMap<Vec<String>, ShapeOccurrences> = BTreeMap::new();
        for module in &program.modules {
            for func in &module.funcs {
                for (_, ty) in &func.params {
                    collect_record_shapes(interner, ty, &mut shapes)?;
                }
                collect_record_shapes(interner, &func.ret, &mut shapes)?;
            }
            for ty in &module.records {
                collect_record_shapes(interner, ty, &mut shapes)?;
            }
            // An enum variant's payload field type may itself be (or carry) a
            // record shape (`type Boxed a = Box { value : a }`). The variant
            // field types are not in any signature, so collect them here too —
            // otherwise emitting the enum would resolve the record type to a
            // struct that was never synthesised (a `CompilerBug` miss).
            for ty in &module.types {
                let TypeDef::Enum(def) = ty;
                for variant in &def.variants {
                    for field_ty in &variant.fields {
                        collect_record_shapes(interner, field_ty, &mut shapes)?;
                    }
                }
            }
        }
        // seal: the three whole-program enum trait fixpoints. An enum with no
        // registered `EnumDef` answers from its classified facts, and an
        // unclassified one (a `CompilerBug`) answers `false`: no trait is ever
        // claimed for a type the backend cannot account for.
        let unregistered_has = |trait_of: fn(EnumTraits) -> bool| {
            move |home: &ModPath, name: Symbol| {
                unregistered_enum_facts(interner, home, name).is_ok_and(|f| trait_of(f.traits()))
            }
        };
        let enum_derivable = enum_trait_fixpoint(
            &enum_variants,
            unregistered_has(|t| t.derivable),
            |f, lookup| ipe_ir::ir_type_is_derivable(f, &lookup),
        );
        let enum_serde = enum_trait_fixpoint(
            &enum_variants,
            unregistered_has(|t| t.serde),
            |f, lookup| ipe_ir::ir_type_is_serde(f, &lookup),
        );
        let enum_clone = enum_trait_fixpoint(
            &enum_variants,
            unregistered_has(|t| t.clone),
            field_is_clone,
        );
        let enum_traits: BTreeMap<(ModPath, Symbol), EnumTraits> = enum_variants
            .keys()
            .map(|key| {
                let has = |table: &BTreeMap<(ModPath, Symbol), bool>| {
                    table.get(key).copied().unwrap_or(false)
                };
                let traits = EnumTraits {
                    clone: has(&enum_clone),
                    derivable: has(&enum_derivable),
                    serde: has(&enum_serde),
                };
                (key.clone(), traits)
            })
            .collect();
        for variants in enum_variants.values() {
            for field in variants.iter().flat_map(|(_, fields)| fields) {
                refuse_unclassified_enum(&enum_traits, interner, field)?;
            }
        }
        let has_trait = |trait_of: fn(EnumTraits) -> bool| {
            let enum_traits = &enum_traits;
            move |home: &ModPath, name: Symbol| {
                enum_facts_in(enum_traits, interner, home, name).is_ok_and(|f| trait_of(f.traits()))
            }
        };

        let mut record_structs = Vec::with_capacity(shapes.len());
        let mut record_by_fieldset: BTreeMap<Vec<String>, Vec<usize>> = BTreeMap::new();
        let mut used_names: BTreeSet<String> = BTreeSet::new();
        for (key, occurrences) in shapes {
            // A field-name set may reconcile to MORE than one struct when two
            // structurally-distinct records share only their field names; each
            // gets its own struct, deterministically named.
            for (fields, type_params) in reconcile_shapes(&key, &occurrences)? {
                let name = unique_struct_name(naming::record_struct_name(&key), &mut used_names);
                // seal: a record struct is derivable iff every field type is,
                // consulting the enum fixpoint for referenced user enums.
                for (_, ty) in &fields {
                    refuse_unclassified_enum(&enum_traits, interner, ty)?;
                }
                let is_derivable = {
                    let lookup = has_trait(|t| t.derivable);
                    fields
                        .iter()
                        .all(|(_, ty)| ipe_ir::ir_type_is_derivable(ty, &lookup))
                };
                // seal: a record struct is serde-OK iff every field type is,
                // consulting the parallel enum-serde fixpoint. Strictly implies
                // `is_derivable` (serde-OK leaves ⊂ derivable leaves), so a record
                // never gets serde without CDPeq. Gates the serde derive under
                // `uses_web` so a CDPeq-but-not-serde record (Html/Element/Color/
                // UiPlain field) in a Web program is not forced to serde.
                let is_serde = {
                    let lookup = has_trait(|t| t.serde);
                    fields
                        .iter()
                        .all(|(_, ty)| ipe_ir::ir_type_is_serde(ty, &lookup))
                };
                // A record whose every field carrier is `Clone` (including the
                // promoted `Arc<dyn Fn>` `SharedFun` slot) gets a hand-written
                // `impl Clone` when it is not fully `CDPeq`-derivable — the property
                // the fn-value-reuse promotion relies on to duplicate a reused
                // record-of-functions.
                //
                // Consulted through `field_is_clone`, the enum-payload rule, not
                // the bare `carrier_is_clone` leaf test: a bare type variable
                // field is `Clone` under the emitted `impl<Tn: Clone> Clone`
                // bound (a generic union's inner record may carry both a
                // `SharedFun` slot keyed on `a` AND a bare-`a` field), and a
                // referenced named enum consults the `Clone` fixpoint.
                let is_clone = {
                    let lookup = has_trait(|t| t.clone);
                    fields.iter().all(|(_, ty)| field_is_clone(ty, &lookup))
                };
                record_by_fieldset
                    .entry(key.clone())
                    .or_default()
                    .push(record_structs.len());
                record_structs.push(RecordStruct {
                    name,
                    fields,
                    type_params,
                    is_derivable,
                    is_serde,
                    is_clone,
                });
            }
        }

        // detect whether the lowerer injected SqlValue / SqlField.
        // The lowerer injects them iff any Db kernel is used. Detecting here
        // (rather than re-scanning Func bodies) avoids a duplicate walk and
        // keeps the "what's in the type list?" answer canonical.
        let uses_db = program.modules.iter().any(|m| {
            m.types.iter().any(|td| {
                let TypeDef::Enum(def) = td;
                interner.resolve(def.name) == Some("SqlValue")
            })
        });
        let sqlvalue_rust_name = if uses_db {
            // The SqlValue enum was injected into the same module as the rest of the
            // program (the lowerer always uses one module), so its Rust name is in
            // `enum_names` under the "SqlValue" symbol.  Look it up by scanning the
            // names map for the entry whose interner resolution is "SqlValue".
            program.modules.iter().find_map(|m| {
                m.types.iter().find_map(|td| {
                    let TypeDef::Enum(def) = td;
                    if interner.resolve(def.name) == Some("SqlValue") {
                        enum_names.get(&(def.home.clone(), def.name)).cloned()
                    } else {
                        None
                    }
                })
            })
        } else {
            None
        };
        let sqlfield_rust_name = if uses_db {
            program.modules.iter().find_map(|m| {
                m.types.iter().find_map(|td| {
                    let TypeDef::Enum(def) = td;
                    if interner.resolve(def.name) == Some("SqlField") {
                        enum_names.get(&(def.home.clone(), def.name)).cloned()
                    } else {
                        None
                    }
                })
            })
        } else {
            None
        };

        // detect whether any TEA kernel is used, from the flag the lowerer
        // set on the module.
        let uses_tea = program.modules.iter().any(|m| m.uses_tea);

        // detect whether any Ipe.Http.Server kernel is used.
        let uses_server = program.modules.iter().any(|m| m.uses_server);

        // detect outbound Ipe.Http client usage (gates `http_client` + reqwest).
        let uses_http = program.modules.iter().any(|m| m.uses_http);

        // detect Ipe.Config TOML/YAML decoder usage (gates `config_decode` +
        // `toml` + `serde_yaml`).
        let uses_config = program.modules.iter().any(|m| m.uses_config);

        // detect Ipe.Compression usage (gates `compression` + `flate2` + `zstd`).
        let uses_compression = program.modules.iter().any(|m| m.uses_compression);

        // detect Ipe.Csv usage (gates `csv` module + `csv` crate).
        let uses_csv = program.modules.iter().any(|m| m.uses_csv);

        // detect Ipe.Cache usage (gates the `cache` module + the `cache_kernel`
        // runtime feature). A leaf — no other surface reaches it.
        let uses_cache = program.modules.iter().any(|m| m.uses_cache);

        // detect HEAVY Ipe.Crypto usage (gates `crypto` module + sha1 + md-5 +
        // aes-gcm + chacha20poly1305 + pbkdf2). The `crypto` feature implies
        // `crypto-core`, so the floor is pulled transitively.
        let uses_crypto = program.modules.iter().any(|m| m.uses_crypto);

        // detect crypto-FLOOR usage (gates `crypto_core.rs` + sha2 + hmac +
        // subtle via the `crypto-core` feature). Folded with the
        // crypto/jwt/db/web/webview/email/server surfaces in
        // [`Self::reaches_crypto_core`], not here.
        let uses_crypto_core = program.modules.iter().any(|m| m.uses_crypto_core);

        // detect Ipe.Secret usage (gates `secret.rs` + zeroize via the `secret`
        // feature). `secret` implies `crypto-core` for the shared `subtle`.
        let uses_secret = program.modules.iter().any(|m| m.uses_secret);

        // detect whether the program names `Value`/`Decoder` (a Json-building
        // kernel or a `Json`/`Decoder` type-mention). Gates the two fixed prelude
        // aliases and the `json` runtime feature; folded with db/config/jwt in
        // `reaches_json`.
        let uses_json = program.modules.iter().any(|m| m.uses_json);

        // detect Ipe.Encoding / Ipe.Bytes usage (gates `encoding` + `bytes`
        // modules + base64 + hex + percent-encoding crates). Also reached by the
        // crypto/db/server/email/jwt/web surfaces — folded in by
        // [`Self::reaches_encoding`], not here.
        let uses_encoding = program.modules.iter().any(|m| m.uses_encoding);

        // detect Ipe.Regex / String.isUrl usage (gates `regex_kernel` module +
        // the `regex` crate). Standalone leaf — no surface folds in.
        let uses_regex = program.modules.iter().any(|m| m.uses_regex);

        // detect Ipe.Uuid usage (gates `uuid_kernel` module + the `uuid` crate).
        // Also reached by the server/web surfaces — folded in by
        // [`Self::reaches_uuid`], not here.
        let uses_uuid = program.modules.iter().any(|m| m.uses_uuid);

        // detect Ipe.Random usage (gates the `random.rs` module via the `random`
        // feature). Standalone leaf — no surface folds in.
        let uses_random = program.modules.iter().any(|m| m.uses_random);

        // detect Ipe.Log usage (gates the `log.rs` module + the base `chrono`
        // crate). `chrono` itself is selected under `reaches_time_core` (log ∪
        // Time/Db/Web/WebView); this flag is the `log`-feature leaf.
        let uses_log = program.modules.iter().any(|m| m.uses_log);

        // detect Ipe.Decimal / Ipe.Money usage (gates `decimal.rs`/`money.rs` +
        // the `rust_decimal` crate). `chrono`-style: the crate is kept under
        // `reaches_decimal` (this flag OR the Db surface).
        let uses_decimal = program.modules.iter().any(|m| m.uses_decimal);

        // detect Ipe.Char General_Category-predicate usage (gates `char_category.rs`
        // + the `unicode-general-category` crate). A standalone leaf.
        let uses_char_category = program.modules.iter().any(|m| m.uses_char_category);

        // detect Ipe.Jwt usage (gates `jwt` module + `jsonwebtoken` crate).
        let uses_jwt = program.modules.iter().any(|m| m.uses_jwt);

        // detect Ipe.Url usage (gates `url` module + the `url` crate's idna →
        // ICU4X subtree). The http_client / ws_client surfaces also parse with
        // the `url` crate — that transitive reach is folded in by
        // [`Self::reaches_url`], not here.
        let uses_url = program.modules.iter().any(|m| m.uses_url);

        // detect Ipe.Ui / Ipe.Html / Ipe.Web / Ipe.Tui / Ipe.Console / Ipe.WebView usage.
        // `uses_webview` is the webview-native delivery signal: the resolved
        // `web desktop` host (threaded in as `webview_host`) OR a source module
        // that still carries the leaf. A webview-native delivery renders the
        // server-free `web-core` core over a local IPC bridge; it does NOT run the
        // axum `web` surface, so `uses_webview` does NOT force `uses_web`. The
        // `uses_webview && !uses_web` path selects the lean render shell
        // (`RUNTIME_MOD_RS_WEBVIEW_CORE_APPEND`) and the `web-core`/`webview` Cargo
        // features; a program that reaches BOTH keeps the full `web` module.
        let uses_webview = webview_host || program.modules.iter().any(|m| m.uses_webview);
        let entry_surface = entry_app_surface(program, uses_webview);
        let (uses_ui, uses_web, uses_tui, uses_console) = (
            program.modules.iter().any(|m| m.uses_ui),
            program.modules.iter().any(|m| m.uses_web),
            program.modules.iter().any(|m| m.uses_tui),
            program.modules.iter().any(|m| m.uses_console),
        );

        // detect Ipe.Css (Ipe.CssSafety) leaf-kernel usage.
        let uses_css = program.modules.iter().any(|m| m.uses_css);

        // detect Ipe.Auth kernel usage.
        let uses_auth = program.modules.iter().any(|m| m.uses_auth);
        // detect `Ipe.Auth.subject` usage (touches the opaque `Principal`).
        let uses_principal = program.modules.iter().any(|m| m.uses_principal);
        // detect Ipe.Email usage (kernel or type-mention).
        let uses_email = program.modules.iter().any(|m| m.uses_email);
        // detect Ipe.Locale usage (kernel or type-mention).
        let uses_locale = program.modules.iter().any(|m| m.uses_locale);
        // detect non-TEA Ipe.Time kernel usage — gates the `time` Cargo feature
        // and the `chrono-tz` dependency.
        let uses_time = program.modules.iter().any(|m| m.uses_time);
        // detect Ipe.Env `Env.public` kernel usage.
        let uses_env_public = program.modules.iter().any(|m| m.uses_env_public);

        // detect outbound Ipe.WebSocket client usage.
        let uses_websocket = program.modules.iter().any(|m| m.uses_websocket);

        // detect foreign-crate FFI wrapper usage.
        let uses_ffi = program.modules.iter().any(|m| m.uses_ffi);

        // detect whether the program needs the tokio reactor. Two independent
        // triggers must BOTH force it on, because the manifest augmenter chain
        // and the entry-point selection share this one flag:
        //   1. a reactor-requiring KERNEL in any module (the per-module flag,
        //      unioned — one async module makes the whole program async); and
        //   2. any reactor SURFACE flag, even when reached by a reserved-type
        //      mention alone (e.g. a `Request`-typed handler sets `uses_server`
        //      without calling a server kernel). Every surface OR'd in here has
        //      an augmenter that inserts, extends, or depends on the base `tokio`
        //      dependency line, and a runtime module that parks on the reactor —
        //      so it MUST link tokio and enter through its runtime. Folding them
        //      in makes this flag a true superset of the surface set, so the
        //      `async_runtime_cargo_toml` restore always precedes the per-surface
        //      tokio-line surgery, and a reactor program never gets a synchronous
        //      `fn main`. Pure surfaces (crypto/url/config/csv/compression) are
        //      excluded — their runtime resolves without the reactor, so forcing
        //      tokio would relink a subtree they shed.
        let uses_async_runtime = program.modules.iter().any(|m| m.uses_async_runtime)
            || uses_db
            || uses_server
            || uses_web
            || uses_webview
            || uses_websocket
            || uses_http
            || uses_tui
            || uses_tea
            || uses_email;

        // Type-closure fold: derive the feature set from the emitted TYPES, not a
        // per-kernel allowlist. Every gated `IrType` leaf reachable in the
        // program's type declarations / signatures forces its feature through the
        // IR-crate SSOT ([`ipe_ir::ir_type_feature_requirement`]), so a program
        // that MENTIONS a gated type with no kernel call still selects that type's
        // feature (the `Url`/`ImageSrc` and Http `StatusCode` breach class). This
        // OR-folds each type-required feature into the corresponding `uses_*`
        // flag; the reachability `reaches_*` unions then close over it as before.
        // Fail-closed and idempotent: it can only ADD a feature the emit spells,
        // never drop one, and unions redundantly with the lowerer's body-position
        // walk (which routes the SAME SSOT), so a missed wiring in either side is
        // covered by the other.
        let type_reqs = program_type_feature_requirements(program);
        let has = |f: ipe_ir::RuntimeFeatureId| type_reqs.contains(&f);
        let uses_json = uses_json || has(ipe_ir::RuntimeFeatureId::Json);
        let uses_url = uses_url || has(ipe_ir::RuntimeFeatureId::Url);
        let uses_secret = uses_secret || has(ipe_ir::RuntimeFeatureId::Secret);
        let uses_decimal = uses_decimal || has(ipe_ir::RuntimeFeatureId::Decimal);
        let uses_regex = uses_regex || has(ipe_ir::RuntimeFeatureId::Regex);
        let uses_csv = uses_csv || has(ipe_ir::RuntimeFeatureId::Csv);
        let uses_cache = uses_cache || has(ipe_ir::RuntimeFeatureId::CacheKernel);
        let uses_websocket = uses_websocket || has(ipe_ir::RuntimeFeatureId::WebsocketClient);
        let uses_email = uses_email || has(ipe_ir::RuntimeFeatureId::Email);
        let uses_crypto_core = uses_crypto_core || has(ipe_ir::RuntimeFeatureId::CryptoCore);
        let uses_db = uses_db || has(ipe_ir::RuntimeFeatureId::Db);
        let uses_server = uses_server || has(ipe_ir::RuntimeFeatureId::Server);
        let uses_http = uses_http || has(ipe_ir::RuntimeFeatureId::HttpClient);
        let uses_web = uses_web || has(ipe_ir::RuntimeFeatureId::Web);
        // A type-only reach that flips a reactor surface (`web` / `server` /
        // `db` / `http` / `websocket` / `email`) must also force the reactor
        // spine — the same surfaces the kernel-side union force above — or the
        // emitted crate links a runtime module that parks on tokio without the
        // reactor. Fold the newly-forced surfaces back in, fail-closed.
        let uses_async_runtime = uses_async_runtime
            || uses_db
            || uses_server
            || uses_web
            || uses_websocket
            || uses_http
            || uses_email;

        // Collect qualifying `Ipe.Ui` structural wrapper bodies: pure, single-kernel
        // layout builders whose bodies reduce to a `UiNode` / `UiTaggedNode` /
        // `UiText` / `UiNone` kernel call. The partition pass inlines these at
        // call sites with literal arguments, templatizing them identically to a
        // raw kernel call.
        //
        // Qualifying predicate: the function is in `Ipe.Ui` and its body is a
        // single `Callee::Kernel` call to one of the four static element-node
        // builders. Type/row parameters are not a disqualifier — `msg` is
        // type-level and erased in the IR body, so value-level substitution is
        // unaffected. This excludes `Ui.button` / `Ui.link` / `Ui.image` /
        // `Ui.html` / `CustomElement.node` / `Ui.cells` (handlers, raw markup, record
        // config). The body may contain `Var`/`CloneVar` references to value
        // parameters, `Cons` prepend (the marker-attr pattern), and nested
        // kernel calls.
        let ui_structural_wrappers: BTreeMap<FuncId, crate::emit_ui_template::WrapperBody> =
            program
                .modules
                .iter()
                .flat_map(|m| m.funcs.iter())
                .filter(|f| is_ipe_ui_structural_wrapper(f, interner))
                .map(|f| {
                    let params: Vec<Symbol> = f.params.iter().map(|(s, _)| *s).collect();
                    (f.id, (params, f.body.clone()))
                })
                .collect();

        let route_tables: BTreeMap<FuncId, Vec<Expr>> = program
            .modules
            .iter()
            .flat_map(|m| m.funcs.iter())
            .filter(|f| f.params.is_empty())
            .filter_map(|f| match &f.body {
                Expr::List { items, .. } if items.iter().all(is_web_route_call) => {
                    Some((f.id, items.clone()))
                }
                _ => None,
            })
            .collect();

        let mut ctx = Self {
            interner,
            uses_db,
            db_driver,
            target,
            uses_tea,
            uses_server,
            uses_http,
            uses_config,
            uses_compression,
            uses_csv,
            uses_cache,
            uses_encoding,
            uses_regex,
            uses_uuid,
            uses_random,
            uses_log,
            uses_decimal,
            uses_char_category,
            uses_crypto_core,
            uses_secret,
            uses_json,
            uses_crypto,
            uses_jwt,
            uses_url,
            uses_ui,
            uses_web,
            uses_tui,
            uses_console,
            entry_surface,
            uses_webview,
            webview_window,
            uses_css,
            uses_auth,
            uses_principal,
            uses_websocket,
            uses_email,
            uses_locale,
            uses_time,
            uses_ffi,
            ffi,
            uses_env_public,
            uses_async_runtime,
            wasm_public_env,
            wasm_hydrate_mode,
            runtime_dep,
            debugger,
            build_intent,
            sqlvalue_rust_name,
            sqlfield_rust_name,
            hydration_state_rust_name: None,
            enum_names,
            variant_fields,
            enum_variants,
            enum_traits,
            func_names,
            impl_fn_params,
            record_structs,
            record_by_fieldset,
            cargo_name,
            // Appearance hot-swap routes literals through the crate-root
            // `LiteralTable` (`ipe_runtime::literal_table`), a pure module a
            // dev-loop build compiles under either `web-core` (the served render
            // host) or `control-wire` (the loopback tui socket). It is a
            // repaintable-VIEW concern: a shape with no appearance surface to
            // repaint (worker/script, and a line-oriented `Cli.tea` — a cli emits
            // a transcript, not a repaintable frame) has nothing to hot-swap, so
            // hoisting stays fenced to the repaintable view shapes.
            //   • `uses_web` — the served web app, patched over its HTTP control
            //     port.
            //   • `uses_tui` — the terminal `Tui.tea` app, patched over the
            //     loopback control socket (no HTTP endpoint).
            // A cli (`uses_console`) is excluded: it has no repaintable
            // appearance surface, and its dev-loop debugger uses the
            // `IPE_DEBUGGER_RECORD` dump at loop exit, not the control socket. A
            // pure webview shape (`uses_webview && !uses_web`) is likewise gated
            // off: it ships `web-core` (so the table would build) but runs no
            // control port to push to. With the flag off (`ipe dev build`/`ipe
            // release`) the whole hoist is inert and the emit is byte-identical to
            // the direct-literal form — so a release artifact never references the
            // dev-loop table. `tui_shape_hoists`, `pure_webview_shape_does_not_hoist`,
            // and `web_content_kernel_does_not_hoist_on_tui_shape` pin the shapes.
            hot_appearance: hot_appearance && (uses_web || uses_tui),
            ui_structural_wrappers,
            route_tables,
            scope: ScopeState::default(),
            web_capabilities: program.imported_web_capabilities.clone(),
        };
        // Resolve the `HydrationState` type name through the same renderer the
        // emitted `main_from_hydration_state` signature uses, so the wasm-hydrate
        // glue references EXACTLY that type (single source of truth — no drift
        // between glue and signature). Needs the fully-built `ctx` because
        // `render_type` reads its enum/record tables. Only meaningful under
        // `wasm_hydrate_mode`; skip the walk otherwise.
        if wasm_hydrate_mode {
            ctx.hydration_state_rust_name = ctx.resolve_hydration_state_rust_name(program)?;
        }
        Ok(ctx)
    }

    /// The Rust type name of the `HydrationState` island-parse target, resolved
    /// from the user's `fromHydrationState` projection's parameter type through
    /// [`emit_types::render_type`] — the identical renderer that produces the
    /// emitted `main_from_hydration_state` signature. Returns `None` when the
    /// program declares no `fromHydrationState` function (the glue then never
    /// names a hydration type and falls straight through to a clean init).
    fn resolve_hydration_state_rust_name(&self, program: &Program) -> DResult<Option<String>> {
        for module in &program.modules {
            for func in &module.funcs {
                if self.interner.resolve(func.name) != Some(ipe_ir::HYDRATION_PROJECTION_NAME) {
                    continue;
                }
                let Some((_, param_ty)) = func.params.first() else {
                    // A `fromHydrationState` with no parameter cannot name an
                    // island type — treat as absent (fall through to clean init).
                    return Ok(None);
                };
                // The `HydrationState` island type is monomorphic (the M7
                // field-type gate admits only serialisable, non-generic leaves),
                // so an empty generic scope is exact.
                let rendered =
                    emit_types::render_type(self, param_ty, emit_types::GenericScope::new(&[]))?;
                return Ok(Some(rendered));
            }
        }
        Ok(None)
    }

    /// Arm the per-function literal accumulator for a fresh function body and
    /// return the previous accumulator state so the caller can restore it after
    /// the body is emitted. Only meaningful under [`Self::hot_appearance`]; when
    /// the flag is off it is a cheap no-op reset that stays inert (nothing ever
    /// hoists), keeping the emit byte-identical to the direct-literal form.
    fn begin_function_literals(&self) -> LiteralAccum {
        self.scope.begin_function_literals(self.hot_appearance)
    }

    /// Finish the current function body: take its accumulated style-literal
    /// defaults (in emit order) and restore the previous accumulator. An empty
    /// vector means nothing was hoisted, so the caller emits no table prologue.
    fn end_function_literals(&self, previous: LiteralAccum) -> Vec<String> {
        self.scope.end_function_literals(previous)
    }

    /// Enter a `move`-closure body: hoisting is fenced off inside a closure
    /// because it captures `__ipe_lit` by move. Balanced by [`Self::exit_closure`].
    fn enter_closure(&self) {
        self.scope.enter_closure();
    }

    /// Leave a `move`-closure body, re-enabling top-level hoisting once every
    /// enclosing closure has been left.
    fn exit_closure(&self) {
        self.scope.exit_closure();
    }

    /// Arm the `update`-arm transition rewrite for the duration of the `update`
    /// lambda body: while set, [`crate::emit_expr::emit_match`] reduces a
    /// data-describable arm to an `apply_transition_hot` call. Returns the
    /// previous value so the caller can restore it after the body is emitted
    /// (nested lambdas inside the arm bodies never inherit the arming — the arm
    /// bodies are emitted as ordinary expressions, so only the top `case msg of`
    /// is transition-aware). A no-op arming (`None`) leaves every `case` compiled.
    pub(crate) fn begin_transition_update(
        &self,
        model_param: Option<ipe_intern::Symbol>,
    ) -> Option<ipe_intern::Symbol> {
        self.scope.begin_transition_update(model_param)
    }

    /// Restore the transition-update arming saved by [`Self::begin_transition_update`].
    pub(crate) fn end_transition_update(&self, prev: Option<ipe_intern::Symbol>) {
        self.scope.end_transition_update(prev);
    }

    /// The `Model` parameter of the `update` lambda currently being emitted, when
    /// the transition rewrite is armed; `None` otherwise. Read by
    /// [`crate::emit_expr::emit_match`] to decide whether to attempt the
    /// transition reduction on the top `case`.
    pub(crate) fn transition_model_param(&self) -> Option<ipe_intern::Symbol> {
        self.scope.transition_model_param()
    }

    /// Arm the `subscriptions`-entry sub-description rewrite for the duration of a
    /// TEA `subscriptions` lambda body: while set, [`crate::emit_expr`]'s
    /// `Sub.every` / `Time.every` emit reduces a data-describable tick entry to a
    /// `sub_every_hot("<baked datum>")` call. Returns the previous value so the
    /// caller can restore it after the body is emitted (nested lambdas never leak
    /// the arming). `false` leaves every subscription compiled.
    fn begin_subs_hot(&self, active: bool) -> bool {
        self.scope.begin_subs_hot(active)
    }

    /// Restore the subscriptions arming saved by [`Self::begin_subs_hot`].
    fn end_subs_hot(&self, prev: bool) {
        self.scope.end_subs_hot(prev);
    }

    /// Whether the `subscriptions`-entry sub-description rewrite is currently
    /// armed. Read by [`crate::emit_expr`]'s `Sub.every`/`Time.every` emit to
    /// decide whether to attempt the sub-description reduction.
    pub(crate) fn subs_hot_active(&self) -> bool {
        self.scope.subs_hot_active()
    }

    /// Enter a discard-only probe emit: hoisting is suppressed so the probe does
    /// not append a literal the real emit will append again. Balanced by
    /// [`Self::exit_probe`].
    fn enter_probe(&self) {
        self.scope.enter_probe();
    }

    /// Leave a probe emit, re-enabling hoisting once every enclosing probe has
    /// been left.
    fn exit_probe(&self) {
        self.scope.exit_probe();
    }

    /// Hoist a style-value literal into the current function's table, returning
    /// its slot index. `None` when hoisting is not armed (flag off, no active
    /// body, or inside a `move` closure) — the caller then emits the literal
    /// directly. The baked default is exactly `value`, so a read of the returned
    /// slot renders identically to the direct literal (dev == prod).
    fn hoist_style_literal(&self, value: &str) -> Option<usize> {
        self.scope.hoist_style_literal(value)
    }

    /// Is `home` a driver-generated FFI interface module (`Rust.*`)?
    pub(crate) fn is_foreign_interface_home(&self, home: &ModPath) -> bool {
        home_is_foreign_interface(self.interner, home)
    }

    /// `true` when the emitted crate reaches the `http_client` runtime module —
    /// so `project::assemble_project_files` declares it, adds the `reqwest`
    /// dependency, and keeps the `http_client` prelude bindings.
    ///
    /// The module is reached directly by a client kernel ([`Self::uses_http`])
    /// or by the email surface (whose `email.rs` calls `http_client::ssrf_apply`
    /// for outbound-request SSRF hardening). `http_stream.rs` (which calls
    /// `http_client::ssrf_apply` + `method_to_reqwest`) is declared alongside
    /// `http_client` whenever this is true, keeping reqwest out of server/web
    /// apps that make no outbound HTTP calls.
    ///
    /// This is the single source of truth shared by the manifest augmenter, the
    /// `mod.rs` append, and the prelude filter — they can never disagree.
    pub(crate) const fn reaches_http_client(&self) -> bool {
        self.uses_http || self.uses_email
    }

    /// `true` when the emitted crate reaches the `ssrf` runtime module — so
    /// `project::assemble_project_files` declares it and adds tokio's `"net"`
    /// feature, which its resolver (`tokio::net::lookup_host`) needs.
    ///
    /// Reached by every surface that dials a network host: the HTTP client
    /// ([`Self::reaches_http_client`]), the WebSocket client, and the database.
    /// This is the single source of truth shared by the `mod.rs` append and the
    /// manifest augmenter, so the module is never declared without the feature.
    pub(crate) const fn reaches_ssrf(&self) -> bool {
        self.reaches_http_client() || self.uses_websocket || self.uses_db
    }

    /// `true` when the emitted crate reaches the `jwt` runtime module — so
    /// `project::assemble_project_files` declares it and adds the `jsonwebtoken`
    /// dependency.
    ///
    /// Reached directly by a JWT kernel ([`Self::uses_jwt`]), or transitively by
    /// the `Ipe.Auth` surface: `auth.rs` calls `crate::jwt::…` unconditionally, so
    /// an auth program with no direct `Jwt.*` kernel still needs the `jwt`
    /// module. This is the single source of truth shared by the manifest
    /// augmenter and the `mod.rs` append — they can never disagree.
    pub(crate) const fn reaches_jwt(&self) -> bool {
        self.uses_jwt || self.uses_auth
    }

    /// `true` when the emitted crate names the `Value` (`JsonVal`) or `Decoder<T>`
    /// type — so [`crate::project::assemble_project_files`] keeps the two fixed
    /// prelude aliases (`type Value = JsonVal;` and `pub type Decoder<T> = …`) and
    /// selects the `json` runtime feature (`serde_json`, and via `json = […,
    /// "serde"]` the whole serde stack). A program that reaches neither drops both
    /// aliases and that whole dependency subtree — the last structural feature-floor
    /// removal, leaving a bare emitted app at `app + ipe_runtime + rustix`.
    ///
    /// Reached directly by [`Self::uses_json`] (a `Json`-building kernel or a
    /// `Json`/`Decoder` type-mention), or transitively by a surface whose crate
    /// feature already lists `json` — so this SSOT and the crate-graph closure
    /// agree even at `--no-default-features`: the `Db` surface (`Db.Decode.*` share
    /// the `json` module's carrier; `db = [… "json"]`), `Config` (its decoders
    /// share `decode_*`; `config = [… "json"]`), `jwt` (`jwt = [… "json"]` for the
    /// claims round-trip), and the `web` / `webview` app runtimes (`web = […
    /// "json"]`, and `webview` implies `web`). `server` / `tui` do NOT list `json`,
    /// so a bare server or TUI program that names neither `Value` nor `Decoder`
    /// still drops the feature and the two aliases. FAIL-CLOSED: any uncertain
    /// `json` consumer keeps the feature and the aliases on; dropping them from a
    /// program that spells either type is the forbidden failure, over-inclusion the
    /// accepted cost.
    pub(crate) const fn reaches_json(&self) -> bool {
        self.uses_json
            || self.uses_db
            || self.uses_config
            || self.uses_web
            || self.uses_webview
            || self.reaches_jwt()
    }

    /// `true` when the emitted crate reaches the heavy `crypto_core` floor — the
    /// RSA SHA-256 sign/verify pair and its `rsa` dependency (a ~34-crate
    /// subtree). The RSA arm is `cfg(feature = "crypto")` in `crypto_core.rs`, so
    /// this predicate is the single source of truth for both enabling the
    /// `crypto` feature and declaring the `rsa` dependency; they can never
    /// disagree.
    ///
    /// Reached directly by a heavy `Ipe.Crypto` kernel ([`Self::uses_crypto`]),
    /// or transitively through the JWT / Auth surface ([`Self::reaches_jwt`]):
    /// `jwt.rs`'s RS256 path calls `crate::crypto_core`'s RSA signer, and
    /// `auth.rs` reaches `jwt`. The floor primitives that a non-crypto program
    /// still needs — the entropy pair, the SHA-2 / HMAC family, the constant-time
    /// compare, the `Key`/`Mac` newtypes — are not `cfg`-gated and stay
    /// unconditional. A program that touches none of crypto / jwt / auth pulls no
    /// `rsa`.
    pub(crate) const fn reaches_crypto_core_heavy(&self) -> bool {
        self.uses_crypto || self.reaches_jwt()
    }

    /// `true` when the emitted crate reaches the `crypto_core.rs` FLOOR — so
    /// `project::assemble_project_files` selects the `crypto-core` feature
    /// (`sha2` + `hmac` + `subtle`) and, in the prelude, keeps the
    /// `crypto_random_bytes`/`crypto_random_token` wrapper block. This is the
    /// single source of truth shared by the manifest feature selection, the
    /// prelude-section gate ([`crate::project::native_runtime_bindings`]), and the
    /// closure SEALs; they can never disagree.
    ///
    /// Reached directly by a crypto-floor kernel ([`Self::uses_crypto_core`]), or
    /// transitively by every surface whose runtime module reaches the floor:
    /// `crypto.rs` ([`Self::uses_crypto`]) re-exports and reveals through it;
    /// `jwt.rs` (via [`Self::reaches_jwt`]) signs with `crypto_core`'s HMAC/RSA and
    /// wraps its `Algorithm` in a `secret::Secret`; `db.rs` ([`Self::uses_db`])
    /// SHA-256s the `_ipe_migrations` ledger checksum; `web/*` ([`Self::uses_web`]
    /// / [`Self::uses_webview`]) SHA-256s the client-JS SRI hash and constant-time
    /// compares CSRF tokens through `subtle`; `email.rs` ([`Self::uses_email`])
    /// HMAC-SHA-256s the SMTP auth; `server.rs` ([`Self::uses_server`])
    /// constant-time compares session ids through `subtle`. Each consumer is
    /// verified against the runtime source. FAIL-CLOSED — any uncertain consumer
    /// keeps the floor on. A program that reaches none of these drops the whole
    /// SHA-2/HMAC subtree.
    pub(crate) const fn reaches_crypto_core(&self) -> bool {
        self.uses_crypto_core
            || self.uses_crypto
            || self.reaches_jwt()
            || self.uses_db
            || self.uses_web
            || self.uses_webview
            || self.uses_email
            || self.uses_server
            || self.reaches_secret()
    }

    /// `true` when the emitted crate reaches the `secret.rs` module — so
    /// `project::assemble_project_files` selects the `secret` feature (`zeroize` +
    /// `subtle`, which itself implies `crypto-core`).
    ///
    /// Reached directly by an `Ipe.Secret` kernel or a `Secret`-typed value
    /// ([`Self::uses_secret`]), or transitively by the JWT / Auth surface (via
    /// [`Self::reaches_jwt`]): `jwt.rs`'s builder returns its `Algorithm` as a
    /// `secret::Secret`, and `auth.rs` reaches `jwt`. The single source of truth
    /// shared by the manifest augmenter and the closure SEALs.
    pub(crate) const fn reaches_secret(&self) -> bool {
        self.uses_secret || self.reaches_jwt()
    }

    /// `true` when the emitted crate reaches the `base64` / `hex` /
    /// `percent-encoding` crates — so `project::assemble_project_files` selects
    /// the `encoding` feature, declares `pub mod encoding;` + `pub mod bytes;`,
    /// and adds the three codec deps. The single source of truth shared by the
    /// manifest augmenter and the `mod.rs` append; they can never disagree.
    ///
    /// Reached directly by an `Ipe.Encoding` / `Ipe.Bytes` kernel
    /// ([`Self::uses_encoding`]), OR transitively by every
    /// surface whose runtime module uses the raw codec crates: `crypto.rs`
    /// ([`Self::uses_crypto`]) base64-encodes AEAD output; `db.rs`
    /// ([`Self::uses_db`]) hex-encodes blob columns + migration checksums;
    /// `server.rs` ([`Self::uses_server`]) percent-decodes path params; `email.rs`
    /// ([`Self::uses_email`]) base64/hex for SMTP + signing; `jwt.rs` (via
    /// [`Self::reaches_jwt`]) base64url/hex for token segments; `web/*`
    /// ([`Self::uses_web`] / [`Self::uses_webview`]) base64/hex for the session
    /// store + console proxy + SRI; and `http_client.rs` (via
    /// [`Self::reaches_http_client`]) form-url-decodes query pairs. FAIL-CLOSED —
    /// any uncertain consumer keeps the feature on; over-inclusion is the accepted
    /// precision loss, dropping a codec a program needs is the forbidden failure.
    pub(crate) const fn reaches_encoding(&self) -> bool {
        self.uses_encoding
            || self.uses_crypto
            || self.uses_db
            || self.uses_server
            || self.uses_web
            || self.uses_webview
            || self.reaches_http_client()
            || self.reaches_jwt()
    }

    /// `true` when the emitted crate reaches the `uuid` crate — so
    /// `project::assemble_project_files` selects the `uuid` feature, declares
    /// `pub mod uuid_kernel;`, and adds the dep. The single source of truth shared
    /// by the manifest augmenter and the `mod.rs` append; they can never disagree.
    ///
    /// Reached directly by an `Ipe.Uuid` kernel ([`Self::uses_uuid`]), OR
    /// transitively by:
    /// - the `server` ([`Self::uses_server`]) and `web` ([`Self::uses_web`] /
    ///   [`Self::uses_webview`]) surfaces, whose runtime modules mint session ids /
    ///   CSRF tokens via `uuid::new_v4` directly. Web implies server, but both are
    ///   listed for locality.
    /// - the `jwt` / `auth` surface ([`Self::reaches_jwt`]): `auth.rs` is compiled
    ///   under `#[cfg(feature = "jwt")]` and calls `uuid::Uuid::new_v4()` to mint
    ///   per-session `jti` ids in `auth_sign_token`. The `uuid` dep is optional in
    ///   the runtime crate; without this gate a jwt-only program (no server/web)
    ///   fails with E0433 at cargo build despite `ipe` exit 0.
    ///
    /// FAIL-CLOSED — any uncertain consumer keeps the feature on; dropping `uuid`
    /// from a program that needs it is the forbidden failure.
    pub(crate) const fn reaches_uuid(&self) -> bool {
        self.uses_uuid
            || self.uses_server
            || self.uses_web
            || self.uses_webview
            || self.reaches_jwt()
    }

    /// `true` when the emitted crate reaches the `random.rs` module — so
    /// `project::assemble_project_files` selects the `random` feature and declares
    /// `pub mod random;`.
    ///
    /// Reached directly by an `Ipe.Random` kernel ([`Self::uses_random`]), OR
    /// transitively by the async runtime ([`Self::uses_async_runtime`]):
    /// `task.rs`'s `tokio`-gated retry-with-jitter path draws from `random`'s LCG
    /// (`super::random::lcg_next`), so any tokio program links `random.rs`
    /// regardless of whether user code names a `Random.*` kernel. The crate-side
    /// `async` / `db` / `server` / … features (each of which enables `tokio`) list
    /// `random`, carrying the same closure at `--no-default-features`. FAIL-CLOSED
    /// — dropping `random.rs` from a program whose `task.rs` retry path needs it is
    /// the forbidden failure; a bare (sync) Program that reaches no `Ipe.Random`
    /// kernel still drops the module.
    pub(crate) const fn reaches_random(&self) -> bool {
        self.uses_random || self.uses_async_runtime
    }

    /// `true` when the emitted crate reaches the `log.rs` runtime module — so
    /// `project::assemble_project_files` selects the `log` feature and declares
    /// `pub mod log;`. A standalone leaf: only an `Ipe.Log` kernel
    /// ([`Self::uses_log`]) reaches `log.rs` (nothing else calls into it). `Debug`
    /// is a separate always-on module, so it does not fold in here.
    pub(crate) const fn reaches_log(&self) -> bool {
        self.uses_log
    }

    /// `true` when the emitted crate reaches the `decimal.rs` / `money.rs` runtime
    /// modules — so `project::assemble_project_files` selects the `decimal` feature
    /// (declaring `pub mod decimal;` / `pub mod money;` and adding `rust_decimal`).
    ///
    /// Reached by a `Decimal.*`/`Money.*` kernel ([`Self::uses_decimal`]) OR the
    /// `db` surface: `db.rs` decodes numeric SQL columns (and `Db.Decode.money`)
    /// through `rust_decimal` and the `Decimal` newtype. The crate-side feature
    /// graph carries the same closure (`db = [… "decimal"]`), so this selection and
    /// the manifest agree even at `--no-default-features`. FAIL-CLOSED: an uncertain
    /// `rust_decimal` consumer keeps `decimal` on.
    pub(crate) const fn reaches_decimal(&self) -> bool {
        self.uses_decimal || self.uses_db
    }

    /// `true` when the emitted crate reaches the `char_category.rs` runtime module
    /// — so `project::assemble_project_files` selects the `char-category` feature
    /// (declaring `pub mod char_category;` and adding `unicode-general-category`).
    /// A standalone leaf: only an `Ipe.Char` `General_Category` predicate
    /// ([`Self::uses_char_category`]) reaches it; no surface folds in. The std-only
    /// `Ipe.Char` kernels stay in the always-compiled `char_kernel.rs`.
    pub(crate) const fn reaches_char_category(&self) -> bool {
        self.uses_char_category
    }

    /// `true` when the emitted crate reaches base `chrono` (the `time-core`
    /// feature) — so `project::assemble_project_files` selects `time-core`,
    /// enabling the `chrono` dependency and the `time.rs` module.
    ///
    /// `chrono` is reached by any of: the `log.rs` timestamp
    /// ([`Self::reaches_log`]); any `Ipe.Time` kernel ([`Self::uses_time`], whose
    /// whole `time.rs` module — calendar math + the `chrono-tz` zone helpers —
    /// lives behind `time-core`, with the IANA zones additionally behind `time`);
    /// or the `db` / `web` / `webview` surfaces, whose runtime modules render
    /// `chrono` timestamps (migration ledger, session store, console proxy). The
    /// crate-side feature graph carries the SAME closure — `log`/`time`/`db`/`web`
    /// each imply `time-core` — so this selection and the manifest agree even at
    /// `--no-default-features`. FAIL-CLOSED: any uncertain `chrono` consumer keeps
    /// `time-core` on; dropping `chrono` from a program that renders a timestamp
    /// is the forbidden failure, over-inclusion the accepted precision loss.
    pub(crate) const fn reaches_time_core(&self) -> bool {
        self.reaches_log() || self.uses_time || self.uses_db || self.uses_web || self.uses_webview
    }

    /// `true` when the emitted crate reaches the `url` runtime module — so
    /// `project::assemble_project_files` declares it and adds the `url` crate
    /// (with its `idna` → ICU4X subtree, the single largest gateable dependency
    /// root).
    ///
    /// Reached directly by an `Ipe.Url` kernel ([`Self::uses_url`]), or
    /// transitively by a surface whose runtime module parses with the `url`
    /// crate: the outbound HTTP client ([`Self::reaches_http_client`], whose
    /// `http_client.rs` targets a typed `crate::url::Url`), the WebSocket
    /// client ([`Self::uses_websocket`], whose `ws_client.rs` calls
    /// `::url::Url::parse`), or the Db surface ([`Self::uses_db`], whose
    /// `db.rs::VettedPool::connect` applies the SSRF host gate via `::url::Url::parse`
    /// and `ssrf.rs` parses URLs with `url::Url`). The shared `ssrf` validators
    /// (`use url::Url`) are declared exactly when any of these is, so this union
    /// covers them too. This is the single source of truth shared by the manifest
    /// augmenter and the `mod.rs` append — they can never disagree.
    pub(crate) const fn reaches_url(&self) -> bool {
        self.uses_url || self.reaches_http_client() || self.uses_websocket || self.uses_db
    }

    /// The absolute Rust path for a foreign opaque type declared by an FFI
    /// interface module (`(Rust.Semver, Version)` → `::semver::Version`).
    ///
    /// # Errors
    ///
    /// [`Diagnostic::CompilerBug`] when no FFI emission inputs were supplied
    /// or the type is absent from the map — the driver derives the map and
    /// the interface modules from the SAME artifacts, so a miss is an
    /// internal invariant violation, surfaced rather than emitted as a
    /// dangling Rust type.
    pub(crate) fn foreign_type_path(&self, home: &ModPath, name: Symbol) -> DResult<String> {
        let mut key = String::new();
        for seg in &home.0 {
            key.push_str(self.resolve_ident(*seg)?);
            key.push('.');
        }
        key.push_str(self.resolve_ident(name)?);
        self.ffi
            .as_ref()
            .and_then(|f| f.foreign_types.get(&key))
            .cloned()
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "backend.foreign_type_path",
                detail: format!(
                    "foreign opaque type `{key}` has no Rust path in the FFI emission \
                     inputs — the driver must supply every installed crate's opaque map"
                ),
            })
    }

    /// The conversion glue for an FFI wrapper ident, when the driver supplied
    /// any — `None` for the opaque-handle baseline (no conversion at the call).
    pub(crate) fn ffi_wrapper_glue(&self, ident: Symbol) -> DResult<Option<&FfiWrapperGlue>> {
        let Some(ffi) = self.ffi.as_ref() else {
            return Ok(None);
        };
        let name = self.resolve_ident(ident)?;
        Ok(ffi.wrapper_glue.get(name))
    }

    /// Is a real `EnumDef` registered for `(home, name)`? A `Rust.*`-home
    /// enum with one is a TRANSPARENT FFI import (the lowerer emitted its
    /// declaration); without one it is an opaque handle rendered at its
    /// foreign path.
    pub(crate) fn has_enum_def(&self, home: &ModPath, name: Symbol) -> bool {
        self.enum_names.contains_key(&(home.clone(), name))
    }

    /// Resolve an already-interned identifier string back to its [`Symbol`].
    ///
    /// # Errors
    ///
    /// [`Diagnostic::CompilerBug`] when the string was never interned — the
    /// glue's names come from the injected interface module source, so a miss
    /// is an internal invariant violation, surfaced rather than mis-emitted.
    pub(crate) fn lookup_symbol(&self, s: &str) -> DResult<Symbol> {
        self.interner
            .lookup(s)
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::EmitCtx::lookup_symbol",
                detail: format!("identifier `{s}` from the FFI glue map was never interned"),
            })
    }

    /// The facts of named enum `(home, sym)`: how its Rust type is provided and which traits it implements.
    ///
    /// # Errors
    ///
    /// [`Diagnostic::CompilerBug`] when the enum is neither registered, an
    /// opaque FFI handle, nor runtime-bridged.
    pub(crate) fn enum_facts(&self, home: &ModPath, sym: Symbol) -> DResult<EnumFacts> {
        enum_facts_in(&self.enum_traits, self.interner, home, sym)
    }

    /// The traits of named enum `(home, sym)`, none for an unclassified enum.
    ///
    /// Fail closed: an unclassified enum is refused at [`Self::build`] and at
    /// render, so answering no trait for it can only withhold a derive.
    fn enum_traits_of(&self, home: &ModPath, sym: Symbol) -> EnumTraits {
        self.enum_facts(home, sym)
            .map_or(EnumTraits::NONE, EnumFacts::traits)
    }

    /// Does named enum `sym`'s rendered Rust type support the full `#[derive(Clone, Debug, PartialEq)]` set?
    pub(crate) fn enum_is_derivable(&self, home: &ModPath, sym: Symbol) -> bool {
        self.enum_traits_of(home, sym).derivable
    }

    /// Does named enum `sym`'s rendered Rust type derive `serde::Serialize` and `serde::de::DeserializeOwned`?
    ///
    /// Used by the Ipe.Web Model-admissibility gate.
    pub(crate) fn enum_is_serde(&self, home: &ModPath, sym: Symbol) -> bool {
        self.enum_traits_of(home, sym).serde
    }

    /// Does this program emit `serde` derives on its serde-legal types?
    ///
    /// Both browser shapes route seal types through serde (the Web session
    /// store, the `CustomElement` down/up seam), and a `--debugger` build encodes
    /// a cli/worker session's `Msg` (and, when legal, `Model`) into the typed
    /// session log `ipe dev run --replay` reads. The derive only ever lands on a
    /// type the serde fixpoint proved derivable, so widening this gate is
    /// cargo-buildable by construction. The ONE predicate every serde derive
    /// site and the app-crate `serde` dependency read, so they cannot drift.
    pub(crate) const fn derives_serde(&self) -> bool {
        self.uses_web || self.uses_webview || self.debugger
    }

    /// Is named enum `sym`'s rendered Rust type `Clone`?
    ///
    /// Read by [`emit_enum`] to gate the hand-written `impl Clone` on a
    /// `Clone`-but-not-derivable enum.
    pub(crate) fn enum_is_clone(&self, home: &ModPath, sym: Symbol) -> bool {
        self.enum_traits_of(home, sym).clone
    }

    /// Every variant of user enum `sym` as `(variant name, payload field
    /// types)`, in declaration order. Empty when `sym` is not a known user
    /// enum. Read by the Model-admissibility gate (payload shapes only) and
    /// by the Model schema tag (names AND shapes — the serialized
    /// discriminant is declaration-index-keyed, so the name at each position
    /// is wire-format-relevant).
    pub(crate) fn enum_variant_payloads(
        &self,
        home: &ModPath,
        sym: Symbol,
    ) -> &[(Symbol, Vec<IrType>)] {
        self.enum_variants
            .get(&(home.clone(), sym))
            .map_or(&[], Vec::as_slice)
    }

    /// The program's `Msg`-set descriptor JSON for the additive-`Msg`-variant
    /// hot-swap, or `None` when the `update` field's first parameter is not a
    /// resolvable user enum.
    ///
    /// Recovers the `Msg` type from `update_e` (its first parameter, per
    /// [`crate::emit_model_gate::msg_ty_of_update`]); when that is an
    /// [`IrType::Enum`] with a registered variant set, reduces the enum to a
    /// [`crate::msg_set_classify::CompileMsgSet`] and serializes it to the runtime
    /// `web::msg_set::MsgSet` serde shape. The variant names are resolved through
    /// the interner (stable across emits), so the descriptor is consistent between
    /// the previous and next emit the watch classifier diffs. `None` (no
    /// descriptor) is fail-open: the classifier then finds nothing to diff and the
    /// edit takes the ordinary path, never a spurious `Msg`-set hot-swap.
    pub(crate) fn msg_set_descriptor_json(&self, update_e: &Expr) -> Option<String> {
        let msg_ty = crate::emit_model_gate::msg_ty_of_update(update_e)?;
        let IrType::Enum { home, name, .. } = msg_ty else {
            return None;
        };
        let payloads = self.enum_variant_payloads(home, *name);
        if payloads.is_empty() {
            return None;
        }
        let variants = payloads
            .iter()
            .map(|(vname, fields)| {
                // Resolve the variant name to its interned string; an unresolvable
                // symbol is described under "" (fail-closed — it can only make the
                // set look less additive, never spuriously additive).
                let vname_s = self.interner.resolve(*vname).unwrap_or("").to_owned();
                (
                    vname_s,
                    crate::msg_set_classify::compile_payload_shape(fields),
                )
            })
            .collect();
        Some(
            crate::msg_set_classify::CompileMsgSet {
                schema: crate::msg_set_classify::MSG_SET_SCHEMA,
                variants,
            }
            .to_json(),
        )
    }

    /// The declared payload field types of constructor `variant` of enum `ty`,
    /// in positional order.
    ///
    /// A miss means a constructor expression / pattern names a variant the
    /// program never declared — an upstream-contract violation (the type checker
    /// pins every constructor to its union), surfaced as a [`Diagnostic::CompilerBug`]
    /// rather than a silent mis-emit.
    pub(crate) fn variant_fields(
        &self,
        home: &ModPath,
        ty: Symbol,
        variant: Symbol,
    ) -> DResult<&[IrType]> {
        self.variant_fields
            .get(&(home.clone(), ty, variant))
            .map(Vec::as_slice)
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::EmitCtx::variant_fields",
                detail: format!(
                    "no declared field types for variant {} of enum {}",
                    variant.as_raw(),
                    ty.as_raw()
                ),
            })
    }

    /// Is `field` a payload field of enum `enum_sym` that sits on a type-size
    /// cycle back to that enum — so the Rust enum is infinite-sized (E0072)
    /// unless the field is boxed?
    ///
    /// This generalises the old direct-self-edge test (`field` *is* the enum's
    /// own type, `type Tree = … | Node Tree …`) to every cycle the field can
    /// close: mutual recursion between two enums, and a self-edge routed through
    /// a tuple (`Node (Tree, Int)`), a record (`Node { left : Tree }`), or
    /// another generic's type argument (`Node (Maybe Tree)`). The backend wraps
    /// such a field in `Box<…>` at the declaration and balances that with
    /// `Box::new` at construction and a deref at pattern binding — boxing at
    /// least one edge of every cycle, which is what keeps the emitted crate
    /// finite-sized and matches the reference's recursive-payload boxing.
    ///
    /// Every *constructible* recursive Ipê type routes through an enum (the enum
    /// supplies the nullary base case), so boxing the cyclic enum-payload edge
    /// breaks every reachable cycle; a hypothetical pure record/tuple alias
    /// cycle (no enum on it) is rejected upstream before it can reach the
    /// backend.
    pub(crate) fn is_cyclic_self_field(
        &self,
        field: &IrType,
        enum_home: &ModPath,
        enum_sym: Symbol,
    ) -> bool {
        let mut visited = BTreeSet::new();
        type_reaches_enum(
            field,
            (enum_home, enum_sym),
            &self.enum_variants,
            &mut visited,
        )
    }

    /// Every synthesised record struct, in emission order.
    pub(crate) fn record_structs(&self) -> &[RecordStruct] {
        &self.record_structs
    }

    /// Is `name` the Rust name of some user enum this program declares?
    ///
    /// A thin accessor over [`Self::enum_names`] so callers outside this
    /// module never need to know that map's internal key shape.
    pub(crate) fn contains_type_name(&self, name: &str) -> bool {
        self.enum_names.values().any(|n| n == name)
    }

    /// Fail closed if any synthesised [`RecordStruct`]'s ALREADY-CHOSEN name
    /// (i.e. after [`unique_struct_name`]'s existing intra-category
    /// collision bumping, which stays the right tool for two record shapes
    /// that coincidentally camel-case to the same base) collides with an
    /// enum name, a function name, or a caller-supplied `mod_ident`.
    ///
    /// **Why this check exists (design doc §2.2).** `RecordStruct` and
    /// `EnumDef` both render as Rust
    /// `struct`/`enum` items and share Rust's TYPE namespace (`mod` items
    /// share it too — the same namespace `mod_ident`'s collision gate
    /// polices). Today's single-file backend never cross-checks a record
    /// struct's name against [`Self::enum_names`] — a collision there
    /// currently surfaces as a loud `cargo`-time `E0428`, never a silent
    /// mis-emit. Under a future flat glob-reexport barrel splitting `EnumDef`s
    /// and `RecordStruct`s across different files, Rust's name-resolution
    /// precedence (local definition wins over a glob `use`) would turn that
    /// SAME collision into a SILENT SHADOW instead of a loud error. This gate
    /// closes that gap now, before any file-splitting code exists, so "the
    /// flat namespace is sound" is true by construction rather than by an
    /// untested assumption.
    ///
    /// `func_names` is included for defense-in-depth even though the
    /// value/type namespace split means a record-struct/func collision is
    /// not strictly load-bearing today — cheap, and it stops relying on an
    /// implicit "func-name casing convention never collides" invariant a
    /// future `naming.rs` change could silently violate.
    ///
    /// Fails closed with `Diagnostic::Name::DuplicateValue` — mirroring
    /// [`crate::rust_file::assert_mod_idents_unique`]'s own choice for
    /// `mod_ident` collisions (mirror, not auto-rename, for a namespace-wide
    /// collision), rather than [`unique_struct_name`]'s intra-category
    /// auto-suffix behaviour.
    pub(crate) fn assert_record_structs_disjoint_from_type_namespace(
        &self,
        mod_idents: &BTreeSet<String>,
    ) -> DResult<()> {
        for rec in &self.record_structs {
            let collides = self.contains_type_name(&rec.name)
                || self.func_names.values().any(|n| n == &rec.name)
                || mod_idents.contains(&rec.name);
            if collides {
                return Err(Diagnostic::Name {
                    span: Span::DUMMY,
                    msg: NameError::DuplicateValue {
                        name: rec.name.clone().into_boxed_str(),
                        first: Span::DUMMY,
                    },
                });
            }
        }
        Ok(())
    }

    /// Fail closed if the synthesised `IpeHas<Field>` witness-trait names are not
    /// pairwise distinct, or if one collides with a user enum / mod name.
    ///
    /// A witness trait's Rust name is `to_camel_case("Ipe_has_" + field)`, so two
    /// DIFFERENT surface field names that camel-case to the same base — the
    /// canonical hazard being `first_name` and `firstName`, BOTH valid
    /// lowercase-initial identifiers the parser admits — synthesise the SAME
    /// `IpeHasFirstName` trait. Emitting two traits under one name is `E0428`
    /// (a SEAL breach); relying on the intra-witness field-name set to be
    /// casing-unique is unsound because the field-name lexer does NOT normalise
    /// case. This gate proves the witness namespace collision-free by
    /// construction — the sibling of the record-struct disjointness gate for the
    /// row-poly substrate.
    ///
    /// `field_names` is the whole-program set of row-required field-name symbols
    /// (see `emit_types::row_witness_field_names`); the empty set (no
    /// row-polymorphic annotation) trivially passes.
    pub(crate) fn assert_row_witness_names_disjoint(
        &self,
        field_names: &BTreeSet<Symbol>,
        mod_idents: &BTreeSet<String>,
    ) -> DResult<()> {
        // Map each witness-trait name back to the field it came from; a second
        // field mapping to a name already claimed is the collision.
        let mut seen: BTreeMap<String, Symbol> = BTreeMap::new();
        for &field in field_names {
            let field_str = self.resolve_ident(field)?;
            let trait_name = crate::naming::field_witness_trait_name(field_str);
            let collides_type =
                self.contains_type_name(&trait_name) || mod_idents.contains(&trait_name);
            if collides_type {
                return Err(Diagnostic::Name {
                    span: Span::DUMMY,
                    msg: NameError::DuplicateType {
                        name: trait_name.into_boxed_str(),
                        first: Span::DUMMY,
                    },
                });
            }
            // Two DIFFERENTLY-spelled row fields folding to one witness trait —
            // the `first_name` / `firstName` hazard the doc comment names. Report
            // BOTH surface field names (IPE-N0048): the prior claimant is the
            // Symbol `seen.insert` returns.
            if let Some(prior) = seen.insert(trait_name.clone(), field) {
                let prior_str = self.resolve_ident(prior)?;
                return Err(Diagnostic::Name {
                    span: Span::DUMMY,
                    msg: NameError::RustNameFold {
                        first: prior_str.to_owned().into_boxed_str(),
                        second: field_str.to_owned().into_boxed_str(),
                        rust_name: trait_name.into_boxed_str(),
                        kind: RustNameFoldKind::Value,
                    },
                });
            }
        }
        Ok(())
    }

    /// Render a record TYPE at a USE SITE to its Rust spelling, keyed by its
    /// field-name set: the bare struct name for a monomorphic shape (`RecXY`),
    /// or the struct instantiated at concrete type
    /// arguments for a generic shape (`RecValue<i64>`).
    ///
    /// `generics` is the enclosing function's generic scope: a use-site field
    /// type may itself be an [`IrType::Generic`] (a parametric signature passing
    /// the record through, `wrap : a -> { value : a }`), in which case the
    /// argument renders as that function's Rust generic (`RecValue<T1>`).
    ///
    /// The prepass collected every `IrType::Record` reachable from a signature,
    /// so a miss here is an internal invariant violation (IPE-I0204).
    fn render_record_use(
        &self,
        fields: &BTreeMap<Symbol, IrType>,
        generics: emit_types::GenericScope,
    ) -> DResult<String> {
        let mut key = Vec::with_capacity(fields.len());
        for sym in fields.keys() {
            key.push(self.resolve_ident(*sym)?.to_owned());
        }
        key.sort();
        // The full field map IS the disambiguating shape when the name set is
        // shared by two distinct structs.
        let rec = self.record_struct_by_key(&key, Some(fields))?;
        if rec.type_params.is_empty() {
            // Monomorphic shape: the bare struct name.
            return Ok(rec.name.clone());
        }
        // Generic shape: match the use-site field types against the struct's
        // template to recover one concrete type per generic parameter, then
        // render each (through the ambient scope) as a turbofish-free arg list.
        let mut by_name: BTreeMap<&str, &IrType> = BTreeMap::new();
        for (sym, ty) in fields {
            by_name.insert(self.resolve_ident(*sym)?, ty);
        }
        let mut subst: BTreeMap<Symbol, IrType> = BTreeMap::new();
        for (field_name, template_ty) in &rec.fields {
            let use_ty =
                by_name
                    .get(field_name.as_str())
                    .ok_or_else(|| Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::EmitCtx::render_record_use",
                        detail: format!(
                            "use-site record is missing field `{field_name}` present in the \
                         synthesised struct template"
                        ),
                    })?;
            match_template(template_ty, use_ty, &mut subst)?;
        }
        let mut args = Vec::with_capacity(rec.type_params.len());
        for param in &rec.type_params {
            let arg_ty = subst.get(param).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::EmitCtx::render_record_use",
                detail: format!(
                    "generic record parameter symbol {} was not pinned by any use-site \
                     field; the use site does not instantiate the struct template",
                    param.as_raw()
                ),
            })?;
            args.push(emit_types::render_type(self, arg_ty, generics)?);
        }
        Ok(format!("{}<{}>", rec.name, args.join(", ")))
    }

    /// The Rust struct name for a record LITERAL, keyed by its field names and
    /// (when the name set is shared by two distinct shapes) disambiguated by the
    /// literal's solved [`IrType::Record`] shape threaded from the lowerer.
    ///
    /// A miss means the literal's shape never appeared in a signature — a
    /// lowerer-contract violation (IPE-I0204), surfaced rather than mis-emitted.
    fn record_name_for_literal(
        &self,
        field_names: &[String],
        ty: Option<&IrType>,
    ) -> DResult<&str> {
        let mut key = field_names.to_vec();
        key.sort();
        let shape = match ty {
            Some(IrType::Record(fields)) => Some(fields),
            _ => None,
        };
        Ok(self.record_struct_by_key(&key, shape)?.name.as_str())
    }

    /// Is a synthesised struct registered for this (unsorted) field-name set?
    ///
    /// Used by [`emit_expr::emit_record`]'s `HttpRequest` name-shape shortcut
    /// to defer to the lowerer's authoritative, TYPE-AWARE decision before
    /// falling back to its own field-NAME-only heuristic: `ipe_lower`'s
    /// `ir_type_from_ty` (consulted transitively via
    /// `Lowerer::collect_records_in_ty`, which populates `module.records`,
    /// which THIS registry is built from — see `collect_record_shapes`
    /// above) folds a genuinely `HttpRequest`-shaped value to the opaque
    /// `IrType::HttpRequest`, which never reaches `collect_record_shapes` as
    /// an `IrType::Record` — so a REAL `HttpRequest` literal never gets an
    /// entry here. Conversely, a record that merely shares the 7 canonical
    /// field NAMES with unrelated field TYPES (e.g. all-`Int`) is correctly
    /// classified as a plain record by the (now type-aware) lowerer, so it
    /// DOES get a registered struct here — checking this registry FIRST lets
    /// `emit_record` use that correctly-typed struct instead of mislabelling
    /// the literal `HttpRequest` by name alone.
    fn has_record_struct_for(&self, field_names: &[String]) -> bool {
        let mut key = field_names.to_vec();
        key.sort();
        self.record_by_fieldset.contains_key(&key)
    }

    /// Among the candidate structs for one field-name set, the one whose field
    /// template is ALPHA-EQUIVALENT to `shape_by_name` (identical `skeleton_key`,
    /// the canonical normal form). Two distinct generic siblings (`{q:a}` and
    /// `{q:(a,a)}`) both instantiation-match a generic use site, so the exact
    /// skeleton match is what makes the resolution unambiguous. `None` when no
    /// candidate is alpha-equivalent — a concrete instantiation of a lone generic
    /// template, left to the caller's instantiation scan.
    fn record_struct_alpha_equivalent(
        &self,
        key: &[String],
        indices: &[usize],
        shape_by_name: &BTreeMap<&str, &IrType>,
    ) -> DResult<Option<&RecordStruct>> {
        let mut named: Vec<(String, IrType)> = shape_by_name
            .iter()
            .map(|(n, t)| ((*n).to_owned(), (*t).clone()))
            .collect();
        named.sort_by(|a, b| a.0.cmp(&b.0));
        let shape_skeleton = skeleton_key(&named);
        for &i in indices {
            let rec = self
                .record_structs
                .get(i)
                .ok_or_else(|| Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::EmitCtx::record_name",
                    detail: format!(
                        "dangling struct index for record shape {{{}}}",
                        key.join(", ")
                    ),
                })?;
            if skeleton_key(&rec.fields) == shape_skeleton {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    /// Resolve a (sorted) field-name set to its synthesised [`RecordStruct`],
    /// disambiguating by the record's full field-type `shape` when the name set
    /// is shared by more than one struct.
    ///
    /// * One struct for the set → return it; `shape` is unneeded (the common
    ///   case — no field-name collision).
    /// * Several structs → `shape` MUST be present and select one: a struct
    ///   whose field template is alpha-equivalent to the shape, else a
    ///   monomorphic struct whose field types equal the shape, or a generic
    ///   struct the shape instantiates. A CONCRETE shape can instantiate two
    ///   distinct generic siblings at once (`{q:(Int,Int)}` matches both `{q:a}`
    ///   and `{q:(a,a)}`); it resolves to the MOST-SPECIFIC template (the one
    ///   with the most concrete constructors — `{q:(a,a)}` here — so the value
    ///   is emitted with the struct carrying its true field types). A missing
    ///   `shape`, no match, or two equally-specific matches is a surfaced
    ///   invariant violation, never a silent pick.
    ///
    /// A miss (no struct for the set) means the shape never appeared in a
    /// signature — a lowerer-contract violation (IPE-I0204).
    fn record_struct_by_key(
        &self,
        key: &[String],
        shape: Option<&BTreeMap<Symbol, IrType>>,
    ) -> DResult<&RecordStruct> {
        let indices = self
            .record_by_fieldset
            .get(key)
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::EmitCtx::record_name",
                detail: format!(
                    "no synthesised struct for record shape {{{}}}; the lowerer must \
                     surface every record type it constructs in a signature",
                    key.join(", ")
                ),
            })?;
        if let [only] = indices.as_slice() {
            return self
                .record_structs
                .get(*only)
                .ok_or_else(|| Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::EmitCtx::record_name",
                    detail: format!(
                        "dangling struct index for record shape {{{}}}",
                        key.join(", ")
                    ),
                });
        }
        // Ambiguous field-name set: the full field-type shape selects the struct.
        let shape = shape.ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::EmitCtx::record_name",
            detail: format!(
                "record field set {{{}}} maps to {} distinct structs but the resolution site \
                 supplied no field-type shape to disambiguate",
                key.join(", "),
                indices.len()
            ),
        })?;
        // Compare the shape (by field name) against each candidate's canonical
        // field template: a monomorphic candidate matches by concrete equality, a
        // generic one by instantiation.
        let mut shape_by_name: BTreeMap<&str, &IrType> = BTreeMap::new();
        for (sym, ty) in shape {
            shape_by_name.insert(self.resolve_ident(*sym)?, ty);
        }
        // Two GENERIC candidates can share a name set yet differ structurally
        // (`{q:a}` vs `{q:(a,a)}`, reconciled to distinct structs). A generic
        // use-site shape (`{q:(a,a)}`) instantiation-matches BOTH the exact struct
        // AND any strictly-more-general one (`{q:a}` binds `a := (a,a)`), which
        // would read as an ambiguous "matched more than one". The exact struct is
        // the alpha-equivalent one: its skeleton equals the shape's. Prefer that —
        // it is the canonical, most-specific choice — and only fall back to the
        // instantiation scan when no candidate is alpha-equivalent (a genuine
        // monomorphic instantiation of a single generic template).
        if let Some(rec) = self.record_struct_alpha_equivalent(key, indices, &shape_by_name)? {
            return Ok(rec);
        }
        self.record_struct_most_specific(key, indices, &shape_by_name)
    }

    /// Among the candidate structs a non-alpha-equivalent `shape_by_name`
    /// instantiation-matches, return the MOST-SPECIFIC one.
    ///
    /// A CONCRETE shape (`{q:(Int,Int)}`) can instantiation-match TWO distinct
    /// generic siblings at once: `{q:a}` binds `a := (Int,Int)`, while `{q:(a,a)}`
    /// binds `a := Int`. Both are legitimate instantiations, so a "first match wins"
    /// rule would produce declaration-order-dependent results (IPE-I0001 on some
    /// orderings, wrong struct on others). Resolve deterministically by a two-pass
    /// scan over the FULL candidate set: first find the global maximum
    /// [`template_specificity`], then collect every candidate that achieves it.
    /// If exactly one achieves the max, it wins regardless of declaration order.
    /// If two or more tie AT the max, they are genuinely ambiguous — no single
    /// concrete use-site can uniquely instantiate both — and the tie is surfaced
    /// as an ambiguity error (IPE-I0001). A tie strictly below the max is
    /// unambiguous: the deeper (max) candidate covers it.
    fn record_struct_most_specific(
        &self,
        key: &[String],
        indices: &[usize],
        shape_by_name: &BTreeMap<&str, &IrType>,
    ) -> DResult<&RecordStruct> {
        let candidate_specificity = |rec: &RecordStruct| -> Option<usize> {
            if rec.fields.len() != shape_by_name.len() {
                return None;
            }
            let instantiates = if rec.type_params.is_empty() {
                rec.fields
                    .iter()
                    .all(|(n, t)| shape_by_name.get(n.as_str()) == Some(&t))
            } else {
                let mut subst: BTreeMap<Symbol, IrType> = BTreeMap::new();
                rec.fields.iter().all(|(n, t)| {
                    shape_by_name
                        .get(n.as_str())
                        .is_some_and(|u| match_template(t, u, &mut subst).is_ok())
                })
            };
            if instantiates {
                Some(
                    rec.fields
                        .iter()
                        .map(|(_, t)| template_specificity(t))
                        .sum(),
                )
            } else {
                None
            }
        };
        let dangling = || Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::EmitCtx::record_name",
            detail: format!(
                "dangling struct index for record shape {{{}}}",
                key.join(", ")
            ),
        };

        // Pass 1: collect (index, specificity) for every matching candidate and
        // find the global maximum specificity.
        let mut matching: Vec<(usize, usize)> = Vec::new();
        let mut max_spec: usize = 0;
        for &i in indices {
            let rec = self.record_structs.get(i).ok_or_else(dangling)?;
            if let Some(spec) = candidate_specificity(rec) {
                if spec > max_spec {
                    max_spec = spec;
                }
                matching.push((i, spec));
            }
        }

        // Pass 2: keep only the candidates at the global maximum.
        let at_max: Vec<usize> = matching
            .into_iter()
            .filter_map(|(i, spec)| (spec == max_spec).then_some(i))
            .collect();

        match at_max.as_slice() {
            [] => Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::EmitCtx::record_name",
                detail: format!(
                    "record shape {{{}}} matched no synthesised struct among {} candidates",
                    key.join(", "),
                    indices.len()
                ),
            }),
            [i] => self.record_structs.get(*i).ok_or_else(dangling),
            _ => Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::EmitCtx::record_name",
                detail: format!(
                    "record shape {{{}}} matched {} synthesised structs at equal maximum \
                     specificity — the concrete use site does not uniquely instantiate \
                     any single template",
                    key.join(", "),
                    at_max.len()
                ),
            }),
        }
    }

    /// Resolve a symbol that will be emitted as a Rust identifier, rejecting an
    /// absent *or* empty resolution. The lowerer is contracted never to hand the
    /// backend a dangling or empty-intended value/variant/param symbol, so a
    /// failure here is an internal invariant violation (IPE-I0201) — surfaced as
    /// a [`Diagnostic::CompilerBug`] rather than silently emitting an empty (and
    /// uncompilable) Rust identifier.
    pub(crate) fn resolve_ident(&self, sym: Symbol) -> DResult<&str> {
        match self.interner.resolve(sym) {
            Some(s) if ipe_intern::is_valid_ident_text(s) => Ok(s),
            Some(s) if !s.is_empty() => Err(Diagnostic::CompilerBug {
                where_: "backend.invalid_ident_symbol",
                detail: format!(
                    "symbol {} resolved to {:?}, which is not a valid Rust identifier \
                     (contains dots or non-ASCII characters); a dot-joined qualified \
                     name must not reach identifier emission",
                    sym.as_raw(),
                    s
                ),
            }),
            _ => Err(Diagnostic::CompilerBug {
                where_: "backend.dangling_symbol",
                detail: format!(
                    "value/variant symbol {} resolved to an empty or absent identifier",
                    sym.as_raw()
                ),
            }),
        }
    }

    /// Resolve a symbol to the Rust identifier to emit for it: checked for
    /// emptiness ([`Self::resolve_ident`]) and then mangled if it collides with
    /// a Rust keyword ([`naming::mangle_reserved`]). Used for every emitted
    /// value/variant/param name.
    pub(crate) fn emit_ident(&self, sym: Symbol) -> DResult<String> {
        Ok(naming::mangle_reserved(self.resolve_ident(sym)?.to_owned()))
    }

    /// is this the `Ipe.Cache.Cache` opaque handle type — home
    /// `["Std", "Cache"]`, name `Cache`, and NOT a user-declared enum of the
    /// same name (absent from `enum_names`)? Backed by the runtime
    /// `IpeCacheHandle`; the render/ctor/pattern paths route there.
    pub(crate) fn is_cache_handle_type(&self, home: &ModPath, ty: Symbol) -> bool {
        self.interner.resolve(ty) == Some("Cache")
            && !self.enum_names.contains_key(&(home.clone(), ty))
            && matches!(
                home.0.as_slice(),
                [a, b] if self.interner.resolve(*a) == Some("Ipe")
                    && self.interner.resolve(*b) == Some("Cache")
            )
    }

    pub(crate) fn enum_name(&self, home: &ModPath, ty: Symbol) -> DResult<&str> {
        // `StreamId` is a builtin opaque Http.Stream type backed by the runtime
        // struct `IpeStreamId`.  It has no synthetic `EnumDef` injection (unlike
        // `SqlValue`), so it is not in `enum_names`; we route it here instead.
        // `ChunkEvent` is handled analogously via a dedicated arm in `render_type`.
        if home.0.is_empty() && matches!(self.interner.resolve(ty), Some("StreamId")) {
            // SAFETY: this literal has 'static lifetime; the returned &str
            // is valid for the duration of the emit pass.
            return Ok("IpeStreamId");
        }
        // `Ipe.Cache.Cache` → the non-generic runtime enum `IpeCacheHandle`
        // (its `EnumDef` is suppressed in `ipe_lower`, so it is absent from
        // `enum_names`). The type-position render drops the phantom `k`/`v` args
        // via a dedicated `render_type` arm before reaching here.
        if self.is_cache_handle_type(home, ty) {
            return Ok("IpeCacheHandle");
        }
        // `RedirectPolicy` is a Prelude-built-in enum backed by the runtime
        // `ipe_runtime::http_client::RedirectPolicy` (in scope via
        // `pub use ipe_runtime::*`). Its `EnumDef` is suppressed in `ipe_lower`,
        // so it is absent from `enum_names`; route it here like `StreamId`, so a
        // `case req.redirects of …` scrutinee type resolves in type position.
        if home.0.is_empty() && matches!(self.interner.resolve(ty), Some("RedirectPolicy")) {
            return Ok("RedirectPolicy");
        }
        self.enum_names
            .get(&(home.clone(), ty))
            .map(String::as_str)
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::EmitCtx::enum_name",
                detail: format!("no Rust name for enum type symbol {}", ty.as_raw()),
            })
    }

    /// `true` when `(home, ty)` is a `Ipe.WebSocket` ADT bridged to a
    /// runtime enum (`WebSocketMessage` / `CloseCode`) — its Ipê decl is
    /// suppressed because the runtime already defines the type. See
    /// [`websocket_bridge_rust_name`].
    pub(crate) fn is_websocket_bridged_enum(&self, home: &ModPath, ty: Symbol) -> DResult<bool> {
        let name = resolve_sym(self.interner, ty)?;
        let home_segs = home
            .0
            .iter()
            .map(|s| resolve_sym(self.interner, *s))
            .collect::<DResult<Vec<&str>>>()?;
        Ok(websocket_bridge_rust_name(&home_segs, name).is_some())
    }

    /// The runtime enum path for a built-in constructor's type, or `None` for a
    /// user-declared enum. `Maybe` / `Result` are not user `type` declarations —
    /// their constructors (`Just` / `Nothing` / `Ok` / `Err`) are Prelude
    /// built-ins backed by the runtime's `IpeMaybe` / `IpeResult`, whose variant
    /// names match Ipê's verbatim. A `Some` result steers constructor and pattern
    /// emission to the runtime type (no user-enum field-boxing lookup applies, as
    /// neither is self-recursive).
    pub(crate) fn builtin_runtime_enum(&self, home: &ModPath, ty: Symbol) -> Option<&'static str> {
        // A declared user enum always wins: real Ipê cannot name a `type` `Maybe`
        // or `Result` (canonicalisation rejects shadowing a built-in), so a
        // program-level enum carrying that symbol is a distinct, user-owned type
        // and must route to its own emitted enum, not the runtime shortcut.
        if self.enum_names.contains_key(&(home.clone(), ty)) {
            return None;
        }
        match self.interner.resolve(ty) {
            Some("Maybe") => Some("IpeMaybe"),
            Some("Result") => Some("IpeResult"),
            // `Order` is backed by `IpeOrder` — the `#[repr(u8)]` enum
            // from the runtime crate, in scope via `pub use ipe_runtime::*`.
            // Constructor emission: `IpeOrder::LT` / `IpeOrder::EQ` / `IpeOrder::GT`.
            Some("Order") => Some("IpeOrder"),
            // `ChunkEvent` — the builtin `Ipe.Http.Stream` chunk event enum
            // backed by `ipe_runtime::http_stream::ChunkEvent<IpeError>`.
            // Constructor names match Ipê's verbatim: `Chunk` / `Done` / `Errored`.
            // NOTE: This returns the bare name "ChunkEvent" (without generic args)
            // so that pattern paths emit `ChunkEvent::Chunk(...)`, not
            // `ChunkEvent<IpeError>::Chunk(...)` (invalid Rust syntax).
            // Type-position rendering adds the `<IpeError>` via a special arm in
            // `emit_types::render_type` BEFORE the general `ctx.enum_name` path.
            Some("ChunkEvent") => Some("ChunkEvent"),
            // `Error` is backed by `IpeError` — a single
            // tuple-variant enum whose constructor shares the type's name
            // (`enum_variants[(Prelude, error)] = [error]`, set in
            // `ipe_lower`), so this emits `IpeError::Error(kind, info)` via
            // the SAME path `Maybe`/`Result` use above.
            Some("Error") => Some("IpeError"),
            // `ErrorKind` is backed by `IpeErrorKind` (#repr(u8), mirrors
            // `Order`/`IpeOrder`). Constructor emission: `IpeErrorKind::Io` /
            // `::Network` / etc.
            Some("ErrorKind") => Some("IpeErrorKind"),
            // `ErrorDetails` is backed by `IpeErrorDetails`. Constructor names
            // match Ipê source verbatim:
            // `FfiPanic` / `TypeMismatch` / `HttpStatus` / `JsonDecode` /
            // `Custom`.
            Some("ErrorDetails") => Some("IpeErrorDetails"),
            // `Ipe.Cache.Cache` is backed by the non-generic runtime enum
            // `IpeCacheHandle { Cache(i64) }`. Its `EnumDef` is suppressed in
            // `ipe_lower` (no `enum_names` entry, so the guard above lets this
            // fire), so the `Cache` ctor + `case … of Cache raw` pattern route
            // to `IpeCacheHandle::Cache`. A user's own `type Cache …` DOES get an
            // `EnumDef` (registered in `enum_names`) and short-circuits above.
            Some("Cache") => Some("IpeCacheHandle"),
            // `Ipe.Email.EmailProvider` is backed by the runtime enum
            // `ipe_runtime::email::EmailProvider` (variant names `Resend`/`Ses`/
            // `SendGrid`/`Smtp` match the Ipê ctors verbatim). Its `EnumDef` is
            // suppressed in `ipe_lower` (no `enum_names` entry, so the guard
            // above lets this fire), so `Resend "k"` / `Ses cfg` construct the
            // runtime variants and `case p of Resend k -> …` matches them. In
            // scope via `pub use ipe_runtime::email::*`. A user's own
            // `type EmailProvider` DOES get an `EnumDef` and short-circuits above.
            Some("EmailProvider") => Some("EmailProvider"),
            // `HttpMethod` is backed by `ipe_runtime::HttpMethod` — a
            // closed 7-variant unit enum (`Get`/`Post`/`Put`/`Delete`/
            // `Patch`/`Head`/`Options`). Constructor names match Ipê
            // verbatim: `HttpMethod::Get`, `HttpMethod::Post`, etc.
            // Its `EnumDef` is suppressed in `ipe_lower`, so construction
            // and pattern-matching route through this arm.
            Some("HttpMethod") => Some("HttpMethod"),
            // `RedirectPolicy` is backed by `ipe_runtime::http_client::RedirectPolicy`
            // (`NoRedirects` / `FollowRedirects(i64)`), in scope via
            // `pub use ipe_runtime::*`. Its `EnumDef` is suppressed in `ipe_lower`,
            // so construction (`FollowRedirects 3`) and matching
            // (`case req.redirects of NoRedirects -> …`) route through this arm.
            Some("RedirectPolicy") => Some("RedirectPolicy"),
            _ => None,
        }
    }

    fn func_name(&self, id: FuncId) -> DResult<&str> {
        self.func_names
            .get(&id)
            .map(String::as_str)
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::EmitCtx::func_name",
                detail: format!("no Rust name for function id {}", id.as_raw()),
            })
    }

    /// Was the 0-based parameter `idx` of function `id` monomorphized to an
    /// `impl Fn` generic (so a call site passes its closure argument UNBOXED)?
    /// `false` for a call to any function that took no such param — the common
    /// case, and every kernel / FFI callee (which are not user `Func`s).
    pub(crate) fn call_arg_is_impl_fn(&self, id: FuncId, idx: usize) -> bool {
        self.impl_fn_params
            .get(&id)
            .is_some_and(|idxs| idxs.contains(&idx))
    }
}

/// Fold every runtime-feature requirement a type's leaves declare into `out`, via
/// the IR-crate SSOT [`ipe_ir::ir_type_feature_requirement`].
///
/// This is the type-side half of the feature closure: the selected feature set is
/// the union of the per-leaf requirement over every [`IrType`] the emitter can
/// spell. A carrier's own node requires nothing; its element leaves are reached by
/// this total recursion (no wildcard arm — a new [`IrType`] variant is a compile
/// error until it is descended here), so a gated leaf embedded anywhere in a
/// program's TYPES forces its feature by construction. Composed with the lowerer's
/// body-position walk (which routes the same SSOT through
/// `program_type_mentions`), the fold ranges over every emitted type — the
/// property that makes "a gated type emitted without its feature" unrepresentable
/// (the `Url`/`ImageSrc` breach class).
#[allow(clippy::too_many_lines)] // one arm per IrType variant, deliberately exhaustive
fn collect_type_feature_requirements(ty: &IrType, out: &mut BTreeSet<ipe_ir::RuntimeFeatureId>) {
    if let Some(req) = ipe_ir::ir_type_feature_requirement(ty) {
        out.insert(req);
    }
    match ty {
        // Non-carrier leaves: no nested `IrType` to descend.
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::Db
        | IrType::Generic(_)
        | IrType::RowGeneric(_)
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        | IrType::Url
        | IrType::UrlRelative
        | IrType::Dsn
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::Locale
        | IrType::Principal
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::CacheStats
        | IrType::WebSocketClientCfg
        | IrType::CsvDoc
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        | IrType::EmailAddress
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::AuthConfig
        | IrType::TokenSource
        | IrType::StreamWriter
        | IrType::HttpRequest
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::WebReq
        | IrType::SessionHandle
        | IrType::Regex
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp
        | IrType::UiPlain(_) => {}
        // Single-payload carriers.
        IrType::Task(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::Decoder(inner)
        | IrType::Maybe(inner)
        | IrType::Set(inner)
        | IrType::WebRoute(inner)
        | IrType::Ui { msg: inner, .. }
        | IrType::List(inner) => collect_type_feature_requirements(inner, out),
        // Two-payload carriers.
        IrType::Result(a, b) | IrType::Dict(a, b) | IrType::CustomElement { down: a, up: b } => {
            collect_type_feature_requirements(a, out);
            collect_type_feature_requirements(b, out);
        }
        // Function carriers, all three boxing families.
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            for p in params {
                collect_type_feature_requirements(p, out);
            }
            collect_type_feature_requirements(ret, out);
        }
        IrType::Tuple(elems) => {
            for e in elems {
                collect_type_feature_requirements(e, out);
            }
        }
        IrType::Record(fields) => {
            for f in fields.values() {
                collect_type_feature_requirements(f, out);
            }
        }
        IrType::Enum { args, .. } => {
            for a in args {
                collect_type_feature_requirements(a, out);
            }
        }
    }
}

/// The union of runtime-feature requirements declared by every [`IrType`] the
/// emitter can spell in `program`'s TYPE declarations and signatures — the
/// backend-side type-closure that closes the SEAL blind spot by construction (a
/// gated type in an enum payload / record field / signature forces its feature
/// even when no kernel is called and the lowerer's per-module flag was not set).
/// It walks the same surfaces the record-shape prepass does (function params /
/// return, `module.records`, enum-variant payloads); body-position type mentions
/// are folded by the lowerer through the same SSOT.
fn program_type_feature_requirements(program: &Program) -> BTreeSet<ipe_ir::RuntimeFeatureId> {
    let mut out = BTreeSet::new();
    for module in &program.modules {
        for func in &module.funcs {
            for (_, ty) in &func.params {
                collect_type_feature_requirements(ty, &mut out);
            }
            collect_type_feature_requirements(&func.ret, &mut out);
            for row in &func.row_params {
                for ty in row.fields.values() {
                    collect_type_feature_requirements(ty, &mut out);
                }
            }
        }
        for ty in &module.records {
            collect_type_feature_requirements(ty, &mut out);
        }
        for ty in &module.types {
            let TypeDef::Enum(def) = ty;
            for variant in &def.variants {
                for field_ty in &variant.fields {
                    collect_type_feature_requirements(field_ty, &mut out);
                }
            }
        }
    }
    out
}

/// True when `ty` is a monomorphic leaf that carries no record shape of its own
/// and requires no recursion. Used to short-circuit [`collect_record_shapes`].
const fn ir_type_is_record_shape_leaf(ty: &IrType) -> bool {
    matches!(
        ty,
        IrType::Int
            | IrType::Float
            | IrType::Bool
            | IrType::Str
            | IrType::Char
            | IrType::Unit
            | IrType::Bytes
            | IrType::Json
            | IrType::Db
            | IrType::ServerRequest
            | IrType::ServerResponse
            | IrType::ServerRoute
            | IrType::ServerCookie
            | IrType::StreamWriter
            | IrType::HttpRequest
            | IrType::Regex
            | IrType::WebSocketServer
            | IrType::WebSocketServerCfg
            | IrType::Generic(_)
            | IrType::UiPlain(_)
            | IrType::WebReq
            | IrType::SessionHandle
            | IrType::BackoffStrategy
            | IrType::Order
            | IrType::HttpMethod
            | IrType::Decimal
            | IrType::ErrorKind
            | IrType::Error
            | IrType::ErrorDetails
            | IrType::ErrorInfo
            | IrType::PanicInfo
            | IrType::TypeInfo
            | IrType::SqlFragment
            | IrType::Secret
            | IrType::Path
            | IrType::ProcessRunWithCfg
            | IrType::ProcessRunInPtyCfg
            | IrType::CacheCfg
            | IrType::WebSocketClientCfg
            | IrType::CacheStats
            | IrType::CsvDoc
            | IrType::EmailMessage
            | IrType::EmailAttachment
            | IrType::EmailSesConfig
            | IrType::EmailSmtpConfig
            | IrType::EmailProvider
            | IrType::CryptoKey
            | IrType::CryptoMac
            | IrType::EmailAddress
            | IrType::Locale
            | IrType::Principal
            | IrType::WebApp
            | IrType::TuiApp
            | IrType::CliApp
            | IrType::WorkerApp
    )
}

/// Walk a type, recording every distinct CLOSED record shape it contains
/// (recursing through tuples and nested records). A shape is keyed by its sorted
/// field-name set; the value accumulates each DISTINCT `(field name, type)` list
/// observed for that set, in first-occurrence order.
///
/// One set can legitimately carry several entries — a generic template
/// (`{ value : a }`) plus concrete instantiations (`{ value : Int }`). The later
/// [`canonicalise_shape`] pass reconciles them into one struct. Storing every
/// distinct occurrence (rather than rejecting the second) is what makes the
/// generic-plus-concrete merge representable.
#[allow(clippy::too_many_lines)] // exhaustive per-variant IrType classification — one arm per opaque leaf
fn collect_record_shapes(
    interner: &Interner,
    ty: &IrType,
    shapes: &mut BTreeMap<Vec<String>, ShapeOccurrences>,
) -> DResult<()> {
    if ir_type_is_record_shape_leaf(ty) {
        return Ok(());
    }
    match ty {
        IrType::Tuple(elems) => {
            for elem in elems {
                collect_record_shapes(interner, elem, shapes)?;
            }
        }
        IrType::Record(map) => {
            for field_ty in map.values() {
                collect_record_shapes(interner, field_ty, shapes)?;
            }
            let mut fields: Vec<(String, IrType)> = Vec::with_capacity(map.len());
            for (sym, field_ty) in map {
                fields.push((resolve_sym(interner, *sym)?.to_owned(), field_ty.clone()));
            }
            fields.sort_by(|a, b| a.0.cmp(&b.0));
            let key: Vec<String> = fields.iter().map(|(n, _)| n.clone()).collect();
            let entry = shapes.entry(key).or_default();
            if !entry.contains(&fields) {
                entry.push(fields);
            }
        }
        // A function type contributes no struct of its own, but its param/return
        // types may carry record shapes (e.g. a callback over a record).
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            for param in params {
                collect_record_shapes(interner, param, shapes)?;
            }
            collect_record_shapes(interner, ret, shapes)?;
        }
        IrType::Enum { args, .. } => {
            for arg in args {
                collect_record_shapes(interner, arg, shapes)?;
            }
        }
        IrType::Maybe(elem) | IrType::List(elem) | IrType::Set(elem) => {
            collect_record_shapes(interner, elem, shapes)?;
        }
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            collect_record_shapes(interner, a, shapes)?;
            collect_record_shapes(interner, b, shapes)?;
        }
        IrType::Decoder(inner) | IrType::Task(inner) | IrType::Cmd(inner) | IrType::Sub(inner) => {
            collect_record_shapes(interner, inner, shapes)?;
        }
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        // The opaque Db connection pool handle carries no record shape.
        | IrType::Db
        // Opaque server types carry no record shapes of their own.
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `StreamWriter` is an opaque handle — no record shape.
        | IrType::StreamWriter
        // `HttpRequest` is an opaque handle — no record shape.
        | IrType::HttpRequest
        // `Regex` is an opaque compiled-pattern handle — no record shape.
        | IrType::Regex
        // `WsHandle` / `WsServerCfg` are opaque handles — no record shape.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        // A generic type variable carries no concrete record shape of its own.
        | IrType::Generic(_)
        // A row variable is erased to a witness-bounded generic; its concrete
        // record shapes are collected from the actual argument structs, not here.
        | IrType::RowGeneric(_)
        // nullary plain types (`Length`, `Color`, …) and the opaque live
        // request handle carry no record shapes of their own.
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        // `Order` (LT/EQ/GT) is a primitive leaf — no record shape.
        // `HttpMethod` is a closed 7-variant ADT — no record shape.
        // `Decimal` is a Copy newtype — no record shape.
        // `BackoffStrategy` is a Copy 4-variant enum — no record shape.
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        // Nominal error-payload leaves (SEAL fix) — monomorphic
        // runtime structs, same classification as `Error`/`ErrorDetails`.
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        // `SqlFragment`/`Secret`/`Path`/`Url` are opaque wrappers — no record shape.
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        | IrType::Url
        | IrType::UrlRelative
        // `Dsn` + the external `Connection`/markers + the runtime-config
        // `Setting`/markers are opaque wrappers — no shape.
        | IrType::Dsn | IrType::Connection | IrType::ConnReadOnly | IrType::ConnReadWrite
        | IrType::Setting | IrType::ShapeWeb | IrType::ShapeWebView | IrType::ShapeTerminal
        // Process-run-with cfg + Cache config / stats + Csv document fold to
        // nominal runtime structs — no structural record shape to synthesise.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email records + provider ADT fold to nominal runtime structs — no shape.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // Typed-key newtypes are opaque scalar wrappers — no record shape.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale`/`Principal`, and the `AuthConfig`/`TokenSource` authed-route
        // descriptors, are opaque handles — no record shape.
        | IrType::Locale | IrType::Principal | IrType::AuthConfig | IrType::TokenSource
        // Shape opaque app leaves — no record shape.
        | IrType::WebApp | IrType::TuiApp | IrType::CliApp | IrType::WorkerApp => {}
        // `WebRoute page` descends in case the page type carries a record shape.
        IrType::WebRoute(page) => collect_record_shapes(interner, page, shapes)?,
        IrType::CustomElement { down, up } => {
            collect_record_shapes(interner, down, shapes)?;
            collect_record_shapes(interner, up, shapes)?;
        }
        // `Ui { ctor, msg }` is a msg-parametric wrapper — descend into
        // `msg` in case it carries a nested record (e.g. `Element { x : Int }`).
        IrType::Ui { msg, .. } => collect_record_shapes(interner, msg, shapes)?,
    }
    Ok(())
}

/// Does `ty` reach the enum type `target` by following type-size edges —
/// tuple elements, record fields, an enum's type arguments, and (memoised by
/// enum name) an enum's own variant payload fields?
///
/// A `Box<…>` and a first-class function value (`Box<dyn Fn …>`) are already a
/// pointer-sized indirection, so traversal does NOT descend through
/// [`IrType::Fun`]; those edges can never make a type infinite-sized.
///
/// `visited` memoises the per-enum *definition* walk (a name-keyed, type-arg-
/// independent set of fields) so a recursive enum is explored once. The
/// use-site type arguments are checked on every visit (NOT memoised), because
/// `Maybe Int` and `Maybe Tree` share the enum name `Maybe` but carry different
/// arguments — memoising under the name would drop the `Tree` argument on the
/// second visit.
#[allow(clippy::too_many_lines)] // exhaustive per-variant IrType classification — one arm per opaque leaf
fn type_reaches_enum(
    ty: &IrType,
    target: (&ModPath, Symbol),
    enums: &BTreeMap<(ModPath, Symbol), VariantList>,
    visited: &mut BTreeSet<(ModPath, Symbol)>,
) -> bool {
    match ty {
        IrType::Enum { home, name, args } => {
            if (home, *name) == target {
                return true;
            }
            if args
                .iter()
                .any(|a| type_reaches_enum(a, target, enums, visited))
            {
                return true;
            }
            // Descend into this enum's own variant payload fields once.
            let self_key = (home.clone(), *name);
            if visited.insert(self_key.clone())
                && let Some(variants) = enums.get(&self_key)
            {
                return variants
                    .iter()
                    .flat_map(|(_, fields)| fields)
                    .any(|f| type_reaches_enum(f, target, enums, visited));
            }
            false
        }
        IrType::Tuple(elems) => elems
            .iter()
            .any(|e| type_reaches_enum(e, target, enums, visited)),
        IrType::Record(map) => map
            .values()
            .any(|v| type_reaches_enum(v, target, enums, visited)),
        // `Maybe a` / `Result e a` are the runtime's own (already finite) types;
        // a size cycle can still pass THROUGH their element types, so descend.
        IrType::Maybe(elem) | IrType::List(elem) => type_reaches_enum(elem, target, enums, visited),
        IrType::Result(err, ok) => {
            type_reaches_enum(err, target, enums, visited)
                || type_reaches_enum(ok, target, enums, visited)
        }
        // `Dict k v` / `Set a` are heap-allocated (pointer-sized); they cannot
        // participate in an infinite-size cycle. Recurse into element types for
        // completeness (a Dict/Set whose element type reaches the target enum is
        // still finite because the backing HashMap/BTreeSet is a heap pointer).
        IrType::Dict(k, v) => {
            type_reaches_enum(k, target, enums, visited)
                || type_reaches_enum(v, target, enums, visited)
        }
        IrType::Set(a) => type_reaches_enum(a, target, enums, visited),
        // `Decoder<T>` / `Task<A>` / `IpeCmd<M>` / `IpeSub<M>` are all heap-
        // allocated; descend into their inner types for completeness.
        IrType::Decoder(inner) | IrType::Task(inner) | IrType::Cmd(inner) | IrType::Sub(inner) => {
            type_reaches_enum(inner, target, enums, visited)
        }
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        // `Db` is a pointer-sized opaque handle (connection pool Arc); it cannot
        // participate in an infinite-size cycle.
        | IrType::Db
        // Opaque server types are pointer-sized — they cannot be part of an
        // infinite-size cycle.
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `StreamWriter` is a pointer-sized opaque handle — no size cycle.
        | IrType::StreamWriter
        // `HttpRequest` is a pointer-sized opaque handle — no size cycle.
        | IrType::HttpRequest
        // `Regex` is a pointer-sized opaque handle — no size cycle.
        | IrType::Regex
        // `WsHandle` / `WsServerCfg` are opaque handles — no size cycle.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::Fun(_, _)
        // The promoted `Arc<dyn Fn>` carrier is pointer-sized — no size cycle.
        | IrType::SharedFun(_, _)
        // A curried `FnOnce` chain is the same boxed-trait-object shape as
        // `Fun` — pointer-sized, no size-cycle risk.
        | IrType::FnOnceChain(_, _)
        | IrType::Generic(_)
        // A row variable is erased to a witness-bounded generic; it reaches no
        // enum of its own (the concrete struct at the call site is finite).
        | IrType::RowGeneric(_)
        // nullary plain types and the opaque live request handle are
        // pointer-sized — they cannot form an infinite-size cycle.
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        // `Order` is a primitive value — no cycle risk.
        // `HttpMethod` is a closed 7-variant ADT — no cycle risk.
        // `Decimal` is a Copy newtype — no cycle risk.
        // `BackoffStrategy` is a Copy 4-variant enum — no cycle risk.
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        // Nominal error-payload leaves (SEAL fix) — monomorphic
        // runtime structs, same classification as `Error`/`ErrorDetails`.
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        // `SqlFragment` is a heap-backed struct (String +
        // Vec<SqlParam>) — no size-cycle risk.
        // `Secret` is a heap-backed newtype (String) — no
        // size-cycle risk.
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        // `Url` is a monomorphic opaque wrapper — no reachable enum edge.
        | IrType::Url
        | IrType::UrlRelative
        // `Dsn` is a monomorphic opaque wrapper — no reachable enum edge.
        | IrType::Dsn
        | IrType::Connection | IrType::ConnReadOnly | IrType::ConnReadWrite
        | IrType::Setting | IrType::ShapeWeb | IrType::ShapeWebView | IrType::ShapeTerminal
        // Process-run-with cfg + Cache config / stats + Csv document are
        // monomorphic runtime structs — no reachable enum edge to `target`.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email records + provider ADT are monomorphic runtime types —
        // no reachable enum edge to `target`.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // Typed-key newtypes are monomorphic opaque wrappers — no enum edge.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale` is a monomorphic opaque handle — no enum edge.
        | IrType::Locale
        // `Principal`, and the `AuthConfig`/`TokenSource` authed-route
        // descriptors, are monomorphic opaque leaves — no enum edge.
        | IrType::Principal | IrType::AuthConfig | IrType::TokenSource
        // Shape opaque app leaves — monomorphic, no enum edge.
        | IrType::WebApp | IrType::TuiApp | IrType::CliApp | IrType::WorkerApp => false,
        // `Route<Page>` stores its `not_found`/built pages by value — a page
        // type reaching `target` through a route is a genuine size edge.
        IrType::WebRoute(page) => type_reaches_enum(page, target, enums, visited),
        IrType::CustomElement { down, up } => {
            type_reaches_enum(down, target, enums, visited)
                || type_reaches_enum(up, target, enums, visited)
        }
        // `Ui { ctor, msg }` — descend into `msg`.
        IrType::Ui { msg, .. } => type_reaches_enum(msg, target, enums, visited),
    }
}

/// Does this type contain an [`IrType::Generic`] anywhere (a field that is — or
/// structurally carries — a type variable)?
fn contains_generic(ty: &IrType) -> bool {
    match ty {
        IrType::Generic(_) => true,
        IrType::Tuple(elems) => elems.iter().any(contains_generic),
        IrType::Record(map) => map.values().any(contains_generic),
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            params.iter().any(contains_generic) || contains_generic(ret)
        }
        IrType::Enum { args, .. } => args.iter().any(contains_generic),
        IrType::Maybe(elem) | IrType::List(elem) => contains_generic(elem),
        IrType::Result(err, ok) => contains_generic(err) || contains_generic(ok),
        IrType::Dict(k, v) => contains_generic(k) || contains_generic(v),
        IrType::Set(a) => contains_generic(a),
        IrType::Decoder(inner) | IrType::Task(inner) | IrType::Cmd(inner) | IrType::Sub(inner) => {
            contains_generic(inner)
        }
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        // `Db` is an opaque monomorphic handle — no generic parameters.
        | IrType::Db
        // Opaque server types are monomorphic — no generic parameters.
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `StreamWriter` is monomorphic — no generic parameters.
        | IrType::StreamWriter
        // `HttpRequest` is monomorphic — no generic parameters.
        | IrType::HttpRequest
        // `Regex` is a monomorphic opaque handle — no generic parameters.
        | IrType::Regex
        // `WsHandle` / `WsServerCfg` are monomorphic — no generic parameters.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        // nullary plain types and the opaque live request handle are
        // monomorphic.
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        // `Order` is monomorphic — no generic parameters.
        // `HttpMethod` is monomorphic — no generic parameters.
        // `Decimal` is monomorphic — no generic parameters.
        // `BackoffStrategy` is monomorphic — no generic parameters.
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        // Nominal error-payload leaves (SEAL fix) — monomorphic
        // runtime structs, same classification as `Error`/`ErrorDetails`.
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        // `SqlFragment` is monomorphic — no generic parameters.
        // `Secret` is monomorphic — no generic parameters.
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        // `Url` is a monomorphic opaque wrapper — no generic parameters.
        | IrType::Url
        | IrType::UrlRelative
        // `Dsn` is a monomorphic opaque wrapper — no generic parameters.
        | IrType::Dsn
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting | IrType::ShapeWeb | IrType::ShapeWebView | IrType::ShapeTerminal
        // Process-run-with cfg + Cache config / stats + Csv document are
        // monomorphic — no generic parameters.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email records + provider ADT are monomorphic — no generic
        // parameters.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // Typed security newtypes are monomorphic opaque wrappers — no generic
        // parameters.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale` is monomorphic — no generic parameters.
        | IrType::Locale
        // `Principal` is monomorphic — no generic parameters.
        | IrType::Principal
        // `AuthConfig` / `TokenSource` are monomorphic — no generic parameters.
        | IrType::AuthConfig
        | IrType::TokenSource
        // Shape opaque app leaves — monomorphic, no generic parameters.
        | IrType::WebApp | IrType::TuiApp | IrType::CliApp | IrType::WorkerApp
        // A row variable is a SEPARATE row generic (`R{n}`), never an ordinary
        // `T{n}` record-struct parameter, and never appears inside a record-
        // struct field. It contributes no `<T>` clause here.
        | IrType::RowGeneric(_) => false,
        // `WebRoute page` is parametric on `page`; check if it carries a
        // generic.
        IrType::WebRoute(page) => contains_generic(page),
        IrType::CustomElement { down, up } => contains_generic(down) || contains_generic(up),
        // `Ui { ctor, msg }` is parametric on `msg`; check if `msg` carries
        // a generic.
        IrType::Ui { msg, .. } => contains_generic(msg),
    }
}

/// Collect the distinct [`IrType::Generic`] symbols in `ty`, appending each (in
/// first-occurrence order) to `out` if not already present.
#[allow(clippy::too_many_lines)] // one exhaustive arm per IrType variant — the completeness is the point
fn collect_generics(ty: &IrType, out: &mut Vec<Symbol>) {
    match ty {
        IrType::Generic(s) => {
            if !out.contains(s) {
                out.push(*s);
            }
        }
        IrType::Tuple(elems) => {
            for e in elems {
                collect_generics(e, out);
            }
        }
        IrType::Record(map) => {
            for v in map.values() {
                collect_generics(v, out);
            }
        }
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            for p in params {
                collect_generics(p, out);
            }
            collect_generics(ret, out);
        }
        IrType::Enum { args, .. } => {
            for a in args {
                collect_generics(a, out);
            }
        }
        IrType::Maybe(elem) | IrType::List(elem) => collect_generics(elem, out),
        IrType::Result(err, ok) => {
            collect_generics(err, out);
            collect_generics(ok, out);
        }
        IrType::Dict(k, v) => {
            collect_generics(k, out);
            collect_generics(v, out);
        }
        IrType::Set(a) => collect_generics(a, out),
        IrType::Decoder(inner) | IrType::Task(inner) | IrType::Cmd(inner) | IrType::Sub(inner) => {
            collect_generics(inner, out);
        }
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        // `Db` is monomorphic — no generic parameters to collect.
        | IrType::Db
        // Opaque server types are monomorphic.
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `StreamWriter` is monomorphic — no generics to collect.
        | IrType::StreamWriter
        // `HttpRequest` is monomorphic — no generics to collect.
        | IrType::HttpRequest
        // `Regex` is a monomorphic opaque handle — no generics to collect.
        | IrType::Regex
        // `WsHandle` / `WsServerCfg` are monomorphic — no generics to collect.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        // nullary plain types and the opaque live request handle
        // contribute no generics.
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        // `Order` is monomorphic — no generics to collect.
        // `HttpMethod` is monomorphic — no generics to collect.
        // `Decimal` is monomorphic — no generics to collect.
        // `BackoffStrategy` is monomorphic — no generics to collect.
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        // Nominal error-payload leaves (SEAL fix) — monomorphic
        // runtime structs, same classification as `Error`/`ErrorDetails`.
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        // `SqlFragment` is monomorphic — no generics to collect.
        // `Secret` is monomorphic — no generics to collect.
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        // `Url` is a monomorphic opaque wrapper — no generics to collect.
        | IrType::Url
        | IrType::UrlRelative
        // `Dsn` is a monomorphic opaque wrapper — no generics to collect.
        | IrType::Dsn
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting | IrType::ShapeWeb | IrType::ShapeWebView | IrType::ShapeTerminal
        // Process-run-with cfg + Cache config / stats + Csv document are
        // monomorphic — no generics to collect.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email records + provider ADT are monomorphic — no generics.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // Typed security newtypes are monomorphic opaque wrappers — no generics.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale` is monomorphic — no generics to collect.
        | IrType::Locale
        // `Principal` is monomorphic — no generics to collect.
        | IrType::Principal
        // `AuthConfig` / `TokenSource` are monomorphic — no generics to collect.
        | IrType::AuthConfig
        | IrType::TokenSource
        // Shape opaque app leaves — monomorphic, no generics to collect.
        | IrType::WebApp | IrType::TuiApp | IrType::CliApp | IrType::WorkerApp
        // A row variable is a separate row generic (`R{n}`), tracked in
        // `Func::row_params`, never in the ordinary `T{n}` scope collected here.
        | IrType::RowGeneric(_) => {}
        // `WebRoute page` may carry generic parameters through `page`.
        IrType::WebRoute(page) => collect_generics(page, out),
        IrType::CustomElement { down, up } => {
            collect_generics(down, out);
            collect_generics(up, out);
        }
        // `Ui { ctor, msg }` may carry generic parameters through `msg`.
        IrType::Ui { msg, .. } => collect_generics(msg, out),
    }
}

/// The app surface the program's entry `main` pins, from its lowered return type.
///
/// A `WebApp` leaf under a webview host is the `WebView` surface; an entry that
/// returns no app leaf (or a program with no entry) is a `Script`.
fn entry_app_surface(program: &Program, webview: bool) -> ipe_ir::AppSurface {
    use ipe_ir::AppSurface;
    let entry_ret = program.modules.iter().find_map(|m| {
        let entry = m.entry?;
        m.funcs.iter().find(|f| f.id == entry).map(|f| &f.ret)
    });
    match entry_ret {
        Some(IrType::WebApp) if webview => AppSurface::WebView,
        Some(IrType::WebApp) => AppSurface::Web,
        Some(IrType::TuiApp) => AppSurface::Tui,
        Some(IrType::CliApp) => AppSurface::Cli,
        Some(IrType::WorkerApp) => AppSurface::Worker,
        _ => AppSurface::Script,
    }
}

/// A position-canonical rendering of a field-shape: every [`IrType::Generic`]
/// symbol is replaced by its first-occurrence index, so two alpha-equivalent
/// templates (`{ value : a }` and `{ value : b }`) render the same string and a
/// non-equivalent one (`{ x : a, y : a }` vs `{ x : a, y : b }`) does not. Used
/// only for equality, never emitted.
fn skeleton_key(fields: &[(String, IrType)]) -> String {
    let mut idx: BTreeMap<Symbol, usize> = BTreeMap::new();
    let mut out = String::new();
    for (name, ty) in fields {
        out.push_str(name);
        out.push(':');
        skeleton_ty(ty, &mut idx, &mut out);
        out.push(';');
    }
    out
}

fn skeleton_ty(ty: &IrType, idx: &mut BTreeMap<Symbol, usize>, out: &mut String) {
    match ty {
        IrType::Generic(s) => {
            let next = idx.len();
            let n = *idx.entry(*s).or_insert(next);
            out.push('G');
            out.push_str(&n.to_string());
        }
        IrType::Tuple(elems) => {
            out.push('(');
            for e in elems {
                skeleton_ty(e, idx, out);
                out.push(',');
            }
            out.push(')');
        }
        IrType::Record(map) => {
            out.push('{');
            for (k, v) in map {
                out.push_str(&k.as_raw().to_string());
                out.push(':');
                skeleton_ty(v, idx, out);
                out.push(',');
            }
            out.push('}');
        }
        IrType::Fun(params, ret) => {
            out.push_str("fn(");
            for p in params {
                skeleton_ty(p, idx, out);
                out.push(',');
            }
            out.push_str(")->");
            skeleton_ty(ret, idx, out);
        }
        IrType::Enum { home, name, args } => {
            // Key by the enum's nominal identity (home + symbol) plus its
            // (possibly generic) type args, so `Maybe a` and `Maybe Int`
            // skeletonise distinctly while `Maybe a` and `Maybe b`
            // (alpha-equivalent) coincide. Home is included so two same-short-named
            // types from different modules do not conflate record shapes.
            out.push('E');
            for seg in &home.0 {
                out.push_str(&seg.as_raw().to_string());
                out.push('.');
            }
            out.push_str(&name.as_raw().to_string());
            out.push('<');
            for a in args {
                skeleton_ty(a, idx, out);
                out.push(',');
            }
            out.push('>');
        }
        IrType::Dict(k, v) => {
            out.push_str("Dict<");
            skeleton_ty(k, idx, out);
            out.push(',');
            skeleton_ty(v, idx, out);
            out.push('>');
        }
        IrType::Set(a) => {
            out.push_str("Set<");
            skeleton_ty(a, idx, out);
            out.push('>');
        }
        // `IpeCmd<M>` / `IpeSub<M>` carry a message type parameter; recurse so
        // `IpeCmd<G0>` and `IpeCmd<G1>` (alpha-equivalent) get the same key.
        IrType::Cmd(inner) => {
            out.push_str("Cmd<");
            skeleton_ty(inner, idx, out);
            out.push('>');
        }
        IrType::Sub(inner) => {
            out.push_str("Sub<");
            skeleton_ty(inner, idx, out);
            out.push('>');
        }
        // Scalar / leaf types (Int / Bool / …): their `Debug` form is a stable,
        // generic-free discriminator — exactly what a skeleton needs.
        other => {
            use core::fmt::Write as _;
            // Writing to a `String` is infallible; the `Result` is discarded.
            let _ = write!(out, "{other:?}");
        }
    }
}

/// Match a struct-template type against a USE-SITE type, recording in `subst`
/// the concrete (or generic-in-the-enclosing-function) type each template
/// [`IrType::Generic`] binds to. A template `Generic` binds any use-site type
/// (consistently — a symbol seen twice must bind the same type); every other
/// node must structurally agree.
///
/// A mismatch means a use site that does not instantiate the struct template —
/// an upstream-contract violation surfaced as a [`Diagnostic::CompilerBug`]
/// (IPE-I0205), never a silent mis-emit.
#[allow(clippy::too_many_lines)]
fn match_template(
    template: &IrType,
    concrete: &IrType,
    subst: &mut BTreeMap<Symbol, IrType>,
) -> DResult<()> {
    let mismatch = || Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::match_template",
        detail: format!(
            "use-site record type does not instantiate the synthesised struct template \
             (template {template:?} vs use site {concrete:?})"
        ),
    };
    match template {
        IrType::Generic(s) => match subst.get(s) {
            Some(prev) if prev != concrete => Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::match_template",
                detail: format!(
                    "generic parameter symbol {} is bound to two distinct types at one use \
                     site ({prev:?} and {concrete:?})",
                    s.as_raw()
                ),
            }),
            Some(_) => Ok(()),
            None => {
                subst.insert(*s, concrete.clone());
                Ok(())
            }
        },
        IrType::Record(tm) => match concrete {
            IrType::Record(cm) if tm.len() == cm.len() => {
                for ((tk, tv), (ck, cv)) in tm.iter().zip(cm.iter()) {
                    if tk != ck {
                        return Err(mismatch());
                    }
                    match_template(tv, cv, subst)?;
                }
                Ok(())
            }
            _ => Err(mismatch()),
        },
        // Every compound node pairs its children with the use site's under one
        // head identity (`ipe_ir::paired_children`): a different variant, enum
        // `(home, name)`, `Ui` ctor, function carrier (`Box` vs `Arc` vs
        // `FnOnce` chain are distinct Rust types), or child count mismatches.
        IrType::Tuple(_)
        | IrType::Fun(..)
        | IrType::SharedFun(..)
        | IrType::FnOnceChain(..)
        | IrType::Enum { .. }
        | IrType::Maybe(_)
        | IrType::List(_)
        | IrType::Result(..)
        | IrType::Dict(..)
        | IrType::Set(_)
        | IrType::Decoder(_)
        | IrType::Task(_)
        | IrType::Cmd(_)
        | IrType::Sub(_)
        | IrType::WebRoute(_)
        | IrType::CustomElement { .. }
        | IrType::Ui { .. } => {
            for (t, c) in ipe_ir::paired_children(template, concrete).ok_or_else(mismatch)? {
                match_template(t, c, subst)?;
            }
            Ok(())
        }
        // A concrete leaf must equal the use-site leaf exactly.
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        // `Db` is a monomorphic opaque handle; its template and concrete forms
        // must be identical (both `IrType::Db`).
        | IrType::Db
        // Opaque server types are monomorphic leaf types.
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `StreamWriter` is a monomorphic opaque handle.
        | IrType::StreamWriter
        // `HttpRequest` is a monomorphic opaque handle.
        | IrType::HttpRequest
        // `Regex` is a monomorphic opaque handle.
        | IrType::Regex
        // `WsHandle` / `WsServerCfg` are monomorphic opaque handles.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        // nullary plain types (`Length`, `Color`, …) and the opaque live
        // request handle are monomorphic — must equal exactly.
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        // `Order` is a monomorphic leaf — must equal exactly.
        // `HttpMethod` is a monomorphic leaf — must equal exactly.
        // `Decimal` is a monomorphic leaf — must equal exactly.
        // `BackoffStrategy` is a monomorphic leaf — must equal exactly.
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        // Nominal error-payload leaves (SEAL fix) — monomorphic
        // runtime structs, same classification as `Error`/`ErrorDetails`.
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        // `SqlFragment` is a monomorphic opaque leaf.
        // `Secret` is a monomorphic opaque leaf.
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        // `Url` is a monomorphic opaque leaf — must equal exactly.
        | IrType::Url
        | IrType::UrlRelative
        // `Dsn` is a monomorphic opaque leaf — must equal exactly.
        | IrType::Dsn
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting | IrType::ShapeWeb | IrType::ShapeWebView | IrType::ShapeTerminal
        // Process-run-with cfg + Cache config / stats + Csv document are
        // monomorphic runtime-struct leaves.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email records + provider ADT are monomorphic runtime-type leaves.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // Typed security newtypes are monomorphic opaque leaves — must equal exactly.
        // `Locale` is a monomorphic opaque leaf.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        | IrType::Locale
        | IrType::Principal
        // `AuthConfig` / `TokenSource` are monomorphic opaque leaves.
        | IrType::AuthConfig
        | IrType::TokenSource
        // Shape opaque app leaves — monomorphic.
        | IrType::WebApp | IrType::TuiApp | IrType::CliApp | IrType::WorkerApp => {
            if template == concrete {
                Ok(())
            } else {
                Err(mismatch())
            }
        }
        // A row variable never enters the struct registry — it is erased to a
        // witness-bounded generic in a function signature, never a record-struct
        // template field. Reaching this arm is an invariant violation.
        IrType::RowGeneric(_) => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::match_template",
            detail: "row-generic type reached record-struct template reconciliation; \
                     an open row must never enter the struct registry"
                .to_owned(),
        }),
    }
}

/// Count the concrete (non-generic) type constructors in a record-struct field
/// template, used to rank two generic templates that a single CONCRETE use-site
/// shape instantiation-matches at once. A [`IrType::Generic`] parameter absorbs
/// arbitrary structure and so contributes 0; every other node contributes 1 for
/// itself plus the specificity of its children. A strictly-higher total means a
/// strictly-more-specific template — the concrete shape `{q:(Int,Int)}` scores
/// the tuple template `{q:(a,a)}` (specificity 1: the `Tuple` node, its two
/// generic leaves scoring 0) above the pass-through `{q:a}` (specificity 0),
/// resolving the value to the struct whose fields carry its true types.
fn template_specificity(ty: &IrType) -> usize {
    match ty {
        IrType::Generic(_) | IrType::RowGeneric(_) => 0,
        IrType::Tuple(elems) => 1 + elems.iter().map(template_specificity).sum::<usize>(),
        IrType::Record(map) => 1 + map.values().map(template_specificity).sum::<usize>(),
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            1 + params.iter().map(template_specificity).sum::<usize>() + template_specificity(ret)
        }
        IrType::Enum { args, .. } => 1 + args.iter().map(template_specificity).sum::<usize>(),
        IrType::Maybe(e)
        | IrType::List(e)
        | IrType::Set(e)
        | IrType::Decoder(e)
        | IrType::Task(e)
        | IrType::Cmd(e)
        | IrType::Sub(e)
        | IrType::WebRoute(e)
        | IrType::Ui { msg: e, .. } => 1 + template_specificity(e),
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            1 + template_specificity(a) + template_specificity(b)
        }
        // Every remaining variant is a concrete leaf (`Int`, opaque handles,
        // nullary plain types, …): it contributes 1 and has no children.
        _ => 1,
    }
}

/// Reconcile every distinct field-type shape observed for one field-name set
/// into ONE OR MORE synthesised structs — each returned as its canonical
/// `(field name, type)` template plus its generic parameter list — in stable
/// first-occurrence order.
///
/// A single field-name set can legitimately carry several STRUCTURALLY DISTINCT
/// shapes that share only their field names (e.g. `{ x : Int }` in one place and
/// `{ x : String }` in another). Both type-check, so each must synthesise its
/// own struct rather than collapse; the resolution site disambiguates a literal
/// by its solved shape. Occurrences are grouped:
///
/// * A GENERIC template (a shape carrying a type variable) forms one struct.
///   Every alpha-equivalent generic occurrence and every concrete occurrence
///   that INSTANTIATES the template (verified via [`match_template`]) joins it —
///   this is the parametric-record path (`wrap : a -> { value : a }` plus its
///   `{ value : Int }` instantiations), preserved exactly.
/// * A concrete occurrence that instantiates no generic template joins the
///   MONOMORPHIC class of its structurally-identical peers, or opens a new class
///   if none matches. Each concrete class is one monomorphic struct.
///
/// Ordering is by each class's first-occurrence index, so the emitted struct set
/// (and thus the disambiguated struct names) is deterministic regardless of map
/// iteration.
fn reconcile_shapes(key: &[String], occurrences: &[RecordFields]) -> DResult<Vec<CanonicalShape>> {
    if occurrences.is_empty() {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::reconcile_shapes",
            detail: format!(
                "record field set {{{}}} has no collected shape",
                key.join(", ")
            ),
        });
    }

    let is_generic = |fields: &[(String, IrType)]| fields.iter().any(|(_, t)| contains_generic(t));

    // The generic templates for this name set, one per distinct shape modulo
    // alpha-equivalence. A field-name set does NOT name a parametric record
    // uniquely: body-local shape surfacing (and signatures generally) can feed
    // two GENUINELY-DISTINCT generic shapes under one set — `{ q = a }` (shape
    // `{q:a}`) in one function and `{ q = (a, a) }` (shape `{q:(a,a)}`) in
    // another. Both are well-typed, so each synthesises its own struct, keyed by
    // its `skeleton_key` (the alpha-equivalence normal form). Alpha-EQUIVALENT
    // occurrences share one skeleton and fold to a single struct — no spurious
    // duplication. This mirrors the monomorphic-sibling path below, where
    // structurally-distinct concrete shapes sharing a name set each get a struct.
    let mut templates: Vec<CanonicalShape> = Vec::new();
    let mut template_skeletons: Vec<String> = Vec::new();
    for occ in occurrences.iter().filter(|f| is_generic(f)) {
        let sk = skeleton_key(occ);
        if template_skeletons.contains(&sk) {
            // An alpha-equivalent generic occurrence: already has its struct.
            continue;
        }
        let mut type_params: Vec<Symbol> = Vec::new();
        for (_, ty) in occ {
            collect_generics(ty, &mut type_params);
        }
        template_skeletons.push(sk);
        templates.push((occ.clone(), type_params));
    }

    let mut classes: Vec<CanonicalShape> = Vec::new();
    for occ in occurrences {
        if is_generic(occ) {
            // Folds into its own generic struct (grouped above by skeleton).
            continue;
        }
        // A concrete occurrence that instantiates SOME generic template belongs to
        // that generic struct — not its own concrete one.
        if templates
            .iter()
            .any(|(template, _)| template_instantiated_by(template, occ))
        {
            continue;
        }
        // Otherwise it is a monomorphic shape: join its structurally-identical
        // class, or open a new one. Concrete records carry no type variables, so
        // structural identity is plain equality of the sorted field-type list.
        if !classes.iter().any(|(existing, _)| existing == occ) {
            classes.push((occ.clone(), Vec::new()));
        }
    }

    // The generic structs lead (each template is its skeleton's first generic
    // occurrence, in first-occurrence order); genuinely-distinct concrete
    // siblings follow, also in first-occurrence order.
    let mut out = Vec::with_capacity(templates.len() + classes.len());
    out.extend(templates);
    out.extend(classes);
    Ok(out)
}

/// Does the concrete occurrence `concrete` instantiate the generic `template`
/// (same field-type shape modulo binding each type variable to a concrete type)?
/// A scratch substitution is discarded either way — this is a pure classifier,
/// so a failed match is a plain `false`, never a surfaced error.
fn template_instantiated_by(template: &[(String, IrType)], concrete: &[(String, IrType)]) -> bool {
    if template.len() != concrete.len() {
        return false;
    }
    let mut subst: BTreeMap<Symbol, IrType> = BTreeMap::new();
    template
        .iter()
        .zip(concrete.iter())
        .all(|((tn, tv), (cn, cv))| tn == cn && match_template(tv, cv, &mut subst).is_ok())
}

/// Return `base` if unused, else the first `base<n>` (n ≥ 2) that is free,
/// recording the chosen name in `used`. Deterministic given a deterministic call
/// order; guarantees a collision-free struct name even when two distinct field
/// sets camel-case to the same base — a shape collision the generic-sibling and
/// monomorphic-sibling paths both reach.
///
/// The suffix is appended WITHOUT a separator (`RecQ` → `RecQ2`) so the result
/// stays a valid `UpperCamelCase` type name; a `RecQ_2` spelling tripped rustc's
/// `non_camel_case_types` lint on otherwise-clean emitted code. The `used` set
/// still guards against a base that legitimately ends in that digit.
fn unique_struct_name(base: String, used: &mut BTreeSet<String>) -> String {
    if used.insert(base.clone()) {
        return base;
    }
    let mut n: u32 = 2;
    loop {
        let candidate = format!("{base}{n}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
        n = n.saturating_add(1);
    }
}

/// Resolve a symbol that the IR guarantees came from `interner`. A `None` here
/// means the IR carried a symbol from a different interner — an internal
/// invariant violation, surfaced as a [`Diagnostic::CompilerBug`] rather than a
/// silent empty name.
fn resolve_sym(interner: &Interner, sym: Symbol) -> DResult<&str> {
    interner
        .resolve(sym)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::resolve_sym",
            detail: format!("symbol {} not present in interner", sym.as_raw()),
        })
}

/// The dotted Ipê source spelling of a definition — `Std.Ui.borderRounded` from
/// home segments `["Std", "Ui"]` and leaf `borderRounded`, or just the leaf when
/// the home is empty (a single-module program). Used only to name the two
/// colliding definitions in an [`IPE-N0048`](NameError::RustNameFold) diagnostic,
/// so it is built lazily on the error path.
fn ipe_dotted_name(home_segs: &[&str], leaf: &str) -> String {
    if home_segs.is_empty() {
        leaf.to_owned()
    } else {
        format!("{}.{leaf}", home_segs.join("."))
    }
}

/// A ceiling on the suffix search in [`disambiguated_rust_name`]. A distinct
/// suffix always exists below this bound for any realistic program (it is at
/// most the count of definitions folding to one base name), so exhausting it
/// means the name space is degenerate; the caller fails closed rather than loop.
const RUST_NAME_FOLD_SUFFIX_LIMIT: u32 = 1_000_000;

/// A non-injective mangling can fold two distinct Ipê identifiers (`firstName`
/// and `first_name`, or `Std.Palette/Color` and `Std/PaletteColor`) to one Rust
/// name. Rather than reject the legal program, disambiguate the SECOND claimant
/// to a distinct name by appending a numeric suffix, so both definitions emit.
///
/// The base name is tried first; on collision `<base><sep>2`, `<base><sep>3`, …
/// are tried against `claimed` (the Rust names already taken in this namespace)
/// until one is free. `sep` is `"_"` for snake-cased value names and `""` for
/// `CamelCase` type names, keeping the result a valid Rust identifier in either
/// namespace. Deterministic: definitions fold in a fixed order, so the same
/// program always assigns the same disambiguated names.
///
/// Returns `None` only when every candidate up to [`RUST_NAME_FOLD_SUFFIX_LIMIT`]
/// is taken — a degenerate name space the caller turns back with the fold
/// diagnostic (fail closed, bounded by construction).
fn disambiguated_rust_name(
    base: &str,
    sep: &str,
    claimed: &BTreeMap<String, String>,
) -> Option<String> {
    if !claimed.contains_key(base) {
        return Some(base.to_owned());
    }
    (2..=RUST_NAME_FOLD_SUFFIX_LIMIT).find_map(|n| {
        let candidate = format!("{base}{sep}{n}");
        (!claimed.contains_key(&candidate)).then_some(candidate)
    })
}

/// Is `e` a `Web.route pattern builder` kernel call?
pub(crate) const fn is_web_route_call(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Call {
            callee: Callee::Kernel(KernelFn::WebRoute),
            ..
        }
    )
}

/// Whether a function is a qualifying `Ipe.Ui` structural wrapper for the
/// subtree partition pass.
///
/// Qualifies when ALL of:
/// 1. The function's home module is `["Ipe", "Ui"]`.
/// 2. The body is a single `Callee::Kernel` call whose kernel is one of the
///    four static element-node builders (`UiNode`, `UiTaggedNode`, `UiText`,
///    `UiNone`).
///
/// Type and row parameters are NOT a disqualifier: the layout wrappers
/// (`row`, `column`, etc.) are parametric in `msg` so callers can attach
/// typed event handlers, but `msg` is a type-level variable — it is erased
/// in the IR body and never appears as an `Expr::Var` or `Expr::CloneVar`.
/// The value-level substitution in `substitute_wrapper` only replaces value
/// params (those listed in `func.params`), so a `msg` type param is
/// transparent to the partition pass. Keeping it out would block every
/// wrapper that carries a message type, which is all of them.
///
/// This excludes `Ui.button` / `Ui.link` / `Ui.image` / `Ui.html` /
/// `CustomElement.node` / `Ui.cells` (handlers, raw markup, record config). The body
/// may contain `Var`/`CloneVar` references to value parameters, `Cons`
/// prepend (the marker-attr pattern that `row` / `column` / `wrappedRow` /
/// `grid` / `paragraph` / `textColumn` lower to), and nested kernel calls.
fn is_ipe_ui_structural_wrapper(func: &ipe_ir::Func, interner: &Interner) -> bool {
    // Gate 1: home module is exactly `Ipe.Ui`.
    let home = &func.home.0;
    let [seg0, seg1] = home.as_slice() else {
        return false;
    };
    if interner.resolve(*seg0) != Some("Ipe") || interner.resolve(*seg1) != Some("Ui") {
        return false;
    }
    // Gate 2: body is a single kernel call to one of the four static
    // element-node builders.
    wrapper_body_kernel(&func.body).is_some()
}

/// The element-node kernel a wrapper body calls, looking through any `Let`
/// chain the lowerer may introduce for intermediate expressions.
///
/// Accepts `UiNode` / `UiTaggedNode` / `UiText` / `UiNone` — the four kernels
/// the static partition pass can reduce. Every other kernel is refused.
fn wrapper_body_kernel(body: &Expr) -> Option<KernelFn> {
    // The lowerer may wrap the outermost call in one or more `Let` bindings
    // for subexpressions (e.g. the cons prepend in `row`/`column`). Peel them.
    let mut expr = body;
    while let Expr::Let { body: let_body, .. } = expr {
        expr = let_body;
    }
    let Expr::Call {
        callee: Callee::Kernel(k),
        ..
    } = expr
    else {
        return None;
    };
    match k {
        KernelFn::UiNode | KernelFn::UiTaggedNode | KernelFn::UiText | KernelFn::UiNone => Some(*k),
        _ => None,
    }
}

/// The runtime enum name a `Ipe.WebSocket` ADT is BRIDGED to, or `None`
/// for any other type.
///
/// `WebSocketMessage` and `CloseCode` are declared in the stdlib with
/// constructors, but the `sub_subscribe_ws_{message,close}` runtime fns
/// take/produce `ipe_runtime::ws_client::{WsClientMessage, WsCloseCode}` — whose
/// variant names (`Text`/`Binary`, `Normal`/`GoingAway`/`UnsupportedData`/
/// `InternalError`/`Custom`) and field types match the Ipê ADTs 1:1. Emitting
/// the enum name AS the runtime type makes every constructor / pattern / typed
/// param resolve to the runtime enum (so the user's `toMsg` closure has the
/// exact `Fn(WsClientMessage) -> M` shape the runtime fn requires), and the Ipê
/// enum's own decl is suppressed in [`crate::emit_types::emit_enum`]. Keyed on
/// the type's HOME module so a user's unrelated `type CloseCode` never folds.
pub(crate) fn websocket_bridge_rust_name(home_segs: &[&str], name: &str) -> Option<&'static str> {
    if home_segs != ["Ipe", "WebSocket"] {
        return None;
    }
    match name {
        "WebSocketMessage" => Some("WsClientMessage"),
        "CloseCode" => Some("WsCloseCode"),
        _ => None,
    }
}

#[cfg(test)]
mod record_struct_namespace_tests {
    use ipe_ir::{EnumDef, Module, Variant};

    use super::*;

    /// A record shape whose synthesised name collides with a user enum's Rust
    /// name must fail closed, not silently coexist (today's single-file backend
    /// never cross-checks `RecordStruct` names against `enum_names`/`func_names`
    /// — a gap that only manifests once file-splitting lets a local declaration
    /// silently shadow a glob-reexported one).
    ///
    /// `naming::enum_name(&["Rec"], "XY")` folds to `"RecXY"` — module home
    /// `["Rec"]`, type name `"XY"`. Separately, a record literal with fields
    /// `{x, y}` (`naming::record_struct_name(&["x", "y"])`, asserted
    /// byte-for-byte "`RecXY`" by `naming::record_struct_names_from_field_sets`)
    /// synthesises a struct with the SAME Rust name — a real, constructible
    /// collision, not a hedged placeholder.
    #[test]
    #[allow(clippy::too_many_lines)] // one exhaustive collision-construction fixture
    fn record_struct_colliding_with_enum_name_fails_closed() -> DResult<()> {
        let mut interner = Interner::new();
        let rec_mod = interner.intern("Rec")?;
        let xy_ty = interner.intern("XY")?;
        let a_ctor = interner.intern("A")?;
        let b_ctor = interner.intern("B")?;
        let x_field = interner.intern("x")?;
        let y_field = interner.intern("y")?;

        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![rec_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    name: xy_ty,
                    home: ModPath(vec![rec_mod]),
                    type_params: vec![],
                    variants: vec![
                        Variant {
                            name: a_ctor,
                            fields: vec![],
                        },
                        Variant {
                            name: b_ctor,
                            fields: vec![],
                        },
                    ],
                })],
                funcs: vec![],
                entry: None,
                records: vec![IrType::Record(BTreeMap::from([
                    (x_field, IrType::Int),
                    (y_field, IrType::Int),
                ]))],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        // `EmitCtx::build` itself must still succeed today — the
        // record-vs-enum collision is a PRE-EXISTING gap `build` does not
        // check; this task adds the check as a SEPARATE, explicit gate.
        let ctx = EmitCtx::build(
            &interner,
            &program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            false,
            None,
            false,
            BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )?;
        assert_eq!(ctx.record_structs().len(), 1);
        assert_eq!(
            ctx.record_structs().first().map(|r| r.name.as_str()),
            Some("RecXY")
        );
        assert!(ctx.contains_type_name("RecXY"));

        let result = ctx.assert_record_structs_disjoint_from_type_namespace(&BTreeSet::new());
        assert!(
            matches!(
                result,
                Err(Diagnostic::Name {
                    msg: NameError::DuplicateValue { .. },
                    ..
                })
            ),
            "expected a fail-closed DuplicateValue collision, got {result:?}"
        );
        Ok(())
    }

    /// The common case (no record/enum name collision) must stay unaffected
    /// — the new gate is purely additive.
    #[test]
    fn disjoint_record_structs_do_not_fail_closed() -> DResult<()> {
        let mut interner = Interner::new();
        let main_mod = interner.intern("Main")?;
        let msg_ty = interner.intern("Msg")?;
        let increment = interner.intern("Increment")?;
        let a_field = interner.intern("a")?;
        let b_field = interner.intern("b")?;

        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    name: msg_ty,
                    home: ModPath(vec![main_mod]),
                    type_params: vec![],
                    variants: vec![Variant {
                        name: increment,
                        fields: vec![],
                    }],
                })],
                funcs: vec![],
                entry: None,
                records: vec![IrType::Record(BTreeMap::from([
                    (a_field, IrType::Int),
                    (b_field, IrType::Int),
                ]))],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let ctx = EmitCtx::build(
            &interner,
            &program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            false,
            None,
            false,
            BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )?;
        ctx.assert_record_structs_disjoint_from_type_namespace(&BTreeSet::new())
    }

    /// Two row-required field names that camel-case to ONE witness-trait name
    /// (`first_name` / `firstName` → `IpeHasFirstName`) must fail the row-witness
    /// disjointness gate closed — emitting two `IpeHasFirstName` traits is E0428.
    #[test]
    #[allow(clippy::too_many_lines)] // one exhaustive collision-construction fixture
    fn colliding_row_witness_names_fail_closed() -> DResult<()> {
        let mut interner = Interner::new();
        let main_mod = interner.intern("Main")?;
        let snake = interner.intern("first_name")?;
        let camel = interner.intern("firstName")?;

        // A minimal well-formed program (one nullary enum, no records) is enough
        // to build the ctx; the field-name set is supplied to the gate directly,
        // exactly as `row_witness_field_names` would collect it.
        let unit_ctor = interner.intern("Unit")?;
        let ty = interner.intern("T")?;
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    name: ty,
                    home: ModPath(vec![main_mod]),
                    type_params: vec![],
                    variants: vec![Variant {
                        name: unit_ctor,
                        fields: vec![],
                    }],
                })],
                funcs: vec![],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };

        let ctx = EmitCtx::build(
            &interner,
            &program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            false,
            None,
            false,
            BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )?;

        let colliding: BTreeSet<Symbol> = [snake, camel].into_iter().collect();
        let result = ctx.assert_row_witness_names_disjoint(&colliding, &BTreeSet::new());
        // The two folding field names must BOTH be named (IPE-N0048), not just
        // the mangled trait — that is the point of the fix.
        assert!(
            matches!(
                &result,
                Err(Diagnostic::Name {
                    msg: NameError::RustNameFold { .. },
                    ..
                })
            ),
            "two field names colliding to one witness trait must fail closed with RustNameFold, got {result:?}"
        );
        if let Err(Diagnostic::Name {
            msg:
                NameError::RustNameFold {
                    first,
                    second,
                    rust_name,
                    kind,
                },
            ..
        }) = &result
        {
            let named: BTreeSet<&str> = [first.as_ref(), second.as_ref()].into_iter().collect();
            assert_eq!(
                named,
                ["firstName", "first_name"]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                "both colliding Ipê field names must be reported"
            );
            assert_eq!(rust_name.as_ref(), "IpeHasFirstName");
            assert_eq!(*kind, ipe_diagnostics::RustNameFoldKind::Value);
        }

        // Distinct field names pass — the gate is purely additive.
        let distinct: BTreeSet<Symbol> = std::iter::once(snake).collect();
        assert!(
            ctx.assert_row_witness_names_disjoint(&distinct, &BTreeSet::new())
                .is_ok(),
            "a single field name has no collision to report"
        );
        Ok(())
    }

    /// Two GENUINELY-DISTINCT generic shapes under one field-name set (`{q:a}`
    /// and `{q:(a,a)}`) reconcile to TWO structs, not a `CompilerBug`. This is the
    /// generic twin of the monomorphic-sibling path: distinct shapes sharing a
    /// name set each get a struct. Regression for the IPE-I0001 ICE.
    #[test]
    fn distinct_generic_shapes_one_field_set_reconcile_to_two_structs() -> DResult<()> {
        let mut interner = Interner::new();
        let a = interner.intern("a")?;
        let scalar: RecordFields = vec![("q".to_owned(), IrType::Generic(a))];
        let pair: RecordFields = vec![(
            "q".to_owned(),
            IrType::Tuple(vec![IrType::Generic(a), IrType::Generic(a)]),
        )];

        let out = reconcile_shapes(&["q".to_owned()], &[scalar.clone(), pair.clone()])?;
        // Each distinct generic shape gets its own struct, in first-occurrence
        // order, and both are generic (carry the type parameter `a`) — no
        // monomorphic class, no `CompilerBug`.
        assert_eq!(
            out,
            vec![(scalar, vec![a]), (pair, vec![a])],
            "each distinct generic shape gets its own generic struct"
        );
        Ok(())
    }

    /// Alpha-EQUIVALENT generic occurrences of ONE shape (`{q:a}` and `{q:b}`,
    /// distinct type-var symbols) fold to a SINGLE struct — the fix disambiguates
    /// only genuinely-distinct shapes and never spuriously duplicates.
    #[test]
    fn alpha_equivalent_generic_shapes_fold_to_one_struct() -> DResult<()> {
        let mut interner = Interner::new();
        let a = interner.intern("a")?;
        let b = interner.intern("b")?;
        let with_a: RecordFields = vec![("q".to_owned(), IrType::Generic(a))];
        let with_b: RecordFields = vec![("q".to_owned(), IrType::Generic(b))];

        let out = reconcile_shapes(&["q".to_owned()], &[with_a.clone(), with_b])?;
        assert_eq!(
            out,
            vec![(with_a, vec![a])],
            "alpha-equivalent shapes fold to one generic struct"
        );
        Ok(())
    }

    /// A concrete instantiation of a single generic template folds INTO that
    /// template's struct (the parametric-record path), leaving exactly one struct.
    #[test]
    fn concrete_instantiation_folds_into_its_generic_template() -> DResult<()> {
        let mut interner = Interner::new();
        let a = interner.intern("a")?;
        let generic: RecordFields = vec![("q".to_owned(), IrType::Generic(a))];
        let concrete: RecordFields = vec![("q".to_owned(), IrType::Int)];

        let out = reconcile_shapes(&["q".to_owned()], &[generic.clone(), concrete])?;
        assert_eq!(
            out,
            vec![(generic, vec![a])],
            "the concrete shape instantiates the lone generic template"
        );
        Ok(())
    }

    /// `unique_struct_name` disambiguates a shared base with a separatorless
    /// numeric suffix (`RecQ` → `RecQ2`), keeping every name a valid
    /// `UpperCamelCase` type identifier (a `RecQ_2` spelling trips
    /// `non_camel_case_types` on otherwise-clean emitted code).
    #[test]
    fn unique_struct_name_appends_camel_case_valid_suffix() {
        let mut used = BTreeSet::new();
        assert_eq!(unique_struct_name("RecQ".to_owned(), &mut used), "RecQ");
        assert_eq!(unique_struct_name("RecQ".to_owned(), &mut used), "RecQ2");
        assert_eq!(unique_struct_name("RecQ".to_owned(), &mut used), "RecQ3");
    }
}

#[cfg(test)]
mod sanitize_cargo_name_tests {
    use super::sanitize_cargo_name;

    #[test]
    fn normal_name_passes_through() {
        assert_eq!(sanitize_cargo_name("my-app"), "my-app");
    }

    #[test]
    fn uppercase_is_lowercased() {
        assert_eq!(sanitize_cargo_name("MyApp"), "myapp");
    }

    #[test]
    fn spaces_become_hyphens() {
        assert_eq!(sanitize_cargo_name("my app"), "my-app");
    }

    #[test]
    fn unicode_chars_are_replaced_and_stripped() {
        // é is non-ASCII → replaced with `-`, then trailing `-` stripped
        assert_eq!(sanitize_cargo_name("café"), "caf");
        // ü is non-ASCII → replaced with `-`, then leading `-` stripped
        assert_eq!(sanitize_cargo_name("üapp"), "app");
    }

    #[test]
    fn leading_digit_gets_prefix() {
        assert_eq!(sanitize_cargo_name("1game"), "app-1game");
        assert_eq!(sanitize_cargo_name("42"), "app-42");
    }

    #[test]
    fn empty_input_returns_fallback() {
        assert_eq!(sanitize_cargo_name(""), "ipe-app");
    }

    #[test]
    fn all_invalid_chars_returns_fallback() {
        assert_eq!(sanitize_cargo_name("!!!"), "ipe-app");
        assert_eq!(sanitize_cargo_name("   "), "ipe-app");
    }

    #[test]
    fn reserved_keyword_gets_suffix() {
        assert_eq!(sanitize_cargo_name("mod"), "mod-app");
        assert_eq!(sanitize_cargo_name("fn"), "fn-app");
        assert_eq!(sanitize_cargo_name("ipe"), "ipe-app");
        assert_eq!(sanitize_cargo_name("union"), "union-app");
    }

    #[test]
    fn every_ssot_keyword_gets_suffix() {
        for kw in ipe_intern::RUST_KEYWORDS {
            let lower = kw.to_ascii_lowercase();
            assert_eq!(
                sanitize_cargo_name(kw),
                format!("{lower}-app"),
                "{kw} should get the -app suffix"
            );
        }
    }

    #[test]
    fn cargo_forbidden_bin_name_gets_suffix() {
        // These would be inferred as the emitted crate's binary target and
        // collide with Cargo's build-directory names, failing manifest parse.
        assert_eq!(sanitize_cargo_name("build"), "build-app");
        assert_eq!(sanitize_cargo_name("deps"), "deps-app");
        assert_eq!(sanitize_cargo_name("examples"), "examples-app");
        assert_eq!(sanitize_cargo_name("incremental"), "incremental-app");
    }

    #[test]
    fn long_name_is_truncated_to_64_chars() {
        let long = "a".repeat(100);
        let result = sanitize_cargo_name(&long);
        assert!(
            result.len() <= 64,
            "name must be at most 64 chars, got {}",
            result.len()
        );
    }

    #[test]
    fn truncation_does_not_leave_trailing_hyphen() {
        // 63 'a's then a unicode char that becomes a hyphen at position 64
        let input = format!("{}é", "a".repeat(63));
        let result = sanitize_cargo_name(&input);
        assert!(
            !result.ends_with('-'),
            "truncated name must not end with hyphen"
        );
        assert!(result.len() <= 64);
    }

    #[test]
    fn valid_name_with_underscores() {
        assert_eq!(sanitize_cargo_name("my_app"), "my_app");
    }

    #[test]
    fn consecutive_invalid_chars_become_one_hyphen() {
        assert_eq!(sanitize_cargo_name("a  b"), "a-b");
        assert_eq!(sanitize_cargo_name("a!!b"), "a-b");
    }

    // Issue #2981's exact regression target: a purely-underscore name. `_`
    // alone is the Rust underscore token, not a legal identifier, so it is
    // guarded as defense in depth. Multi-underscore names (`__`, `___`) are
    // legal identifiers and Cargo (1.98.1, verified with `cargo new`/`cargo
    // build`) accepts them unmodified — pass through untouched, not silently
    // rewritten into a name Cargo never actually rejected.
    #[test]
    fn all_underscore_name_is_handled() {
        assert_eq!(sanitize_cargo_name("_"), "_-app");
        assert_eq!(sanitize_cargo_name("__"), "__");
        assert_eq!(sanitize_cargo_name("___"), "___");
    }

    // `test` is not a Rust keyword and was NOT in any prior guard list, but
    // real Cargo (1.98.1, verified with `cargo new`/`cargo build`) rejects it:
    // "package name `test` conflicts with Rust's built-in test library". This
    // pins the confirmed gap #2981 closes.
    #[test]
    fn test_literal_gets_suffix() {
        assert_eq!(sanitize_cargo_name("test"), "test-app");
        assert_eq!(sanitize_cargo_name("Test"), "test-app");
    }

    // `std`/`core`/`alloc`/`proc_macro` were checked against real Cargo
    // (1.98.1, `cargo new`/`cargo build`) and found buildable as package
    // names — they are not rejected, so no guard is added for them; a guard
    // here would pin a false premise into the fallback grammar.
    #[test]
    fn std_core_like_names_are_not_forced_into_fallback() {
        assert_eq!(sanitize_cargo_name("std"), "std");
        assert_eq!(sanitize_cargo_name("core"), "core");
        assert_eq!(sanitize_cargo_name("alloc"), "alloc");
        assert_eq!(sanitize_cargo_name("proc_macro"), "proc_macro");
    }

    // Class-closing property: `sanitize_cargo_name`'s output is NEVER itself
    // one of the exact names Cargo rejects outright, for any input that
    // collapses to one. Proves the refusal for the whole reserved set in one
    // sweep, not just the handful of names spelled out above.
    #[test]
    fn output_never_collides_with_a_reserved_name() {
        let mut candidates: Vec<&str> = ipe_intern::RUST_KEYWORDS.to_vec();
        candidates.extend_from_slice(&[
            "ipe",
            "union",
            "test",
            "_",
            "build",
            "deps",
            "examples",
            "incremental",
        ]);
        let reserved: std::collections::HashSet<&str> = candidates.iter().copied().collect();
        for candidate in candidates {
            let sanitized = sanitize_cargo_name(candidate);
            assert!(
                !reserved.contains(sanitized.as_str()),
                "sanitize_cargo_name({candidate:?}) = {sanitized:?} still collides with a reserved name"
            );
        }
    }

    // `sanitize_cargo_name` is a thin wrapper over the `CargoPackageName`
    // smart constructor — the newtype is the actual invariant holder, and no
    // caller can construct one except through `sanitize`.
    #[test]
    fn wrapper_matches_newtype_constructor() {
        for input in ["my-app", "", "_", "test", "1game", "café", "mod"] {
            assert_eq!(
                sanitize_cargo_name(input),
                super::CargoPackageName::sanitize(input).into_inner()
            );
        }
    }
}

#[cfg(test)]
mod crate_identity_tests {
    use super::{CRATE_IDENTITY_HEX_LEN, crate_identity};
    use std::path::Path;

    // Anti-thrash guarantee: same canonical project path → same crate identity
    // every build (deterministic — PRINCIPLE 2 Correctness), so a shared
    // CARGO_TARGET_DIR keeps one stable cache slot per project.
    #[test]
    fn same_path_yields_same_identity() {
        let dir = Path::new("/home/user/projects/app");
        assert_eq!(crate_identity("test", dir), crate_identity("test", dir));
    }

    // Anti-thrash guarantee: two projects sharing a friendly name but living at
    // DIFFERENT canonical paths get DIFFERENT crate identities → separate cache
    // slots → no cross-project fingerprint thrash (PRINCIPLE 4 Efficiency).
    #[test]
    fn same_name_different_paths_yield_distinct_identities() {
        let a = crate_identity("test", Path::new("/home/alice/test"));
        let b = crate_identity("test", Path::new("/home/bob/test"));
        assert_ne!(a, b);
    }

    #[test]
    fn identity_keeps_the_friendly_base_as_prefix() {
        let id = crate_identity("my-app", Path::new("/tmp/one"));
        assert!(
            id.starts_with("my-app_"),
            "identity must keep the friendly base as its prefix, got {id:?}"
        );
        // Suffix is exactly the fixed-width lowercase-hex digest.
        let suffix = id.rsplit('_').next().unwrap_or_default();
        assert_eq!(suffix.len(), CRATE_IDENTITY_HEX_LEN);
        assert!(
            suffix
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "suffix must be lowercase hex, got {suffix:?}"
        );
    }

    // The join must never exceed Cargo's 64-char name ceiling: the base is
    // trimmed to make room, the hash is preserved whole (it is the disambiguator).
    #[test]
    fn over_long_base_is_truncated_under_the_cargo_ceiling() {
        let long_base = "a".repeat(100);
        let id = crate_identity(&long_base, Path::new("/tmp/x"));
        assert!(id.len() <= 64, "identity {} chars exceeds 64", id.len());
        assert!(id.ends_with(&format!("_{}", id.rsplit('_').next().unwrap_or_default())));
    }
}
