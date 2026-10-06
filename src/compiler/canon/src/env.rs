//! The canonicalisation environment: the name → resolution tables consulted
//! during name resolution. Port of the supported subset of
//! `Ipe.Canonicalise.Environment`.
//!
//! Iteration order is never observable (lookups only), but the tables are
//! `BTreeMap`s so the structure is deterministic regardless of insertion order.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use ipe_diagnostics::{DResult, Diagnostic, NameError, Span};
use ipe_intern::{Interner, Symbol};
use ipe_kernels::{AppSurface, StdlibKernel};

use crate::resolve::{ModuleOrigin, QualifierForm, import_qualifier_forms};
use crate::scope::{ExprTarget, Identity, ModuleScope, Origin, Tier, ValueIdentity};

/// Authoritative map from a stdlib module's full import path to its canonical
/// qualifier short-name.
///
/// The key is the module's segment list; the value is the short-name under which
/// that module's members are pooled in [`Env::kernel_members`] (see the
/// `QUALIFIERS` table in [`Env::install_prelude_qualifiers`]).
///
/// This is the single source of truth consulted by the canonicaliser when it
/// registers a user's `import Ipe.… as Alias` (or the Elm last-segment default)
/// so the alias resolves to the same kernel members as the canonical qualifier.
/// It is the Rust-port counterpart of the upstream the compiler
/// `Ipe.Canonicalise.Environment.staticKernelModules` (path → canonical name).
///
/// Two invariants keep this table from drifting out of sync with the qualifier
/// registry, both enforced by unit tests:
///
/// * **No dangling target** (`stdlib_module_paths_target_a_known_qualifier`):
///   every `canonical` here is a key of a freshly-built `Env`'s `kernel_members`. A
///   path whose canonical were absent would resolve to `None` (fail-closed) —
///   the alias is simply not registered and the reference surfaces the usual
///   `UnknownModule` at its use site, never a silently-invented empty qualifier.
/// * **Total coverage** (`every_canonical_qualifier_has_an_import_path`): every
///   primary qualifier the registry defines appears here under at least one
///   import path, so a newly-added kernel module cannot ship without a way for
///   users to `import … as Alias` it.
///
/// Only real `Ipe.*` module paths belong here — the first segment must
/// be `Ipe`, matching the guard in `resolve::register_stdlib_import_aliases`.
pub const STDLIB_MODULE_QUALIFIERS: &[(&[&str], &str)] = &[
    // A compiled-source module (`ipe_stdlib::COMPILED_STD_MODULES`) never appears
    // here: a module is EITHER a kernel qualifier OR compiled source
    // (`compiled_vs_kernel_qualifier_disjoint`). Its members reach kernels via
    // `Kernel.kernel "X_*"` aliases resolved by `detect_kernel_alias`.
    //
    // ── Ipe.* pure + effect modules (kernel qualifiers) ────────────────────
    (&["Ipe", "Crypto"], "Crypto"),
    // `Ipe.Secret` — opaque secret-string wrapper.
    (&["Ipe", "Secret"], "Secret"),
    // `Ipe.CssSafety` — the Ipe.Css leaf security kernels. This
    // is a KERNEL qualifier (imported by the compiled-source `Ipe.Css`); `Ipe.Css`
    // itself stays OUT of this table (it is compiled source, registered in ipe's
    // `COMPILED_STD_MODULES`), so the `compiled_vs_kernel_qualifier_disjoint`
    // invariant holds.
    (&["Ipe", "CssSafety"], "CssSafety"),
    (&["Ipe", "Jwt"], "Jwt"),
    (&["Ipe", "Json", "Encode"], "JsonEnc"),
    (&["Ipe", "Json", "Decode"], "JsonDec"),
    (&["Ipe", "Json", "Decode", "Pipeline"], "JsonDecP"),
    (&["Ipe", "System"], "System"),
    // `Ipe.File` is DELIBERATELY absent: it is compiled-source
    // (`ipe::stdlib::COMPILED_STD_MODULES`), so `readFileLimit`'s typed
    // `ByteSize` ceiling is the checked Ipê wrapper, not the raw-`Int` kernel.
    (&["Ipe", "Process"], "Process"),
    (&["Ipe", "Http"], "Http"),
    // ── Ipe.Http.* server surface ───────────────────────────────────────────
    (&["Ipe", "Http", "Server"], "Server"),
    (&["Ipe", "Http", "Middleware"], "Middleware"),
    (&["Ipe", "Http", "RateLimit"], "RateLimit"),
    // ── Ipe.* modules ───────────────────────────────────────────────────────
    // `Ipe.Cmd` / `Ipe.Sub` are DELIBERATELY absent: the canonical `Cmd` / `Sub`
    // kernel qualifiers are compiler/runtime internals, not user-importable
    // modules. `Cmd` / `Sub` are shape-specific, so user code reaches them
    // through the shape-scoped re-export modules below (`Ipe.Tea.Web.Cmd`,
    // `Ipe.Tea.Terminal.Sub`, …). A user `import Ipe.Cmd` names no known stdlib
    // path and fails closed with the ordinary `UnknownModule` diagnostic.
    (&["Ipe", "Db"], "Db"),
    // `Ipe.App` / `Ipe.Host` — the runtime-config front door kernel qualifiers.
    // `App.fromEnv` seals an env var into a `Secret`; `Host.bind` builds a
    // host-bind `Setting`. Kernel qualifiers (their members are kernels, not a
    // compiled-source veneer), so they stay out of `COMPILED_STD_MODULES`.
    (&["Ipe", "App"], "App"),
    (&["Ipe", "Host"], "Host"),
    // `Ipe.Console` — the console/telemetry `Secret`-typed token settings
    // (`adminToken` / `ingestToken` / `metricsToken`). A kernel qualifier (its
    // members build `Setting` values), so it stays out of `COMPILED_STD_MODULES`.
    (&["Ipe", "Console"], "Console"),
    (&["Ipe", "Db", "Decode"], "Db.Decode"),
    (&["Ipe", "Db", "Sql"], "Sql"), // SqlFragment builder
    // `Ipe.Ui.*` sub-qualifiers: Ipe.Ui itself is compiled-source (see the
    // exclusion table above); these leaf sub-qualifiers are kernel qualifiers.
    (&["Ipe", "Ui", "Background"], "Background"),
    (&["Ipe", "Ui", "Border"], "Border"),
    (&["Ipe", "Ui", "Font"], "Font"),
    (&["Ipe", "Ui", "Region"], "Region"),
    (&["Ipe", "Ui", "Input"], "Input"),
    (&["Ipe", "Ui", "Lazy"], "Lazy"),
    (&["Ipe", "Ui", "Keyed"], "Keyed"), // ipe-key diff identity
    // `Ipe.Html` / `Ipe.Html.Attributes` are compiled-source (see exclusion table
    // above); `Ipe.Html.Events` is a kernel qualifier and stays in this table.
    (&["Ipe", "Html", "Events"], "Event"),
    // ── Ipe.Tea.<Shape> managed-update-loop shapes (ADR 0005) ────────────────
    // The TEA shapes live under `Ipe.Tea.*`; the canonical short qualifier
    // ("Web"/"Tui"/…) is preserved so every lower.rs kernel match arm is
    // unchanged. Importing any `Ipe.Tea.*` module marks the module a TEA app —
    // a plain-`main` Program that imports one is rejected (IPE-N0033).
    (&["Ipe", "Tea", "Web"], "Web"),
    // `Ipe.Tea.Tui` / `Ipe.Tea.Cli` — the two app-entry surfaces over the one
    // terminal rendering family's two drive axes. `Tui.tea` is the full-screen
    // entry (view=Element, key input via `Tui.Sub.onKey`); `Cli.tea` is the
    // line-oriented entry (view=Lines, line input via `Cli.Sub.onLine`). Both carry `KernelClass::Terminal` internally, so
    // every lower.rs Terminal-family arm is unchanged. `Ipe.Tea.Terminal` (the
    // bare app surface) is retired: the entries are `Tui.tea` / `Cli.tea`.
    (&["Ipe", "Tea", "Tui"], "Tui"),
    (&["Ipe", "Tea", "Cli"], "Cli"),
    // `Ipe.Tea.Worker` — the view-less co-located worker app-entry surface:
    // `Worker.tea { init, update, subscriptions }`. No render; output is `Cmd`.
    // Importing it marks the module a TEA app (IPE-N0033). A worker classifies to
    // the co-located Script placement and can never reach the Solo/wasm sandbox.
    (&["Ipe", "Tea", "Worker"], "Worker"),
    // `Ipe.Tea.Web.PubSub` — the Web-shape-scoped TEA-side broadcast surface:
    // `publish` / `publishNoEcho` (Cmd forms, fired from `update`) and
    // `subscribeTopic` (Sub form, declared in `subscriptions`). Distinct from the
    // top-level Task-shaped `Ipe.PubSub`: these return `Cmd msg` / `Sub msg`, so
    // they are TEA-loop machinery and importing this path marks the module a TEA
    // app (IPE-N0033). Its members re-export the canonical `Cmd` / `Sub` kernels.
    (&["Ipe", "Tea", "Web", "PubSub"], "TeaWebPubSub"),
    // ── Shape-scoped `Cmd` / `Sub` re-export modules ─────────────────────────
    // `Cmd` / `Sub` are shape-specific: each TEA shape re-exports the canonical
    // `Cmd` / `Sub` kernels under its own `Ipe.Tea.<Shape>.{Cmd,Sub}` path.
    // Importing one marks the module a TEA app (IPE-N0033), and referencing a
    // shape whose `Cmd` / `Sub` does not match the app entry kernel fails closed
    // (IPE-N0035). The canonical `Cmd` / `Sub` qualifiers stay internal.
    (&["Ipe", "Tea", "Web", "Cmd"], "TeaWebCmd"),
    (&["Ipe", "Tea", "Web", "Sub"], "TeaWebSub"),
    (&["Ipe", "Tea", "Terminal", "Cmd"], "TeaTerminalCmd"),
    (&["Ipe", "Tea", "Terminal", "Sub"], "TeaTerminalSub"),
    (&["Ipe", "Tea", "Tui", "Cmd"], "TeaTuiCmd"),
    (&["Ipe", "Tea", "Tui", "Sub"], "TeaTuiSub"),
    (&["Ipe", "Tea", "Cli", "Cmd"], "TeaCliCmd"),
    (&["Ipe", "Tea", "Cli", "Sub"], "TeaCliSub"),
    (&["Ipe", "Tea", "Worker", "Cmd"], "TeaWorkerCmd"),
    (&["Ipe", "Tea", "Worker", "Sub"], "TeaWorkerSub"),
    // ── Effect stdlib modules ───────────────────────────────────────────────
    (&["Ipe", "Auth"], "Auth"),
    // `Ipe.Auth.Revocation` — per-session and per-subject revocation gate.
    // Requires `Principal` (enforces auth-on-auth); fail-closed on store error.
    (&["Ipe", "Auth", "Revocation"], "Revocation"),
    (&["Ipe", "Http", "Server", "Stream"], "Stream"),
    (&["Ipe", "Http", "Stream"], "HttpStream"),
    // Ipe.Http.Server.WebSocket (12 kernels).
    (&["Ipe", "Http", "Server", "WebSocket"], "Ws"),
    // ── Ipe.Server.* — the canonical-facing server namespace ─────────────────
    // Additional import paths onto the existing server canonicals (path→canonical
    // is many-to-one), so `import Ipe.Server.Http as Server` reaches the same
    // members as `import Ipe.Http.Server`. lower.rs is untouched: the canonical
    // qualifier symbols are unchanged.
    (&["Ipe", "Server"], "Server"),
    (&["Ipe", "Server", "Http"], "Server"),
    (&["Ipe", "Server", "Middleware"], "Middleware"),
    (&["Ipe", "Server", "RateLimit"], "RateLimit"),
    (&["Ipe", "Server", "Stream"], "Stream"),
    (&["Ipe", "Server", "WebSocket"], "Ws"),
];

/// The canonical qualifier text a stdlib import path is registered under.
///
/// The textual lookup behind [`Env::kernel_module`]: matches the
/// dotted path segments against [`STDLIB_MODULE_QUALIFIERS`], so a consumer
/// without an [`Env`] (a lint over the parse tree) derives the same qualifier
/// the resolver registers. `None` for a path naming no kernel-qualified module.
#[must_use]
pub fn stdlib_canonical_qualifier(path: &[&str]) -> Option<&'static str> {
    STDLIB_MODULE_QUALIFIERS
        .iter()
        .find(|(p, _)| p.len() == path.len() && p.iter().zip(path).all(|(a, b)| a == b))
        .map(|(_, canonical)| *canonical)
}

/// The dot-joined import paths of every kernel stdlib module (e.g. `Ipe.String`,
/// `Ipe.Json.Decode`), derived from [`STDLIB_MODULE_QUALIFIERS`] — the single
/// source of truth. Feeds the did-you-mean candidate set when an `Ipe.*` import
/// names no known kernel module. Builds strings directly off the `&'static str`
/// segments, so it never touches the interner.
#[must_use]
pub fn stdlib_module_dot_paths() -> Vec<Box<str>> {
    STDLIB_MODULE_QUALIFIERS
        .iter()
        .map(|(segments, _)| segments.join(".").into_boxed_str())
        .collect()
}

/// The importable-module catalog: every dotted module path a qualifier may name.
///
/// Kernel paths from [`STDLIB_MODULE_QUALIFIERS`] are always present; the
/// driver adds compiled-source stdlib paths and the project's own modules.
/// Text only, so building it never interns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModuleCatalog {
    modules: Rc<BTreeSet<Box<str>>>,
}

impl ModuleCatalog {
    /// The catalog of the kernel paths plus `extra` dotted module paths.
    #[must_use]
    pub fn new(extra: impl IntoIterator<Item = Box<str>>) -> Self {
        Self {
            modules: Rc::new(stdlib_module_dot_paths().into_iter().chain(extra).collect()),
        }
    }

    /// The dotted module paths, sorted.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.modules.iter().map(|m| &**m)
    }

    /// Every module other than `home` a bare `import` of which binds `qualifier`.
    ///
    /// The one candidate source for an unimported qualifier: every catalog
    /// entry is tested against [`bare_import_binds`], so two modules sharing a
    /// last segment (a kernel `Ipe.Tea.Tui` and a compiled `Ipe.Ui.Tui`) are
    /// both listed. Sorted and deduplicated (the catalog is a set).
    #[must_use]
    pub fn modules_bound_by(&self, qualifier: &str, home: &str) -> Box<[Box<str>]> {
        self.modules
            .iter()
            .filter(|module| &***module != home && bare_import_binds(module, qualifier))
            .cloned()
            .collect()
    }
}

/// `true` when a bare `import module` registers `qualifier`.
///
/// A kernel stdlib module (a [`STDLIB_MODULE_QUALIFIERS`] path) binds its
/// canonical qualifier, its exact dotted path when that path is a
/// [`DOTTED_QUALIFIER_SPELLINGS`] row, and its last segment when
/// [`kernel_import_binds_last_segment`] allows it. Any other module binds the
/// forms of `import_qualifier_forms(false, len)`: the last segment, plus the
/// dotted path when the path has more than one segment.
#[must_use]
pub fn bare_import_binds(module: &str, qualifier: &str) -> bool {
    let segments: Vec<&str> = module.split('.').collect();
    let last = segments.last().copied();
    if let Some(canonical) = stdlib_canonical_qualifier(&segments) {
        return qualifier == canonical
            || (module == qualifier && is_dotted_qualifier_spelling(&segments))
            || last.is_some_and(|last| {
                last == qualifier && kernel_import_binds_last_segment(last, canonical)
            });
    }
    import_qualifier_forms(false, segments.len())
        .iter()
        .any(|form| match form {
            QualifierForm::LastSegment => last == Some(qualifier),
            QualifierForm::DottedPath => module == qualifier,
            QualifierForm::Alias => false,
        })
}

/// `true` when a bare import of the kernel module with canonical qualifier
/// `canonical` also binds its last path segment `last`.
///
/// It does unless `last` is a DIFFERENT kernel module's canonical qualifier:
/// binding it would unlock that foreign module's import gate
/// (`import Ipe.Server.Http` must not unlock client `Http`).
#[must_use]
pub fn kernel_import_binds_last_segment(last: &str, canonical: &str) -> bool {
    last == canonical || !is_canonical_qualifier_text(last)
}

/// `true` when `name` is the canonical qualifier of some kernel stdlib module.
fn is_canonical_qualifier_text(name: &str) -> bool {
    STDLIB_MODULE_QUALIFIERS
        .iter()
        .any(|(_, canonical)| *canonical == name)
}

/// `true` when `name` is the canonical short qualifier of some stdlib module in
/// [`STDLIB_MODULE_QUALIFIERS`] (e.g. `Crypto`, `Sql`, `Db.Decode`).
///
/// Used to reject an `import Ipe.X as <Y>` whose alias `Y` names a DIFFERENT
/// stdlib module's canonical qualifier — which would otherwise merge unrelated
/// members into that qualifier's table. Internal re-export qualifiers such as
/// `Cmd` / `Sub` are absent from the table, so aliasing to them stays allowed.
#[must_use]
pub fn is_stdlib_canonical_qualifier(interner: &Interner, name: Symbol) -> bool {
    interner
        .resolve(name)
        .is_some_and(is_canonical_qualifier_text)
}

/// The reserved kernel-alias qualifier path. `import Ipe.Ffi.Kernel as Kernel`
/// brings the `Kernel.kernel "…"` alias surface into scope for a driver-vouched
/// stdlib / FFI-interface source. It is a compiler-internal qualifier, not a
/// member-bearing stdlib module, so it lives outside [`STDLIB_MODULE_QUALIFIERS`]
/// yet must be accepted at the import boundary.
const RESERVED_FFI_QUALIFIER_PATH: &[&str] = &["Ipe", "Ffi", "Kernel"];

/// The reserved native-binding qualifier path. `import Ipe.Ffi.Rust as Rust`
/// brings the `Rust.fn "<crate>" "<path>"` binding surface into scope for a
/// user source module. Like [`RESERVED_FFI_QUALIFIER_PATH`] it is a
/// compiler-internal qualifier, not a member-bearing stdlib module, so it lives
/// outside [`STDLIB_MODULE_QUALIFIERS`] yet must be accepted at the import
/// boundary. The `Rust.fn` calls it enables are recognised and rewritten by the
/// resolver (`ipe_canon::resolve::canonicalise_asserted_call`) onto the
/// driver-generated forwarder module, exactly as the legacy `Rust.Ffi.call`
/// spelling is.
const RESERVED_RUST_FFI_QUALIFIER_PATH: &[&str] = &["Ipe", "Ffi", "Rust"];

/// Whether `path` (segment symbols) names a known importable `Ipe.*` module that
/// needs no dep injection: a kernel stdlib module registered in
/// [`STDLIB_MODULE_QUALIFIERS`], the reserved `Ipe.Ffi.Kernel` kernel-alias
/// qualifier, or the reserved `Ipe.Ffi.Rust` native-binding qualifier. An
/// un-interned segment cannot match a known module, so it answers `false`.
/// Purely immutable — no interning.
#[must_use]
pub fn is_kernel_stdlib_module(path: &[Symbol], interner: &Interner) -> bool {
    let mut segments: Vec<&str> = Vec::with_capacity(path.len());
    for &symbol in path {
        match interner.resolve(symbol) {
            Some(segment) => segments.push(segment),
            None => return false,
        }
    }
    let matches = |candidate: &[&str]| {
        candidate.len() == segments.len() && candidate.iter().zip(&segments).all(|(a, b)| a == b)
    };
    matches(RESERVED_FFI_QUALIFIER_PATH)
        || matches(RESERVED_RUST_FFI_QUALIFIER_PATH)
        || STDLIB_MODULE_QUALIFIERS
            .iter()
            .any(|(candidate, _)| matches(candidate))
}

/// The exact dotted paths a bare kernel import is also reachable under.
///
/// A bare `import Ipe.Auth` installs `Ipe.Auth` as a qualifier beside `Auth`,
/// so `Ipe.Auth.hashPassword` resolves; `import Ipe.Auth as A` installs `A`
/// only. Each row is a [`STDLIB_MODULE_QUALIFIERS`] path (the `const` check
/// below), whose canonical is looked up there, so the two tables cannot drift.
/// An import installs only its own path, never a sibling path of the same
/// canonical.
pub const DOTTED_QUALIFIER_SPELLINGS: &[&[&str]] = &[
    &["Ipe", "Html", "Events"],
    &["Ipe", "Tea", "Web"],
    &["Ipe", "Tea", "Tui"],
    &["Ipe", "Tea", "Cli"],
    &["Ipe", "Tea", "Worker"],
    &["Ipe", "Auth"],
    &["Ipe", "Http", "Server", "Stream"],
    &["Ipe", "Http", "Stream"],
    &["Ipe", "Http", "Server", "WebSocket"],
    &["Ipe", "Server"],
    &["Ipe", "Server", "Http"],
    &["Ipe", "Server", "Middleware"],
    &["Ipe", "Server", "RateLimit"],
    &["Ipe", "Server", "Stream"],
    &["Ipe", "Server", "WebSocket"],
    &["Ipe", "Ui", "Input"],
    &["Ipe", "Ui", "Lazy"],
    &["Ipe", "Ui", "Keyed"],
];

/// `true` when a bare import of `path` also installs its exact dotted spelling.
#[must_use]
pub fn is_dotted_qualifier_spelling(path: &[&str]) -> bool {
    DOTTED_QUALIFIER_SPELLINGS
        .iter()
        .any(|row| row.len() == path.len() && row.iter().zip(path).all(|(a, b)| a == b))
}

/// The TEA app shapes, each the kernel module `Ipe.Tea.<Shape>`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TeaShape {
    /// `Ipe.Tea.Web`.
    Web,
    /// `Ipe.Tea.Tui`.
    Tui,
    /// `Ipe.Tea.Cli`.
    Cli,
    /// `Ipe.Tea.Worker`.
    Worker,
}

impl TeaShape {
    /// Every shape, once each.
    pub const ALL: [Self; 4] = [Self::Web, Self::Tui, Self::Cli, Self::Worker];

    /// The shape module's canonical qualifier, also its `Ipe.Tea.<segment>`.
    #[must_use]
    pub const fn canonical(self) -> &'static str {
        match self {
            Self::Web => "Web",
            Self::Tui => "Tui",
            Self::Cli => "Cli",
            Self::Worker => "Worker",
        }
    }

    /// The app surface this shape's entry builds.
    #[must_use]
    pub const fn surface(self) -> AppSurface {
        match self {
            Self::Web => AppSurface::Web,
            Self::Tui => AppSurface::Tui,
            Self::Cli => AppSurface::Cli,
            Self::Worker => AppSurface::Worker,
        }
    }

    /// The shape whose module has the canonical qualifier `canonical`.
    #[must_use]
    pub fn from_canonical(canonical: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.canonical() == canonical)
    }

    /// The canonical of this shape's own `Cmd` or `Sub` module.
    #[must_use]
    pub fn cmd_sub(self, family: CmdOrSub) -> Option<&'static str> {
        CMD_SUB_MODULES
            .iter()
            .find(|(segment, _, _)| *segment == self.canonical())
            .map(|&(_, cmd, sub)| family.pick(cmd, sub))
    }

    /// Whether a module importing this shape may reach `Ipe.Tea.<segment>.{Cmd,Sub}`.
    ///
    /// The shape's own row, plus the shared `Terminal` row for a terminal
    /// shape; [`AppSurface::admits_cmd_sub_of`] is the one rule.
    #[must_use]
    pub fn admits_cmd_sub_of(self, segment: &str) -> bool {
        self.surface().admits_cmd_sub_of(segment)
    }
}

/// One of the two shape-scoped effect families.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CmdOrSub {
    /// `Ipe.Tea.<Shape>.Cmd`.
    Cmd,
    /// `Ipe.Tea.<Shape>.Sub`.
    Sub,
}

impl CmdOrSub {
    /// Both families.
    pub const ALL: [Self; 2] = [Self::Cmd, Self::Sub];

    /// The qualifier a shape import installs this family under.
    #[must_use]
    pub const fn qualifier(self) -> &'static str {
        match self {
            Self::Cmd => "Cmd",
            Self::Sub => "Sub",
        }
    }

    /// `cmd` for [`Self::Cmd`], `sub` for [`Self::Sub`].
    #[must_use]
    pub const fn pick(self, cmd: &'static str, sub: &'static str) -> &'static str {
        match self {
            Self::Cmd => cmd,
            Self::Sub => sub,
        }
    }

    /// The family a qualifier spelling names, if it is `Cmd` or `Sub`.
    #[must_use]
    pub fn from_qualifier(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.qualifier() == text)
    }
}

/// Every `Ipe.Tea.<segment>.{Cmd,Sub}` module as `(segment, Cmd canonical, Sub canonical)`.
///
/// One row per shape plus the shared `Terminal` row. Each module re-exports the
/// whole canonical `Cmd` / `Sub` member set; which module a shape may import is
/// [`TeaShape::admits_cmd_sub_of`].
pub const CMD_SUB_MODULES: &[(&str, &str, &str)] = &[
    ("Web", "TeaWebCmd", "TeaWebSub"),
    ("Terminal", "TeaTerminalCmd", "TeaTerminalSub"),
    ("Tui", "TeaTuiCmd", "TeaTuiSub"),
    ("Cli", "TeaCliCmd", "TeaCliSub"),
    ("Worker", "TeaWorkerCmd", "TeaWorkerSub"),
];

/// The `(segment, family)` of a shape-scoped `Cmd` / `Sub` canonical.
#[must_use]
pub fn cmd_sub_module(canonical: &str) -> Option<(&'static str, CmdOrSub)> {
    CMD_SUB_MODULES.iter().find_map(|&(segment, cmd, sub)| {
        if cmd == canonical {
            Some((segment, CmdOrSub::Cmd))
        } else if sub == canonical {
            Some((segment, CmdOrSub::Sub))
        } else {
            None
        }
    })
}

/// `const`-context equality of two segment paths.
#[allow(clippy::indexing_slicing)] // every index is guarded by `i < a.len() == b.len()`
const fn const_path_eq(a: &[&str], b: &[&str]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if !const_str_eq(a[i], b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// `const`-context: `true` when `path` is a [`STDLIB_MODULE_QUALIFIERS`] path.
#[allow(clippy::indexing_slicing)] // the index is guarded by `i < len`
const fn is_stdlib_module_path(path: &[&str]) -> bool {
    let mut i = 0;
    while i < STDLIB_MODULE_QUALIFIERS.len() {
        if const_path_eq(STDLIB_MODULE_QUALIFIERS[i].0, path) {
            return true;
        }
        i += 1;
    }
    false
}

/// `const`-context: `true` when `name` is a [`STDLIB_MODULE_QUALIFIERS`] canonical.
#[allow(clippy::indexing_slicing)] // the index is guarded by `i < len`
const fn is_stdlib_canonical_const(name: &str) -> bool {
    let mut i = 0;
    while i < STDLIB_MODULE_QUALIFIERS.len() {
        if const_str_eq(STDLIB_MODULE_QUALIFIERS[i].1, name) {
            return true;
        }
        i += 1;
    }
    false
}

/// Every [`DOTTED_QUALIFIER_SPELLINGS`] row is a [`STDLIB_MODULE_QUALIFIERS`] path.
#[allow(clippy::indexing_slicing)] // every index is guarded by its `while` bound
const fn dotted_spellings_are_paths() -> bool {
    let mut i = 0;
    while i < DOTTED_QUALIFIER_SPELLINGS.len() {
        if !is_stdlib_module_path(DOTTED_QUALIFIER_SPELLINGS[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Every [`CMD_SUB_MODULES`] and [`TeaShape`] canonical is a
/// [`STDLIB_MODULE_QUALIFIERS`] canonical.
#[allow(clippy::indexing_slicing)] // every index is guarded by its `while` bound
const fn shape_canonicals_exist() -> bool {
    let mut j = 0;
    while j < CMD_SUB_MODULES.len() {
        let (_, cmd, sub) = CMD_SUB_MODULES[j];
        if !(is_stdlib_canonical_const(cmd) && is_stdlib_canonical_const(sub)) {
            return false;
        }
        j += 1;
    }
    let mut k = 0;
    while k < TeaShape::ALL.len() {
        if !is_stdlib_canonical_const(TeaShape::ALL[k].canonical()) {
            return false;
        }
        k += 1;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a dotted qualifier spelling drifts from the stdlib module table [ledger #boundary]
const _: () = assert!(
    dotted_spellings_are_paths(),
    "DOTTED_QUALIFIER_SPELLINGS lists a path that is not a STDLIB_MODULE_QUALIFIERS path",
);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a TEA shape or `Cmd`/`Sub` module names a canonical absent from the stdlib module table [ledger #boundary]
const _: () = assert!(
    shape_canonicals_exist(),
    "a CMD_SUB_MODULES or TeaShape canonical is absent from STDLIB_MODULE_QUALIFIERS",
);

/// A kernel stdlib module, named by its canonical qualifier.
///
/// Only this module constructs one, from a [`STDLIB_MODULE_QUALIFIERS`]
/// canonical that carries members in [`Env::kernel_members`], so holding one
/// proves the module exists.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct KernelModule(Symbol);

impl KernelModule {
    /// The canonical qualifier symbol (`Auth`, `JsonDec`, `Db.Decode`).
    #[must_use]
    pub const fn symbol(self) -> Symbol {
        self.0
    }
}

impl std::borrow::Borrow<Symbol> for KernelModule {
    fn borrow(&self) -> &Symbol {
        &self.0
    }
}

/// The module a qualifier spelling resolves into.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ModuleIdentity {
    /// A kernel stdlib module.
    Kernel(KernelModule),
    /// A user or compiled-source module, by its path.
    Source(Vec<Symbol>),
}

/// How an import spells a qualifier it installs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimForm {
    /// An explicit `as Alias`.
    Alias,
    /// The module's own name: a kernel canonical, an exact dotted path, or the
    /// `Cmd` / `Sub` a shape import brings.
    Path,
    /// A bare import's last-segment shorthand.
    LastSegment,
}

/// One import's claim on a qualifier spelling.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct QualifierClaim {
    /// The qualifier spelling.
    pub spelling: Symbol,
    /// The module the spelling resolves into.
    pub owner: ModuleIdentity,
    /// How the import spelled it.
    pub form: ClaimForm,
    /// The import's span.
    pub span: Span,
}

/// Two imports' claims on one spelling where neither outranks the other.
///
/// The spelling holds no members; a use of it is refused naming both imports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AmbiguousQualifier {
    /// The import earlier in the source.
    pub first: Span,
    /// The import later in the source.
    pub second: Span,
}

/// The import-installed qualifier scope of one module.
///
/// Written only by [`Env::install_import`] and [`Env::set_cmd_sub_shape`].
#[derive(Clone, Debug, Default)]
pub struct ImportScope {
    /// Every module this module imported.
    pub imported_modules: BTreeSet<ModuleIdentity>,
    /// The claim that owns each installed spelling.
    pub qualifier_owner: BTreeMap<Symbol, QualifierClaim>,
    /// Spellings two claims share with neither outranking the other.
    pub ambiguous: BTreeMap<Symbol, AmbiguousQualifier>,
    /// The TEA shape this module imports, with its import span.
    pub cmd_sub_shape: Option<(TeaShape, Span)>,
}

/// Why a qualifier holds no members in this module.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AbsentQualifier {
    /// Two imports claim the spelling; see [`AmbiguousQualifier`].
    Ambiguous(AmbiguousQualifier),
    /// The canonical of a kernel module this module did not import, with the
    /// module's import path.
    KnownStdlib(Vec<Symbol>),
    /// `Cmd` / `Sub` with no shape import and no `Ipe.Tea.<Shape>.{Cmd,Sub}` import.
    InternalCmdSub(CmdOrSub),
    /// No kernel module is gated under the spelling.
    Unknown,
}

/// How a new claim on an installed spelling relates to the claim already there.
enum ClaimVerdict {
    /// The same module (or the same `Cmd` / `Sub` family): merge.
    Same,
    /// The new claim outranks the installed one: replace it.
    Replace,
    /// The installed claim outranks the new one: drop the new one.
    Keep,
    /// Neither outranks the other and both are explicit: refuse now.
    Refuse,
    /// Neither outranks the other and at least one is a shorthand: refuse at use.
    Ambiguous,
}

/// Decide how `new` relates to `installed` on one spelling.
///
/// `shape` is the TEA shape the module imports, if any.
fn claim_verdict(
    installed: &QualifierClaim,
    new: &QualifierClaim,
    shape: Option<TeaShape>,
    interner: &Interner,
) -> ClaimVerdict {
    if installed.owner == new.owner
        || same_cmd_sub_family(&installed.owner, &new.owner, shape, interner)
    {
        return ClaimVerdict::Same;
    }
    match (installed.form, new.form) {
        (ClaimForm::Alias | ClaimForm::Path, ClaimForm::Alias | ClaimForm::Path) => {
            ClaimVerdict::Refuse
        }
        (ClaimForm::Alias, ClaimForm::LastSegment) => ClaimVerdict::Keep,
        (ClaimForm::LastSegment, ClaimForm::Alias) => ClaimVerdict::Replace,
        (ClaimForm::Path | ClaimForm::LastSegment, ClaimForm::LastSegment)
        | (ClaimForm::LastSegment, ClaimForm::Path) => ClaimVerdict::Ambiguous,
    }
}

/// `true` when both owners are `Cmd` / `Sub` modules of one family that the
/// imported `shape` admits.
///
/// The modules a shape admits are one effect surface (its own row plus the
/// shared `Terminal` row), so two of them under one spelling denote that
/// surface. With no shape import nothing admits two different modules: each
/// shape owns members the others lack (`Ipe.Tea.Tui.Sub.onKey`), so they are
/// different modules and the spelling is decided like any other.
fn same_cmd_sub_family(
    a: &ModuleIdentity,
    b: &ModuleIdentity,
    shape: Option<TeaShape>,
    interner: &Interner,
) -> bool {
    let Some(shape) = shape else {
        return false;
    };
    let admitted = |owner: &ModuleIdentity| match owner {
        ModuleIdentity::Kernel(module) => interner
            .resolve(module.symbol())
            .and_then(cmd_sub_module)
            .filter(|&(segment, _)| shape.admits_cmd_sub_of(segment))
            .map(|(_, family)| family),
        ModuleIdentity::Source(_) => None,
    };
    admitted(a).is_some_and(|fa| admitted(b) == Some(fa))
}

/// The members one import installs under one spelling.
pub type InstalledMembers = (BTreeMap<Symbol, VarHome>, BTreeMap<Symbol, CtorHome>);

/// Where a (possibly qualified) variable resolves to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VarHome {
    /// A locally-bound name.
    Local,
    /// A top-level binding of the named module.
    TopLevel(Vec<Symbol>),
    /// A stdlib kernel function that is backed by a concrete [`StdlibKernel`]
    /// registry entry.
    ///
    /// A reachable qualifier member can only be registered as this variant by
    /// carrying its backing kernel, so "a reachable member with no backing
    /// kernel" is not a representable state: reachability implies a backing
    /// kernel by construction. `module` and `name` are the canonical symbols
    /// used for diagnostics and the type-constraint scheme lookup.
    Kernel(StdlibKernel, Symbol, Symbol),
    /// A stdlib qualifier member that is reachable (users may name it) but has
    /// no backing [`StdlibKernel`] yet — the explicit reserved category.
    ///
    /// A reference resolves through name resolution (so it never surfaces the
    /// "unknown member" diagnostic), then fails closed at type-check with
    /// IPE-L0108 (`kernel function not available yet`) because it carries no
    /// registry id. This variant is the sole, named home for a
    /// deliberately-unbacked-yet-reachable member; there is no `None` hiding
    /// inside [`Self::Kernel`].
    ReservedKernel { module: Symbol, name: Symbol },
}

/// Resolve a qualifier member's `(module, name)` to its [`VarHome`], choosing
/// the variant by whether a backing [`StdlibKernel`] exists in `index`.
///
/// A hit yields [`VarHome::Kernel`] carrying the concrete kernel; a miss yields
/// [`VarHome::ReservedKernel`] — the explicit reserved category for a reachable
/// member with no backing kernel. This is the single construction point that
/// makes "reachable ⇒ backed" hold by construction: a member can never be
/// registered as a backed `Kernel` without an actual registry entry.
fn kernel_home(
    index: &BTreeMap<(Symbol, Symbol), StdlibKernel>,
    module: Symbol,
    name: Symbol,
) -> VarHome {
    match index.get(&(module, name)) {
        Some(&k) => VarHome::Kernel(k, module, name),
        None => VarHome::ReservedKernel { module, name },
    }
}

/// Where a constructor resolves to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CtorHome {
    pub home: Vec<Symbol>,
    pub type_name: Symbol,
    pub name: Symbol,
    pub index: usize,
    pub arity: usize,
}

/// The defining identity of a constructor brought in by an open import: its
/// type's home and name.
///
/// Two open imports reaching the same constructor through different modules
/// (a module imported twice, or a re-export) share one identity and so one
/// origin; two distinct declarations of the same spelling stay two origins.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CtorIdentity {
    pub home: Vec<Symbol>,
    pub type_name: Symbol,
}

/// The name-resolution environment.
#[derive(Clone, Debug, Default)]
pub struct Env {
    /// The module being canonicalised.
    pub home: Vec<Symbol>,
    /// The lexical binders in scope (function parameters, `let` and `case`
    /// bindings), each [`VarHome::Local`].
    ///
    /// The one genuinely scope-local table: it stays owned so a per-scope
    /// `env.clone()` copies only the current binders. Every other table below
    /// is set up once and sits behind an `Rc`, so the per-scope clone is a
    /// refcount bump. A lexical binder shadows every module-level name.
    pub vars: BTreeMap<Symbol, VarHome>,
    /// Every bare module-level name, in its two namespaces, each bound and read
    /// through the one ladder in [`crate::scope`].
    ///
    /// Written only during module setup, through `Rc::make_mut`.
    pub module_scope: Rc<ModuleScope>,
    /// Qualified variable bindings: qualifier spelling → (name → home).
    ///
    /// Empty in a fresh environment; written only by [`Self::install_import`],
    /// so a spelling holds members only when an import of this module
    /// installed it.
    pub qual_vars: Rc<BTreeMap<Symbol, BTreeMap<Symbol, VarHome>>>,
    /// Qualified constructor bindings: qualifier spelling → (`ctor_name` → home).
    ///
    /// Written only by [`Self::install_import`] beside [`Self::qual_vars`]:
    /// a compiled-source ADT's constructors (`Money.USD`) and a kernel module's
    /// built-in union constructors (`Http.Post`).
    pub qual_ctors: Rc<BTreeMap<Symbol, BTreeMap<Symbol, CtorHome>>>,
    /// The kernel member pool: every kernel module's members, by module.
    ///
    /// Filled once by [`Env::initial`]. Qualified resolution never reads it; an
    /// import copies a module's members out of it into [`Self::qual_vars`].
    pub kernel_members: Rc<BTreeMap<KernelModule, BTreeMap<Symbol, VarHome>>>,
    /// The kernel constructor pool, the constructor half of [`Self::kernel_members`].
    pub kernel_ctors: Rc<BTreeMap<KernelModule, BTreeMap<Symbol, CtorHome>>>,
    /// What this module's imports installed: the modules, the owner of each
    /// spelling, the ambiguous spellings, and the TEA shape.
    pub import_scope: Rc<ImportScope>,
    /// **Parse-once registry index.**  Maps `(qualifier_sym, name_sym)`
    /// to the typed [`StdlibKernel`] variant, built anti-drift from
    /// [`StdlibKernel::ALL`] in `install_prelude_qualifiers`.
    ///
    /// Threaded through `VarHome::Kernel`, and exposed here so the
    /// `canon_equals_registry` tripwire test can validate parity with
    /// `kernel_members` without touching any downstream path.
    pub stdlib_index: Rc<BTreeMap<(Symbol, Symbol), StdlibKernel>>,
    /// The import path of every gated kernel canonical.
    ///
    /// Every canonical stdlib qualifier that carries members in
    /// [`Self::kernel_members`], minus the Tier-A `Basics`, mapped to the
    /// primary `Ipe.*` path a diagnostic tells the user to import. A use of
    /// one with no installing import is IPE-N0034.
    ///
    /// `Rc` so the per-scope `env.clone()` is a refcount bump, not a deep copy.
    pub gated_stdlib_quals: Rc<BTreeMap<Symbol, Vec<Symbol>>>,
    /// Every module this module could import, for the unbound-qualifier verdict.
    pub module_catalog: ModuleCatalog,
    /// Each module this module imports under an `as` alias (dotted path), with
    /// those aliases: an unbound qualifier spelling such a module's own name is
    /// pointed at its alias, never told to import a module already imported.
    pub import_aliases: Rc<BTreeMap<Box<str>, BTreeSet<Box<str>>>>,
    /// The module's driver-vouched trust provenance. `Ffi.binding` bodies
    /// resolve ONLY under [`ModuleOrigin::FfiInterface`]; any other origin
    /// falls through to ordinary qualified-name resolution (and fails there —
    /// `Ffi` is not an importable module).
    pub origin: ModuleOrigin,
    /// The context the `Ipe.Codec.auto` derive reads at a call site: the record
    /// shape of every annotated top-level value, plus the qualifier symbols that
    /// name the imported `Ipe.Codec` module. Both are computed once per module and
    /// carried on the env, which every value body's resolution already clones.
    /// `Rc` so the per-scope `env.clone()` is a refcount bump, not a deep copy.
    pub codec_auto: Rc<CodecAutoContext>,
}

/// Per-module context for the `Ipe.Codec.auto` derive.
///
/// `auto` is recognised at its call site (`<Codec>.auto witness`) and rewritten
/// into the field-by-field codec a hand-written record codec would build. To do
/// that it needs two facts computed where the module's values, aliases, and
/// imports are all in view: which qualifiers name the `Ipe.Codec` module, and
/// the record shape of each witness value.
#[derive(Debug, Default)]
pub struct CodecAutoContext {
    /// Qualifier symbols bound to the imported `Ipe.Codec` module (its default
    /// last-segment name and every `as` alias). A `<qual>.auto` call is a derive
    /// only when `qual` is in this set — so an unrelated `Other.auto` is left to
    /// ordinary resolution. Empty when the module does not import `Ipe.Codec`.
    pub qualifiers: BTreeSet<Symbol>,
    /// Record shape of every top-level value annotated with a record type, keyed
    /// by the value name: the fields (name + canonical type) in declared order.
    /// The witness a derive is applied to is looked up here. Empty for a module
    /// that declares no such value.
    pub witness_records: BTreeMap<Symbol, Vec<(Symbol, crate::ast::Type)>>,
}

/// Prelude kernel qualifier table — the `(qualifier, &[member])` surface
/// registered by [`Env::install_prelude_qualifiers`]. Hoisted to module
/// level so the compile-time drift gate (the `const _` block just below) can
/// check it against the kernel registry without running the installer.
#[rustfmt::skip]
pub const PRELUDE_QUALIFIERS: &[(&str, &[&str])] = &[
        // `Ipe.Error` — the real `Error ErrorKind ErrorInfo` ADT.
        // Message constructors + nullary constructors + `toString`
        // render + `withMessage` modifier + `isRetryable` classification +
        // `withDetails` modifier (attaches the
        // `ErrorDetails` union to `ErrorInfo.details : Maybe ErrorDetails`).
        // `Ipe.CssSafety` — the Ipe.Css leaf security kernels: four
        // `String -> Maybe String` parsers (`safeValue`/`safePropName`/
        // `safeSelector` gate declarations/selectors at construction;
        // `sanitizeRawBody` is the authoritative raw/keyframes-body gate over
        // the audited `css_safety` policy) + the `String -> String`
        // `<style>`-breakout floor. Imported (and called unqualified) by the
        // compiled-source `Ipe.Css`.
        (
            "CssSafety",
            &[
                "safeValue",
                "safePropName",
                "safeSelector",
                "sanitizeRawBody",
                "stripStyleClose",
            ],
        ),
        // `Ipe.Log` — qualified form (`import Ipe.Log as Log`).
        // `info`/`debug`/`warn`/`error` are backed; the `*With`
        // variants take Stringify-bounded attrs and stay fail-closed
        // (IPE-L0108) until the Stringify obligation is added.
        // `Log` is observability-only — line printing lives in `Ipe.Io`
        // (`Io.println` / `Io.eprintln`).
        // `Ipe.App` — runtime-config front door. `fromEnv` seals an env var
        // into a `Secret` (the ONLY way to get a config secret);
        // `fromEnvRequired` is its fail-closed variant (a missing/empty var
        // is a named load-time `ConfigError`, not an empty secret).
        ("App", &["fromEnv", "fromEnvRequired"]),
        // `Ipe.Console` — the console/telemetry `Secret`-typed token settings.
        // Each takes a `Secret` (from `App.fromEnvRequired`), so a hard-coded
        // token `String` does not type-check.
        ("Console", &["adminToken", "ingestToken", "metricsToken"]),
        // `Ipe.Host` — the host-bind setting builder plus the `HostMode`
        // constructors it takes.
        ("Host", &["bind", "loopback", "allInterfaces", "envDriven"]),
        // `Ipe.Level` — the `LogLevel` constructors `Log.level` takes. A
        // separate qualifier from `Log` because `Log.debug`/`Log.info`/… are
        // already the logging kernels; `Level.debug`/… are the severity tags.
        // `Ipe.Json.Encode` — JSON encoder.
        (
            "JsonEnc",
            &[
                "string", "int", "float", "bool", "null", "list", "object", "encode",
            ],
        ),
        // `Ipe.Json.Decode` — JSON decoder combinators.
        (
            "JsonDec",
            &[
                "string",
                "int",
                "float",
                "bool",
                "value",
                "decodeString",
                "decodeValue",
                "field",
                "at",
                "index",
                "list",
                "nullable",
                "map",
                "andThen",
                "succeed",
                "fail",
                "oneOf",
                "map2",
                "map3",
                "map4",
            ],
        ),
        // `Ipe.Json.Decode.Pipeline` — pipeline-style record decoders.
        (
            "JsonDecP",
            &["required", "optional", "custom", "requiredAt"],
        ),
        // `Ipe.Crypto` — hashes / HMAC / RSA / AEAD / key-derivation / random.
        // String-typed surface (backward-compat) + typed-key variants (§6.11).
        (
            "Crypto",
            &[
                "sha256",
                "sha512",
                "sha1",
                "md5",
                "rsaSha256Sign",
                "rsaSha256Verify",
                "constantTimeEqual",
                "aesGcmEncrypt",
                "aesGcmDecrypt",
                "chacha20Encrypt",
                "chacha20Decrypt",
                "aesKeyFromPassword",
                "chachaKeyFromPassword",
                "randomBytes",
                "randomToken",
                // Typed HMAC kernels; the AEAD/key-derivation entry points
                // above already require/return the typed `Key`, so there is
                // no separate bare-`String`-key spelling to register.
                "hmacSha256WithKey",
                "hmacSha512WithKey",
            ],
        ),
        // `Ipe.Secret` — opaque secret-string wrapper.
        // `fromString` is the seal; `use` is the scoped consume (apply a
        // function to the plaintext, return its result); `redacted` is the
        // explicit "<redacted>" accessor. The blunt raw un-parse `reveal`
        // relocated to the compiled-source `Ipe.Secret.Unsafe` submodule
        // (`src/stdlib/Ipe/Secret/Unsafe.ipe`) as `unsafeReveal`, reached
        // through the `Kernel.kernel "Secret_reveal"` alias to the SAME kernel —
        // so it is absent here and no longer resolves off a plain
        // `import Ipe.Secret`.
        ("Secret", &["fromString", "use", "redacted"]),
        // `Ipe.Jwt` — JWT encode/decode for HS256 and RS256,
        // plus builder API: claims / hs256 / rs256 / subject / issuer /
        // audience / expiresAt / notBefore / issuedAt / jwtId / withClaim /
        // encode / decode.
        (
            "Jwt",
            &[
                "encodeHs256",
                "decodeHs256",
                "encodeRs256",
                "decodeRs256",
                // builder API
                "claims",
                "hs256",
                "rs256",
                "subject",
                "issuer",
                "audience",
                "expiresAt",
                "notBefore",
                "issuedAt",
                "jwtId",
                "withClaim",
                "encode",
                "decode",
            ],
        ),
        // `Ipe.System` — system effects.
        (
            "System",
            &[
                "args",
                "getenv",
                "getenvOr",
                "getArg",
                "getenvInt",
                "getenvBool",
                "setenv",
                "unsetenv",
                "cwd",
                "getcwd",
                "loadEnv",
                "exit",
            ],
        ),
        // `Ipe.Random` is DELIBERATELY absent: it is COMPILED-SOURCE
        // (`ipe::stdlib::COMPILED_STD_MODULES`), so its whole surface resolves
        // from `Ipe/Random.ipe` — the `Kernel.kernel "Random_*"` aliases and the
        // pure Ipê wrappers — not from this kernel-qualifier catalog.
        // `Ipe.File` is DELIBERATELY absent: it is COMPILED-SOURCE
        // (`ipe::stdlib::COMPILED_STD_MODULES`), so its whole surface resolves
        // from `Ipe/File.ipe` — the `Kernel.kernel "File_*"` aliases and the
        // `ByteSize`-typed `readFileLimit` wrapper.
        // `Ipe.Process` — subprocess execution with NO shell.
        // `run` : `String -> List String -> Task Error String`.
        // `runWith` : `{ command, args, cwd, env } -> Task Error { exitCode, stdout, stderr }`.
        // `runInPty` : `{ command, args, cwd, env, cols, rows } -> Task Error { exitCode, output }`.
        // All are server-only (`subprocess` capability), default-denied under wasm.
        ("Process", &["run", "runWith", "runInPty"]),
        // `Ipe.Http` — outbound HTTP client.
        // `get` / `post` / `request` are effect kernels (Task Error
        // HttpResponse); `parseQuery` is a pure kernel (String -> Result
        // Error (Dict String String)); the `with*` builders + `defaultRequest` are ALSO
        // pure kernels (HttpRequest record-update emission in the backend) —
        // cross-module pure-Ipê stdlib calls are not resolved by ipe, so the
        // builders cannot live as pure Ipê in Http.ipe. Every name below is
        // registered so `Http.foo` resolves during name-resolution and lands
        // as `Callee::Kernel` (see lower.rs ("Http", _) arms + constrain.rs
        // kernel_ty Http entries that give each its record type).
        (
            "Http",
            &[
                "get",
                "post",
                "request",
                "defaultRequest",
                "defaultRequestFromString",
                "withMethod",
                "withHeader",
                "withTimeout",
                "withBody",
                "withUrl",
                "withRedirects",
                "parseQuery",
                "methodToString",
                "methodFromString",
            ],
        ),
        // ── TEA Cmd / Sub kernels ───────────────────────────────────────────
        // `Cmd.publish` / `Cmd.publishNoEcho` are backed by runtime
        // `cmd_publish` / `cmd_publish_no_echo` in live/pubsub.rs.
        // `Sub.subscribeTopic` is backed by runtime `sub_subscribe_topic`
        // in live/pubsub.rs; emit path uses the standard N-arg route.
        (
            "Cmd",
            &[
                "none",
                "batch",
                "perform",
                "map",
                "publish",
                "publishNoEcho",
            ],
        ),
        (
            "Sub",
            &[
                "none",
                "batch",
                "every",
                "map",
                "subscribeTopic",
                "subscribeWebSocket",
            ],
        ),
        // `Ipe.PubSub` (the top-level, Task-shaped publish surface) is a
        // COMPILED-SOURCE stdlib module (`src/stdlib/Ipe/PubSub.ipe`), so it
        // stays OUT of this kernel-qualifier table (kernel qualifier here OR
        // compiled-source — never both). Its `publish` / `publishNoEcho` bodies
        // are `Kernel.kernel "PubSub_publish"` / `"PubSub_publishNoEcho"`; the
        // alias fast-path (`detect_kernel_alias`) splits `"PubSub_publish"` →
        // the canonical `("PubSub", "publish")` kernel (`class = Web`,
        // Task-shaped — NOT TEA-loop machinery).
        // ── Db kernels ──────────────────────────────────────────────────────
        // `Ipe.Db` — the SAFE database connection + query surface. The
        // raw-SQL and untyped-column-read escape hatches (`unsafeExecRaw`,
        // `unsafeQuery`, `unsafeGet*`) live in the compiled-source
        // `Ipe.Db.Unsafe` submodule (`src/stdlib/Ipe/Db/Unsafe.ipe`), reached
        // through `Kernel.kernel "Db_*"` aliases to the SAME kernels — so they
        // are absent here and no longer resolve off a plain `import Ipe.Db`.
        // `SqlValue` / `SqlField` ADT constructors are handled by
        // `install_builtin_ctors` above; they are unqualified.
        (
            "Db",
            &[
                "connect",
                "open",
                "close",
                "exec",
                "queryDecode",
                "insertRow",
                "getById",
                "updateById",
                "deleteById",
                "findOneByField",
                "findManyByField",
                "findByConditions",
                "findWhere",
                "findWhereMasked",
                "findJoin",
                "findProjection",
                "findJoinOrdered",
                "findProjectionOrdered",
                "deleteWhere",
                "updateWhere",
                // External read path — `…On` reads over a `Connection a`.
                "findWhereOn",
                "queryDecodeOn",
                "getByIdOn",
                "insertFields",
                "updateFields",
                "upsertFields",
                "insertFieldsReturning",
                "withTransaction",
                "migrate",
                "defaultMigration",
                // Runtime-config front door — `Db.url : Secret -> Setting a`.
                "url",
            ],
        ),
        // `Ipe.Db.Sql` — typed, parameterized WHERE-fragment builder.
        // A `SqlFragment` can only be built through
        // these combinators, so a naive string-concatenated WHERE clause
        // is a type error (`String` where `SqlFragment` is expected) at
        // `Db.findWhere` / `Db.deleteWhere`, not a runtime injection risk.
        (
            "Sql",
            &[
                "column",
                "maskedColumn",
                "param",
                "int",
                "string",
                "float",
                "bool",
                "eq",
                "ne",
                "gt",
                "lt",
                "gte",
                "lte",
                "and",
                "or",
                "not",
                "isNull",
                "isNotNull",
                "inList",
                "like",
                "startsWith",
                "exists",
            ],
        ),
        // `Ipe.Db.Decode` — row decoder combinators.
        // The qualifier string contains a dot ("Db.Decode") which the parser
        // produces correctly for the 3-segment path `Db.Decode.string` — see
        // ipe_parse::parser::ident_expr (qualifier = init.join(".")).
        (
            "Db.Decode",
            &[
                "string", "int", "float", "bool", "bytes", "money", "decimal", "nullable",
                "map", "andThen", "succeed", "fail", "map2", "map3", "map4", "required",
                "optional",
            ],
        ),
        // Ipe.Http.Server kernels.
        (
            "Server",
            &[
                "get",
                "post",
                "put",
                "delete",
                "any",
                "api",
                "static",
                "mountApp",
                "listen",
                "text",
                "json",
                "html",
                "withStatus",
                "withHeader",
                "redirect",
                "param",
                "queryParam",
                "header",
                "getCookie",
                "body",
                "path",
                "method",
                "cookie",
                "withCookie",
                "authConfig",
                "bearerToken",
                "cookieToken",
                "withRevocation",
                "getAuthed",
                "postAuthed",
                "putAuthed",
                "deleteAuthed",
            ],
        ),
        // Ipe.Http.Middleware kernels.
        (
            "Middleware",
            &[
                "withCors",
                "withLogging",
                "withBasicAuth",
                "withRateLimit",
                "withCsrf",
            ],
        ),
        // Ipe.Http.RateLimit kernels.
        ("RateLimit", &["allow"]),
        // `Ipe.Ui` is COMPILED-SOURCE (see `COMPILED_STD_MODULES`), not a
        // kernel qualifier: the layout builders (`el`/`row`/`column`/
        // `wrappedRow`/`grid`/`paragraph`/`textColumn`/`form`/`input`) are
        // pure Ipê over the retained `node`/`taggedNode` primitives, and every
        // other member is a `Kernel.kernel "Ui_*"` alias resolving to its
        // unchanged kernel. The `Ipe.Ui.*` sub-qualifiers (Background/Border/
        // Font/Region/Input/Lazy/Keyed) stay native below. The disjointness
        // invariant forbids `Ui` here.
        // ── Ipe.Ui.Background sub-module ─────────────────────────────────────
        (
            "Background",
            &[
                "color",
                "image",
                "hoverColor",
                "focusColor",
                "activeColor",
                "disabledColor",
                "linearGradient",
            ],
        ),
        // ── Ipe.Ui.Border sub-module ─────────────────────────────────────────
        (
            "Border",
            &[
                "width",
                "widthEach",
                "color",
                "rounded",
                "solid",
                "dashed",
                "dotted",
                "shadow",
                "glow",
                "innerShadow",
                "hoverColor",
                "focusColor",
                "activeColor",
                "hoverWidth",
                "hoverRounded",
            ],
        ),
        // ── Ipe.Ui.Font sub-module ───────────────────────────────────────────
        (
            "Font",
            &[
                "color",
                "family",
                "size",
                "weight",
                "bold",
                "semiBold",
                "regular",
                "light",
                "extraBold",
                "black",
                "italic",
                "underline",
                "lineThrough",
                "noDecoration",
                "letterSpacing",
                "wordSpacing",
                "alignLeft",
                "alignRight",
                "alignCenter",
                "center",
                "justify",
                "sansSerif",
                "serif",
                "monospace",
                "hoverColor",
                "focusColor",
                "activeColor",
                "disabledColor",
                "hoverSize",
            ],
        ),
        // ── Ipe.Ui.Region sub-module ─────────────────────────────────────────
        (
            "Region",
            &[
                "mainContent",
                "navigation",
                "footer",
                "aside",
                "heading",
                "label",
                "announce",
                "announceUrgently",
            ],
        ),
        // ── Ipe.Ui.Input sub-module ──────────────────────────────────────────
        (
            "Input",
            &[
                "labelAbove",
                "labelBelow",
                "labelLeft",
                "labelRight",
                "labelHidden",
                "placeholder",
                "text",
                "multiline",
                "email",
                "username",
                "search",
                "currentPassword",
                "newPassword",
                "checkbox",
                "slider",
                "option",
                "radio",
                "radioRow",
            ],
        ),
        // ── Ipe.Ui.Lazy sub-module ───────────────────────────────────────────
        ("Lazy", &["lazy", "lazy2", "lazy3", "lazy4", "lazy5"]),
        // ── Ipe.Ui.Keyed — ipe-key for diff identity ─────────────────────────
        ("Keyed", &["column", "row"]),
        // `Ipe.Html` and `Ipe.Html.Attributes` are compiled-source (see exclusion
        // table in `STDLIB_MODULE_QUALIFIERS`); `Ipe.Html.Events` is a kernel qualifier.
        // ── Ipe.Html.Events alias ─────────────────────────────────────────────
        (
            "Event",
            &[
                "onClick",
                "onInput",
                "onChange",
                "onSubmit",
                "onFocus",
                "onBlur",
                "onMouseOver",
                "onMouseOut",
                "onKeyDown",
                "onKeyUp",
                "onBool",
                "onMsg",
            ],
        ),
        // ── Ipe.Web app-entry kernels ────────────────────────────────────────
        (
            "Web",
            &[
                "tea",
                "appRouted",
                "embed",
                "appWith",
                "route",
                "csrf",
                "sessionTtl",
                "authMaxLifetime",
                "authSlideWindow",
                "withRevocation",
                // `CsrfMode` constructors `Web.csrf` takes. No disabling
                // variant — a setting cannot turn CSRF off.
                "strict",
                "inheritCsrf",
                // `RevocationMode` constructors `Web.withRevocation` takes.
                "revocationOff",
                "revocationStore",
            ],
        ),
        // ── Ipe.Tui / Ipe.Cli app-entry kernels ──────────────────────────────
        // `Tui.tea` (full screen, key input) and `Cli.tea` (line stream, line
        // input) — one terminal rendering family, two drive axes. Both
        // carry `KernelClass::Terminal` internally.
        ("Tui", &["tea"]),
        ("Cli", &["tea"]),
        // Shape-owned input subscriptions. Registered under the shape-scoped
        // `Sub` qualifiers only (never the canonical `Sub`), so `onKey` is
        // nameable solely through `Ipe.Tea.Tui.Sub` and `onLine` solely through
        // `Ipe.Tea.Cli.Sub`; the rest of each qualifier's members are the
        // canonical `Sub` set cloned in by `CMD_SUB_MODULES`.
        ("TeaTuiSub", &["onKey"]),
        ("TeaCliSub", &["onLine"]),
        // `Ipe.Tea.Worker.tea` — view-less co-located worker app-entry
        // (`{ init, update, subscriptions } -> Program Worker msg`). No render.
        ("Worker", &["tea"]),
        // Ipe.Auth / Ipe.Auth — authentication helpers (fail-closed: no lower
        // arm yet → IPE-L0108 at lower time; canon registration removes N0004).
        (
            "Auth",
            &[
                "hashPassword",
                "hashPasswordCost",
                "verifyPassword",
                "passwordStrength",
                "signToken",
                "verifyToken",
                "register",
                "login",
                "setRole",
                "subject",
                "claim",
                "hasRole",
                "memberOf",
            ],
        ),
        // Ipe.Auth.Revocation — per-session and per-subject revocation gate.
        // Requires `Principal` (enforces auth-on-auth); fail-closed on store error.
        (
            "Revocation",
            &["revokeUser", "revokeSession", "restoreUser", "isRevoked"],
        ),
        // Ipe.Http.Server.Stream — server-side streaming HTTP (fail-closed).
        ("Stream", &["stream", "emit", "finish", "withContentType"]),
        // Ipe.Http.Stream — client-side HTTP streaming (fail-closed).
        ("HttpStream", &["open", "forEachChunk", "close", "chunks"]),
        // Ipe.Decimal — DELIBERATELY absent: migrated to compiled-source
        // `Ipe/Decimal.ipe` (COMPILED_STD_MODULES). Every member reaches its
        // kernel via `Kernel.kernel "Decimal_*"`, so this catalog block is no
        // longer needed here.
        //
        // Ipe.Http.Server.WebSocket (12 kernels).
        (
            "Ws",
            &[
                "defaultCfg",
                "withOnConnect",
                "withOnMessage",
                "withOnClose",
                "withOnError",
                "withMaxMessageBytes",
                "withOriginPatterns",
                "upgrade",
                "sendToClient",
                "sendBinaryToClient",
                "broadcast",
                "closeClient",
            ],
        ),
    ];

/// Surface members that appear in [`PRELUDE_QUALIFIERS`] under a qualifier that
/// backs no [`StdlibKernel`] of the *same* member name, because they are
/// in-table aliases resolved to a different canonical kernel name at
/// registration time (see `install_prelude_qualifiers`). They are still backed
/// kernels — just under another name — so the drift gate exempts them.
///
/// `("Event", "onMsg")` is the generic alias for the `Event.onClick` kernel
/// (`onMsg foo == onClick foo`); its canonical name is rewritten to `onClick`
/// before the `stdlib_index` lookup, so no `StdlibKernel::decl()` carries the
/// literal `("Event", "onMsg")` pair.
const PRELUDE_QUALIFIER_ALIASES: &[(&str, &str)] = &[("Event", "onMsg")];

/// Number of wired kernel variants — the length of [`StdlibKernel::ALL`].
const REGISTRY_LEN: usize = StdlibKernel::ALL.len();

// Raw slice indexing below is deliberate and provably panic-free: `slice::get`
// is not `const`-stable on this toolchain, so a `const`-context scan must index.
// Every index is bounded by its own `while i < slice.len()` guard, so it can
// never be out of range — the `indexing_slicing` lint is a false positive here.

/// The `(qualifier, name)` identity of every wired kernel, projected once from
/// [`StdlibKernel::decl`]. Building this flat table calls the heavy `decl()`
/// projection exactly `REGISTRY_LEN` times; the drift gate then cross-checks each
/// prelude member against it with cheap `&str` compares, instead of re-projecting
/// every kernel for every member (which trips the const-eval step budget).
// `indexing_slicing`: index guarded by `i < REGISTRY_LEN` (see note above).
// `large_const_arrays`: must be `const`, not `static` — the drift gate reads it
// during const evaluation, which cannot access a `static`'s value.
#[allow(clippy::indexing_slicing, clippy::large_const_arrays)]
const REGISTRY_DECL_PAIRS: [(&str, &str); REGISTRY_LEN] = {
    let mut pairs = [("", ""); REGISTRY_LEN];
    let all = StdlibKernel::ALL;
    let mut i = 0;
    while i < REGISTRY_LEN {
        let decl = all[i].decl();
        pairs[i] = (decl.qualifier, decl.name);
        i += 1;
    }
    pairs
};

/// `const`-context byte-exact string equality (`str::eq` is not `const`).
#[allow(clippy::indexing_slicing)] // indices guarded by `i < len`; see note above
pub const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `true` iff `(qualifier, member)` is one of the sanctioned in-table aliases.
#[allow(clippy::indexing_slicing)] // index guarded by `i < len`; see note above
const fn is_prelude_qualifier_alias(qualifier: &str, member: &str) -> bool {
    let mut i = 0;
    while i < PRELUDE_QUALIFIER_ALIASES.len() {
        let (q, m) = PRELUDE_QUALIFIER_ALIASES[i];
        if const_str_eq(q, qualifier) && const_str_eq(m, member) {
            return true;
        }
        i += 1;
    }
    false
}

/// `true` iff some wired [`StdlibKernel`] declares exactly `(qualifier, member)`.
#[allow(clippy::indexing_slicing)] // index guarded by `i < REGISTRY_LEN`; see note above
const fn registry_backs(qualifier: &str, member: &str) -> bool {
    let mut i = 0;
    while i < REGISTRY_LEN {
        let (q, n) = REGISTRY_DECL_PAIRS[i];
        if const_str_eq(q, qualifier) && const_str_eq(n, member) {
            return true;
        }
        i += 1;
    }
    false
}

/// **Compile-time drift tripwire (fail-closed).** Every `(qualifier, member)`
/// the canonicaliser will register from [`PRELUDE_QUALIFIERS`] must be backed by
/// a wired [`StdlibKernel`] of the same name — or be a sanctioned in-table alias
/// ([`PRELUDE_QUALIFIER_ALIASES`]). If the two const tables drift (a member is
/// added here without a matching kernel, or a kernel is renamed/removed out from
/// under a registered member) this `assert!` fails **at build time**, before any
/// test runs — so a resolver that recognises a name the registry cannot lower
/// (the `ipe`-accepts-then-`cargo`-fails class) can never ship.
///
/// The runtime `canon_equals_registry` test in `crate::tests` still checks the
/// dynamic wiring the interner builds (`stdlib_index` propagation, the reserved
/// category, `.Unsafe`-relocation), which cannot be evaluated in `const` context;
/// this gate is the const-data half the project rulebook mandates be build-time.
///
/// The `allow(long_running_const_eval)` covers the bounded
/// `PRELUDE_QUALIFIERS.len() × StdlibKernel::ALL.len()` cross-scan — deterministic
/// and finite (no data-dependent iteration), just larger than the lint's default
/// step budget for a soft infinite-loop guard.
#[allow(long_running_const_eval)]
#[allow(clippy::indexing_slicing)] // indices guarded by `i < len`; see note above
const _: () = {
    let mut qi = 0;
    while qi < PRELUDE_QUALIFIERS.len() {
        let (qualifier, members) = PRELUDE_QUALIFIERS[qi];
        // Internal-only qualifiers never surface a user-visible kernel member.
        let bytes = qualifier.as_bytes();
        let is_internal = !bytes.is_empty() && bytes[0] == b'_';
        if !is_internal {
            let mut mi = 0;
            while mi < members.len() {
                let member = members[mi];
                // IPE-RUST-AUDIT:ACCEPTED — this `assert!` runs during const-eval of the
                // enclosing `const _` block, so it fails the build on kernel-table drift and
                // can never panic at runtime; it is a compile-time proof, not a runtime abort.
                assert!(
                    registry_backs(qualifier, member)
                        || is_prelude_qualifier_alias(qualifier, member),
                    "kernel-table drift: PRELUDE_QUALIFIERS lists a (qualifier, \
                     member) pair with no matching StdlibKernel::decl() and no \
                     sanctioned alias in PRELUDE_QUALIFIER_ALIASES. Add the kernel \
                     variant (+ its type scheme) to the registry, or register the \
                     alias, or remove the stale member.",
                );
                mi += 1;
            }
        }
        qi += 1;
    }
};

impl Env {
    /// Build the base environment with Ipê's built-in variables and the
    /// auto-qualified prelude kernel modules. The `home` module's top-level
    /// names and unions are registered separately by the caller.
    ///
    /// # Errors
    /// [`ipe_diagnostics::Diagnostic::CompilerBug`] if the interner's symbol
    /// table is exhausted while interning the built-in names.
    pub fn initial(home: Vec<Symbol>, interner: &mut Interner) -> DResult<Self> {
        let mut env = Self {
            home,
            module_catalog: ModuleCatalog::new(std::iter::empty()),
            ..Self::default()
        };
        // Pre-intern the view type names so both the engine-tagged carrier
        // (`View`) and its per-engine aliases (`Element` / `Screen` / `Lines`)
        // are resolvable even in a source that names only one of them, along
        // with the closed engine tags `Web` / `Tui` / `Cli` an alias rewrites
        // into so the alias arm can look them up without a mutable interner.
        // `TuiAttr` / `CliAttr` are the builtins a terminal engine's public
        // `Attribute` resolves to.
        interner.intern("View")?;
        interner.intern("TuiAttr")?;
        interner.intern("CliAttr")?;
        interner.intern("Element")?;
        interner.intern("Screen")?;
        interner.intern("Lines")?;
        interner.intern("Web")?;
        interner.intern("Tui")?;
        interner.intern("Cli")?;
        // install_prelude_qualifiers MUST run first — it populates
        // stdlib_index, which install_builtin_vars consults for the fast-path id.
        env.install_prelude_qualifiers(interner)?;
        env.install_builtin_ctors(interner)?;
        env.install_builtin_vars(interner)?;
        // Move every installed kernel table into the member pool and record the
        // import path of each gated canonical, before any import is processed.
        env.freeze_stdlib_import_gate(interner)?;
        Ok(env)
    }

    /// Move the installed kernel members into the pool and freeze the gate catalog.
    ///
    /// Runs after every ambient qualifier is installed and before any import is
    /// seen. Every qualifier table the installers built moves into
    /// [`Self::kernel_members`] / [`Self::kernel_ctors`], leaving
    /// [`Self::qual_vars`] and [`Self::qual_ctors`] empty: a spelling holds
    /// members only once an import installs it. [`Self::gated_stdlib_quals`]
    /// maps each kernel canonical to its primary import path, which a
    /// diagnostic tells the user to import. `Basics` (Tier A) is never gated.
    ///
    /// # Errors
    /// [`ipe_diagnostics::Diagnostic::CompilerBug`] if interning `Basics` or a path
    /// segment exhausts the interner.
    fn freeze_stdlib_import_gate(&mut self, interner: &mut Interner) -> DResult<()> {
        let qual_vars = std::mem::take(&mut self.qual_vars);
        let qual_ctors = std::mem::take(&mut self.qual_ctors);
        self.kernel_members = Rc::new(
            Rc::unwrap_or_clone(qual_vars)
                .into_iter()
                .map(|(q, members)| (KernelModule(q), members))
                .collect(),
        );
        self.kernel_ctors = Rc::new(
            Rc::unwrap_or_clone(qual_ctors)
                .into_iter()
                .map(|(q, ctors)| (KernelModule(q), ctors))
                .collect(),
        );
        let basics = interner.intern("Basics")?;
        // canonical → its primary `Ipe.*` import path (the FIRST table entry
        // naming it). The IPE-N0034 candidate list is every catalog module whose
        // bare import binds the qualifier (`ModuleCatalog::modules_bound_by`), so
        // a canonical with several paths lists them all.
        let mut canon_to_path: BTreeMap<Symbol, Vec<Symbol>> = BTreeMap::new();
        for (path, canonical) in STDLIB_MODULE_QUALIFIERS {
            let canon_sym = interner.intern(canonical)?;
            if canon_sym == basics || !self.kernel_members.contains_key(&canon_sym) {
                continue;
            }
            let mut segs = Vec::with_capacity(path.len());
            for seg in *path {
                segs.push(interner.intern(seg)?);
            }
            canon_to_path.entry(canon_sym).or_insert(segs);
        }
        self.gated_stdlib_quals = Rc::new(canon_to_path);
        Ok(())
    }

    /// The qualifiers a use site may be pointed at by a did-you-mean.
    ///
    /// Exactly the spellings an import installed: an unimported module is never
    /// offered.
    pub fn usable_qualifiers(&self) -> impl Iterator<Item = Symbol> + '_ {
        self.qual_vars.keys().copied()
    }

    /// The kernel module registered under the canonical qualifier `canonical`.
    #[must_use]
    pub fn kernel_module_of(&self, canonical: Symbol) -> Option<KernelModule> {
        self.kernel_members
            .get_key_value(&canonical)
            .map(|(module, _)| *module)
    }

    /// The kernel module a stdlib import `path` names, parsed once from the table.
    ///
    /// Consults [`STDLIB_MODULE_QUALIFIERS`] (the single source of truth) and
    /// yields the module only when its canonical carries members in
    /// [`Self::kernel_members`]. A path naming no kernel module yields `None`,
    /// so the caller installs nothing and a use fails closed at its site.
    ///
    /// # Errors
    /// [`ipe_diagnostics::Diagnostic::CompilerBug`] if interning the canonical
    /// name exhausts the interner's symbol table.
    pub fn kernel_module(
        &self,
        path: &[Symbol],
        interner: &mut Interner,
    ) -> DResult<Option<KernelModule>> {
        // The `&'static str` canonical is owned by the table, so it outlives the
        // immutable interner borrow released at the end of the block.
        let canonical: Option<&'static str> = {
            let mut segs: Vec<&str> = Vec::with_capacity(path.len());
            for &s in path {
                match interner.resolve(s) {
                    Some(seg) => segs.push(seg),
                    // An un-interned path segment cannot name a known module.
                    None => return Ok(None),
                }
            }
            stdlib_canonical_qualifier(&segs)
        };
        match canonical {
            None => Ok(None),
            Some(canon) => {
                let sym = interner.intern(canon)?;
                Ok(self.kernel_module_of(sym))
            }
        }
    }

    /// The pooled members of a kernel module.
    #[must_use]
    pub fn kernel_module_members(&self, module: KernelModule) -> InstalledMembers {
        (
            self.kernel_members
                .get(&module)
                .cloned()
                .unwrap_or_default(),
            self.kernel_ctors.get(&module).cloned().unwrap_or_default(),
        )
    }

    /// Install one import's claim on a qualifier spelling: the one writer of
    /// [`Self::qual_vars`] and [`Self::qual_ctors`].
    ///
    /// The import is recorded in [`ImportScope::imported_modules`]. A spelling
    /// already owned by the same module merges; one owned by another module is
    /// decided by [`ClaimForm`]: an alias outranks a last-segment shorthand,
    /// two explicit spellings (alias or path) of different modules are refused
    /// now, and a shorthand against a non-alias claim leaves the spelling
    /// ambiguous, refused at its first use. The entry is created even when
    /// `members` is empty, so a type qualifier sees the spelling as installed.
    ///
    /// # Errors
    /// [`NameError::DuplicateQualifier`] (IPE-N0027) for two
    /// explicit spellings of different modules; [`Diagnostic::CompilerBug`] if
    /// the spelling is not interned.
    pub fn install_import(
        &mut self,
        claim: QualifierClaim,
        members: InstalledMembers,
        interner: &Interner,
    ) -> DResult<()> {
        let spelling = claim.spelling;
        let scope = Rc::make_mut(&mut self.import_scope);
        scope.imported_modules.insert(claim.owner.clone());
        let installed_span = scope.qualifier_owner.get(&spelling).map(|c| c.span);
        let shape = scope.cmd_sub_shape.map(|(shape, _)| shape);
        let verdict = if scope.ambiguous.contains_key(&spelling) {
            if claim.form == ClaimForm::Alias {
                scope.ambiguous.remove(&spelling);
                ClaimVerdict::Replace
            } else {
                ClaimVerdict::Keep
            }
        } else {
            scope
                .qualifier_owner
                .get(&spelling)
                .map_or(ClaimVerdict::Replace, |installed| {
                    claim_verdict(installed, &claim, shape, interner)
                })
        };
        let earlier = installed_span.map_or(claim.span, |s| s.min(claim.span));
        let later = installed_span.map_or(claim.span, |s| s.max(claim.span));
        match verdict {
            ClaimVerdict::Same => {
                if claim.form == ClaimForm::Alias
                    && let Some(owner) = scope.qualifier_owner.get_mut(&spelling)
                {
                    owner.form = ClaimForm::Alias;
                }
                self.extend_spelling(spelling, members);
            }
            ClaimVerdict::Keep => {}
            ClaimVerdict::Replace => {
                scope.qualifier_owner.insert(spelling, claim);
                Rc::make_mut(&mut self.qual_vars).remove(&spelling);
                Rc::make_mut(&mut self.qual_ctors).remove(&spelling);
                self.extend_spelling(spelling, members);
            }
            ClaimVerdict::Refuse => {
                let qualifier =
                    interner
                        .resolve(spelling)
                        .ok_or_else(|| Diagnostic::CompilerBug {
                            where_: "canon.install_import",
                            detail: "an installed qualifier spelling is not interned".to_owned(),
                        })?;
                return Err(Diagnostic::Name {
                    span: later,
                    msg: NameError::DuplicateQualifier {
                        qualifier: qualifier.into(),
                        first: earlier,
                    },
                });
            }
            ClaimVerdict::Ambiguous => {
                scope.qualifier_owner.remove(&spelling);
                scope.ambiguous.insert(
                    spelling,
                    AmbiguousQualifier {
                        first: earlier,
                        second: later,
                    },
                );
                Rc::make_mut(&mut self.qual_vars).remove(&spelling);
                Rc::make_mut(&mut self.qual_ctors).remove(&spelling);
            }
        }
        Ok(())
    }

    /// Add `members` under an installed `spelling`, creating its entry.
    fn extend_spelling(&mut self, spelling: Symbol, (vars, ctors): InstalledMembers) {
        Rc::make_mut(&mut self.qual_vars)
            .entry(spelling)
            .or_default()
            .extend(vars);
        if !ctors.is_empty() {
            Rc::make_mut(&mut self.qual_ctors)
                .entry(spelling)
                .or_default()
                .extend(ctors);
        }
    }

    /// Install a kernel module's pooled members under one spelling.
    ///
    /// # Errors
    /// As [`Self::install_import`].
    pub fn install_kernel_import(
        &mut self,
        module: KernelModule,
        form: ClaimForm,
        spelling: Symbol,
        span: Span,
        interner: &Interner,
    ) -> DResult<()> {
        let members = self.kernel_module_members(module);
        self.install_import(
            QualifierClaim {
                spelling,
                owner: ModuleIdentity::Kernel(module),
                form,
                span,
            },
            members,
            interner,
        )
    }

    /// Record the TEA shape this module imports.
    pub fn set_cmd_sub_shape(&mut self, shape: TeaShape, span: Span) {
        Rc::make_mut(&mut self.import_scope).cmd_sub_shape = Some((shape, span));
    }

    /// Why `qualifier` holds no members in this module.
    #[must_use]
    pub fn classify_absent(&self, qualifier: Symbol, interner: &Interner) -> AbsentQualifier {
        if let Some(ambiguous) = self.import_scope.ambiguous.get(&qualifier) {
            return AbsentQualifier::Ambiguous(*ambiguous);
        }
        if let Some(path) = self.gated_stdlib_quals.get(&qualifier) {
            return AbsentQualifier::KnownStdlib(path.clone());
        }
        interner
            .resolve(qualifier)
            .and_then(CmdOrSub::from_qualifier)
            .map_or(AbsentQualifier::Unknown, AbsentQualifier::InternalCmdSub)
    }

    /// Register the ambient (Tier-B) built-in constructors so `Just` / `Nothing` /
    /// `Ok` / `Err` / `True` / `False` resolve as constructors — both as value
    /// expressions and in `case` patterns — without an explicit import. These
    /// belong to the built-in `Maybe a` / `Result e a` / `Bool` types, which have
    /// no user `type` declaration; `home` is left empty (matching how the builtin
    /// type names carry no user module) and `type_name` is the built-in type's
    /// symbol so downstream stages recognise it by name.
    ///
    /// # Errors
    /// [`ipe_diagnostics::Diagnostic::CompilerBug`] if the interner is exhausted.
    fn install_builtin_ctors(&mut self, interner: &mut Interner) -> DResult<()> {
        // The full built-in constructor set is drawn from the ONE shared table
        // (`crate::builtins::BUILTIN_UNIONS`) that `types::exhaust` and `lower`
        // also consume, so the three can never disagree. Every built-in type
        // carries no user `type` declaration, so `home` is left empty (matching
        // how the built-in type names carry no user module); `type_name` is the
        // built-in type's interned symbol so downstream stages recognise it.
        for union in crate::builtins::BUILTIN_UNIONS {
            let type_name = interner.intern(union.type_name)?;
            // A built-in union whose constructors live under a kernel-qualifier
            // module (e.g. `Http.Post`) names that qualifier and is registered
            // qualified-only; `None` means ambient-unqualified like `Just`/`Ok`.
            let qualifier = union
                .qualified_home
                .map(|q| interner.intern(q))
                .transpose()?;
            for &(name, index, arity) in union.ctors {
                let name = interner.intern(name)?;
                let ctor_home = CtorHome {
                    home: Vec::new(),
                    type_name,
                    name,
                    index,
                    arity,
                };
                // A built-in union with a `qualified_home` (e.g. `HttpMethod`
                // -> `Http`) is import-scoped: its constructors are reachable
                // ONLY as `Http.Post`, never ambient unqualified, so a user's
                // own `Post`/`Get`/… constructor is not silently shadowed.
                if let Some(qsym) = qualifier {
                    Rc::make_mut(&mut self.qual_ctors)
                        .entry(qsym)
                        .or_default()
                        .insert(name, ctor_home);
                } else {
                    // A home-less built-in (`Just`/`Nothing`/`Ok`/`Err`/`True`/
                    // `False`) has no user module and binds at the ambient tier.
                    let origin = Origin {
                        identity: Identity::Ctor(CtorIdentity {
                            home: Vec::new(),
                            type_name,
                        }),
                        target: ExprTarget::Ctor(ctor_home),
                        importers: BTreeSet::new(),
                        span: Span::DUMMY,
                    };
                    Rc::make_mut(&mut self.module_scope)
                        .expr
                        .bind(name, Tier::Ambient, origin)
                        .map_err(|_| Diagnostic::CompilerBug {
                            where_: "canon.builtin_ctor_twice",
                            detail: "a built-in constructor name is installed twice".to_owned(),
                        })?;
                }
            }
        }
        Ok(())
    }

    /// Bind a name as a local (function parameter / `case` binding).
    pub fn add_local(&mut self, name: Symbol) {
        self.vars.insert(name, VarHome::Local);
    }

    /// Look up an unqualified variable.
    #[must_use]
    pub fn lookup_var(&self, name: Symbol) -> Option<&VarHome> {
        self.vars.get(&name)
    }

    /// Look up a qualified variable (`Qualifier.name`).
    #[must_use]
    pub fn lookup_qual_var(&self, qualifier: Symbol, name: Symbol) -> Option<&VarHome> {
        self.qual_vars.get(&qualifier).and_then(|m| m.get(&name))
    }

    /// The member table for a qualifier, or `None` when the qualifier names no
    /// known module/import alias. Lets a caller distinguish an unknown
    /// qualifier from a known qualifier missing the member.
    #[must_use]
    pub fn qual_members(&self, qualifier: Symbol) -> Option<&BTreeMap<Symbol, VarHome>> {
        self.qual_vars.get(&qualifier)
    }

    /// All `StdlibKernel` values that are catalog-reachable in this `Env`.
    ///
    /// Iterates every module in [`Self::kernel_members`] and yields the kernel
    /// carried by each [`VarHome::Kernel`] home. Each yielded kernel has at
    /// least one surface name an import can reach — the inverse direction
    /// guarded by the anti-drift tripwire in `ipe_stdlib`.
    ///
    /// Re-exports and shape-scoped copies yield one kernel more than once;
    /// callers that need set membership deduplicate.
    pub fn kernel_homes(&self) -> impl Iterator<Item = StdlibKernel> + '_ {
        self.kernel_members
            .values()
            .flat_map(|members| members.values())
            .filter_map(|home| {
                if let VarHome::Kernel(k, _, _) = home {
                    Some(*k)
                } else {
                    None
                }
            })
    }

    /// Built-in unqualified variables (the Tier-A `Ipe.Basics` surface).
    /// Supported subset of `Environment.builtinVars`.
    ///
    /// Must run AFTER `install_prelude_qualifiers` so `stdlib_index` is
    /// populated and the id fast-path can be threaded in.
    fn install_builtin_vars(&mut self, interner: &mut Interner) -> DResult<()> {
        let basics = interner.intern("Basics")?;
        let error_sym = interner.intern("Error")?;
        let basics_path = vec![interner.intern("Ipe")?, basics];
        let prelude_bug = || Diagnostic::CompilerBug {
            where_: "canon.prelude_value",
            detail: "a prelude value has no module-level identity".to_owned(),
        };
        for (name, module, func) in [
            ("identity", basics, "identity"),
            ("always", basics, "always"),
            ("not", basics, "not"),
            ("modBy", basics, "modBy"),
            ("clamp", basics, "clamp"),
            ("fst", basics, "fst"),
            ("snd", basics, "snd"),
            // `errorToString` is the Basics-exposed unqualified form of
            // `Error.toString`.  The kernel declaration uses module="Error" /
            // func="toString", so the stdlib_index key is (Error, toString).
            // We must register with the same key so `id` resolves to
            // `Some(StdlibKernel::ErrorToString)` and the type-checker
            // can look up its scheme without hitting IPE-L0108.
            ("errorToString", error_sym, "toString"),
            // Three-way comparison — `compare : comparable -> comparable -> Order`.
            ("compare", basics, "compare"),
            // ── Basics numerics ─────────────────────────────────────────────
            ("negate", basics, "negate"),
            ("abs", basics, "abs"),
            ("sqrt", basics, "sqrt"),
            ("min", basics, "min"),
            ("max", basics, "max"),
            // ── end Basics numerics ─────────────────────────────────────────
        ] {
            let key = interner.intern(name)?;
            let func_sym = interner.intern(func)?;
            let home = kernel_home(&self.stdlib_index, module, func_sym);
            let identity = ValueIdentity::of(&home, key).ok_or_else(prelude_bug)?;
            let origin = Origin {
                identity: Identity::Value(identity),
                target: ExprTarget::Value(home),
                importers: BTreeSet::from([basics_path.clone()]),
                span: Span::DUMMY,
            };
            // The prelude values bind as an open import of `Ipe.Basics`: a local
            // declaration or an explicit import of the same spelling outranks
            // them, and an open import of another definition is ambiguous.
            Rc::make_mut(&mut self.module_scope)
                .expr
                .bind(key, Tier::Open, origin)
                .map_err(|_| prelude_bug())?;
        }
        Ok(())
    }

    /// Auto-qualified prelude kernel modules. Supported subset of
    /// `Environment.preludeQualifiers` — `String.fromInt`, `String.fromFloat`,
    /// etc. resolve without an explicit `import String`.
    #[allow(clippy::too_many_lines)] // declarative table — extracting a helper would obscure the data
    fn install_prelude_qualifiers(&mut self, interner: &mut Interner) -> DResult<()> {
        // Compiled-source modules absent from QUALIFIERS (enforced by
        // `compiled_vs_kernel_qualifier_disjoint`; see the exclusion table in
        // `STDLIB_MODULE_QUALIFIERS` for the full list and per-module rationale):
        // String, Char, List, Math, Bitwise, Dict, Set, Bytes, Encoding,
        // Uuid, Task, Io, Debug, Time, Random, Decimal, Css, Ui, Html,
        // Html.Attributes, Path, Regex.
        // Their kernels are reached via `detect_kernel_alias`, not this table.
        //
        // The table itself is hoisted to the module-level `PRELUDE_QUALIFIERS`
        // so a compile-time drift gate can check it against the kernel registry
        // without executing this function.
        const QUALIFIERS: &[(&str, &[&str])] = PRELUDE_QUALIFIERS;

        // ── Per-qualifier function name aliases ───────────────────────────────
        // Maps a Ipê-source alias name (e.g. `htmlRender`) to its canonical
        // kernel function name (e.g. `render`) within a qualifier module, so
        // `Html.htmlRender` and `Ipe.Html.htmlRender` both produce
        // `VarKernel { module: html_sym, name: render_sym }` — which lower.rs
        // matches under the same `("Html", "render")` arm.
        //
        // Declared here (before the first `for` statement) to satisfy
        // `clippy::items_after_statements`.
        //
        // MUST be processed BEFORE the `CMD_SUB_MODULES` copies (installed
        // below) so that alias entries are included in any qual-to-qual copy.
        const FUNC_ALIASES: &[(&str, &str, &str)] = &[
            // ("qualifier", "alias_name", "canonical_kernel_name")
            // `Html`'s legacy pipeline-readable spellings (`htmlRender` /
            // `htmlEscapeText` / `htmlEscapeAttr` / `htmlAttrToString`) are
            // DELIBERATELY absent: `Ipe.Html` is now COMPILED-SOURCE
            // (`COMPILED_STD_MODULES`), so those aliases live in `Ipe/Html.ipe`
            // as `Kernel.kernel "Html_*"` bindings, not the kernel-qualifier prelude.
            // `Random.range` is likewise DELIBERATELY absent: `Ipe.Random` is now
            // COMPILED-SOURCE, so `range lo hi = int lo hi` lives in
            // `Ipe/Random.ipe` as pure Ipê, not a kernel-qualifier alias.
            //
            // `Crypto.hmacSha256`/`hmacSha512` are the typed-`Key` HMAC surface,
            // aliasing the canonical `hmacSha256WithKey`/`hmacSha512WithKey`
            // kernels. The String-keyed originals were removed so passing a bare
            // `String` key is a compile-time type error; the alias inherits the
            // canonical kernel's `Key -> String -> Mac` scheme.
            ("Crypto", "hmacSha256", "hmacSha256WithKey"),
            ("Crypto", "hmacSha512", "hmacSha512WithKey"),
        ];

        // ── Cross-qualifier member re-exports ────────────────────────────────
        // A member exposed under a NEW qualifier whose backing kernel lives under
        // a DIFFERENT canonical qualifier. The `VarHome::Kernel` carries the
        // CANONICAL module + name symbols, so the lowerer's kernel match arms
        // (`("Cmd", "publish")`, `("Sub", "subscribeTopic")`) fire unchanged; only
        // the resolution qualifier differs. Used to give the Web-shape-scoped
        // `Ipe.Tea.Web.PubSub` (canonical `TeaWebPubSub`) its TEA-side broadcast
        // members, which aggregate two canonical kernel families (`Cmd` + `Sub`).
        const CROSS_QUALIFIER_MEMBERS: &[(&str, &str, &str, &str)] = &[
            // (new_qualifier, member_name, canonical_qualifier, canonical_name)
            // `Crypto`'s typed-key surface: the `Key` constructors and the `Mac`
            // extractor are canonical `Key.*` / `Mac.*` kernels, re-exported under
            // the `Crypto` qualifier so `Crypto.keyFromBytes` / `Crypto.macToHex`
            // resolve off a plain `import Ipe.Crypto`.
            ("Crypto", "keyFromString", "Key", "fromString"),
            ("Crypto", "keyFromBytes", "Key", "fromBytes"),
            ("Crypto", "macToHex", "Mac", "toHex"),
            ("TeaWebPubSub", "publish", "Cmd", "publish"),
            ("TeaWebPubSub", "publishNoEcho", "Cmd", "publishNoEcho"),
            ("TeaWebPubSub", "subscribeTopic", "Sub", "subscribeTopic"),
        ];

        // Build stdlib_index FIRST so every `kernel_home` call below can look
        // up the backing kernel and pick `Kernel` vs `ReservedKernel`.
        // Derived from StdlibKernel::ALL + decl() — anti-drift by construction.
        // Skip internal-only qualifiers (e.g. "_internal_").
        {
            // Hoist the copy-on-write out of the per-kernel loop: one refcount
            // check yields a mutable handle reused for every insert, rather than
            // re-checking on each of the ~1285 kernels.
            let index = Rc::make_mut(&mut self.stdlib_index);
            for sk in StdlibKernel::ALL {
                let decl = sk.decl();
                if decl.qualifier.starts_with('_') {
                    continue; // e.g. "_internal_" — skip
                }
                let qual_sym = interner.intern(decl.qualifier)?;
                let name_sym = interner.intern(decl.name)?;
                index.insert((qual_sym, name_sym), *sk);
            }
        }

        for (qual, funcs) in QUALIFIERS {
            let qual_sym = interner.intern(qual)?;
            let mut module = BTreeMap::new();
            for func in *funcs {
                let func_sym = interner.intern(func)?;
                // Resolve the backing kernel so lower_callee can use the fast
                // path for registered kernels.
                //
                // `Ipe.Html.Events` (`Event`) resolves to the DEDICATED
                // `Html*` event kernels (`HtmlOnClick` …), which produce
                // `Ipe.Html.Attribute msg` (`html_attr`) — the same nominal type
                // the `Ipe.Html.Attributes` builders and every element builder's
                // `List (html_attr msg)` slot use. (They must NOT alias to
                // the `Ui` event kernels, which produce the `Ipe.Ui.Attribute`
                // variant — that makes `button [ onClick Msg ]` fail to unify.) `onMsg`
                // is the generic alias for `onClick`. All members are registered
                // under `(Event, name)` in `stdlib_index`, so `kernel_home`
                // yields a backed `Kernel` and `lower_callee`'s fast path returns
                // the `Html*` kernel directly.
                let name_sym = if *qual == "Event" {
                    let canonical = if *func == "onMsg" { "onClick" } else { *func };
                    interner.intern(canonical)?
                } else {
                    func_sym
                };
                module.insert(
                    func_sym,
                    kernel_home(&self.stdlib_index, qual_sym, name_sym),
                );
            }
            Rc::make_mut(&mut self.qual_vars)
                .entry(qual_sym)
                .or_default()
                .extend(module);
        }

        for (qual, alias, canonical) in FUNC_ALIASES {
            let qual_sym = interner.intern(qual)?;
            let alias_sym = interner.intern(alias)?;
            let canonical_sym = interner.intern(canonical)?;
            // VarHome stores the CANONICAL module + fn symbols so lower.rs
            // match arms (`("Html", "render")`) work without any changes.
            // The backing kernel is resolved against the CANONICAL (qual, name)
            // key.
            let home = kernel_home(&self.stdlib_index, qual_sym, canonical_sym);
            Rc::make_mut(&mut self.qual_vars)
                .entry(qual_sym)
                .or_default()
                .insert(alias_sym, home);
        }

        for (new_qual, member, canon_qual, canon_name) in CROSS_QUALIFIER_MEMBERS {
            let new_qual_sym = interner.intern(new_qual)?;
            let member_sym = interner.intern(member)?;
            let canon_qual_sym = interner.intern(canon_qual)?;
            let canon_name_sym = interner.intern(canon_name)?;
            // Resolve the backing kernel against the CANONICAL (qualifier, name)
            // key so the fast path in `lower_callee` still works; the VarHome
            // carries the canonical module + name so the lowerer's match arms
            // are unaffected.
            let home = kernel_home(&self.stdlib_index, canon_qual_sym, canon_name_sym);
            Rc::make_mut(&mut self.qual_vars)
                .entry(new_qual_sym)
                .or_default()
                .insert(member_sym, home);
        }

        // Each `Ipe.Tea.<segment>.{Cmd,Sub}` module re-exports the whole
        // canonical `Cmd` / `Sub` member set. Each cloned `VarHome::Kernel` keeps
        // the CANONICAL module + name, so the lowerer's `("Cmd", …)` /
        // `("Sub", …)` arms fire unchanged; which shape may import which module
        // is IPE-N0035.
        for &(_, cmd, sub) in CMD_SUB_MODULES {
            for family in CmdOrSub::ALL {
                let module_sym = interner.intern(family.pick(cmd, sub))?;
                let canonical_sym = interner.intern(family.qualifier())?;
                if let Some(canonical_members) = self.qual_vars.get(&canonical_sym).cloned() {
                    Rc::make_mut(&mut self.qual_vars)
                        .entry(module_sym)
                        .or_default()
                        .extend(canonical_members);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod kernel_table_drift_gate_tests {
    //! Guards the compile-time drift tripwire (`const _` block above, using
    //! `registry_backs` / `is_prelude_qualifier_alias`). The `const` gate itself
    //! cannot be exercised with a *drifted* table at test time — a real drift
    //! fails the build, not a test — so these tests instead prove the gate's
    //! decision logic: it rejects an unbacked pair and accepts the backed /
    //! aliased cases, and the live table has zero unsanctioned drift.

    use super::{PRELUDE_QUALIFIERS, is_prelude_qualifier_alias, registry_backs};
    use ipe_kernels::StdlibKernel;

    /// A real registry pair is recognised as backed.
    #[test]
    fn registry_backs_a_real_pair() {
        let first = StdlibKernel::ALL.first().expect("registry is non-empty");
        let decl = first.decl();
        assert!(registry_backs(decl.qualifier, decl.name));
    }

    /// A pair no kernel declares is NOT backed — the drift the const gate rejects.
    #[test]
    fn registry_does_not_back_a_synthetic_drift_pair() {
        assert!(!registry_backs("CssSafety", "driftProbeXyz"));
        assert!(!is_prelude_qualifier_alias("CssSafety", "driftProbeXyz"));
    }

    /// The sanctioned in-table alias (`Event.onMsg`) is exempt: unbacked by its
    /// own name, but recognised as an alias.
    #[test]
    fn event_on_msg_is_a_sanctioned_alias() {
        assert!(!registry_backs("Event", "onMsg"));
        assert!(is_prelude_qualifier_alias("Event", "onMsg"));
    }

    /// Runtime mirror of the compile-time gate: every surfaced
    /// `(qualifier, member)` in the live table is either registry-backed or a
    /// sanctioned alias. If this fails, the `const _` gate above has already
    /// failed the build — this is the readable diagnostic form.
    #[test]
    fn every_prelude_qualifier_member_is_backed_or_aliased() {
        let mut offenders = Vec::new();
        for (qualifier, members) in PRELUDE_QUALIFIERS {
            if qualifier.starts_with('_') {
                continue;
            }
            for member in *members {
                if !registry_backs(qualifier, member)
                    && !is_prelude_qualifier_alias(qualifier, member)
                {
                    offenders.push(format!("{qualifier}.{member}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "PRELUDE_QUALIFIERS members with no backing StdlibKernel and no \
             sanctioned alias: {offenders:?}"
        );
    }
}

#[cfg(test)]
mod builtin_ctor_registration_tests {
    //! A built-in union with a `qualified_home` (e.g. `HttpMethod` -> `Http`)
    //! is import-scoped: its constructors live ONLY under the qualified
    //! path (`Http.Post`), never in the ambient unqualified table where they
    //! would shadow a user's own same-spelled constructor. The home-less
    //! built-ins (`Just`/`Nothing`/`Ok`/`Err`/`True`/`False`) stay ambient.

    use super::Env;
    use crate::scope::{ExprTarget, Resolved, Tier};
    use ipe_intern::Interner;

    /// The `HttpMethod` verbs must NOT be ambient unqualified — a user's own
    /// `Post`/`Get`/… constructor must win.
    #[test]
    fn http_verbs_are_not_ambient_unqualified() {
        let mut interner = Interner::new();
        let env = Env::initial(Vec::new(), &mut interner).expect("base env");
        for verb in ["Get", "Post", "Put", "Delete", "Patch", "Head", "Options"] {
            let sym = interner.intern(verb).expect("intern");
            assert!(
                matches!(env.module_scope.expr.resolve(sym), Resolved::Missing),
                "`{verb}` must not be an ambient unqualified constructor \
                 (it would shadow a user's own `{verb}` ctor)"
            );
        }
    }

    /// The `HttpMethod` verbs are pooled under the `Http` kernel module, which
    /// an import of `Ipe.Http` installs as `Http.<Verb>`.
    #[test]
    fn http_verbs_resolve_qualified() {
        let mut interner = Interner::new();
        let env = Env::initial(Vec::new(), &mut interner).expect("base env");
        let http = interner.intern("Http").expect("intern");
        let module = env
            .kernel_module_of(http)
            .expect("`Http` is a kernel module");
        for verb in ["Get", "Post", "Put", "Delete", "Patch", "Head", "Options"] {
            let sym = interner.intern(verb).expect("intern");
            let members = env
                .kernel_ctors
                .get(&module)
                .expect("`Http` kernel module must carry ctors");
            assert!(
                members.contains_key(&sym),
                "`Http.{verb}` must resolve to the HttpMethod verb"
            );
        }
    }

    /// A fresh environment installs no qualifier: a spelling reaches a module
    /// only through an import.
    #[test]
    fn fresh_env_installs_no_qualifier() {
        let mut interner = Interner::new();
        let env = Env::initial(Vec::new(), &mut interner).expect("base env");
        assert!(env.qual_vars.is_empty(), "no qualifier before any import");
        assert!(
            env.qual_ctors.is_empty(),
            "no qualified ctor before any import"
        );
        assert!(!env.kernel_members.is_empty(), "the kernel pool is filled");
    }

    /// The home-less prelude constructors stay ambient unqualified.
    #[test]
    fn homeless_builtin_ctors_stay_ambient() {
        let mut interner = Interner::new();
        let env = Env::initial(Vec::new(), &mut interner).expect("base env");
        for ctor in ["Just", "Nothing", "Ok", "Err", "True", "False"] {
            let sym = interner.intern(ctor).expect("intern");
            assert!(
                matches!(
                    env.module_scope.expr.resolve(sym),
                    Resolved::Found(origin, Tier::Ambient)
                        if matches!(origin.target, ExprTarget::Ctor(_))
                ),
                "`{ctor}` must stay an ambient unqualified constructor"
            );
        }
    }
}

#[cfg(test)]
mod stdlib_module_qualifier_distinctness_tests {
    use super::STDLIB_MODULE_QUALIFIERS;

    /// Every path in `STDLIB_MODULE_QUALIFIERS` must be distinct — a duplicate
    /// path silently shadows the earlier entry in `Env::kernel_module`
    /// (linear scan, first-match wins), making the second entry unreachable.
    #[test]
    fn no_duplicate_paths() {
        let mut seen: std::collections::BTreeSet<Vec<&str>> = std::collections::BTreeSet::new();
        for (path, _canonical) in STDLIB_MODULE_QUALIFIERS {
            let key: Vec<&str> = path.to_vec();
            assert!(
                seen.insert(key.clone()),
                "duplicate path in STDLIB_MODULE_QUALIFIERS: {}",
                key.join(".")
            );
        }
    }

    /// Every canonical qualifier in `STDLIB_MODULE_QUALIFIERS` must be distinct
    /// across the rows that claim to be the primary mapping for that qualifier.
    /// A qualifier that maps from two *different* paths is expected (alias rows),
    /// but a qualifier that maps to *itself* more than once — the same path and
    /// the same canonical string — is a copy-paste error.
    ///
    /// This guard targets the same-path/same-qualifier form of duplicate; the
    /// `no_duplicate_paths` test catches same-path/different-qualifier.
    #[test]
    fn no_duplicate_qualifier_strings_for_same_path() {
        // Build a (path, canonical) pair set — both fields must be jointly unique.
        let mut seen: std::collections::BTreeSet<(Vec<&str>, &str)> =
            std::collections::BTreeSet::new();
        for (path, canonical) in STDLIB_MODULE_QUALIFIERS {
            let key = (path.to_vec(), *canonical);
            assert!(
                seen.insert(key),
                "fully-duplicate row (same path AND qualifier) in \
                 STDLIB_MODULE_QUALIFIERS: {}.{}",
                path.join("."),
                canonical
            );
        }
    }
}
