//! Library single-source-of-truth: which standard-library module is admissible
//! in which (shape × runtime) placement.
//!
//! A program is placed on two orthogonal axes (spec § 0): its **shape** — what
//! `view` renders (DOM / cells / lines / http / none), pinned by the head of
//! `main` — and, for the Web shape, its **runtime** — whether the loop is
//! co-located with native effects (`served`, the served/desktop default) or
//! self-contained in a browser (`solo`). Every other shape has one runtime, so
//! its runtime axis is fixed.
//!
//! One table, [`allowed_in`], classifies the placement-constrained stdlib module
//! families — native effects and browser-host capabilities — by the set of
//! placements each is admissible in. `resolve`, the LSP, and the docs consume
//! this one table, so no placement rule for these families is duplicated per
//! site. A disallowed import is a compile error at resolve time — before any
//! downstream cargo build (THE SEAL) can break, and before a native effect (a
//! DB handle, a secret) could ever be emitted into a sandboxed browser bundle.
//!
//! Scope: this table owns the families with no other gate — native effects and
//! browser-host capabilities. The SHAPE-RENDER surfaces (`Ipe.Tea.*` TEA
//! machinery, `Ipe.Ui.*` / `Ipe.Html` view libraries) are governed by the
//! dedicated shape gates (IPE-N0033 / N0035 / N0045 and the lowering shape
//! gates), which already encode the shape-fold rules (`Tui`/`Cli` share the
//! terminal view family and `Ipe.Tea.Terminal.{Cmd,Sub}` but each own their
//! `Sub`, `WebView` folds onto `Web`); this table classifies them as
//! [`ModuleClass::Pure`] rather than re-gate them with a second, fold-unaware
//! rule.
//!
//! Soundness direction (Security > ease of use): the table may over-restrict
//! toward rejection (a false "not allowed here"), but it must never admit a
//! native effect into a sandboxed runtime. Where the placement of a family is
//! ambiguous, the security-conservative (deny) reading is chosen. The
//! runtime-aware wasm link gate (IPE-N0029, a default-deny kernel allowlist) is
//! the defence-in-depth backstop that refuses any unclassified native kernel in
//! a sandboxed bundle even if a new effect module is not yet a row here.

use crate::env::{STDLIB_MODULE_QUALIFIERS, const_str_eq};

/// A rendering shape, pinned by the head of `main` (spec § 1).
///
/// Mirrors [`crate::shape_source::MainShape`]; kept as its own type so this
/// module reads as a self-contained placement model and does not depend on the
/// classifier's direction of use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `main : Task Error ()` — renders nothing; a native binary.
    Script,
    /// `main = Tui.tea …` — full-screen terminal cells.
    Tui,
    /// `main = Cli.tea …` — line-oriented terminal output.
    Cli,
    /// `main = Worker.tea …` — the view-less TEA loop; renders nothing, a native
    /// binary. Co-located, capability-gated (no view sink → no browser, no
    /// sandbox).
    Worker,
    /// `main = Web.tea …` — a DOM app, the only shape with a runtime choice.
    Web,
}

impl Shape {
    /// The delivery shape a compiler-classified `main` pins.
    #[must_use]
    pub const fn from_main(shape: crate::shape_source::MainShape) -> Self {
        use crate::shape_source::MainShape;
        match shape {
            MainShape::Script => Self::Script,
            MainShape::Tui => Self::Tui,
            MainShape::Cli => Self::Cli,
            MainShape::Worker => Self::Worker,
            MainShape::Web => Self::Web,
        }
    }

    /// The canonical CLI/error word for this shape — the one vocabulary shared
    /// by the CLI grammar, diagnostics, config, and docs.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::Tui => "tui",
            Self::Cli => "cli",
            Self::Worker => "worker",
            Self::Web => "web",
        }
    }
}

/// The effect-locality axis of a placement (spec § 0, § 2). Only the Web shape
/// carries a genuine choice; every other shape has exactly one runtime, so its
/// value here is fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    /// The loop sits *at* native effects: served/desktop `served` for Web, and
    /// the single runtime of every non-Web shape (`terminal`, `binary`). Native
    /// effects (`Ipe.Db`, `Ipe.File`, a `Secret`) are admissible.
    Served,
    /// The self-contained client loop — wasm in a browser/webview (`web solo`).
    /// Effects reach the host only through Web-platform capabilities plus HTTP to
    /// a backend; a native effect has no denotation here and is denied.
    Solo,
}

/// A fully-placed program: a shape and its runtime. The runtime of every non-Web
/// shape is fixed to [`Runtime::Served`]; only the Web shape admits both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    /// The rendering shape.
    pub shape: Shape,
    /// The effect-locality runtime.
    pub runtime: Runtime,
}

impl Placement {
    /// The single placement every non-Web shape has: its one co-located runtime.
    /// Web has no single placement (it admits both runtimes), so this rejects it
    /// — callers with a Web shape must supply the resolved runtime explicitly.
    #[must_use]
    pub const fn sole_for(shape: Shape) -> Option<Self> {
        match shape {
            Shape::Script | Shape::Tui | Shape::Cli | Shape::Worker => Some(Self {
                shape,
                runtime: Runtime::Served,
            }),
            Shape::Web => None,
        }
    }

    /// The canonical placement phrase for a diagnostic — `script`, `terminal`,
    /// `worker`, `web served`, or `web solo`. One vocabulary with the CLI grammar.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match (self.shape, self.runtime) {
            (Shape::Script, _) => "script",
            (Shape::Tui | Shape::Cli, _) => "terminal",
            (Shape::Worker, _) => "worker",
            (Shape::Web, Runtime::Served) => "web served",
            (Shape::Web, Runtime::Solo) => "web solo",
        }
    }
}

/// The placement family of a standard-library module (spec § 5).
///
/// The coarse classification the allow-table is keyed on. The classifier
/// ([`classify`]) maps a module dot-path onto one of these; only the
/// placement-constrained families (native effects and browser-host
/// capabilities) are named, and everything else is [`Self::Pure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleClass {
    /// A pure module — no effect, no render (`String`, `List`, `Dict`, `Json`,
    /// `Math`, `Result`, `Task`, …). Also the shape-render surfaces
    /// (`Ipe.Tea.*`, `Ipe.Ui.*`, `Ipe.Html`), which the dedicated shape gates
    /// (IPE-N0033 / N0035 / N0045 and the lowering shape gates) govern with the
    /// shape-fold rules this table deliberately does not duplicate. Admissible in
    /// every placement here.
    Pure,
    /// `Ipe.Browser.*` — Web-platform host capabilities (Geolocation, Camera,
    /// Microphone, Clipboard, …). Needs a JS host: admissible in the Web shape
    /// (served or solo, on any host). Rejected in the live-rendering terminal
    /// shapes, which have no browser and never will. The `script` shape is
    /// exempt: it renders nothing and is the build-time harness a decoder probe
    /// or an export check imports these modules from, so a browser module there
    /// is a no-render tool use, not a mis-placed live capability.
    BrowserHost,
    /// `Ipe.Db.*`, `Ipe.File.*`, the server `Ipe.Http.Server`, and `Auth` secret
    /// surfaces — direct native effects. Admissible only in a co-located runtime;
    /// **rejected in `solo`** (the DB/secret-to-browser leak the gate exists to
    /// prevent).
    NativeEffect,
    /// The portable client `Ipe.Http` fetch surface — admissible in any placement
    /// with a browser (Web live/spa) and in every co-located native placement.
    ClientHttp,
}

/// The verdict of the allow-table for one (module family × placement) cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admissibility {
    /// The module is admissible in this placement.
    Allow,
    /// The module is not admissible in this placement, with a reason that names
    /// the module family, the placement, and what to use instead.
    Deny(DenyReason),
}

/// Why a module family is denied in a placement (spec § 6).
///
/// A machine-readable reason the diagnostic layer turns into a kind-teacher
/// message. Each variant carries exactly the facts the message needs; the prose
/// lives with the diagnostic so the message set is itself a single source of
/// truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// A native effect (`Ipe.Db` / `Ipe.File` / `Ipe.Http.Server` / a secret) was
    /// reached in a sandboxed `solo` runtime. Move it behind an HTTP boundary, or
    /// deliver as `web served` where the loop runs server-side.
    NativeEffectInSandbox,
    /// A `Ipe.Browser.*` host capability was reached in a placement with no JS
    /// host (`terminal` / `server` / `script`).
    BrowserOutsideBrowserHost {
        /// The placement that has no browser host.
        placement: Placement,
    },
}

/// The placement family of every kernel canonical in [`STDLIB_MODULE_QUALIFIERS`].
///
/// One row per canonical, so every import path of one module (`Ipe.Http.Server`
/// and `Ipe.Server.Http`, both canonical `Server`) classifies alike. A
/// `const` check refuses to build when a canonical has no row, two rows, or a
/// row names no canonical.
const CANONICAL_CLASSES: &[(&str, ModuleClass)] = &[
    ("Crypto", ModuleClass::Pure),
    ("Secret", ModuleClass::Pure),
    ("CssSafety", ModuleClass::Pure),
    ("Jwt", ModuleClass::Pure),
    ("JsonEnc", ModuleClass::Pure),
    ("JsonDec", ModuleClass::Pure),
    ("JsonDecP", ModuleClass::Pure),
    ("System", ModuleClass::Pure),
    ("Process", ModuleClass::Pure),
    ("Http", ModuleClass::ClientHttp),
    ("HttpStream", ModuleClass::ClientHttp),
    // The server surface binds a socket and serves.
    ("Server", ModuleClass::NativeEffect),
    ("Middleware", ModuleClass::NativeEffect),
    ("RateLimit", ModuleClass::NativeEffect),
    ("Stream", ModuleClass::NativeEffect),
    ("Ws", ModuleClass::NativeEffect),
    ("Db", ModuleClass::NativeEffect),
    ("Db.Decode", ModuleClass::NativeEffect),
    ("Sql", ModuleClass::NativeEffect),
    ("Auth", ModuleClass::NativeEffect),
    ("Revocation", ModuleClass::NativeEffect),
    ("App", ModuleClass::Pure),
    ("Host", ModuleClass::Pure),
    ("Console", ModuleClass::Pure),
    ("Background", ModuleClass::Pure),
    ("Border", ModuleClass::Pure),
    ("Font", ModuleClass::Pure),
    ("Region", ModuleClass::Pure),
    ("Input", ModuleClass::Pure),
    ("Lazy", ModuleClass::Pure),
    ("Keyed", ModuleClass::Pure),
    ("Event", ModuleClass::Pure),
    // Shape-render surfaces: governed by the dedicated shape gates.
    ("Web", ModuleClass::Pure),
    ("Tui", ModuleClass::Pure),
    ("Cli", ModuleClass::Pure),
    ("Worker", ModuleClass::Pure),
    ("TeaWebPubSub", ModuleClass::Pure),
    ("TeaWebCmd", ModuleClass::Pure),
    ("TeaWebSub", ModuleClass::Pure),
    ("TeaTerminalCmd", ModuleClass::Pure),
    ("TeaTerminalSub", ModuleClass::Pure),
    ("TeaTuiCmd", ModuleClass::Pure),
    ("TeaTuiSub", ModuleClass::Pure),
    ("TeaCliCmd", ModuleClass::Pure),
    ("TeaCliSub", ModuleClass::Pure),
    ("TeaWorkerCmd", ModuleClass::Pure),
    ("TeaWorkerSub", ModuleClass::Pure),
];

/// How many class rows name `canonical`.
#[allow(clippy::indexing_slicing)] // index guarded by `i < len`
const fn class_rows(rows: &[(&str, ModuleClass)], canonical: &str) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < rows.len() {
        if const_str_eq(rows[i].0, canonical) {
            count += 1;
        }
        i += 1;
    }
    count
}

/// `true` when `canonical` is the canonical of some catalog path.
#[allow(clippy::indexing_slicing)] // index guarded by `i < len`
const fn is_catalog_canonical(catalog: &[(&[&str], &str)], canonical: &str) -> bool {
    let mut i = 0;
    while i < catalog.len() {
        if const_str_eq(catalog[i].1, canonical) {
            return true;
        }
        i += 1;
    }
    false
}

/// `true` when each catalog canonical has one class row and each row names one.
#[allow(clippy::indexing_slicing)] // indices guarded by `i < len`
const fn classes_cover(catalog: &[(&[&str], &str)], rows: &[(&str, ModuleClass)]) -> bool {
    let mut i = 0;
    while i < catalog.len() {
        if class_rows(rows, catalog[i].1) != 1 {
            return false;
        }
        i += 1;
    }
    let mut j = 0;
    while j < rows.len() {
        if !is_catalog_canonical(catalog, rows[j].0) {
            return false;
        }
        j += 1;
    }
    true
}

// The build fails when `CANONICAL_CLASSES` and the catalog drift.
// IPE-RUST-AUDIT:ACCEPTED — this `assert!` runs during const-eval of a `const _`,
// so it fails the build on drift and can never panic at runtime.
const _: () = assert!(
    classes_cover(STDLIB_MODULE_QUALIFIERS, CANONICAL_CLASSES),
    "every STDLIB_MODULE_QUALIFIERS canonical needs exactly one CANONICAL_CLASSES row"
);

/// Classify a standard-library module dot-path into its placement family.
///
/// The path is the dotted form (`"Ipe.Db.Store"`, `"Ipe.Browser.Camera"`,
/// `"String"`). A kernel path (one in [`STDLIB_MODULE_QUALIFIERS`]) classifies
/// by its canonical module through [`CANONICAL_CLASSES`], so two paths onto
/// one module never disagree. Any other path classifies by its first segment
/// after `Ipe.`: native effects (`Ipe.Db` / `Ipe.File` / `Ipe.Auth`), the
/// server under `Ipe.Http.Server`, the client `Ipe.Http`, and browser-host
/// capabilities (`Ipe.Browser.*`); everything else (pure stdlib, and the
/// shape-render surfaces owned by the dedicated shape gates) is
/// [`ModuleClass::Pure`].
///
/// A user/dep module path (not `Ipe.`-prefixed) is likewise [`ModuleClass::Pure`]
/// — a user module carries no stdlib placement constraint of its own, and its
/// own imports are gated when that module is itself resolved.
#[must_use]
pub fn classify(path: &str) -> ModuleClass {
    let kernel_canonical = STDLIB_MODULE_QUALIFIERS
        .iter()
        .find(|(segments, _)| segments.iter().copied().eq(path.split('.')))
        .map(|(_, canonical)| *canonical);
    if let Some(canonical) = kernel_canonical {
        // Unreachable fallback: every catalog canonical has a row (const proof above).
        return CANONICAL_CLASSES
            .iter()
            .find(|(c, _)| *c == canonical)
            .map_or(ModuleClass::NativeEffect, |(_, class)| *class);
    }
    // Non-`Ipe.` paths: the auto-imported pure prelude, or a user/dep module.
    // Neither carries a placement constraint here, so both are treated as pure —
    // a user module's own stdlib imports are gated when it is resolved.
    let Some(rest) = path.strip_prefix("Ipe.") else {
        return ModuleClass::Pure;
    };
    // A compiled-source `Ipe.*` module: the first segment decides the family,
    // so every sub-module of a family (`Ipe.Db`, `Ipe.Db.Store`) shares a row.
    //
    // Division of labour: the SHAPE-RENDER surfaces — the `Ipe.Tea.*` TEA
    // app/Cmd/Sub machinery and the shape view libraries (`Ipe.Ui.*` cells,
    // `Ipe.Html`) — are governed by the dedicated shape gates that already know
    // the shape-fold rules (`Tui`/`Cli` share the terminal view family but each
    // own their `Sub`, `WebView` folds onto `Web`): the resolver's Program/TEA
    // gate (IPE-N0033), the cross-shape `Cmd`/`Sub` gate (IPE-N0035), the
    // runtime-branched-`main` gate (IPE-N0045), and the lowering shape gates for the raw view leaves
    // (IPE-L0132 / IPE-L0153 / IPE-L0147). This table therefore classifies those
    // as [`ModuleClass::Pure`] here to avoid double-gating them with a second,
    // fold-unaware rule. What this table uniquely owns is the placement families
    // with no other gate: native effects and browser-host capabilities.
    let head = rest.split('.').next().unwrap_or(rest);
    match head {
        // Native effects — direct DB, file, server-http, and the secret surface.
        "Db" | "File" | "Auth" | "Server" => ModuleClass::NativeEffect,
        // `Ipe.Http.Server` is a native effect (it binds a socket and serves);
        // the plain client `Ipe.Http` fetch surface is portable.
        "Http" => {
            if rest.starts_with("Http.Server") {
                ModuleClass::NativeEffect
            } else {
                ModuleClass::ClientHttp
            }
        }
        // Web-platform host capabilities — need a JS host.
        "Browser" => ModuleClass::BrowserHost,
        // Every other `Ipe.*` module — pure stdlib, or a shape-render surface
        // owned by the dedicated shape gates above. A NEW restricted-EFFECT
        // module MUST be added as its own head here rather than left to fall
        // through as pure; the runtime-aware wasm link gate (IPE-N0029, a
        // default-deny kernel allowlist) is the defence-in-depth backstop that
        // still refuses an unclassified native kernel in a sandboxed bundle.
        _ => ModuleClass::Pure,
    }
}

/// The single source of truth: is a module of family `class` admissible in
/// `placement`?
///
/// Total and exhaustive over [`ModuleClass`] — there is **no wildcard fallthrough
/// that could silently admit a newly-added family**. Every family names its own
/// arm; adding a [`ModuleClass`] variant forces a decision here.
// `match_same_arms`: `Pure` and `ClientHttp` both resolve to `Allow`, but they
// are distinct families with distinct rationales (a pure module is admissible
// because it has no effect; client HTTP because an outbound request is available
// in every placement). Keeping the arms separate documents that decision and
// forces a fresh judgement if either family's admissibility ever narrows.
#[allow(clippy::match_same_arms)]
#[must_use]
pub const fn allowed_in(class: ModuleClass, placement: Placement) -> Admissibility {
    use Admissibility::{Allow, Deny};
    match class {
        // Pure modules (and shape-render surfaces owned by the dedicated shape
        // gates): admissible everywhere here.
        ModuleClass::Pure => Allow,

        // Browser host capabilities: the Web shape (served on server/desktop or
        // solo browser/ios/android/desktop) has a JS host. The live-rendering
        // terminal shapes never do, so they are rejected. `script` renders nothing and is
        // the build-time harness (decoder probes, export checks) these modules
        // are imported from, so it is exempt — a no-render tool use, not a
        // mis-placed live capability. A server is a `script` too (a `Direct`
        // program running `Server.listen`), so it takes the same exempt arm.
        ModuleClass::BrowserHost => match placement.shape {
            Shape::Web | Shape::Script => Allow,
            Shape::Tui | Shape::Cli | Shape::Worker => {
                Deny(DenyReason::BrowserOutsideBrowserHost { placement })
            }
        },

        // Native effects: co-located only. The security invariant — a native
        // effect (DB handle, secret) must never be emitted into a sandboxed
        // browser bundle. Denied in `solo`; admissible in every co-located
        // runtime (served, terminal, script — a server being a `script`).
        ModuleClass::NativeEffect => match placement.runtime {
            Runtime::Served => Allow,
            Runtime::Solo => Deny(DenyReason::NativeEffectInSandbox),
        },

        // Portable client HTTP fetch: every browser placement and every
        // co-located native placement. Admissible everywhere the program can make
        // an outbound request, which is every placement in the model.
        ModuleClass::ClientHttp => Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn co(shape: Shape) -> Placement {
        Placement {
            shape,
            runtime: Runtime::Served,
        }
    }

    fn web(runtime: Runtime) -> Placement {
        Placement {
            shape: Shape::Web,
            runtime,
        }
    }

    #[test]
    fn pure_modules_are_admissible_everywhere() {
        for path in [
            "String", "List", "Dict", "Json", "Math", "Ipe.Json", "Ipe.Task",
        ] {
            assert_eq!(classify(path), ModuleClass::Pure, "{path}");
        }
        for p in [
            co(Shape::Script),
            co(Shape::Tui),
            co(Shape::Cli),
            co(Shape::Worker),
            web(Runtime::Served),
            web(Runtime::Solo),
        ] {
            assert_eq!(allowed_in(ModuleClass::Pure, p), Admissibility::Allow);
        }
    }

    /// The shape-render surfaces (`Ipe.Tea.*`, `Ipe.Ui.*`, `Ipe.Html`) defer to
    /// the dedicated shape gates, so this table classifies them as `Pure` — it
    /// does not re-gate them with a second, fold-unaware rule.
    #[test]
    fn shape_render_surfaces_defer_to_the_shape_gates_as_pure() {
        for path in [
            "Ipe.Tea.Web",
            "Ipe.Tea.Web.Cmd",
            "Ipe.Tea.Tui",
            "Ipe.Tea.Cli",
            "Ipe.Ui.Cli",
            "Ipe.Tea.Terminal.Cmd",
            "Ipe.Tea.WebView",
            "Ipe.Ui",
            "Ipe.Ui.Cells",
            "Ipe.Html",
        ] {
            assert_eq!(classify(path), ModuleClass::Pure, "{path}");
        }
    }

    #[test]
    fn native_effect_denied_in_solo_allowed_co_located() {
        for path in [
            "Ipe.Db",
            "Ipe.Db.Store",
            "Ipe.File",
            "Ipe.Http.Server",
            "Ipe.Auth",
        ] {
            assert_eq!(classify(path), ModuleClass::NativeEffect, "{path}");
        }
        // Denied in the sandboxed solo runtime — the DB/secret-to-browser leak.
        assert_eq!(
            allowed_in(ModuleClass::NativeEffect, web(Runtime::Solo)),
            Admissibility::Deny(DenyReason::NativeEffectInSandbox)
        );
        // Admissible in every co-located placement — including a worker, whose
        // co-located native effects (DB, file, secret) are allowed.
        for p in [
            co(Shape::Script),
            co(Shape::Tui),
            co(Shape::Cli),
            co(Shape::Worker),
            web(Runtime::Served),
        ] {
            assert_eq!(
                allowed_in(ModuleClass::NativeEffect, p),
                Admissibility::Allow
            );
        }
    }

    /// Every import path of one kernel module classifies alike, so a sibling
    /// spelling (`Ipe.Server.Http`) is never a softer family than its twin.
    #[test]
    fn paths_sharing_a_canonical_classify_alike() {
        let dot = |segments: &[&str]| segments.join(".");
        for (path, canonical) in STDLIB_MODULE_QUALIFIERS {
            for (other, other_canonical) in STDLIB_MODULE_QUALIFIERS {
                if canonical == other_canonical {
                    assert_eq!(
                        classify(&dot(path)),
                        classify(&dot(other)),
                        "{} vs {}",
                        dot(path),
                        dot(other)
                    );
                }
            }
        }
        // The `Ipe.Server.*` spellings reach the native server modules.
        for path in [
            "Ipe.Server",
            "Ipe.Server.Http",
            "Ipe.Server.Middleware",
            "Ipe.Server.RateLimit",
            "Ipe.Server.Stream",
            "Ipe.Server.WebSocket",
        ] {
            assert_eq!(classify(path), ModuleClass::NativeEffect, "{path}");
        }
        // Positive controls: the client surfaces, a pure kernel, and a
        // compiled-source path keep their families.
        assert_eq!(classify("Ipe.Http"), ModuleClass::ClientHttp);
        assert_eq!(classify("Ipe.Http.Stream"), ModuleClass::ClientHttp);
        assert_eq!(classify("Ipe.Crypto"), ModuleClass::Pure);
        assert_eq!(classify("Ipe.Db.Store"), ModuleClass::NativeEffect);
        // A compiled-source `Ipe.Server.*` path outside the kernel catalog
        // still classifies as the native server family.
        assert_eq!(classify("Ipe.Server.Extra"), ModuleClass::NativeEffect);
    }

    /// The coverage check refuses a canonical with no class row, a duplicated
    /// row, and a row naming no canonical.
    #[test]
    fn canonical_class_coverage_refuses_drift() {
        assert!(classes_cover(STDLIB_MODULE_QUALIFIERS, CANONICAL_CLASSES));
        let missing: &[(&[&str], &str)] = &[(&["Ipe", "Nope"], "Nope")];
        assert!(!classes_cover(missing, &[]));
        let catalog: &[(&[&str], &str)] = &[(&["Ipe", "Crypto"], "Crypto")];
        assert!(classes_cover(catalog, &[("Crypto", ModuleClass::Pure)]));
        assert!(!classes_cover(
            catalog,
            &[("Crypto", ModuleClass::Pure), ("Crypto", ModuleClass::Pure)]
        ));
        assert!(!classes_cover(
            catalog,
            &[("Crypto", ModuleClass::Pure), ("Ghost", ModuleClass::Pure)]
        ));
    }

    #[test]
    fn client_http_is_portable_but_server_http_is_native() {
        assert_eq!(classify("Ipe.Http"), ModuleClass::ClientHttp);
        assert_eq!(classify("Ipe.Http.Server"), ModuleClass::NativeEffect);
        // Client fetch is admissible even in the sandbox.
        assert_eq!(
            allowed_in(ModuleClass::ClientHttp, web(Runtime::Solo)),
            Admissibility::Allow
        );
    }

    #[test]
    fn browser_host_needs_a_browser() {
        assert_eq!(
            classify("Ipe.Browser.Geolocation"),
            ModuleClass::BrowserHost
        );
        // Any Web placement has a browser; `script` is the exempt no-render
        // build-time harness.
        for r in [Runtime::Served, Runtime::Solo] {
            assert_eq!(
                allowed_in(ModuleClass::BrowserHost, web(r)),
                Admissibility::Allow
            );
        }
        assert_eq!(
            allowed_in(ModuleClass::BrowserHost, co(Shape::Script)),
            Admissibility::Allow
        );
        // No browser in the terminal and worker shapes. (A server is a `script`,
        // which takes the exempt no-render arm above.)
        for shape in [Shape::Tui, Shape::Cli, Shape::Worker] {
            assert_eq!(
                allowed_in(ModuleClass::BrowserHost, co(shape)),
                Admissibility::Deny(DenyReason::BrowserOutsideBrowserHost {
                    placement: co(shape)
                })
            );
        }
    }

    #[test]
    fn sole_placement_is_none_for_web_some_otherwise() {
        assert_eq!(Placement::sole_for(Shape::Web), None);
        for shape in [Shape::Script, Shape::Tui, Shape::Cli, Shape::Worker] {
            assert_eq!(
                Placement::sole_for(shape),
                Some(Placement {
                    shape,
                    runtime: Runtime::Served
                })
            );
        }
    }
}
