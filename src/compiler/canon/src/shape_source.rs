//! Classify a program's rendering shape from the head of `main`, over the raw
//! parse tree — the single compile-time source of truth the delivery grammar
//! cross-checks against (spec § 0, § 1).
//!
//! A program's shape is pinned by what `main` head-calls, never by config: a
//! `main = Web.tea …` is a DOM app, `main = Tui.tea …` a terminal-cells app,
//! `main = Cli.tea …` a terminal-lines app, and any other `main` (a plain
//! `Task`) a script — a batch tool or an HTTP server (`main = Server.listen …`)
//! alike, since both share the `Task Error ()` interface. This peels the same
//! head-forms the resolver's shape gate peels — application, lambda, and `let` —
//! so the CLI cross-check and the compiler agree on one classification.

use ipe_diagnostics::{Diagnostic, NameError};
use ipe_intern::Interner;
use ipe_syntax::{Exposed, Exposing, Expr, Expr_, Import, Module};

/// The rendering shape a `main` pins, as read from the parse tree.
///
/// Mirrors the delivery grammar's shape axis: the four non-web shapes plus the
/// DOM `Web` shape (the only one with a delivery runtime choice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MainShape {
    /// A plain `main : Task Error ()` — renders nothing.
    Script,
    /// `main = Tui.tea …` — terminal cells.
    Tui,
    /// `main = Cli.tea …` — terminal lines.
    Cli,
    /// `main = Worker.tea …` — the view-less TEA loop (Elm `Platform.worker`):
    /// `init` / `update` / `subscriptions` with no `view`. Co-located and
    /// capability-gated; renders nothing.
    Worker,
    /// `main = Web.tea …` / `appRouted` / `appWith` — the DOM shape. A webview is
    /// a delivery *host* of this shape (`web desktop`), not a distinct shape
    /// (spec § 1).
    Web,
}

/// How a program drives itself, projected from its compiler-pinned [`MainShape`].
///
/// A closed set: every shape maps to exactly one control model, so a disclosure
/// surface (`ipe audit`, `ipe doc`, LSP hover) can name the model without a
/// second derivation that could disagree with the shape the compiler already
/// pinned. This is the single source of truth every such surface reads — none
/// re-inspects `main` on its own; each projects this from [`classify_main_shape`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControlModel {
    /// The Elm-style model/update/(view) loop — a `Web`/`Tui`/`Cli`/`Worker`
    /// shape. The `Worker` corner runs the same managed loop with no `view`.
    Tea,
    /// A plain `main : Task Error ()` that runs directly to completion — a
    /// `Script` shape (a batch tool or a listening `Server.listen` server alike;
    /// server-ness is disclosed on the capability axis, not as a control model).
    Direct,
}

impl ControlModel {
    /// The control model a compiler-pinned [`MainShape`] runs under. A projection
    /// of the shape the compiler already pinned, never a second derivation: a
    /// view-ful shape (`Web`/`Tui`/`Cli`) and the view-less `Worker` run the
    /// Elm-style managed loop; a `Script` (a plain `Task Error ()`) runs directly
    /// to completion, a one-shot batch tool or a listening server alike.
    #[must_use]
    pub const fn from_shape(shape: MainShape) -> Self {
        match shape {
            MainShape::Web | MainShape::Tui | MainShape::Cli | MainShape::Worker => Self::Tea,
            MainShape::Script => Self::Direct,
        }
    }

    /// The canonical word for this control model — the one vocabulary shared by
    /// the audit disclosure, its JSON verdict, the consent gate, `ipe doc`, LSP
    /// hover, and docs.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Tea => "tea",
            Self::Direct => "direct",
        }
    }

    /// Parse a control-model word (the inverse of [`Self::word`]). `None` for any
    /// token outside the closed set — a consumer's `acceptsControl` entry that is
    /// not a known model must be rejected, never read as a permissive default.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "tea" => Self::Tea,
            "direct" => Self::Direct,
            _ => return None,
        })
    }

    /// Whether this control model is a *managed* one — the runtime drives the
    /// loop and every effect flows through a capability axis already gated. The
    /// managed model (`Tea`) is the safe, implicitly-admitted default; only the
    /// elevated [`Self::Direct`] model (a self-driving `Task Error ()` program
    /// outside the managed loop) requires a consumer's explicit consent.
    #[must_use]
    pub const fn is_managed(self) -> bool {
        matches!(self, Self::Tea)
    }
}

/// A `main` head that head-calls one of these `(canonical-module-path, name)`
/// pairs pins the paired shape. The first element is the head's *canonical
/// module* — the full dotted stdlib path the written qualifier resolves to
/// through the import table (`Ipe.Tea.Web` for a `Web`/aliased head), NEVER the
/// written qualifier token, which may be an alias (`import … as W`) or
/// accidentally collide with a user module's leaf (`Acme.Web`). Matching the
/// resolved canonical path — not the spelling — is what closes the alias/rename
/// gap and the leaf-collision gap (issue #2142).
///
/// Every row is a TEA app entry under `Ipe.Tea.*`. A `Server.listen` head is
/// NOT here: a server is a plain `Task Error ()` `Direct` program (spelled
/// `script`), disclosed on the capability axis, so it falls through to
/// [`MainShape::Script`] like any other bare `Task`.
///
/// This table and the resolver's `TEA_APP_ENTRIES` are held in agreement by a
/// build-time relation (a `const` bijection assertion in `resolve`), not by
/// prose: the `Ipe.Tea.*` rows here — keyed by canonical path — must be exactly
/// the `TEA_APP_ENTRIES` rows keyed by `(last-path-segment, name)`. A one-sided
/// edit fails compilation.
pub(crate) const SHAPE_ENTRIES: &[(&[&str], &str, MainShape)] = &[
    (&["Ipe", "Tea", "Web"], "tea", MainShape::Web),
    (&["Ipe", "Tea", "Web"], "appRouted", MainShape::Web),
    (&["Ipe", "Tea", "Web"], "appWith", MainShape::Web),
    (&["Ipe", "Tea", "Tui"], "tea", MainShape::Tui),
    (&["Ipe", "Tea", "Cli"], "tea", MainShape::Cli),
    // `Ipe.Tea.Worker.tea` — the view-less worker app-entry: the no-view corner
    // of the TEA loop. It pins the first-class `MainShape::Worker`, whose control
    // model discloses as `Tea` (a managed `init`/`update`/`subscriptions` loop),
    // not `Direct`. A worker is co-located and capability-gated: its runtime is
    // fixed to `Served` (never the sandboxed `Solo` — no view sink, no wasm
    // bundle path, which stays behind the closed `Ipe.Tea.Web` shape entry).
    (&["Ipe", "Tea", "Worker"], "tea", MainShape::Worker),
];

/// Classify a parsed module's `main` into its pinned [`MainShape`].
///
/// Returns [`MainShape::Script`] for a module that defines no `main`, or a
/// `main` whose head is not one of the shape-entry kernels — a plain `Task`
/// program renders nothing. A shape-entry head pins the paired shape.
///
/// The head is found by peeling the same forms the resolver's shape gate peels:
/// `entry cfg` (the callee is the head), `\arg -> entry cfg` (the lambda body),
/// and `let … in entry cfg` (the `in` body). A qualified head (`Web.tea`) and a
/// bare head brought into scope by `import Ipe.Tea.Web exposing (tea)` classify
/// identically. Any other head is a script.
#[must_use]
pub fn classify_main_shape(module: &Module, interner: &Interner) -> MainShape {
    let Some(main_sym) = interner.lookup("main") else {
        return MainShape::Script; // `main` never interned → no entry here.
    };
    let Some(value) = module
        .values
        .iter()
        .find(|v| v.value.name.value == main_sym)
    else {
        return MainShape::Script; // helper module with no `main`.
    };
    // A `main x = …` binding with argument patterns is desugared to a lambda
    // head; classify its body head the same way as a `main = \x -> …`.
    head_shape(&value.value.body, module, interner).unwrap_or(MainShape::Script)
}

/// The render-to-`String` sink for a shape's view: the canonical module that
/// exposes the serialiser turning a built view into a `String` (or writing it
/// out), and the entry names that do so. A Script that references such a sink
/// CONSUMES the view rather than dropping it — the static-site-generation case —
/// so IPE-N0050 does not fire for the paired shape-UI library.
///
/// `Ipe.Html` re-exposes the native serialiser (`render` / `toString` / their
/// pipeline-spelled aliases) and the render sink `renderStatic`; a `web`-shape UI
/// (`Ipe.Ui` → `Ui.layout` → `Html`, or `Ipe.Html` directly) reaches a `String`
/// through it. A row is [`None`] when the shape has no `String` sink at all
/// (`Ipe.Ui.Cells` builds a `Screen` only a `Tui.tea` renders), so that UI is
/// ALWAYS genuinely dropped in a Script and always warns.
#[derive(Clone, Copy)]
struct RenderSink {
    /// Canonical dotted path of the module exposing the sink (`Ipe.Html`).
    module: &'static [&'static str],
    /// Entry names on `module` that consume a view into a `String` / render sink.
    entries: &'static [&'static str],
}

/// The `web`-shape render-to-`String` sink: `Ipe.Html`'s re-exposed serialiser
/// and render sink. Kept in lockstep with `Ipe/Html.ipe`'s exposed
/// `render` / `renderStatic` / `toString` / `htmlRender`.
const WEB_RENDER_SINK: RenderSink = RenderSink {
    module: &["Ipe", "Html"],
    entries: &["render", "renderStatic", "toString", "htmlRender"],
};

/// A top-level shape view/UI library, the shape whose app entry renders it, and
/// the render-to-`String` sink (if any) that lets a Script consume it.
/// These are the shape-agnostic-*looking* but shape-render surfaces a Script may
/// legally import (they are NOT under `Ipe.Tea.*`, so IPE-N0033 does not fire),
/// yet a Script has no `view` to hand them to. Each row names the shape, the app
/// entry that WOULD render this UI, and the [`RenderSink`] that turns it into a
/// `String` — `None` when the shape has no `String` sink.
const SHAPE_VIEW_LIBRARIES: &[(&[&str], &str, &str, Option<RenderSink>)] = &[
    // `Ipe.Ui` / `Ipe.Html` build the DOM view a `Web.tea` renders; both reach a
    // `String` through `Ipe.Html`'s serialiser, so a static-site Script consumes
    // them.
    (&["Ipe", "Ui"], "web", "Web.tea", Some(WEB_RENDER_SINK)),
    (&["Ipe", "Html"], "web", "Web.tea", Some(WEB_RENDER_SINK)),
    // `Ipe.Ui.Cells` builds the terminal-cells view a `Tui.tea` renders; it has
    // no `String` sink, so in a Script it is always genuinely dropped.
    (&["Ipe", "Ui", "Cells"], "terminal", "Tui.tea", None),
];

/// The Script-hole hint (IPE-N0050): a **Warning** for a Script that imports a
/// shape's view/UI library but never renders it.
///
/// Being a Script (a plain-`Task` `main`), any view it builds cannot be rendered,
/// so that UI is genuinely dropped.
///
/// Returns `None` for any non-Script `main` (an app renders its view; no hole),
/// a Script that imports no shape view library (nothing built to drop), or a
/// Script that DOES consume the built view through a render-to-`String` sink —
/// static-site generation (`Ui.layout`/`Html` → `Html.render` → a `String` it
/// prints or writes). When it does fire, the returned [`Diagnostic`] is
/// `Severity::Warning`: a Script is a legal program, so this HINTS the
/// likely-intended `<Shape>.tea` entry rather than rejecting. Emit it into the
/// compiler's warning channel; it must never fail the build.
///
/// The carve-out is structural, not heuristic: the hint is withheld only when a
/// reference in the program resolves — through the import table, exactly as name
/// resolution does — to the paired shape's [`RenderSink`] (`Ipe.Html`'s
/// serialiser). A bare `render` from an unrelated module, or a `H.render` whose
/// `H` does not resolve to `Ipe.Html`, is NOT a sink, so the view stays dropped
/// and the hint stands (fail-closed: absent proof the view is consumed, warn).
///
/// This is deliberately distinct from IPE-N0033: that gate is a hard error for a
/// Script importing the live-loop machinery under `Ipe.Tea.*`; this hint is for a
/// Script importing a top-level *view* library (`Ipe.Ui` / `Ipe.Html` /
/// `Ipe.Ui.Cells`), which is legal but almost certainly a mistake.
#[must_use]
pub fn script_view_hole_hint(module: &Module, interner: &Interner) -> Option<Diagnostic> {
    if classify_main_shape(module, interner) != MainShape::Script {
        return None; // an app renders its view — no hole.
    }
    // A Script with no `main` at all cannot mean to render anything.
    let main_sym = interner.lookup("main")?;
    if !module.values.iter().any(|v| v.value.name.value == main_sym) {
        return None;
    }
    for import in &module.imports {
        let Some(path) = module_path_segments(import, interner) else {
            continue;
        };
        if let Some((_, shape, entry, sink)) = SHAPE_VIEW_LIBRARIES
            .iter()
            .find(|(lib_path, _, _, _)| path_eq(lib_path, &path))
        {
            // A render-to-`String` sink for this shape, referenced anywhere in
            // the program, CONSUMES the view — the static-site case — so the view
            // is not dropped and no hole is reported.
            if sink.is_some_and(|s| program_references_sink(&s, module, interner)) {
                continue;
            }
            let shape_ui_module = path.join(".").into_boxed_str();
            return Some(Diagnostic::Name {
                span: import.name.span,
                msg: NameError::ScriptImportsShapeView {
                    shape_ui_module,
                    shape: (*shape).into(),
                    entry: (*entry).into(),
                },
            });
        }
    }
    None
}

/// Does any value body in the module reference this render-to-`String` [`RenderSink`]?
///
/// A reference counts only when it resolves — through the same import table name
/// resolution uses elsewhere in this module — to a `sink.entries` name on
/// `sink.module`: a qualified `H.render` whose `H` resolves to `sink.module`, or
/// a bare `render` an `import <sink.module> exposing (render)` brings into scope.
/// A like-spelled name from any other module is not the sink (fail-closed).
fn program_references_sink(sink: &RenderSink, module: &Module, interner: &Interner) -> bool {
    module
        .values
        .iter()
        .any(|value| expr_references_sink(&value.value.body, sink, module, interner))
}

/// Walk an expression tree for a reference to the [`RenderSink`], resolving each
/// candidate name through the module's imports.
fn expr_references_sink(
    expr: &Expr,
    sink: &RenderSink,
    module: &Module,
    interner: &Interner,
) -> bool {
    let hit_here = match &expr.value {
        // `H.render` — the qualifier must resolve to the sink module and the name
        // must be one of its consuming entries.
        Expr_::VarQual(qual, name) => name_is_sink_qualified(*qual, *name, sink, module, interner),
        // A bare `render` — a sink hit only when an exposing import of the sink
        // module brings that exact name into scope.
        Expr_::VarLocal(name) => name_is_sink_exposed(*name, sink, module, interner),
        _ => false,
    };
    if hit_here {
        return true;
    }
    // Recurse over every sub-expression. New `Expr_` variants must be added here;
    // an unhandled variant is a compile error, never a silently-missed sink.
    match &expr.value {
        Expr_::VarLocal(_)
        | Expr_::VarQual(_, _)
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::Unit => false,
        Expr_::Call(callee, args) => {
            expr_references_sink(callee, sink, module, interner)
                || args
                    .iter()
                    .any(|a| expr_references_sink(a, sink, module, interner))
        }
        Expr_::Case(scrutinee, arms) => {
            expr_references_sink(scrutinee, sink, module, interner)
                || arms
                    .iter()
                    .any(|(_, body)| expr_references_sink(body, sink, module, interner))
        }
        Expr_::Lambda(_, body) => expr_references_sink(body, sink, module, interner),
        Expr_::Binops(chain, last) => {
            chain
                .iter()
                .any(|(operand, _)| expr_references_sink(operand, sink, module, interner))
                || expr_references_sink(last, sink, module, interner)
        }
        Expr_::Let(bindings, body) => {
            bindings
                .iter()
                .any(|b| expr_references_sink(&b.body, sink, module, interner))
                || expr_references_sink(body, sink, module, interner)
        }
        Expr_::If(branches, else_) => {
            branches.iter().any(|(cond, branch)| {
                expr_references_sink(cond, sink, module, interner)
                    || expr_references_sink(branch, sink, module, interner)
            }) || expr_references_sink(else_, sink, module, interner)
        }
        Expr_::Tuple(elems) | Expr_::List(elems) => elems
            .iter()
            .any(|e| expr_references_sink(e, sink, module, interner)),
        Expr_::Record(fields) => fields
            .iter()
            .any(|(_, value)| expr_references_sink(value, sink, module, interner)),
        Expr_::Update(_, fields) => fields
            .iter()
            .any(|(_, value)| expr_references_sink(value, sink, module, interner)),
        Expr_::Access(base, _) => expr_references_sink(base, sink, module, interner),
    }
}

/// Does the qualified reference `qualifier.name` name a `sink.entries` entry on
/// `sink.module`, resolving `qualifier` through the import table (as
/// [`shape_for_qualified`] does)? An alias or leaf that resolves to any other
/// module is not the sink.
fn name_is_sink_qualified(
    qualifier: ipe_intern::Symbol,
    name: ipe_intern::Symbol,
    sink: &RenderSink,
    module: &Module,
    interner: &Interner,
) -> bool {
    let (Some(qual), Some(name)) = (interner.resolve(qualifier), interner.resolve(name)) else {
        return false;
    };
    if !sink.entries.contains(&name) {
        return false;
    }
    resolve_qualifier_to_module_path(qual, module, interner)
        .is_some_and(|path| path_eq(sink.module, &path))
}

/// Does a bare reference `name` resolve to a `sink.entries` entry on `sink.module`
/// through an `import <sink.module> exposing (name)` (as [`shape_for_exposed`]
/// does)? Only an explicit exposing list binds a bare name here.
fn name_is_sink_exposed(
    name: ipe_intern::Symbol,
    sink: &RenderSink,
    module: &Module,
    interner: &Interner,
) -> bool {
    let Some(name) = interner.resolve(name) else {
        return false;
    };
    if !sink.entries.contains(&name) {
        return false;
    }
    module.imports.iter().any(|import| {
        import_exposes_value(import, name, interner)
            && module_path_segments(import, interner)
                .is_some_and(|path| path_eq(sink.module, &path))
    })
}

/// Peel a `main` body to its head reference and match it against the shape
/// entries. `None` when the head is not a shape-entry reference.
///
/// A head is a shape entry either qualified — `Web.tea`, or an aliased `W.tea`
/// from `import Ipe.Tea.Web as W` — or unqualified through an
/// `import Ipe.Tea.Web exposing (tea)` that brings the entry into scope under
/// its bare name. A qualified head's written qualifier is resolved through the
/// import table to the *canonical module* it names, then matched — never the
/// written token — so an alias or rename classifies identically to the
/// written-out module (issue #2142). An unqualified head is resolved the same way
/// its exposing import binds it.
fn head_shape(body: &Expr, module: &Module, interner: &Interner) -> Option<MainShape> {
    let mut node = body;
    loop {
        match &node.value {
            // `entry cfg` — the callee is the head.
            Expr_::Call(callee, _) => node = callee,
            // `\arg -> entry cfg` (lambda body) and `let … in entry cfg` (the
            // `in` body) both peel to the inner expression.
            Expr_::Lambda(_, inner) | Expr_::Let(_, inner) => node = inner,
            // `Web.tea` / `W.tea` (alias) at the head pins its shape — but only
            // after the written qualifier is resolved to the canonical module it
            // imports; a spelling match would break on rename.
            Expr_::VarQual(qual, name) => {
                let (q, n) = (interner.resolve(*qual)?, interner.resolve(*name)?);
                return shape_for_qualified(q, n, module, interner);
            }
            // A bare `app` head: pinned iff exactly one exposing import brings a
            // shape entry of that name into scope (fail-closed on none/ambiguity).
            Expr_::VarLocal(name) => {
                let n = interner.resolve(*name)?;
                return shape_for_exposed(n, module, interner);
            }
            _ => return None,
        }
    }
}

/// The shape a qualified head `qualifier.name` pins, resolving `qualifier`
/// through the import table to the canonical module it names before matching.
///
/// `qualifier` is the *written* token at the call site — a module leaf
/// (`Web` from `import Ipe.Tea.Web`) or an alias (`W` from `… as W`). We
/// resolve it exactly as name resolution would: the import whose `as` alias is
/// `qualifier`, or, absent an alias, whose module-path leaf is `qualifier`, names
/// the canonical module; that module's FULL dotted path keys the shape table.
/// Matching the full canonical path closes both gaps of #2142: an alias
/// (`W.tea` → `Ipe.Tea.Web.tea` → Web) and a like-spelled user module
/// (`Acme.Web.tea` does NOT resolve to `Ipe.Tea.Web`, so it stays a Script).
///
/// Fail-safe: a qualifier no import in scope names (a bare reference that never
/// resolves) pins no shape (`None`) — the least-capability Script posture, never
/// a panic.
fn shape_for_qualified(
    qualifier: &str,
    name: &str,
    module: &Module,
    interner: &Interner,
) -> Option<MainShape> {
    let canonical_path = resolve_qualifier_to_module_path(qualifier, module, interner)?;
    shape_for_path(&canonical_path, name)
}

/// Resolve a written qualifier token to the dotted segments of the canonical
/// module it names, via the import table.
///
/// An `import M as A` binds the qualifier `A` to module `M`; an `import M` with
/// no alias binds `M`'s own leaf segment. So a written `qualifier` names the
/// canonical module of the first import whose alias equals it, or — when it
/// matches no alias — whose module-path leaf equals it. Returns that module's
/// full dotted path (`["Ipe", "Tea", "Web"]`), which keys [`SHAPE_ENTRIES`].
///
/// Returns `None` when no import in scope names the qualifier (fail-safe to
/// Script, never a panic). An alias always shadows a leaf of the same spelling
/// (name resolution's rule), so aliases are scanned before bare-leaf imports.
fn resolve_qualifier_to_module_path(
    qualifier: &str,
    module: &Module,
    interner: &Interner,
) -> Option<Vec<String>> {
    // An `as` alias binds the qualifier directly to its module; it shadows any
    // like-spelled bare-leaf import, so aliases win.
    for import in &module.imports {
        if import
            .alias
            .and_then(|alias_sym| interner.resolve(alias_sym))
            == Some(qualifier)
        {
            return module_path_segments(import, interner);
        }
    }
    // No alias claims the qualifier: it must be a module's own leaf, brought into
    // scope by an un-aliased `import M`.
    for import in &module.imports {
        if import.alias.is_some() {
            continue;
        }
        if import
            .name
            .value
            .last()
            .and_then(|leaf| interner.resolve(*leaf))
            == Some(qualifier)
        {
            return module_path_segments(import, interner);
        }
    }
    None
}

/// The dotted path segments of an import's module name, or `None` if any segment
/// fails to resolve in the interner (fail-safe, never a panic).
fn module_path_segments(import: &Import, interner: &Interner) -> Option<Vec<String>> {
    import
        .name
        .value
        .iter()
        .map(|seg| interner.resolve(*seg).map(str::to_owned))
        .collect()
}

/// The shape a `(canonical-module-path, name)` head reference pins, or `None`
/// when the pair is not a shape-entry kernel. Matches the full dotted path, so a
/// user module that merely shares a leaf segment never masquerades as a shape.
fn shape_for_path(path: &[String], name: &str) -> Option<MainShape> {
    SHAPE_ENTRIES
        .iter()
        .find(|(module_path, n, _)| *n == name && path_eq(module_path, path))
        .map(|(_, _, shape)| *shape)
}

/// Segment-wise string equality between a static shape-module path and a
/// resolved import path.
fn path_eq(shape_path: &[&str], resolved: &[String]) -> bool {
    shape_path.len() == resolved.len()
        && shape_path
            .iter()
            .zip(resolved)
            .all(|(s, r)| *s == r.as_str())
}

/// The shape an unqualified head name pins by being exposed from a shape module.
///
/// The name is resolved exactly as name resolution would: each `import M
/// exposing (name)` binds `name` to `M`'s member, whose qualified spelling is
/// `<leaf(M)>.name`. Matching that against the shape entries pins the shape.
/// Fail-closed: a name no exposing import brings into scope, or one that two
/// imports expose to different shapes, stays a script (`None`).
fn shape_for_exposed(name: &str, module: &Module, interner: &Interner) -> Option<MainShape> {
    let mut pinned: Option<MainShape> = None;
    for import in &module.imports {
        if !import_exposes_value(import, name, interner) {
            continue;
        }
        let Some(path) = module_path_segments(import, interner) else {
            continue;
        };
        if let Some(shape) = shape_for_path(&path, name) {
            match pinned {
                // A second, differently-shaped exposing import is ambiguous —
                // fail closed rather than guess a shape.
                Some(prior) if prior != shape => return None,
                _ => pinned = Some(shape),
            }
        }
    }
    pinned
}

/// Does this `import M exposing (name)` bring the value `name` into unqualified
/// scope? Only an explicit `exposing (…, name, …)` list counts: an open
/// `exposing (..)` on a stdlib module is a resolver no-op, so it binds no bare
/// name here either.
fn import_exposes_value(import: &Import, name: &str, interner: &Interner) -> bool {
    let Exposing::List(items) = &import.exposing.value else {
        return false;
    };
    items.iter().any(|item| {
        matches!(&item.value, Exposed::Value(sym)
            if interner.resolve(*sym) == Some(name))
    })
}

/// A **lenient** shape read for scaffolding UX only — NOT a capability gate.
///
/// [`classify_main_shape`] resolves a head's written qualifier through the import
/// table (the strict rule the capability gate keys on: an alias must not smuggle a
/// shape). That strictness is right for gating but wrong for `ipe init`'s
/// scaffold-detection, which runs against a *partially written* `src/Main.ipe`
/// that may spell `main = Tui.tea config` before its `import Ipe.Tea.Tui` line is
/// typed. There the strict classifier reads Script (no import to resolve), and the
/// re-run guard would stop recognising the project's shape.
///
/// So this reads the shape by the *written* head qualifier's leaf spelling
/// (`Tui.tea`/`Web.tea`/`Cli.tea`/`Worker.tea`), matching the shape entries by
/// their module leaf and entry name, without requiring the import to resolve. It
/// exists purely to pick a scaffold template / detect a re-run conflict — a wrong
/// read scaffolds the wrong thing or misses a conflict, it can NEVER escalate a
/// capability. It must never be used where a capability decision is made; use
/// [`classify_main_shape`] there.
#[must_use]
pub fn scaffold_shape_hint(module: &Module, interner: &Interner) -> MainShape {
    let Some(main_sym) = interner.lookup("main") else {
        return MainShape::Script;
    };
    let Some(value) = module
        .values
        .iter()
        .find(|v| v.value.name.value == main_sym)
    else {
        return MainShape::Script;
    };
    lenient_head_shape(&value.value.body, interner).unwrap_or(MainShape::Script)
}

/// Peel a `main` body to its head the same way [`head_shape`] does, but classify
/// a qualified head by the written qualifier's leaf spelling — no import
/// resolution. Scaffolding-only (see [`scaffold_shape_hint`]).
fn lenient_head_shape(body: &Expr, interner: &Interner) -> Option<MainShape> {
    let mut node = body;
    loop {
        match &node.value {
            Expr_::Call(callee, _) => node = callee,
            Expr_::Lambda(_, inner) | Expr_::Let(_, inner) => node = inner,
            Expr_::VarQual(qual, name) => {
                let (q, n) = (interner.resolve(*qual)?, interner.resolve(*name)?);
                return shape_for_written_leaf(q, n);
            }
            _ => return None,
        }
    }
}

/// The shape a `leaf.name` head spells, matching the written qualifier leaf and
/// entry name against the shape entries' module leaf and name. Lenient: it does
/// not confirm the qualifier resolves to the shape module, so it must never gate a
/// capability (see [`scaffold_shape_hint`]).
fn shape_for_written_leaf(qualifier_leaf: &str, name: &str) -> Option<MainShape> {
    SHAPE_ENTRIES
        .iter()
        .find(|(module_path, n, _)| *n == name && module_path.last() == Some(&qualifier_leaf))
        .map(|(_, _, shape)| *shape)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(src: &str) -> MainShape {
        let mut interner = Interner::new();
        let module = ipe_parse::parse_module(src, &mut interner).expect("parse");
        classify_main_shape(&module, &interner)
    }

    fn script_hole(src: &str) -> Option<Diagnostic> {
        let mut interner = Interner::new();
        let module = ipe_parse::parse_module(src, &mut interner).expect("parse");
        script_view_hole_hint(&module, &interner)
    }

    #[test]
    fn control_model_is_the_projection_of_the_pinned_shape() {
        // The disclosure vocabulary and the shape→model projection are one
        // definition here; audit/doc/LSP read it, never re-derive it.
        assert_eq!(ControlModel::from_shape(MainShape::Web), ControlModel::Tea);
        assert_eq!(ControlModel::from_shape(MainShape::Tui), ControlModel::Tea);
        assert_eq!(ControlModel::from_shape(MainShape::Cli), ControlModel::Tea);
        assert_eq!(
            ControlModel::from_shape(MainShape::Worker),
            ControlModel::Tea
        );
        assert_eq!(
            ControlModel::from_shape(MainShape::Script),
            ControlModel::Direct
        );

        assert_eq!(ControlModel::Tea.word(), "tea");
        assert_eq!(ControlModel::Direct.word(), "direct");

        // `word` and `from_word` are exact inverses over the closed set, and no
        // out-of-set token parses (fail-closed — never a permissive default). The
        // retired `server` model no longer parses.
        for m in [ControlModel::Tea, ControlModel::Direct] {
            assert_eq!(ControlModel::from_word(m.word()), Some(m));
        }
        assert_eq!(ControlModel::from_word("server"), None);
        assert_eq!(ControlModel::from_word("library"), None);
        assert_eq!(ControlModel::from_word(""), None);

        // Only the managed TEA loop is implicitly admitted; a `Direct` program
        // (a `Task Error ()` run to completion — a batch tool or a listening
        // server alike) requires a consumer's explicit consent.
        assert!(ControlModel::Tea.is_managed());
        assert!(!ControlModel::Direct.is_managed());
    }

    #[test]
    fn worker_head_classifies_worker_and_discloses_tea_never_web() {
        use crate::shape_runtime::{Placement, Runtime, Shape};
        // A `Worker.tea { … }` head pins the first-class `Worker` shape — the
        // view-less corner of the TEA loop. Its control model discloses as `Tea`
        // (a managed `init`/`update`/`subscriptions` loop), NOT `Direct`. A worker
        // is never Web, so it can never reach the Solo/wasm sandbox path (gated
        // behind the closed `Ipe.Tea.Web` shape entry): NO `SHAPE_ENTRIES` row maps
        // a worker to `MainShape::Web`.
        let shape = classify(
            "module Main exposing (..)\n\nimport Ipe.Tea.Worker\n\nmain = Worker.tea cfg\n",
        );
        assert_eq!(shape, MainShape::Worker);
        assert_ne!(shape, MainShape::Web);
        assert_eq!(
            ControlModel::from_shape(shape),
            ControlModel::Tea,
            "a worker discloses as the managed TEA loop, not a run-to-completion program"
        );
        // The co-located placement is the ONLY one a worker can hold: `sole_for`
        // fixes its runtime to `Served`, so `Runtime::Solo` — the sandbox — is
        // unrepresentable for a worker (no view sink, no wasm bundle path).
        let placement = Placement::sole_for(Shape::from_main(shape))
            .expect("a worker has a sole co-located placement");
        assert_eq!(placement.runtime, Runtime::Served);
        assert_ne!(placement.runtime, Runtime::Solo);
    }

    #[test]
    fn aliased_worker_head_classifies_worker() {
        // Resolve-not-spell (#2142) applies to the worker entry too: an `as W`
        // alias resolving to `Ipe.Tea.Worker` classifies the `Worker` shape.
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Tea.Worker as W\n\nmain = W.tea cfg\n"
            ),
            MainShape::Worker
        );
    }

    #[test]
    fn plain_task_main_is_script() {
        assert_eq!(
            classify("module Main exposing (..)\n\nmain = Io.println \"hi\"\n"),
            MainShape::Script
        );
    }

    #[test]
    fn no_main_is_script() {
        assert_eq!(
            classify("module Helper exposing (..)\n\nhelper = 1\n"),
            MainShape::Script
        );
    }

    #[test]
    fn web_app_head_is_web() {
        assert_eq!(
            classify("module Main exposing (..)\n\nimport Ipe.Tea.Web\n\nmain = Web.tea cfg\n"),
            MainShape::Web
        );
    }

    #[test]
    fn tui_and_cli_heads() {
        assert_eq!(
            classify("module Main exposing (..)\n\nimport Ipe.Tea.Tui\n\nmain = Tui.tea cfg\n"),
            MainShape::Tui
        );
        assert_eq!(
            classify("module Main exposing (..)\n\nimport Ipe.Tea.Cli\n\nmain = Cli.tea cfg\n"),
            MainShape::Cli
        );
    }

    #[test]
    fn server_listen_head_is_script() {
        // A `Server.listen` main is a plain `Task Error ()` — the SAME interface
        // as a batch script — so it classifies `Script` (the `Direct` bucket),
        // NOT a distinct shape. Server-ness is disclosed on the capability axis
        // (`Server.listen` classifies `Capability::Network`), never as a shape or
        // a control model.
        let shape = classify(
            "module Main exposing (..)\n\nimport Ipe.Http.Server\n\nmain = Server.listen cfg\n",
        );
        assert_eq!(shape, MainShape::Script);
        assert_eq!(ControlModel::from_shape(shape), ControlModel::Direct);
    }

    #[test]
    fn bare_task_main_is_script() {
        // A Direct program's `main` is a bare `Task Error ()` — it names no shape
        // entry at its head, so it classifies Script. This is the Direct posture:
        // a script, server body, or batch job that renders nothing needs no
        // wrapper to pin its shape; the absence of a shape entry IS the pin.
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Io as Io\n\nmain = Io.println \"hi\"\n"
            ),
            MainShape::Script
        );
    }

    #[test]
    fn non_shape_qualified_head_is_script() {
        // A qualified head whose resolved module is not a shape entry stays
        // Script — the least-capability posture, never a guessed shape.
        assert_eq!(
            classify("module Main exposing (..)\n\nimport Acme.Batch\n\nmain = Batch.run cfg\n"),
            MainShape::Script
        );
    }

    #[test]
    fn aliased_server_listen_head_is_script() {
        // A `Server.listen` head — however imported or aliased — is a plain
        // `Task Error ()`, so it classifies `Script` (the `Direct` bucket): the
        // shape table holds no server row to key on. An `import … as S` alias
        // resolves the same way and lands in the same bucket.
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Http.Server as S\n\nmain = S.listen cfg\n"
            ),
            MainShape::Script
        );
    }

    #[test]
    fn aliased_web_app_head_is_web() {
        // The same resolve-not-spell rule for a renamed Web import: `as W` +
        // `main = W.tea …` classifies Web because `W` resolves to `Ipe.Tea.Web`.
        assert_eq!(
            classify("module Main exposing (..)\n\nimport Ipe.Tea.Web as W\n\nmain = W.tea cfg\n"),
            MainShape::Web
        );
    }

    #[test]
    fn qualifier_matching_shape_leaf_by_spelling_only_stays_script() {
        // A qualifier that spells `Server` but names a DIFFERENT module (no
        // `Ipe.Http.Server` import in scope) must NOT classify Server — the
        // resolve-not-spell rule fails safe to Script. Here `Server` is the leaf
        // of an unrelated `Acme.Server` import, whose `listen` is not the shape
        // kernel.
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Acme.Server\n\nmain = Server.listen cfg\n"
            ),
            MainShape::Script
        );
    }

    fn scaffold_hint(src: &str) -> MainShape {
        let mut interner = Interner::new();
        let module = ipe_parse::parse_module(src, &mut interner).expect("parse");
        scaffold_shape_hint(&module, &interner)
    }

    #[test]
    fn scaffold_hint_reads_a_written_head_without_its_import() {
        // A partially written entry — `Tui.tea` before its `import Ipe.Tea.Tui`
        // line is typed — reads its shape leniently for scaffold detection, where
        // the strict gate classifier correctly fails safe to Script. The two must
        // disagree here: the gate stays strict, the UX read is lenient.
        let src = "module Main exposing (main)\n\nmain =\n    Tui.tea config\n";
        assert_eq!(scaffold_hint(src), MainShape::Tui);
        assert_eq!(classify(src), MainShape::Script);
    }

    #[test]
    fn scaffold_hint_stays_script_for_a_plain_task_and_a_bare_head() {
        // The lenient read is qualified-head-only: a plain Task or an unqualified
        // head is not confidently a shape.
        assert_eq!(
            scaffold_hint("module Main exposing (main)\n\nmain = Io.println \"hi\"\n"),
            MainShape::Script
        );
        assert_eq!(
            scaffold_hint("module Main exposing (main)\n\nmain =\n    app config\n"),
            MainShape::Script
        );
    }

    #[test]
    fn scaffold_hint_does_not_confuse_a_like_spelled_leaf_across_shapes() {
        // Every shape leaf reads its own shape; a non-shape head stays Script.
        assert_eq!(
            scaffold_hint("module Main exposing (main)\n\nmain = Web.tea config\n"),
            MainShape::Web
        );
        assert_eq!(
            scaffold_hint("module Main exposing (main)\n\nmain = Cli.tea config\n"),
            MainShape::Cli
        );
        assert_eq!(
            scaffold_hint("module Main exposing (main)\n\nmain = Worker.tea config\n"),
            MainShape::Worker
        );
        // A `Server.listen` head is not a shape entry — it scaffolds as the
        // `Direct` bucket (`script`), like any other bare `Task`.
        assert_eq!(
            scaffold_hint("module Main exposing (main)\n\nmain = Server.listen config\n"),
            MainShape::Script
        );
        assert_eq!(
            scaffold_hint("module Main exposing (main)\n\nmain = Widget.app config\n"),
            MainShape::Script
        );
    }

    #[test]
    fn let_bound_config_still_classifies() {
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Tea.Web\n\nmain =\n    let cfg = { init = () }\n    in Web.tea cfg\n"
            ),
            MainShape::Web
        );
    }

    #[test]
    fn app_with_head_classifies_web() {
        assert_eq!(
            classify("module Main exposing (..)\n\nimport Ipe.Tea.Web\n\nmain = Web.appWith cfg\n"),
            MainShape::Web
        );
    }

    #[test]
    fn exposed_bare_app_head_classifies_web() {
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Tea.Web exposing (tea)\n\nmain = tea cfg\n"
            ),
            MainShape::Web
        );
    }

    #[test]
    fn exposed_bare_app_head_from_tui_classifies_tui() {
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Tea.Tui exposing (tea)\n\nmain = tea cfg\n"
            ),
            MainShape::Tui
        );
    }

    #[test]
    fn exposed_bare_app_through_let_classifies_web() {
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Tea.Web exposing (tea)\n\nmain =\n    let cfg = { init = () }\n    in tea cfg\n"
            ),
            MainShape::Web
        );
    }

    #[test]
    fn bare_app_with_no_shape_import_stays_script() {
        // Fail-closed: nothing brings `app` into scope from a shape module.
        assert_eq!(
            classify("module Main exposing (..)\n\nmain = app cfg\n"),
            MainShape::Script
        );
    }

    #[test]
    fn bare_app_from_non_shape_import_stays_script() {
        // An `app` exposed by a non-shape module is not a shape entry.
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Widget exposing (app)\n\nmain = app cfg\n"
            ),
            MainShape::Script
        );
    }

    #[test]
    fn open_exposing_import_does_not_pin_bare_head() {
        // `exposing (..)` on a stdlib module is a resolver no-op, so it binds no
        // bare name here either — the head stays a script.
        assert_eq!(
            classify(
                "module Main exposing (..)\n\nimport Ipe.Tea.Web exposing (..)\n\nmain = app cfg\n"
            ),
            MainShape::Script
        );
    }

    #[test]
    fn script_importing_web_ui_gets_hole_hint() {
        // A Script (plain-`Task` main) that imports `Ipe.Ui` builds a view it can
        // never render — a warning-level hint (IPE-N0050), not a rejection.
        let hint = script_hole(
            "module Main exposing (..)\n\nimport Ipe.Ui as Ui\n\nmain = Io.println \"hi\"\n",
        )
        .expect("expected a Script-hole hint");
        assert!(
            matches!(
                &hint,
                Diagnostic::Name {
                    msg: NameError::ScriptImportsShapeView { shape_ui_module, shape, entry },
                    ..
                } if &**shape_ui_module == "Ipe.Ui" && &**shape == "web" && &**entry == "Web.tea"
            ),
            "wrong diagnostic: {hint:?}"
        );
        // It carries the Script-hole wire code and is warning-severity — it
        // must not fail the build.
        assert_eq!(hint.code(), ipe_diagnostics::IPE_N0050);
        assert_eq!(hint.severity(), ipe_diagnostics::Severity::Warning);
    }

    #[test]
    fn script_importing_cells_ui_hints_terminal() {
        let hint = script_hole(
            "module Main exposing (..)\n\nimport Ipe.Ui.Cells as Cells\n\nmain = Io.println \"hi\"\n",
        )
        .expect("expected a Script-hole hint");
        assert!(
            matches!(
                &hint,
                Diagnostic::Name {
                    msg: NameError::ScriptImportsShapeView { shape, entry, .. },
                    ..
                } if &**shape == "terminal" && &**entry == "Tui.tea"
            ),
            "wrong diagnostic: {hint:?}"
        );
    }

    #[test]
    fn web_app_importing_ui_has_no_hole() {
        // A real Web app renders its `Ipe.Ui` view — no hole, no hint.
        assert!(
            script_hole(
                "module Main exposing (..)\n\nimport Ipe.Tea.Web\nimport Ipe.Ui as Ui\n\nmain = Web.tea cfg\n"
            )
            .is_none()
        );
    }

    #[test]
    fn script_without_view_import_has_no_hole() {
        // A plain Script that imports no view library builds nothing to drop.
        assert!(script_hole("module Main exposing (..)\n\nmain = Io.println \"hi\"\n").is_none());
    }

    #[test]
    fn ssg_script_rendering_ui_to_string_has_no_hole() {
        // Static-site generation: a Script builds an `Ipe.Ui` view, renders it to
        // a `String` through `Ipe.Html`'s serialiser, and prints it. The view IS
        // consumed, so IPE-N0050 must NOT fire.
        assert!(
            script_hole(
                "module Main exposing (..)\n\
                 import Ipe.Ui as Ui\n\
                 import Ipe.Html as Html\n\n\
                 main = Io.println (Html.render (Ui.layout [] page))\n"
            )
            .is_none(),
            "a Script that renders its view to a String is SSG, not a dropped view"
        );
    }

    #[test]
    fn ssg_script_via_exposed_bare_render_has_no_hole() {
        // The sink reached through a bare `render` an exposing import binds is
        // still a consume — the carve-out resolves the name through the import
        // table, not by spelling.
        assert!(
            script_hole(
                "module Main exposing (..)\n\
                 import Ipe.Html exposing (render)\n\n\
                 main = Io.println (render page)\n"
            )
            .is_none()
        );
    }

    #[test]
    fn script_importing_ui_but_never_rendering_still_warns() {
        // The original protection: a Script that imports `Ipe.Ui` and builds a
        // view but never renders it to a String genuinely drops it — IPE-N0050
        // must STILL fire.
        let hint = script_hole(
            "module Main exposing (..)\n\
             import Ipe.Ui as Ui\n\n\
             page = Ui.layout [] Ui.none\n\n\
             main = Io.println \"hi\"\n",
        )
        .expect("a built-but-unrendered view is still a hole");
        assert_eq!(hint.code(), ipe_diagnostics::IPE_N0050);
    }

    #[test]
    fn bare_render_from_unrelated_module_still_warns() {
        // A `render` that does NOT resolve to `Ipe.Html` (here a user function of
        // the same name) is not the sink — the view stays dropped, the hint holds.
        // Fail-closed: absent proof the view is consumed, warn.
        let hint = script_hole(
            "module Main exposing (..)\n\
             import Ipe.Ui as Ui\n\n\
             render x = x\n\n\
             main = Io.println (render \"hi\")\n",
        )
        .expect("a like-spelled non-sink render must not suppress the hole");
        assert_eq!(hint.code(), ipe_diagnostics::IPE_N0050);
    }

    #[test]
    fn cells_ui_still_warns_even_with_html_render() {
        // `Ipe.Ui.Cells` has no `String` sink — `Html.render` consumes an `Html`
        // web view, never a `Screen`. The Cells view is still genuinely dropped,
        // so the terminal hint must STILL fire.
        let hint = script_hole(
            "module Main exposing (..)\n\
             import Ipe.Ui.Cells as Cells\n\
             import Ipe.Html as Html\n\n\
             main = Io.println (Html.render web)\n",
        )
        .expect("a Cells view has no String sink; it is always dropped");
        assert!(
            matches!(
                &hint,
                Diagnostic::Name {
                    msg: NameError::ScriptImportsShapeView { shape, .. },
                    ..
                } if &**shape == "terminal"
            ),
            "wrong diagnostic: {hint:?}"
        );
    }
}
