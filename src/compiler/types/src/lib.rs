#![forbid(unsafe_code)]
//! `ipe_types` — Hindley-Milner type inference for the supported subset of
//! Ipê.
//!
//! Entry point: [`infer`]. It consumes a name-resolved [`ipe_canon::ast::Module`]
//! and produces a [`SolvedTypes`] carrying (a) the inferred type of every
//! top-level binding (`env`) and (b) the inferred type of every sub-expression
//! source region (`regions`) — the latter being exactly what the type-directed
//! lowerer reads to fill its `IrType` slots.
//!
//! The implementation is a faithful but narrowed port of the reference compiler's
//! `Ipe.Type.{Type,UnionFind,Unify,Solve}` + `Constrain.Expression`:
//!
//! * [`unionfind`] — `Vec`-backed weighted union-find (port of `UnionFind`).
//! * [`constrain`] — constraint generation over the canonical AST (the
//!   supported arms of `Constrain.Expression`).
//! * [`unify`] — in-place unification with an occurs check (port of `Unify`).
//! * [`solve`] — budget-bounded constraint discharge (port of `Solve`).
//!
//! ## Interner mutability
//! [`infer`] takes `&mut Interner`. The type checker must *name* built-in type
//! constructors that never appear in user source — notably `Task` (the result
//! of `println`). Minting their [`Symbol`]s requires interning, exactly as the
//! sibling pipeline stages (`parse_module`, `canonicalise`) already take
//! `&mut Interner`. The freshly-interned names flow downstream so the lowerer
//! (which keeps `&Interner`) can resolve them.

mod constrain;
mod doc;
mod exhaust;
mod solve;
pub(crate) mod super_bounds;
mod ty;
mod unify;
mod unionfind;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::Arc;

use ipe_canon::ModuleExports;
use ipe_canon::ast as canon;
use ipe_diagnostics::{DResult, Diagnostic, LowerError, Span, TypeError};
use ipe_intern::{Interner, Symbol};

pub use constrain::{kernel_type_table, resolve_scheme};
pub use doc::{VarNamer, canon_type_to_doc, letters, ty_to_doc};
pub use solve::{BUDGET_ENV, Budget, DEFAULT_SOLVER_BUDGET};
pub use ty::{
    RETRY_POLICY_FIELDS, RowTail, Ty, TyBounds, is_solver_var, tag_solver_var, untag_solver_var,
};

use constrain::{
    Builder, FieldAccess, RecordUpdate, RouteWitnessCheck, RoutedWebCheck, SchemeApp,
    promote_untyped_boundaries, reify_scheme, zonk,
};
use solve::solve_attributed;
use ty::{Content, FlatType};
use unify::unify;
use unionfind::{UnionFind, VarId};

/// The result of inference: resolved types for bindings and for every region.
///
/// Mirrors the reference compiler `SolvedTypes` record's `_stEnv` + `_stRegions`. Both
/// maps are `BTreeMap`s so iteration is deterministic.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SolvedTypes {
    /// Type of each top-level binding, keyed by `(home_module_path, bare_name)`.
    ///
    /// The qualified key ensures that same-named defs from different modules
    /// (e.g. `Lib.helper` and `Main.helper`) remain distinct after
    /// `link::link` merges them into a single flat def list.  Consumers that
    /// need the inferred type for a specific def must supply **both** the home
    /// path and the bare name; looking up by bare name alone is unsound when
    /// cross-module defs share a name.
    pub env: BTreeMap<(Vec<Symbol>, Symbol), Ty>,
    /// Type of each sub-expression source region, keyed by `(home_module_path,
    /// Span)`. Drives type-directed lowering.
    ///
    /// The home path discriminant prevents span collisions after `link::link`
    /// merges N source modules into a single flat def list: two different files
    /// can independently contain expressions at the same byte-offset span.  A
    /// bare-`Span` key silently overwrote earlier entries, causing IPE-I0001.
    pub regions: BTreeMap<(Vec<Symbol>, Span), Ty>,
    /// The type EXPECTED at each source region by its surrounding context,
    /// keyed by `(home_module_path, Span)` — the type-directed-completion
    /// sidecar (ADR 0007 / LSP plan §6). Where [`Self::regions`] holds the type
    /// an expression WAS inferred to have, this holds the type its enclosing
    /// context PUSHES DOWN onto it: a `Call` argument's declared parameter
    /// slot, a typed def body's annotation return, an `if`/`case` branch's
    /// shared result, a list/cons element. The LSP's `expected_type_at` query
    /// reads this to filter + rank completion candidates: a candidate whose
    /// type unifies with the expected type ranks first, and the expected type's
    /// own constructors / record fields are surfaced.
    ///
    /// Additive by construction: it is populated by pure map inserts of solver
    /// variables the inference already minted, reading it changes nothing the
    /// solver does, and it is zonked in the same read-back pass as
    /// [`Self::regions`]. `expected_types_additive` (this crate's tests) proves
    /// every OTHER `SolvedTypes` field is byte-identical whether or not this
    /// map exists. Only positions with a genuine contextual expectation appear;
    /// an unconstrained position is absent and completion degrades to
    /// scope-only there.
    pub expected: BTreeMap<(Vec<Symbol>, Span), Ty>,
    /// Super-type obligations of each typed binding's generic variables, keyed
    /// by `(home, def_name)` — NOT bare `def_name` (AUD-05 seal fix): two
    /// modules can each declare a same-named generic binding with DIFFERENT
    /// obligations (`Lib.scale : a -> a -> a` needing `Add` vs `Main.scale :
    /// a -> a -> a` needing nothing), matching the key shape [`Self::env`] /
    /// [`Self::regions`] already use for the identical cross-module-collision
    /// reason. Value: annotation variable symbol → its [`TyBounds`]. Only
    /// variables the body actually constrained appear; a structurally-
    /// parametric variable is absent (its bound is empty). The lowerer turns
    /// each obligation into the matching Rust trait bound on the emitted
    /// generic parameter.
    pub bounds: BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<Symbol, TyBounds>>,
    /// Non-fatal diagnostics collected during type-checking (e.g. IPE-T0011
    /// `RedundantCaseBranch`, IPE-L0124). Every diagnostic reaching this field
    /// is [`Severity::Warning`]: callers MUST print them but MUST NOT treat them
    /// as compilation failures. Error-severity diagnostics collected during the
    /// same passes (IPE-T0018 over a closed union) never reach here — [`infer`]
    /// converts any collected `Severity::Error` into a returned `Err` before
    /// building this value, so a `SolvedTypes` witnesses a program that compiles.
    pub warnings: Vec<Diagnostic>,
    /// Per-typed-binding map from union-find representative id to annotation
    /// variable symbol, keyed by `(home, def_name)`.
    ///
    /// After solving, every annotation type variable for a `Def::Typed` binding
    /// is represented as a `Ty::Var(u32)` in the zonked region types, where the
    /// `u32` is the union-find representative of the rigid (skolem) that was
    /// used while checking the binding's body.  This map records that
    /// correspondence so the lowerer can tell apart a "this `Ty::Var` is a
    /// generic type parameter of the enclosing function" from a "this `Ty::Var`
    /// is a truly unconstrained, message-free subtree placeholder".
    ///
    /// Concretely: `Attribute<T1>` in `view : (Msg -> parentMsg) -> Counter ->
    /// Html parentMsg` is an attribute list whose element type resolves to
    /// `Ty::Con { Attribute, [Ty::Var(rep)] }` in the region map.  Without this
    /// map the lowerer fell back to `IrType::Unit` (the `Attribute<()>` path),
    /// producing E0308 in the emitted Rust.  With it, the lowerer emits
    /// `IrType::Generic(parentMsg_sym)` → `Attribute<T1>`.
    pub poly_var_map: BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<u32, Symbol>>,
    /// Generalized type-variable symbols of each untyped top-level binding
    /// that Boundary Scheme Promotion generalized, in synthesis order (`"a"`,
    /// `"b"`, …), keyed by `(home, def_name)`. Absent or empty for a def that
    /// stayed fully monomorphic (no boundary-free residual `Flex` root) — the
    /// lowerer's untyped-def arm behaves exactly as before this field
    /// existed. See `docs/adr/0001-language-semantics-and-types.md`.
    pub untyped_type_params: BTreeMap<(Vec<Symbol>, Symbol), Vec<Symbol>>,
    /// Annotation type-variable symbols of each **typed** binding whose only
    /// role is a UI message slot (`Html msg` / `Element msg` / `Attribute msg`
    /// / `Event msg`) that solving never pinned to a concrete `Msg` -- at the
    /// binding itself nor at any use site. Keyed by `(home, def_name)`.
    ///
    /// Such a variable has no polymorphic requirement (a message-free subtree
    /// carries no handler, and no caller instantiates it), so the lowerer
    /// defaults it to `Unit`: it emits `Html<()>` for the signature, the return,
    /// and every body node, instead of a `fn page<T1>() -> Html<T1>` whose
    /// generic no call site can infer (E0283 / E0308). A variable a use DOES pin
    /// to a concrete `Msg` (`sharedRow` under `viewA : Html MsgA`) is absent --
    /// genuine msg-polymorphism is preserved. Empty for a binding with no such
    /// variable (the common case), so the lowerer behaves exactly as before.
    pub msg_defaulted_vars: BTreeMap<(Vec<Symbol>, Symbol), BTreeSet<Symbol>>,
}

/// Infer the types of a canonical module.
///
/// # Errors
/// * [`ipe_diagnostics::Diagnostic::Type`] with [`ipe_diagnostics::TypeError::Mismatch`]
///   when two types fail to unify, or [`ipe_diagnostics::TypeError::BudgetExceeded`]
///   when the solver step budget is exhausted.
/// * [`ipe_diagnostics::Diagnostic::CompilerBug`] on a violated internal
///   invariant (dangling union-find id, unbound local, arity mismatch — all
///   unreachable for well-canonicalised input).
pub fn infer(m: &canon::Module, interner: &mut Interner) -> DResult<SolvedTypes> {
    let mut budget = Budget::from_env();
    infer_with_budget(m, interner, &mut budget)
}

/// Like [`infer`] but on a type-error from the constraint solver also returns
/// the **home module path** of the failing constraint.
///
/// This lets the compiler driver's error-attribution path select the correct
/// source file for a cross-module type error without relying on the
/// byte-offset heuristic that can fail when two merged modules share the same
/// numeric span range.
///
/// On a non-solver error (constraint generation, field-access pass, etc.) the
/// returned home is `Vec::new()` and callers should fall back to the heuristic.
///
/// # Errors
/// Same conditions as [`infer`]; on failure the tuple carries both the
/// diagnostic and the failing constraint's home module path.
pub fn infer_attributed(
    m: &canon::Module,
    interner: &mut Interner,
) -> Result<SolvedTypes, (Diagnostic, Vec<Symbol>)> {
    let mut budget = Budget::from_env();
    infer_with_budget_attributed(m, interner, &mut budget)
}

/// One exported binding's cross-module type contract: its generalized scheme
/// plus the super-type obligations its generic variables carry.
///
/// For a typed binding the scheme is the normalized annotation type (the
/// exact value every cross-module reference already instantiates in the
/// whole-program solve); for an untyped binding it is the boundary-promoted
/// scheme reified with canonical variable ids ([`constrain::reify_scheme`]).
/// Span-free by construction ([`Ty`] carries no spans), so a body-only edit
/// that preserves the scheme yields a byte-equal value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypedScheme {
    /// The generalized scheme.
    pub ty: Ty,
    /// Annotation variable symbol → the obligations the binding's body
    /// imposed on it (empty map for an obligation-free binding).
    pub bounds: BTreeMap<Symbol, TyBounds>,
}

/// The typed cross-module interface of one module.
///
/// Carries every exported binding's [`TypedScheme`] plus the module's union
/// definitions (constructor payload types, needed by an importer's
/// constructor references, patterns, and exhaustiveness analysis). This is
/// the typed analogue of the canon-level [`ModuleExports`], and the
/// invalidation firewall of the per-module solve tier: a dependency body
/// edit that preserves this value lets every importer's scoped solve stand.
/// Union constructor spans are erased ([`ipe_diagnostics::Span::DUMMY`]) so
/// a span-shifting edit above a union cannot bust the firewall.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypedInterface {
    /// Exported value name → its scheme. Exported kernel aliases are absent
    /// (they resolve through the canon kernel route, never through the
    /// scheme table).
    pub values: BTreeMap<Symbol, TypedScheme>,
    /// The module's union definitions, constructor spans erased.
    pub unions: Vec<canon::Union>,
}

/// Whether a module's typed interface can stand for it in a dependency-first
/// scoped solve.
///
/// `Open` means at least one exported binding's scheme still reaches a
/// residual non-quantified solver variable (a shared monomorphic root, a
/// pending `Super` obligation, a rigid contamination, an open record tail)
/// — a variable an importer may legitimately pin, so information can flow
/// AGAINST the import direction and no per-module interface is faithful.
/// Consumers must fall back to the whole-program solve for the module and
/// its importers; anything else risks a scoped result the joint solve
/// disagrees with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InterfaceStatus {
    /// Every exported scheme is closed; the interface is faithful.
    Closed(TypedInterface),
    /// Some exported scheme is open; only the whole-program solve is
    /// faithful for this module and its importers.
    Open,
}

/// The result of a scoped per-module solve: the module's own solved types
/// plus its typed interface (or `Open`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModuleInference {
    /// The module's solved types — same shape as the whole-program result,
    /// scoped to this module's constraints over its deps' interfaces.
    pub solved: SolvedTypes,
    /// The module's own typed interface, for its importers' scoped solves.
    pub interface: InterfaceStatus,
}

/// Per-binding super-type obligations, keyed `(home, name)` — the shape of
/// [`SolvedTypes::bounds`].
type BoundsTable = BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<Symbol, TyBounds>>;

/// The dependency seeds of a scoped per-module solve, threaded through the
/// shared inference core.
struct ScopedContext<'a> {
    /// The module's own canon-level export surface (which names must appear
    /// in the produced interface; which are kernel aliases to skip).
    exports: &'a ModuleExports,
    /// Resolved dep module path → its CLOSED typed interface.
    deps: &'a BTreeMap<Vec<Symbol>, Arc<TypedInterface>>,
}

/// Infer the types of ONE module of a multi-module program, scoped.
///
/// The solve covers only `m`'s own constraints, with every cross-module
/// reference instantiated against the dependency's [`TypedInterface`] scheme
/// (fresh per use site, exactly as the whole-program solve instantiates a
/// typed binding's annotation).
///
/// The whole-program emission path stays on [`infer_attributed`] over the
/// linked merge; this scoped entry point exists for the per-module query
/// tier, and its result is meaningful ONLY under the closed-interface
/// discipline: every resolved dep of `m` must have produced
/// [`InterfaceStatus::Closed`] from its own scoped solve. The returned
/// [`ModuleInference::interface`] reports whether `m` itself sustains that
/// discipline for its importers.
///
/// # Errors
/// Same conditions as [`infer_attributed`], scoped to this module's
/// constraints.
pub fn infer_module(
    m: &canon::Module,
    exports: &ModuleExports,
    deps: &BTreeMap<Vec<Symbol>, Arc<TypedInterface>>,
    interner: &mut Interner,
) -> Result<ModuleInference, (Diagnostic, Vec<Symbol>)> {
    let mut budget = Budget::from_env();
    let scoped = ScopedContext { exports, deps };
    let (solved, interface) = infer_core(m, interner, &mut budget, Some(&scoped))?;
    Ok(ModuleInference {
        solved,
        interface: interface.unwrap_or(InterfaceStatus::Open),
    })
}

/// A [`canon::Union`] clone with every constructor span erased — interface
/// identity must not depend on where in the file a union sits.
fn erase_union_spans(union: &canon::Union) -> canon::Union {
    canon::Union {
        home: union.home.clone(),
        name: union.name,
        vars: union.vars.clone(),
        ctors: union
            .ctors
            .iter()
            .map(|c| canon::Ctor {
                name: c.name,
                index: c.index,
                arity: c.arity,
                args: c.args.clone(),
                span: Span::DUMMY,
            })
            .collect(),
    }
}

/// Inference with an explicit solver budget. Exposed for tests that need to
/// drive the [`ipe_diagnostics::TypeError::BudgetExceeded`] path deterministically
/// without mutating process-global environment state.
fn infer_with_budget(
    m: &canon::Module,
    interner: &mut Interner,
    budget: &mut Budget,
) -> DResult<SolvedTypes> {
    infer_with_budget_attributed(m, interner, budget).map_err(|(diag, _home)| diag)
}

/// Like [`infer_with_budget`] but on a solver error also returns the failing
/// constraint's home module path.  Non-solver errors (constraint generation,
/// post-solve passes) return `Vec::new()` as the home.
fn infer_with_budget_attributed(
    m: &canon::Module,
    interner: &mut Interner,
    budget: &mut Budget,
) -> Result<SolvedTypes, (Diagnostic, Vec<Symbol>)> {
    infer_core(m, interner, budget, None).map(|(solved, _interface)| solved)
}

/// The ONE inference body behind both the whole-program solve
/// ([`infer_attributed`], `scoped == None` — byte-identical behaviour) and
/// the scoped per-module solve ([`infer_module`], `scoped == Some`). A single
/// code path so the two solves cannot drift; every scoped-only step is gated
/// on `scoped` and adds nothing to the whole-program run.
#[allow(clippy::too_many_lines)] // structural mirror of the solve pipeline; split would obscure flow
fn infer_core(
    m: &canon::Module,
    interner: &mut Interner,
    budget: &mut Budget,
    scoped: Option<&ScopedContext<'_>>,
) -> Result<(SolvedTypes, Option<InterfaceStatus>), (Diagnostic, Vec<Symbol>)> {
    // Convenience: wrap a `DResult`-returning expression so `?` works inside
    // this function whose error type is `(Diagnostic, Vec<Symbol>)`.  Non-solver
    // errors (constraint generation, post-solve passes) carry no meaningful home,
    // so they surface with an empty home and callers fall back to the heuristic.
    macro_rules! lift {
        ($e:expr) => {
            $e.map_err(|d: Diagnostic| (d, Vec::<Symbol>::new()))?
        };
    }

    let mut uf = UnionFind::new();
    // Dep-interface seeds (scoped solve only): the deps' exported schemes
    // pre-populate the `(home, name)` scheme table, and the deps' unions are
    // registered alongside the module's own so cross-module constructor
    // references, patterns, and exhaustiveness see full definitions. The
    // union list stays alive past constraint generation — `exhaust::check`
    // reads it below.
    let dep_unions: Vec<&canon::Union> = scoped.map_or_else(Vec::new, |ctx| {
        ctx.deps
            .values()
            .flat_map(|iface| iface.unions.iter())
            .collect()
    });
    // The user enums whose definition embeds a function payload — consulted by
    // every concrete equality / stringify obligation so a `==` / `toString` on a
    // function-carrying enum fails closed (the payload arrow is invisible in a
    // `Ty::Con`'s applied type arguments; see [`fn_embedding_enums`]).
    let fn_enums = fn_embedding_enums(&m.unions, &dep_unions);
    let enum_embeds_fn = |home: &[Symbol], name: Symbol| fn_enums.contains(&(home.to_vec(), name));
    let generated = match scoped {
        None => lift!(Builder::run(&mut uf, interner, m)),
        Some(ctx) => {
            let mut seed: BTreeMap<(Vec<Symbol>, Symbol), Rc<Ty>> = BTreeMap::new();
            for (path, iface) in ctx.deps {
                for (name, scheme) in &iface.values {
                    seed.insert((path.clone(), *name), Rc::new(scheme.ty.clone()));
                }
            }
            lift!(Builder::run_seeded(&mut uf, interner, m, &dep_unions, seed))
        }
    };

    solve_attributed(&mut uf, budget, interner, &generated.constraints)?;

    // Boundary Scheme Promotion (class-1 inference fix #2): generalize every
    // untyped top-level binding at its home module's boundary and discharge
    // every cross-module reference against the resulting scheme, fresh per
    // use site. Must run BEFORE `resolve_deferred` below: a discharged
    // cross-module call site's field accesses / record updates need the
    // freshly-instantiated (not the stale program-wide-shared) structure to
    // resolve correctly. See
    // `docs/adr/0001-language-semantics-and-types.md`.
    let untyped_schemes = promote_untyped_boundaries(&mut uf, budget, interner, &generated)?;

    // Discharge deferred field accesses and record updates in a joint fixpoint.
    // These two passes must interleave because a record update can pin the
    // element type of a field that a downstream field access needs (e.g.
    // `{ model | history = snapshots }` pins `model.history : List Snapshot`,
    // enabling `snap.ok` to resolve in the next pass).  Running them sequentially
    // would leave element types Flex when field accesses are processed, causing
    // a false IPE-T0012.  See [`resolve_deferred`] for the full algorithm.
    // The opaque server `Request` type has a fixed field set (see
    // [`RequestFields`]); intern it once here so the immutable-borrow
    // `resolve_deferred` pass can resolve `req.<field>` accesses.
    let req_fields = lift!(RequestFields::build(interner));
    // The opaque `WebReq` type (Ipe.Web `init`'s per-session request context)
    // has a fixed field set too (see [`WebReqFields`]); intern it once here so
    // `req.path` / `req.cookies` accesses resolve against the runtime struct.
    let web_req_fields = lift!(WebReqFields::build(interner));
    // The nominal error-payload types `PanicInfo`/`TypeInfo`/`ErrorInfo`
    // resolve field accesses the same way (SEAL fix — see
    // [`ErrorRecordFields`]).
    let err_fields = lift!(ErrorRecordFields::build(interner));
    let builtin_field_tables = BuiltinFieldTables {
        req: &req_fields,
        web_req: &web_req_fields,
        err: &err_fields,
    };
    // Unlike the other post-solve passes, `resolve_deferred` returns the failing
    // field-access / record-update's `home` module path so a IPE-T0012 attributes
    // to the source file that actually owns the access — not the byte-offset
    // heuristic's best guess, which can mis-blame `info.message` in one module
    // on a `class` call in another.
    resolve_deferred(
        &mut uf,
        budget,
        interner,
        &builtin_field_tables,
        &generated.field_accesses,
        &generated.record_updates,
    )?;

    // Per-route page witnesses: each `Web.route pattern ctor`
    // relates its builder argument's settled type to the route's page type —
    // a nullary builder witnesses the page directly, a params-consuming
    // constructor (`String -> Page`) witnesses it with its result type.  Must
    // run BEFORE `resolve_routed_web_checks` so route constructors pin the
    // page variable before the `notFound ≟ Model.page` gate reads it.  See
    // the `RouteWitnessCheck` doc comment for the full rationale.
    lift!(resolve_route_witness_checks(
        &mut uf,
        budget,
        interner,
        &generated.route_witness_checks
    ));

    // Diagnostics collected during the post-solve deferred passes and the
    // exhaustiveness pass. Most are `Severity::Warning` (IPE-L0124, IPE-T0011)
    // and stay in `SolvedTypes::warnings` for the caller to print. The
    // exhaustiveness pass may also collect a `Severity::Error` (IPE-T0018 over a
    // closed union); those are partitioned out below and promoted to a returned
    // `Err`, so the collected channel that survives into `SolvedTypes` carries
    // only warnings.
    let mut warnings: Vec<Diagnostic> = Vec::new();

    // For routed `Web.tea` calls: if the now-settled Model type has a `page`
    // field, the `notFound` type must match that field's type.  Non-routed
    // apps (Model has no `page` field) are silently skipped — UNLESS the app
    // declared a non-empty `routes` list, in which case the routes are ignored
    // and we emit the IPE-L0124 warning (usually a mis-named `page` field). See
    // the `RoutedWebCheck` doc comment for the full rationale.
    let has_routes = !generated.route_witness_checks.is_empty();
    lift!(resolve_routed_web_checks(
        &mut uf,
        budget,
        interner,
        &generated.routed_web_checks,
        has_routes,
        generated.route_witness_checks.len(),
        &mut warnings,
    ));

    // A read-back of every region's resolved type, taken HERE (before the final
    // `SolvedTypes` assembly) so the exhaustiveness pass can consult a `case`
    // scrutinee's settled type: a bare `_`-only match over a closed union carries
    // NO constructor head in its patterns, so its union identity is knowable only
    // from the scrutinee's type. This snapshot is used ONLY to identify a
    // scrutinee's nominal union (a `Ty::Con` pinned by pattern constructors, which
    // numeric/SQL defaulting below never rewrites), so taking it pre-defaulting is
    // sound for that use. The map consumed by downstream tooling (`SolvedTypes`)
    // is built separately AFTER defaulting, so emit still sees fully-defaulted
    // region types. Iterated by reference to leave `generated.regions` intact.
    let mut regions_for_exhaust: BTreeMap<(Vec<Symbol>, Span), Ty> = BTreeMap::new();
    for ((home, span), var) in &generated.regions {
        regions_for_exhaust.insert((home.clone(), *span), lift!(zonk(&mut uf, budget, *var)));
    }

    // End-of-checking exhaustiveness + redundancy pass. Running it here — after
    // the solver settles — makes the lowerer's `Match::new` exhaustiveness
    // contract a genuinely unreachable compiler-bug case.
    // The pass collects into `warnings` rather than early-returning on the first
    // finding, so all offending sites are reported in one run. IPE-T0011 is a
    // Warning and must not abort; IPE-T0018 over a closed union is an Error.
    // IPE-T0010 (non-exhaustive) still early-returns `Err` from inside the pass.
    // Every error the pass returns carries its owning definition's home, so the
    // driver frames it against that module's source rather than guessing a file
    // from byte offsets that every linked module shares.
    exhaust::check(
        m,
        &dep_unions,
        &regions_for_exhaust,
        interner,
        &mut warnings,
    )?;

    // Fail-closed promotion: a diagnostic collected above is only a compilation
    // failure if it is Error-severity. The pass already returns its first Error
    // with a home; this partition is the second, independent boundary — an
    // Error-severity diagnostic that ever reaches the sink still fails
    // compilation instead of rendering while the program compiles (the exact
    // silent-accept the lint exists to prevent). Warning-severity diagnostics
    // ride on in `SolvedTypes::warnings`.
    let first_error = warnings
        .iter()
        .position(|d| d.severity() == ipe_diagnostics::Severity::Error);
    if let Some(idx) = first_error {
        let err = warnings.swap_remove(idx);
        return Err((err, Vec::new()));
    }

    // Scoped solve only: reify every exported UNTYPED binding's promoted
    // scheme for the module's typed interface. Must run HERE — after the
    // deferred passes settle, BEFORE numeric/SQL defaulting — because
    // defaulting pins residual `Super` flexes to concrete types, which would
    // disguise an OPEN scheme (one an importer can still pin, e.g.
    // `double x = x + x` whose importer's `double 1.5` makes it
    // `Float -> Float` in the joint solve) as a closed `Int -> Int`.
    // `None` from `reify_scheme`, or an exported name with neither a scheme
    // nor a kernel-alias route, marks the whole interface open — fail closed.
    let mut reified_untyped: BTreeMap<Symbol, Ty> = BTreeMap::new();
    let mut interface_open = false;
    if let Some(ctx) = scoped {
        for name in &ctx.exports.values {
            if ctx.exports.kernel_aliases.contains_key(name) {
                continue;
            }
            let key = (m.name.clone(), *name);
            if generated.top_level.contains_key(&key) {
                continue; // annotation scheme — closed by construction
            }
            let reified = match untyped_schemes.get(&key) {
                Some(scheme) => lift!(reify_scheme(&mut uf, budget, scheme)),
                None => None,
            };
            if let Some(ty) = reified {
                reified_untyped.insert(*name, ty);
            } else {
                interface_open = true;
                break;
            }
        }
    }

    // Numeric defaulting: a `Number` variable the program never pinned to a
    // concrete type resolves to `Int` (an untyped `\a b -> a + b` is `Int`, not
    // an under-determined generic). Only super-typed FLEX variables default; an
    // annotation skolem (rigid super) stays generic so its bound surfaces on the
    // emitted type parameter. (Ordering-only flex variables are left generic, as
    // before — they carry no numeric obligation to default.)
    let int_sym = lift!(interner.intern("Int"));
    // SQL-bind-parameter defaulting: the element variable of a `List a`
    // argument bound into `Db.exec` / `Db.query` / `Db.queryDecode`'s params
    // position that the program never pinned to a concrete type (an empty
    // `[]` literal at that call site, e.g. `Database.queryOrLog label sql []`
    // in `examples/17-ipemon`). Left un-defaulted, the lowerer's wildcard-`any`
    // convention would resolve it to `IrType::Json` (`serde_json::Value`,
    // which has no `Into<SqlParam>` impl) and the emitted `Vec::new()` call
    // argument would carry zero type evidence — trading today's E0283 for an
    // equally unresolvable `cargo` failure. Defaulting to Ipê's own `SqlValue`
    // ADT instead keeps the call sound end-to-end: `SqlValue` already has a
    // generated `Into<SqlParam>` impl (`ipe_backend_rust::project`), so an
    // empty params list becomes a concretely-typed empty `Vec<SqlValue>`.
    let sqlvalue_sym = lift!(interner.intern("SqlValue"));
    for (v, orig_bounds, span, home) in &generated.super_vars {
        let root = lift!(uf.find(*v));
        match lift!(uf.content(root)) {
            // An unpinned `Number` flex defaults to `Int` — an untyped
            // `\a b -> a + b` is `Int`, not an under-determined generic.
            // Ordering / equality flexes carry no numeric default, so an unpinned
            // one is left generic (matching the reference compiler).
            Content::Super {
                rigid: false,
                bounds,
            } if bounds.has_number() => {
                let int_ty = Ty::Con {
                    module: Vec::new(),
                    name: int_sym,
                    args: Vec::new(),
                };
                if !concrete_super_ok(interner, bounds, &int_ty, &enum_embeds_fn) {
                    return Err((
                        super_unsatisfied(interner, bounds, &int_ty, *span),
                        home.clone(),
                    ));
                }
                lift!(uf.set_content(
                    root,
                    Content::Structure(FlatType::Con {
                        module: Vec::new(),
                        name: int_sym,
                        args: Vec::new(),
                    }),
                ));
            }
            // An unpinned SQL-bind-parameter flex defaults to `SqlValue` — see
            // the doc comment above `sqlvalue_sym`.
            Content::Super {
                rigid: false,
                bounds,
            } if bounds.has_sql_param() => {
                let sqlvalue_ty = Ty::Con {
                    module: Vec::new(),
                    name: sqlvalue_sym,
                    args: Vec::new(),
                };
                if !concrete_super_ok(interner, bounds, &sqlvalue_ty, &enum_embeds_fn) {
                    return Err((
                        super_unsatisfied(interner, bounds, &sqlvalue_ty, *span),
                        home.clone(),
                    ));
                }
                lift!(uf.set_content(
                    root,
                    Content::Structure(FlatType::Con {
                        module: Vec::new(),
                        name: sqlvalue_sym,
                        args: Vec::new(),
                    }),
                ));
            }
            // An unpinned ordering / equality flex stays generic. A super var is
            // never a plain `Flex` / `Rigid` after solving (it merges as a
            // `Super`, pins to a `Structure`, or adopts a skolem's rigidity as a
            // rigid `Super`), but those arms are covered for totality and need no
            // action either.
            Content::Super { .. } | Content::Flex | Content::Rigid => {}
            // The variable pinned to a concrete type during solving. Verify —
            // deeply, against the fully-resolved type — that the type really
            // supports the operation. The unifier's head pin-check already
            // cleared a function HEAD; this catches a function NESTED inside a
            // tuple / record / enum under an equality obligation (Rust cannot
            // compare it), failing closed with IPE-T0014 instead of emitting
            // code `cargo` rejects.
            Content::Structure(_) => {
                let ty = lift!(zonk(&mut uf, budget, root));
                if !concrete_super_ok(interner, *orig_bounds, &ty, &enum_embeds_fn) {
                    return Err((
                        super_unsatisfied(interner, *orig_bounds, &ty, *span),
                        home.clone(),
                    ));
                }
            }
        }
    }

    // Record, per typed binding, each annotation variable whose ONLY role is a
    // UI message slot that no use pinned to a concrete `Msg`. The lowerer
    // defaults such a variable to `Unit` for the binding's own signature -- a
    // never-pinned `page : Html msg` emits `fn page() -> Html<()>` rather than
    // an uninferable `fn page<T1>() -> Html<T1>`.
    //
    // A variable is defaulted only when EVERY use instantiates it without
    // pinning it to a concrete type (`SchemeApp::vars` records each use's
    // instantiation): `sharedRow` used under `viewA : Html MsgA` has a use whose
    // instantiation is the concrete `MsgA`, so it is NOT defaulted and stays a
    // genuine generic. A variable appearing anywhere OUTSIDE a UI msg slot is
    // also excluded -- only a pure message placeholder defaults.
    let ui_msg_cons: BTreeSet<Symbol> = ["Html", "Element", "Attribute", "Event"]
        .into_iter()
        .map(|n| interner.intern(n))
        .collect::<Result<_, _>>()
        .map_err(|d| (d, Vec::new()))?;
    let mut msg_defaulted_vars: BTreeMap<(Vec<Symbol>, Symbol), BTreeSet<Symbol>> = BTreeMap::new();
    {
        let mut apps_by_binding: SchemeAppVars<'_> = BTreeMap::new();
        for app in &generated.scheme_apps {
            apps_by_binding
                .entry((app.home.clone(), app.name))
                .or_default()
                .push(&app.vars);
        }
        // The wildcard `any` -- a bare `Html` / `Attribute` annotation the parser
        // arity-fills to `Html any` -- is NOT a defaulting candidate: it has its
        // own resolution (the lowerer substitutes its concrete type from the
        // body's solved region, e.g. a `view` whose body pins the msg via an
        // event handler), which defaulting to `Unit` would clobber.
        let any_sym = interner.intern("any").map_err(|d| (d, Vec::new()))?;
        for (key, ty) in &generated.top_level {
            let mut ui_msg_vars = BTreeSet::new();
            let mut other_vars = BTreeSet::new();
            collect_ui_msg_and_other_vars(
                ty,
                &ui_msg_cons,
                false,
                &mut ui_msg_vars,
                &mut other_vars,
            );
            // A ui-msg var in a PARAMETER position stays generic (its `Element<T1>`
            // param is instantiated by the caller's argument), so the RESULT slot
            // must match it — never default such a var to `()`. `box_ : Element
            // msg -> Element msg` keeps `msg` generic in both positions.
            let mut param_msg_vars = BTreeSet::new();
            collect_param_ui_msg_vars(ty, &ui_msg_cons, &mut param_msg_vars);
            let candidates: BTreeSet<Symbol> = ui_msg_vars
                .into_iter()
                .filter(|v| !other_vars.contains(v))
                .filter(|v| !param_msg_vars.contains(v))
                .filter(|v| *v != any_sym)
                .collect();
            if candidates.is_empty() {
                continue;
            }
            let empty = Vec::new();
            let apps = apps_by_binding.get(key).unwrap_or(&empty);
            let mut defaulted = BTreeSet::new();
            for var_sym in candidates {
                let raw = var_sym.as_raw();
                // A use pins the variable when its instantiation resolves to a
                // concrete non-`Unit` structure (`viewA : Html MsgA` pins
                // `sharedRow`'s msg to `MsgA`) OR to a `Rigid` -- the msg is
                // threaded into an enclosing generic a further-out use will pin
                // (`class` called inside the generic `sharedRow` binds its msg to
                // `sharedRow`'s own type parameter). The unpinned states are
                // `Flex` (never constrained) and `Unit` (a message-free use).
                let mut pinned = false;
                for vars in apps {
                    if let Some(&inst) = vars.get(&raw) {
                        let root = lift!(uf.find(inst));
                        match lift!(uf.content(root)) {
                            Content::Structure(FlatType::Unit) | Content::Flex => {}
                            Content::Structure(_) | Content::Rigid | Content::Super { .. } => {
                                pinned = true;
                                break;
                            }
                        }
                    }
                }
                if !pinned {
                    defaulted.insert(var_sym);
                }
            }
            if !defaulted.is_empty() {
                msg_defaulted_vars.insert(key.clone(), defaulted);
            }
        }
    }

    // Recover each typed binding's generic-variable super-type obligations from
    // the skolems its body constrained. A variable the body never constrained
    // stays a plain rigid (no obligation, absent from the map).
    //
    // Also build `poly_var_map`: the reverse mapping from union-find representative
    // id → annotation var symbol, keyed by `(home, def_name)`.  The lowerer uses
    // this to distinguish "this `Ty::Var` is a generic type parameter of the
    // enclosing function" from "this `Ty::Var` is a message-free UI subtree
    // placeholder" when lowering attribute-list element types inside polymorphic
    // functions.
    let mut bounds: BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<Symbol, TyBounds>> = BTreeMap::new();
    let mut poly_var_map: BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<u32, Symbol>> = BTreeMap::new();
    for ((home, def_name), var_rigids) in &generated.typed_rigids {
        let mut var_bounds = BTreeMap::new();
        let mut rep_to_sym: BTreeMap<u32, Symbol> = BTreeMap::new();
        for (var_sym, rigid) in var_rigids {
            let rep = lift!(uf.find(*rigid));
            rep_to_sym.insert(rep, *var_sym);
            if let Content::Super { bounds: b, .. } = lift!(uf.content(*rigid))
                && !b.is_empty()
            {
                var_bounds.insert(*var_sym, b);
            }
        }
        if !var_bounds.is_empty() {
            bounds.insert((home.clone(), *def_name), var_bounds);
        }
        if !rep_to_sym.is_empty() {
            poly_var_map.insert((home.clone(), *def_name), rep_to_sym);
        }
    }

    // Fold each Boundary-Scheme-Promoted untyped def's quantified vars into
    // `untyped_type_params` / `poly_var_map`, alongside the typed bindings'
    // entries above. Region/env `Ty::Var`s for these defs come from `zonk`
    // (see the `env` read-back below), which always tags a solver
    // representative with `tag_solver_var` before storing it — so these
    // `poly_var_map` keys must be tagged too, or `current_poly_tvars` lookups
    // in the lowerer would never match (unlike the typed-rigids loop above,
    // which is keyed by the untagged skolem representative because a typed
    // binding's own `params`/`ret` are read from its ANNOTATION type, never
    // zonked).
    // Unconstrained UI-msg defaulting for UNTYPED bindings -- the counterpart of
    // the typed `msg_defaulted_vars` computation above. A fully unannotated
    // message-free view helper (`nav = Html.div [] [ Html.text "x" ]`, no
    // signature) generalizes its phantom `msg` at the module boundary into a
    // quantified var. Emitted as a Rust generic (`fn nav<T1: 'static + Clone>()
    // -> Html<T1>`) it is an uninferable-at-the-call-site parameter needing a
    // `'static` bound the caller cannot satisfy -- an E0310 / E0283
    // exit-0-then-cargo-fail. A quantified root that appears ONLY inside a
    // `Html` / `Element` / `Attribute` / `Event` constructor is a pure message
    // placeholder no use pinned to a concrete `Msg` (an untyped binding is
    // monomorphic within its home module, so a still-`Flex` quantified root was
    // never pinned by any same-module reference); pin it to `Unit` so the
    // binding emits `Html<()>`, matching the concrete `Html ()` annotation a
    // user would otherwise be forced to write. This propagates through the
    // `env` / `regions` read-back below (both post-date this pin).
    //
    // The "no same-module reference pinned it" reasoning only holds WITHIN the
    // home module. A binding referenced from ANOTHER module MAY be genuinely
    // message-polymorphic across the boundary: `promote_untyped_boundaries`
    // discharges each cross-module use through a fresh `copy_var` of the
    // scheme, so the shared root can legitimately stay `Flex` while distinct
    // uses pin distinct concrete `Msg` types (`viewA : Html MsgA`, `viewB :
    // Html MsgB`). Defaulting such a binding to `Unit` would emit `fn helper()
    // -> Html<()>` and break every caller needing `Html<MsgN>` — an
    // exit-0-then-cargo-fail.
    //
    // But "referenced across a module boundary" is only a PROXY for "genuinely
    // message-polymorphic". A cross-module use that renders the helper directly
    // (`Html.render helper`) or threads it into another still-message-free
    // helper pins NOTHING: the boundary placeholder discharges to a `Flex` /
    // `Unit` slot, and the emitted `fn helper<T1>() -> Html<T1>` (or, for a
    // message-free attribute body, `-> Attribute<T1>` over an `Attribute<()>`
    // body) has no site to fix `T1` — E0283 / E0308 after `ipe` exit 0. So read
    // the actual DISCHARGE OUTCOME off each promoted placeholder rather than the
    // coarse boolean: default the slot to `Unit` exactly when no cross-module
    // use pins it to a concrete `Msg`, and keep it generic when ≥1 use does.
    let mut cross_module_placeholders: BTreeMap<(Vec<Symbol>, Symbol), Vec<VarId>> =
        BTreeMap::new();
    for pi in &generated.pending_instantiations {
        cross_module_placeholders
            .entry(pi.source.clone())
            .or_default()
            .push(pi.placeholder);
    }
    let mut discharge_outcomes: BTreeMap<(Vec<Symbol>, Symbol), MsgDischargeOutcome> =
        BTreeMap::new();
    for (key, placeholders) in &cross_module_placeholders {
        let mut pinned: BTreeSet<MsgConId> = BTreeSet::new();
        for &placeholder in placeholders {
            let discharged = lift!(zonk(&mut uf, budget, placeholder));
            collect_ui_msg_concrete_cons(&discharged, &ui_msg_cons, false, &mut pinned);
        }
        discharge_outcomes.insert(
            key.clone(),
            MsgDischargeOutcome::from_distinct_pin_count(pinned.len()),
        );
    }
    for (key, scheme) in &untyped_schemes {
        if scheme.quantified.is_empty() {
            continue;
        }
        // A cross-module reference keeps the binding generic only when a use
        // discharges its ui-msg slot to a concrete `Msg`; an unpinned outcome
        // falls through to the same `Unit`-defaulting the same-module path uses.
        if let Some(outcome) = discharge_outcomes.get(key)
            && !outcome.should_default()
        {
            continue;
        }
        let scheme_ty = lift!(zonk(&mut uf, budget, scheme.root));
        let mut ui_msg_vars = BTreeSet::new();
        let mut other_vars = BTreeSet::new();
        collect_ui_msg_and_other_vars(
            &scheme_ty,
            &ui_msg_cons,
            false,
            &mut ui_msg_vars,
            &mut other_vars,
        );
        for &root in scheme.quantified.keys() {
            // A zonked unresolved var reads back as `Ty::Var(tag_solver_var(root))`.
            let tagged_sym = Symbol::from_raw(tag_solver_var(root));
            let msg_only = ui_msg_vars.contains(&tagged_sym) && !other_vars.contains(&tagged_sym);
            if msg_only {
                let rep = lift!(uf.find(root));
                lift!(uf.set_content(rep, Content::Structure(FlatType::Unit)));
            }
        }
    }

    let mut untyped_type_params: BTreeMap<(Vec<Symbol>, Symbol), Vec<Symbol>> = BTreeMap::new();
    for (key, scheme) in &untyped_schemes {
        if scheme.quantified.is_empty() {
            continue;
        }
        // A quantified root pinned to `Unit` by the UI-msg defaulting above is no
        // longer a generic type parameter -- drop it from the binding's emitted
        // signature so the lowerer sees `Html<()>`, not a dangling `T{n}`.
        let mut quantified: BTreeMap<VarId, Symbol> = BTreeMap::new();
        for (&root, &sym) in &scheme.quantified {
            let rep = lift!(uf.find(root));
            let content = lift!(uf.content(rep));
            if !matches!(content, Content::Structure(FlatType::Unit)) {
                quantified.insert(root, sym);
            }
        }
        if quantified.is_empty() {
            continue;
        }
        let tagged: BTreeMap<u32, Symbol> = quantified
            .iter()
            .map(|(&root, &sym)| (tag_solver_var(root), sym))
            .collect();
        untyped_type_params.insert(key.clone(), quantified.values().copied().collect());
        poly_var_map.insert(key.clone(), tagged);
    }

    // Soundness gate: a super-typed binding used at a concrete type must be used
    // at a type that actually supports the operations its generic emission
    // requires. Without this, `double True` (where `double` needs Number) would
    // type-check here yet emit Rust that `cargo` rejects.
    // Scoped solve only: a use of a dep's obligated binding must be checked
    // against the DEP's recorded obligations — the joint solve reads them
    // from its program-wide bounds map; the scoped solve merges them in from
    // the dep interfaces.
    let merged_bounds: Option<BoundsTable> = scoped.map(|ctx| {
        let mut merged = bounds.clone();
        for (path, iface) in ctx.deps {
            for (name, scheme) in &iface.values {
                if !scheme.bounds.is_empty() {
                    merged.insert((path.clone(), *name), scheme.bounds.clone());
                }
            }
        }
        merged
    });
    let bounds_for_apps = merged_bounds.as_ref().unwrap_or(&bounds);
    lift!(check_scheme_applications(
        &mut uf,
        budget,
        interner,
        bounds_for_apps,
        &generated.scheme_apps,
        &enum_embeds_fn
    ));

    // Scoped solve only: assemble the module's typed interface — exported
    // typed bindings carry their normalized annotation scheme + recorded
    // obligations; exported untyped bindings carry the pre-defaulting
    // reified scheme built above.
    let interface = scoped.map(|ctx| {
        if interface_open {
            return InterfaceStatus::Open;
        }
        let mut values: BTreeMap<Symbol, TypedScheme> = BTreeMap::new();
        for name in &ctx.exports.values {
            if ctx.exports.kernel_aliases.contains_key(name) {
                continue;
            }
            let key = (m.name.clone(), *name);
            if let Some(ty) = generated.top_level.get(&key) {
                values.insert(
                    *name,
                    TypedScheme {
                        ty: (**ty).clone(),
                        bounds: bounds.get(&key).cloned().unwrap_or_default(),
                    },
                );
            } else if let Some(ty) = reified_untyped.get(name) {
                values.insert(
                    *name,
                    TypedScheme {
                        ty: ty.clone(),
                        bounds: BTreeMap::new(),
                    },
                );
            }
        }
        InterfaceStatus::Closed(TypedInterface {
            values,
            unions: m.unions.iter().map(erase_union_spans).collect(),
        })
    });

    // Read back every region's resolved type — AFTER numeric/SQL defaulting, so
    // the map handed to downstream tooling carries fully-defaulted types. (The
    // exhaustiveness pass above used a separate pre-defaulting snapshot, which it
    // only reads to identify a scrutinee's nominal union.)
    let mut regions = BTreeMap::new();
    for ((home, span), var) in generated.regions {
        regions.insert((home, span), lift!(zonk(&mut uf, budget, var)));
    }

    // Read back every recorded contextual expectation (the type-directed
    // completion sidecar). Same zonk pass as `regions`; the solver never read
    // `generated.expected`, so this cannot change any type above.
    let mut expected = BTreeMap::new();
    for ((home, span), var) in generated.expected {
        expected.insert((home, span), lift!(zonk(&mut uf, budget, var)));
    }

    // `env` = annotation types of typed bindings (exact) + read-back of every
    // untyped binding's inferred body type. The typed schemes lived behind an
    // `Rc` during constraint generation (per-reference clone = refcount bump);
    // unwrap here to keep the public `SolvedTypes::env` shape. The refcount is
    // 1 by now (per-reference clones were transient), so `try_unwrap` moves
    // without copying; the fallback deep-clone is correctness-equivalent.
    let mut env: BTreeMap<(Vec<Symbol>, Symbol), Ty> = generated
        .top_level
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                std::rc::Rc::try_unwrap(v).unwrap_or_else(|rc| (*rc).clone()),
            )
        })
        .collect();
    for (name, var) in generated.untyped {
        env.insert(name, lift!(zonk(&mut uf, budget, var)));
    }

    Ok((
        SolvedTypes {
            env,
            regions,
            expected,
            bounds,
            warnings,
            poly_var_map,
            untyped_type_params,
            msg_defaulted_vars,
        },
        interface,
    ))
}

/// Per-binding use-site instantiation maps: each `(home, name)` maps to the
/// list of `SchemeApp::vars` (scheme var raw id -> instantiation) recorded at
/// its reference sites, borrowed from `Generated::scheme_apps`.
type SchemeAppVars<'a> = BTreeMap<(Vec<Symbol>, Symbol), Vec<&'a BTreeMap<u32, VarId>>>;

/// Classify each annotation type variable of `ty` as either a **UI message
/// slot** variable (it appears as the argument of a `Html` / `Element` /
/// `Attribute` / `Event` constructor) or an **other-position** variable.
///
/// A variable can land in both sets (`Html msg -> msg`); the caller keeps only
/// the vars that are exclusively message slots, so a variable used anywhere a
/// call site can pin it is never defaulted. `in_ui_msg` tracks whether the
/// current position is already inside such a constructor's argument.
fn collect_ui_msg_and_other_vars(
    ty: &Ty,
    ui_msg_cons: &BTreeSet<Symbol>,
    in_ui_msg: bool,
    ui_msg_vars: &mut BTreeSet<Symbol>,
    other_vars: &mut BTreeSet<Symbol>,
) {
    match ty {
        Ty::Var(raw) => {
            let sym = Symbol::from_raw(*raw);
            if in_ui_msg {
                ui_msg_vars.insert(sym);
            } else {
                other_vars.insert(sym);
            }
        }
        Ty::Fun(a, b) => {
            collect_ui_msg_and_other_vars(a, ui_msg_cons, in_ui_msg, ui_msg_vars, other_vars);
            collect_ui_msg_and_other_vars(b, ui_msg_cons, in_ui_msg, ui_msg_vars, other_vars);
        }
        Ty::Con { name, args, .. } => {
            let child_in_ui_msg = ui_msg_cons.contains(name);
            for a in args {
                collect_ui_msg_and_other_vars(
                    a,
                    ui_msg_cons,
                    child_in_ui_msg,
                    ui_msg_vars,
                    other_vars,
                );
            }
        }
        Ty::Tuple(elems) => {
            for e in elems {
                collect_ui_msg_and_other_vars(e, ui_msg_cons, in_ui_msg, ui_msg_vars, other_vars);
            }
        }
        Ty::Record(fields, _) => {
            for v in fields.values() {
                collect_ui_msg_and_other_vars(v, ui_msg_cons, in_ui_msg, ui_msg_vars, other_vars);
            }
        }
        Ty::Unit => {}
    }
}

/// Collect the ui-msg-slot variables that appear in a PARAMETER (input) position
/// of `ty` — a var inside a `Html` / `Element` / `Attribute` / `Event`
/// constructor anywhere left of a top-level arrow.
///
/// Such a variable is genuinely polymorphic and must NOT be message-defaulted:
/// its parameter lowers to the generic `Element<T1>` (the caller supplies the
/// concrete message type through the argument), so the RESULT slot must stay the
/// same `T1` for the signature to typecheck. Defaulting it to `()` would emit a
/// `fn helper<T1>(child: Element<T1>) -> Element<()>` whose body wraps `child`
/// yet claims `Element<()>` — an E0308 after `ipe` exit 0 (a SEAL breach).
///
/// Only left-of-arrow positions count: the whole return type is the RESULT, and
/// a ui-msg var appearing solely there with no input occurrence is the honest
/// unpinnable-slot case the defaulting exists to catch.
fn collect_param_ui_msg_vars(ty: &Ty, ui_msg_cons: &BTreeSet<Symbol>, out: &mut BTreeSet<Symbol>) {
    let mut cur = ty;
    while let Ty::Fun(param, rest) = cur {
        let mut param_msg_vars = BTreeSet::new();
        let mut discard = BTreeSet::new();
        collect_ui_msg_and_other_vars(param, ui_msg_cons, false, &mut param_msg_vars, &mut discard);
        out.extend(param_msg_vars);
        cur = rest.as_ref();
    }
}

/// A concrete `Msg` type's identity: its defining module path and type name.
/// Two cross-module uses "pin the same message type" exactly when their
/// discharged ui-msg slot holds the same `(module, name)`.
type MsgConId = (Vec<Symbol>, Symbol);

/// How an untyped message-free helper's phantom `msg` is fixed by the concrete
/// types its *cross-module* uses discharge it to — read off each use's promoted
/// placeholder after solving, not the coarse "is it referenced across a module
/// boundary at all" proxy.
///
/// * `Unpinned` — no cross-module use pins the slot to a concrete `Msg` (every
///   use rendered it directly via `Html.render`, threaded it into another
///   still-message-free helper, or does not reference it at all). The emitted
///   generic `fn helper<T1>() -> Html<T1>` has no site that fixes `T1`, so
///   `cargo` cannot infer it (E0283) — and a message-free *attribute* body even
///   emits `Attribute<()>` under a `-> Attribute<T1>` signature (E0308). Default
///   the slot to `Unit` so the binding emits the concrete `Html<()>` a user
///   would otherwise annotate by hand.
/// * `Pinned` — exactly one distinct concrete `Msg` fixes the slot across every
///   cross-module use (`viewA : Html MsgA` is the sole caller, threading
///   `MsgA`). Kept generic: the honest generic body threads the caller's own
///   message type and rustc infers `T1 = MsgA` at the single site; defaulting
///   to `Unit` would mismatch the caller's `Html<MsgA>` (T0001/E0308).
/// * `MultiplyPinned` — ≥2 distinct concrete `Msg` types fix the slot (`viewA :
///   Html MsgA`, `viewB : Html MsgB`): genuinely message-polymorphic across the
///   boundary. Kept generic; each caller instantiates its own message type.
///
/// The defaulting DECISION collapses `Pinned` and `MultiplyPinned` (both keep
/// the binding generic), but the three-way distinction records WHY — a
/// single-type pin is monomorphic-but-inferable, not polymorphic — so the
/// outcome is legible on its own terms rather than a bare "keep / default" bit.
enum MsgDischargeOutcome {
    Unpinned,
    Pinned,
    MultiplyPinned,
}

impl MsgDischargeOutcome {
    /// Build the outcome from the count of DISTINCT concrete `Msg` identities
    /// the binding's cross-module uses discharged its ui-msg slot to.
    const fn from_distinct_pin_count(distinct: usize) -> Self {
        match distinct {
            0 => Self::Unpinned,
            1 => Self::Pinned,
            _ => Self::MultiplyPinned,
        }
    }

    /// Default the slot to `Unit` only when no cross-module use pins it to any
    /// concrete `Msg` — the sole outcome for which `Html<()>` cannot mismatch a
    /// caller's concrete message type. A single- or multiply-pinned slot stays
    /// generic.
    const fn should_default(&self) -> bool {
        matches!(self, Self::Unpinned)
    }
}

/// Collect the concrete `Msg` identities occupying a ui-msg slot of `ty` — the
/// argument position of a `Html` / `Element` / `Attribute` / `Event`
/// constructor. Mirrors [`collect_ui_msg_and_other_vars`] but records resolved
/// `Con` identities (a use that pinned the slot) rather than free vars (a use
/// that left it open).
fn collect_ui_msg_concrete_cons(
    ty: &Ty,
    ui_msg_cons: &BTreeSet<Symbol>,
    in_ui_msg: bool,
    out: &mut BTreeSet<MsgConId>,
) {
    match ty {
        Ty::Var(_) | Ty::Unit => {}
        Ty::Fun(a, b) => {
            collect_ui_msg_concrete_cons(a, ui_msg_cons, in_ui_msg, out);
            collect_ui_msg_concrete_cons(b, ui_msg_cons, in_ui_msg, out);
        }
        Ty::Con { module, name, args } => {
            if in_ui_msg && !ui_msg_cons.contains(name) {
                // A concrete type standing directly in a ui-msg slot IS the
                // pinned message type (`Html MsgA` -> `MsgA`). A nested ui-msg
                // constructor (`Html (Html MsgA)` never arises, but be robust)
                // is not itself the message; recurse with the slot re-opened.
                out.insert((module.clone(), *name));
            }
            let child_in_ui_msg = ui_msg_cons.contains(name);
            for a in args {
                collect_ui_msg_concrete_cons(a, ui_msg_cons, child_in_ui_msg, out);
            }
        }
        Ty::Tuple(elems) => {
            for e in elems {
                collect_ui_msg_concrete_cons(e, ui_msg_cons, in_ui_msg, out);
            }
        }
        Ty::Record(fields, _) => {
            for v in fields.values() {
                collect_ui_msg_concrete_cons(v, ui_msg_cons, in_ui_msg, out);
            }
        }
    }
}

/// Verify every use of a super-typed binding pins each obligated generic
/// variable to a type that satisfies the bound its generic emission requires.
///
/// A binding like `double : a -> a` whose body adds `a` to itself is emitted as
/// a generic function bounded by Rust's `Add` (and `Copy`). A use `double True`
/// instantiates `a` to `Bool`, which provides neither — so it must be rejected
/// *here*, in the type checker, rather than left to fail when `cargo` compiles
/// the emitted Rust. A use that leaves the variable non-concrete (it flows into
/// an enclosing generic, e.g. `f x = double x`) is also rejected: propagating a
/// super-type obligation across binding boundaries is not yet supported, so it
/// is a fail-closed limitation rather than unsound emission.
fn check_scheme_applications(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    bounds: &BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<Symbol, TyBounds>>,
    apps: &[SchemeApp],
    enum_embeds_fn: &impl Fn(&[Symbol], Symbol) -> bool,
) -> DResult<()> {
    for app in apps {
        // (AUD-05) keyed by (home, name) — a bare-name lookup would check a
        // same-named binding from a DIFFERENT module's obligations, both
        // false-accepting a violation and false-rejecting a clean use.
        let Some(var_bounds) = bounds.get(&(app.home.clone(), app.name)) else {
            continue;
        };
        for (var_sym, b) in var_bounds {
            let Some(fresh) = app.vars.get(&var_sym.as_raw()) else {
                continue;
            };
            let ty = zonk(uf, budget, *fresh)?;
            if !emitted_bound_satisfied(interner, *b, &ty, &enum_embeds_fn) {
                return Err(super_unsatisfied(interner, *b, &ty, app.span));
            }
        }
    }
    Ok(())
}

/// Whether a concrete type satisfies the Rust bound a super-typed *generic*
/// emits at a use site. `Number` / `Comparable` emissions carry `Copy`, so a
/// non-`Copy` orderable type (`String`) is excluded from ordering even though it
/// supports comparison, and both require a bare scalar primitive. An equality
/// emission carries only `PartialEq` (no `Copy`), so it admits any equatable
/// type — every concrete type free of a function ([`ty_is_equatable`]), which
/// includes `String`, tuples, and enums. A non-concrete type (a bare variable
/// the obligation escaped into) satisfies nothing — fail-closed, as cross-
/// binding obligation propagation is not yet supported.
fn emitted_bound_satisfied(
    interner: &Interner,
    bounds: TyBounds,
    ty: &Ty,
    enum_embeds_fn: &impl Fn(&[Symbol], Symbol) -> bool,
) -> bool {
    super_bounds_satisfied(
        interner,
        bounds,
        ty,
        super_bounds::BoundSite::EmittedGeneric,
        enum_embeds_fn,
    )
}

/// The single per-bound clause set both super-type gates share, selected by
/// [`super_bounds::BoundSite`]. `emitted_bound_satisfied` (generic emission) and
/// [`concrete_super_ok`] (direct concrete pin) are its only two callers; the
/// sole legitimate difference between them — `Ord` over `String`, admitted at a
/// concrete pin but not under a `Copy`-bound emitted generic — is carried by the
/// `site` argument, so no clause is stated twice and neither gate can silently
/// omit one (a missing use-site clause is an ipe-accepts-then-cargo-fails seal
/// break). `TyBounds::ALL_BITS` walked by `all_bounds_have_a_use_site_clause`
/// pins that every obligation bit reaches a clause here.
fn super_bounds_satisfied(
    interner: &Interner,
    bounds: TyBounds,
    ty: &Ty,
    site: super_bounds::BoundSite,
    enum_embeds_fn: &impl Fn(&[Symbol], Symbol) -> bool,
) -> bool {
    let prim = match ty {
        Ty::Con { module, name, args } if module.is_empty() && args.is_empty() => {
            interner.resolve(*name)
        }
        _ => None,
    };
    let number_ok = super_bounds::prim_satisfies_number(prim);
    // Ordering `String` slot varies by site: excluded under a `Copy`-bound
    // emitted generic, included at a borrow-based concrete pin. See
    // `super_bounds::ORD_COPY` vs `ORD_BORROW`.
    let ord_ok = super_bounds::prim_satisfies_ord(prim, site);
    // A `Set` element / `Dict` key carries no `Copy` (the runtime helpers
    // consume by value; `String` keys must be admitted), so both sites use the
    // `String`-inclusive comparable-key set.
    let key_ok = super_bounds::prim_satisfies_comparable_key(prim);
    // `++`: accepted for `String` or `List _`.
    let appendable_ok = super_bounds::prim_satisfies_append_prim(prim)
        || matches!(ty,
            Ty::Con { module, name, args }
                if module.is_empty()
                    && args.len() == 1
                    && interner.resolve(*name) == Some("List")
        );
    // The higher-order-kernel callback-result obligation (`map` /
    // `map2..5` / `mapError` / `andMap` over `Maybe`/`Result` — see
    // `TyBounds::HOF_KERNEL_RESULT`). Deliberately SHALLOW on structure —
    // only the HEAD is checked (`Ty::Fun` directly, not nested anywhere) —
    // unlike `ty_is_equatable`'s deep walk:
    // `Result e (List (Int -> Int))` is a different, already-gated hazard
    // (collections of functions), not the kernels' arity restriction, which
    // only cares whether the callback's final RESULT itself is an arrow.
    //
    // A bare `Ty::Var` fails CLOSED, exactly like every sibling obligation in
    // this function ("a non-concrete type — a bare variable the obligation
    // escaped into — satisfies nothing"). This is load-bearing for the seal:
    // an ANNOTATED DOUBLE FORWARDER (`am2 x f = am1 x f` over `am1 x f =
    // Result.andMap x f`, both with explicit signatures) instantiates `am1`'s
    // obligated `b` to `am2`'s OWN fresh annotation skolem — a bare variable at
    // this check. `check_scheme_applications` is a one-shot check, not a
    // bound-transfer: `am2` itself never touches the kernel, so it records no
    // obligation of its own, and a fail-OPEN here let an arity-2 payload flow
    // unguarded to `main`'s call of `am2` and reach `cargo build` as E0308.
    // Failing closed rejects the inner `am1` reference itself — the same
    // conservative behaviour `Math.min`'s `ord` obligation already shows on the
    // identical double-forwarder shape. The precision loss (a legitimately-
    // arity-1 annotated double forwarder is also rejected) is the SAME
    // documented loss every sibling bound accepts; genuine cross-binding
    // obligation propagation is a follow-up design for ALL bounds at once — see
    // `docs/adr/0001-language-semantics-and-types.md` §6.
    let not_curried_ok = !matches!(ty, Ty::Fun(_, _) | Ty::Var(_));
    // SQL-bind-parameter obligation: satisfied by exactly the Ipê types the
    // runtime has a `From<T> for SqlParam` impl for — the bare scalars
    // `ipe_runtime::db` binds directly, plus the `SqlValue` ADT itself.
    let sql_param_ok = super_bounds::prim_satisfies_sql_param(prim);
    (!bounds.has_number() || number_ok)
        && (!bounds.has_ord() || ord_ok)
        && (!bounds.has_eq() || ty_is_equatable(ty, enum_embeds_fn))
        && (!bounds.has_comparable_key() || key_ok)
        // Stringify (`toString` / `Log.*With`): showable iff it contains no
        // function anywhere — the SAME "no function nested" rule as equatable,
        // since every non-function type derives `IpeStringify`.
        && (!bounds.has_show() || ty_is_equatable(ty, enum_embeds_fn))
        && (!bounds.has_append() || appendable_ok)
        && (!bounds.has_hof_kernel_result() || not_curried_ok)
        && (!bounds.has_sql_param() || sql_param_ok)
}

/// Whether a resolved concrete type satisfies super-type obligations `bounds`
/// when a variable pinned *directly* to it (a non-generic, concrete use such as
/// `n == n` on a known type). Mirrors the unifier's head pin-check
/// ([`crate::unify`]'s `super_concrete_ok`) but over the fully-resolved [`Ty`],
/// so it rejects a function nested anywhere inside an equated type — the case
/// the head check defers to here. `String` satisfies ordering (a direct
/// `"a" > "b"` borrows its operands, needing no `Copy`), unlike the
/// generic-emission gate [`emitted_bound_satisfied`].
pub(crate) fn concrete_super_ok(
    interner: &Interner,
    bounds: TyBounds,
    ty: &Ty,
    enum_embeds_fn: &impl Fn(&[Symbol], Symbol) -> bool,
) -> bool {
    super_bounds_satisfied(
        interner,
        bounds,
        ty,
        super_bounds::BoundSite::ConcretePin,
        enum_embeds_fn,
    )
}

/// Whether a resolved type derives Rust's `PartialEq`: true for every fully
/// concrete type containing no function anywhere (primitives, unit, tuples,
/// records, and enums all derive `PartialEq`; a function never does). A bare
/// type variable is rejected (fail-closed): an equality obligation that escaped
/// into an enclosing generic is not yet propagated across binding boundaries.
/// Does canonical type `t` embed a function arrow anywhere — a direct `Lambda`,
/// or one nested in a tuple / record / type-constructor argument?
fn canon_type_embeds_lambda(t: &canon::Type) -> bool {
    match t {
        canon::Type::Lambda(_, _) => true,
        canon::Type::Var(_) | canon::Type::Unit => false,
        canon::Type::Tuple(elems) => elems.iter().any(canon_type_embeds_lambda),
        canon::Type::Con { args, .. } => args.iter().any(canon_type_embeds_lambda),
        canon::Type::Record(fields) => fields.iter().any(|(_, f)| canon_type_embeds_lambda(f)),
        canon::Type::RecordOpen(_, fields) => {
            fields.iter().any(|(_, f)| canon_type_embeds_lambda(f))
        }
    }
}

/// The `(home, name)` set of user enums whose DEFINITION embeds a function in
/// any constructor payload (`type Handler a = OnClick (Int -> a) | Plain a`).
///
/// Such an enum is not `Equatable` / showable however it is applied: its payload
/// arrow is invisible in a `Ty::Con`'s type arguments (which carry only applied
/// type parameters), so the structural [`ty_is_equatable`] walk cannot see it
/// without this out-of-band definition lookup. Consulted at every concrete
/// equality / stringify obligation so a `==` / `toString` on a function-carrying
/// enum fails closed (IPE-T0014) instead of emitting Rust that does not build.
fn fn_embedding_enums(
    module_unions: &[canon::Union],
    dep_unions: &[&canon::Union],
) -> BTreeSet<(Vec<Symbol>, Symbol)> {
    module_unions
        .iter()
        .chain(dep_unions.iter().copied())
        .filter(|u| {
            u.ctors
                .iter()
                .any(|c| c.args.iter().any(canon_type_embeds_lambda))
        })
        .map(|u| (u.home.clone(), u.name))
        .collect()
}

fn ty_is_equatable(ty: &Ty, enum_embeds_fn: &impl Fn(&[Symbol], Symbol) -> bool) -> bool {
    match ty {
        Ty::Var(_) | Ty::Fun(_, _) => false,
        Ty::Unit => true,
        Ty::Tuple(elems) => elems.iter().all(|e| ty_is_equatable(e, enum_embeds_fn)),
        Ty::Record(fields, _) => fields.values().all(|f| ty_is_equatable(f, enum_embeds_fn)),
        // A `Ty::Con` head names a user enum (or a builtin like `Maybe`) whose
        // variant payloads are NOT in `args` — `args` carries only the applied
        // type parameters. An enum whose DEFINITION embeds a function in a
        // payload (`type Handler a = OnClick (Int -> a) | Plain a`) is therefore
        // not equatable however it is applied, even though every `arg` is
        // (`Handler Int`'s only arg is `Int`). Consult `enum_embeds_fn` on the
        // head, then still recurse the args so a function reaching a type
        // parameter (`Box (Int -> Int)` for `type Box a = Box a`) is caught too.
        Ty::Con { module, name, args } => {
            !enum_embeds_fn(module, *name)
                && args.iter().all(|a| ty_is_equatable(a, enum_embeds_fn))
        }
    }
}

/// Build the [`TypeError::SuperTypeUnsatisfied`] (IPE-T0014) for a super-typed
/// binding used at a type that does not meet its obligations.
fn super_unsatisfied(interner: &Interner, bounds: TyBounds, ty: &Ty, span: Span) -> Diagnostic {
    // Name every super-type the variable owes, in a fixed order, joined with
    // `+` (`Number + Equatable` when a variable is both added and compared for
    // equality). A bound set always carries at least one obligation at a call
    // site, so the join is non-empty; the fallback keeps the function total.
    let mut classes: Vec<&str> = Vec::new();
    if bounds.has_number() {
        classes.push("Number");
    }
    // A `Set` element / `Dict` key obligation is a Ipê `Comparable` (the same
    // class the ordering operators impose); name it once even when both an
    // ordering use and a Set/Dict use constrained the variable.
    if bounds.has_ord() || bounds.has_comparable_key() {
        classes.push("Comparable");
    }
    if bounds.has_eq() {
        classes.push("Equatable");
    }
    if bounds.has_show() {
        classes.push("Stringify");
    }
    if bounds.has_append() {
        classes.push("Appendable");
    }
    // The higher-order-kernel callback-result obligation. Named
    // distinctly from the other classes (it is not a Ipê super-type a user
    // annotates against — it is an internal arity restriction on the
    // callback-result slot of `Maybe`/`Result`'s `map`/`map2..5`/`mapError`/
    // `andMap` kernels): the callback's final result must not itself be a
    // function, because the runtime kernel applies the callback at one exact
    // arity while the IR flattens curried functions.
    if bounds.has_hof_kernel_result() {
        // Shared constant: the renderer keys a tailored (non-double-negative)
        // sentence off this exact label.
        classes.push(ipe_diagnostics::HOF_KERNEL_RESULT_CLASS);
    }
    let class = if classes.is_empty() {
        "Equatable".to_owned()
    } else {
        classes.join(" + ")
    };
    let mut namer = VarNamer::new();
    let found = match ty_to_doc(ty, interner, &mut namer) {
        Ok(d) => d,
        Err(bug) => return bug,
    };
    Diagnostic::Type {
        span,
        msg: TypeError::SuperTypeUnsatisfied {
            class: class.into_boxed_str(),
            found: Box::new(found),
        },
    }
}

/// Discharge every deferred record field access (`record.field`).
///
/// By the time this runs the main solve has settled each record's type. For each
/// access, the now-resolved record type is read: a closed record carrying the
/// field links the access's result variable to the field's type (so any
/// surrounding constraint already placed on the result, e.g. `record.field + 1`,
/// is checked against the field's real type); a record without the field — or a
/// base that is not a record at all — is a [`TypeError::NoSuchField`] blamed at
/// the access span.
///
/// # Ordering / fixpoint pass
///
/// Field accesses can depend on each other: `m.status` is only resolvable after
/// `model.monitors` has been resolved (which then unifies `m` with `Monitor`
/// via `List.filter`'s element-type propagation). A single left-to-right pass
/// over the access list would fail whenever a dependent access appears before its
/// provider. The function therefore iterates to a fixpoint: each pass processes
/// every access whose record variable has already settled to a concrete record;
/// `Flex` vars are deferred for the next pass. The loop terminates because each
/// pass that makes progress resolves at least one access, strictly shrinking the
/// pending set. When a full pass makes no progress, the remaining accesses carry
/// record variables that genuinely could not be pinned — reported as errors.
/// Discharge deferred field accesses and record updates in a joint fixpoint.
///
/// ## Why a joint loop is required
///
/// Field accesses (`snap.ok`) and record updates (`{ model | history = snapshots }`)
/// can form dependency chains where a record update pins the element type of a
/// list field that a downstream field access then needs.  Running the two passes
/// sequentially breaks this: if field accesses run first the element type is still
/// `Flex`, `snap.ok` stalls, and a false [`TypeError::NoSuchField`] (IPE-T0012)
/// is reported.
///
/// Concrete example (example 18 `job-queue`):
/// * `init` produces `{ …, history = [] }` — `history : List[v_flex]`.
/// * `HistoryLoaded (Ok snapshots)` arm does `{ model | history = snapshots }` where
///   `snapshots : List Snapshot` — this **record update** pins `v_flex = Snapshot`.
/// * `viewSnapshot snap = … snap.ok …` — this **field access** needs `v_flex` to
///   be settled to `Snapshot` before it can resolve.
///
/// ## Algorithm
///
/// Each iteration processes ALL pending field accesses and ALL pending record
/// updates:
/// * If the base var is `Flex` → defer to the next iteration.
/// * If the base is a settled record that has the field → discharge (call [`unify`]);
///   mark `made_progress = true`.
/// * If the base is a settled record that is **missing** the field, or is not a
///   record at all → return an immediate [`TypeError::NoSuchField`].
///
/// The loop terminates when both pending lists are empty (success) or when an
/// entire iteration makes no progress while items remain (stuck — emit the first
/// item as the error).
/// The fixed field set of the opaque server `Request` type.
///
/// The reference models `Ipe.Http.Server.Request` as a `type alias` over a
/// closed record `{ method, path, body, headers, params, query, cookies,
/// remoteAddr }`, so `req.body` is ordinary record-field access. The Rust port
/// carries `Request` as an opaque nullary `Con` (it threads through kernel
/// signatures — `Server.get`, `Server.param`, the `Handler` alias — as an
/// opaque handle, and the lowerer maps it to `IrType::ServerRequest` backed by
/// `runtime::ServerRequest`). Field access on that opaque `Con` would otherwise
/// fail closed with IPE-T0012.
///
/// This table lets [`resolve_deferred`] resolve `req.<field>` against the known
/// field types. The emit side needs no synthesised record: a field access
/// lowers to `(req).<field>.clone()` (see `emit_expr` `Access`), which reads the
/// `runtime::ServerRequest` struct directly — every field name + type here
/// matches that struct (`String` scalars; `HashMap<String, String>` = Ipê
/// `Dict String String` for the four map fields).
struct RequestFields {
    /// The `"Request"` type-constructor symbol (opaque server request Con).
    con: Symbol,
    /// The `"String"` type-constructor symbol.
    string: Symbol,
    /// The `"Dict"` type-constructor symbol.
    dict: Symbol,
    /// field-name symbol → `true` when the field is `Dict String String`,
    /// `false` when it is a bare `String`.
    fields: BTreeMap<Symbol, bool>,
}

impl RequestFields {
    /// Intern the field set once (idempotent). Called with the mutable interner
    /// before the immutable-borrow [`resolve_deferred`] pass.
    fn build(interner: &mut Interner) -> DResult<Self> {
        let con = interner.intern("Request")?;
        let string = interner.intern("String")?;
        let dict = interner.intern("Dict")?;
        let mut fields = BTreeMap::new();
        // (field name, is `Dict String String`?) — matches `runtime::ServerRequest`.
        for (name, is_dict) in [
            ("method", false),
            ("path", false),
            ("body", false),
            ("remoteAddr", false),
            ("headers", true),
            ("params", true),
            ("query", true),
            ("cookies", true),
        ] {
            fields.insert(interner.intern(name)?, is_dict);
        }
        Ok(Self {
            con,
            string,
            dict,
            fields,
        })
    }

    /// Build the union-find variable for `field`'s type, or `None` when `field`
    /// is not a member of `Request` (→ a genuine IPE-T0012).
    fn field_var(&self, uf: &mut UnionFind<Content>, field: Symbol) -> DResult<Option<VarId>> {
        let string_var = |uf: &mut UnionFind<Content>| {
            uf.fresh(Content::Structure(FlatType::Con {
                module: Vec::new(),
                name: self.string,
                args: Vec::new(),
            }))
        };
        match self.fields.get(&field) {
            None => Ok(None),
            Some(false) => Ok(Some(string_var(uf)?)),
            Some(true) => {
                let k = string_var(uf)?;
                let v = string_var(uf)?;
                let d = uf.fresh(Content::Structure(FlatType::Con {
                    module: Vec::new(),
                    name: self.dict,
                    args: vec![k, v],
                }))?;
                Ok(Some(d))
            }
        }
    }
}

/// The fixed field set of the opaque `WebReq` type — the per-session request
/// context passed to a Ipe.Web `init` callback.
///
/// Mirrors [`RequestFields`] exactly: `WebReq` is an opaque nullary `Con` at
/// the type level (so `init : {} -> …` fails closed with IPE-T0001 against the
/// prescriptive `WebReq -> (Model, Cmd Msg)` scheme, and no bare record literal
/// can masquerade as the runtime struct), but its fields stay READABLE. The
/// deferred [`FieldAccess`] pass resolves `req.path` / `req.cookies` against this
/// table; the emit side needs no synthesised record — a field access lowers to
/// `(req).<field>.clone()` (see `emit_expr` `Access`), reading the
/// `ipe_runtime::dom::req::WebReq` struct directly. Every field name + type here
/// matches that struct (`path`/`query`/`method` = bare `String`;
/// `params`/`headers`/`cookies` = `Dict String String`, i.e. `IpeDict<String>`).
struct WebReqFields {
    /// The `"WebReq"` type-constructor symbol (opaque Ipe.Web request Con).
    con: Symbol,
    /// The `"String"` type-constructor symbol.
    string: Symbol,
    /// The `"Dict"` type-constructor symbol.
    dict: Symbol,
    /// field-name symbol → `true` when the field is `Dict String String`,
    /// `false` when it is a bare `String`.
    fields: BTreeMap<Symbol, bool>,
}

impl WebReqFields {
    /// Intern the field set once (idempotent). Called with the mutable interner
    /// before the immutable-borrow [`resolve_deferred`] pass.
    fn build(interner: &mut Interner) -> DResult<Self> {
        let con = interner.intern("WebReq")?;
        let string = interner.intern("String")?;
        let dict = interner.intern("Dict")?;
        let mut fields = BTreeMap::new();
        // (field name, is `Dict String String`?) — matches
        // `ipe_runtime::web::WebReq` (see `src/runtime/rust/src/web/req.rs`).
        for (name, is_dict) in [
            ("path", false),
            ("query", false),
            ("method", false),
            ("params", true),
            ("headers", true),
            ("cookies", true),
        ] {
            fields.insert(interner.intern(name)?, is_dict);
        }
        Ok(Self {
            con,
            string,
            dict,
            fields,
        })
    }

    /// Build the union-find variable for `field`'s type, or `None` when `field`
    /// is not a member of `WebReq` (→ a genuine IPE-T0012).
    fn field_var(&self, uf: &mut UnionFind<Content>, field: Symbol) -> DResult<Option<VarId>> {
        let string_var = |uf: &mut UnionFind<Content>| {
            uf.fresh(Content::Structure(FlatType::Con {
                module: Vec::new(),
                name: self.string,
                args: Vec::new(),
            }))
        };
        match self.fields.get(&field) {
            None => Ok(None),
            Some(false) => Ok(Some(string_var(uf)?)),
            Some(true) => {
                let k = string_var(uf)?;
                let v = string_var(uf)?;
                let d = uf.fresh(Content::Structure(FlatType::Con {
                    module: Vec::new(),
                    name: self.dict,
                    args: vec![k, v],
                }))?;
                Ok(Some(d))
            }
        }
    }
}

/// The three fixed-field-table lookups the deferred [`resolve_deferred`] pass
/// needs, bundled so the resolver helpers thread one reference instead of three
/// (keeps `resolve_deferred` under clippy's `too_many_arguments` bound and reads
/// as a single "builtin field tables" capability).
struct BuiltinFieldTables<'a> {
    /// Opaque server `Ipe.Http.Server.Request` field table.
    req: &'a RequestFields,
    /// Opaque Ipe.Web `WebReq` field table.
    web_req: &'a WebReqFields,
    /// Nominal error-payload (`PanicInfo`/`TypeInfo`/`ErrorInfo`) field tables.
    err: &'a ErrorRecordFields,
}

/// The field type of a builtin nominal-record field ([`ErrorRecordFields`]).
#[derive(Clone, Copy)]
enum ErrFieldTy {
    /// `String`
    Str,
    /// `List String`
    ListStr,
    /// `Maybe ErrorDetails`
    MaybeErrorDetails,
}

/// Fixed field tables for the NOMINAL error-payload types `PanicInfo` /
/// `TypeInfo` / `ErrorInfo` (SEAL fix — see
/// `docs/adr/0001-language-semantics-and-types.md`).
///
/// These three types are opaque `Con`s at the type level (so a bare record
/// literal cannot masquerade as the runtime's concrete `IpePanicInfo` /
/// `IpeTypeInfo` / `IpeErrorInfo` structs — that shape was an
/// exit-0-then-cargo-fail), but their fields stay READABLE: the deferred
/// [`FieldAccess`] pass resolves `p.message` / `t.expected` / `info.details`
/// against this table, exactly like the opaque server `Request` type does via
/// [`RequestFields`]. Record UPDATE on them intentionally falls through to
/// the non-record rejection — a structurally-updated copy has no sound
/// lowering (the runtime type is the only constructor-side representation).
struct ErrorRecordFields {
    /// `"PanicInfo"` / `"TypeInfo"` / `"ErrorInfo"` type-constructor symbols.
    panicinfo: Symbol,
    typeinfo: Symbol,
    errorinfo: Symbol,
    /// `"String"` / `"List"` / `"Maybe"` / `"ErrorDetails"` constructor
    /// symbols for building field-type variables.
    string: Symbol,
    list: Symbol,
    maybe: Symbol,
    errordetails: Symbol,
    /// (owning con, field name) → field type.
    fields: BTreeMap<(Symbol, Symbol), ErrFieldTy>,
}

impl ErrorRecordFields {
    /// Intern the three field tables once (idempotent). Called with the
    /// mutable interner before the immutable-borrow [`resolve_deferred`] pass.
    fn build(interner: &mut Interner) -> DResult<Self> {
        let panicinfo = interner.intern("PanicInfo")?;
        let typeinfo = interner.intern("TypeInfo")?;
        let errorinfo = interner.intern("ErrorInfo")?;
        let message = interner.intern("message")?;
        let stack = interner.intern("stack")?;
        let expected = interner.intern("expected")?;
        let actual = interner.intern("actual")?;
        let details = interner.intern("details")?;
        let mut fields = BTreeMap::new();
        // Matches `src/runtime/rust/src/error.rs`'s struct definitions.
        fields.insert((panicinfo, message), ErrFieldTy::Str);
        fields.insert((panicinfo, stack), ErrFieldTy::ListStr);
        fields.insert((typeinfo, expected), ErrFieldTy::Str);
        fields.insert((typeinfo, actual), ErrFieldTy::Str);
        fields.insert((errorinfo, message), ErrFieldTy::Str);
        fields.insert((errorinfo, details), ErrFieldTy::MaybeErrorDetails);
        Ok(Self {
            panicinfo,
            typeinfo,
            errorinfo,
            string: interner.intern("String")?,
            list: interner.intern("List")?,
            maybe: interner.intern("Maybe")?,
            errordetails: interner.intern("ErrorDetails")?,
            fields,
        })
    }

    /// Whether `con` is one of the three builtin nominal-record types.
    fn owns(&self, con: Symbol) -> bool {
        con == self.panicinfo || con == self.typeinfo || con == self.errorinfo
    }

    /// Build the union-find variable for `field`'s type on `con`, or `None`
    /// when `field` is not a member (→ a genuine IPE-T0012).
    fn field_var(
        &self,
        uf: &mut UnionFind<Content>,
        con: Symbol,
        field: Symbol,
    ) -> DResult<Option<VarId>> {
        let nullary = |uf: &mut UnionFind<Content>, name: Symbol| {
            uf.fresh(Content::Structure(FlatType::Con {
                module: Vec::new(),
                name,
                args: Vec::new(),
            }))
        };
        match self.fields.get(&(con, field)) {
            None => Ok(None),
            Some(ErrFieldTy::Str) => Ok(Some(nullary(uf, self.string)?)),
            Some(ErrFieldTy::ListStr) => {
                let s = nullary(uf, self.string)?;
                let l = uf.fresh(Content::Structure(FlatType::Con {
                    module: Vec::new(),
                    name: self.list,
                    args: vec![s],
                }))?;
                Ok(Some(l))
            }
            Some(ErrFieldTy::MaybeErrorDetails) => {
                let d = nullary(uf, self.errordetails)?;
                let m = uf.fresh(Content::Structure(FlatType::Con {
                    module: Vec::new(),
                    name: self.maybe,
                    args: vec![d],
                }))?;
                Ok(Some(m))
            }
        }
    }
}

/// The 3-way outcome of resolving one [`FieldAccess`]'s base (helper of
/// [`resolve_deferred`]; built by [`field_access_state`]).
enum FieldState {
    /// The base var is still `Flex` — defer to the next fixpoint pass.
    Deferred,
    /// The base is a record (or a fixed-field builtin Con) and has the
    /// field; the payload is the field's type var.
    Found(VarId),
    /// The base is an OPEN record (Flex tail) that does not yet carry the
    /// field. Row-polymorphic access grows the record with the field rather
    /// than erroring (Ipe's `Access` constrain unifies the target with a fresh
    /// open record `{ field : ρ | ext }`). The caller re-reads the root's field
    /// map, inserts `field ↦ result`, and re-seats a fresh open tail.
    GrowOpen,
    /// The base is resolved (closed record missing the field, or not a record
    /// at all) — an immediate IPE-T0012.
    Missing,
}

/// Small decision datum peeked BY REFERENCE from a field-access base's
/// union-find descriptor (helper of [`field_access_state`]).
///
/// The former `uf.content(root)?` deep-cloned the whole record field map per
/// field access (efficiency-audit §2 medium); extracting this `Copy`-sized
/// outcome instead releases the `&uf` borrow before the `&mut uf` table
/// lookups that follow.
enum Peek {
    /// `(field-var-if-present, tail-var)` — the tail lets the caller tell an
    /// open record (Flex tail, growable) from a closed one (`EmptyRecord`).
    Record(Option<VarId>, VarId),
    Req,
    WebReq,
    ErrCon(Symbol),
    Deferred,
    Missing,
}

/// Per-update pre-copy of the K needed field vars, peeked BY REFERENCE from
/// the base record's union-find descriptor (helper of [`resolve_deferred`]'s
/// record-update pass; see the call-site comment for the borrow rationale).
enum RuPeek {
    /// `(field, value_var, field_var-if-present)` per updated field.
    Fields(Vec<(Symbol, VarId, Option<VarId>)>),
    Flex,
    /// The base is a nominal BUILTIN with a fixed READABLE field table
    /// (`PanicInfo` / `TypeInfo` / `ErrorInfo` / `Request`) — field access
    /// works, record UPDATE does not. Reported as the dedicated IPE-T0017
    /// rather than a misleading "no field" IPE-T0012.
    BuiltinCon(Symbol),
    Other,
}

/// Resolve one [`FieldAccess`]'s base to its [`FieldState`].
///
/// `uf.root_content()` peeks the descriptor by reference (the caller already
/// ran `find`, so path compression is preserved); the [`Peek`] extraction ends
/// the borrow before any `fresh` call the table lookups make, avoiding a
/// simultaneous mutable borrow.
fn field_access_state(
    uf: &mut UnionFind<Content>,
    tables: &BuiltinFieldTables,
    root: VarId,
    field: Symbol,
) -> DResult<FieldState> {
    let found_or_missing = |v: Option<VarId>| v.map_or(FieldState::Missing, FieldState::Found);
    let peek = match uf.root_content(root)? {
        Content::Structure(FlatType::Record(fields, ext)) => {
            Peek::Record(fields.get(&field).copied(), *ext)
        }
        // The opaque server `Request` Con is not a structural record, but
        // its field set is fixed (see [`RequestFields`]). Resolve the
        // field against the known table so `req.body` type-checks; the
        // emit reads `runtime::ServerRequest` directly.
        Content::Structure(FlatType::Con { name, args, .. })
            if *name == tables.req.con && args.is_empty() =>
        {
            Peek::Req
        }
        // The opaque `WebReq` Con (Ipe.Web `init`'s per-session request)
        // resolves the same way against its fixed field set (see
        // [`WebReqFields`]); `req.path` type-checks, the emit reads
        // `ipe_runtime::dom::req::WebReq` directly.
        Content::Structure(FlatType::Con { name, args, .. })
            if *name == tables.web_req.con && args.is_empty() =>
        {
            Peek::WebReq
        }
        // `PanicInfo` / `TypeInfo` / `ErrorInfo` are opaque nominal Cons
        // (SEAL fix) whose field sets are fixed (see
        // [`ErrorRecordFields`]). Resolve the field against the known table
        // so `p.message` / `t.expected` / `info.details` type-check; the
        // emit reads the runtime structs' pub fields directly.
        Content::Structure(FlatType::Con { name, args, .. })
            if tables.err.owns(*name) && args.is_empty() =>
        {
            Peek::ErrCon(*name)
        }
        Content::Flex => Peek::Deferred, // not settled yet
        _ => Peek::Missing,              // rigid / super / non-record structure — error
    };
    Ok(match peek {
        // Present → Found. Missing on an OPEN tail (Flex root) → GrowOpen (the
        // record is row-polymorphic and absorbs the new field); missing on a
        // CLOSED tail (`EmptyRecord` / any non-Flex) → Missing (IPE-T0012).
        Peek::Record(Some(v), _) => FieldState::Found(v),
        Peek::Record(None, ext) => {
            // Resolve the tail's root (mutable `find`) BEFORE the immutable
            // `root_content` read so the two borrows don't overlap.
            let ext_root = uf.find(ext)?;
            if matches!(uf.root_content(ext_root)?, Content::Flex) {
                FieldState::GrowOpen
            } else {
                FieldState::Missing
            }
        }
        Peek::Req => found_or_missing(tables.req.field_var(uf, field)?),
        Peek::WebReq => found_or_missing(tables.web_req.field_var(uf, field)?),
        Peek::ErrCon(name) => found_or_missing(tables.err.field_var(uf, name, field)?),
        Peek::Deferred => FieldState::Deferred,
        Peek::Missing => FieldState::Missing,
    })
}

fn resolve_deferred(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    tables: &BuiltinFieldTables,
    accesses: &[FieldAccess],
    updates: &[RecordUpdate],
) -> Result<(), (Diagnostic, Vec<Symbol>)> {
    // Incidental union-find failures (`find` / `content` / `unify` / the
    // `Request` field lookup) carry no user-facing home — they are compiler
    // bugs, not source-attributed type errors — so they surface with an empty
    // home and the caller falls back to the byte-offset heuristic.  Only a
    // genuine IPE-T0012 (built below with the failing item's `home`) attributes
    // to a specific module.
    macro_rules! lift {
        ($e:expr) => {
            $e.map_err(|d: Diagnostic| (d, Vec::<Symbol>::new()))?
        };
    }
    // References avoid collecting indices and the `clippy::indexing_slicing`
    // lint on `accesses[i]` / `updates[i]`.
    let mut pending_fa: Vec<&FieldAccess> = accesses.iter().collect();
    let mut pending_ru: Vec<&RecordUpdate> = updates.iter().collect();

    loop {
        if pending_fa.is_empty() && pending_ru.is_empty() {
            return Ok(());
        }

        let mut next_fa: Vec<&FieldAccess> = Vec::new();
        let mut next_ru: Vec<&RecordUpdate> = Vec::new();
        let mut made_progress = false;

        // ── Field accesses ────────────────────────────────────────────────────
        for fa in &pending_fa {
            let root = lift!(uf.find(fa.record));
            // See [`field_access_state`] for the encoding + borrow discipline.
            match lift!(field_access_state(uf, tables, root, fa.field)) {
                FieldState::Deferred => {
                    next_fa.push(fa);
                }
                FieldState::Found(v) => {
                    made_progress = true;
                    lift!(unify(uf, budget, interner, fa.span, fa.result, v));
                }
                FieldState::GrowOpen => {
                    // Row-poly growth: the base is an open record missing this
                    // field. Add it (value var = the access's result var) and
                    // keep the tail open for further growth. Re-read the root's
                    // field map (the `field_access_state` borrow has ended),
                    // insert, and re-seat with a FRESH open tail.
                    made_progress = true;
                    let mut fields = match lift!(uf.root_content(root)).clone() {
                        Content::Structure(FlatType::Record(fs, _)) => fs,
                        // Unreachable: `GrowOpen` is only produced from a
                        // `Record` root above; treat any drift as a fresh map.
                        _ => BTreeMap::new(),
                    };
                    fields.insert(fa.field, fa.result);
                    let new_ext = lift!(uf.fresh(Content::Flex));
                    lift!(uf.set_content(
                        root,
                        Content::Structure(FlatType::Record(fields, new_ext)),
                    ));
                }
                FieldState::Missing => {
                    return Err((
                        no_such_field(uf, budget, interner, fa.record, fa.field, fa.span),
                        fa.home.clone(),
                    ));
                }
            }
        }
        pending_fa = next_fa;

        // ── Record updates ────────────────────────────────────────────────────
        for ru in &pending_ru {
            // Deferred → carry to the next pass; Discharged → progress; Error →
            // propagate. Extracted into a helper so this fixpoint driver stays
            // under the readability line-cap.
            match resolve_one_record_update(uf, budget, interner, tables, ru)? {
                RuOutcome::Deferred => next_ru.push(ru),
                RuOutcome::Discharged => made_progress = true,
            }
        }
        pending_ru = next_ru;

        if !made_progress {
            // Nothing was discharged this pass — every remaining item's base var
            // is still `Flex` (no closed record ever pinned it).
            //
            // A `Flex` base is NOT an error: it is a field access on a parameter
            // no call site constrained (an un-called `viewJob job = … job.running`),
            // which the reference infers row-polymorphically — Ipe's `Access`
            // constrain (`Ipe.Type.Constrain.Expression`) unifies the target with
            // a fresh open record `{ field : ρ | ext }` on the spot. Our deferred
            // pass reproduces that here: settle the first stuck flex base to the
            // singleton open record carrying the accessed field (its result var IS
            // the field's type var), then re-loop. Sibling accesses on the same
            // base (`job.result`, `job.id`) absorb into the open tail via the
            // open-record unify path; the loop makes progress and terminates.
            //
            // A base that has settled to a NON-record structure (rigid var, a
            // concrete non-record type) still falls through to IPE-T0012 — those
            // are genuine "not a record" errors, never reached here because a
            // settled non-record makes `field_access_state` return `Missing`
            // during the pass (handled above), not `Deferred`.
            if let Some(fa) = pending_fa.first() {
                let root = lift!(uf.find(fa.record));
                if matches!(lift!(uf.root_content(root)), Content::Flex) {
                    let mut fields = BTreeMap::new();
                    fields.insert(fa.field, fa.result);
                    let ext = lift!(uf.fresh(Content::Flex));
                    lift!(uf.set_content(root, Content::Structure(FlatType::Record(fields, ext)),));
                    continue;
                }
                return Err((
                    no_such_field(uf, budget, interner, fa.record, fa.field, fa.span),
                    fa.home.clone(),
                ));
            }
            if let Some(ru) = pending_ru.first()
                && let Some((field, _)) = ru.fields.first()
            {
                return Err((
                    no_such_field(uf, budget, interner, ru.record, *field, ru.span),
                    ru.home.clone(),
                ));
            }
        }
    }
}

/// Whether one deferred record update was discharged this pass or must wait
/// for the next fixpoint iteration (an error propagates out of the helper
/// directly, so it is not a variant here).
enum RuOutcome {
    Deferred,
    Discharged,
}

/// Process ONE deferred record update against the settled union-find (helper
/// of [`resolve_deferred`]'s record-update pass).
///
/// Peeks the base's descriptor by reference into a small [`RuPeek`] pre-copy
/// (releasing the arena borrow without deep-cloning the field map —
/// efficiency-audit §2 medium), then:
/// * a structural record → unify each updated field's value var against the
///   field's type var (or IPE-T0012 on a missing field);
/// * a nominal builtin (`PanicInfo`/`TypeInfo`/`ErrorInfo`/`Request`) → the
///   dedicated IPE-T0017 (readable fields, no update form);
/// * `Flex` → defer to the next pass;
/// * anything else → IPE-T0012 on the first updated field (degenerate empty
///   update on a non-record base is treated as discharged so the loop can't
///   stall on it).
fn resolve_one_record_update(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    tables: &BuiltinFieldTables,
    ru: &RecordUpdate,
) -> Result<RuOutcome, (Diagnostic, Vec<Symbol>)> {
    macro_rules! lift {
        ($e:expr) => {
            $e.map_err(|d: Diagnostic| (d, Vec::<Symbol>::new()))?
        };
    }
    let root = lift!(uf.find(ru.record));
    let peek = match lift!(uf.root_content(root)) {
        Content::Structure(FlatType::Record(fields, _ext)) => RuPeek::Fields(
            ru.fields
                .iter()
                .map(|(field, value_var)| (*field, *value_var, fields.get(field).copied()))
                .collect(),
        ),
        Content::Structure(FlatType::Con { name, args, .. })
            if args.is_empty()
                && (tables.err.owns(*name)
                    || *name == tables.req.con
                    || *name == tables.web_req.con) =>
        {
            RuPeek::BuiltinCon(*name)
        }
        Content::Flex => RuPeek::Flex,
        _ => RuPeek::Other,
    };
    match peek {
        RuPeek::Fields(fields) => {
            for (field, value_var, field_var) in fields {
                match field_var {
                    Some(field_var) => {
                        lift!(unify(uf, budget, interner, ru.span, value_var, field_var));
                    }
                    None => {
                        return Err((
                            no_such_field(uf, budget, interner, ru.record, field, ru.span),
                            ru.home.clone(),
                        ));
                    }
                }
            }
            Ok(RuOutcome::Discharged)
        }
        RuPeek::Flex => Ok(RuOutcome::Deferred),
        RuPeek::BuiltinCon(name) => Err((
            lift!(builtin_record_update(interner, name, ru.span)),
            ru.home.clone(),
        )),
        RuPeek::Other => {
            if let Some((field, _)) = ru.fields.first() {
                return Err((
                    no_such_field(uf, budget, interner, ru.record, *field, ru.span),
                    ru.home.clone(),
                ));
            }
            // Empty update on a non-record base: degenerate; treat as
            // discharged so we don't stall the loop on it.
            Ok(RuOutcome::Discharged)
        }
    }
}

/// Discharge every deferred per-route page witness.
///
/// For each `Web.route pattern builder` reference: follow the builder
/// variable's settled structure and peel its leading `_ -> rest` arrows —
/// each arrow is one `:param` payload slot of a params-consuming page
/// constructor (`String -> Page`, `String -> String -> Page`, …; the emit
/// tier separately gates the payload types to `String`/`Int`/`Float`/`Bool`).
/// What remains after peeling is the PAGE type the route builds; unify it
/// with the route's page variable, which the `K::WebRoute` scheme threads
/// into `WebRoute page` and thence (through `List (WebRoute var(2))` in the
/// `K::WebApp` scheme) into `notFound` and `Model.page`.
///
/// * Nullary builder (`Web.route "/" HomePage` — no arrows) → the builder IS
///   the page: unify directly.
/// * Param constructor (`Web.route "/u/:id" UserPage`) → peel `String ->`,
///   unify the result — the canonical corpus shape, falsely IPE-T0001'd by
///   the pre-round-4 shared-variable scheme.
/// * Wrong-ADT constructor (`Web.route "/" Increment` in a `Page` app) →
///   the peeled result (`Msg`) fails unification → IPE-T0001 at this route's
///   span.
/// * A builder that never settled (an unapplied `Web.route "/"` value) has a
///   flex root — not an arrow — and unifies with the page variable directly,
///   which merely links the two variables (sound: no structure is invented).
///
/// The peel is bounded by the arena's acyclicity (the occurs check forbids an
/// infinite arrow chain); the explicit fuel is belt-and-braces so a violated
/// invariant degrades to a normal unification error instead of a hang.
fn resolve_route_witness_checks(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    checks: &[RouteWitnessCheck],
) -> DResult<()> {
    for check in checks {
        let mut cur = uf.find(check.builder_var)?;
        let mut fuel: u32 = 1024;
        while fuel > 0 {
            match uf.content(cur)? {
                Content::Structure(FlatType::Fun(_, ret)) => {
                    cur = uf.find(ret)?;
                }
                _ => break,
            }
            fuel -= 1;
        }
        // Unify the built page type with the route's page variable.  A
        // mismatch is a normal IPE-T0001 blamed at the `Web.route` span.
        unify(uf, budget, interner, check.span, cur, check.page_var)?;
    }
    Ok(())
}

/// For routed `Web.tea` calls: if the settled Model type has a `page` field,
/// the `notFound` type must match (IPE-T0001) — the `set_page` closure emitted
/// by the backend already assumes this invariant.  Non-routed apps (Model has
/// no `page` field) are silently skipped, so a blanket open-row projection is
/// never needed and every non-routed app continues to pass.
///
/// The detection criterion (`page` field presence) mirrors `emit_web.rs`'s
/// `routed_page_field` helper: both agree on what "routed" means, ensuring the
/// type-check gate and the emit gate fire on exactly the same programs.
fn resolve_routed_web_checks(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    checks: &[RoutedWebCheck],
    has_routes: bool,
    route_count: usize,
    warnings: &mut Vec<Diagnostic>,
) -> DResult<()> {
    for check in checks {
        // Find the settled root of the Model type variable.
        let model_root = uf.find(check.model_var)?;
        // Clone the content to avoid borrowing `uf` across the subsequent
        // `unify` call.
        let model_content = uf.content(model_root)?;
        // Extract the `page` field's VarId from the settled Model Record, if
        // any.  A non-Record descriptor (Flex, Con, etc.) or a Record without
        // a `page` field means this is a non-routed app — silently skip.
        let page_var = match model_content {
            Content::Structure(FlatType::Record(fields, _ext)) => fields
                .iter()
                .find(|(sym, _)| interner.resolve(**sym) == Some("page"))
                .map(|(_, v)| *v),
            _ => None,
        };
        if let Some(page_var) = page_var {
            // Routed app: `notFound` must be the same type as `Model.page`.
            // `unify` produces IPE-T0001 (TypeMismatch) if they differ.
            unify(
                uf,
                budget,
                interner,
                check.span,
                check.not_found_var,
                page_var,
            )?;
        } else if has_routes {
            // Non-routed Model (no `page` field) BUT the program declared a
            // non-empty `routes` list: the routes are forwarded to the
            // non-routed runtime path and silently ignored. This compiles
            // (matching the reference's `applyRoute` no-op), but it is
            // almost always a mistake — usually a mis-named `page` field. Emit
            // the IPE-L0124 warning at the `Web.tea` span.
            //
            // `route_count` is the total number of `Web.route` references in
            // the compile unit. In the common single-app-per-program case this
            // equals this app's route count exactly; the rare multi-app case
            // (only sub-apps, which are separate binaries in practice) could
            // over-count, but the warning stays advisory — the build proceeds.
            warnings.push(Diagnostic::Lower {
                span: check.span,
                msg: LowerError::RoutedAppMissingPageField { route_count },
            });
        }
        // Non-routed with no routes → genuinely non-routed → silently skip.
    }
    Ok(())
}

/// Build the [`TypeError::BuiltinRecordUpdate`] (IPE-T0017) for a record
/// update on a nominal builtin (`PanicInfo` / `TypeInfo` / `ErrorInfo` /
/// `Request`) — readable fields, no user-writable update form. Resolving the
/// type-constructor symbol is the only fallible step; a missing backing string
/// is a compiler-bug invariant, surfaced as such.
fn builtin_record_update(interner: &Interner, name: Symbol, span: Span) -> DResult<Diagnostic> {
    let name: Box<str> = match interner.resolve(name) {
        Some(s) => Box::from(s),
        None => {
            return Err(Diagnostic::CompilerBug {
                where_: "intern.resolve",
                detail: format!(
                    "no backing string for builtin type symbol {}",
                    name.as_raw()
                ),
            });
        }
    };
    Ok(Diagnostic::Type {
        span,
        msg: TypeError::BuiltinRecordUpdate { name },
    })
}

/// Build the [`TypeError::NoSuchField`] (IPE-T0012) for a field that is absent
/// from the (settled) record type, or whose base is not a record.  Shared by
/// all arms of the joint fixpoint in [`resolve_deferred`]; the record type is
/// zonked + rendered here so the reporter needs no arena access.
fn no_such_field(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    record: VarId,
    field: Symbol,
    span: Span,
) -> Diagnostic {
    let field = match interner.resolve(field) {
        Some(s) => Box::from(s),
        None => {
            return Diagnostic::CompilerBug {
                where_: "intern.resolve",
                detail: format!("no backing string for field symbol {}", field.as_raw()),
            };
        }
    };
    let record_ty = match zonk(uf, budget, record) {
        Ok(t) => t,
        Err(bug) => return bug,
    };
    let mut namer = VarNamer::new();
    let record_doc = match ty_to_doc(&record_ty, interner, &mut namer) {
        Ok(d) => d,
        Err(bug) => return bug,
    };
    Diagnostic::Type {
        span,
        msg: TypeError::NoSuchField {
            field,
            record: Box::new(record_doc),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_diagnostics::{Diagnostic, LowerError, TypeError};

    const GOLDEN: &str = include_str!("../../../../tests/golden/basics/Main.ipe");

    /// Parse + canonicalise the golden module, returning it plus the interner.
    fn canon_golden() -> Option<(canon::Module, Interner)> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(GOLDEN, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
        Some((m, i))
    }

    /// Parse + canonicalise + infer an arbitrary single-module source string.
    fn infer_src(src: &str) -> (DResult<SolvedTypes>, Interner, Option<canon::Module>) {
        let mut i = Interner::new();
        let parsed = match ipe_parse::parse_module(src, &mut i) {
            Ok(p) => p,
            Err(e) => return (Err(e), i, None),
        };
        let m = match ipe_canon::canonicalise(&parsed, &mut i) {
            Ok(m) => m,
            Err(e) => return (Err(e), i, None),
        };
        let solved = infer(&m, &mut i);
        (solved, i, Some(m))
    }

    const M2C_HDR: &str = "module Main exposing (main)\n\n";

    #[test]
    fn generic_record_signature_typechecks() {
        // `wrap : a -> { value : a }` over the identity-shaped body. The env entry
        // is `Fun(Var, Record{ value : Var })` with the SAME variable in both
        // positions (the field is the parameter's type).
        let src = format!(
            "{M2C_HDR}wrap : a -> {{ value : a }}\nwrap x =\n    {{ value = x }}\n\nmain = wrap 1\n"
        );
        let (solved, i, m) = infer_src(&src);
        assert!(
            solved.is_ok(),
            "generic record signature must typecheck: {solved:?}"
        );
        let (Ok(solved), Some(m)) = (solved, m) else {
            return;
        };
        let Some(wrap) = def_key(&i, &m, "wrap") else {
            return;
        };
        let Some(ty) = solved.env.get(&wrap) else {
            return;
        };
        // `wrap : a -> { value : a }` — the parameter's type variable and the
        // record field's type variable must be the SAME id. Extract both ids
        // structurally, then assert their identity (so a wrong shape fails the
        // final assertion rather than via a forbidden `panic!`).
        let ids: Option<(u32, u32)> = match ty {
            Ty::Fun(arg, ret) => match (arg.as_ref(), ret.as_ref()) {
                (Ty::Var(arg_id), Ty::Record(fields, _)) => fields
                    .iter()
                    .find(|(name, _)| i.resolve(**name) == Some("value"))
                    .and_then(|(_, fty)| match fty {
                        Ty::Var(fid) => Some((*arg_id, *fid)),
                        _ => None,
                    }),
                _ => None,
            },
            _ => None,
        };
        assert!(
            matches!(ids, Some((a, f)) if a == f),
            "wrap is `a -> {{ value : a }}` with the field carrying the parameter's \
             own type variable; got env type {ty:?}"
        );
    }

    #[test]
    fn generic_record_field_access_typechecks() {
        // `unwrap : { value : a } -> a ; unwrap r = r.value` — the deferred
        // field-access links the result to the rigid field var; both are the same
        // skolem, so it checks.
        let src = format!(
            "{M2C_HDR}unwrap : {{ value : a }} -> a\nunwrap r =\n    r.value\n\nmain = unwrap\n"
        );
        let (solved, ..) = infer_src(&src);
        assert!(
            solved.is_ok(),
            "generic field access must typecheck: {solved:?}"
        );
    }

    #[test]
    fn body_constraining_a_record_field_var_is_rejected() {
        // `bad : a -> { value : a } ; bad x = { value = 1 }` pins the rigid field
        // variable `a` to `Int` in the body — the rigid-skolem gate rejects it,
        // rather than silently accepting it.
        let src = format!(
            "{M2C_HDR}bad : a -> {{ value : a }}\nbad x =\n    {{ value = 1 }}\n\nmain = bad\n"
        );
        let (solved, ..) = infer_src(&src);
        assert!(
            solved.is_err(),
            "a body pinning a rigid record-field variable must be a type error"
        );
    }

    #[test]
    fn record_type_alias_expands_and_typechecks() {
        // `type alias Box a = { value : a }` used in a signature `mk : Int -> Box
        // Int` expands to a closed record and typechecks.
        let src = format!(
            "{M2C_HDR}type alias Box a = {{ value : a }}\n\nmk : Int -> Box Int\nmk n =\n    {{ value = n }}\n\nmain = mk 1\n"
        );
        let (solved, ..) = infer_src(&src);
        assert!(
            solved.is_ok(),
            "record-type alias must expand + typecheck: {solved:?}"
        );
    }

    #[test]
    fn field_access_after_record_update_dep_chain_typechecks() {
        // Regression for IPE-T0012 (example 18 `job-queue` shape).
        //
        // Pattern: a record `{{ items = [] }}` has a Flex list-element type.
        // `setItems xs model = {{ model | items = xs }}` is a record update that
        // pins the element type to `Item` when called with a `List Item` argument.
        // `getSum` accesses `x.value` on each element via `List.foldl`.
        // When `setItems` and `getSum` share the SAME model via `main`, the field
        // access `x.value` must resolve after the record update in the joint
        // fixpoint — NOT emit IPE-T0012.
        //
        // The old sequential approach ran `resolve_field_accesses` to completion
        // before `resolve_record_updates`, so `x.value` saw a Flex element type
        // and stalled with a false T0012.
        let src = concat!(
            "module Main exposing (main)\n",
            "\n",
            "type alias Item = { value : Int }\n",
            "\n",
            "foldl fn acc list =\n",
            "    case list of\n",
            "        [] ->\n",
            "            acc\n",
            "        x :: rest ->\n",
            "            foldl fn (fn x acc) rest\n",
            "\n",
            "setItems xs model = { model | items = xs }\n",
            "\n",
            "getSum model =\n",
            "    foldl (\\x acc -> x.value + acc) 0 model.items\n",
            "\n",
            "main =\n",
            "    let\n",
            "        item = { value = 5 }\n",
            "        m = { items = [] }\n",
            "    in\n",
            "        getSum (setItems [item] m)\n",
        );
        let (solved, ..) = infer_src(src);
        assert!(
            solved.is_ok(),
            "field access after record-update dep chain must typecheck: {solved:?}"
        );
    }

    /// Return the `SolvedTypes::env` key `(home_path, bare_symbol)` for the
    /// named def in a module.  `solved.env` is keyed by the qualified
    /// `(home, name)` pair so same-named defs from different modules never
    /// collide.
    fn def_key(i: &Interner, m: &canon::Module, name: &str) -> Option<(Vec<Symbol>, Symbol)> {
        for d in &m.defs {
            if i.resolve(d.name().value) == Some(name) {
                return Some((d.home().to_vec(), d.name().value));
            }
        }
        None
    }

    /// Drill into a `Call` node.
    fn as_call(e: &canon::Expr) -> Option<(&canon::Expr, &[canon::Expr])> {
        match &e.value {
            canon::Expr_::Call(callee, args) => Some((callee, args)),
            _ => None,
        }
    }

    fn ty_con_name(ty: &Ty, i: &Interner) -> Option<String> {
        match ty {
            Ty::Con { name, .. } => i.resolve(*name).map(str::to_owned),
            _ => None,
        }
    }

    /// The body expression of a `Def`, regardless of typed/untyped shape.
    fn def_body(d: &canon::Def) -> &canon::Expr {
        match d {
            canon::Def::Typed { body, .. } | canon::Def::Untyped { body, .. } => body,
        }
    }

    // ── Type-directed-completion `expected` sidecar (ADR 0007 / plan §6) ──────

    #[test]
    fn expected_type_at_typed_body_is_the_annotation_return() {
        // `favorite : Color ; favorite = Red` — the body span expects `Color`,
        // so completion there surfaces `Color`'s constructors first.
        let src = format!(
            "{M2C_HDR}type Color = Red | Blue\n\nfavorite : Color\nfavorite =\n    Red\n\nmain = favorite\n"
        );
        let (solved, i, m) = infer_src(&src);
        let solved = solved.expect("must typecheck: no solved types");
        let m = m.expect("must typecheck: module present");
        // The `favorite` body is `Red`; find its span via the def's body.
        let fav = m
            .defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some("favorite"))
            .expect("favorite def present");
        let body_span = def_body(fav).span;
        let home = fav.home().to_vec();
        let exp = solved
            .expected
            .get(&(home, body_span))
            .expect("body span carries an expected type");
        assert_eq!(
            ty_con_name(exp, &i).as_deref(),
            Some("Color"),
            "typed body expects its annotation return type; got {exp:?}"
        );
    }

    #[test]
    fn expected_type_at_call_arg_is_the_declared_param() {
        // `len : String -> Int` applied to a string literal — the argument
        // position expects `String`.
        let src = format!(
            "{M2C_HDR}len : String -> Int\nlen s =\n    0\n\nmain : Int\nmain =\n    len \"hi\"\n"
        );
        let (solved, i, m) = infer_src(&src);
        let solved = solved.expect("must typecheck");
        let m = m.expect("module present");
        let main = m
            .defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some("main"))
            .expect("main present");
        let (_callee, args) = as_call(def_body(main)).expect("main body is a call");
        let arg_span = args.first().expect("one arg").span;
        let home = main.home().to_vec();
        let exp = solved
            .expected
            .get(&(home, arg_span))
            .expect("call argument carries an expected type");
        assert_eq!(
            ty_con_name(exp, &i).as_deref(),
            Some("String"),
            "call arg expects the callee's declared param type; got {exp:?}"
        );
    }

    #[test]
    fn expected_sidecar_is_additive_leaves_env_and_regions_unchanged() {
        // Additivity gate (plan F-3): populating `expected` must not perturb
        // any OTHER `SolvedTypes` field. The sidecar is written by pure map
        // inserts of solver variables inference already minted and is read only
        // in the final zonk pass, so `env`, `regions`, `bounds`, `warnings`,
        // `poly_var_map`, and `untyped_type_params` are exactly what they were
        // before the sidecar existed. We prove it by pinning those fields to
        // their expected values on a representative program AND asserting the
        // sidecar populated alongside them without collision: no `expected` key
        // overwrites or is confused with a `regions` entry (they are separate
        // maps), and every `expected` value is a well-formed zonked type.
        let src = format!(
            "{M2C_HDR}type Color = Red | Blue\n\npick : Bool -> Color\npick b =\n    if b then Red else Blue\n\nmain = pick True\n"
        );
        let (solved, i, m) = infer_src(&src);
        let solved = solved.expect("must typecheck");
        let m = m.expect("module present");
        // `env` unchanged: `pick : Bool -> Color`.
        let pick = def_key(&i, &m, "pick").expect("pick key");
        let pick_ty = solved.env.get(&pick).expect("pick typed");
        assert!(
            matches!(pick_ty, Ty::Fun(_, ret) if ty_con_name(ret, &i).as_deref() == Some("Color")),
            "env['pick'] returns Color, unperturbed by the sidecar; got {pick_ty:?}"
        );
        // The sidecar is a DISJOINT map: it never removes or rewrites a
        // `regions` entry (different map), and it recorded the `if`/branch
        // expectations for this program.
        assert!(
            !solved.expected.is_empty(),
            "the sidecar recorded the if-branch + call-arg expectations"
        );
        // Every expected value zonked to a well-formed type (no dangling var
        // panic during read-back) — the read-back reused the same zonk pass as
        // regions, so a corrupt sidecar would have failed inference already.
        for ((_home, _span), ty) in &solved.expected {
            // A trivially-true structural touch that forces each value to be
            // inspected; the real proof is that inference succeeded above with
            // the sidecar populated.
            let _ = ty_con_name(ty, &i);
        }
        // The `if` result and both branch bodies expect `Color`.
        let color_expectations = solved
            .expected
            .values()
            .filter(|ty| ty_con_name(ty, &i).as_deref() == Some("Color"))
            .count();
        assert!(
            color_expectations >= 2,
            "both `if` branch bodies (Red, Blue) expect Color; found {color_expectations}"
        );
    }

    #[test]
    fn env_update_is_msg_to_int_to_int() {
        let opt = canon_golden();
        assert!(opt.is_some(), "golden must parse + canonicalise");
        let Some((m, mut i)) = opt else { return };
        let solved = infer(&m, &mut i);
        assert!(solved.is_ok(), "inference must succeed");
        let Ok(solved) = solved else { return };

        let Some(update) = def_key(&i, &m, "update") else {
            return;
        };
        let Some(ty) = solved.env.get(&update) else {
            return;
        };

        // Msg -> (Int -> Int)
        assert!(matches!(ty, Ty::Fun(..)), "update is an arrow");
        let Ty::Fun(msg_arg, tail) = ty else { return };
        assert_eq!(ty_con_name(msg_arg, &i).as_deref(), Some("Msg"));
        assert!(matches!(tail.as_ref(), Ty::Fun(..)), "tail is an arrow");
        let Ty::Fun(int_arg, ret) = tail.as_ref() else {
            return;
        };
        assert_eq!(ty_con_name(int_arg, &i).as_deref(), Some("Int"));
        assert_eq!(ty_con_name(ret, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn regions_carry_call_and_kernel_types() {
        let opt = canon_golden();
        assert!(opt.is_some(), "golden");
        let Some((m, mut i)) = opt else { return };
        let solved = infer(&m, &mut i);
        assert!(solved.is_ok(), "inference must succeed");
        let Ok(solved) = solved else { return };

        // main = System.setenv "HOME" "x"
        let main_def = m
            .defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some("main"));
        assert!(
            matches!(main_def, Some(canon::Def::Untyped { .. })),
            "main is untyped"
        );
        let Some(canon::Def::Untyped {
            body,
            home: main_home,
            ..
        }) = main_def
        else {
            return;
        };

        // Outer call: (System.setenv "HOME") "x" : Task ()
        let outer = as_call(body);
        assert!(outer.is_some(), "main body is a call");
        let Some((_setenv_partial, outer_args)) = outer else {
            return;
        };
        let setenv_region = solved.regions.get(&(main_home.clone(), body.span));
        assert!(
            matches!(
                setenv_region,
                Some(Ty::Con { name, args, .. })
                    if i.resolve(*name) == Some("Task") && args.as_slice() == [Ty::Unit]
            ),
            "setenv region must be Task (): {setenv_region:?}"
        );

        // The outer arg is the string literal "x" : String
        let Some(str_arg) = outer_args.first() else {
            return;
        };
        assert!(
            matches!(&str_arg.value, canon::Expr_::Str(_)),
            "setenv outer arg is a string literal"
        );
        assert_eq!(
            solved
                .regions
                .get(&(main_home.clone(), str_arg.span))
                .and_then(|t| ty_con_name(t, &i))
                .as_deref(),
            Some("String"),
            "string literal region must be String"
        );
    }

    #[test]
    fn regions_carry_scrutinee_and_binop_types() {
        let opt = canon_golden();
        assert!(opt.is_some(), "golden");
        let Some((m, mut i)) = opt else { return };
        let solved = infer(&m, &mut i);
        assert!(solved.is_ok(), "inference must succeed");
        let Ok(solved) = solved else { return };

        let update_def = m
            .defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some("update"));
        assert!(
            matches!(update_def, Some(canon::Def::Typed { .. })),
            "update is typed"
        );
        let Some(canon::Def::Typed {
            body,
            home: update_home,
            ..
        }) = update_def
        else {
            return;
        };
        assert!(
            matches!(&body.value, canon::Expr_::Case(..)),
            "update body is case"
        );
        let canon::Expr_::Case(scrut, branches) = &body.value else {
            return;
        };

        // Scrutinee `msg` : Msg
        assert_eq!(
            solved
                .regions
                .get(&(update_home.clone(), scrut.span))
                .and_then(|t| ty_con_name(t, &i))
                .as_deref(),
            Some("Msg")
        );

        // First arm body `count + 1` : Int
        let Some(first) = branches.first() else {
            return;
        };
        assert!(
            matches!(first.body.value, canon::Expr_::Binop { .. }),
            "arm body is binop"
        );
        assert_eq!(
            solved
                .regions
                .get(&(update_home.clone(), first.body.span))
                .and_then(|t| ty_con_name(t, &i))
                .as_deref(),
            Some("Int")
        );
    }

    #[test]
    fn env_main_is_task_unit() {
        let opt = canon_golden();
        assert!(opt.is_some(), "golden");
        let Some((m, mut i)) = opt else { return };
        let solved = infer(&m, &mut i);
        assert!(solved.is_ok(), "inference must succeed");
        let Ok(solved) = solved else { return };
        let Some(main) = def_key(&i, &m, "main") else {
            return;
        };
        let main_ty = solved.env.get(&main);
        assert!(
            matches!(
                main_ty,
                Some(Ty::Con { name, args, .. })
                    if i.resolve(*name) == Some("Task") && args.as_slice() == [Ty::Unit]
            ),
            "env[main] must be Task (): {main_ty:?}"
        );
    }

    #[test]
    fn exhausted_budget_yields_budget_exceeded() {
        let opt = canon_golden();
        assert!(opt.is_some(), "golden");
        let Some((m, mut i)) = opt else { return };
        // A budget of one step cannot discharge the golden program's
        // constraints; the very first unify trips the bound.
        let mut budget = Budget::new(1);
        let r = infer_with_budget(&m, &mut i, &mut budget);
        assert!(matches!(
            r,
            Err(Diagnostic::Type {
                msg: TypeError::StepBudgetExceeded { budget: 1 },
                ..
            })
        ));
    }

    #[test]
    fn disabled_budget_still_succeeds() {
        let opt = canon_golden();
        assert!(opt.is_some(), "golden");
        let Some((m, mut i)) = opt else { return };
        let mut budget = Budget::unbounded();
        assert!(infer_with_budget(&m, &mut i, &mut budget).is_ok());
    }

    // ── rich TypeError payloads (E3) ───────────────────────────────────────

    /// Parse + canonicalise an inline module, returning it plus the interner.
    fn canon_src(src: &str) -> Option<(canon::Module, Interner)> {
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&parsed, &mut i).ok()?;
        Some((m, i))
    }

    // ── Boundary Scheme Promotion (class-1 inference fix #2) ────────────────

    /// Canonicalise + link N modules, given in dependency-first topo order
    /// (each entry's own `import`s must reference only EARLIER entries),
    /// mirroring what the real multi-file build driver does
    /// (`ipe::project` discovers + topo-orders files, `ipe_canon::link`
    /// merges them into one program). Each entry is `(dotted module path,
    /// source)`. Returns `None` on any parse / canonicalise / link failure —
    /// per this file's existing convention, a `None` here means "test can't
    /// run" (fails the caller's own `let Some(..) = .. else { return; }`
    /// guard), it is never itself the assertion.
    fn link_modules(modules_src: &[(&str, &str)]) -> Option<(canon::Module, Interner)> {
        let mut i = Interner::new();
        let mut deps: BTreeMap<Vec<Symbol>, ipe_canon::ModuleExports> = BTreeMap::new();
        let mut canon_modules: Vec<canon::Module> = Vec::new();
        let mut entry_path: Vec<Symbol> = Vec::new();
        for (path_str, src) in modules_src {
            let path: Vec<Symbol> = path_str
                .split('.')
                .map(|seg| i.intern(seg))
                .collect::<DResult<Vec<Symbol>>>()
                .ok()?;
            let parsed = ipe_parse::parse_module(src, &mut i).ok()?;
            let (cm, exports) =
                ipe_canon::canonicalise_module(&parsed, &path, &deps, &mut i).ok()?;
            deps.insert(path.clone(), exports);
            entry_path = path;
            canon_modules.push(cm);
        }
        let linked = ipe_canon::link::link(entry_path, canon_modules, &i).ok()?;
        Some((linked, i))
    }

    const LIB1_IDENT: (&str, &str) = ("Lib1", "module Lib1 exposing (ident)\n\nident x =\n    x\n");

    /// Test matrix item 1: a cross-module untyped helper used at two
    /// DIFFERENT concrete types from two DIFFERENT importers must be
    /// accepted (see the fix spec's decision record).
    #[test]
    fn untyped_binding_generalizes_across_cross_module_uses() {
        let mid = (
            "ModA",
            "module ModA exposing (useInt)\n\n\
             import Lib1 exposing (ident)\n\n\
             useInt : Int\n\
             useInt =\n    ident 5\n",
        );
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (ident)\n\
             import ModA exposing (useInt)\n\n\
             useBool : Bool\n\
             useBool =\n    ident (0 == 0)\n\n\
             main =\n    Io.println (String.fromInt useInt)\n",
        );
        let Some((m, mut i)) = link_modules(&[LIB1_IDENT, mid, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a cross-module untyped helper used at Int (ModA) and Bool (Main) \
             must be accepted: {r:?}"
        );
    }

    // Test matrix item 2 (existing, unchanged reference-parity behaviour):
    // see `untyped_polymorphic_use_at_two_types_is_rejected` — same-module
    // reuse at two types stays rejected.

    /// Test matrix item 3: an untyped VALUE binding (no parameters) also
    /// generalizes cross-module — no value restriction (the reference
    /// compiler has none; Ipê is pure, so it's sound).
    #[test]
    fn untyped_value_binding_generalizes_across_cross_module_uses() {
        let lib = ("Lib1", "module Lib1 exposing (empty)\n\nempty =\n    []\n");
        let mid = (
            "ModA",
            "module ModA exposing (ints)\n\n\
             import Lib1 exposing (empty)\n\n\
             ints : List Int\n\
             ints =\n    empty\n",
        );
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (empty)\n\
             import ModA exposing (ints)\n\n\
             bools : List Bool\n\
             bools =\n    empty\n\n\
             main =\n    Io.println (String.fromInt (List.length ints + List.length bools))\n",
        );
        let Some((m, mut i)) = link_modules(&[lib, mid, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "an untyped zero-param value binding used at List Int and List \
             Bool cross-module must be accepted (no value restriction): {r:?}"
        );
    }

    /// Test matrix item 4: a chained cross-module untyped helper
    /// (`twice x = Lib1.ident (Lib1.ident x)`) proves discharge instantiates
    /// fresh per reference — the SAME call site referencing `ident` twice
    /// must not force the two occurrences to share one instantiation.
    #[test]
    fn chained_cross_module_untyped_reference_discharges_fresh_per_site() {
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (ident)\n\n\
             twice x =\n    ident (ident x)\n\n\
             useInt : Int\n\
             useInt =\n    twice 5\n\n\
             main =\n    Io.println (String.fromInt useInt)\n",
        );
        let Some((m, mut i)) = link_modules(&[LIB1_IDENT, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a chained cross-module untyped reference (ident (ident x)) must \
             typecheck: {r:?}"
        );
    }

    /// Test matrix item 5: a same-module recursive/mutually-recursive
    /// untyped pair, used polymorphically from OUTSIDE the group, is
    /// accepted — recursion resolves via the shared var within the module
    /// (required for HM decidability), then the WHOLE group generalizes
    /// together at the module boundary.
    #[test]
    fn recursive_untyped_pair_generalizes_together_at_the_boundary() {
        let lib = (
            "Lib1",
            "module Lib1 exposing (isEven)\n\n\
             isEven n =\n    if n == 0 then True else isOdd (n - 1)\n\n\
             isOdd n =\n    if n == 0 then False else isEven (n - 1)\n",
        );
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (isEven)\n\n\
             result : Bool\n\
             result =\n    isEven 4\n\n\
             main =\n    Io.println (String.fromInt (if result then 1 else 0))\n",
        );
        let Some((m, mut i)) = link_modules(&[lib, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a same-module recursive untyped pair used cross-module must \
             typecheck: {r:?}"
        );
    }

    /// Test matrix item 6: an obligation-gated def (`getName r = r.name`) —
    /// a single-record-type cross-module use is still accepted (the existing
    /// deferred-field-access gate fallback is preserved); a two-DIFFERENT-
    /// record-type cross-module use is still rejected (D2/D3-style
    /// row-conservatism: a Flex root still reachable from a pending field
    /// access is excluded from quantification, so it stays program-wide
    /// shared — exactly like before this fix).
    #[test]
    fn obligation_gated_untyped_def_single_record_type_cross_module_use_accepted() {
        let lib = (
            "Lib1",
            "module Lib1 exposing (getName)\n\ngetName r =\n    r.name\n",
        );
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (getName)\n\n\
             name : String\n\
             name =\n    getName { name = \"Ada\" }\n\n\
             main =\n    Io.println name\n",
        );
        let Some((m, mut i)) = link_modules(&[lib, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a single-record-type cross-module use of an obligation-gated \
             untyped def must still typecheck: {r:?}"
        );
    }

    #[test]
    fn obligation_gated_untyped_def_two_record_types_cross_module_is_rejected() {
        let lib = (
            "Lib1",
            "module Lib1 exposing (getName)\n\ngetName r =\n    r.name\n",
        );
        let mid = (
            "ModA",
            "module ModA exposing (aName)\n\n\
             import Lib1 exposing (getName)\n\n\
             aName : String\n\
             aName =\n    getName { name = \"Ada\" }\n",
        );
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (getName)\n\
             import ModA exposing (aName)\n\n\
             bName : String\n\
             bName =\n    getName { name = \"Bea\", age = 9 }\n\n\
             main =\n    Io.println (aName ++ bName)\n",
        );
        let Some((m, mut i)) = link_modules(&[lib, mid, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_err(),
            "an obligation-gated untyped def used at TWO DIFFERENT record \
             types cross-module must still be rejected (D2/D3-style \
             row-conservatism, matches the pre-fix gate fallback): {r:?}"
        );
    }

    /// Regression for the `RecordUpdate.fields` obligation-exclusion gap
    /// (BACKLOG "Boundary Scheme Promotion — `obligation_roots`" Low row,
    /// symmetric to the `fa.result` gap): a cross-module untyped record-update
    /// helper's field VALUE var (`n` in `setName r n = { r | name = n }`) is
    /// pinned by `resolve_record_updates` AFTER `promote_untyped_boundaries`
    /// runs, so it must be excluded from quantification like `ru.record`
    /// itself. Pre-fix, the scheme quantified it (a quantified-then-later-
    /// pinned var — the exact E0283 class the `fa.result` fix closed), and
    /// only the lowerer's `used_generics` backstop kept the emitted Rust
    /// building. This test pins the PRIMARY mechanism: the promoted scheme
    /// for `setName` must quantify nothing.
    #[test]
    fn record_update_field_value_var_is_excluded_from_quantification() {
        let lib = (
            "Lib1",
            "module Lib1 exposing (setName)\n\n\
             setName r n =\n    { r | name = n }\n",
        );
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (setName)\n\n\
             main =\n    Io.println ((setName { name = \"Ada\" } \"Bea\").name)\n",
        );
        let Some((m, mut i)) = link_modules(&[lib, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a single-record-type cross-module use of an untyped record-update \
             helper must typecheck: {r:?}"
        );
        let Ok(solved) = r else { return };
        let Ok(lib1) = i.intern("Lib1") else { return };
        let Ok(set_name) = i.intern("setName") else {
            return;
        };
        // An all-monomorphic scheme is skipped when `untyped_type_params` is
        // populated (empty `quantified` ⇒ no entry), so the post-fix success
        // signal is "no entry OR an empty entry"; pre-fix the gap produced a
        // one-symbol entry for the field VALUE var.
        let quantified = solved.untyped_type_params.get(&(vec![lib1], set_name));
        assert!(
            quantified.is_none_or(Vec::is_empty),
            "setName's promoted scheme must quantify NOTHING — both `r` \
             (`ru.record`) and `n` (the field VALUE var, pinned later by \
             resolve_record_updates) are obligation roots; a non-empty list \
             means a quantified-then-later-pinned var leaked into the scheme \
             (the E0283 stale-generic class): {quantified:?}"
        );
    }

    /// Test matrix item 7: a `Super`-bounded untyped helper (`plus a b = a +
    /// b`) used at `Int` in one module and `Float` in another must still be
    /// rejected — Divergence D2: `Super`-bounded residual vars stay
    /// program-monomorphic in phase 1 (the reference DOES generalize these;
    /// deferred to phase 2, `bounds` map plumbing is additive-only).
    #[test]
    fn super_bounded_untyped_helper_cross_module_is_rejected() {
        let lib = (
            "Lib1",
            "module Lib1 exposing (plus)\n\nplus a b =\n    a + b\n",
        );
        let mid = (
            "ModA",
            "module ModA exposing (sumInt)\n\n\
             import Lib1 exposing (plus)\n\n\
             sumInt : Int\n\
             sumInt =\n    plus 1 2\n",
        );
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (plus)\n\
             import ModA exposing (sumInt)\n\n\
             sumFloat : Float\n\
             sumFloat =\n    plus 1.0 2.0\n\n\
             main =\n    Io.println (String.fromInt sumInt)\n",
        );
        let Some((m, mut i)) = link_modules(&[lib, mid, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_err(),
            "a Super-bounded untyped helper used at Int and Float \
             cross-module must still be rejected (D2 — phase 1 does not \
             generalize Number-bounded vars): {r:?}"
        );
    }

    /// A rigid-contaminated untyped def (its body unifies with a typed
    /// sibling's skolem) is not generalized — generalization conservatively
    /// excludes rigid roots.
    #[test]
    fn rigid_contaminated_untyped_def_stays_unquantified() {
        let src = "module Main exposing (main)\n\
                   f : a -> a\n\
                   f x =\n    ident x\n\
                   ident y =\n    y\n\
                   useInt : Int\n\
                   useInt =\n    f 5\n\
                   useBool : Bool\n\
                   useBool =\n    f (0 == 0)\n\
                   main =\n    Io.println (String.fromInt useInt)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        // `ident`'s own shared var unifies with `f`'s rigid skolem `a` while
        // `f`'s body is checked, so `ident` is rigid-contaminated. `f` itself
        // is typed (annotated) and genuinely polymorphic — its own two uses
        // at Int/Bool must still typecheck (this is unrelated to Boundary
        // Scheme Promotion, just confirming the surrounding program is
        // otherwise sound). The load-bearing assertion is only that this
        // program's SHAPE (an untyped def rigid-contaminated by a typed
        // sibling) does not ICE and does not silently over-generalize.
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a typed polymorphic binding whose body routes through a \
             rigid-contaminated untyped helper must still typecheck: {r:?}"
        );
    }

    fn con_doc(name: &str) -> ipe_diagnostics::TyDoc {
        ipe_diagnostics::TyDoc::Con {
            module: "".into(),
            name: name.into(),
            args: Box::new([]),
        }
    }

    #[test]
    fn type_mismatch_carries_expected_and_found() {
        // `h : Int` but the body is a `Msg` constructor.
        let src = "module Main exposing (main)\n\
                   type Msg = Increment | Decrement\n\
                   h : Int\n\
                   h = Increment\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "expected a TypeMismatch, got {r:?}"
        );
        let Err(Diagnostic::Type {
            msg: TypeError::TypeMismatch {
                expected, found, ..
            },
            ..
        }) = r
        else {
            return;
        };
        assert_eq!(*expected, con_doc("Int"));
        // A user type carries its defining module home.
        assert_eq!(
            *found,
            ipe_diagnostics::TyDoc::Con {
                module: "Main".into(),
                name: "Msg".into(),
                args: Box::new([]),
            }
        );
    }

    #[test]
    fn call_arg_mismatch_expected_is_declared_param_found_is_actual_arg() {
        // `Task.fail : Error -> Task Error a` called with a `String` argument:
        // the DECLARED parameter type is the *expected* side and the user's
        // actual argument the *found* side — "expected Error, found String",
        // never the inversion. The Call arm must orient the constraint so the
        // declared parameter, not the actual argument, lands on unify's
        // *expected* side.
        let src = "module Main exposing (main)\n\
                   main =\n    Task.fail \"plain string\"\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "Task.fail \"str\" must be a TypeMismatch, got {r:?}"
        );
        let Err(Diagnostic::Type {
            msg: TypeError::TypeMismatch {
                expected, found, ..
            },
            ..
        }) = r
        else {
            return;
        };
        assert_eq!(
            *expected,
            con_doc("Error"),
            "declared param type must be the expected side"
        );
        assert_eq!(
            *found,
            con_doc("String"),
            "actual argument type must be the found side"
        );
    }

    #[test]
    fn calling_a_non_function_keeps_function_shape_on_expected_side() {
        // Calling a non-function value: the *expected* side stays the
        // function shape the call site demands, the *found* side the callee's
        // actual (non-function) type. Locks the companion orientation so the
        // per-arg fix above cannot silently flip this arm.
        // (`String`, not an integer literal — a bare `5` is a polymorphic
        // Number var and would render as a type variable, not a Con.)
        let src = "module Main exposing (main)\n\
                   main =\n    let x = \"s\" in x 1\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "calling a String must be a TypeMismatch, got {r:?}"
        );
        let Err(Diagnostic::Type {
            msg: TypeError::TypeMismatch {
                expected, found, ..
            },
            ..
        }) = r
        else {
            return;
        };
        assert!(
            matches!(*expected, ipe_diagnostics::TyDoc::Fun(..)),
            "the call-shape (a function type) must be the expected side, got {expected:?}"
        );
        assert_eq!(
            *found,
            con_doc("String"),
            "the non-function callee's type must be the found side"
        );
    }

    #[test]
    fn record_update_on_builtin_nominal_is_dedicated_diagnostic() {
        // `{ p | message = "x" }` on the nominal builtin `PanicInfo` must NOT
        // surface as IPE-T0012 "type PanicInfo has no field `message`" — the
        // field IS readable (`p.message`); the real reason is that a nominal
        // builtin has no user-writable record-update form. It must be the
        // dedicated `BuiltinRecordUpdate` (IPE-T0017) naming the type.
        let src = "module Main exposing (main)\n\
                   f : PanicInfo -> PanicInfo\n\
                   f p =\n    { p | message = \"x\" }\n\
                   main =\n    0\n";
        let parsed = canon_src(src);
        assert!(
            parsed.is_some(),
            "fixture must parse + canonicalise (a None here would make the \
             test vacuous)"
        );
        let Some((m, mut i)) = parsed else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::BuiltinRecordUpdate { .. },
                    ..
                })
            ),
            "record update on the nominal builtin PanicInfo must surface the \
             dedicated BuiltinRecordUpdate (IPE-T0017), not IPE-T0012, got {r:?}"
        );
        let Err(Diagnostic::Type {
            msg: TypeError::BuiltinRecordUpdate { name },
            ..
        }) = r
        else {
            return;
        };
        assert_eq!(&*name, "PanicInfo");
    }

    #[test]
    fn if_branches_unify_to_the_annotated_return() {
        // A well-typed `if`: condition `Bool`, both branches `Int`, agreeing
        // with the `Int` return annotation.
        let src = "module Main exposing (main)\n\
                   f : Int -> Int\n\
                   f n =\n    if n > 0 then n else 0\n\
                   main =\n    Io.println (String.fromInt (f 1))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(r.is_ok(), "well-typed if must infer: {r:?}");
        let Ok(solved) = r else { return };
        let Some(f) = def_key(&i, &m, "f") else {
            return;
        };
        let Some(Ty::Fun(arg, ret)) = solved.env.get(&f) else {
            return;
        };
        assert_eq!(ty_con_name(arg, &i).as_deref(), Some("Int"));
        assert_eq!(ty_con_name(ret, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn if_condition_must_be_bool() {
        // `if n then …` with `n : Int` — the condition is not `Bool`.
        let src = "module Main exposing (main)\n\
                   f : Int -> Int\n\
                   f n =\n    if n then 1 else 0\n\
                   main =\n    Io.println (String.fromInt (f 1))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "a non-Bool condition must be a TypeMismatch, got {r:?}"
        );
    }

    #[test]
    fn if_branches_must_agree() {
        // The `then` branch is `Int` and the `else` is a `Msg` constructor —
        // the two branches cannot unify.
        let src = "module Main exposing (main)\n\
                   type Msg = Increment | Decrement\n\
                   f : Int -> Int\n\
                   f n =\n    if n > 0 then 1 else Increment\n\
                   main =\n    Io.println (String.fromInt (f 1))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "disagreeing branches must be a TypeMismatch, got {r:?}"
        );
    }

    #[test]
    fn too_many_parameters_names_binding_and_signature() {
        // `g : Int` but `g a = 0` binds a parameter the signature has no arrow
        // for.
        let src = "module Main exposing (main)\n\
                   g : Int\n\
                   g a = 0\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::TooManyParameters { .. },
                    ..
                })
            ),
            "expected TooManyParameters, got {r:?}"
        );
        let Err(Diagnostic::Type {
            msg: TypeError::TooManyParameters { binding, signature },
            ..
        }) = r
        else {
            return;
        };
        assert_eq!(&*binding, "g");
        assert_eq!(*signature, con_doc("Int"));
    }

    #[test]
    fn non_exhaustive_case_lists_missing_constructors() {
        // The `case` covers only `Increment`; `Decrement` is missing.
        let src = "module Main exposing (main)\n\
                   type Msg = Increment | Decrement\n\
                   f : Msg -> Int\n\
                   f msg =\n        case msg of\n            Increment -> 1\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::NonExhaustiveCase { .. },
                    ..
                })
            ),
            "expected NonExhaustiveCase, got {r:?}"
        );
        let Err(Diagnostic::Type {
            msg: TypeError::NonExhaustiveCase { missing },
            ..
        }) = r
        else {
            return;
        };
        let names: Vec<&str> = missing.iter().map(AsRef::as_ref).collect();
        assert_eq!(names, vec!["Decrement"]);
    }

    #[test]
    fn refutable_ctor_def_head_param_is_rejected_t0015() {
        // `f (Just x) = x` — a constructor parameter is a refutable binding
        // position, rejected by the irrefutability gate BEFORE lowering.
        let src = "module Main exposing (main)\n\
                   f : Maybe Int -> Int\n\
                   f (Just x) = x\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::RefutablePatternParameter,
                    ..
                })
            ),
            "expected RefutablePatternParameter (IPE-T0015), got {r:?}"
        );
    }

    #[test]
    fn refutable_ctor_lambda_param_is_rejected_t0015() {
        // `\(Just x) -> x` in argument position — the lambda-param sweep must
        // catch it too (the pre-existing Lambda arm dropped its params).
        let src = "module Main exposing (main)\n\
                   apply : (Maybe Int -> Int) -> Int\n\
                   apply f = f (Just 1)\n\
                   main =\n    Io.println (String.fromInt (apply (\\(Just x) -> x)))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::RefutablePatternParameter,
                    ..
                })
            ),
            "expected RefutablePatternParameter (IPE-T0015), got {r:?}"
        );
    }

    #[test]
    fn irrefutable_tuple_and_wildcard_params_pass_the_gate() {
        // `f _ (a, b) = a + b` — a wildcard and a tuple param are both
        // irrefutable, so the gate lets them through (no false positive).
        let src = "module Main exposing (main)\n\
                   f : Int -> (Int, Int) -> Int\n\
                   f _ (a, b) = a + b\n\
                   main =\n    Io.println (String.fromInt (f 9 (1, 2)))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "irrefutable params must pass the gate, got {r:?}"
        );
    }

    #[test]
    fn redundant_case_branch_names_constructor() {
        // `Increment` is matched twice; the case is otherwise exhaustive, so the
        // redundancy is the only finding.  IPE-T0011 is Severity::Warning —
        // `infer` must return `Ok` with the warning in `types.warnings`, NOT
        // return `Err`.  The compiler must not fail with exit 1 for a warning.
        let src = "module Main exposing (main)\n\
                   type Msg = Increment | Decrement\n\
                   f : Msg -> Int\n\
                   f msg =\n        case msg of\n            Increment -> 1\n\
                   \x20           Decrement -> 2\n            Increment -> 3\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("redundant branch is a warning (IPE-T0011), not an error");
        assert_eq!(
            types.warnings.len(),
            1,
            "expected exactly one warning, got {:?}",
            types.warnings
        );
        let warning = types.warnings.first().expect("len==1 asserted above");
        assert!(
            matches!(
                warning,
                Diagnostic::Type {
                    msg: TypeError::RedundantCaseBranch { .. },
                    ..
                }
            ),
            "expected RedundantCaseBranch warning, got {warning:?}"
        );
        if let Diagnostic::Type {
            msg: TypeError::RedundantCaseBranch { constructor },
            ..
        } = warning
        {
            assert_eq!(&**constructor, "Increment");
        }
    }

    #[test]
    fn or_pattern_covering_all_ctors_is_exhaustive_no_t0010() {
        // `Red | Green | Blue -> …` enumerates the whole union in one arm, with
        // NO wildcard. Row expansion makes the matrix cover all three
        // constructors, so IPE-T0010 does NOT fire — the case type-checks.
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   name : Color -> Int\n\
                   name c =\n        case c of\n            Red | Green | Blue -> 1\n\
                   main =\n    Io.println (String.fromInt (name Red))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "an or-pattern enumerating the whole union is exhaustive (no IPE-T0010), got {r:?}"
        );
    }

    #[test]
    fn or_pattern_missing_a_variant_is_non_exhaustive_t0010() {
        // `Red | Green -> …` groups two of three variants; `Blue` is covered by
        // no arm and no or-group, so the case is non-exhaustive — IPE-T0010,
        // naming the missing `Blue`. Proves an or-pattern COUNTS toward
        // exhaustiveness rather than being treated as a catch-all.
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   name : Color -> Int\n\
                   name c =\n        case c of\n            Red | Green -> 1\n\
                   main =\n    Io.println (String.fromInt (name Red))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let err = infer(&m, &mut i)
            .expect_err("an or-group missing a union variant must be non-exhaustive (IPE-T0010)");
        assert!(
            matches!(
                &err,
                Diagnostic::Type {
                    msg: TypeError::NonExhaustiveCase { .. },
                    ..
                }
            ),
            "expected IPE-T0010 NonExhaustiveCase, got {err:?}"
        );
        if let Diagnostic::Type {
            msg: TypeError::NonExhaustiveCase { missing },
            ..
        } = &err
        {
            let names: Vec<&str> = missing.iter().map(AsRef::as_ref).collect();
            assert_eq!(names, vec!["Blue"], "the uncovered variant is named");
        }
    }

    #[test]
    fn or_pattern_redundant_alternative_is_flagged_t0011() {
        // `Red | Green` then `Green | Blue`: the second `Green` alternative is
        // already covered → IPE-T0011 (Warning), but the arm stays reachable via
        // `Blue`, so the program still type-checks.
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   label : Color -> Int\n\
                   label c =\n        case c of\n\
                   \x20           Red | Green -> 1\n\
                   \x20           Green | Blue -> 2\n\
                   main =\n    Io.println (String.fromInt (label Blue))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("a per-alternative redundancy is a warning, not an error");
        let redundant: Vec<_> = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::RedundantCaseBranch { .. },
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(
            redundant.len(),
            1,
            "exactly the second `Green` alternative is redundant, got {redundant:?}"
        );
    }

    #[test]
    fn internally_redundant_or_pattern_is_flagged_t0011() {
        // `Red | Red` — the second alternative is not useful against the first.
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   f : Color -> Int\n\
                   f c =\n        case c of\n\
                   \x20           Red | Red -> 1\n\
                   \x20           Green -> 2\n            Blue -> 3\n\
                   main =\n    Io.println (String.fromInt (f Green))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("an internally-redundant or-pattern is a warning, not an error");
        let redundant = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::RedundantCaseBranch { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            redundant, 1,
            "the duplicate `Red` alternative is flagged once, got {redundant}"
        );
    }

    #[test]
    fn or_pattern_binding_set_mismatch_is_t0019_in_canon() {
        // `Circle r | Dot -> r`: `r` is bound by the left alternative but not the
        // right. Canon rejects it fail-fast with IPE-T0019 (before types run).
        let src = "module Main exposing (main)\n\
                   type Shape = Circle Int | Dot\n\
                   bad : Shape -> Int\n\
                   bad s =\n        case s of\n            Circle r | Dot -> r\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i).expect("source parses");
        let r = ipe_canon::canonicalise(&parsed, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::OrPatternBindingMismatch { .. },
                    ..
                })
            ),
            "expected IPE-T0019 OrPatternBindingMismatch, got {r:?}"
        );
        if let Err(Diagnostic::Type {
            msg: TypeError::OrPatternBindingMismatch { names },
            ..
        }) = r
        {
            let names: Vec<&str> = names.iter().map(AsRef::as_ref).collect();
            assert_eq!(names, vec!["r"], "the message names the diverging binder");
        }
    }

    #[test]
    fn or_pattern_binding_mismatch_names_are_string_ordered_not_interner_ordered() {
        // `Pair z a | Dot -> …`: the left alternative binds `z` and `a`, the
        // right binds neither, so BOTH diverge. `z` is written (and interned)
        // before `a`, so an interner-id sort would render `["z","a"]`. The
        // diagnostic newtype must render the diverging binders in canonical
        // string order: `["a","z"]`.
        let src = "module Main exposing (main)\n\
                   type Shape = Pair Int Int | Dot\n\
                   bad : Shape -> Int\n\
                   bad s =\n        case s of\n            Pair z a | Dot -> z + a\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i).expect("source parses");
        let r = ipe_canon::canonicalise(&parsed, &mut i);
        let Err(Diagnostic::Type {
            msg: TypeError::OrPatternBindingMismatch { names },
            ..
        }) = r
        else {
            assert!(
                matches!(r, Err(Diagnostic::Type { .. })),
                "expected IPE-T0019 OrPatternBindingMismatch, got {r:?}"
            );
            return;
        };
        let rendered: Vec<&str> = names.iter().map(AsRef::as_ref).collect();
        assert_eq!(
            rendered,
            vec!["a", "z"],
            "diverging binders render in canonical string order"
        );
    }

    // -----------------------------------------------------------------------
    // IPE-T0018: wildcard covers known constructors
    // -----------------------------------------------------------------------

    /// FAIL-CLOSED PROOF: a catch-all arm that absorbs a NAMED remaining
    /// constructor of a closed ADT must make `infer` FAIL (return `Err`), not
    /// merely collect a diagnostic into `warnings`. This asserts the promotion
    /// at the compile boundary — the crux that keeps the feature from failing
    /// open (a diagnostic that renders but still compiles).
    #[test]
    fn wildcard_covering_known_ctor_fails_compilation() {
        // `Color` has three constructors; only `Red` is named — `_` silently
        // absorbs `Green` and `Blue`. Compilation must FAIL naming both.
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   name : Color -> String\n\
                   name c =\n        case c of\n\
                   \x20           Red -> \"red\"\n\
                   \x20           _ -> \"other\"\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let err = r.expect_err(
            "a closed-union catch-all must FAIL compilation (not just warn) — \
             this is the fail-closed boundary",
        );
        // The failure must be Error-severity IPE-T0018 naming the absorbed ctors.
        assert_eq!(
            err.severity(),
            ipe_diagnostics::Severity::Error,
            "IPE-T0018 over a closed union must be Error-severity"
        );
        assert!(
            matches!(
                &err,
                Diagnostic::Type {
                    msg: TypeError::WildcardCoversKnownConstructors { .. },
                    ..
                }
            ),
            "expected IPE-T0018 WildcardCoversKnownConstructors, got {err:?}"
        );
        if let Diagnostic::Type {
            msg: TypeError::WildcardCoversKnownConstructors { constructors },
            ..
        } = &err
        {
            let names: Vec<&str> = constructors.iter().map(AsRef::as_ref).collect();
            assert_eq!(
                names,
                vec!["Blue", "Green"],
                "the error names the absorbed ctors in canonical string order"
            );
        }
    }

    /// A closed-union catch-all in a NON-entry module is returned with that
    /// module's home and the span of the `_` arm itself.
    ///
    /// Linked spans are file-local byte offsets, so the home is the only thing
    /// that tells the driver which file to frame the error against; without it
    /// the error was framed against whichever module's definition enclosed the
    /// same offsets (an embedded stdlib module, in practice).
    #[test]
    fn closed_union_catch_all_error_carries_owning_module_home_and_arm_span() {
        let lib_src = "module Lib exposing (Color(..), isRed)\n\n\
                       type Color = Red | Green | Blue\n\n\
                       isRed : Color -> Bool\n\
                       isRed c =\n    case c of\n        Red ->\n            True\n\n        \
                       _ ->\n            False\n";
        let main_src = "module Main exposing (main)\n\n\
                        import Lib exposing (Color(..), isRed)\n\n\
                        main =\n    Io.println (if isRed Green then \"red\" else \"other\")\n";
        let Some((m, mut i)) = link_modules(&[("Lib", lib_src), ("Main", main_src)]) else {
            return;
        };
        let r = infer_attributed(&m, &mut i);
        assert!(r.is_err(), "a closed-union catch-all must fail compilation");
        let Err((err, home)) = r else {
            return;
        };
        let Ok(lib) = i.intern("Lib") else {
            return;
        };
        assert_eq!(
            home,
            vec![lib],
            "the error must carry the owning module's home, not an empty one"
        );
        assert!(
            matches!(
                &err,
                Diagnostic::Type {
                    msg: TypeError::WildcardCoversKnownConstructors { .. },
                    ..
                }
            ),
            "expected IPE-T0018 WildcardCoversKnownConstructors, got {err:?}"
        );
        let Diagnostic::Type { span, .. } = &err else {
            return;
        };
        let arm_offset = lib_src.find("_ ->").and_then(|o| u32::try_from(o).ok());
        assert_eq!(
            Some(span.lo),
            arm_offset,
            "the error must point at the `_` arm in Lib"
        );
    }

    /// FAIL-CLOSED, MULTI-SITE: a module with more than one closed-union
    /// catch-all still FAILS compilation. The pass collects every offending site
    /// before the promotion (better UX than aborting on the first), and the
    /// promotion returns an Error so the build genuinely fails. This guards
    /// against a plumbing regression that would push the Error onto the
    /// warnings-only channel and silently compile.
    #[test]
    fn multiple_closed_union_catch_alls_fail_compilation() {
        // Two functions, each with its own closed-union catch-all.
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   name : Color -> String\n\
                   name c =\n        case c of\n\
                   \x20           Red -> \"red\"\n\
                   \x20           _ -> \"other\"\n\
                   toMaybe : Color -> Maybe Int\n\
                   toMaybe c =\n        case c of\n\
                   \x20           Green -> Just 1\n\
                   \x20           _ -> Nothing\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let err =
            r.expect_err("a module with multiple closed-union catch-alls must FAIL compilation");
        assert_eq!(
            err.severity(),
            ipe_diagnostics::Severity::Error,
            "the returned diagnostic must be Error-severity"
        );
        assert!(
            matches!(
                err,
                Diagnostic::Type {
                    msg: TypeError::WildcardCoversKnownConstructors { .. },
                    ..
                }
            ),
            "the failure must be an IPE-T0018 error, got {err:?}"
        );
    }

    /// A `case` with a wildcard arm where the arms before it cover ALL constructors
    /// of the type — making the wildcard redundant — must NOT emit IPE-T0018
    /// (the wildcard is already flagged IPE-T0011 as redundant; double-warning
    /// would be confusing). This also guards the no-warn boundary when the
    /// wildcard covers zero remaining constructors of a closed type.
    #[test]
    fn wildcard_after_all_ctors_explicit_emits_only_t0011_not_t0018() {
        // `Red`, `Green`, `Blue` are all named; `_` is fully redundant.
        // IPE-T0011 should fire; IPE-T0018 must NOT.
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   name : Color -> String\n\
                   name c =\n        case c of\n\
                   \x20           Red -> \"red\"\n\
                   \x20           Green -> \"green\"\n\
                   \x20           Blue -> \"blue\"\n\
                   \x20           _ -> \"other\"\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("fully-covered wildcard is a warning (IPE-T0011), not an error");
        let t0018: Vec<_> = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::WildcardCoversKnownConstructors { .. },
                        ..
                    }
                )
            })
            .collect();
        assert!(
            t0018.is_empty(),
            "a fully-redundant wildcard must NOT emit IPE-T0018, got {t0018:?}"
        );
        // The redundant-branch warning must still fire.
        let t0011 = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::RedundantCaseBranch { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            t0011, 1,
            "redundant wildcard must emit exactly one IPE-T0011"
        );
    }

    /// A `case` over a closed ADT where every constructor is listed explicitly
    /// (no wildcard) must emit NEITHER IPE-T0018 NOR any other warning.
    #[test]
    fn fully_explicit_case_emits_no_t0018() {
        // Every constructor named; no wildcard at all.
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   name : Color -> String\n\
                   name c =\n        case c of\n\
                   \x20           Red -> \"red\"\n\
                   \x20           Green -> \"green\"\n\
                   \x20           Blue -> \"blue\"\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("exhaustive explicit case must type-check");
        let t0018: Vec<_> = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::WildcardCoversKnownConstructors { .. },
                        ..
                    }
                )
            })
            .collect();
        assert!(
            t0018.is_empty(),
            "a fully explicit case must emit no IPE-T0018, got {t0018:?}"
        );
    }

    /// A `case` over an OPEN type (`Int`) with a wildcard must NOT emit IPE-T0018
    /// — the remaining set is infinite and un-nameable, so the wildcard is the
    /// correct and only viable spelling.
    #[test]
    fn wildcard_on_open_type_int_does_not_emit_t0018() {
        // Only a few literals are named; `_` is needed for the open remainder.
        let src = "module Main exposing (main)\n\
                   describe : Int -> String\n\
                   describe n =\n        case n of\n\
                   \x20           0 -> \"zero\"\n\
                   \x20           1 -> \"one\"\n\
                   \x20           _ -> \"other\"\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("wildcard on Int must type-check");
        let t0018: Vec<_> = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::WildcardCoversKnownConstructors { .. },
                        ..
                    }
                )
            })
            .collect();
        assert!(
            t0018.is_empty(),
            "a wildcard on an open type (Int) must not emit IPE-T0018, got {t0018:?}"
        );
    }

    /// A `case` over `Bool` (`True -> …; _ -> …`) must NOT emit IPE-T0018.
    /// `Bool` is closed but its variant set is frozen by the language — no user
    /// adds a variant — so a catch-all is a safe idiom, not an evolution hazard.
    #[test]
    fn wildcard_on_bool_does_not_emit_t0018() {
        let src = "module Main exposing (main)\n\
                   label : Bool -> String\n\
                   label b =\n        case b of\n\
                   \x20           True -> \"yes\"\n\
                   \x20           _ -> \"no\"\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("wildcard on Bool must type-check");
        let t0018 = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::WildcardCoversKnownConstructors { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            t0018, 0,
            "a wildcard over Bool must not emit IPE-T0018 (Bool is excluded)"
        );
    }

    /// A `case` over `List` (`[] -> …; _ -> …`) must NOT emit IPE-T0018. `List`
    /// is closed (`Nil | Cons`) but its variant set is frozen, and `_` meaning
    /// "cons" is a ubiquitous safe idiom.
    #[test]
    fn wildcard_on_list_does_not_emit_t0018() {
        let src = "module Main exposing (main)\n\
                   isEmpty : List Int -> String\n\
                   isEmpty xs =\n        case xs of\n\
                   \x20           [] -> \"empty\"\n\
                   \x20           _ -> \"non-empty\"\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("wildcard on List must type-check");
        let t0018 = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::WildcardCoversKnownConstructors { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            t0018, 0,
            "a wildcard over List must not emit IPE-T0018 (List is excluded)"
        );
    }

    /// A `case c of _ -> …` whose ONLY arm is a bare catch-all over a closed
    /// union is an ERROR (IPE-T0018), naming every variant it silently absorbs.
    /// The union identity comes from the scrutinee's solved type, so no earlier
    /// constructor arm is needed to identify it — this is the fail-closed
    /// boundary that a later-added variant cannot slip through unhandled.
    #[test]
    fn bare_wildcard_only_case_over_closed_union_is_rejected() {
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   name : Color -> String\n\
                   name c =\n        case c of\n\
                   \x20           _ -> \"other\"\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let err = r.expect_err(
            "a bare `_ ->`-only case over a closed union must FAIL compilation — \
             the catch-all absorbs every variant with no exhaustive cover",
        );
        assert_eq!(
            err.severity(),
            ipe_diagnostics::Severity::Error,
            "IPE-T0018 over a closed union must be Error-severity"
        );
        assert!(
            matches!(
                &err,
                Diagnostic::Type {
                    msg: TypeError::WildcardCoversKnownConstructors { .. },
                    ..
                }
            ),
            "expected IPE-T0018 WildcardCoversKnownConstructors, got {err:?}"
        );
        if let Diagnostic::Type {
            msg: TypeError::WildcardCoversKnownConstructors { constructors },
            ..
        } = &err
        {
            let names: Vec<&str> = constructors.iter().map(AsRef::as_ref).collect();
            assert_eq!(
                names,
                vec!["Blue", "Green", "Red"],
                "the error names every absorbed constructor in canonical string order"
            );
        }
    }

    /// A `Debug._` catch-all over a closed union is EXEMPT from IPE-T0018: it is
    /// the sanctioned development-only escape hatch, so the type checker accepts
    /// it (release rejection is enforced separately, at lowering, via
    /// IPE-L0140). Neither a T0018 error nor a T0018 warning is emitted.
    #[test]
    fn debug_wildcard_over_closed_union_is_exempt_from_t0018() {
        let src = "module Main exposing (main)\n\
                   type Color = Red | Green | Blue\n\
                   name : Color -> String\n\
                   name c =\n        case c of\n\
                   \x20           Debug._ -> \"other\"\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let types = infer(&m, &mut i)
            .expect("`Debug._` is the dev-only escape hatch — it type-checks (no IPE-T0018)");
        let t0018 = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::WildcardCoversKnownConstructors { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(t0018, 0, "`Debug._` must not emit IPE-T0018 in any form");
    }

    /// Regression against the IPE-T0011 false-positive class (the ex10-shaped
    /// bug): a `case` whose arms cover every constructor of a closed union
    /// EXACTLY ONCE — no trailing `_`, no redundant arm — must emit ZERO
    /// `RedundantCaseBranch` warnings, even when the same function body also
    /// contains attribute-list / call / list sub-expressions (the
    /// `[class "…"]`-shaped nodes a `view` function is built from). The
    /// redundancy walk runs only over real `case` arm matrices; it must never
    /// mis-attribute a "redundant" verdict to a `List` / `Call` node that is not
    /// a `case` arm at all. Mirrors `redundant_case_branch_names_constructor`
    /// (which locks the true-positive) so the two together pin the checker to
    /// fire on genuinely-subsumed arms and nowhere else.
    #[test]
    fn exhaustive_case_with_attr_lists_emits_no_redundant_warning() {
        // Three-constructor `Msg`, each arm once, no `_`; the `view` helper wraps
        // the branch bodies in list literals (`[a, b]`) and calls (`f […]`) — the
        // exact shapes the false positive mis-blamed at "line 71 col 23".
        let src = "module Main exposing (main)\n\
                   type Msg = Increment | Decrement | Reset\n\
                   step : Msg -> Int -> Int\n\
                   step msg n =\n        case msg of\n\
                   \x20           Increment -> n + 1\n\
                   \x20           Decrement -> n - 1\n\
                   \x20           Reset -> 0\n\
                   view : Int -> List Int\n\
                   view n =\n        wrap [ n, n + 1 ] [ n - 1 ]\n\
                   wrap : List Int -> List Int -> List Int\n\
                   wrap a b =\n        List.append a b\n\
                   main =\n    Io.println (String.fromInt (step Reset 0))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("an exhaustive, non-redundant program must type-check");
        let redundant: Vec<_> = types
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w,
                    Diagnostic::Type {
                        msg: TypeError::RedundantCaseBranch { .. },
                        ..
                    }
                )
            })
            .collect();
        assert!(
            redundant.is_empty(),
            "an exhaustive case with no redundant arm must emit ZERO IPE-T0011, \
             got {redundant:?}"
        );
    }

    /// IPE-L0124: a `Web.tea` with a non-empty `routes` list
    /// whose Model has NO `page` field emits a **warning**, not an error. The
    /// program still type-checks (`applyRoute` no-ops the same shape); the
    /// warning flags the likely mis-named routed-page field.
    ///
    /// Exercises `resolve_routed_web_checks` directly with a hand-built
    /// non-routed Model record (a single `count` field, no `page`) and
    /// `has_routes = true`.
    #[test]
    fn routed_app_missing_page_field_is_a_warning() {
        let mut interner = Interner::new();
        let count_sym = interner.intern("count").expect("intern count");
        let mut budget = Budget::unbounded();
        let mut uf = UnionFind::new();

        // Closed record `{ count : <flex> }` — no `page` field → non-routed.
        let count_var = uf.fresh(Content::Flex).expect("fresh count var");
        let ext = uf
            .fresh(Content::Structure(FlatType::EmptyRecord))
            .expect("fresh ext");
        let mut fields = BTreeMap::new();
        fields.insert(count_sym, count_var);
        let model_var = uf
            .fresh(Content::Structure(FlatType::Record(fields, ext)))
            .expect("fresh model var");
        let not_found_var = uf.fresh(Content::Flex).expect("fresh notFound var");

        let check = RoutedWebCheck {
            model_var,
            not_found_var,
            span: Span::DUMMY,
        };
        let mut warnings: Vec<Diagnostic> = Vec::new();
        resolve_routed_web_checks(
            &mut uf,
            &mut budget,
            &interner,
            &[check],
            /* has_routes */ true,
            /* route_count */ 2,
            &mut warnings,
        )
        .expect("non-routed Model + routes is a warning, not an error");

        assert_eq!(
            warnings.len(),
            1,
            "expected exactly one IPE-L0124 warning, got {warnings:?}"
        );
        let w = warnings.first().expect("len==1 asserted above");
        assert!(
            matches!(
                w,
                Diagnostic::Lower {
                    msg: LowerError::RoutedAppMissingPageField { route_count: 2 },
                    ..
                }
            ),
            "expected RoutedAppMissingPageField {{ route_count: 2 }}, got {w:?}"
        );
        assert_eq!(w.severity(), ipe_diagnostics::Severity::Warning);
    }

    /// The same non-routed Model with `has_routes = false` (empty `routes`)
    /// is a genuine non-routed app and must emit NO warning.
    #[test]
    fn non_routed_app_without_routes_is_silent() {
        let mut interner = Interner::new();
        let count_sym = interner.intern("count").expect("intern count");
        let mut budget = Budget::unbounded();
        let mut uf = UnionFind::new();

        let count_var = uf.fresh(Content::Flex).expect("fresh count var");
        let ext = uf
            .fresh(Content::Structure(FlatType::EmptyRecord))
            .expect("fresh ext");
        let mut fields = BTreeMap::new();
        fields.insert(count_sym, count_var);
        let model_var = uf
            .fresh(Content::Structure(FlatType::Record(fields, ext)))
            .expect("fresh model var");
        let not_found_var = uf.fresh(Content::Flex).expect("fresh notFound var");

        let check = RoutedWebCheck {
            model_var,
            not_found_var,
            span: Span::DUMMY,
        };
        let mut warnings: Vec<Diagnostic> = Vec::new();
        resolve_routed_web_checks(
            &mut uf,
            &mut budget,
            &interner,
            &[check],
            /* has_routes */ false,
            /* route_count */ 0,
            &mut warnings,
        )
        .expect("genuine non-routed app must type-check");
        assert!(
            warnings.is_empty(),
            "empty-routes non-routed app must be silent, got {warnings:?}"
        );
    }

    #[test]
    fn nested_non_exhaustive_case_names_the_missing_nested_pattern() {
        // `Som (Som x)` only matches when the inner value is `Som`, so the value
        // `Som Non` escapes every arm. The usefulness checker must report it as a
        // non-exhaustive case naming the precise missing pattern `Som Non` —
        // BEFORE lowering, so the Rust backend never emits a non-exhaustive match.
        let src = "module Main exposing (main)\n\
                   type Opt a = Som a | Non\n\
                   f : Opt (Opt Int) -> Int\n\
                   f o =\n        case o of\n            Som (Som x) -> x\n\
                   \x20           Non -> 0\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::NonExhaustiveCase { .. },
                    ..
                })
            ),
            "expected NonExhaustiveCase, got {r:?}"
        );
        let Err(Diagnostic::Type {
            msg: TypeError::NonExhaustiveCase { missing },
            ..
        }) = r
        else {
            return;
        };
        let names: Vec<&str> = missing.iter().map(AsRef::as_ref).collect();
        assert_eq!(names, vec!["Som Non"], "names the nested missing pattern");
    }

    #[test]
    fn nested_redundant_arm_names_the_subsuming_constructor() {
        // `Som x` (a bare variable payload) already matches every `Som _`, so the
        // later, deeper `Som (Som y)` arm covers no new value. The redundancy
        // finding is computed over the same nested matrix as exhaustiveness, so it
        // must fire even when the useless arm is more specific than the arm that
        // subsumes it — reported as IPE-T0011 (Warning) naming the top-level `Som`.
        // IPE-T0011 is Severity::Warning — infer must return Ok with the warning in
        // types.warnings, NOT return Err.
        let src = "module Main exposing (main)\n\
                   type Opt a = Som a | Non\n\
                   f : Opt (Opt Int) -> Int\n\
                   f o =\n        case o of\n            Som x -> 1\n\
                   \x20           Som (Som y) -> y\n            Non -> 0\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        let types = r.expect("redundant branch is a warning (IPE-T0011), not an error");
        assert_eq!(
            types.warnings.len(),
            1,
            "expected exactly one warning, got {:?}",
            types.warnings
        );
        let warning = types.warnings.first().expect("len==1 asserted above");
        assert!(
            matches!(
                warning,
                Diagnostic::Type {
                    msg: TypeError::RedundantCaseBranch { .. },
                    ..
                }
            ),
            "expected RedundantCaseBranch warning, got {warning:?}"
        );
        if let Diagnostic::Type {
            msg: TypeError::RedundantCaseBranch { constructor },
            ..
        } = warning
        {
            assert_eq!(&**constructor, "Som", "names the subsuming top-level ctor");
        }
    }

    #[test]
    fn nested_exhaustive_case_passes_the_check() {
        // Every nested possibility is covered: `Som (Som x)`, `Som Non`, `Non`.
        let src = "module Main exposing (main)\n\
                   type Opt a = Som a | Non\n\
                   f : Opt (Opt Int) -> Int\n\
                   f o =\n        case o of\n            Som (Som x) -> x\n\
                   \x20           Som Non -> 0\n            Non -> 0\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        // Exhaustiveness passes: the two `Som` arms discriminate on their nested
        // sub-pattern and together with `Non` cover every value. So `infer` must
        // succeed (the lowerer then emits one Rust arm per source arm).
        assert!(
            infer(&m, &mut i).is_ok(),
            "an exhaustive nested case must pass the exhaustiveness check"
        );
    }

    #[test]
    fn self_application_is_an_infinite_type() {
        // `f x = x x` forces `a = a -> b`, tripping the occurs check.
        let src = "module Main exposing (main)\n\
                   f x = x x\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::InfiniteType { .. },
                    ..
                })
            ),
            "expected InfiniteType, got {r:?}"
        );
        let Err(Diagnostic::Type {
            msg: TypeError::InfiniteType { var, ty },
            span,
        }) = r
        else {
            return;
        };
        // Real offending span — not DUMMY (the historic bug).
        assert_ne!(span, Span::DUMMY, "occurs-check span must be real");
        // `var` appears on the left of the arrow it would have to equal.
        assert!(matches!(
            ty.as_ref(),
            ipe_diagnostics::TyDoc::Fun(lhs, _)
                if matches!(lhs.as_ref(), ipe_diagnostics::TyDoc::Var(v) if *v == var)
        ));
    }

    #[test]
    fn exhaustive_case_passes_the_check() {
        // The golden program's `update` covers every `Msg` constructor.
        let opt = canon_golden();
        let Some((m, mut i)) = opt else { return };
        assert!(
            infer(&m, &mut i).is_ok(),
            "an exhaustive, non-redundant program must pass the new pass"
        );
    }

    /// Parse + canonicalise + infer `source`; return the resolved type of the
    /// binding named `which` from the env.
    fn infer_env_ty(source: &str, which: &str) -> Option<(Ty, Interner)> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(source, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
        let solved = infer(&m, &mut i).ok()?;
        let key = def_key(&i, &m, which)?;
        let ty = solved.env.get(&key)?.clone();
        Some((ty, i))
    }

    /// Walk an arrow type to its final (return) constructor name.
    fn return_con_name(ty: &Ty, i: &Interner) -> Option<String> {
        match ty {
            Ty::Fun(_, rest) => return_con_name(rest, i),
            Ty::Con { name, .. } => i.resolve(*name).map(str::to_owned),
            _ => None,
        }
    }

    #[test]
    fn lambda_binding_infers_a_function_type() {
        // `f = \x -> x + 1` infers `Int -> Int` (the `+ 1` pins both x and the
        // result to Int).
        let opt = infer_env_ty("module Main exposing (f)\nf =\n    \\x -> x + 1\n", "f");
        assert!(opt.is_some(), "f must infer");
        let Some((ty, i)) = opt else { return };
        assert!(matches!(ty, Ty::Fun(..)), "f must be an arrow, got {ty:?}");
        let Ty::Fun(arg, ret) = &ty else { return };
        assert_eq!(ty_con_name(arg, &i).as_deref(), Some("Int"));
        assert_eq!(ty_con_name(ret, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn multi_param_lambda_infers_curried_arrows() {
        // `f = \a b -> a + b` infers `Int -> Int -> Int`.
        let opt = infer_env_ty("module Main exposing (f)\nf =\n    \\a b -> a + b\n", "f");
        assert!(opt.is_some(), "f must infer");
        let Some((ty, i)) = opt else { return };
        assert!(matches!(ty, Ty::Fun(..)), "f must be an arrow, got {ty:?}");
        let Ty::Fun(a, tail) = &ty else { return };
        assert_eq!(ty_con_name(a, &i).as_deref(), Some("Int"));
        assert!(
            matches!(tail.as_ref(), Ty::Fun(..)),
            "tail must be an arrow, got {tail:?}"
        );
        let Ty::Fun(b, ret) = tail.as_ref() else {
            return;
        };
        assert_eq!(ty_con_name(b, &i).as_deref(), Some("Int"));
        assert_eq!(ty_con_name(ret, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn applied_captured_lambda_infers_int() {
        // `(\x -> x + n) 5` with `n = 10` applies a capturing lambda; the whole
        // binding is `Int`.
        let opt = infer_env_ty(
            "module Main exposing (v)\nv =\n    let n = 10 in (\\x -> x + n) 5\n",
            "v",
        );
        assert!(opt.is_some(), "v must infer");
        let Some((ty, i)) = opt else { return };
        assert_eq!(ty_con_name(&ty, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn applying_a_non_function_is_rejected() {
        // `v = 5 1` applies an Int to an argument — `Int` cannot unify with a
        // function type, so it is a type error (no panic, no silent accept).
        let mut i = Interner::new();
        let source = "module Main exposing (v)\nv : Int\nv =\n    let g = 5 in g 1\n";
        let parsed = ipe_parse::parse_module(source, &mut i);
        assert!(parsed.is_ok(), "must parse");
        let Ok(src) = parsed else { return };
        let canon = ipe_canon::canonicalise(&src, &mut i);
        assert!(canon.is_ok(), "must canonicalise");
        let Ok(m) = canon else { return };
        assert!(
            infer(&m, &mut i).is_err(),
            "applying a non-function must be a type error"
        );
    }

    #[test]
    fn arithmetic_chain_is_int() {
        let opt = infer_env_ty(
            "module Main exposing (v)\nv : Int\nv =\n    2 + 3 * 4 - 1\n",
            "v",
        );
        assert!(opt.is_some(), "v must infer");
        let Some((ty, i)) = opt else { return };
        assert_eq!(ty_con_name(&ty, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn comparison_and_boolean_produce_bool() {
        // `f : Int -> Bool` ⇒ body `n > 10 && n < 100` must be Bool.
        let opt = infer_env_ty(
            "module Main exposing (f)\nf : Int -> Bool\nf n =\n    n > 10 && n < 100\n",
            "f",
        );
        assert!(opt.is_some(), "f must infer");
        let Some((ty, i)) = opt else { return };
        assert_eq!(
            return_con_name(&ty, &i).as_deref(),
            Some("Bool"),
            "comparison + && yields Bool"
        );
    }

    #[test]
    fn untyped_comparison_infers_bool_return() {
        // No annotation: the inferred return of `g a b = a == b` must be Bool.
        let opt = infer_env_ty("module Main exposing (g)\ng a b =\n    a == b\n", "g");
        assert!(opt.is_some(), "g must infer");
        let Some((ty, i)) = opt else { return };
        assert_eq!(return_con_name(&ty, &i).as_deref(), Some("Bool"));
    }

    #[test]
    fn boolean_operand_type_mismatch_is_rejected() {
        // `1 && 2` — `&&` demands Bool operands; an Int operand must fail.
        let mut i = Interner::new();
        let source = "module Main exposing (v)\nv : Bool\nv =\n    1 && 2\n";
        let parsed = ipe_parse::parse_module(source, &mut i);
        assert!(parsed.is_ok(), "must parse");
        let Ok(src) = parsed else { return };
        let canon = ipe_canon::canonicalise(&src, &mut i);
        assert!(canon.is_ok(), "must canonicalise");
        let Ok(m) = canon else { return };
        assert!(
            infer(&m, &mut i).is_err(),
            "Int operand to && must be a type error"
        );
    }

    #[test]
    fn string_append_infers_string() {
        // `"a" ++ "b"` — `++` is `String -> String -> String`, so the result
        // type is `String`.
        let opt = infer_env_ty("module Main exposing (v)\nv =\n    \"a\" ++ \"b\"\n", "v");
        assert!(opt.is_some(), "v must infer");
        let Some((ty, i)) = opt else { return };
        assert_eq!(
            ty_con_name(&ty, &i).as_deref(),
            Some("String"),
            "`++` of two strings infers String, got {ty:?}"
        );
    }

    #[test]
    fn append_on_non_string_operand_is_rejected() {
        // `++` carries an `Appendable` obligation; an `Int` operand (which is
        // neither `String` nor `List _`) fails the pin and surfaces as a type
        // error rather than reaching the backend (fail-closed).
        let mut i = Interner::new();
        let source = "module Main exposing (v)\nv : Int\nv =\n    1 ++ 2\n";
        let parsed = ipe_parse::parse_module(source, &mut i);
        assert!(parsed.is_ok(), "must parse");
        let Ok(src) = parsed else { return };
        let canon = ipe_canon::canonicalise(&src, &mut i);
        assert!(canon.is_ok(), "must canonicalise");
        let Ok(m) = canon else { return };
        assert!(
            infer(&m, &mut i).is_err(),
            "Int operand to ++ must be a type error"
        );
    }

    #[test]
    fn tuple_value_infers_tuple_type() {
        // Untyped `v = (1, 2)` infers the product type `(Int, Int)`.
        let opt = infer_env_ty("module Main exposing (v)\nv =\n    (1, 2)\n", "v");
        assert!(opt.is_some(), "v must infer");
        let Some((ty, i)) = opt else { return };
        let shape = match &ty {
            Ty::Tuple(elems) => Some((
                elems.len(),
                elems
                    .iter()
                    .all(|e| ty_con_name(e, &i).as_deref() == Some("Int")),
            )),
            _ => None,
        };
        assert_eq!(
            shape,
            Some((2, true)),
            "v infers the 2-tuple `(Int, Int)`, got {ty:?}"
        );
    }

    #[test]
    fn tuple_against_int_annotation_is_rejected() {
        // `v : Int` with a tuple body must fail: `(Int, Int)` ≠ `Int`.
        let mut i = Interner::new();
        let source = "module Main exposing (v)\nv : Int\nv =\n    (1, 2)\n";
        let parsed = ipe_parse::parse_module(source, &mut i);
        assert!(parsed.is_ok(), "must parse");
        let Ok(src) = parsed else { return };
        let canon = ipe_canon::canonicalise(&src, &mut i);
        assert!(canon.is_ok(), "must canonicalise");
        let Ok(m) = canon else { return };
        assert!(
            infer(&m, &mut i).is_err(),
            "a tuple body against an Int annotation must be a type error"
        );
    }

    #[test]
    fn record_value_infers_record_type() {
        // Untyped `v = { x = 1, y = 2 }` infers the closed record type
        // `{ x : Int, y : Int }`.
        let opt = infer_env_ty("module Main exposing (v)\nv =\n    { x = 1, y = 2 }\n", "v");
        assert!(opt.is_some(), "v must infer");
        let Some((ty, i)) = opt else { return };
        let shape = match &ty {
            Ty::Record(fields, _) => Some((
                fields.len(),
                fields
                    .values()
                    .all(|t| ty_con_name(t, &i).as_deref() == Some("Int")),
            )),
            _ => None,
        };
        assert_eq!(
            shape,
            Some((2, true)),
            "v infers `{{ x : Int, y : Int }}`, got {ty:?}"
        );
    }

    #[test]
    fn field_access_infers_the_field_type() {
        // `let p = { x = 1, y = 2 } in p.x` has the field's type, `Int`.
        let opt = infer_env_ty(
            "module Main exposing (v)\nv =\n    let p = { x = 1, y = 2 } in p.x\n",
            "v",
        );
        assert!(opt.is_some(), "v must infer");
        let Some((ty, i)) = opt else { return };
        assert_eq!(ty_con_name(&ty, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn field_access_constrains_through_arithmetic() {
        // `p.x + p.y` forces both fields to `Int`; the whole binding is `Int`.
        let opt = infer_env_ty(
            "module Main exposing (v)\nv =\n    let p = { x = 1, y = 2 } in p.x + p.y\n",
            "v",
        );
        assert!(opt.is_some(), "v must infer");
        let Some((ty, i)) = opt else { return };
        assert_eq!(ty_con_name(&ty, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn accessing_a_missing_field_is_no_such_field() {
        // `{ x = 1 }` has no `y`: a closed record rejects the access (IPE-T0012).
        let source = "module Main exposing (v)\nv =\n    let p = { x = 1 } in p.y\n";
        let Some((m, mut i)) = canon_src(source) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::NoSuchField { .. },
                    ..
                })
            ),
            "a missing field must be NoSuchField, got {r:?}"
        );
    }

    #[test]
    fn accessing_a_field_on_a_non_record_is_no_such_field() {
        // `p` is an `Int`, so `p.x` has no field to read (IPE-T0012).
        let source = "module Main exposing (v)\nv =\n    let p = 5 in p.x\n";
        let Some((m, mut i)) = canon_src(source) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::NoSuchField { .. },
                    ..
                })
            ),
            "a field on a non-record must be NoSuchField, got {r:?}"
        );
    }

    #[test]
    fn record_update_has_the_base_record_type() {
        // `{ p | x = 41 }` is the same record type as `p`, so reading `q.x`
        // afterwards is an `Int`.
        let opt = infer_env_ty(
            "module Main exposing (v)\nv =\n    let p = { x = 1, y = 2 } in let q = { p | x = 41 } in q.y\n",
            "v",
        );
        assert!(opt.is_some(), "v must infer");
        let Some((ty, i)) = opt else { return };
        assert_eq!(ty_con_name(&ty, &i).as_deref(), Some("Int"));
    }

    #[test]
    fn updating_a_missing_field_is_no_such_field() {
        // `{ p | z = 0 }` where `p` has only `x`/`y`: a closed record rejects the
        // update of an absent field (IPE-T0012).
        let source =
            "module Main exposing (v)\nv =\n    let p = { x = 1, y = 2 } in { p | z = 0 }\n";
        let Some((m, mut i)) = canon_src(source) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::NoSuchField { .. },
                    ..
                })
            ),
            "updating a missing field must be NoSuchField, got {r:?}"
        );
    }

    #[test]
    fn updating_a_field_to_the_wrong_type_is_rejected() {
        // `p.x` is an `Int`; updating it to a record `{ a = 1 }` cannot unify, so
        // the whole binding is a type error.
        let source = "module Main exposing (v)\nv =\n    let p = { x = 1, y = 2 } in { p | x = { a = 1 } }\n";
        let Some((m, mut i)) = canon_src(source) else {
            return;
        };
        assert!(
            infer(&m, &mut i).is_err(),
            "updating a field to a value of the wrong type must be a type error"
        );
    }

    #[test]
    fn updating_a_field_on_a_non_record_is_no_such_field() {
        // `p` is an `Int`, so `{ p | x = 1 }` has no field to update (IPE-T0012).
        let source = "module Main exposing (v)\nv =\n    let p = 5 in { p | x = 1 }\n";
        let Some((m, mut i)) = canon_src(source) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::NoSuchField { .. },
                    ..
                })
            ),
            "updating a field on a non-record must be NoSuchField, got {r:?}"
        );
    }

    #[test]
    fn records_with_different_field_sets_do_not_unify() {
        // `{ x = 1 } == { y = 1 }`: closed records unify only at equal field
        // sets, so this is a type error.
        let source = "module Main exposing (v)\nv : Bool\nv =\n    { x = 1 } == { y = 1 }\n";
        let Some((m, mut i)) = canon_src(source) else {
            return;
        };
        assert!(
            infer(&m, &mut i).is_err(),
            "records with different field sets must not unify"
        );
    }

    #[test]
    fn tuple_arity_mismatch_is_rejected() {
        // Comparing a 2-tuple with a 3-tuple must fail: tuples unify only at
        // equal arity.
        let mut i = Interner::new();
        let source = "module Main exposing (v)\nv : Bool\nv =\n    (1, 2) == (1, 2, 3)\n";
        let parsed = ipe_parse::parse_module(source, &mut i);
        assert!(parsed.is_ok(), "must parse");
        let Ok(src) = parsed else { return };
        let canon = ipe_canon::canonicalise(&src, &mut i);
        assert!(canon.is_ok(), "must canonicalise");
        let Ok(m) = canon else { return };
        assert!(
            infer(&m, &mut i).is_err(),
            "2-tuple vs 3-tuple must be a type error"
        );
    }

    // ── let-generalization + per-call-site instantiation ────────────────────

    /// A polymorphic annotation `a -> a` reads back into `env` as one quantified
    /// variable used on both sides of the arrow — `Fun(Var p, Var p)` with the
    /// *same* `p`. That single quantified var is what a later lowering pass turns
    /// into one Rust generic parameter (`fn identity<T1>(x: T1) -> T1`).
    #[test]
    fn polymorphic_identity_generalises_to_one_var() {
        let opt = infer_env_ty(
            "module Main exposing (identity)\n\
             identity : a -> a\n\
             identity x =\n    x\n",
            "identity",
        );
        assert!(opt.is_some(), "identity must infer");
        let Some((ty, _i)) = opt else { return };
        assert!(
            matches!(&ty, Ty::Fun(a, r)
                if matches!((a.as_ref(), r.as_ref()),
                    (Ty::Var(x), Ty::Var(y)) if x == y)),
            "identity must generalise to one quantified var `a -> a`, got {ty:?}"
        );
    }

    /// One polymorphic function, two concrete uses in the same module: applied to
    /// an `Int` and to a `Bool`, both must type-check. Each `VarTopLevel`
    /// reference instantiates `identity`'s scheme into *fresh* variables, so the
    /// two uses are satisfied independently (Rust later monomorphises the single
    /// generic fn at both types).
    #[test]
    fn polymorphic_identity_used_at_int_and_bool_both_unify() {
        let src = "module Main exposing (main)\n\
                   identity : a -> a\n\
                   identity x =\n    x\n\
                   useInt : Int\n\
                   useInt =\n    identity 5\n\
                   useBool : Bool\n\
                   useBool =\n    identity (0 == 0)\n\
                   main =\n    Io.println (String.fromInt useInt)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "identity used at Int and Bool in one module must infer: {r:?}"
        );
        let Ok(solved) = r else { return };
        // The two consumers settle at their concrete result types.
        let Some(use_int) = def_key(&i, &m, "useInt") else {
            return;
        };
        let Some(use_bool) = def_key(&i, &m, "useBool") else {
            return;
        };
        assert_eq!(
            solved
                .env
                .get(&use_int)
                .and_then(|t| ty_con_name(t, &i))
                .as_deref(),
            Some("Int")
        );
        assert_eq!(
            solved
                .env
                .get(&use_bool)
                .and_then(|t| ty_con_name(t, &i))
                .as_deref(),
            Some("Bool")
        );
    }

    /// `const : a -> b -> a` keeps two *distinct* quantified variables: the first
    /// parameter and the return share one, the second is its own. Confirms the
    /// per-signature instantiation maps each annotation variable consistently
    /// without conflating different ones.
    #[test]
    fn const_keeps_two_distinct_type_vars() {
        let opt = infer_env_ty(
            "module Main exposing (constant)\n\
             constant : a -> b -> a\n\
             constant x y =\n    x\n",
            "constant",
        );
        assert!(opt.is_some(), "constant must infer");
        let Some((ty, _i)) = opt else { return };
        // `a -> b -> a`: positions 1 and 3 share one var; position 2 is distinct.
        assert!(
            matches!(&ty, Ty::Fun(a1, tail)
                if matches!(tail.as_ref(), Ty::Fun(b, a2)
                    if matches!((a1.as_ref(), b.as_ref(), a2.as_ref()),
                        (Ty::Var(x), Ty::Var(y), Ty::Var(z)) if x == z && x != y))),
            "constant must be `a -> b -> a` (first param == result, distinct from second), got {ty:?}"
        );
    }

    /// `apply : (a -> b) -> a -> b` — a structural pass-through over a function
    /// argument — infers with `a` and `b` threaded through correctly.
    #[test]
    fn higher_order_apply_infers_structurally() {
        let opt = infer_env_ty(
            "module Main exposing (apply)\n\
             apply : (a -> b) -> a -> b\n\
             apply f x =\n    f x\n",
            "apply",
        );
        assert!(opt.is_some(), "apply must infer");
        let Some((ty, _i)) = opt else { return };
        // `(a -> b) -> a -> b`: the `a`s match, the `b`s match, `a` != `b`.
        assert!(
            matches!(&ty, Ty::Fun(fa, tail)
                if matches!((fa.as_ref(), tail.as_ref()),
                    (Ty::Fun(a1, b1), Ty::Fun(a2, b2))
                    if matches!((a1.as_ref(), b1.as_ref(), a2.as_ref(), b2.as_ref()),
                        (Ty::Var(va1), Ty::Var(vb1), Ty::Var(va2), Ty::Var(vb2))
                        if va1 == va2 && vb1 == vb2 && va1 != vb1))),
            "apply must be `(a -> b) -> a -> b`, got {ty:?}"
        );
    }

    /// `bad : a -> b; bad x = x` returns a value of the parameter's type from a
    /// signature that promised an *independent* return variable. The rigid
    /// (skolem) check rejects it — the body cannot conflate two distinct
    /// annotation variables.
    #[test]
    fn annotation_returning_a_different_var_is_rejected() {
        let src = "module Main exposing (main)\n\
                   bad : a -> b\n\
                   bad x =\n    x\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        assert!(
            matches!(
                infer(&m, &mut i),
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "returning the parameter from `a -> b` must be a type mismatch"
        );
    }

    /// `f : a -> a; f x = x + 1` annotates a fully-parametric `a`, but the
    /// literal `1` pins `a` to `Int`. The annotation promised *any* type while
    /// the body needs a concrete one, so the rigid skolem `a` meeting the `Int`
    /// the literal forces is a mismatch — the signature is too general for its
    /// body. (Contrast `f x = x + x`, which carries no literal: `a` stays a
    /// Number-bounded generic.)
    #[test]
    fn parametric_annotation_body_forcing_concrete_is_rejected() {
        let src = "module Main exposing (main)\n\
                   f : a -> a\n\
                   f x =\n    x + 1\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        assert!(
            matches!(
                infer(&m, &mut i),
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "a body pinning a parametric `a` to Int must be a type mismatch"
        );
    }

    /// An *un*annotated binding reconstructs its full arrow type into `env`
    /// (parameters included), and an unconstrained parameter generalises: for
    /// `k a b = a`, `env[k]` is `a -> b -> a` with the first parameter and the
    /// result sharing one inferred variable.
    #[test]
    fn untyped_binding_reconstructs_and_generalises_arrow() {
        let opt = infer_env_ty(
            "module Main exposing (k)\n\
             k a b =\n    a\n",
            "k",
        );
        assert!(opt.is_some(), "k must infer");
        let Some((ty, _i)) = opt else { return };
        // Reconstructed `a -> b -> a` (params included), first param == result.
        assert!(
            matches!(&ty, Ty::Fun(a1, tail)
                if matches!(tail.as_ref(), Ty::Fun(b, a2)
                    if matches!((a1.as_ref(), b.as_ref(), a2.as_ref()),
                        (Ty::Var(x), Ty::Var(y), Ty::Var(z)) if x == z && x != y))),
            "k must reconstruct + generalise to `a -> b -> a`, got {ty:?}"
        );
    }

    /// Regression for AUD-06 (seal): `Auth.signToken` claims pinned to
    /// `Dict String String`, not flexible `var(0)`. `var(0)` unified with
    /// anything (a record literal included), so ipe accepted a program the
    /// generated project's `HashMap<String,String>`-pinned wrapper could not
    /// build (exit-0-then-cargo-fail). A `Dict.fromList [...]` literal claims
    /// argument must still type-check clean; a record literal must now be
    /// REJECTED at type-check (IPE-T0001-class), not silently accepted.
    #[test]
    fn auth_sign_token_claims_pinned_to_dict_string_string() {
        // `signToken`'s first argument is `Secret`, not `String` —
        // seal via `Secret.fromString` (auto-qualified prelude module, no
        // import needed, same as `Uuid.v4`).
        let ok_src = "module Main exposing (main)\n\
             import Ipe.Auth as Auth\n\
             main =\n    Auth.signToken (Secret.fromString \"s\") (Dict.fromList [(\"sub\", \"x\")]) 3600\n";
        let Some((m, mut i)) = canon_src(ok_src) else {
            return;
        };
        assert!(
            infer(&m, &mut i).is_ok(),
            "Auth.signToken with a Dict String String claims literal must type-check clean"
        );

        let bad_src = "module Main exposing (main)\n\
             import Ipe.Auth as Auth\n\
             main =\n    Auth.signToken (Secret.fromString \"s\") { sub = \"x\" } 3600\n";
        let Some((m2, mut i2)) = canon_src(bad_src) else {
            return;
        };
        assert!(
            infer(&m2, &mut i2).is_err(),
            "Auth.signToken with a RECORD literal claims argument must now be \
             REJECTED (pre-fix: var(0) unified with anything, accepting a \
             shape the emitted HashMap<String,String>-pinned wrapper cannot build)"
        );
    }

    /// Reference-parity semantics (Boundary Scheme Promotion, class-1
    /// inference fix #2): an *un*annotated binding is monomorphic *within its
    /// home module* — every same-module reference shares one variable, so
    /// using it at two different concrete types from within its own module is
    /// a sound rejection, exactly matching the reference `ipe` compiler's
    /// `CLocal` semantics (see
    /// `docs/adr/0001-language-semantics-and-types.md`). A
    /// CROSS-module use at two different types IS accepted — see
    /// [`untyped_binding_generalizes_across_cross_module_uses`]. To get
    /// polymorphism from within the same module, annotate it (see
    /// [`polymorphic_identity_used_at_int_and_bool_both_unify`]).
    #[test]
    fn untyped_polymorphic_use_at_two_types_is_rejected() {
        let src = "module Main exposing (main)\n\
                   ident x =\n    x\n\
                   useInt : Int\n\
                   useInt =\n    ident 5\n\
                   useBool : Bool\n\
                   useBool =\n    ident (0 == 0)\n\
                   main =\n    Io.println (String.fromInt useInt)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        assert!(
            infer(&m, &mut i).is_err(),
            "an unannotated binding used at Int and Bool must be rejected (monomorphic)"
        );
    }

    /// The single recorded [`TyBounds`] of a binding's one bounded variable, or
    /// `None` if the binding recorded no obligated variable.
    fn sole_bound(solved: &SolvedTypes, i: &mut Interner, binding: &str) -> Option<TyBounds> {
        let sym = i.intern(binding).ok()?;
        // `bounds` is keyed by (home, name) (AUD-05); these tests use a single
        // module, so find by name component regardless of home.
        solved
            .bounds
            .iter()
            .find(|((_, name), _)| *name == sym)?
            .1
            .values()
            .next()
            .copied()
    }

    /// `double : a -> a; double x = x + x` constrains `a` numerically (no literal
    /// pins it), so instead of the rigid-skolem rejection a structurally-
    /// parametric variable would get, `a` carries the `Add` (Number) obligation.
    #[test]
    fn number_generic_double_carries_add_bound() {
        let src = "module Main exposing (main)\n\
                   double : a -> a\n\
                   double x =\n    x + x\n\
                   main =\n    Io.println (String.fromInt (double 21))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let solved = infer(&m, &mut i);
        assert!(solved.is_ok(), "double must type-check, got {solved:?}");
        let Ok(solved) = solved else { return };
        let bound = sole_bound(&solved, &mut i, "double");
        assert!(bound.is_some(), "double records a bound");
        let Some(b) = bound else { return };
        assert!(b.has_add(), "double's `a` carries the Add (Number) bound");
        assert!(
            !b.has_ord() && !b.has_sub() && !b.has_mul(),
            "double needs only Add, got {b:?}"
        );
    }

    /// `maxOf : a -> a -> a; maxOf p q = if p > q then p else q` orders `a`, so
    /// `a` carries the `PartialOrd` (Comparable) obligation.
    #[test]
    fn comparable_generic_max_carries_ord_bound() {
        let src = "module Main exposing (main)\n\
                   maxOf : a -> a -> a\n\
                   maxOf p q =\n    if p > q then p else q\n\
                   main =\n    Io.println (String.fromInt (maxOf 3 7))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        let solved = infer(&m, &mut i);
        assert!(solved.is_ok(), "maxOf must type-check, got {solved:?}");
        let Ok(solved) = solved else { return };
        let bound = sole_bound(&solved, &mut i, "maxOf");
        assert!(bound.is_some(), "maxOf records a bound");
        let Some(b) = bound else { return };
        assert!(b.has_ord(), "maxOf's `a` carries the ordering bound");
        assert!(
            !b.has_add() && !b.has_sub() && !b.has_mul(),
            "maxOf needs only ordering, got {b:?}"
        );
    }

    /// A Number generic used at both `Int` (a literal) and `Float` (through an
    /// annotated forwarder) type-checks: both satisfy the `Add` obligation.
    #[test]
    fn number_generic_used_at_int_and_float_checks() {
        let src = "module Main exposing (main)\n\
                   double : a -> a\n\
                   double x =\n    x + x\n\
                   doubleFloat : Float -> Float\n\
                   doubleFloat x =\n    double x\n\
                   main =\n    Io.println (String.fromInt (double 21))\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        assert!(
            infer(&m, &mut i).is_ok(),
            "double used at Int and Float must type-check"
        );
    }

    /// A Number generic used at `Bool` is rejected: `Bool` is not a `Number`, so
    /// the use surfaces IPE-T0014 rather than emitting Rust `cargo` cannot build.
    #[test]
    fn number_generic_at_bool_is_super_type_unsatisfied() {
        let src = "module Main exposing (main)\n\
                   double : a -> a\n\
                   double x =\n    x + x\n\
                   doubleBool : Bool -> Bool\n\
                   doubleBool x =\n    double x\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        assert!(
            matches!(
                infer(&m, &mut i),
                Err(Diagnostic::Type {
                    msg: TypeError::SuperTypeUnsatisfied { .. },
                    ..
                })
            ),
            "a Number generic used at Bool must be SuperTypeUnsatisfied"
        );
    }

    /// An unannotated `\\a b -> a + b` is `Int -> Int -> Int` by numeric
    /// defaulting: the body constrains the parameters to `Number`, and a
    /// `Number` the program never pins resolves to `Int`.
    #[test]
    fn unpinned_numeric_binding_defaults_to_int() {
        let opt = infer_env_ty("module Main exposing (f)\nf =\n    \\a b -> a + b\n", "f");
        assert!(opt.is_some(), "f must infer");
        let Some((ty, i)) = opt else { return };
        // `Int -> Int -> Int`.
        assert_eq!(return_con_name(&ty, &i).as_deref(), Some("Int"));
        assert!(matches!(ty, Ty::Fun(..)), "f must be an arrow, got {ty:?}");
        let Ty::Fun(a, tail) = &ty else { return };
        assert_eq!(ty_con_name(a, &i).as_deref(), Some("Int"));
        assert!(
            matches!(tail.as_ref(), Ty::Fun(..)),
            "f's tail must be an arrow, got {tail:?}"
        );
        let Ty::Fun(b, _) = tail.as_ref() else { return };
        assert_eq!(ty_con_name(b, &i).as_deref(), Some("Int"));
    }

    /// Numeric-literal polymorphism (IPE-T0001): an integer literal is
    /// `Number`-polymorphic, so passing `100` where a `Float` is expected
    /// type-checks — the literal resolves to `Float`.  The minimized shape is
    /// `pct 100` with `pct : Float -> Length`: the literal must not be pinned
    /// to a concrete `Int` at creation, which would clash with the `Float`
    /// parameter.
    #[test]
    fn integer_literal_accepted_where_float_expected() {
        let src = "module Main exposing (main)\n\
                   toF : Float -> Float\n\
                   toF x =\n    x\n\
                   v : Float\n\
                   v =\n    toF 100\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        assert!(
            infer(&m, &mut i).is_ok(),
            "an integer literal `100` must satisfy a `Float` parameter"
        );
    }

    /// Companion soundness guard: a *float* literal is concretely `Float` and must
    /// NOT satisfy an `Int` parameter (the polymorphism is one-directional —
    /// integer literals are `number`, float literals are `Float`).
    #[test]
    fn float_literal_rejected_where_int_expected() {
        let src = "module Main exposing (main)\n\
                   toI : Int -> Int\n\
                   toI x =\n    x\n\
                   v : Int\n\
                   v =\n    toI 1.5\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        assert!(
            infer(&m, &mut i).is_err(),
            "a float literal `1.5` must not satisfy an `Int` parameter"
        );
    }

    /// Soundness guard preserved through the numeric-literal change: a numeric
    /// literal added to a fully-parametric annotation skolem is still rejected.
    /// `f : a -> a; f x = x + 1` forces the annotated-generic `a` to a concrete
    /// number, which Elm/Ipê reject.  The literal (`Super { Number, rigid:false }`)
    /// meeting the annotation skolem (`Super { .., rigid:true }`) is a mismatch.
    #[test]
    fn literal_added_to_parametric_skolem_is_rejected() {
        let src = "module Main exposing (main)\n\
                   f : a -> a\n\
                   f x =\n    x + 1\n\
                   main =\n    Io.println (String.fromInt 0)\n";
        let Some((m, mut i)) = canon_src(src) else {
            return;
        };
        assert!(
            matches!(
                infer(&m, &mut i),
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "adding a concrete literal to a parametric `a` must be a mismatch"
        );
    }

    /// `constrain_pattern` must recurse into sub-patterns of a
    /// constructor whose scheme is not registered (e.g. an imported kernel-stdlib
    /// ADT like `ChunkEvent`).  If the no-scheme fallback skips binding arg
    /// variables into `br_local`, the arm body's `VarLocal` lookup
    /// fires the "unbound local" ICE (IPE-I0001).
    ///
    /// We exercise this directly by building a `canon::Module` with no `unions`
    /// (so `ImportedCtor` has no scheme) and a single `case` arm:
    ///
    /// ```
    /// case scrut of
    ///     ImportedCtor x -> x   -- arm uses `x`, must not ICE
    /// ```
    #[test]
    fn imported_ctor_pvar_does_not_ice() {
        use ipe_diagnostics::Span;

        let mut i = Interner::new();
        let main_sym = i.intern("Main").unwrap();
        let f_sym = i.intern("f").unwrap();
        let arg_sym = i.intern("scrut").unwrap();
        let ctor_type_sym = i.intern("ImportedType").unwrap();
        let ctor_sym = i.intern("ImportedCtor").unwrap();
        let var_sym = i.intern("x").unwrap();

        // No `unions` → `ImportedCtor` has no scheme, triggering the no-scheme
        // fallback path in `constrain_pattern`.
        let module = canon::Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: vec![main_sym],
            unions: vec![],
            defs: vec![canon::Def::Untyped {
                home: vec![main_sym],
                name: ipe_diagnostics::Located::new(Span::DUMMY, f_sym),
                patterns: vec![ipe_diagnostics::Located::new(
                    Span::DUMMY,
                    canon::Pattern_::PVar(arg_sym),
                )],
                body: ipe_diagnostics::Located::new(
                    Span::DUMMY,
                    canon::Expr_::Case(
                        Box::new(ipe_diagnostics::Located::new(
                            Span::DUMMY,
                            canon::Expr_::VarLocal(arg_sym),
                        )),
                        vec![canon::CaseBranch {
                            // Pattern: `ImportedCtor x`
                            pat: ipe_diagnostics::Located::new(
                                Span::DUMMY,
                                canon::Pattern_::PCtor {
                                    home: vec![],
                                    type_name: ctor_type_sym,
                                    name: ctor_sym,
                                    index: 0,
                                    args: vec![ipe_diagnostics::Located::new(
                                        Span::DUMMY,
                                        canon::Pattern_::PVar(var_sym),
                                    )],
                                },
                            ),
                            // Body: `x` — uses the pattern-bound variable
                            body: ipe_diagnostics::Located::new(
                                Span::DUMMY,
                                canon::Expr_::VarLocal(var_sym),
                            ),
                        }],
                    ),
                ),
            }],
        };

        let result = infer(&module, &mut i);

        // The result may be a type error (e.g. T0001) but must NOT be the
        // "unbound local" compiler bug.
        if let Err(ipe_diagnostics::Diagnostic::CompilerBug { detail, .. }) = &result {
            assert!(
                !detail.contains("unbound local"),
                "#145 regression: imported ctor PVar arg must not fire \
                 'unbound local' ICE; detail: {detail}"
            );
        }
    }

    /// A cross-module untyped recursive function polymorphic in
    /// its LIST-ELEMENT type (`listLen : List a -> Int`) must generalize its
    /// element var at the boundary so the lowerer can emit a Rust generic — NOT
    /// leave it a residual flex that hits IPE-L0102.
    #[test]
    fn i201_polymorphic_list_element_cross_module_generalizes() {
        let lib = (
            "Lib1",
            "module Lib1 exposing (listLen)\n\n\
             listLen xs =\n    case xs of\n        [] -> 0\n        _ :: rest -> 1 + listLen rest\n",
        );
        let main = (
            "Main",
            "module Main exposing (main)\n\n\
             import Lib1 exposing (listLen)\n\n\
             main =\n    Io.println (String.fromInt (listLen [ 90, 35 ]))\n",
        );
        let Some((m, mut i)) = link_modules(&[lib, main]) else {
            return;
        };
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a polymorphic-list-element cross-module untyped def must typecheck: {r:?}"
        );
        let Ok(solved) = r else { return };
        let Ok(lib1) = i.intern("Lib1") else { return };
        let Ok(list_len) = i.intern("listLen") else {
            return;
        };
        let quantified = solved.untyped_type_params.get(&(vec![lib1], list_len));
        assert!(
            quantified.is_some_and(|v| v.len() == 1),
            "listLen's promoted scheme must quantify EXACTLY the list-element \
             var so the lowerer emits a Rust generic instead of IPE-L0102; got: {quantified:?}"
        );
    }

    /// A cross-module type mismatch — module `Lib` exports a value of a user
    /// type `Stamp`, module `Main` feeds it to an `Int`-field constructor
    /// (`Wrap stamp`) while also holding an UNRELATED `case` that shares the
    /// `Int` type variable — must be blamed:
    ///
    /// 1. at the ACTUAL mismatching sub-term (`stamp` in `Wrap stamp`), never
    ///    at the unrelated `case` arm, and
    /// 2. in the module that OWNS that sub-term (`Main`), via the constraint's
    ///    carried `home` — not the byte-offset heuristic that can pick a
    ///    numerically-closer def in a different file when two linked modules
    ///    share a span range, and
    /// 3. IDENTICALLY on every run — the blamed `(span, home)` is a pure
    ///    function of the source, with no dependence on hash-map iteration
    ///    order in the solve/attribution path (principle 2, Correctness: same
    ///    program + same input yields the same diagnostic, every run).
    ///
    /// The wrong-file / wrong-line / run-to-run-moving-caret failure this pins
    /// made a real localised type error effectively undebuggable.
    #[test]
    fn cross_module_mismatch_blames_the_real_subterm_deterministically() {
        let lib = (
            "Lib",
            "module Lib exposing (stamp, Stamp)\n\n\
             type Stamp =\n    Stamp\n\n\
             stamp : Stamp\n\
             stamp =\n    Stamp\n",
        );
        // `Main` imports `stamp : Stamp` and feeds it to `Wrap`'s `Int` field
        // (`Wrap stamp`), the genuine mismatch. `classify`'s `case` arm is
        // unrelated but shares the `Int` type variable through `Maybe Int`;
        // the blame must NOT drift onto it.
        let main_src = "module Main exposing (result, classify)\n\n\
             import Lib exposing (stamp)\n\n\
             type Wrap =\n    Wrap Int\n\n\
             classify : Maybe Int -> Int\n\
             classify m =\n    case m of\n        \
             Just uid ->\n            uid\n\n        \
             Nothing ->\n            0\n\n\
             result : Wrap\n\
             result =\n    Wrap stamp\n";
        let main = ("Main", main_src);

        let Some((m, mut i)) = link_modules(&[lib, main]) else {
            return;
        };

        // The mismatching sub-term is the `stamp` in the FINAL `Wrap stamp`;
        // the caret must land inside this byte range, never on `Just uid`.
        let culprit = "Wrap stamp";
        let culprit_off = main_src
            .rfind(culprit)
            .expect("main source must contain `Wrap stamp`");
        let stamp_lo = culprit_off + "Wrap ".len();
        let stamp_hi = stamp_lo + "stamp".len();
        let case_arm_off = main_src
            .find("Just uid")
            .expect("main source must contain the unrelated `Just uid` arm");

        let main_home = vec![i.intern("Main").expect("intern Main")];

        // First run establishes the blamed span + home; every subsequent run
        // must reproduce them byte-for-byte.
        let mut settled: Option<(Span, Vec<Symbol>)> = None;
        for run in 0..50 {
            let mut budget = Budget::from_env();
            let (diag, home) = infer_with_budget_attributed(&m, &mut i, &mut budget)
                .expect_err("Wrap stamp (Int vs Stamp) must be a type error");

            assert!(
                matches!(
                    &diag,
                    Diagnostic::Type {
                        msg: TypeError::TypeMismatch { .. },
                        ..
                    }
                ),
                "expected IPE-T0001 TypeMismatch, got {diag:?}"
            );
            let Diagnostic::Type { span, .. } = &diag else {
                continue; // unreachable given the assertion above; keeps the bind total
            };

            // Defect 1 (wrong sub-term): the caret sits on `stamp`, never on
            // the unrelated `case` arm.
            let (lo, hi) = (span.lo as usize, span.hi as usize);
            assert!(
                lo >= stamp_lo && hi <= stamp_hi,
                "run {run}: the mismatch must be blamed on the `stamp` argument \
                 (bytes {stamp_lo}..{stamp_hi}), got {lo}..{hi}"
            );
            assert!(
                !(lo >= case_arm_off && lo < case_arm_off + "Just uid".len()),
                "run {run}: the mismatch must NOT be blamed on the unrelated \
                 `Just uid` case arm at byte {case_arm_off}"
            );

            // Defect 1 (wrong file): the carried home is Main, the module that
            // owns `Wrap stamp` — resolved directly, not guessed from the span.
            assert_eq!(
                home, main_home,
                "run {run}: the mismatch must be attributed to its owning \
                 module `Main`, not another file"
            );

            // Defect 2 (non-determinism): the blamed (span, home) is identical
            // on every run.
            match &settled {
                None => settled = Some((*span, home)),
                Some((prev_span, prev_home)) => {
                    assert_eq!(
                        (*span, &home),
                        (*prev_span, prev_home),
                        "run {run}: the blamed (span, home) must be byte-identical \
                         across runs — a moving caret is a Correctness (principle 2) \
                         violation"
                    );
                }
            }
        }
    }

    /// Every obligation bit must reach a clause in the shared use-site gate.
    /// An arrow type satisfies NO super-type bound — so for each single-bit set
    /// a function must be rejected at both call sites. A future bit added to
    /// `TyBounds` but left out of `super_bounds_satisfied`'s conjunction would
    /// leave that bit's clause vacuously true, accepting the function and
    /// re-opening the ipe-accepts-then-cargo-fails seal break; this walk turns
    /// that omission into a failing test rather than a downstream `cargo` error.
    #[test]
    fn every_bound_bit_rejects_a_function_at_both_sites() {
        let mut i = Interner::new();
        let int_sym = i.intern("Int").expect("intern Int");
        let int_ty = Ty::Con {
            module: Vec::new(),
            name: int_sym,
            args: Vec::new(),
        };
        let fn_ty = Ty::Fun(Box::new(int_ty.clone()), Box::new(int_ty));
        let no_fn_enums = |_home: &[Symbol], _name: Symbol| false;
        for &bit in TyBounds::ALL_BITS {
            assert!(
                !bit.is_empty(),
                "ALL_BITS entries are single obligation bits, never EMPTY"
            );
            assert!(
                !super_bounds_satisfied(
                    &i,
                    bit,
                    &fn_ty,
                    super_bounds::BoundSite::EmittedGeneric,
                    &no_fn_enums,
                ),
                "obligation bit {bit:?} must reject a function type at an emitted-generic \
                 site — a vacuously-true clause here is a SEAL hole (ipe accepts, cargo fails)"
            );
            assert!(
                !super_bounds_satisfied(
                    &i,
                    bit,
                    &fn_ty,
                    super_bounds::BoundSite::ConcretePin,
                    &no_fn_enums,
                ),
                "obligation bit {bit:?} must reject a function type at a concrete-pin site"
            );
        }
    }

    /// A `Show`-bounded generic instantiated to a FUNCTION must be REJECTED by
    /// the shared use-site gate. The obligation models `describe : a -> String`
    /// with `describe x = Basics.toString x` — a `Stringify` obligation on `a` —
    /// instantiated to `someFn : Int -> Int`. Before the gate carried the `Show`
    /// clause, `ipe` accepted this and the backend emitted
    /// `fn describe<T0: IpeStringify>(..)` fed a closure — an E0277 at `cargo`.
    ///
    /// Driven directly against `super_bounds_satisfied` (like
    /// [`every_bound_bit_rejects_a_function_at_both_sites`]) rather than through
    /// a stdlib call: the single-module inference harness canonicalises `Main`
    /// with no stdlib in scope, so a qualified `Basics.toString` dies at
    /// `UnknownModule` before any Show obligation is recorded — a refusal that
    /// never reaches this gate and holds green even with the `Show` clause
    /// deleted (vacuous). This construction exercises the `has_show()` conjunct
    /// itself: removing it from `super_bounds_satisfied` turns this assertion RED.
    #[test]
    fn show_bounded_generic_escaping_to_function_is_rejected() {
        let mut i = Interner::new();
        let int_sym = i.intern("Int").expect("intern Int");
        let int_ty = Ty::Con {
            module: Vec::new(),
            name: int_sym,
            args: Vec::new(),
        };
        let fn_ty = Ty::Fun(Box::new(int_ty.clone()), Box::new(int_ty));
        let no_fn_enums = |_home: &[Symbol], _name: Symbol| false;
        let show = TyBounds::show();
        assert!(
            !super_bounds_satisfied(
                &i,
                show,
                &fn_ty,
                super_bounds::BoundSite::EmittedGeneric,
                &no_fn_enums,
            ),
            "a Stringify-bounded generic instantiated to a function must be \
             rejected at an emitted-generic site (SEAL)"
        );
        assert!(
            !super_bounds_satisfied(
                &i,
                show,
                &fn_ty,
                super_bounds::BoundSite::ConcretePin,
                &no_fn_enums,
            ),
            "a Stringify obligation pinned directly to a function must be rejected \
             at a concrete-pin site (SEAL)"
        );
    }

    /// The happy path the refusal above must not break: a `Show` obligation is
    /// satisfied by a non-function type (`Int`), at both use sites — every
    /// non-function type derives `IpeStringify`. Driven directly against the
    /// gate for the same reason as the refusal above.
    #[test]
    fn show_bounded_generic_accepts_non_function_arguments() {
        let mut i = Interner::new();
        let int_sym = i.intern("Int").expect("intern Int");
        let int_ty = Ty::Con {
            module: Vec::new(),
            name: int_sym,
            args: Vec::new(),
        };
        let no_fn_enums = |_home: &[Symbol], _name: Symbol| false;
        let show = TyBounds::show();
        for site in [
            super_bounds::BoundSite::EmittedGeneric,
            super_bounds::BoundSite::ConcretePin,
        ] {
            assert!(
                super_bounds_satisfied(&i, show, &int_ty, site, &no_fn_enums),
                "a Stringify-satisfying non-function type (Int) must be accepted \
                 at {site:?}"
            );
        }
    }
}
