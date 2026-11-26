//! Constraint generation, ported from the relevant arms of
//! `Ipe.Type.Constrain.Expression` (derivative of elm/compiler's
//! `Type.Constrain.Expression`, BSD-3-Clause).
//!
//! Walks the canonical module, minting a union-find variable for each
//! sub-expression region and emitting equality [`Constraint`]s that the solver
//! discharges. The arms modelled are exactly those the golden program
//! exercises: integer literals, `VarLocal` / `VarTopLevel` / `VarKernel` /
//! `VarCtor` references, function application (`Call`), `case`, and the binary
//! operators `+` / `-`.
//!
//! This module also owns the two bridges between the resolved [`Ty`] level and
//! the solver level: [`Builder::instantiate`] (a [`Ty`] → fresh union-find
//! structure) and [`Builder::zonk`] (a settled union-find variable → [`Ty`]).

pub use crate::doc::{VarNamer, canon_type_to_doc, ty_to_doc};
pub use crate::solve::{Budget, Constraint};
pub use crate::ty::{
    Content, FlatType, RowTail, Ty, TyBounds, from_canon, is_solver_var, tag_solver_var,
};
pub use crate::unify::unify;
pub use crate::unionfind::{UnionFind, VarId};
pub use ipe_canon::ast as canon;
pub use ipe_diagnostics::{DResult, Diagnostic, Feature, LowerError, Span, TypeError};
pub use ipe_intern::{Interner, Symbol};
pub use ipe_kernels::{BuiltinTag, FieldTag, RowTailShape, SchemeKey, StdlibKernel, TyShape};
pub use std::cell::RefCell;
pub use std::collections::{BTreeMap, BTreeSet};
pub use std::rc::Rc;

/// `where_` tag for any `CompilerBug` raised during constraint generation.
pub const STAGE: &str = "ipe_types::constrain";

/// Recursively replace every `Ty::Var(v)` where `v` resolves to the `"any"`
/// wildcard AND `v` is NOT one of the union's declared type parameters with
/// `Dict String String` — the concrete pub/sub wire carrier.
///
/// Mirrors the reference's `any`-wildcard semantics for union-ctor field types:
/// the the compiler/the backend carries `any` payloads as dynamic `interface{}`; the
/// Rust backend pins them to `Dict String String`, the sole concrete carrier that
/// satisfies `Clone + Debug + PartialEq + Serialize + DeserializeOwned`.
pub fn pin_any_in_ty(
    ty: Ty,
    union_vars: &[Symbol],
    interner: &Interner,
    dict: Symbol,
    string: Symbol,
) -> Ty {
    match ty {
        Ty::Var(v) => {
            let is_any = interner
                .resolve(Symbol::from_raw(v))
                .is_some_and(|n| n == "any");
            let is_declared = union_vars.iter().any(|uv| uv.as_raw() == v);
            if is_any && !is_declared {
                let mk_str = || Ty::Con {
                    module: Vec::new(),
                    name: string,
                    args: Vec::new(),
                };
                Ty::Con {
                    module: Vec::new(),
                    name: dict,
                    args: vec![mk_str(), mk_str()],
                }
            } else {
                Ty::Var(v)
            }
        }
        Ty::Fun(a, b) => Ty::Fun(
            Box::new(pin_any_in_ty(*a, union_vars, interner, dict, string)),
            Box::new(pin_any_in_ty(*b, union_vars, interner, dict, string)),
        ),
        Ty::Con { module, name, args } => Ty::Con {
            module,
            name,
            args: args
                .into_iter()
                .map(|a| pin_any_in_ty(a, union_vars, interner, dict, string))
                .collect(),
        },
        Ty::Unit => Ty::Unit,
        Ty::Tuple(elems) => Ty::Tuple(
            elems
                .into_iter()
                .map(|e| pin_any_in_ty(e, union_vars, interner, dict, string))
                .collect(),
        ),
        Ty::Record(fields, tail) => Ty::Record(
            fields
                .into_iter()
                .map(|(k, v)| (k, pin_any_in_ty(v, union_vars, interner, dict, string)))
                .collect(),
            tail,
        ),
    }
}

/// Per-binding polymorphic-variable entry: maps `(home_module, def_name)` to
/// the annotation-variable → rigid-VarId map for that definition.
///
/// Used in [`Builder::typed_rigids`] and re-exported via [`Generated::typed_rigids`]
/// so `SolvedTypes::poly_var_map` can build the lowerer's generic-variable lookup.
pub type PolyVarEntry = ((Vec<Symbol>, Symbol), BTreeMap<Symbol, VarId>);

/// The wildcard `any` occurrences of one typed binding's own checked signature.
///
/// `wildcards` lists the fresh flex of each occurrence in signature order
/// (parameters left to right, then the return), each walked pre-order by
/// [`Builder::instantiate_in`]. `param_counts` splits that list by parameter:
/// the lowerer mints one generic per parameter occurrence and pairs them by
/// index, so the per-parameter counts are what it asserts agreement against.
#[derive(Clone, Debug)]
pub struct WildcardEntry {
    /// The binding's `(home, name)`.
    pub key: (Vec<Symbol>, Symbol),
    /// The fresh flex of each wildcard occurrence, in signature order.
    pub wildcards: Vec<VarId>,
    /// How many leading entries of `wildcards` each parameter contributes, in
    /// parameter order; the return's occurrences follow.
    pub param_counts: Vec<usize>,
    /// Whether each parameter's whole annotation is the bare wildcard `any`,
    /// in parameter order (parallel to `param_counts`).
    pub bare_params: Vec<bool>,
    /// The binding name's span, for blame on a wildcard that cannot stay one.
    pub span: Span,
}

/// Maximum number of nodes [`zonk`] reads back from a single type before
/// declaring it pathologically deep. The occurs check in unification rules out
/// true cycles, so this bound is only ever hit on adversarial input.
///
/// Kept deliberately **well under** the native-stack ceiling (a few thousand,
/// not the previous 100 000): the [`Ty`] this produces is then walked
/// recursively by the renderer ([`crate::doc::ty_to_doc`]), so capping the node
/// count here keeps that downstream recursion provably stack-safe. The
/// read-back itself is iterative (an explicit work stack), so it never grows the
/// native stack regardless of the bound.
pub const ZONK_NODE_LIMIT: u32 = 4_096;

/// The constraint-generation state threaded through the walk.
pub struct Builder<'a> {
    pub uf: &'a mut UnionFind<Content>,
    pub interner: &'a Interner,
    pub builtins: Builtins,
    /// Resolved type per source region, keyed by `(home_module_path, Span)`.
    ///
    /// The home path discriminant prevents span collisions after `link::link`
    /// merges N source modules into a single flat def list: two different files
    /// may independently contain expressions at the same byte-offset span.  The
    /// bare-`Span` key (pre-fix) silently overwrote earlier entries, causing the
    /// lowerer to read the wrong type and produce IPE-I0001.
    pub regions: BTreeMap<(Vec<Symbol>, Span), VarId>,
    /// The type EXPECTED at each source region by its surrounding context,
    /// keyed by `(home_module_path, Span)` — the type-directed-completion
    /// sidecar (ADR 0007 / LSP plan §6). Where [`Self::regions`] records the
    /// type an expression WAS inferred to have, this records the type its
    /// enclosing context PUSHES DOWN onto it: a `Call` argument's declared
    /// parameter slot, a typed def body's annotation return, an `if` branch's
    /// shared result, a `let` binding's pattern, a list/cons element. Recording
    /// an already-created solver variable is a pure map insert — it adds NO
    /// constraint and NO variable, so `SolvedTypes`'s existing fields are
    /// byte-identical whether or not this map is populated (additivity proven
    /// by `expected_types_additive` in `lib.rs`). Only positions with a genuine
    /// contextual expectation appear; an unconstrained position (a bare
    /// top-level body, a lambda not in an annotated context) is absent, and the
    /// completion provider degrades to scope-only ranking there.
    pub expected: BTreeMap<(Vec<Symbol>, Span), VarId>,
    /// Home module path of the def currently being constrained.  Set at the
    /// start of each `constrain_def` call; read by every `regions.insert`.
    pub current_home: Vec<Symbol>,
    /// Equality constraints to be discharged by the solver.
    pub constraints: Vec<Constraint>,
    /// Annotation-derived types of every top-level binding, for cross-binding
    /// references (`main` mentions `update`).
    ///
    /// Keyed by `(home_module_path, bare_name)` — not bare `Symbol` alone — so
    /// same-named defs from different modules (e.g. `Lib.helper` and
    /// `Main.helper`) never overwrite each other after `link::link` merges them
    /// into one flat def list.  Every `VarTopLevel { module, name }` reference
    /// looks up its home module's entry, not an entry that may belong to a
    /// different module that happens to share the bare name.
    /// Values are `Rc` so a typed top-level reference clones a refcount, not
    /// the whole annotation `Ty` tree (efficiency-audit §2/§7 medium).
    /// `instantiate_tracked` only reads the scheme; resolved types are
    /// byte-identical. Single-threaded solver → `Rc` suffices.
    pub top_level: BTreeMap<(Vec<Symbol>, Symbol), Rc<Ty>>,
    /// Body region-var of each untyped top-level binding, read back for `env`.
    ///
    /// Keyed by `(home_module_path, bare_name)` for the same reason as
    /// [`Self::top_level`].
    pub untyped: BTreeMap<(Vec<Symbol>, Symbol), VarId>,
    /// Deferred record field-access obligations, resolved after the main solve.
    pub field_accesses: Vec<FieldAccess>,
    /// Deferred record-update obligations, resolved after the main solve.
    pub record_updates: Vec<RecordUpdate>,
    /// Deferred routed-Web.tea type checks, resolved after the main solve.
    pub routed_web_checks: Vec<RoutedWebCheck>,
    /// Deferred per-route page-witness checks (one per `Web.route` reference),
    /// resolved after the main solve, BEFORE the routed-Web.tea checks.
    pub route_witness_checks: Vec<RouteWitnessCheck>,
    /// Body result var of every typed top-level binding whose RETURN annotation
    /// is the bare wildcard `any`. Keyed by `(home_module_path, bare_name)`.
    /// A wildcard `any` return severs the body's settled type from every use
    /// site (each occurrence instantiates its own fresh flex); this map is the
    /// handle [`Self::tie_wildcard_any_uses_to_bodies`] uses to re-connect them.
    pub wildcard_any_return_bodies: BTreeMap<(Vec<Symbol>, Symbol), VarId>,
    /// Names of typed bindings whose RETURN annotation is the bare wildcard
    /// `any`, recorded in the registration pass. Each reference to one of these
    /// (in [`Self::constrain_var_top_level`]) records a use tie so its body can
    /// flow to the use site.
    pub wildcard_any_return_bindings: BTreeSet<(Vec<Symbol>, Symbol)>,
    /// One entry per reference to a wildcard-`any`-return binding: the use's
    /// instantiated arrow var + the binding it references. Tied to the binding's
    /// body by [`Self::tie_wildcard_any_uses_to_bodies`] once every def is
    /// constrained.
    pub wildcard_any_use_results: Vec<(VarId, (Vec<Symbol>, Symbol))>,
    /// The type scheme of every data constructor in the program, keyed by the
    /// constructor's fully-qualified identity `(home, type_name, name)` — the
    /// declaring module path, its type, and the constructor name. A constructor
    /// is a (possibly generic) function `field0 -> … -> fieldN -> T vars`; each
    /// use site instantiates the scheme fresh, exactly as a polymorphic
    /// top-level binding does.
    ///
    /// The key is qualified, not the bare name, because after `link::link`
    /// merges every module into one program two modules may each declare a
    /// same-named constructor (a user `type X = Compare Int` beside
    /// `Ipe.Db.Store`'s own `type Cond = Compare CompareOp String SqlValue`). A
    /// bare-name key silently overwrote one with the other, so a module's own
    /// pattern resolved against the foreign constructor's arity (IPE-T0013
    /// blamed on stdlib internals). Canon already resolves each `PCtor` /
    /// `VarCtor` to its declaring `home` + `type_name`; keying by that identity
    /// keeps the two distinct constructors distinct.
    ///
    /// Each value is an `Rc` so per-use-site instantiation clones a refcount,
    /// not the whole scheme (efficiency-audit §2 medium: the constructor-ref /
    /// ctor-pattern checks deep-cloned the full `CtorScheme` per use to
    /// release the `&self` borrow before the `&mut self` instantiate call).
    /// The `Rc` holds byte-identical data — same fresh vars, same constraints,
    /// same errors. Fully internal to `Builder`.
    pub ctors: BTreeMap<CtorKey, Rc<CtorScheme>>,
    /// One entry per typed binding: its `(home, name)` and the rigid (skolem)
    /// variable each of its annotation type variables instantiated to while its
    /// body was checked. Read post-solve to recover each variable's super-type
    /// obligations (the bounds the body imposed) for generalisation, and to build
    /// `SolvedTypes::poly_var_map` (the per-binding generic-variable map the
    /// lowerer uses to distinguish enclosing-generic `Ty::Var`s from
    /// message-free `Ty::Var`s inside UI attribute lists).
    pub typed_rigids: Vec<PolyVarEntry>,
    /// One entry per *reference* to a typed top-level binding (each `VarTopLevel`
    /// use site), recording how that use instantiated the binding's scheme. Used
    /// post-solve to check a super-typed binding's obligations against the
    /// concrete type each use pins it to.
    pub scheme_apps: Vec<SchemeApp>,
    /// Every super-typed flex variable minted by a numeric / ordering / equality
    /// operator, paired with the obligations it was minted with and the operand
    /// span to blame. Read post-solve for two jobs: numeric defaulting (an
    /// unpinned `Number` variable resolves to `Int`, matching the reference
    /// compiler's defaulting of an otherwise-unconstrained `number`) and the
    /// concrete-pin soundness gate (a variable that pinned to a concrete type
    /// during solving must be one the operation truly supports — an equality
    /// obligation rejects a type containing a function, which Rust cannot
    /// compare, with IPE-T0014 rather than emitting code `cargo` rejects).
    ///
    /// The `home` is the module path of the def the operator lives in
    /// (`current_home` at mint time). A post-solve obligation failure
    /// (`super_unsatisfied`) attributes to this home DIRECTLY, so a
    /// kernel/operator-synthesized obligation error frames against its own
    /// source file rather than falling into the byte-offset heuristic — which
    /// can pick a wrong, order-unstable file for a cross-module program (the
    /// IPE-T0014/T0001 span-collision class).
    pub super_vars: Vec<(VarId, TyBounds, Span, Vec<Symbol>)>,
    /// The fresh flex of every wildcard `any` occurrence in a typed binding's
    /// OWN checked signature. Each is a generic parameter of that binding (the
    /// lowerer emits it as a bounded type parameter, and each use site
    /// instantiates its own copy), so the interpolation default never pins one: a
    /// default would rewrite the definition's type while every caller's
    /// instantiation already settled on its own concrete argument.
    pub signature_wildcards: Vec<VarId>,
    /// The fresh flex of every wildcard `any` occurrence in each typed binding's
    /// OWN checked signature, in signature order, keyed by `(home, name)`. A
    /// wildcard the body obligates (`"${x}"` with `x : any`) is a bounded generic
    /// parameter of the emitted function exactly like a named variable, so its
    /// obligation is recorded under the unforgeable key `any#<i>` and every use
    /// site checks the type its own `i`-th wildcard occurrence settled on
    /// ([`SchemeApp::wildcards`]).
    pub typed_wildcards: Vec<WildcardEntry>,
    /// While `Some`, [`Builder::instantiate_in`] appends each wildcard `any`
    /// occurrence's fresh flex here, in traversal order. Scoped to exactly one
    /// signature instantiation by [`Builder::instantiate_logging_wildcards`].
    pub wildcard_log: Option<Vec<VarId>>,
    /// One entry per *cross-module* reference to an untyped top-level binding
    /// (`Builder::current_home != source.0`). A same-module reference keeps
    /// sharing `untyped[key]` directly (unchanged monomorphic-within-module
    /// behaviour); a cross-module reference instead gets its own isolated
    /// placeholder here, discharged post-solve by `promote_untyped_boundaries`
    /// against the source binding's *generalized* scheme — see the "Boundary
    /// Scheme Promotion" design at
    /// `docs/adr/0001-language-semantics-and-types.md`.
    pub pending_instantiations: Vec<PendingInstantiation>,
    /// Per-kernel memo of [`Builder::resolve_scheme`]. A kernel's scheme is a
    /// pure function of the interned built-in names (fixed for the builder's
    /// lifetime), so it is materialised at most once and cloned on subsequent
    /// references instead of rebuilding the whole scheme `Ty` tree per use site.
    /// Indexed by `StdlibKernel as usize`.
    pub scheme_cache: RefCell<Vec<SchemeSlot>>,
}

/// One entry of [`Builder::scheme_cache`]: either not yet resolved, or resolved
/// to the same `Option<Ty>` [`Builder::resolve_scheme`] returns (a `None`
/// mirroring its fail-closed miss).
#[derive(Clone)]
pub enum SchemeSlot {
    Unresolved,
    Resolved(Option<Ty>),
}

/// A cross-module reference to an untyped top-level binding, recorded during
/// constraint generation. `placeholder` is a fresh, isolated `Flex` var minted
/// at the reference site (instead of sharing the binding's program-wide var);
/// the post-solve `promote_untyped_boundaries` pass unifies it with a fresh
/// instantiation of the source binding's generalized scheme, once that scheme
/// exists (source module precedes `use_home` in topo order).
pub struct PendingInstantiation {
    /// The referenced binding's `(home, name)`.
    pub source: (Vec<Symbol>, Symbol),
    /// The fresh, isolated `Flex` var minted at the reference site.
    pub placeholder: VarId,
    /// The module that owns the reference (for blame attribution).
    pub use_home: Vec<Symbol>,
    /// The reference's source span (for blame attribution).
    pub span: Span,
}

/// A single use site of a typed top-level binding.
///
/// At each reference the binding's scheme is instantiated into fresh variables
/// (the [`Builder::instantiate`] / `CForeign` path). `vars` records, for each of
/// the scheme's type variables (keyed by the annotation variable's raw symbol
/// id), the fresh union-find variable it instantiated to — so once the solver
/// settles, the concrete type this use pinned each variable to can be read back
/// and checked against the binding's super-type obligations.
pub struct SchemeApp {
    /// The referenced binding's HOME module path (AUD-05 seal fix) — paired
    /// with `name` so the use-site soundness check
    /// ([`super::check_scheme_applications`]) looks up the bound set of the
    /// binding actually referenced, not a same-named binding from a different
    /// module (matches the `(home, name)` key shape `SolvedTypes::env` /
    /// `SolvedTypes::regions` already use for the identical reason).
    pub home: Vec<Symbol>,
    /// The referenced binding's name.
    pub name: Symbol,
    /// Scheme type-variable raw id → the fresh variable it instantiated to here.
    pub vars: BTreeMap<u32, VarId>,
    /// The fresh flex of each wildcard `any` occurrence of the scheme, in the
    /// same signature order as [`Builder::typed_wildcards`].
    pub wildcards: Vec<VarId>,
    /// The reference's source span, for blame on an unsatisfied bound.
    pub span: Span,
}

/// A constructor's fully-qualified identity: `(home, type_name, name)` — its
/// declaring module path, the union type it belongs to, and its own name.
///
/// This is the key of [`Builder::ctors`]. Two modules that each declare a
/// same-named constructor differ in `home` (and usually `type_name`), so a
/// module's own pattern resolves against its own constructor's scheme rather
/// than a foreign one that merely shares the leaf name. Built from the same
/// `(home, type_name, name)` triple canon records on every `PCtor` / `VarCtor`,
/// so the insert side and the lookup side agree by construction.
pub type CtorKey = (Vec<Symbol>, Symbol, Symbol);

/// A data constructor's quantified type scheme.
///
/// `arg_tys` are the declared payload field types (a nullary constructor has an
/// empty list); `result` is the enum type the constructor builds, applied to the
/// union's type variables (`Maybe a` for `Just`). Both sides share the union's
/// type variables as [`Ty::Var`]s, so instantiating them through one shared map
/// alpha-renames a generic constructor consistently per use site.
#[derive(Clone)]
pub struct CtorScheme {
    pub arg_tys: Vec<Ty>,
    pub result: Ty,
}

/// A deferred record field-access obligation `record.field`.
///
/// Closed records carry no row variable, so a field access cannot be discharged
/// by ordinary unification while the constraints are still being built (the
/// record's type may not be settled yet). Each access is recorded here and
/// resolved once after the main solve, when [`crate::resolve_field_accesses`]
/// can read the now-settled record type and link `result` to the field's type.
pub struct FieldAccess {
    /// The variable of the record sub-expression (`record` in `record.field`).
    pub record: VarId,
    /// The accessed field name.
    pub field: Symbol,
    /// The variable the access's result type was bound to (the access's region).
    pub result: VarId,
    /// The access expression's source span, for blame.
    pub span: Span,
    /// The home module path of the def this access lives in. After `link::link`
    /// merges modules, a bare byte-offset span cannot identify the source file;
    /// the home lets a post-solve error (IPE-T0012) attribute to the correct
    /// module instead of the byte-offset heuristic's best guess (which can pick
    /// a numerically-closer def in a *different* file — the span-collision
    /// class, here surfacing as an `info.message` error blamed on an unrelated
    /// `class` call in another module).
    pub home: Vec<Symbol>,
}

/// A deferred record-update obligation `{ base | field = value, ... }`.
///
/// Like [`FieldAccess`], a closed record carries no row variable, so the
/// updated fields cannot be checked against the base's type while the
/// constraints are still being built. Each update is recorded here and resolved
/// once after the main solve, when [`crate::resolve_record_updates`] reads the
/// settled base type and unifies each updated value against the corresponding
/// field's type (a field absent from the base is a [`crate::TypeError::NoSuchField`]).
pub struct RecordUpdate {
    /// The variable of the base record being copied (`base` in `{ base | … }`).
    pub record: VarId,
    /// The updated `(field name, value variable)` pairs.
    pub fields: Vec<(Symbol, VarId)>,
    /// The update expression's source span, for blame.
    pub span: Span,
    /// The home module path of the def this update lives in — see
    /// [`FieldAccess::home`].
    pub home: Vec<Symbol>,
}

/// A deferred post-solve check for routed `Web.tea` configurations.
///
/// `Web.tea`'s cfg row accepts both routed apps (Model has a `page : Page`
/// field) and non-routed apps (Model has no `page` field) through the same
/// open-record scheme.  The distinction cannot be expressed as a plain HM
/// constraint at build time (a conditional `{ page : var(2) | ρ }` projection
/// would break every non-routed app whose Model has no `page` field).
///
/// Instead, the constrain pass pushes one `RoutedWebCheck` per `Web.tea`
/// call site and defers the gate to [`crate::resolve_routed_web_checks`],
/// which runs after the main solve when the Model type has settled:
///
/// * If Model's settled type has a `page` field → this is a routed app →
///   `notFound`'s type must match `Model.page`'s type (same `var(2)` share).
///   A mismatch produces IPE-T0001 here instead of a cargo E0308 / E0631
///   from the emitted `set_page` closure.
/// * If Model has no `page` field → non-routed → no validation; passes.
pub struct RoutedWebCheck {
    /// `var(0)` from the `K::WebApp` scheme instantiation — the Model type.
    pub model_var: VarId,
    /// `var(2)` from the `K::WebApp` scheme instantiation — the `notFound` type.
    pub not_found_var: VarId,
    /// The `Web.tea { … }` call span; used to blame a type mismatch.
    pub span: Span,
}

/// A deferred per-route page-witness check for `Web.route`.
///
/// `Web.route : String -> builder -> WebRoute page` types its second
/// argument with a variable (`builder`, var(1)) DISTINCT from the result's
/// page variable (`page`, var(0)), because the argument is legitimately either
/// shape:
///
/// * a nullary page VALUE — `Web.route "/" HomePage` (builder : `Page`), or
/// * a params-consuming page CONSTRUCTOR —
///   `Web.route "/apps/:slug" AppDetailPage` (builder : `String -> Page`;
///   multi-`:param` routes curry further: `String -> String -> Page`, …).
///
/// A single shared variable (the pre-round-4 scheme) forced
/// `Page ≟ String -> Page` on every param route — a false IPE-T0001 on the
/// canonical corpus shape.  A plain HM constraint cannot express the
/// disjunction, so the constrain pass pushes one `RouteWitnessCheck` per
/// `Web.route` reference and defers it to
/// [`crate::resolve_route_witness_checks`], which runs after the main solve:
///
/// * Follow `builder_var`'s settled structure, peeling leading `_ -> rest`
///   arrows (each arrow is one `:param` payload slot; the emit tier separately
///   gates the payload types to `String`/`Int`/`Float`/`Bool`).
/// * Unify what remains — the built PAGE type — with `page_var`.
///
/// A nullary route therefore witnesses `page` directly, a param constructor
/// witnesses it with its result type, and a wrong-ADT constructor
/// (`Web.route "/" Increment` in a `Page`-routed app) still fails unification
/// with IPE-T0001 at this route's span.  Runs BEFORE
/// [`crate::resolve_routed_web_checks`] so route constructors pin the page
/// variable before the `notFound ≟ Model.page` gate reads it.
pub struct RouteWitnessCheck {
    /// `var(1)` from the `K::WebRoute` scheme instantiation — the route's
    /// page-builder argument type.
    pub builder_var: VarId,
    /// `var(0)` from the `K::WebRoute` scheme instantiation — the page type
    /// carried by the resulting `WebRoute page`.
    pub page_var: VarId,
    /// The `Web.route` reference span; used to blame a type mismatch.
    pub span: Span,
}

/// The output of constraint generation, consumed by the solver + read-back.
pub struct Generated {
    /// Resolved type per source region, keyed by `(home_module_path, Span)`.
    /// See [`Builder::regions`] for the rationale.
    pub regions: BTreeMap<(Vec<Symbol>, Span), VarId>,
    /// Contextually-EXPECTED type per source region — the type-directed
    /// completion sidecar. See [`Builder::expected`]. Read back into
    /// `SolvedTypes::expected` and never consulted by the solver, so it is
    /// purely additive over the existing inference result.
    pub expected: BTreeMap<(Vec<Symbol>, Span), VarId>,
    pub constraints: Vec<Constraint>,
    /// Values stay behind the builder's `Rc`; the read-back (`lib.rs`) unwraps
    /// them into the public `SolvedTypes::env` shape (refcount is 1 by then —
    /// every per-reference clone is transient inside constraint generation).
    pub top_level: BTreeMap<(Vec<Symbol>, Symbol), Rc<Ty>>,
    pub untyped: BTreeMap<(Vec<Symbol>, Symbol), VarId>,
    pub field_accesses: Vec<FieldAccess>,
    pub record_updates: Vec<RecordUpdate>,
    /// Deferred routed-Web.tea checks, resolved after the main solve.
    pub routed_web_checks: Vec<RoutedWebCheck>,
    /// Deferred per-route page-witness checks, resolved after the main solve
    /// (before `routed_web_checks`).
    pub route_witness_checks: Vec<RouteWitnessCheck>,
    pub typed_rigids: Vec<PolyVarEntry>,
    pub scheme_apps: Vec<SchemeApp>,
    pub super_vars: Vec<(VarId, TyBounds, Span, Vec<Symbol>)>,
    /// The fresh flex of every wildcard `any` occurrence in a typed binding's
    /// OWN checked signature. Each is a generic parameter of that binding (the
    /// lowerer emits it as a bounded type parameter, and each use site
    /// instantiates its own copy), so the interpolation default never pins one: a
    /// default would rewrite the definition's type while every caller's
    /// instantiation already settled on its own concrete argument.
    pub signature_wildcards: Vec<VarId>,
    /// The fresh flex of every wildcard `any` occurrence in each typed binding's
    /// OWN checked signature, in signature order, keyed by `(home, name)`. A
    /// wildcard the body obligates (`"${x}"` with `x : any`) is a bounded generic
    /// parameter of the emitted function exactly like a named variable, so its
    /// obligation is recorded under the unforgeable key `any#<i>` and every use
    /// site checks the type its own `i`-th wildcard occurrence settled on
    /// ([`SchemeApp::wildcards`]).
    pub typed_wildcards: Vec<WildcardEntry>,
    /// Every cross-module untyped-binding reference recorded during
    /// constraint generation. See [`PendingInstantiation`].
    pub pending_instantiations: Vec<PendingInstantiation>,
    /// Every distinct module home reachable in the linked program, in
    /// first-encounter order over `module.defs` — which is itself
    /// dependency-first topo order, since `link::link` concatenates each
    /// source module's whole def list in the caller-supplied topo order (see
    /// `ipe_canon::link` and `ipe::project::topological_order`). Consumed by
    /// `promote_untyped_boundaries` to discharge/generalize each module's
    /// untyped defs only after every module it depends on has already been
    /// generalized.
    pub module_order: Vec<Vec<Symbol>>,
}

mod builder_core;
mod builtins;
mod constrain_ast;
mod constrain_expr;
mod constrain_pattern;
mod normalize_ty;
mod scheme_table;
#[cfg(test)]
mod tests;
mod zonk;

pub use builtins::*;
pub use zonk::*;
