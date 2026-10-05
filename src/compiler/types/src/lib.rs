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
mod homed;
mod pairing;
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
use ipe_diagnostics::{DResult, Diagnostic, LowerError, Span, TypeError, WildcardDependence};
use ipe_intern::{Interner, Symbol};

pub use constrain::{Builtins, kernel_type_table, resolve_scheme};
pub use doc::{VarNamer, canon_type_to_doc, letters, ty_to_doc};
pub use homed::{HomedWarning, InferError, ModuleHome, ProgramDiag};
pub use pairing::{ArgPairs, ConHead, EmittedHeads, HeadIdentity, TyPairs, paired_ty_children};
pub use solve::{BUDGET_ENV, Budget, DEFAULT_SOLVER_BUDGET};
pub use ty::{
    RETRY_POLICY_FIELDS, RowTail, SolverVar, Ty, TyBounds, VarCeiling, is_solver_var,
    tag_solver_var,
};

use constrain::{
    Builder, FieldAccess, RecordUpdate, RouteWitnessCheck, RoutedWebCheck, SchemeApp, SuperVar,
    promote_untyped_boundaries, reify_scheme, zonk,
};
use solve::solve_attributed;
use ty::{Content, FlatType};
pub use unify::con_heads_compatible;
use unify::{occurs_guard, super_admits_record, unify_at};
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
    /// `RedundantCaseBranch`, IPE-L0124), each paired with its owning module.
    ///
    /// A [`HomedWarning`] is Warning-severity and homed by construction: callers
    /// MUST print each against the source file of its [`HomedWarning::home`] and
    /// MUST NOT treat it as a compilation failure. A finding of any other
    /// severity is refused at construction and returned as the inference error,
    /// so a `SolvedTypes` witnesses a program that compiles.
    pub warnings: Vec<HomedWarning>,
    /// Per-binding map from solver-tagged union-find representative to
    /// annotation variable symbol, keyed by `(home, def_name)`.
    ///
    /// After solving, every annotation type variable for a `Def::Typed` binding
    /// is represented as a `Ty::Var(u32)` in the zonked region types, where the
    /// `u32` is [`tag_solver_var`] of the union-find representative of the
    /// rigid (skolem) that was used while checking the binding's body.  Every
    /// key is in that tagged form, for typed and boundary-promoted untyped
    /// bindings alike, so a lookup is exact: an untagged raw is an annotation
    /// symbol and never names a key.  This map records that
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
    pub poly_var_map: BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<SolverVar, Symbol>>,
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
    /// The solved wildcard `any` facts of each typed binding whose own
    /// signature has at least one wildcard, keyed by `(home, def_name)`. The
    /// wildcards' body obligations live in [`Self::bounds`] under the
    /// `any#<i>` keys ([`wildcard_bound_index`]); this carries the rest the
    /// lowerer needs to lower wildcard `i` exactly as the checker did.
    pub signature_wildcards: BTreeMap<(Vec<Symbol>, Symbol), SignatureWildcards>,
}

/// The solved wildcard `any` facts of one typed binding's own signature.
///
/// Index `i` names the binding's `i`-th wildcard occurrence in signature order
/// (parameters left to right, each walked pre-order, then the return) — the
/// same order every use site instantiates ([`TypedScheme::wildcard_pins`]) and
/// the bounds table's `any#<i>` keys count.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SignatureWildcards {
    /// Wildcard occurrences each parameter contributes, in parameter order.
    /// The lowerer mints its per-occurrence generics per parameter and asserts
    /// these counts before pairing its `k`-th mint with wildcard `k`.
    pub param_counts: Vec<usize>,
    /// Parameter wildcard index → the ground type the body pinned it to
    /// ([`ty_is_ground`]). A pinned wildcard lowers to that concrete type, so
    /// every use must instantiate it at exactly that type.
    pub pins: BTreeMap<usize, Ty>,
}

/// Which solver variables a renumbering treats as one variable.
///
/// A solver variable's raw id is only meaningful inside the solve that
/// minted it, so the same raw in two modules' slices names two variables
/// unless those slices came from one joint solve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VarScope {
    /// One raw id is one variable across every module: the joint solve's
    /// numbering, where a variable shared by two modules stays one variable.
    Program,
    /// One raw id is one variable only within its owning module: slices that
    /// were solved separately and merged, so equal raws in different modules
    /// are distinct variables.
    PerHome,
}

/// A renumbering ran out of ids below its [`VarCeiling`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CanonicalizeError {
    /// More distinct solver variables than the ceiling admits.
    VarSpaceExhausted,
}

/// A [`SolvedTypes`] in canonical form.
///
/// Its solver variables are densely numbered in the first-encounter order of
/// [`canonicalize`] and its warnings are in canonical order. Built only by
/// [`canonicalize`], so two producers of the same typed program that both pass
/// through it agree byte for byte.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CanonicalTypes(SolvedTypes);

impl CanonicalTypes {
    /// The canonical typed program.
    #[must_use]
    pub const fn as_solved(&self) -> &SolvedTypes {
        &self.0
    }
}

impl std::ops::Deref for CanonicalTypes {
    type Target = SolvedTypes;

    fn deref(&self) -> &SolvedTypes {
        &self.0
    }
}

/// Dense ids for the solver variables of one typed program.
///
/// The one walker over every position that holds a solver-variable id: `Ty`
/// values and the `poly_var_map` keys are renumbered through the same table.
struct Renumbering {
    scope: VarScope,
    ceiling: VarCeiling,
    /// Dense index of each owning-module key; under [`VarScope::Program`]
    /// every module shares the one empty key.
    homes: BTreeMap<Vec<Symbol>, u32>,
    /// The dense variable assigned to each `(home index, original variable)`.
    assigned: BTreeMap<(u32, SolverVar), SolverVar>,
}

impl Renumbering {
    const fn new(scope: VarScope, ceiling: VarCeiling) -> Self {
        Self {
            scope,
            ceiling,
            homes: BTreeMap::new(),
            assigned: BTreeMap::new(),
        }
    }

    /// The dense index of the module owning a key.
    fn home(&mut self, home: &[Symbol]) -> Result<u32, CanonicalizeError> {
        let key: &[Symbol] = match self.scope {
            VarScope::Program => &[],
            VarScope::PerHome => home,
        };
        if let Some(&index) = self.homes.get(key) {
            return Ok(index);
        }
        let index =
            u32::try_from(self.homes.len()).map_err(|_| CanonicalizeError::VarSpaceExhausted)?;
        self.homes.insert(key.to_vec(), index);
        Ok(index)
    }

    /// The dense variable for `var` in module `home`, minting the next id on first sight.
    fn var(&mut self, home: u32, var: SolverVar) -> Result<SolverVar, CanonicalizeError> {
        if let Some(&dense) = self.assigned.get(&(home, var)) {
            return Ok(dense);
        }
        let next =
            u32::try_from(self.assigned.len()).map_err(|_| CanonicalizeError::VarSpaceExhausted)?;
        if next >= self.ceiling.get() {
            return Err(CanonicalizeError::VarSpaceExhausted);
        }
        let dense = SolverVar::from_var(next);
        self.assigned.insert((home, var), dense);
        Ok(dense)
    }

    /// A raw id from the [`Ty::Var`] id space.
    ///
    /// A solver variable is renumbered; an annotation-symbol raw is kept.
    fn raw(&mut self, home: u32, raw: u32) -> Result<u32, CanonicalizeError> {
        let Some(var) = SolverVar::from_raw(raw) else {
            return Ok(raw);
        };
        Ok(self.var(home, var)?.raw())
    }

    /// Renumber every solver variable of `ty` in place, in pre-order.
    fn ty(&mut self, home: u32, ty: &mut Ty) -> Result<(), CanonicalizeError> {
        match ty {
            Ty::Var(raw) => *raw = self.raw(home, *raw)?,
            Ty::Unit => {}
            Ty::Fun(arg, result) => {
                self.ty(home, arg)?;
                self.ty(home, result)?;
            }
            Ty::Tuple(elems) => {
                for elem in elems {
                    self.ty(home, elem)?;
                }
            }
            Ty::Record(fields, tail) => {
                for field in fields.values_mut() {
                    self.ty(home, field)?;
                }
                match tail {
                    RowTail::Closed => {}
                    RowTail::Open(raw) => *raw = self.raw(home, *raw)?,
                }
            }
            Ty::Con {
                module: _,
                name: _,
                args,
            } => {
                for arg in args {
                    self.ty(home, arg)?;
                }
            }
        }
        Ok(())
    }

    /// Renumber in place every `Ty` value of a map keyed by `(home, _)`.
    fn ty_map<K>(
        &mut self,
        map: &mut BTreeMap<(Vec<Symbol>, K), Ty>,
    ) -> Result<(), CanonicalizeError> {
        for ((home, _), ty) in map {
            let home = self.home(home)?;
            self.ty(home, ty)?;
        }
        Ok(())
    }
}

/// The canonical order of warnings: owning module, then span, then code.
fn sort_warnings(mut warnings: Vec<HomedWarning>) -> Vec<HomedWarning> {
    fn key(warning: &HomedWarning) -> (&[Symbol], u32, u32, &'static str) {
        let span = warning.diagnostic().primary_span();
        (
            warning.home(),
            span.lo,
            span.hi,
            warning.diagnostic().code().as_str(),
        )
    }
    warnings.sort_by(|a, b| key(a).cmp(&key(b)));
    warnings
}

/// Put a typed program into canonical form.
///
/// Solver variables are renumbered densely from 0 in first-encounter order
/// over a fixed traversal: `env`, `regions`, `expected`, the
/// `signature_wildcards` pins, then the `poly_var_map` keys, each in map
/// order. The `Ty` values and the `poly_var_map` keys share one table, so a
/// generic keyed in `poly_var_map` stays the variable its region types name.
/// Only solver-tagged raws are renumbered; an untagged raw is an annotation
/// symbol and is kept. Warnings are put in canonical order.
///
/// `scope` decides whether equal raws in different modules are one variable
/// ([`VarScope::Program`]) or two ([`VarScope::PerHome`]); a program in which
/// a variable is shared between modules numbers differently under the two.
///
/// # Errors
/// [`CanonicalizeError::VarSpaceExhausted`] when the program holds more
/// distinct solver variables than `ceiling` admits. The count never
/// saturates, so no two variables ever share an id.
pub fn canonicalize(
    types: SolvedTypes,
    scope: VarScope,
    ceiling: VarCeiling,
) -> Result<CanonicalTypes, CanonicalizeError> {
    let SolvedTypes {
        mut env,
        mut regions,
        mut expected,
        bounds,
        warnings,
        mut poly_var_map,
        untyped_type_params,
        msg_defaulted_vars,
        mut signature_wildcards,
    } = types;
    let mut table = Renumbering::new(scope, ceiling);
    table.ty_map(&mut env)?;
    table.ty_map(&mut regions)?;
    table.ty_map(&mut expected)?;
    for ((home, _), wildcards) in &mut signature_wildcards {
        let SignatureWildcards {
            param_counts: _,
            pins,
        } = wildcards;
        let home = table.home(home)?;
        for pin in pins.values_mut() {
            table.ty(home, pin)?;
        }
    }
    for ((home, _), vars) in &mut poly_var_map {
        let home = table.home(home)?;
        // Injective per home, so no two keys collapse into one entry.
        *vars = std::mem::take(vars)
            .into_iter()
            .map(|(var, name)| -> Result<_, CanonicalizeError> {
                Ok((table.var(home, var)?, name))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
    }
    Ok(CanonicalTypes(SolvedTypes {
        env,
        regions,
        expected,
        bounds,
        warnings: sort_warnings(warnings),
        poly_var_map,
        untyped_type_params,
        msg_defaulted_vars,
        signature_wildcards,
    }))
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

/// Like [`infer`] but every error names the module that owns it.
///
/// In a linked multi-module program spans are byte offsets every module
/// shares, so a span alone cannot name its file. A source error comes back as
/// [`InferError::Sited`] with its owning module; only an internal or
/// whole-program diagnostic comes back as [`InferError::Program`]. Every
/// warning in the result carries its home ([`HomedWarning`]).
///
/// # Errors
/// Same conditions as [`infer`], each paired with its owning module when it
/// has one.
pub fn infer_attributed(
    m: &canon::Module,
    interner: &mut Interner,
) -> Result<SolvedTypes, InferError> {
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
    /// Parameter wildcard index → the ground type the binding's body pinned it
    /// to ([`SignatureWildcards::pins`]); a dependent module's use must pass
    /// exactly that type.
    pub wildcard_pins: BTreeMap<usize, Ty>,
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
    /// Every union its dependencies reach, transitively, its own excluded.
    ///
    /// An importer's case-analysis and equality checks meet a union through
    /// any value it reaches, not only through a direct import, so the closure
    /// travels with the interface; `reachable_dep_unions` builds it from the
    /// direct deps alone. Each entry is shared with every other interface
    /// that reaches the same union, so a long import chain holds one copy of
    /// each definition rather than one per importer.
    pub reachable_unions: Vec<Arc<canon::Union>>,
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
    /// Every exported scheme is closed and the module's own solved facts
    /// read no importer's use site: the interface and the module's own
    /// result are both faithful.
    Closed(TypedInterface),
    /// Every exported scheme is closed, so the interface is faithful for
    /// importers, but the module's own solved facts read its importers' use
    /// sites (an exported UI-message slot whose default depends on every
    /// use): only the whole-program solve is faithful for the module itself.
    ImporterDependent(TypedInterface),
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

/// Per-binding wildcard pins, keyed like [`BoundsTable`].
type PinTable = BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<usize, Ty>>;

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
) -> Result<ModuleInference, InferError> {
    let mut budget = Budget::from_env();
    let scoped = ScopedContext { exports, deps };
    let (solved, interface) = infer_core(m, interner, &mut budget, Some(&scoped))?;
    Ok(ModuleInference {
        solved,
        interface: interface.unwrap_or(InterfaceStatus::Open),
    })
}

/// A [`canon::Union`] clone with every span (its own name-token span and every
/// constructor's) erased — interface identity must not depend on where in the
/// file a union sits.
fn erase_union_spans(union: &canon::Union) -> canon::Union {
    canon::Union {
        home: union.home.clone(),
        name: union.name,
        name_span: Span::DUMMY,
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
    infer_with_budget_attributed(m, interner, budget).map_err(InferError::into_diagnostic)
}

/// Like [`infer_with_budget`] but every error names its owning module.
fn infer_with_budget_attributed(
    m: &canon::Module,
    interner: &mut Interner,
    budget: &mut Budget,
) -> Result<SolvedTypes, InferError> {
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
) -> Result<(SolvedTypes, Option<InterfaceStatus>), InferError> {
    // Wrap a `DResult` step that can only fail on an internal invariant (a
    // union-find lookup, an intern, a read-back): its error has no owning
    // module, so a source error reaching it is refused as a compiler bug.
    macro_rules! lift {
        ($e:expr) => {
            $e.map_err(InferError::unsited)?
        };
    }

    let mut uf = UnionFind::new();
    // Dep-interface seeds (scoped solve only): the deps' exported schemes
    // pre-populate the `(home, name)` scheme table, and every union the deps
    // reach transitively is registered alongside the module's own so
    // cross-module constructor references, patterns, equality, and
    // exhaustiveness see full definitions from ONE closure. The union list
    // stays alive past constraint generation — `exhaust::check` reads it below.
    let dep_union_closure: Vec<Arc<canon::Union>> =
        scoped.map_or_else(Vec::new, |ctx| reachable_dep_unions(ctx.deps));
    let dep_unions: Vec<&canon::Union> = dep_union_closure.iter().map(Arc::as_ref).collect();
    // The user enums whose definition embeds a function payload — consulted by
    // every concrete equality / stringify obligation so a `==` / `{{…}}` on a
    // function-carrying enum fails closed (the payload arrow is invisible in a
    // `Ty::Con`'s applied type arguments; see [`fn_embedding_enums`]).
    let fn_enums = fn_embedding_enums(&m.unions, &dep_unions);
    let enum_embeds_fn = |home: &[Symbol], name: Symbol| fn_enums.contains(&(home.to_vec(), name));
    let generated = match scoped {
        None => Builder::run(&mut uf, interner, m)?,
        Some(ctx) => {
            let mut seed: BTreeMap<(Vec<Symbol>, Symbol), Rc<Ty>> = BTreeMap::new();
            for (path, iface) in ctx.deps {
                for (name, scheme) in &iface.values {
                    seed.insert((path.clone(), *name), Rc::new(scheme.ty.clone()));
                }
            }
            Builder::run_seeded(&mut uf, interner, m, &dep_unions, seed)?
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
    // Every error `resolve_deferred` returns is sited at the failing field
    // access's / record update's owning module.
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
    resolve_route_witness_checks(&mut uf, budget, interner, &generated.route_witness_checks)?;

    // Warnings collected during the post-solve deferred passes and the
    // exhaustiveness pass (IPE-L0124, IPE-T0011), each homed at construction.
    // The sink holds only `HomedWarning`s, so an Error-severity finding cannot
    // enter it: the producing pass returns it as the inference error instead.
    let mut warnings: Vec<HomedWarning> = Vec::new();

    // For routed `Web.tea` calls: if the now-settled Model type has a `page`
    // field, the `notFound` type must match that field's type.  Non-routed
    // apps (Model has no `page` field) are silently skipped — UNLESS the app
    // declared a non-empty `routes` list, in which case the routes are ignored
    // and we emit the IPE-L0124 warning (usually a mis-named `page` field). See
    // the `RoutedWebCheck` doc comment for the full rationale.
    let has_routes = !generated.route_witness_checks.is_empty();
    resolve_routed_web_checks(
        &mut uf,
        budget,
        interner,
        &generated.routed_web_checks,
        has_routes,
        generated.route_witness_checks.len(),
        &mut warnings,
    )?;

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
    // Warning and must not abort; IPE-T0018 over a closed union is an Error the
    // pass returns (after scanning every definition). IPE-T0010
    // (non-exhaustive) early-returns `Err` from inside the pass.
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
    // Scoped solve only: whether the module's own solved facts read a use
    // site in an importer, which the scoped solve cannot see.
    let mut own_facts_importer_dependent = false;
    // Scoped solve only: whether `key` is one of this module's exported values
    // (a binding an importer's use sites can reach).
    let exported_by_scoped_module = |key: &(Vec<Symbol>, Symbol)| {
        scoped.is_some_and(|ctx| key.0 == m.name && ctx.exports.values.contains(&key.1))
    };
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
    // Interpolation defaulting: the element variable of a `Log.*With`
    // attribute list the program never pinned (an empty `[]` literal). Left
    // un-defaulted, the lowerer's wildcard-`any` convention would resolve it to
    // `IrType::Json`, which the sealed runtime `IpeInterpolate` trait does not
    // cover; `String` is in the closed interpolable set, so the empty list
    // becomes a concretely-typed `Vec<String>`.
    let string_sym = lift!(interner.intern("String"));
    // A typed binding's own wildcard `any` is a generic parameter (see
    // `Generated::signature_wildcards`): neither the SQL-parameter nor the
    // interpolation default pins its root; the lowerer bounds that generic on
    // its recorded `any#<i>` obligation instead. The numeric default still
    // pins it: a literal merges into the wildcard's flex, and a generic `T`
    // cannot hold an `Int` literal.
    let generic_roots: BTreeSet<VarId> = generated
        .signature_wildcards
        .iter()
        .map(|w| uf.find(*w))
        .collect::<Result<_, _>>()
        .map_err(InferError::unsited)?;
    // Every pinned variable's deep check reads its nested variables, which a
    // LATER entry's default may still pin (`{ x = n }` compared before
    // `n + 1` defaults `n` to `Int`). The checks therefore run after every
    // default, so the verdict never depends on the order the obligations were
    // generated in.
    let mut pinned: Vec<(VarId, TyBounds, Span, &ModuleHome)> = Vec::new();
    for SuperVar {
        var: v,
        bounds: orig_bounds,
        span,
        home,
    } in &generated.super_vars
    {
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
                    return Err(InferError::sited(
                        super_unsatisfied(interner, bounds, &int_ty, *span),
                        home,
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
            } if bounds.has_sql_param() && !generic_roots.contains(&root) => {
                let sqlvalue_ty = Ty::Con {
                    module: Vec::new(),
                    name: sqlvalue_sym,
                    args: Vec::new(),
                };
                if !concrete_super_ok(interner, bounds, &sqlvalue_ty, &enum_embeds_fn) {
                    return Err(InferError::sited(
                        super_unsatisfied(interner, bounds, &sqlvalue_ty, *span),
                        home,
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
            // An unpinned interpolation flex defaults to `String` — see the
            // doc comment above `string_sym`.
            Content::Super {
                rigid: false,
                bounds,
            } if bounds.has_interpolable() && !generic_roots.contains(&root) => {
                let string_ty = Ty::Con {
                    module: Vec::new(),
                    name: string_sym,
                    args: Vec::new(),
                };
                if !concrete_super_ok(interner, bounds, &string_ty, &enum_embeds_fn) {
                    return Err(InferError::sited(
                        super_unsatisfied(interner, bounds, &string_ty, *span),
                        home,
                    ));
                }
                lift!(uf.set_content(
                    root,
                    Content::Structure(FlatType::Con {
                        module: Vec::new(),
                        name: string_sym,
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
            // The variable pinned to a concrete type during solving: checked
            // below, once every default has been applied.
            Content::Structure(_) => pinned.push((root, *orig_bounds, *span, home)),
        }
    }
    // Verify — deeply, against the fully-resolved type — that each pinned type
    // really supports the operation. The unifier's head pin-check already
    // cleared a function HEAD; this catches a function NESTED inside a tuple /
    // record / enum under an equality obligation (Rust cannot compare it),
    // failing closed with IPE-T0014 instead of emitting code `cargo` rejects.
    for (root, orig_bounds, span, home) in pinned {
        let ty = lift!(zonk(&mut uf, budget, root));
        if !concrete_super_ok(interner, orig_bounds, &ty, &enum_embeds_fn) {
            return Err(InferError::sited(
                super_unsatisfied(interner, orig_bounds, &ty, span),
                home,
            ));
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
        .map_err(InferError::unsited)?;
    // Each untyped binding's cross-module discharge outcome (see the untyped
    // defaulting below), read before any slot is pinned to `Unit`. A use that
    // threads the slot into an enclosing generic -- a typed helper's `Rigid`
    // msg, or an untyped helper's quantified root that itself stays generic --
    // keeps it generic too (`Lib.nav` inside `Mid.wrap`, which `Main.view :
    // Html Msg` pins), as the typed path counts a `Rigid` instantiation pinned.
    // `msg_classes.generic` holds every quantified untyped root that stays
    // generic, so a typed use threaded into one counts as pinned below.
    let msg_classes = lift!(msg_slot_classes(
        &mut uf,
        budget,
        &generated.pending_instantiations,
        &untyped_schemes,
        &ui_msg_cons,
    ));
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
        let any_sym = interner.intern("any").map_err(InferError::unsited)?;
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
            // Whether a candidate defaults depends on EVERY use site, importers'
            // included, so an exported candidate makes this module's own solved
            // facts importer-dependent. Its exported scheme is the annotation,
            // which no use site changes.
            if exported_by_scoped_module(key) {
                own_facts_importer_dependent = true;
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
                // `sharedRow`'s own type parameter) -- OR to a `Flex` that is a
                // still-generic untyped binding's quantified root (`badge` inside
                // the unannotated `wrap` a further-out use pins). The unpinned
                // states are any other `Flex` (never constrained) and `Unit` (a
                // message-free use).
                let mut pinned = false;
                for vars in apps {
                    if let Some(&inst) = vars.get(&raw) {
                        let root = lift!(uf.find(inst));
                        match lift!(uf.content(root)) {
                            Content::Structure(FlatType::Unit) => {}
                            Content::Flex => {
                                if msg_classes.generic.contains(&root) {
                                    pinned = true;
                                    break;
                                }
                            }
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
    // Also build `poly_var_map`: the reverse mapping from the solver-tagged
    // union-find representative (`tag_solver_var(rep)`, the raw `zonk` writes
    // into every region `Ty::Var`) → annotation var symbol, keyed by
    // `(home, def_name)`.  The lowerer uses
    // this to distinguish "this `Ty::Var` is a generic type parameter of the
    // enclosing function" from "this `Ty::Var` is a message-free UI subtree
    // placeholder" when lowering attribute-list element types inside polymorphic
    // functions.
    let mut bounds: BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<Symbol, TyBounds>> = BTreeMap::new();
    let mut poly_var_map: BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<SolverVar, Symbol>> =
        BTreeMap::new();
    for ((home, def_name), var_rigids) in &generated.typed_rigids {
        let mut var_bounds = BTreeMap::new();
        let mut rep_to_sym: BTreeMap<SolverVar, Symbol> = BTreeMap::new();
        for (var_sym, rigid) in var_rigids {
            let rep = lift!(uf.find(*rigid));
            rep_to_sym.insert(SolverVar::from_var(rep), *var_sym);
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
    // A wildcard `any` the body obligated is a bounded generic parameter too:
    // record it under `any#<i>` (never a writable type-variable name) so each
    // use site — same module or, through the interface, a dependent one — checks
    // its own `i`-th wildcard. It stays out of `poly_var_map`: a wildcard is no
    // named type parameter of the enclosing function.
    //
    // Every parameter wildcard is classified ([`classify_param_wildcard`]): one
    // the body left an independent free variable stays a generic; one the body
    // pinned to one ground type (`h x = x + x == x` defaults it to `Int`; `f x =
    // String.length x` pins `String`) is no generic at all, so the pin is
    // recorded for the lowerer to emit concretely and every use site is held to
    // it ([`check_wildcard_pins`]). Any other solved root — a signature type
    // variable, another parameter's wildcard, a structure that still leaves part
    // of the type open — has no sound lowering and is refused here (IPE-T0021).
    let mut signature_wildcards: BTreeMap<(Vec<Symbol>, Symbol), SignatureWildcards> =
        BTreeMap::new();
    for entry in &generated.typed_wildcards {
        for (i, wildcard) in entry.wildcards.iter().enumerate() {
            if let Content::Super { bounds: b, .. } = lift!(uf.content(*wildcard))
                && !b.is_empty()
            {
                let sym = lift!(interner.intern(&wildcard_bound_key(i)));
                bounds.entry(entry.key.clone()).or_default().insert(sym, b);
            }
        }
        let rigid_names = poly_var_map.get(&entry.key);
        let mut pins = BTreeMap::new();
        // Solved root of each free (or row-record) parameter wildcard → its
        // 1-based parameter, so a second wildcard on that root is refused.
        let mut free_roots: BTreeMap<VarId, usize> = BTreeMap::new();
        let mut wildcards = entry.wildcards.iter().enumerate();
        for (param, (&count, &bare)) in entry
            .param_counts
            .iter()
            .zip(entry.bare_params.iter())
            .enumerate()
        {
            let parameter = param.saturating_add(1);
            for (i, wildcard) in wildcards.by_ref().take(count) {
                let fact = lift!(classify_param_wildcard(
                    &mut uf,
                    budget,
                    interner,
                    rigid_names,
                    *wildcard,
                    bare
                ));
                let dependence = match fact {
                    WildcardFact::Pinned(ty) => {
                        pins.insert(i, ty);
                        None
                    }
                    WildcardFact::Free | WildcardFact::RowRecord => {
                        let root = lift!(uf.find(*wildcard));
                        let earlier = free_roots.get(&root).copied();
                        if earlier.is_none() {
                            free_roots.insert(root, parameter);
                        }
                        earlier.map(|parameter| WildcardDependence::SharedWith { parameter })
                    }
                    WildcardFact::Dependent(dependence) => Some(dependence),
                };
                if let Some(dependence) = dependence {
                    return Err(InferError::sited_at_path(
                        Diagnostic::Type {
                            span: entry.span,
                            msg: TypeError::WildcardNotIndependent {
                                parameter,
                                dependence,
                            },
                        },
                        &entry.key.0,
                    ));
                }
            }
        }
        signature_wildcards.insert(
            entry.key.clone(),
            SignatureWildcards {
                param_counts: entry.param_counts.clone(),
                pins,
            },
        );
    }

    // Fold each Boundary-Scheme-Promoted untyped def's quantified vars into
    // `untyped_type_params` / `poly_var_map`, alongside the typed bindings'
    // entries above. Every `poly_var_map` key is a solver-tagged raw, the one
    // form `zonk` writes into region/env `Ty::Var`s, so the lowerer's lookup is
    // exact and an annotation-symbol raw can never match a variable key.
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
    //
    // The decision is taken per union-find CLASS, not per binding: a
    // same-module reference is the one shared variable, so `nav` and `wrap =
    // Html.div [] [ nav ]` own the same slot, and pinning it for `nav` would
    // pin `wrap` too. `msg_classes` was settled before the typed defaulting
    // above, from the pre-pin classification: a class is pinned to `Unit`
    // only when it is message-only for every owner and no owner stays
    // generic.
    for (&rep, owners) in &msg_classes.defaulted {
        // A cross-module use may keep this slot generic in the joint solve, so
        // a defaulted class an exported binding owns makes this module's own
        // solved facts importer-dependent. Its exported scheme was reified
        // before this pin.
        if owners.iter().any(|owner| exported_by_scoped_module(owner)) {
            own_facts_importer_dependent = true;
        }
        lift!(uf.set_content(rep, Content::Structure(FlatType::Unit)));
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
        let tagged: BTreeMap<SolverVar, Symbol> = quantified
            .iter()
            .map(|(&root, &sym)| (SolverVar::from_var(root), sym))
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
    check_scheme_applications(
        &mut uf,
        budget,
        interner,
        bounds_for_apps,
        &generated.scheme_apps,
        &enum_embeds_fn,
    )?;
    // A pinned parameter wildcard lowers to its one ground type: hold every use
    // — same module, or a dependent one through the interface — to it.
    // Every wildcard-carrying binding has an entry (possibly empty), so a use
    // whose binding has none is a drift, never "nothing pinned".
    let mut pins_for_apps: PinTable = signature_wildcards
        .iter()
        .map(|(key, w)| (key.clone(), w.pins.clone()))
        .collect();
    if let Some(ctx) = scoped {
        for (path, iface) in ctx.deps {
            for (name, scheme) in &iface.values {
                pins_for_apps.insert((path.clone(), *name), scheme.wildcard_pins.clone());
            }
        }
    }
    check_wildcard_pins(
        &mut uf,
        budget,
        interner,
        &pins_for_apps,
        &generated.scheme_apps,
    )?;

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
                        wildcard_pins: signature_wildcards
                            .get(&key)
                            .map(|w| w.pins.clone())
                            .unwrap_or_default(),
                    },
                );
            } else if let Some(ty) = reified_untyped.get(name) {
                values.insert(
                    *name,
                    TypedScheme {
                        ty: ty.clone(),
                        bounds: BTreeMap::new(),
                        wildcard_pins: BTreeMap::new(),
                    },
                );
            }
        }
        let interface = TypedInterface {
            values,
            unions: m.unions.iter().map(erase_union_spans).collect(),
            reachable_unions: dep_union_closure,
        };
        if own_facts_importer_dependent {
            InterfaceStatus::ImporterDependent(interface)
        } else {
            InterfaceStatus::Closed(interface)
        }
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
            signature_wildcards,
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
/// * `Threaded` — no use pins a concrete `Msg`, but one threads the slot into
///   an enclosing generic: a typed helper's own message variable, or an
///   untyped helper's slot that itself stays generic (`Lib.nav` inside
///   `Mid.wrap`, which `Main.view : Html Msg` pins). Kept generic: the
///   enclosing helper's generic body fixes `T1` at each use, and a `Unit`
///   default would mismatch its `Html<T1>` (E0308).
///
/// The defaulting DECISION collapses `Threaded`, `Pinned` and `MultiplyPinned`
/// (all keep the binding generic), but the distinction records WHY — a
/// single-type pin is monomorphic-but-inferable, not polymorphic — so the
/// outcome is legible on its own terms rather than a bare "keep / default" bit.
enum MsgDischargeOutcome {
    Unpinned,
    Threaded,
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
    /// concrete `Msg` nor threads it into an enclosing generic — the sole
    /// outcome for which `Html<()>` cannot mismatch a caller's message type. A
    /// threaded, single- or multiply-pinned slot stays generic.
    const fn should_default(&self) -> bool {
        matches!(self, Self::Unpinned)
    }
}

/// An untyped binding's key.
type BindingKey = (Vec<Symbol>, Symbol);

/// Each quantified untyped root's representative, split by whether the
/// untyped msg defaulting may pin it to `Unit`.
struct QuantifiedMsgRoots<'a> {
    /// Message-only roots, mapped to the bindings owning them.
    msg_only_owners: BTreeMap<VarId, Vec<&'a BindingKey>>,
    /// Every other root: no defaulting touches it, so it always stays generic.
    always_generic: BTreeSet<VarId>,
}

/// Classify every quantified untyped root (see [`QuantifiedMsgRoots`]).
fn quantified_msg_roots<'a>(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    untyped_schemes: &'a constrain::UntypedSchemes,
    ui_msg_cons: &BTreeSet<Symbol>,
) -> DResult<QuantifiedMsgRoots<'a>> {
    let mut msg_only_owners: BTreeMap<VarId, Vec<&BindingKey>> = BTreeMap::new();
    let mut always_generic: BTreeSet<VarId> = BTreeSet::new();
    for (key, scheme) in untyped_schemes {
        if scheme.quantified.is_empty() {
            continue;
        }
        let scheme_ty = zonk(uf, budget, scheme.root)?;
        let mut ui_msg_vars = BTreeSet::new();
        let mut other_vars = BTreeSet::new();
        collect_ui_msg_and_other_vars(
            &scheme_ty,
            ui_msg_cons,
            false,
            &mut ui_msg_vars,
            &mut other_vars,
        );
        for &root in scheme.quantified.keys() {
            let tagged_sym = Symbol::from_raw(tag_solver_var(root));
            let rep = uf.find(root)?;
            if ui_msg_vars.contains(&tagged_sym) && !other_vars.contains(&tagged_sym) {
                msg_only_owners.entry(rep).or_default().push(key);
            } else {
                always_generic.insert(rep);
            }
        }
    }
    Ok(QuantifiedMsgRoots {
        msg_only_owners,
        always_generic,
    })
}

/// The untyped msg defaulting's decision over the union-find classes of the
/// quantified untyped roots, taken once per class before any slot is pinned.
///
/// A same-module reference to an untyped binding is the one shared variable,
/// so a single class can be the quantified root of several bindings (`nav` and
/// `wrap = Html.div [] [ nav ]`). Pinning the class for one owner pins it for
/// every owner, so the decision belongs to the class: it stays generic when it
/// is not message-only for some owner, or when any owner's
/// [`MsgDischargeOutcome`] keeps that owner generic.
struct MsgSlotClasses<'a> {
    /// Every class that stays generic.
    generic: BTreeSet<VarId>,
    /// Every message-only class pinned to `Unit`, with the bindings owning it.
    defaulted: BTreeMap<VarId, Vec<&'a BindingKey>>,
}

/// Settle every untyped binding's cross-module [`MsgDischargeOutcome`], then
/// decide each class (see [`MsgSlotClasses`]).
///
/// A use threads the slot into an enclosing generic when a discharged msg
/// slot holds a `Rigid` / `Super` (a typed helper's own message variable), a
/// quantified root that is not message-only (always generic), or the
/// message-only root of a binding that is itself kept generic. The last is a
/// dependency between bindings, settled by a worklist: each binding turns
/// `Threaded` at most once, so the pass ends after at most one visit per
/// binding.
fn msg_slot_classes<'a>(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    pending: &[constrain::PendingInstantiation],
    untyped_schemes: &'a constrain::UntypedSchemes,
    ui_msg_cons: &BTreeSet<Symbol>,
) -> DResult<MsgSlotClasses<'a>> {
    let mut placeholders: BTreeMap<&BindingKey, Vec<VarId>> = BTreeMap::new();
    for pi in pending {
        placeholders
            .entry(&pi.source)
            .or_default()
            .push(pi.placeholder);
    }
    let QuantifiedMsgRoots {
        msg_only_owners,
        always_generic,
    } = quantified_msg_roots(uf, budget, untyped_schemes, ui_msg_cons)?;
    let mut outcomes: BTreeMap<BindingKey, MsgDischargeOutcome> = BTreeMap::new();
    // Binding -> the bindings whose discharged slot threads into its root.
    let mut threaded_into: BTreeMap<&BindingKey, BTreeSet<&BindingKey>> = BTreeMap::new();
    for (&key, vars) in &placeholders {
        let mut pinned: BTreeSet<MsgConId> = BTreeSet::new();
        let mut slot_vars: BTreeSet<Symbol> = BTreeSet::new();
        for &placeholder in vars {
            let discharged = zonk(uf, budget, placeholder)?;
            collect_ui_msg_concrete_cons(&discharged, ui_msg_cons, false, &mut pinned);
            let mut other_vars = BTreeSet::new();
            collect_ui_msg_and_other_vars(
                &discharged,
                ui_msg_cons,
                false,
                &mut slot_vars,
                &mut other_vars,
            );
        }
        let mut anchored = false;
        for sym in &slot_vars {
            let Some(var) = SolverVar::from_raw(sym.as_raw()) else {
                continue;
            };
            let rep = uf.find(var.var())?;
            match uf.content(rep)? {
                Content::Rigid | Content::Super { .. } => anchored = true,
                Content::Flex => {
                    if always_generic.contains(&rep) {
                        anchored = true;
                    }
                    for &owner in msg_only_owners.get(&rep).into_iter().flatten() {
                        if owner != key {
                            threaded_into.entry(owner).or_default().insert(key);
                        }
                    }
                }
                Content::Structure(_) => {}
            }
        }
        let outcome = match MsgDischargeOutcome::from_distinct_pin_count(pinned.len()) {
            MsgDischargeOutcome::Unpinned if anchored => MsgDischargeOutcome::Threaded,
            outcome => outcome,
        };
        outcomes.insert(key.clone(), outcome);
    }
    let mut work: Vec<&BindingKey> = outcomes
        .iter()
        .filter(|(_, outcome)| !outcome.should_default())
        .map(|(key, _)| key)
        .filter_map(|key| placeholders.get_key_value(key).map(|(k, _)| *k))
        .collect();
    while let Some(kept) = work.pop() {
        for &dependent in threaded_into.get(kept).into_iter().flatten() {
            if let Some(outcome) = outcomes.get_mut(dependent)
                && outcome.should_default()
            {
                *outcome = MsgDischargeOutcome::Threaded;
                work.push(dependent);
            }
        }
    }
    let mut generic = always_generic;
    let mut defaulted: BTreeMap<VarId, Vec<&BindingKey>> = BTreeMap::new();
    for (rep, owners) in msg_only_owners {
        let kept = generic.contains(&rep)
            || owners
                .iter()
                .any(|owner| outcomes.get(*owner).is_some_and(|o| !o.should_default()));
        if kept {
            generic.insert(rep);
        } else {
            defaulted.insert(rep, owners);
        }
    }
    Ok(MsgSlotClasses { generic, defaulted })
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
///
/// A violation is sited at the use's module, not at the binding's.
fn check_scheme_applications(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    bounds: &BTreeMap<(Vec<Symbol>, Symbol), BTreeMap<Symbol, TyBounds>>,
    apps: &[SchemeApp],
    enum_embeds_fn: &impl Fn(&[Symbol], Symbol) -> bool,
) -> Result<(), InferError> {
    for app in apps {
        // (AUD-05) keyed by (home, name) — a bare-name lookup would check a
        // same-named binding from a DIFFERENT module's obligations, both
        // false-accepting a violation and false-rejecting a clean use.
        let Some(var_bounds) = bounds.get(&(app.home.clone(), app.name)) else {
            continue;
        };
        for (var_sym, b) in var_bounds {
            let fresh = match wildcard_bound_index(interner, *var_sym) {
                Some(i) => match app.wildcards.get(i) {
                    Some(fresh) => fresh,
                    // The definition and its use instantiate one signature, so
                    // their wildcard counts agree; a drift must not pass unchecked.
                    None => {
                        return Err(InferError::unsited(Diagnostic::CompilerBug {
                            where_: "ipe_types::check_scheme_applications",
                            detail: format!(
                                "use site has {} wildcard(s), binding obligates wildcard {i}",
                                app.wildcards.len()
                            ),
                        }));
                    }
                },
                None => match app.vars.get(&var_sym.as_raw()) {
                    Some(fresh) => fresh,
                    None => continue,
                },
            };
            let ty = zonk(uf, budget, *fresh).map_err(InferError::unsited)?;
            if !emitted_bound_satisfied(interner, *b, &ty, &enum_embeds_fn) {
                return Err(InferError::sited(
                    super_unsatisfied(interner, *b, &ty, app.span),
                    &app.use_home,
                ));
            }
        }
    }
    Ok(())
}

/// The bounds-table key of a typed binding's `i`-th wildcard `any` obligation.
/// `#` is no identifier character, so no annotation variable can collide.
fn wildcard_bound_key(i: usize) -> String {
    format!("{WILDCARD_BOUND_PREFIX}{i}")
}

const WILDCARD_BOUND_PREFIX: &str = "any#";

/// The wildcard index a bounds-table key names, when it is one.
///
/// A typed binding's `i`-th wildcard `any` obligation is keyed `any#<i>` in
/// [`SolvedTypes::bounds`]; every other key is an annotation variable.
#[must_use]
pub fn wildcard_bound_index(interner: &Interner, sym: Symbol) -> Option<usize> {
    interner
        .resolve(sym)?
        .strip_prefix(WILDCARD_BOUND_PREFIX)?
        .parse()
        .ok()
}

/// Reject a use that instantiates a pinned parameter wildcard at another type.
///
/// A wildcard `any` parameter the body pinned to one ground type lowers to that
/// concrete Rust type, not a generic, while each use instantiates its own fresh
/// copy of the wildcard. Without this check `h 1.5` against a body that pinned
/// `Int` would pass here and fail `cargo` with a type mismatch. A use whose
/// wildcard stays non-ground (it flows into the caller's own generic) is
/// rejected too: it cannot be shown to be the pinned type.
///
/// A use that instantiates wildcards of a binding the pin table has no entry
/// for is a compiler bug: the table holds every wildcard-carrying binding, so a
/// missing entry must never read as "nothing pinned". A mismatch is sited at
/// the use's module, not at the binding's.
fn check_wildcard_pins(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    pins: &PinTable,
    apps: &[SchemeApp],
) -> Result<(), InferError> {
    for app in apps {
        let Some(binding_pins) = pins.get(&(app.home.clone(), app.name)) else {
            if app.wildcards.is_empty() {
                continue;
            }
            return Err(InferError::unsited(Diagnostic::CompilerBug {
                where_: "ipe_types::check_wildcard_pins",
                detail: format!(
                    "use site instantiates {} wildcard(s) of a binding with no pin entry",
                    app.wildcards.len()
                ),
            }));
        };
        for (i, pinned) in binding_pins {
            // The definition and its use instantiate one signature, so their
            // wildcard counts agree; a drift must not pass unchecked.
            let Some(fresh) = app.wildcards.get(*i) else {
                return Err(InferError::unsited(Diagnostic::CompilerBug {
                    where_: "ipe_types::check_wildcard_pins",
                    detail: format!(
                        "use site has {} wildcard(s), binding pins wildcard {i}",
                        app.wildcards.len()
                    ),
                }));
            };
            let found = zonk(uf, budget, *fresh).map_err(InferError::unsited)?;
            if found != *pinned {
                let mut namer = VarNamer::new();
                let expected =
                    ty_to_doc(pinned, interner, &mut namer).map_err(InferError::unsited)?;
                let found = ty_to_doc(&found, interner, &mut namer).map_err(InferError::unsited)?;
                return Err(InferError::sited(
                    Diagnostic::Type {
                        span: app.span,
                        msg: TypeError::TypeMismatch {
                            expected: Box::new(expected),
                            found: Box::new(found),
                            definition: None,
                            path: Box::new([]),
                        },
                    },
                    &app.use_home,
                ));
            }
        }
    }
    Ok(())
}

/// Whether a resolved type is ground: no type variable and no open record row.
///
/// This is the read-back form of "the type is fully known": the lowerer
/// concretizes a wildcard parameter's region only when it holds. Inference
/// classifies a wildcard with `solved_is_ground` instead, which also sees
/// the open rows [`zonk`] reads back as closed; every type it admits is one
/// this admits, so the lowerer never concretizes a wildcard inference left
/// unpinned.
#[must_use]
pub fn ty_is_ground(ty: &Ty) -> bool {
    match ty {
        Ty::Var(_) | Ty::Record(_, RowTail::Open(_)) => false,
        Ty::Unit => true,
        Ty::Record(fields, RowTail::Closed) => fields.values().all(ty_is_ground),
        Ty::Fun(a, b) => ty_is_ground(a) && ty_is_ground(b),
        Ty::Con { args, .. } => args.iter().all(ty_is_ground),
        Ty::Tuple(elems) => elems.iter().all(ty_is_ground),
    }
}

/// Whether every solver node reachable from `roots` is known: no type
/// variable, and every record extension ends in the closed-row sentinel.
///
/// Read on the union-find, not on a zonked [`Ty`]: [`zonk`] presents every
/// record as closed, so an open row a field read left behind is invisible
/// after read-back. A type this admits zonks to one [`ty_is_ground`] admits.
///
/// # Errors
/// A union-find invariant violation, or [`TypeError::StepBudgetExceeded`]
/// once the shared budget is spent.
fn solved_is_ground(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    roots: impl IntoIterator<Item = VarId>,
) -> DResult<bool> {
    let mut work: Vec<VarId> = roots.into_iter().collect();
    let mut seen: BTreeSet<VarId> = BTreeSet::new();
    while let Some(var) = work.pop() {
        budget.tick()?;
        let root = uf.find(var)?;
        if !seen.insert(root) {
            continue;
        }
        match uf.root_content(root)? {
            Content::Flex | Content::Rigid | Content::Super { .. } => return Ok(false),
            Content::Structure(FlatType::Unit | FlatType::EmptyRecord) => {}
            Content::Structure(FlatType::Fun(arg, result)) => {
                work.push(*arg);
                work.push(*result);
            }
            Content::Structure(FlatType::Con { args, .. }) => work.extend(args.iter().copied()),
            Content::Structure(FlatType::Tuple(elems)) => work.extend(elems.iter().copied()),
            Content::Structure(FlatType::Record(fields, ext)) => {
                work.extend(fields.values().copied());
                work.push(*ext);
            }
        }
    }
    Ok(true)
}

/// What a parameter wildcard's solved root makes of it.
enum WildcardFact {
    /// An unsolved non-rigid variable: the wildcard stays its own generic.
    Free,
    /// A bare `any` parameter solved to a record whose every field is ground:
    /// it lowers to a structural row generic admitting wider caller records.
    /// A field holding an unknown leaves the lowerer no concrete field type,
    /// so such a record is a partial structure instead.
    RowRecord,
    /// One ground type the lowerer emits concretely ([`solved_is_ground`]).
    Pinned(Ty),
    /// A root no lowering keeps independent; the binding is refused.
    Dependent(WildcardDependence),
}

/// Classify one parameter wildcard by its solved root.
///
/// `rigid_names` maps the binding's solver-tagged signature-variable roots to
/// their names;
/// `bare` says whether the wildcard is the parameter's whole annotation.
fn classify_param_wildcard(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    rigid_names: Option<&BTreeMap<SolverVar, Symbol>>,
    wildcard: VarId,
    bare: bool,
) -> DResult<WildcardFact> {
    match uf.content(wildcard)? {
        Content::Flex | Content::Super { rigid: false, .. } => Ok(WildcardFact::Free),
        Content::Rigid | Content::Super { rigid: true, .. } => {
            let root = uf.find(wildcard)?;
            let name = rigid_names
                .and_then(|names| names.get(&SolverVar::from_var(root)))
                .and_then(|sym| interner.resolve(*sym))
                .map(Box::from);
            Ok(WildcardFact::Dependent(WildcardDependence::TypeVariable {
                name,
            }))
        }
        Content::Structure(flat) => {
            // A bare record's row tail is its extensibility, so only its fields
            // must be ground; anywhere else an open row is an unknown.
            let ground = if bare && let FlatType::Record(fields, _) = &flat {
                if solved_is_ground(uf, budget, fields.values().copied())? {
                    return Ok(WildcardFact::RowRecord);
                }
                false
            } else {
                solved_is_ground(uf, budget, [wildcard])?
            };
            let ty = zonk(uf, budget, wildcard)?;
            if ground {
                Ok(WildcardFact::Pinned(ty))
            } else {
                let mut namer = VarNamer::new();
                Ok(WildcardFact::Dependent(
                    WildcardDependence::PartialStructure {
                        found: Box::new(ty_to_doc(&ty, interner, &mut namer)?),
                    },
                ))
            }
        }
    }
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
    // The higher-order-kernel callback-result obligation (every callback
    // final result a pure higher-order kernel applies — see
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
    // Interpolation obligation (`{{…}}` / `Log.*With` attributes): exactly the
    // closed scalar set the runtime's sealed `IpeInterpolate` trait covers. A
    // bare variable (`prim == None`) fails closed like every sibling.
    let interpolable_ok = super_bounds::prim_satisfies_interpolable(prim);
    (!bounds.has_number() || number_ok)
        && (!bounds.has_ord() || ord_ok)
        && (!bounds.has_eq() || ty_is_equatable(ty, enum_embeds_fn))
        && (!bounds.has_comparable_key() || key_ok)
        // Stringify (`Debug.log` / `Error.toString`): showable iff it contains
        // no function anywhere — the SAME "no function nested" rule as
        // equatable, since every non-function type derives `IpeStringify`.
        && (!bounds.has_show() || ty_is_equatable(ty, enum_embeds_fn))
        && (!bounds.has_append() || appendable_ok)
        && (!bounds.has_hof_kernel_result() || not_curried_ok)
        && (!bounds.has_sql_param() || sql_param_ok)
        && (!bounds.has_interpolable() || interpolable_ok)
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

/// Every union reachable through `deps`, each `(home, name)` identity once.
///
/// A dependency's interface carries its own unions plus, in
/// [`TypedInterface::reachable_unions`], every union its own dependencies
/// reach, so one pass over the direct deps yields the transitive closure:
/// each interface is read exactly once (the map is keyed by module path), no
/// recursion runs, and the work is bounded by the deps' union counts. A
/// diamond reaching one union along two paths keeps one copy. A union
/// already in a dependency's closure is shared, never copied; only a direct
/// dependency's own unions are cloned, once each.
fn reachable_dep_unions(
    deps: &BTreeMap<Vec<Symbol>, Arc<TypedInterface>>,
) -> Vec<Arc<canon::Union>> {
    let mut by_id: BTreeMap<(&[Symbol], Symbol), Arc<canon::Union>> = BTreeMap::new();
    for iface in deps.values() {
        for union in &iface.reachable_unions {
            by_id
                .entry((union.home.as_slice(), union.name))
                .or_insert_with(|| Arc::clone(union));
        }
    }
    for iface in deps.values() {
        for union in &iface.unions {
            by_id
                .entry((union.home.as_slice(), union.name))
                .or_insert_with(|| Arc::new(union.clone()));
        }
    }
    by_id.into_values().collect()
}

/// The `(home, name)` set of user enums whose DEFINITION embeds a function in
/// any constructor payload (`type Handler a = OnClick (Int -> a) | Plain a`).
///
/// Such an enum is not `Equatable` / showable however it is applied: its payload
/// arrow is invisible in a `Ty::Con`'s type arguments (which carry only applied
/// type parameters), so the structural [`ty_is_equatable`] walk cannot see it
/// without this out-of-band definition lookup. Consulted at every concrete
/// equality / stringify obligation so a `==` / `{{…}}` on a function-carrying
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
pub(crate) fn super_unsatisfied(
    interner: &Interner,
    bounds: TyBounds,
    ty: &Ty,
    span: Span,
) -> Diagnostic {
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
    // callback-result slot of a higher-order kernel such as `List.map`,
    // `List.foldl`, or `Maybe.map2`): the callback's final result must not itself be a
    // function, because the runtime kernel applies the callback at one exact
    // arity while the IR flattens curried functions.
    if bounds.has_hof_kernel_result() {
        // Shared constant: the renderer keys a tailored (non-double-negative)
        // sentence off this exact label.
        classes.push(ipe_diagnostics::HOF_KERNEL_RESULT_CLASS);
    }
    // The interpolation obligation's closed scalar set is a subset of every
    // sibling class's domain, so it alone names the failure; the shared label
    // keys the renderer's tailored sentence (accepted scalars + the fix).
    let class = if bounds.has_interpolable() {
        ipe_diagnostics::INTERPOLABLE_CLASS.to_owned()
    } else if classes.is_empty() {
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
    /// The base is still undecided ([`base_state`]) — defer to the next
    /// fixpoint pass.
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
    /// The base is still undecided ([`base_state`]) — defer to the next pass.
    Undecided,
    /// The base is a nominal BUILTIN with a fixed READABLE field table
    /// (`PanicInfo` / `TypeInfo` / `ErrorInfo` / `Request`) — field access
    /// works, record UPDATE does not. Reported as the dedicated IPE-T0017
    /// rather than a misleading "no field" IPE-T0012.
    BuiltinCon(Symbol),
    Other,
}

/// How far unification has decided a deferred obligation's base variable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BaseState {
    /// An unconstrained variable: a record may still be grown onto it.
    Flex,
    /// A non-rigid super variable whose obligations admit a record head: a
    /// later pass, or [`unify`], may still pin it to a record.
    PinnableSuper,
    /// Unification will never make it a record it is not already.
    Decided,
}

impl BaseState {
    /// Whether a later pass could still settle the base to a record.
    const fn is_undecided(self) -> bool {
        matches!(self, Self::Flex | Self::PinnableSuper)
    }
}

/// Classify a base descriptor, exhaustively over [`Content`].
///
/// The one rule every deferred pass (field access, its row tail, record update,
/// the no-progress settle) asks, so no pass decides against a variable another
/// pass would still wait on.
fn base_state(content: &Content) -> BaseState {
    match content {
        Content::Flex => BaseState::Flex,
        Content::Super {
            rigid: false,
            bounds,
        } if super_admits_record(*bounds) => BaseState::PinnableSuper,
        Content::Super { .. }
        | Content::Rigid
        | Content::Structure(
            FlatType::Fun(_, _)
            | FlatType::Con { .. }
            | FlatType::Unit
            | FlatType::Tuple(_)
            | FlatType::Record(_, _)
            | FlatType::EmptyRecord,
        ) => BaseState::Decided,
    }
}

/// Whether the variable `var` is still undecided ([`BaseState::is_undecided`]).
fn base_is_undecided(uf: &mut UnionFind<Content>, var: VarId) -> DResult<bool> {
    let root = uf.find(var)?;
    Ok(base_state(uf.root_content(root)?).is_undecided())
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
        // Undecided (a `Flex`, or a super that may still pin to a record) →
        // wait; a rigid, a record-refusing super, or a non-record structure →
        // a genuine "no field".
        content @ (Content::Flex
        | Content::Super { .. }
        | Content::Rigid
        | Content::Structure(
            FlatType::Fun(_, _)
            | FlatType::Con { .. }
            | FlatType::Unit
            | FlatType::Tuple(_)
            | FlatType::EmptyRecord,
        )) => {
            if base_state(content).is_undecided() {
                Peek::Deferred
            } else {
                Peek::Missing
            }
        }
    };
    Ok(match peek {
        // Present → Found. Missing on an OPEN tail (Flex root) → GrowOpen (the
        // record is row-polymorphic and absorbs the new field); on a tail that
        // may still pin to a record → Deferred; on a CLOSED or otherwise decided
        // tail → Missing (IPE-T0012).
        Peek::Record(Some(v), _) => FieldState::Found(v),
        Peek::Record(None, ext) => {
            // Resolve the tail's root (mutable `find`) BEFORE the immutable
            // `root_content` read so the two borrows don't overlap.
            let ext_root = uf.find(ext)?;
            match base_state(uf.root_content(ext_root)?) {
                BaseState::Flex => FieldState::GrowOpen,
                BaseState::PinnableSuper => FieldState::Deferred,
                BaseState::Decided => FieldState::Missing,
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
) -> Result<(), InferError> {
    // A union-find or field-table step fails only on an internal invariant, so
    // its error has no owning module. Every source error — a field mismatch
    // from `unify_at`, an IPE-T0012 — is sited at the failing item's `home`.
    macro_rules! lift {
        ($e:expr) => {
            $e.map_err(InferError::unsited)?
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
        // Every visit of a pending item is a solver step: a pass may discharge
        // only one of `n` items (a chain `r.f.f…f` settles one base per pass), so
        // the fixpoint costs O(n²) visits and the solver budget is its ceiling.
        for fa in &pending_fa {
            lift!(budget.tick());
            let root = lift!(uf.find(fa.record));
            // See [`field_access_state`] for the encoding + borrow discipline.
            match lift!(field_access_state(uf, tables, root, fa.field)) {
                FieldState::Deferred => {
                    next_fa.push(fa);
                }
                FieldState::Found(v) => {
                    made_progress = true;
                    unify_at(uf, budget, interner, &fa.home, fa.span, fa.result, v)?;
                }
                FieldState::GrowOpen => {
                    // Row-poly growth: the base is an open record missing this
                    // field. Add it (value var = the access's result var) and
                    // keep the tail open for further growth. Re-read the root's
                    // field map (the `field_access_state` borrow has ended),
                    // insert, and re-seat with a FRESH open tail.
                    made_progress = true;
                    // The record adopts `fa.result` as a field, so the base must
                    // not occur inside it (`let a = r.a in g r.next`): a cycle is
                    // an infinite type, never written.
                    occurs_guard(uf, budget, interner, fa.span, root, fa.result)
                        .map_err(|d| InferError::sited(d, &fa.home))?;
                    let Content::Structure(FlatType::Record(mut fields, _)) =
                        lift!(uf.root_content(root)).clone()
                    else {
                        // `GrowOpen` is only produced from a `Record` root.
                        return Err(InferError::unsited(Diagnostic::CompilerBug {
                            where_: "ipe_types::resolve_deferred",
                            detail: "a grow-open field access base is not a record".into(),
                        }));
                    };
                    fields.insert(fa.field, fa.result);
                    let new_ext = lift!(uf.fresh(Content::Flex));
                    lift!(uf.set_content(
                        root,
                        Content::Structure(FlatType::Record(fields, new_ext)),
                    ));
                }
                FieldState::Missing => {
                    return Err(InferError::sited(
                        no_such_field(uf, budget, interner, fa.record, fa.field, fa.span),
                        &fa.home,
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
            lift!(budget.tick());
            match resolve_one_record_update(uf, budget, interner, tables, ru)? {
                RuOutcome::Deferred => next_ru.push(ru),
                RuOutcome::Discharged => made_progress = true,
            }
        }
        pending_ru = next_ru;

        if !made_progress {
            // Nothing was discharged this pass — every remaining item's base var
            // is still undecided (no closed record ever pinned it).
            //
            // An undecided base is NOT an error: it is a field access on a parameter
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
            // The settle goes through `unify`, never a raw write: it checks a
            // super base's obligations and runs the occurs check, so
            // `g r = g r.next` is an infinite type, not a cyclic record.
            //
            // When no pending base is undecided (each is a record waiting on a
            // super tail), the first access falls through to IPE-T0012.
            let mut undecided = None;
            for fa in &pending_fa {
                if lift!(base_is_undecided(uf, fa.record)) {
                    undecided = Some(*fa);
                    break;
                }
            }
            if let Some(fa) = undecided {
                let mut fields = BTreeMap::new();
                fields.insert(fa.field, fa.result);
                let ext = lift!(uf.fresh(Content::Flex));
                let rec = lift!(uf.fresh(Content::Structure(FlatType::Record(fields, ext))));
                unify_at(uf, budget, interner, &fa.home, fa.span, fa.record, rec)?;
                continue;
            }
            if let Some(fa) = pending_fa.first() {
                return Err(InferError::sited(
                    no_such_field(uf, budget, interner, fa.record, fa.field, fa.span),
                    &fa.home,
                ));
            }
            if let Some(ru) = pending_ru.first()
                && let Some((field, _)) = ru.fields.first()
            {
                return Err(InferError::sited(
                    no_such_field(uf, budget, interner, ru.record, *field, ru.span),
                    &ru.home,
                ));
            }
            // A pass that made no progress, settled nothing and named no failing
            // item would repeat itself forever: fail closed instead.
            return Err(InferError::unsited(Diagnostic::CompilerBug {
                where_: "ipe_types::resolve_deferred",
                detail: "a deferred pass made no progress and reported no item".into(),
            }));
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
/// * an undecided base ([`base_state`]) → defer to the next pass;
/// * anything else → IPE-T0012 on the first updated field (degenerate empty
///   update on a non-record base is treated as discharged so the loop can't
///   stall on it).
fn resolve_one_record_update(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    tables: &BuiltinFieldTables,
    ru: &RecordUpdate,
) -> Result<RuOutcome, InferError> {
    macro_rules! lift {
        ($e:expr) => {
            $e.map_err(InferError::unsited)?
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
        // An update never grows a record: an undecided base waits, a decided
        // non-record base is a genuine "no field".
        content @ (Content::Flex
        | Content::Super { .. }
        | Content::Rigid
        | Content::Structure(
            FlatType::Fun(_, _)
            | FlatType::Con { .. }
            | FlatType::Unit
            | FlatType::Tuple(_)
            | FlatType::EmptyRecord,
        )) => {
            if base_state(content).is_undecided() {
                RuPeek::Undecided
            } else {
                RuPeek::Other
            }
        }
    };
    match peek {
        RuPeek::Fields(fields) => {
            for (field, value_var, field_var) in fields {
                match field_var {
                    Some(field_var) => {
                        unify_at(
                            uf, budget, interner, &ru.home, ru.span, value_var, field_var,
                        )?;
                    }
                    None => {
                        return Err(InferError::sited(
                            no_such_field(uf, budget, interner, ru.record, field, ru.span),
                            &ru.home,
                        ));
                    }
                }
            }
            Ok(RuOutcome::Discharged)
        }
        RuPeek::Undecided => Ok(RuOutcome::Deferred),
        RuPeek::BuiltinCon(name) => Err(InferError::sited(
            lift!(builtin_record_update(interner, name, ru.span)),
            &ru.home,
        )),
        RuPeek::Other => {
            if let Some((field, _)) = ru.fields.first() {
                return Err(InferError::sited(
                    no_such_field(uf, budget, interner, ru.record, *field, ru.span),
                    &ru.home,
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
) -> Result<(), InferError> {
    for check in checks {
        let mut cur = uf.find(check.builder_var).map_err(InferError::unsited)?;
        let mut fuel: u32 = 1024;
        while fuel > 0 {
            match uf.content(cur).map_err(InferError::unsited)? {
                Content::Structure(FlatType::Fun(_, ret)) => {
                    cur = uf.find(ret).map_err(InferError::unsited)?;
                }
                _ => break,
            }
            fuel -= 1;
        }
        // Unify the built page type with the route's page variable.  A
        // mismatch is a normal IPE-T0001 blamed at the `Web.route` span in
        // the module owning it.
        unify_at(
            uf,
            budget,
            interner,
            &check.home,
            check.span,
            cur,
            check.page_var,
        )?;
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
///
/// `onNavigate`, an optional cfg field absorbed by the row tail, is typed
/// `Page -> Msg` in a routed app (IPE-T0001 otherwise) and refused in an
/// unrouted one (IPE-L0162), where nothing would call it.
///
/// Every source error and warning is sited at the home of the `Web.tea` call
/// it concerns; a union-find invariant violation has no home.
fn resolve_routed_web_checks(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    checks: &[RoutedWebCheck],
    has_routes: bool,
    route_count: usize,
    warnings: &mut Vec<HomedWarning>,
) -> Result<(), InferError> {
    for check in checks {
        // Find the settled root of the Model type variable.
        let model_root = uf.find(check.model_var).map_err(InferError::unsited)?;
        // Clone the content to avoid borrowing `uf` across the subsequent
        // `unify` call.
        let model_content = uf.content(model_root).map_err(InferError::unsited)?;
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
        let on_navigate = row_tail_field(uf, interner, check.cfg_tail_var, "onNavigate")
            .map_err(InferError::unsited)?;
        if let Some(page_var) = page_var {
            // Routed app: `notFound` must be the same type as `Model.page`.
            // `unify` produces IPE-T0001 (TypeMismatch) if they differ.
            unify_at(
                uf,
                budget,
                interner,
                &check.home,
                check.span,
                check.not_found_var,
                page_var,
            )?;
            if let Some(on_navigate) = on_navigate {
                let page_to_msg = uf
                    .fresh(Content::Structure(FlatType::Fun(page_var, check.msg_var)))
                    .map_err(InferError::unsited)?;
                unify_at(
                    uf,
                    budget,
                    interner,
                    &check.home,
                    check.span,
                    on_navigate,
                    page_to_msg,
                )?;
            }
        } else if on_navigate.is_some() {
            return Err(InferError::sited(
                Diagnostic::Lower {
                    span: check.span,
                    msg: LowerError::OnNavigateWithoutPage,
                },
                &check.home,
            ));
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
            warnings.push(HomedWarning::new(
                Diagnostic::Lower {
                    span: check.span,
                    msg: LowerError::RoutedAppMissingPageField { route_count },
                },
                check.home.path(),
            )?);
        }
        // Non-routed with no routes → genuinely non-routed → silently skip.
    }
    Ok(())
}

/// The variable of field `name` in the settled row starting at `tail`, if the
/// row has one. A row deeper than the walk's fuel is a compiler bug, never a
/// silently absent field.
fn row_tail_field(
    uf: &mut UnionFind<Content>,
    interner: &Interner,
    tail: VarId,
    name: &str,
) -> DResult<Option<VarId>> {
    let mut cur = uf.find(tail)?;
    for _ in 0..4096u32 {
        let Content::Structure(FlatType::Record(fields, ext)) = uf.content(cur)? else {
            return Ok(None);
        };
        if let Some(var) = fields
            .iter()
            .find(|(sym, _)| interner.resolve(**sym) == Some(name))
            .map(|(_, v)| *v)
        {
            return Ok(Some(var));
        }
        cur = uf.find(ext)?;
    }
    Err(Diagnostic::CompilerBug {
        where_: "ipe_types::row_tail_field",
        detail: "a cfg row is deeper than any record the checker builds".into(),
    })
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

    /// A typed binding's generic-variable keys are solver-tagged, the form its zonked regions carry.
    ///
    /// The lowerer looks a region `Ty::Var` up by exact key, so an untagged
    /// key would leave the binding's generic unfound in its own body.
    #[test]
    fn typed_binding_poly_var_keys_are_solver_tagged_region_vars() {
        let src = format!("{M2C_HDR}identity : a -> a\nidentity x =\n    x\n\nmain = identity 1\n");
        let (solved, i, m) = infer_src(&src);
        assert!(
            matches!((&solved, &m), (Ok(_), Some(_))),
            "identity must typecheck: {solved:?}"
        );
        let (Ok(solved), Some(m)) = (solved, m) else {
            return;
        };
        let identity = def_key(&i, &m, "identity");
        assert!(identity.is_some(), "identity must be defined in canon");
        let Some(identity) = identity else { return };
        let keys = solved.poly_var_map.get(&identity);
        assert!(
            keys.is_some_and(|k| !k.is_empty()),
            "identity's generic must be recorded"
        );
        let Some(keys) = keys else { return };
        let region_vars: BTreeSet<SolverVar> = solved
            .regions
            .iter()
            .filter(|((home, _), _)| *home == identity.0)
            .filter_map(|(_, ty)| match ty {
                Ty::Var(raw) => SolverVar::from_raw(*raw),
                _ => None,
            })
            .collect();
        assert!(
            keys.keys().any(|key| region_vars.contains(key)),
            "the body's region var is a key verbatim: keys {keys:?}, region vars {region_vars:?}"
        );
    }

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
            matches!((&solved, &m), (Ok(_), Some(_))),
            "generic record signature must typecheck: {solved:?}"
        );
        let (Ok(solved), Some(m)) = (solved, m) else {
            return;
        };
        let wrap = def_key(&i, &m, "wrap").expect("wrap must be defined in canon");
        let ty = solved
            .env
            .get(&wrap)
            .expect("wrap must have an inferred type");
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

        let update = def_key(&i, &m, "update").expect("update must be defined in canon");
        let ty = solved
            .env
            .get(&update)
            .expect("update must have an inferred type");

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
        let str_arg = outer_args
            .first()
            .expect("main body call must have at least one arg");
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
        let first = branches.first().expect("case must have at least one arm");
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
        let main = def_key(&i, &m, "main").expect("main must be defined in canon");
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
    /// source)`. Returns `None` on any parse / canonicalise / link failure;
    /// callers `.expect(..)` this so a setup failure fails the test loudly
    /// instead of returning early — it is never itself the assertion.
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

    /// A dependency exposing a record alias, linked ahead of `Main`.
    const DEP_POINT: &str = "module Dep exposing (Point, origin)\n\n\
                             type alias Point =\n    { x : Int, y : Int }\n\n\
                             origin : Point\n\
                             origin =\n    { x = 0, y = 0 }\n";

    /// Link `Dep` then `Main` and infer the program, returning the error's
    /// diagnostic and the dotted module it is sited at (`None` when unsited),
    /// or `None` when the program links and infers cleanly.
    fn linked_error_site(dep_src: &str, main_src: &str) -> Option<(Diagnostic, Option<String>)> {
        let (m, mut i) = link_modules(&[("Dep", dep_src), ("Main", main_src)])?;
        let err = infer_attributed(&m, &mut i).err()?;
        let home = err.home().map(|home| {
            home.path()
                .iter()
                .filter_map(|seg| i.resolve(*seg))
                .collect::<Vec<_>>()
                .join(".")
        });
        Some((err.into_diagnostic(), home))
    }

    /// A field read whose type disagrees with its use is sited in the module
    /// owning the read, never left homeless for a surface to guess a file.
    #[test]
    fn field_access_type_mismatch_is_sited_in_owning_module() {
        let main_src = "module Main exposing (getX)\n\n\
                        import Dep exposing (Point)\n\n\
                        getX : Point -> String\n\
                        getX p =\n    p.x\n";
        let site = linked_error_site(DEP_POINT, main_src);
        assert!(
            matches!(&site, Some((Diagnostic::Type { .. }, Some(home))) if home == "Main"),
            "a field mismatch must be sited at Main, got {site:?}"
        );
    }

    /// A record update storing the wrong type is sited in the module owning
    /// the update.
    #[test]
    fn record_update_type_mismatch_is_sited_in_owning_module() {
        let main_src = "module Main exposing (bump)\n\n\
                        import Dep exposing (Point)\n\n\
                        bump : Point -> Point\n\
                        bump p =\n    { p | x = \"a\" }\n";
        let site = linked_error_site(DEP_POINT, main_src);
        assert!(
            matches!(&site, Some((Diagnostic::Type { .. }, Some(home))) if home == "Main"),
            "a record-update mismatch must be sited at Main, got {site:?}"
        );
    }

    /// A route whose builder disagrees with the page type is sited in the
    /// module owning the `Web.route` reference.
    #[test]
    fn route_witness_mismatch_is_sited() {
        let mut interner = Interner::new();
        let mut budget = Budget::unbounded();
        let mut uf = UnionFind::new();
        let Ok(main) = interner.intern("Main") else {
            return;
        };
        let Some(home) = ModuleHome::new(vec![main]) else {
            return;
        };
        let Ok(builder_var) = uf.fresh(Content::Structure(FlatType::Unit)) else {
            return;
        };
        let Ok(page_var) = uf.fresh(Content::Structure(FlatType::EmptyRecord)) else {
            return;
        };
        let check = RouteWitnessCheck {
            builder_var,
            page_var,
            span: Span::DUMMY,
            home: home.clone(),
        };
        let result = resolve_route_witness_checks(&mut uf, &mut budget, &interner, &[check]);
        assert!(
            matches!(&result, Err(InferError::Sited { home: sited, .. }) if *sited == home),
            "a route witness mismatch must be sited at its route's module, got {result:?}"
        );
    }

    /// A refusal raised while generating a def's constraints is sited in the
    /// module owning that def.
    #[test]
    fn constraint_generation_error_is_sited() {
        let main_src = "module Main exposing (f)\n\n\
                        import Dep exposing (Point)\n\n\
                        f : Int -> Int\n\
                        f a b =\n    a\n";
        let site = linked_error_site(DEP_POINT, main_src);
        assert!(
            matches!(
                &site,
                Some((
                    Diagnostic::Type {
                        msg: TypeError::TooManyParameters { .. },
                        ..
                    },
                    Some(home)
                )) if home == "Main"
            ),
            "a constraint-generation refusal must be sited at Main, got {site:?}"
        );
    }

    /// A use that instantiates a bounded generic at a type violating its bound
    /// is sited at the use's module, not at the binding's.
    #[test]
    fn scheme_app_bound_violation_is_sited_at_use() {
        let dep_src = "module Dep exposing (double)\n\n\
                       double : a -> a\n\
                       double x =\n    x + x\n";
        let main_src = "module Main exposing (doubleBool)\n\n\
                        import Dep exposing (double)\n\n\
                        doubleBool : Bool -> Bool\n\
                        doubleBool x =\n    double x\n";
        let site = linked_error_site(dep_src, main_src);
        assert!(
            matches!(
                &site,
                Some((
                    Diagnostic::Type {
                        msg: TypeError::SuperTypeUnsatisfied { .. },
                        ..
                    },
                    Some(home)
                )) if home == "Main"
            ),
            "a bound violation must be sited at the use in Main, got {site:?}"
        );
    }

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
             main =\n    useInt\n",
        );
        let (m, mut i) = link_modules(&[LIB1_IDENT, mid, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
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
             main =\n    0\n",
        );
        let (m, mut i) = link_modules(&[lib, mid, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
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
             main =\n    useInt\n",
        );
        let (m, mut i) = link_modules(&[LIB1_IDENT, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
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
             main =\n    result\n",
        );
        let (m, mut i) = link_modules(&[lib, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
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
             main =\n    name\n",
        );
        let (m, mut i) = link_modules(&[lib, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
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
             main =\n    aName ++ bName\n",
        );
        let (m, mut i) = link_modules(&[lib, mid, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
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
             main =\n    (setName { name = \"Ada\" } \"Bea\").name\n",
        );
        let (m, mut i) = link_modules(&[lib, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a single-record-type cross-module use of an untyped record-update \
             helper must typecheck: {r:?}"
        );
        let Ok(solved) = r else { return };
        let lib1 = i.intern("Lib1").expect("intern Lib1");
        let set_name = i.intern("setName").expect("intern setName");
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
             main =\n    sumInt\n",
        );
        let (m, mut i) = link_modules(&[lib, mid, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
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
                   main =\n    useInt\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
        // `fail : Error -> Task Error a` (a stand-in for `Task.fail`, which lives
        // in the compiled-source `Ipe.Task` module this unit-level harness
        // cannot resolve) called with a `String` argument: the DECLARED
        // parameter type is the *expected* side and the user's actual argument
        // the *found* side — "expected Error, found String", never the
        // inversion. The Call arm must orient the constraint so the declared
        // parameter, not the actual argument, lands on unify's *expected* side.
        let src = "module Main exposing (main)\n\
                   fail : Error -> Task Error a\n\
                   fail x =\n    fail x\n\n\
                   main =\n    fail \"plain string\"\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "fail \"str\" must be a TypeMismatch, got {r:?}"
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
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
        let Some((m, mut i)) = parsed else { return };
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
                   main =\n    f 1\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        assert!(r.is_ok(), "well-typed if must infer: {r:?}");
        let Ok(solved) = r else { return };
        let f = def_key(&i, &m, "f").expect("f must be defined in canon");
        let f_ty = solved.env.get(&f);
        assert!(
            matches!(f_ty, Some(Ty::Fun(..))),
            "f must have an arrow type, got {f_ty:?}"
        );
        let Some(Ty::Fun(arg, ret)) = f_ty else {
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
                   main =\n    f 1\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    f 1\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    apply (\\(Just x) -> x)\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    f 9 (1, 2)\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("redundant branch is a warning (IPE-T0011), not an error");
        assert_eq!(
            types.warnings.len(),
            1,
            "expected exactly one warning, got {:?}",
            types.warnings
        );
        let warning = types
            .warnings
            .first()
            .map(HomedWarning::diagnostic)
            .expect("len==1 asserted above");
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
                   main =\n    name Red\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    name Red\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    label Blue\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("a per-alternative redundancy is a warning, not an error");
        let redundant: Vec<_> = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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
                   main =\n    f Green\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("an internally-redundant or-pattern is a warning, not an error");
        let redundant = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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
                   main =\n    0\n";
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
                   main =\n    0\n";
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                        main =\n    if isRed Green then 1 else 0\n";
        #[allow(clippy::expect_used)] // a fixture that fails to link is a broken test, never a skip
        let (m, mut i) = link_modules(&[("Lib", lib_src), ("Main", main_src)])
            .expect("fixture modules parse, canonicalise, and link");
        let r = infer_attributed(&m, &mut i);
        assert!(
            matches!(r, Err(InferError::Sited { .. })),
            "a closed-union catch-all must fail compilation, sited, got {r:?}"
        );
        let Err(InferError::Sited { diag: err, home }) = r else {
            return;
        };
        let Ok(lib) = i.intern("Lib") else {
            return;
        };
        assert_eq!(
            home.path(),
            [lib].as_slice(),
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

    /// A redundant branch (IPE-T0011) in a NON-entry module is a warning homed
    /// at that module and spanned at the redundant arm's pattern.
    #[test]
    fn redundant_branch_warning_in_imported_module_carries_its_home_and_arm_span() {
        let lib_src = "module Lib exposing (Color(..), label)\n\n\
                       type Color = Red | Green\n\n\
                       label : Color -> Int\n\
                       label c =\n    case c of\n        Red ->\n            1\n\n        \
                       Green ->\n            2\n\n        \
                       Red ->\n            3\n";
        let main_src = "module Main exposing (main)\n\n\
                        import Lib exposing (Color(..), label)\n\n\
                        main =\n    label Green\n";
        #[allow(clippy::expect_used)] // a fixture that fails to link is a broken test, never a skip
        let (m, mut i) = link_modules(&[("Lib", lib_src), ("Main", main_src)])
            .expect("fixture modules parse, canonicalise, and link");
        #[allow(clippy::expect_used)] // a redundant branch is a warning; an `Err` fails the test
        let types = infer_attributed(&m, &mut i).expect("a redundant branch is only a warning");
        #[allow(clippy::expect_used)] // interning a short literal cannot exhaust the interner
        let lib = i.intern("Lib").expect("intern Lib");
        assert_eq!(
            types.warnings.len(),
            1,
            "expected exactly one warning, got {:?}",
            types.warnings
        );
        let Some(warning) = types.warnings.first() else {
            return;
        };
        assert_eq!(
            warning.home(),
            [lib].as_slice(),
            "the warning must carry the owning module's home"
        );
        assert!(
            matches!(
                warning.diagnostic(),
                Diagnostic::Type {
                    msg: TypeError::RedundantCaseBranch { .. },
                    ..
                }
            ),
            "expected IPE-T0011 RedundantCaseBranch, got {warning:?}"
        );
        let Diagnostic::Type { span, .. } = warning.diagnostic() else {
            return;
        };
        let arm_offset = lib_src.rfind("Red ->").and_then(|o| u32::try_from(o).ok());
        assert_eq!(
            Some(span.lo),
            arm_offset,
            "the warning must point at the redundant `Red` arm in Lib"
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("fully-covered wildcard is a warning (IPE-T0011), not an error");
        let t0018: Vec<_> = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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
            .map(HomedWarning::diagnostic)
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("exhaustive explicit case must type-check");
        let t0018: Vec<_> = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("wildcard on Int must type-check");
        let t0018: Vec<_> = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("wildcard on Bool must type-check");
        let t0018 = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("wildcard on List must type-check");
        let t0018 = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let types = infer(&m, &mut i)
            .expect("`Debug._` is the dev-only escape hatch — it type-checks (no IPE-T0018)");
        let t0018 = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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
                   wrap a b =\n        a ++ b\n\
                   main =\n    step Reset 0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("an exhaustive, non-redundant program must type-check");
        let redundant: Vec<_> = types
            .warnings
            .iter()
            .map(HomedWarning::diagnostic)
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

        let home = vec![interner.intern("Main").expect("intern Main")];
        let msg_var = uf.fresh(Content::Flex).expect("fresh msg var");
        let cfg_tail_var = uf
            .fresh(Content::Structure(FlatType::EmptyRecord))
            .expect("fresh cfg tail");
        let check = RoutedWebCheck {
            model_var,
            msg_var,
            not_found_var,
            cfg_tail_var,
            span: Span::DUMMY,
            home: ModuleHome::new(home.clone()).expect("a non-empty home"),
        };
        let mut warnings: Vec<HomedWarning> = Vec::new();
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
        let homed = warnings.first().expect("len==1 asserted above");
        assert_eq!(
            homed.home(),
            home.as_slice(),
            "the warning carries the home of its `Web.tea` call"
        );
        let w = homed.diagnostic();
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

        let msg_var = uf.fresh(Content::Flex).expect("fresh msg var");
        let cfg_tail_var = uf
            .fresh(Content::Structure(FlatType::EmptyRecord))
            .expect("fresh cfg tail");
        let check = RoutedWebCheck {
            model_var,
            msg_var,
            not_found_var,
            cfg_tail_var,
            span: Span::DUMMY,
            home: ModuleHome::new(vec![interner.intern("Main").expect("intern Main")])
                .expect("a non-empty home"),
        };
        let mut warnings: Vec<HomedWarning> = Vec::new();
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

    /// A routed-check fixture: a closed Model `{ <field> : page }` (or
    /// `{ count : _ }` when `routed` is false), a cfg tail `{ onNavigate : nav }`
    /// when `nav` is given, and a `Web.tea` check over them.
    fn on_navigate_fixture(
        interner: &mut Interner,
        uf: &mut UnionFind<Content>,
        routed: bool,
        nav: Option<FlatType>,
    ) -> (RoutedWebCheck, VarId, VarId) {
        let field = interner
            .intern(if routed { "page" } else { "count" })
            .expect("intern field");
        let page_var = uf
            .fresh(Content::Structure(FlatType::Unit))
            .expect("fresh page var");
        let model_ext = uf
            .fresh(Content::Structure(FlatType::EmptyRecord))
            .expect("fresh model ext");
        let model_var = uf
            .fresh(Content::Structure(FlatType::Record(
                BTreeMap::from([(field, page_var)]),
                model_ext,
            )))
            .expect("fresh model var");
        let msg_var = uf.fresh(Content::Flex).expect("fresh msg var");
        let not_found_var = uf.fresh(Content::Flex).expect("fresh notFound var");
        let empty = uf
            .fresh(Content::Structure(FlatType::EmptyRecord))
            .expect("fresh empty tail");
        let cfg_tail_var = nav.map_or(empty, |shape| {
            let nav_var = uf.fresh(Content::Structure(shape)).expect("fresh nav");
            let nav_sym = interner.intern("onNavigate").expect("intern onNavigate");
            uf.fresh(Content::Structure(FlatType::Record(
                BTreeMap::from([(nav_sym, nav_var)]),
                empty,
            )))
            .expect("fresh cfg tail")
        });
        let check = RoutedWebCheck {
            model_var,
            msg_var,
            not_found_var,
            cfg_tail_var,
            span: Span::DUMMY,
            home: ModuleHome::new(vec![interner.intern("Main").expect("intern Main")])
                .expect("a non-empty home"),
        };
        (check, page_var, msg_var)
    }

    fn run_routed_check(
        interner: &Interner,
        uf: &mut UnionFind<Content>,
        check: RoutedWebCheck,
    ) -> Result<(), InferError> {
        let mut budget = Budget::unbounded();
        let mut warnings: Vec<HomedWarning> = Vec::new();
        resolve_routed_web_checks(
            uf,
            &mut budget,
            interner,
            &[check],
            /* has_routes */ true,
            /* route_count */ 1,
            &mut warnings,
        )
    }

    /// In a routed app `onNavigate` is typed `Page -> Msg`: a well-typed one
    /// passes and fixes the message type.
    #[test]
    fn routed_on_navigate_is_typed_page_to_msg() {
        let mut interner = Interner::new();
        let mut uf = UnionFind::new();
        let nav_arg = uf.fresh(Content::Flex).expect("fresh arg");
        let nav_ret = uf.fresh(Content::Flex).expect("fresh ret");
        let (check, page_var, msg_var) = on_navigate_fixture(
            &mut interner,
            &mut uf,
            true,
            Some(FlatType::Fun(nav_arg, nav_ret)),
        );
        run_routed_check(&interner, &mut uf, check).expect("a Page -> Msg onNavigate type-checks");
        assert_eq!(
            uf.find(nav_arg).ok(),
            uf.find(page_var).ok(),
            "argument is the page"
        );
        assert_eq!(
            uf.find(nav_ret).ok(),
            uf.find(msg_var).ok(),
            "result is the Msg"
        );
    }

    /// A routed app's `onNavigate` that is not a function is IPE-T0001.
    #[test]
    fn routed_on_navigate_of_wrong_type_is_refused() {
        let mut interner = Interner::new();
        let mut uf = UnionFind::new();
        let (check, _, _) = on_navigate_fixture(&mut interner, &mut uf, true, Some(FlatType::Unit));
        let result = run_routed_check(&interner, &mut uf, check);
        assert!(
            matches!(
                result,
                Err(InferError::Sited {
                    diag: Diagnostic::Type { .. },
                    ..
                })
            ),
            "a non-function onNavigate must be a type mismatch, got {result:?}"
        );
    }

    /// An unrouted app (no `page` field) that sets `onNavigate` is IPE-L0162.
    #[test]
    fn unrouted_on_navigate_is_refused() {
        let mut interner = Interner::new();
        let mut uf = UnionFind::new();
        let arg = uf.fresh(Content::Flex).expect("fresh arg");
        let ret = uf.fresh(Content::Flex).expect("fresh ret");
        let (check, _, _) =
            on_navigate_fixture(&mut interner, &mut uf, false, Some(FlatType::Fun(arg, ret)));
        let result = run_routed_check(&interner, &mut uf, check);
        assert!(
            matches!(
                result,
                Err(InferError::Sited {
                    diag: Diagnostic::Lower {
                        msg: LowerError::OnNavigateWithoutPage,
                        ..
                    },
                    ..
                })
            ),
            "onNavigate without a page field must be refused, got {result:?}"
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        let types = r.expect("redundant branch is a warning (IPE-T0011), not an error");
        assert_eq!(
            types.warnings.len(),
            1,
            "expected exactly one warning, got {:?}",
            types.warnings
        );
        let warning = types
            .warnings
            .first()
            .map(HomedWarning::diagnostic)
            .expect("len==1 asserted above");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
        let (m, mut i) = canon_golden().expect("golden fixture must parse and canonicalise");
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
        let (m, mut i) = canon_src(source).expect("fixture must parse and canonicalise");
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
        let (m, mut i) = canon_src(source).expect("fixture must parse and canonicalise");
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

    /// Module header for the deferred-base tests. The compiled-source stdlib
    /// modules (`Ipe.List`, `Ipe.Maybe`) do not canonicalise in this crate, so
    /// the higher-order-kernel callback-result shapes are pinned end to end in
    /// `negative_suite.rs` and `g_misc/golden_lambda_field_access_seal.rs`.
    const DEFERRED_HDR: &str = "module Main exposing (ok)\n\n";

    /// Infer `body` under [`DEFERRED_HDR`], returning the result.
    fn infer_deferred(body: &str) -> DResult<SolvedTypes> {
        let (solved, ..) = infer_src(&format!("{DEFERRED_HDR}{body}"));
        solved
    }

    /// Whether `r` is a type error satisfying `is_msg`.
    fn is_type_error(r: &DResult<SolvedTypes>, is_msg: fn(&TypeError) -> bool) -> bool {
        matches!(r, Err(Diagnostic::Type { msg, .. }) if is_msg(msg))
    }

    /// A record of one `depth`-read chain `r.f.f…f` beside `riders` reads
    /// `sK.a`, each on its own never-settled parameter.
    fn chain_with_riders(depth: usize, riders: usize) -> String {
        let params = (0..riders)
            .map(|k| format!(" s{k}"))
            .collect::<Vec<_>>()
            .concat();
        let reads = (0..riders)
            .map(|k| format!(", a{k} = s{k}.a"))
            .collect::<Vec<_>>()
            .concat();
        format!(
            "{DEFERRED_HDR}ok r{params} =\n    {{ c = r{}{reads} }}\n",
            ".f".repeat(depth)
        )
    }

    /// The fewest solver steps `src` infers within; `None` when it fails for a
    /// reason other than the budget, or needs more than `2^20` steps.
    fn min_solver_steps(src: &str) -> Option<u64> {
        let fits = |steps: u64| -> Option<bool> {
            let (m, mut i) = canon_src(src)?;
            match infer_with_budget(&m, &mut i, &mut Budget::new(steps)) {
                Ok(_) => Some(true),
                Err(Diagnostic::Type {
                    msg: TypeError::StepBudgetExceeded { .. },
                    ..
                }) => Some(false),
                Err(_) => None,
            }
        };
        let (mut lo, mut hi) = (0_u64, 1_u64 << 20);
        if !fits(hi)? {
            return None;
        }
        // `lo` does not fit, `hi` fits.
        while hi.checked_sub(lo)? > 1 {
            let mid = lo.checked_add(hi.checked_sub(lo)? / 2)?;
            if fits(mid)? {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        Some(hi)
    }

    #[test]
    fn deferred_fixpoint_charges_the_solver_budget() {
        // The chain settles one base per pass, so the deferred fixpoint runs
        // about `2 * depth` passes, and a rider read whose base nothing settles
        // is revisited on every one of them. Each visit is a solver step, so the
        // budget bounds the fixpoint's work, not only the unifications inside
        // it: the riders cost at least `riders * depth` steps over the chain
        // alone, where their own unifications cost a constant each.
        let (depth, riders) = (64_usize, 8_usize);
        let alone = min_solver_steps(&chain_with_riders(depth, 0));
        let ridden = min_solver_steps(&chain_with_riders(depth, riders));
        assert!(
            alone.is_some() && ridden.is_some(),
            "both chains must infer under some budget: {alone:?} {ridden:?}"
        );
        let (Some(alone), Some(ridden)) = (alone, ridden) else {
            return;
        };
        let floor = u64::try_from(riders * depth).unwrap_or(u64::MAX);
        assert!(
            ridden.saturating_sub(alone) >= floor,
            "{riders} riders over a {depth}-deep chain cost {} steps, under {floor}",
            ridden.saturating_sub(alone)
        );
    }

    #[test]
    fn field_access_on_number_super_is_no_such_field() {
        // A `number` super can never be a record, so the access is decided at
        // once rather than deferred.
        let r = infer_deferred("ok n =\n    n + n.x\n");
        assert!(
            is_type_error(&r, |m| matches!(m, TypeError::NoSuchField { .. })),
            "a field on a number super must be NoSuchField, got {r:?}"
        );
    }

    #[test]
    fn self_referential_access_is_infinite_type() {
        // The access's result is its own base: the no-progress settle goes
        // through `unify`, whose occurs check refuses the cyclic record.
        let r = infer_deferred("ok r =\n    ok r.next\n");
        assert!(
            is_type_error(&r, |m| matches!(m, TypeError::InfiniteType { .. })),
            "a self-referential field access must be InfiniteType, got {r:?}"
        );
    }

    #[test]
    fn self_referential_grow_open_is_infinite_type() {
        // `r.a` settles `r` to an open record; `r.next` then grows it with a
        // field whose type is `r` itself — refused before the write.
        let r = infer_deferred("ok r =\n    let a = r.a in ok r.next\n");
        assert!(
            is_type_error(&r, |m| matches!(m, TypeError::InfiniteType { .. })),
            "a self-referential grown field must be InfiniteType, got {r:?}"
        );
    }

    #[test]
    fn super_pinned_to_containing_structure_is_infinite_type() {
        // The equality super `a` would pin to `List a`: an infinite type, not a
        // solver spin to the step budget.
        let r = infer_deferred("ok a =\n    a == [ a ]\n");
        assert!(
            is_type_error(&r, |m| matches!(m, TypeError::InfiniteType { .. })),
            "a super pinned to a structure containing it must be InfiniteType, got {r:?}"
        );
    }

    #[test]
    fn equality_on_a_deferred_record_base_is_order_independent() {
        // `a` owes equality and settles to `{ x : Int }` only in the deferred
        // pass; the verdict must not depend on which operand was constrained
        // first.
        let fwd = infer_deferred("ok a =\n    a.x == 1 && a == a\n");
        assert!(
            fwd.is_ok(),
            "field read before equality must infer: {fwd:?}"
        );
        let rev = infer_deferred("ok a =\n    a == a && a.x == 1\n");
        assert!(
            rev.is_ok(),
            "equality before field read must infer: {rev:?}"
        );
    }

    #[test]
    fn pinned_super_check_sees_a_later_default() {
        // `p == p` is constrained before `n + 1` makes `n` numeric: the deep
        // equality check on `{ x = n }` must read `n` after it defaults to
        // `Int`, exactly as the reversed spelling does.
        let rev = infer_deferred("ok n =\n    (let p = { x = n } in p == p) && n + 1 > 0\n");
        assert!(
            rev.is_ok(),
            "equality before the numeric use must infer: {rev:?}"
        );
        let fwd = infer_deferred("ok n =\n    n + 1 > 0 && (let p = { x = n } in p == p)\n");
        assert!(
            fwd.is_ok(),
            "numeric use before equality must infer: {fwd:?}"
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
        let (m, mut i) = canon_src(source).expect("fixture must parse and canonicalise");
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
        let (m, mut i) = canon_src(source).expect("fixture must parse and canonicalise");
        assert!(
            infer(&m, &mut i).is_err(),
            "updating a field to a value of the wrong type must be a type error"
        );
    }

    #[test]
    fn updating_a_field_on_a_non_record_is_no_such_field() {
        // `p` is an `Int`, so `{ p | x = 1 }` has no field to update (IPE-T0012).
        let source = "module Main exposing (v)\nv =\n    let p = 5 in { p | x = 1 }\n";
        let (m, mut i) = canon_src(source).expect("fixture must parse and canonicalise");
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
        let (m, mut i) = canon_src(source).expect("fixture must parse and canonicalise");
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
                   main =\n    useInt\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "identity used at Int and Bool in one module must infer: {r:?}"
        );
        let Ok(solved) = r else { return };
        // The two consumers settle at their concrete result types.
        let use_int = def_key(&i, &m, "useInt").expect("useInt must be defined in canon");
        let use_bool = def_key(&i, &m, "useBool").expect("useBool must be defined in canon");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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

    /// Seal: `Auth.signToken` claims are pinned to `Dict String String`, not a
    /// flexible variable that would unify with a record literal and accept a
    /// program the emitted `HashMap<String,String>`-pinned wrapper cannot
    /// build. A `Dict String String` claims argument type-checks clean; a
    /// record literal is refused at type-check.
    #[test]
    fn auth_sign_token_claims_pinned_to_dict_string_string() {
        // Both kernels resolve through their explicit imports and `Dict` is a
        // builtin type, so both fixtures canonicalise without the compiled
        // stdlib and the refusal is inference's own.
        let ok_src = "module Main exposing (sign)\n\n\
             import Ipe.Auth as Auth\n\
             import Ipe.Secret as Secret\n\n\
             sign : Dict String String -> Result Error String\n\
             sign claims =\n    Auth.signToken (Secret.fromString \"s\") claims 3600\n";
        let (m, mut i) = canon_src(ok_src).expect("the Dict-claims fixture must canonicalise");
        let solved = infer(&m, &mut i);
        assert!(
            solved.is_ok(),
            "Auth.signToken with Dict String String claims must type-check clean: {solved:?}"
        );

        let bad_src = "module Main exposing (bad)\n\n\
             import Ipe.Auth as Auth\n\
             import Ipe.Secret as Secret\n\n\
             bad : Result Error String\n\
             bad =\n    Auth.signToken (Secret.fromString \"s\") { sub = \"x\" } 3600\n";
        let (m2, mut i2) = canon_src(bad_src).expect("the record-claims fixture must canonicalise");
        let solved = infer(&m2, &mut i2);
        assert!(
            matches!(solved, Err(Diagnostic::Type { .. })),
            "Auth.signToken with a RECORD claims argument must be REJECTED at type-check \
             (a flexible claims variable would accept a shape the emitted \
             HashMap<String,String>-pinned wrapper cannot build): {solved:?}"
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
                   main =\n    useInt\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
        let r = infer(&m, &mut i);
        assert!(
            matches!(
                r,
                Err(Diagnostic::Type {
                    msg: TypeError::TypeMismatch { .. },
                    ..
                })
            ),
            "an unannotated binding used at Int and Bool must be rejected (monomorphic) \
             with a TypeMismatch, got {r:?}"
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
                   main =\n    double 21\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    maxOf 3 7\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    double 21\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
                   main =\n    0\n";
        let (m, mut i) = canon_src(src).expect("fixture must parse and canonicalise");
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
             main =\n    listLen [ 90, 35 ]\n",
        );
        let (m, mut i) = link_modules(&[lib, main])
            .expect("multi-module fixture must parse, canonicalise, and link");
        let r = infer(&m, &mut i);
        assert!(
            r.is_ok(),
            "a polymorphic-list-element cross-module untyped def must typecheck: {r:?}"
        );
        let Ok(solved) = r else { return };
        let lib1 = i.intern("Lib1").expect("intern Lib1");
        let list_len = i.intern("listLen").expect("intern listLen");
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

        let (m, mut i) = link_modules(&[lib, main])
            .expect("multi-module fixture must parse, canonicalise, and link");

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

        let main_home = ModuleHome::new(vec![i.intern("Main").expect("intern Main")]);

        // First run establishes the blamed span + home; every subsequent run
        // must reproduce them byte-for-byte.
        let mut settled: Option<(Span, Option<ModuleHome>)> = None;
        for run in 0..50 {
            let mut budget = Budget::from_env();
            let err = infer_with_budget_attributed(&m, &mut i, &mut budget)
                .expect_err("Wrap stamp (Int vs Stamp) must be a type error");
            let home = err.home().cloned();
            let diag = err.into_diagnostic();

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
    /// with `describe x = Debug.log "x" x` — a `Stringify` obligation on `a` —
    /// instantiated to `someFn : Int -> Int`. Without the gate's `Show` clause
    /// the backend would emit `fn describe<T0: IpeStringify>(..)` fed a
    /// closure — an E0277 at `cargo`.
    ///
    /// Driven directly against `super_bounds_satisfied` (like
    /// [`every_bound_bit_rejects_a_function_at_both_sites`]) rather than through
    /// a stdlib call: the single-module inference harness canonicalises `Main`
    /// with no stdlib in scope, so a qualified stdlib call dies at
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

    /// `true` iff inference refused the program with the interpolation
    /// IPE-T0014 — a canonicalisation error or any other refusal is `false`, so
    /// a test asserting this cannot pass vacuously.
    fn refused_as_not_interpolable(solved: &DResult<SolvedTypes>) -> bool {
        matches!(
            solved,
            Err(Diagnostic::Type {
                msg: TypeError::SuperTypeUnsatisfied { class, .. },
                ..
            }) if &**class == ipe_diagnostics::INTERPOLABLE_CLASS
        )
    }

    /// Every non-scalar value interpolated with `{{…}}` is refused at type-check
    /// (IPE-T0014): a record, a custom type, a `Maybe Int` and a `List String`.
    /// None of them reaches a Debug rendering or an unbounded Rust generic.
    #[test]
    fn interpolating_a_non_scalar_is_refused() {
        for (what, decls) in [
            ("a record", "v =\n    { x = 1 }\n"),
            ("a custom type", "type Color = Red | Blue\n\nv =\n    Red\n"),
            ("a Maybe Int", "v =\n    Just 1\n"),
            ("a List String", "v =\n    [ \"a\" ]\n"),
        ] {
            let src = format!("{M2C_HDR}{decls}\nmain =\n    \"\"\"v={{{{v}}}}\"\"\"\n");
            let (solved, _i, _m) = infer_src(&src);
            assert!(
                refused_as_not_interpolable(&solved),
                "interpolating {what} must be refused as not interpolable: {solved:?}"
            );
        }
    }

    /// A generic that interpolates its argument carries the interpolation
    /// obligation to every caller: instantiating it at a record is refused at
    /// the use site, exactly as a direct `{{record}}` is.
    #[test]
    fn interpolating_generic_used_at_a_record_is_refused() {
        let src = format!(
            "{M2C_HDR}describe : a -> String\ndescribe x =\n    \"\"\"<{{{{x}}}}>\"\"\"\n\n\
             main =\n    describe {{ x = 1 }}\n"
        );
        let (solved, _i, _m) = infer_src(&src);
        assert!(
            refused_as_not_interpolable(&solved),
            "an interpolating generic used at a record must be refused: {solved:?}"
        );
    }

    /// The acceptance side: each of the five interpolable scalars type-checks.
    #[test]
    fn interpolating_each_scalar_is_accepted() {
        let src = format!(
            "{M2C_HDR}s =\n    \"text\"\n\nn =\n    1\n\nf =\n    1.5\n\nb =\n    True\n\n\
             c =\n    'x'\n\n\
             main =\n    \"\"\"{{{{s}}}} {{{{n}}}} {{{{f}}}} {{{{b}}}} {{{{c}}}}\"\"\"\n"
        );
        let (solved, _i, _m) = infer_src(&src);
        assert!(
            solved.is_ok(),
            "String, Int, Float, Bool and Char must all interpolate: {solved:?}"
        );
    }

    // ── Signature wildcard `any`: bounds and pins held at every use ─────────

    /// A helper whose signature-wildcard parameter is interpolated: the
    /// `{{…}}` kernel lays the same interpolation obligation on the wildcard
    /// a `Log.*With` attribute element does, with no module import.
    const INTERP_ANY: &str = r#"f : any -> String
f x =
    """<{{x}}>"""
"#;

    /// A helper whose body pins its wildcard parameter to `Int` by numeric
    /// defaulting.
    const PIN_INT: &str = r"h : any -> Bool
h x =
    x + x == x
";

    /// The result of one module's scoped solve ([`infer_module`]).
    type ScopedResult = Result<ModuleInference, InferError>;

    /// Scoped-solve each module over its predecessors' closed interfaces.
    ///
    /// Entries are dependency-first `(dotted module path, source)` pairs, as
    /// in [`link_modules`]; a module whose interface is closed is offered to
    /// the later ones. Returns every module's result in order, or `None` when
    /// one fails to parse or canonicalise.
    fn infer_scoped(modules_src: &[(&str, &str)]) -> Option<Vec<ScopedResult>> {
        let mut i = Interner::new();
        let mut exports_by_path: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let mut interfaces: BTreeMap<Vec<Symbol>, Arc<TypedInterface>> = BTreeMap::new();
        let mut results = Vec::new();
        for (path_str, src) in modules_src {
            let path: Vec<Symbol> = path_str
                .split('.')
                .map(|seg| i.intern(seg))
                .collect::<DResult<Vec<Symbol>>>()
                .ok()?;
            let parsed = ipe_parse::parse_module(src, &mut i).ok()?;
            let (cm, exports) =
                ipe_canon::canonicalise_module(&parsed, &path, &exports_by_path, &mut i).ok()?;
            let result = infer_module(&cm, &exports, &interfaces, &mut i);
            if let Ok(ModuleInference {
                interface:
                    InterfaceStatus::Closed(iface) | InterfaceStatus::ImporterDependent(iface),
                ..
            }) = &result
            {
                interfaces.insert(path.clone(), Arc::new(iface.clone()));
            }
            exports_by_path.insert(path, exports);
            results.push(result);
        }
        Some(results)
    }

    /// `true` iff inference refused the program with a type mismatch.
    fn refused_as_mismatch(solved: &DResult<SolvedTypes>) -> bool {
        matches!(
            solved,
            Err(Diagnostic::Type {
                msg: TypeError::TypeMismatch { .. },
                ..
            })
        )
    }

    /// The solved wildcard facts `solved` recorded for the binding `name`.
    fn signature_wildcards_of<'s>(
        solved: &'s SolvedTypes,
        i: &mut Interner,
        name: &str,
    ) -> Option<&'s SignatureWildcards> {
        let sym = i.intern(name).ok()?;
        solved
            .signature_wildcards
            .iter()
            .find(|((_, n), _)| *n == sym)
            .map(|(_, w)| w)
    }

    /// `true` iff the scoped solve closed the first module's interface and
    /// refused the second with a type diagnostic `refused` accepts.
    fn scoped_refuses_importer(
        results: &[ScopedResult],
        refused: impl Fn(&TypeError) -> bool,
    ) -> bool {
        matches!(
            results.first(),
            Some(Ok(ModuleInference {
                interface: InterfaceStatus::Closed(_),
                ..
            }))
        ) && matches!(
            results.get(1),
            Some(Err(InferError::Sited {
                diag: Diagnostic::Type { msg, .. },
                ..
            })) if refused(msg)
        )
    }

    /// `true` iff `msg` is the interpolation IPE-T0014 refusal.
    fn is_not_interpolable(msg: &TypeError) -> bool {
        matches!(
            msg,
            TypeError::SuperTypeUnsatisfied { class, .. }
                if &**class == ipe_diagnostics::INTERPOLABLE_CLASS
        )
    }

    /// `true` iff `sig` pins wildcard 0 to the nullary primitive `prim`.
    fn pins_wildcard_zero_to(sig: Option<&SignatureWildcards>, i: &Interner, prim: &str) -> bool {
        sig.and_then(|w| w.pins.get(&0)).is_some_and(|t| {
            matches!(t, Ty::Con { name, args, .. }
                if args.is_empty() && i.resolve(*name) == Some(prim))
        })
    }

    /// A record or a function value passed through an interpolating wildcard
    /// is refused at the use site, exactly as a direct `{{…}}` of it is.
    #[test]
    fn interpolating_wildcard_refuses_a_record_or_function_argument() {
        for (what, arg) in [("a record", "{ x = 1 }"), ("a function", "(\\n -> n)")] {
            let src = format!("{M2C_HDR}{INTERP_ANY}\nmain =\n    f {arg}\n");
            let (solved, _i, _m) = infer_src(&src);
            assert!(
                refused_as_not_interpolable(&solved),
                "{what} through an interpolating `any` must be refused: {solved:?}"
            );
        }
    }

    /// The same refusal holds when the wildcard helper lives in another
    /// module — through the linked whole-program solve and through the scoped
    /// per-module solve over the helper's interface alike.
    #[test]
    fn interpolating_wildcard_refuses_a_record_or_function_across_modules() {
        let lib_src = format!("module Lib exposing (f)\n\n{INTERP_ANY}");
        for (what, arg) in [("a record", "{ x = 1 }"), ("a function", "(\\n -> n)")] {
            let main_src = format!("{M2C_HDR}import Lib exposing (f)\n\nmain =\n    f {arg}\n");
            let modules = [("Lib", lib_src.as_str()), ("Main", main_src.as_str())];
            let (m, mut i) = link_modules(&modules).expect("the two-module fixture must link");
            let solved = infer(&m, &mut i);
            assert!(
                refused_as_not_interpolable(&solved),
                "{what} through an imported interpolating `any` must be refused: {solved:?}"
            );
            let results = infer_scoped(&modules).expect("the two-module fixture must canonicalise");
            assert!(
                scoped_refuses_importer(&results, is_not_interpolable),
                "{what}: the scoped solve must close the helper and refuse the use: {results:?}"
            );
        }
    }

    /// The acceptance side: a scalar passes, and the helper records its
    /// wildcard's interpolation obligation under `any#0` with no pin — the
    /// fact the lowerer bounds the emitted generic on.
    #[test]
    fn interpolating_wildcard_records_its_bound_and_accepts_a_scalar() {
        let src = format!("{M2C_HDR}{INTERP_ANY}\nmain =\n    f \"s\"\n");
        let (solved, mut i, _m) = infer_src(&src);
        let solved = solved.expect("`f \"s\"` must type-check");
        let f_sym = i.intern("f").expect("intern `f`");
        let bounds = solved
            .bounds
            .iter()
            .find(|((_, n), _)| *n == f_sym)
            .map(|(_, b)| b)
            .expect("`f` must record a bound");
        let wildcard_bounds: Vec<(Option<usize>, TyBounds)> = bounds
            .iter()
            .map(|(k, b)| (wildcard_bound_index(&i, *k), *b))
            .collect();
        assert!(
            matches!(wildcard_bounds.as_slice(), [(Some(0), b)] if b.has_interpolable()),
            "`f` must bound exactly wildcard 0 as interpolable: {wildcard_bounds:?}"
        );
        let sig = signature_wildcards_of(&solved, &mut i, "f");
        assert!(
            matches!(sig, Some(w) if w.param_counts == [1] && w.pins.is_empty()),
            "`f` has one unpinned parameter wildcard: {sig:?}"
        );
    }

    /// A wildcard forwarded into an interpolating wildcard carries no proof it
    /// is interpolable at the forwarding site, so the forwarding use is
    /// refused rather than emitted against an unbounded generic.
    #[test]
    fn wildcard_forwarded_into_an_interpolating_wildcard_is_refused() {
        let src = format!(
            "{M2C_HDR}{INTERP_ANY}\ng : any -> String\ng y =\n    f y\n\nmain =\n    g \"s\"\n"
        );
        let (solved, _i, _m) = infer_src(&src);
        assert!(
            refused_as_not_interpolable(&solved),
            "forwarding one `any` into an interpolating `any` must be refused: {solved:?}"
        );
    }

    /// A function value meeting an interpolation obligation inside one body —
    /// a list element beside an interpolated wildcard, or an untyped top-level
    /// function value under `{{…}}` — is refused where the two unify.
    #[test]
    fn interpolation_obligation_refuses_a_function_during_unification() {
        for (what, src) in [
            (
                "a list element beside a wildcard",
                format!(
                    "{M2C_HDR}f : any -> String\nf x =\n    \
                     let ys = [ x, (\\n -> n) ] in \"\"\"<{{{{x}}}}>\"\"\"\n\n\
                     main =\n    f \"s\"\n"
                ),
            ),
            (
                "an untyped function value",
                format!("{M2C_HDR}v =\n    \\n -> n\n\nmain =\n    \"\"\"v={{{{v}}}}\"\"\"\n"),
            ),
        ] {
            let (solved, _i, _m) = infer_src(&src);
            assert!(
                refused_as_not_interpolable(&solved),
                "{what} under an interpolation obligation must be refused: {solved:?}"
            );
        }
    }

    /// A wildcard the body pins to `Int` lowers to `Int`, so a `Float` use is
    /// refused while an `Int` use is accepted and the pin is recorded.
    #[test]
    fn body_pinned_wildcard_holds_every_use_to_its_pin() {
        let bad = format!("{M2C_HDR}{PIN_INT}\nmain =\n    h 1.5\n");
        let (solved, _i, _m) = infer_src(&bad);
        assert!(
            refused_as_mismatch(&solved),
            "`h 1.5` against an `Int`-pinned wildcard must be refused: {solved:?}"
        );
        let good = format!("{M2C_HDR}{PIN_INT}\nmain =\n    h 0\n");
        let (solved, mut i, _m) = infer_src(&good);
        let solved = solved.expect("`h 0` must type-check");
        let sig = signature_wildcards_of(&solved, &mut i, "h").cloned();
        assert!(
            pins_wildcard_zero_to(sig.as_ref(), &i, "Int"),
            "`h` must pin wildcard 0 to `Int`: {sig:?}"
        );
    }

    /// A wildcard a concretely-typed operation pins to `String` (`++` against
    /// a `String` literal — the same unification a `String`-typed kernel
    /// argument performs) refuses an `Int` use, while a `String` use is
    /// accepted and the pin is recorded.
    #[test]
    fn concretely_pinned_wildcard_refuses_another_type() {
        const PIN_STRING: &str = "f : any -> String\nf x =\n    x ++ \"!\"\n";
        let bad = format!("{M2C_HDR}{PIN_STRING}\nmain =\n    f 3\n");
        let (solved, _i, _m) = infer_src(&bad);
        assert!(
            refused_as_mismatch(&solved),
            "`f 3` against a `String`-pinned wildcard must be refused: {solved:?}"
        );
        let good = format!("{M2C_HDR}{PIN_STRING}\nmain =\n    f \"s\"\n");
        let (solved, mut i, _m) = infer_src(&good);
        let solved = solved.expect("`f \"s\"` must type-check");
        let sig = signature_wildcards_of(&solved, &mut i, "f").cloned();
        assert!(
            pins_wildcard_zero_to(sig.as_ref(), &i, "String"),
            "`f` must pin wildcard 0 to `String`: {sig:?}"
        );
    }

    /// A pinned wildcard in another module holds the importer's use to the pin,
    /// through the linked solve and through the interface in the scoped solve.
    #[test]
    fn body_pinned_wildcard_is_held_across_modules() {
        let lib_src = format!("module Lib exposing (h)\n\n{PIN_INT}");
        let main_src = format!("{M2C_HDR}import Lib exposing (h)\n\nmain =\n    h 1.5\n");
        let modules = [("Lib", lib_src.as_str()), ("Main", main_src.as_str())];
        let (m, mut i) = link_modules(&modules).expect("the two-module fixture must link");
        let solved = infer(&m, &mut i);
        assert!(
            refused_as_mismatch(&solved),
            "an imported `Int`-pinned wildcard used at `Float` must be refused: {solved:?}"
        );
        let results = infer_scoped(&modules).expect("the two-module fixture must canonicalise");
        let lib_pins = match results.first() {
            Some(Ok(ModuleInference {
                interface: InterfaceStatus::Closed(iface),
                ..
            })) => iface
                .values
                .values()
                .map(|scheme| scheme.wildcard_pins.len())
                .sum::<usize>(),
            _ => 0,
        };
        assert_eq!(
            lib_pins, 1,
            "the helper's interface must carry its pin: {results:?}"
        );
        assert!(
            scoped_refuses_importer(&results, |msg| matches!(
                msg,
                TypeError::TypeMismatch { .. }
            )),
            "the scoped solve must refuse the mismatched use too: {results:?}"
        );
    }

    /// A SQL-parameter wildcard is no pin: it stays a generic bounded on the
    /// bind-parameter obligation, so one helper binds an `Int` and a `String`.
    #[test]
    fn sql_param_wildcard_is_used_at_two_types() {
        let src = "module Main exposing (useBoth)\n\nimport Ipe.Db as Db\n\n\
             insertOne : Db -> any -> Task Error Int\n\
             insertOne conn v =\n    Db.exec conn \"INSERT INTO t (v) VALUES (?)\" [ v ]\n\n\
             useBoth : Db -> List (Task Error Int)\n\
             useBoth conn =\n    [ insertOne conn \"s\", insertOne conn 1 ]\n";
        let (solved, mut i, _m) = infer_src(src);
        let solved = solved.expect("the two-type use must type-check");
        let sig = signature_wildcards_of(&solved, &mut i, "insertOne");
        assert!(
            matches!(sig, Some(w) if w.param_counts == [0, 1] && w.pins.is_empty()),
            "`insertOne`'s wildcard must stay unpinned: {sig:?}"
        );
        assert!(
            sole_bound(&solved, &mut i, "insertOne").is_some_and(TyBounds::has_sql_param),
            "`insertOne`'s wildcard must carry the SQL-parameter obligation"
        );
    }

    /// The IPE-T0021 dependence `solved` refused its binding with, if any.
    fn wildcard_refusal(solved: &DResult<SolvedTypes>) -> Option<(usize, &WildcardDependence)> {
        match solved {
            Err(Diagnostic::Type {
                msg:
                    TypeError::WildcardNotIndependent {
                        parameter,
                        dependence,
                    },
                ..
            }) => Some((*parameter, dependence)),
            _ => None,
        }
    }

    /// A parameter wildcard the body unifies with a signature type variable is
    /// that variable, never an independent generic, so the binding is refused
    /// and the diagnostic names the variable.
    #[test]
    fn wildcard_tied_to_a_type_variable_is_refused() {
        let src = format!(
            "{M2C_HDR}k : a -> any -> List a\nk x y =\n    [ x, y ]\n\nmain =\n    k 1 2\n"
        );
        let (solved, _i, _m) = infer_src(&src);
        assert!(
            matches!(
                wildcard_refusal(&solved),
                Some((2, WildcardDependence::TypeVariable { name: Some(n) })) if &**n == "a"
            ),
            "a wildcard unified with `a` must be refused as IPE-T0021: {solved:?}"
        );
    }

    /// Two parameter wildcards the body unifies with each other are one type,
    /// so the later one is refused as shared with the earlier parameter.
    #[test]
    fn wildcards_aliased_to_each_other_are_refused() {
        let src =
            format!("{M2C_HDR}g : any -> any -> Bool\ng x y =\n    x == y\n\nmain =\n    g 1 2\n");
        let (solved, _i, _m) = infer_src(&src);
        assert!(
            matches!(
                wildcard_refusal(&solved),
                Some((2, WildcardDependence::SharedWith { parameter: 1 }))
            ),
            "two aliased wildcards must be refused as IPE-T0021: {solved:?}"
        );
    }

    /// A wildcard the body solves to a structure that still holds a free
    /// variable or an open record row — bare, nested in `List any`, a record
    /// nested in a tuple, or a bare record whose field is not ground — has no
    /// single lowering, so the binding is refused.
    #[test]
    fn wildcard_solved_to_a_partial_structure_is_refused() {
        for (what, def, parameter) in [
            (
                "a tuple with an open slot",
                "f : any -> Int\nf p =\n    case p of\n        ( a, _ ) ->\n            a + 1\n",
                1,
            ),
            (
                "a nested tuple with an open slot",
                "f : List any -> Bool\nf xs =\n    case xs of\n        [ ( a, _ ) ] ->\n            a\n\n        _ ->\n            False\n",
                1,
            ),
            (
                "a record nested in a tuple",
                "f : any -> Int\nf p =\n    case p of\n        ( a, r ) ->\n            a + r.x\n",
                1,
            ),
            (
                "a nested record read through a tuple after a concrete parameter",
                "f : Int -> any -> Int\nf n p =\n    case p of\n        ( a, r ) ->\n            n + a + r.x\n",
                2,
            ),
            (
                "a bare record whose field holds a tuple with an open slot",
                "f : any -> Int\nf p =\n    case p.pair of\n        ( a, _ ) ->\n            a + 1\n",
                1,
            ),
            (
                "a bare record whose field is an open record",
                "f : any -> Int\nf p =\n    p.inner.y + 1\n",
                1,
            ),
        ] {
            let src = format!("{M2C_HDR}{def}\nmain =\n    0\n");
            let (solved, _i, _m) = infer_src(&src);
            assert!(
                matches!(
                    wildcard_refusal(&solved),
                    Some((p, WildcardDependence::PartialStructure { .. })) if p == parameter
                ),
                "{what} must be refused as IPE-T0021: {solved:?}"
            );
        }
    }

    /// The acceptance side: an identity wildcard threaded to the return, two
    /// independent wildcards, two wildcards the body pins to the same ground
    /// type, and a bare record wildcard the body field-reads all type-check.
    #[test]
    fn independent_threaded_or_pinned_wildcards_are_accepted() {
        for (what, def, use_) in [
            (
                "an identity",
                "thread : any -> any\nthread x =\n    x\n",
                "thread 1",
            ),
            (
                "two independent wildcards",
                "constFn : any -> any -> Int\nconstFn x y =\n    0\n",
                "constFn 1 \"s\"",
            ),
            (
                "two wildcards pinned to one ground type",
                "add : any -> any -> Int\nadd x y =\n    x + y + 1\n",
                "add 1 2",
            ),
            (
                "a field-read bare record",
                "getName : any -> String\ngetName p =\n    p.name\n",
                "getName { name = \"a\", age = 1 }",
            ),
        ] {
            let src = format!("{M2C_HDR}{def}\nmain =\n    {use_}\n");
            let (solved, _i, _m) = infer_src(&src);
            assert!(solved.is_ok(), "{what} must type-check: {solved:?}");
        }
    }

    /// Two wildcards the body pins to one ground type each record that pin.
    #[test]
    fn wildcards_sharing_a_ground_root_are_both_pinned() {
        let src = format!(
            "{M2C_HDR}add : any -> any -> Int\nadd x y =\n    x + y + 1\n\nmain =\n    add 1 2\n"
        );
        let (solved, mut i, _m) = infer_src(&src);
        let solved = solved.expect("`add 1 2` must type-check");
        let sig = signature_wildcards_of(&solved, &mut i, "add");
        assert!(
            matches!(sig, Some(w) if w.param_counts == [1, 1] && w.pins.len() == 2),
            "`add` must pin both wildcards: {sig:?}"
        );
    }

    /// Groundness admits closed records of ground fields and refuses a bare
    /// variable, an open row, and a variable nested in a record field.
    #[test]
    fn ty_is_ground_refuses_variables_and_open_rows() {
        let mut i = Interner::new();
        let x = i.intern("x").expect("intern a field name");
        let int_ty = Ty::Con {
            module: Vec::new(),
            name: i.intern("Int").expect("intern a primitive name"),
            args: Vec::new(),
        };
        let record = |field: Ty, tail: RowTail| Ty::Record(BTreeMap::from([(x, field)]), tail);
        assert!(ty_is_ground(&record(int_ty.clone(), RowTail::Closed)));
        assert!(ty_is_ground(&Ty::Tuple(vec![int_ty.clone(), Ty::Unit])));
        assert!(!ty_is_ground(&Ty::Var(0)));
        assert!(!ty_is_ground(&record(int_ty.clone(), RowTail::Open(1))));
        assert!(!ty_is_ground(&record(Ty::Var(2), RowTail::Closed)));
        assert!(!ty_is_ground(&Ty::Tuple(vec![
            int_ty,
            record(Ty::Unit, RowTail::Open(3))
        ])));
    }

    /// The gate itself: the interpolation obligation admits exactly the scalar
    /// primitives, and refuses `Unit`, a `List Int` and a bare variable at both
    /// use sites.
    #[test]
    fn interpolable_gate_admits_only_the_scalars() {
        let mut i = Interner::new();
        let mut prim = |name: &str, args: Vec<Ty>| Ty::Con {
            module: Vec::new(),
            name: i.intern(name).expect("intern a primitive name"),
            args,
        };
        let int_ty = prim("Int", Vec::new());
        let string_ty = prim("String", Vec::new());
        let char_ty = prim("Char", Vec::new());
        let unit_ty = prim("Unit", Vec::new());
        let list_int = prim("List", vec![int_ty.clone()]);
        let var_ty = Ty::Var(0);
        let no_fn_enums = |_home: &[Symbol], _name: Symbol| false;
        let bounds = TyBounds::interpolable();
        for site in [
            super_bounds::BoundSite::EmittedGeneric,
            super_bounds::BoundSite::ConcretePin,
        ] {
            for ok in [&int_ty, &string_ty, &char_ty] {
                assert!(
                    super_bounds_satisfied(&i, bounds, ok, site, &no_fn_enums),
                    "{ok:?} must be interpolable at {site:?}"
                );
            }
            for bad in [&unit_ty, &list_int, &var_ty] {
                assert!(
                    !super_bounds_satisfied(&i, bounds, bad, site, &no_fn_enums),
                    "{bad:?} must not be interpolable at {site:?}"
                );
            }
        }
    }
}

#[cfg(test)]
mod canonicalize_tests {
    use super::*;
    use ipe_diagnostics::{NameError, ParseError};
    use std::num::NonZeroU32;

    fn syms<const N: usize>(names: [&str; N]) -> Result<[Symbol; N], String> {
        let mut interner = Interner::new();
        let minted = names
            .iter()
            .map(|name| interner.intern(name).map_err(|e| format!("{e:?}")))
            .collect::<Result<Vec<_>, _>>()?;
        minted
            .try_into()
            .map_err(|_| "symbol count drifted".to_owned())
    }

    const fn empty() -> SolvedTypes {
        SolvedTypes {
            env: BTreeMap::new(),
            regions: BTreeMap::new(),
            expected: BTreeMap::new(),
            bounds: BTreeMap::new(),
            warnings: Vec::new(),
            poly_var_map: BTreeMap::new(),
            untyped_type_params: BTreeMap::new(),
            msg_defaulted_vars: BTreeMap::new(),
            signature_wildcards: BTreeMap::new(),
        }
    }

    /// The `Ty::Var` of solver variable `id`.
    const fn tv(id: u32) -> Ty {
        Ty::Var(SolverVar::from_var(id).raw())
    }

    const fn at(lo: u32) -> Span {
        Span { lo, hi: lo + 1 }
    }

    fn ceiling(n: u32) -> Result<VarCeiling, String> {
        NonZeroU32::new(n)
            .map(VarCeiling::at_most)
            .ok_or_else(|| "zero ceiling".to_owned())
    }

    fn run(
        types: SolvedTypes,
        scope: VarScope,
        ceiling: VarCeiling,
    ) -> Result<CanonicalTypes, String> {
        canonicalize(types, scope, ceiling).map_err(|e| format!("{e:?}"))
    }

    fn region_values(types: &CanonicalTypes) -> Vec<Ty> {
        types.regions.values().cloned().collect()
    }

    /// Equal raws in two modules are one variable under `Program` and two under `PerHome`.
    ///
    /// The two scopes therefore disagree exactly when a variable is shared
    /// between modules, which is what makes an equality oracle between a
    /// joint solve and a per-module merge catch cross-module sharing.
    #[test]
    fn a_variable_shared_between_homes_numbers_differently_per_scope() -> Result<(), String> {
        let [a, b] = syms(["A", "B"])?;
        let mut shared = empty();
        shared.regions.insert((vec![a], at(0)), tv(5));
        shared.regions.insert((vec![b], at(0)), tv(5));

        let program = run(shared.clone(), VarScope::Program, VarCeiling::SOLVER)?;
        let per_home = run(shared, VarScope::PerHome, VarCeiling::SOLVER)?;
        assert_eq!(region_values(&program), vec![tv(0), tv(0)]);
        assert_eq!(region_values(&per_home), vec![tv(0), tv(1)]);
        assert_ne!(program, per_home);

        let mut distinct = empty();
        distinct.regions.insert((vec![a], at(0)), tv(5));
        distinct.regions.insert((vec![b], at(0)), tv(6));
        assert_eq!(
            run(distinct.clone(), VarScope::Program, VarCeiling::SOLVER)?,
            run(distinct, VarScope::PerHome, VarCeiling::SOLVER)?,
            "without sharing the two scopes agree"
        );
        Ok(())
    }

    /// More distinct variables than the ceiling admits is refused, never wrapped or saturated.
    #[test]
    fn a_program_with_more_variables_than_the_ceiling_is_refused() -> Result<(), String> {
        let [a, f] = syms(["A", "f"])?;
        let mut types = empty();
        types.regions.insert((vec![a], at(0)), tv(1));
        types.regions.insert((vec![a], at(1)), tv(2));
        types.regions.insert((vec![a], at(2)), tv(3));

        let refused = canonicalize(types.clone(), VarScope::Program, ceiling(2)?);
        assert_eq!(refused, Err(CanonicalizeError::VarSpaceExhausted));
        assert!(canonicalize(types, VarScope::Program, ceiling(3)?).is_ok());

        let mut keyed = empty();
        keyed.poly_var_map.insert(
            (vec![a], f),
            BTreeMap::from([
                (SolverVar::from_var(1), f),
                (SolverVar::from_var(2), f),
                (SolverVar::from_var(3), f),
            ]),
        );
        assert_eq!(
            canonicalize(keyed, VarScope::Program, ceiling(2)?),
            Err(CanonicalizeError::VarSpaceExhausted),
            "a `poly_var_map` key counts against the ceiling"
        );
        Ok(())
    }

    /// A `poly_var_map` key is renumbered through the table its region types use.
    #[test]
    fn poly_var_keys_and_region_vars_share_one_table() -> Result<(), String> {
        let [a, f, g, name] = syms(["A", "f", "g", "t"])?;
        let mut types = empty();
        types
            .regions
            .insert((vec![a], at(0)), Ty::Fun(Box::new(tv(9)), Box::new(tv(4))));
        types.poly_var_map.insert(
            (vec![a], f),
            BTreeMap::from([(SolverVar::from_var(4), name)]),
        );
        types.poly_var_map.insert(
            (vec![a], g),
            BTreeMap::from([(SolverVar::from_var(77), name)]),
        );

        let canonical = run(types, VarScope::PerHome, VarCeiling::SOLVER)?;
        assert_eq!(
            region_values(&canonical),
            vec![Ty::Fun(Box::new(tv(0)), Box::new(tv(1)))]
        );
        let keys_of = |def: Symbol| -> Vec<SolverVar> {
            canonical
                .poly_var_map
                .get(&(vec![a], def))
                .map(|vars| vars.keys().copied().collect())
                .unwrap_or_default()
        };
        assert_eq!(
            keys_of(f),
            vec![SolverVar::from_var(1)],
            "the key stays the variable its region type names"
        );
        assert_eq!(
            keys_of(g),
            vec![SolverVar::from_var(2)],
            "a key no region names takes the next fresh id"
        );
        Ok(())
    }

    /// An annotation-symbol raw is kept and takes no dense id; a row tail shares the variable table.
    #[test]
    fn untagged_raws_are_kept_and_row_tails_are_renumbered() -> Result<(), String> {
        let [a, field, con] = syms(["A", "x", "T"])?;
        let mut types = empty();
        types.regions.insert(
            (vec![a], at(0)),
            Ty::Con {
                module: Vec::new(),
                name: con,
                args: vec![Ty::Var(7), tv(3)],
            },
        );
        types.regions.insert(
            (vec![a], at(1)),
            Ty::Record(
                BTreeMap::from([(field, tv(4))]),
                RowTail::Open(SolverVar::from_var(4).raw()),
            ),
        );
        types.regions.insert(
            (vec![a], at(2)),
            Ty::Record(BTreeMap::new(), RowTail::Open(8)),
        );

        let canonical = run(types, VarScope::PerHome, VarCeiling::SOLVER)?;
        assert_eq!(
            region_values(&canonical),
            vec![
                Ty::Con {
                    module: Vec::new(),
                    name: con,
                    args: vec![Ty::Var(7), tv(0)],
                },
                Ty::Record(
                    BTreeMap::from([(field, tv(1))]),
                    RowTail::Open(SolverVar::from_var(1).raw()),
                ),
                Ty::Record(BTreeMap::new(), RowTail::Open(8)),
            ]
        );
        Ok(())
    }

    /// Two programs that differ only in their raw solver ids canonicalize equal, and the form is a fixed point.
    #[test]
    fn canonical_form_ignores_raw_ids_and_is_idempotent() -> Result<(), String> {
        let [a, f, name] = syms(["A", "f", "t"])?;
        let build = |first: u32, second: u32| {
            let mut types = empty();
            types.regions.insert(
                (vec![a], at(0)),
                Ty::Fun(Box::new(tv(first)), Box::new(tv(second))),
            );
            types.poly_var_map.insert(
                (vec![a], f),
                BTreeMap::from([(SolverVar::from_var(second), name)]),
            );
            types
        };
        let one = run(build(5, 9), VarScope::PerHome, VarCeiling::SOLVER)?;
        let other = run(build(100, 3), VarScope::PerHome, VarCeiling::SOLVER)?;
        assert_eq!(one, other);
        let again = run(
            one.as_solved().clone(),
            VarScope::PerHome,
            VarCeiling::SOLVER,
        )?;
        assert_eq!(one, again);
        Ok(())
    }

    /// Every var-bearing position is renumbered through the one table, in the documented traversal order.
    ///
    /// `env`, `regions`, `expected`, the `signature_wildcards` pins and the
    /// `poly_var_map` keys each hold one distinct variable, numbered so the
    /// traversal meets them in reverse raw order: a skipped position keeps
    /// its raw and a reordered traversal assigns a different dense id.
    #[test]
    fn every_var_position_is_renumbered_in_traversal_order() -> Result<(), String> {
        let [a, f, name] = syms(["A", "f", "t"])?;
        let mut types = empty();
        types.env.insert((vec![a], f), tv(50));
        types.regions.insert((vec![a], at(0)), tv(40));
        types.expected.insert((vec![a], at(0)), tv(30));
        types.signature_wildcards.insert(
            (vec![a], f),
            SignatureWildcards {
                param_counts: vec![1],
                pins: BTreeMap::from([(0, tv(20))]),
            },
        );
        types.poly_var_map.insert(
            (vec![a], f),
            BTreeMap::from([(SolverVar::from_var(10), name)]),
        );

        let canonical = run(types, VarScope::PerHome, VarCeiling::SOLVER)?;
        assert_eq!(
            canonical.env.values().cloned().collect::<Vec<_>>(),
            vec![tv(0)]
        );
        assert_eq!(region_values(&canonical), vec![tv(1)]);
        assert_eq!(
            canonical.expected.values().cloned().collect::<Vec<_>>(),
            vec![tv(2)]
        );
        assert_eq!(
            canonical
                .signature_wildcards
                .get(&(vec![a], f))
                .map(|wildcards| wildcards.pins.values().cloned().collect::<Vec<_>>()),
            Some(vec![tv(3)])
        );
        assert_eq!(
            canonical
                .poly_var_map
                .get(&(vec![a], f))
                .map(|vars| vars.keys().copied().collect::<Vec<_>>()),
            Some(vec![SolverVar::from_var(4)])
        );
        Ok(())
    }

    fn warning(diagnostic: Diagnostic, home: Symbol) -> Result<HomedWarning, String> {
        HomedWarning::new(diagnostic, &[home]).map_err(|e| format!("{e:?}"))
    }

    fn redundant(lo: u32, hi: u32) -> Diagnostic {
        Diagnostic::Type {
            span: Span { lo, hi },
            msg: TypeError::RedundantCaseBranch {
                constructor: "Red".into(),
            },
        }
    }

    /// Warnings come out ordered by home, then span, then code, whatever order they arrived in.
    #[test]
    fn warnings_are_sorted_by_home_span_then_code() -> Result<(), String> {
        let [a, b] = syms(["A", "B"])?;
        assert!(a < b, "the ordering below relies on interning order");
        let mut types = empty();
        let doc_warning = Diagnostic::Parse {
            span: Span { lo: 0, hi: 2 },
            msg: ParseError::DocOnUnexported { name: "f".into() },
        };
        let doc_code = doc_warning.code();
        let redundant_code = redundant(0, 1).code();
        assert_ne!(doc_code, redundant_code, "the tie-break needs two codes");
        types.warnings = vec![
            warning(redundant(0, 1), b)?,
            warning(redundant(5, 6), a)?,
            warning(redundant(0, 9), a)?,
            warning(redundant(0, 2), a)?,
            warning(doc_warning, a)?,
        ];
        let canonical = run(types, VarScope::Program, VarCeiling::SOLVER)?;
        let order: Vec<_> = canonical
            .warnings
            .iter()
            .map(|w| {
                let span = w.diagnostic().primary_span();
                let home = w.home().first().copied().unwrap_or(a);
                (home, span.lo, span.hi, w.diagnostic().code())
            })
            .collect();
        assert_eq!(
            order,
            vec![
                (a, 0, 2, doc_code),
                (a, 0, 2, redundant_code),
                (a, 0, 9, redundant_code),
                (a, 5, 6, redundant_code),
                (b, 0, 1, redundant_code),
            ]
        );
        Ok(())
    }

    /// Reads every field of each warning-severity variant with its concrete type.
    ///
    /// `canonicalize` carries warnings through without renumbering, so no
    /// payload may depend on solver-variable ids: the diagnostics crate cannot
    /// name [`Ty`], and a rendered type names its variables in first-seen order
    /// ([`VarNamer`]). Adding a field to one of these variants breaks this
    /// destructure (it names every field, with no `..`), so the new field has
    /// to be classified here before it can ship. A new warning variant is
    /// classified by [`Diagnostic::severity`], not here.
    fn warning_payload_is_ty_free(diagnostic: &Diagnostic) -> bool {
        match diagnostic {
            Diagnostic::Parse {
                span: _,
                msg: ParseError::DocOnUnexported { name } | ParseError::MissingDocString { name },
            } => {
                let _: &str = name;
                true
            }
            Diagnostic::Name {
                span: _,
                msg:
                    NameError::ScriptImportsShapeView {
                        shape_ui_module,
                        shape,
                        entry,
                    },
            } => {
                let _: [&str; 3] = [shape_ui_module, shape, entry];
                true
            }
            Diagnostic::Type {
                span: _,
                msg: TypeError::RedundantCaseBranch { constructor },
            } => {
                let _: &str = constructor;
                true
            }
            Diagnostic::Lower {
                span: _,
                msg: LowerError::RoutedAppMissingPageField { route_count },
            } => {
                let _: &usize = route_count;
                true
            }
            Diagnostic::Parse { .. }
            | Diagnostic::Name { .. }
            | Diagnostic::Type { .. }
            | Diagnostic::Lower { .. }
            | Diagnostic::CompilerBug { .. }
            | Diagnostic::Ffi { .. }
            | Diagnostic::Sandbox { .. }
            | Diagnostic::Consent { .. }
            | Diagnostic::RegistryUnreachable { .. } => false,
        }
    }

    /// Each of the five warning-severity variants is accepted as a warning and has a `Ty`-free payload.
    #[test]
    fn no_warning_variant_embeds_a_ty() -> Result<(), String> {
        let [home] = syms(["A"])?;
        let span = Span { lo: 0, hi: 1 };
        let warnings = [
            Diagnostic::Parse {
                span,
                msg: ParseError::DocOnUnexported { name: "f".into() },
            },
            Diagnostic::Parse {
                span,
                msg: ParseError::MissingDocString { name: "f".into() },
            },
            Diagnostic::Name {
                span,
                msg: NameError::ScriptImportsShapeView {
                    shape_ui_module: "M".into(),
                    shape: "S".into(),
                    entry: "e".into(),
                },
            },
            redundant(0, 1),
            Diagnostic::Lower {
                span,
                msg: LowerError::RoutedAppMissingPageField { route_count: 2 },
            },
        ];
        for diagnostic in warnings {
            assert!(warning_payload_is_ty_free(&diagnostic), "{diagnostic:?}");
            warning(diagnostic, home)?;
        }
        Ok(())
    }
}
