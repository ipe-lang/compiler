use super::{
    BTreeMap, BTreeSet, Budget, Builder, Builtins, Content, DResult, Diagnostic, FlatType,
    Generated, InferError, Interner, RefCell, RowTail, STAGE, SchemeKey, Span, StdlibKernel,
    Symbol, Ty, TypeError, UnionFind, VarId, ZONK_NODE_LIMIT, tag_solver_var, unify_at,
};
use ipe_diagnostics::TypeSizeOrigin;
use ipe_diagnostics::nesting::{TYPE_DEPTH_LIMIT, TYPE_LEVELS_PER_ARROW, TYPE_SIZE_LIMIT};

use crate::expansive::NominalLevels;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

// ===========================================================================
// Boundary Scheme Promotion — untyped top-level binding generalization.
//
// See `docs/adr/0001-language-semantics-and-types.md` for the
// full design. Summary: an unannotated top-level binding is monomorphic
// *within its home module* (unchanged), but is generalized into a scheme at
// its module's boundary, so each cross-module reference instantiates it
// fresh — exactly like an annotated (typed) binding already does via
// `instantiate_tracked`, except the scheme is *discovered* post-solve rather
// than declared. `promote_untyped_boundaries` (called once, between
// `solve_attributed` and `resolve_deferred`) drives this for the whole
// linked program, in module topo order.
// ===========================================================================

/// A generalized scheme for one untyped top-level binding, discovered at its
/// home module's boundary-discharge step.
///
/// `quantified` maps each generalized `Flex` root to its synthesized name
/// (`"a"`, `"b"`, …). Only plain, obligation-free `Flex` roots
/// are quantified in phase 1 — `Super`-bounded and `Rigid`-contaminated roots
/// stay shared program-wide (Divergences D2/D3 in the spec); a residual root
/// still reachable from a pending field-access / record-update / route
/// obligation is excluded too (the existing "single concrete use" gate
/// fallback stays intact for those defs).
pub struct UntypedScheme {
    /// The shared, home-module-monomorphic root every same-module reference
    /// (and, pre-discharge, the binding's own `untyped[key]` var) resolves to.
    pub root: VarId,
    /// Generalized root → synthesized type-variable name.
    pub quantified: BTreeMap<VarId, Symbol>,
}

/// Every untyped def's generalized scheme, keyed by `(home, name)`. Returned
/// by [`promote_untyped_boundaries`].
pub type UntypedSchemes = BTreeMap<(Vec<Symbol>, Symbol), UntypedScheme>;

pub const COPY_VAR_NODE_LIMIT: u32 = 4_096;

/// One step of the iterative [`copy_var`] work stack — the mirror image of
/// [`ZonkTask`]: instead of reading a settled UF node back into an owned
/// [`Ty`], it builds a *fresh* UF substructure over it.
pub enum CopyVarTask {
    Visit(VarId),
    BuildFun,
    BuildCon {
        module: Vec<Symbol>,
        name: Symbol,
        arity: usize,
    },
    BuildTuple {
        arity: usize,
    },
    BuildRecord {
        names: Vec<Symbol>,
    },
}

/// Instantiate a generalized untyped-def scheme at one use site.
///
/// A quantified root (per `quantified`) gets a fresh `Flex` per call — shared
/// via `fresh_map` so repeated occurrences of the same quantified var within
/// *this one* instantiation alpha-rename consistently (`fresh_map` must be
/// fresh per discharge, i.e. per cross-module reference, not shared across
/// references). Every other var — `Flex` not in `quantified`, `Super`,
/// `Rigid` — is returned as-is, unchanged: this is what makes a program with
/// no boundary-free untyped defs byte-identical to today, since nothing is
/// ever copied unless it was actually quantified. Every `Structure` node is
/// rebuilt with fresh children, including a **fresh** `EmptyRecord` sentinel
/// per closed record (mirrors `empty_record_tail`'s occurs-distinctness
/// rule) — this is a UF-level copy-walk, deliberately NOT a `Ty`-level reify
/// (`instantiate_in`), so it never needs to round-trip through a resolved
/// `Ty` (and its `AUD-13` solver-var tagging) at all.
///
/// **Iterative**, mirroring [`zonk`]: an explicit heap-allocated work stack,
/// so it never grows the native call stack regardless of how deep the
/// scheme's type is, budget-ticked per node and bounded by
/// [`COPY_VAR_NODE_LIMIT`] (stack-safety, not the DOS budget).
///
/// # Errors
/// [`Diagnostic::CompilerBug`] on a union-find invariant violation or if the
/// structure has more than [`COPY_VAR_NODE_LIMIT`] nodes;
/// [`TypeError::StepBudgetExceeded`] if the shared budget is exhausted.
#[allow(clippy::too_many_lines)] // one task-stack state machine, mirrors `zonk` — splitting would obscure the Visit/Build pairing
pub fn copy_var(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    var: VarId,
    quantified: &BTreeMap<VarId, Symbol>,
    fresh_map: &mut BTreeMap<VarId, VarId>,
) -> DResult<VarId> {
    let mut work: Vec<CopyVarTask> = vec![CopyVarTask::Visit(var)];
    let mut results: Vec<VarId> = Vec::new();
    let mut nodes_left = COPY_VAR_NODE_LIMIT;

    while let Some(task) = work.pop() {
        match task {
            CopyVarTask::Visit(v) => {
                budget.tick()?;
                nodes_left = nodes_left
                    .checked_sub(1)
                    .ok_or_else(|| Diagnostic::CompilerBug {
                        where_: STAGE,
                        detail: "type exceeded scheme-instantiation node limit".to_owned(),
                    })?;
                let root = uf.find(v)?;
                if let Some(&fresh) = fresh_map.get(&root) {
                    results.push(fresh);
                    continue;
                }
                match uf.content(root)? {
                    Content::Flex if quantified.contains_key(&root) => {
                        let fresh = uf.fresh(Content::Flex)?;
                        fresh_map.insert(root, fresh);
                        results.push(fresh);
                    }
                    Content::Flex | Content::Rigid | Content::Super { .. } => {
                        // Not quantified: shared program-wide, no copy.
                        fresh_map.insert(root, root);
                        results.push(root);
                    }
                    Content::Structure(FlatType::Unit) => {
                        results.push(uf.fresh(Content::Structure(FlatType::Unit))?);
                    }
                    Content::Structure(FlatType::EmptyRecord) => {
                        // A fresh sentinel per copy — same rationale as
                        // `empty_record_tail`: distinct closed records must
                        // stay distinguishable to a later occurs check.
                        results.push(uf.fresh(Content::Structure(FlatType::EmptyRecord))?);
                    }
                    Content::Structure(FlatType::Fun(a, b)) => {
                        work.push(CopyVarTask::BuildFun);
                        work.push(CopyVarTask::Visit(b));
                        work.push(CopyVarTask::Visit(a));
                    }
                    Content::Structure(FlatType::Con { module, name, args }) => {
                        let arity = args.len();
                        work.push(CopyVarTask::BuildCon {
                            module,
                            name,
                            arity,
                        });
                        for a in args.into_iter().rev() {
                            work.push(CopyVarTask::Visit(a));
                        }
                    }
                    Content::Structure(FlatType::Tuple(elems)) => {
                        let arity = elems.len();
                        work.push(CopyVarTask::BuildTuple { arity });
                        for e in elems.into_iter().rev() {
                            work.push(CopyVarTask::Visit(e));
                        }
                    }
                    Content::Structure(FlatType::Record(fields, ext)) => {
                        let names: Vec<Symbol> = fields.keys().copied().collect();
                        work.push(CopyVarTask::BuildRecord { names });
                        work.push(CopyVarTask::Visit(ext));
                        for v in fields.values().copied().rev() {
                            work.push(CopyVarTask::Visit(v));
                        }
                    }
                }
            }
            CopyVarTask::BuildFun => {
                let (Some(b), Some(a)) = (results.pop(), results.pop()) else {
                    return Err(copy_var_underflow());
                };
                results.push(uf.fresh(Content::Structure(FlatType::Fun(a, b)))?);
            }
            CopyVarTask::BuildCon {
                module,
                name,
                arity,
            } => {
                let split = results
                    .len()
                    .checked_sub(arity)
                    .ok_or_else(copy_var_underflow)?;
                let args = results.split_off(split);
                results.push(uf.fresh(Content::Structure(FlatType::Con { module, name, args }))?);
            }
            CopyVarTask::BuildTuple { arity } => {
                let split = results
                    .len()
                    .checked_sub(arity)
                    .ok_or_else(copy_var_underflow)?;
                let elems = results.split_off(split);
                results.push(uf.fresh(Content::Structure(FlatType::Tuple(elems)))?);
            }
            CopyVarTask::BuildRecord { names } => {
                let Some(ext) = results.pop() else {
                    return Err(copy_var_underflow());
                };
                let split = results
                    .len()
                    .checked_sub(names.len())
                    .ok_or_else(copy_var_underflow)?;
                let vals = results.split_off(split);
                let fields: BTreeMap<Symbol, VarId> = names.into_iter().zip(vals).collect();
                results.push(uf.fresh(Content::Structure(FlatType::Record(fields, ext)))?);
            }
        }
    }

    match results.pop() {
        Some(v) if results.is_empty() => Ok(v),
        _ => Err(copy_var_underflow()),
    }
}

/// The work-stack invariant was violated (only reachable via a compiler bug in
/// `copy_var` itself, never from input).
pub fn copy_var_underflow() -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: STAGE,
        detail: "copy_var result stack underflow".to_owned(),
    }
}

/// Every `Flex`-content root structurally reachable from `root` (through
/// `Structure` children only — `Flex`/`Rigid`/`Super` are leaves), collected
/// as UF representatives. The traversal shape mirrors `unify::occurs`
/// exactly (iterative, explicit stack, budget-ticked per node), just
/// collecting instead of comparing against a target.
///
/// Used by `promote_untyped_boundaries` to find an untyped binding's
/// generalization *candidates* — the actual quantified set additionally
/// excludes any root still reachable from a pending deferred obligation (see
/// callers).
pub fn reachable_flex_roots(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    root: VarId,
) -> DResult<std::collections::BTreeSet<VarId>> {
    let mut seen: std::collections::BTreeSet<VarId> = std::collections::BTreeSet::new();
    let mut flex: std::collections::BTreeSet<VarId> = std::collections::BTreeSet::new();
    let mut stack = vec![root];
    while let Some(v) = stack.pop() {
        budget.tick()?;
        let here = uf.find(v)?;
        if !seen.insert(here) {
            continue;
        }
        match uf.content(here)? {
            Content::Flex => {
                flex.insert(here);
            }
            Content::Rigid
            | Content::Super { .. }
            | Content::Structure(FlatType::Unit | FlatType::EmptyRecord) => {}
            Content::Structure(FlatType::Fun(a, b)) => {
                stack.push(a);
                stack.push(b);
            }
            Content::Structure(FlatType::Con { args, .. }) => {
                for a in args {
                    stack.push(a);
                }
            }
            Content::Structure(FlatType::Tuple(elems)) => {
                for e in elems {
                    stack.push(e);
                }
            }
            Content::Structure(FlatType::Record(fields, ext)) => {
                for v in fields.values() {
                    stack.push(*v);
                }
                stack.push(ext);
            }
        }
    }
    Ok(flex)
}

/// Mint a fresh, source-collision-free type-variable name (`"a"`, `"b"`, …,
/// `"z"`, `"a1"`, …) for a generalized untyped-def scheme. `next` is the caller's shared
/// naming cursor, threaded across every quantified var of every scheme in one
/// `promote_untyped_boundaries` run so names stay distinct program-wide (not
/// required for soundness — each scheme's names only need to be distinct
/// *within* that scheme — but keeps `IPE_DEBUG_UNTYPED` dumps unambiguous).
pub fn mint_synth_symbol(interner: &mut Interner, next: &mut u32) -> DResult<Symbol> {
    loop {
        let candidate = crate::doc::letters(*next);
        *next = next.saturating_add(1);
        if !interner.contains(&candidate) {
            return interner.intern(&candidate);
        }
    }
}

/// Boundary Scheme Promotion — discharge every cross-module untyped-binding
/// reference and generalize every untyped def at its home module's boundary.
///
/// Runs once, over the WHOLE linked program, between `solve_attributed` and
/// `resolve_deferred` (see `docs/adr/0001-language-semantics-and-types.md`'s
/// algorithm section). Walks `module_order` (dependency-first topo order): for
/// each module, first discharges its own OUTGOING pending instantiations
/// (against schemes already computed for modules it depends on — always
/// present, since those modules precede it in `module_order`), then
/// generalizes its OWN untyped defs (recording their schemes for later
/// modules to discharge against).
///
/// Returns the generalized scheme for every `(home, name)` key `untyped`
/// covers (an entry with an empty `quantified` map means the def stayed
/// fully monomorphic — no boundary-free residual `Flex` root). The caller
/// folds this into `SolvedTypes::untyped_type_params` / `poly_var_map`.
///
/// # Errors
/// A cross-module reference's instantiated scheme failing to unify against
/// local call-site structure is a genuine `IPE-T0001`, blamed on the
/// referencing (`use_home`) module. A union-find invariant violation is a
/// whole-program [`InferError::Program`] carrying a `Diagnostic::CompilerBug`.
pub fn promote_untyped_boundaries(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &mut Interner,
    generated: &Generated,
) -> Result<UntypedSchemes, InferError> {
    macro_rules! lift {
        ($e:expr) => {
            $e.map_err(InferError::unsited)?
        };
    }

    // Roots still reachable from a still-pending deferred obligation are
    // excluded from quantification — the existing "single concrete use" gate
    // fallback for these defs stays intact (test matrix item 6; D2/D3-style
    // conservative under-acceptance). Computed once, globally: every one of
    // these obligations is still pending at this point in the pipeline (this
    // pass runs BEFORE `resolve_deferred`), regardless of which module owns
    // which untyped def.
    let mut obligation_roots: std::collections::BTreeSet<VarId> = std::collections::BTreeSet::new();
    for fa in &generated.field_accesses {
        obligation_roots.insert(lift!(uf.find(fa.record)));
        // A simple getter's own result var (`fa.result`) IS the function's
        // return-type var — e.g. `getName r = r.name`. Excluding only
        // `fa.record` left `fa.result` a residual plain-`Flex` root, eligible
        // for quantification here even though `resolve_deferred` (which runs
        // AFTER this pass) is what pins it to the concrete field type. A
        // quantified-then-later-pinned var produced a Rust generic that
        // appeared in neither `params` nor `ret` — E0283 at the emitted
        // `cargo build` step. Confirmed by independent review as a real SEAL
        // violation on a 3-module cross-module field-access getter; see
        // BACKLOG.md's "Boundary Scheme Promotion" row.
        obligation_roots.insert(lift!(uf.find(fa.result)));
    }
    for ru in &generated.record_updates {
        obligation_roots.insert(lift!(uf.find(ru.record)));
        // Symmetric to `fa.result` above: each updated field's VALUE var is
        // pinned to the record's concrete field type by
        // [`crate::resolve_record_updates`], which runs AFTER this pass. At
        // this point it can still be a residual plain-`Flex` root (e.g. the
        // `n` parameter in `setName r n = { r | name = n }`), so without this
        // exclusion it would be quantified into the def's scheme and later
        // pinned — producing a stale quantified symbol that structurally
        // appears nowhere in the resolved `params`/`ret`. The lowerer's
        // `used_generics` filter independently strips such a symbol
        // (defense-in-depth, empirically verified), but the primary
        // obligation-exclusion mechanism must be complete in its own right.
        for &(_, value_var) in &ru.fields {
            obligation_roots.insert(lift!(uf.find(value_var)));
        }
    }
    for rw in &generated.route_witness_checks {
        obligation_roots.insert(lift!(uf.find(rw.builder_var)));
        obligation_roots.insert(lift!(uf.find(rw.page_var)));
    }
    for rl in &generated.routed_web_checks {
        obligation_roots.insert(lift!(uf.find(rl.model_var)));
        obligation_roots.insert(lift!(uf.find(rl.not_found_var)));
    }

    let mut schemes: UntypedSchemes = BTreeMap::new();
    // Shared naming cursor across every scheme in this run — see
    // `mint_synth_symbol`'s doc comment for why this is a convenience, not a
    // soundness requirement.
    let mut synth_next: u32 = 0;

    for home in &generated.module_order {
        // (a) Discharge this module's OUTGOING cross-module references.
        for pi in generated
            .pending_instantiations
            .iter()
            .filter(|pi| pi.use_home.path() == home.as_slice())
        {
            let Some(scheme) = schemes.get(&pi.source) else {
                // module_order is dependency-first, and a `PendingInstantiation`
                // only exists for a key already present in `untyped` — so the
                // source module always precedes `use_home` and always has a
                // scheme by now. Unreachable except via a link-order invariant
                // break; fail closed rather than panic.
                return Err(InferError::unsited(Diagnostic::CompilerBug {
                    where_: "ipe_types::promote_untyped_boundaries",
                    detail: "cross-module untyped reference discharged before its source \
                             module was generalized"
                        .to_owned(),
                }));
            };
            let root = scheme.root;
            let quantified = scheme.quantified.clone();
            let mut fresh_map = BTreeMap::new();
            let inst = copy_var(uf, budget, root, &quantified, &mut fresh_map)
                .map_err(|d| InferError::sited(d, &pi.use_home))?;
            unify_at(
                uf,
                budget,
                interner,
                &pi.use_home,
                pi.span,
                inst,
                pi.placeholder,
            )?;
        }

        // (b) Generalize this module's own untyped defs.
        for (key, def) in generated.untyped.iter().filter(|(k, _)| &k.0 == home) {
            let root = lift!(uf.find(def.var));
            let candidates = reachable_flex_roots(uf, budget, root)
                .map_err(|d| InferError::sited_at_path(d, &key.0))?;
            let mut quantified = BTreeMap::new();
            for r in candidates {
                if obligation_roots.contains(&r) {
                    continue;
                }
                let sym = lift!(mint_synth_symbol(interner, &mut synth_next));
                quantified.insert(r, sym);
            }
            schemes.insert(key.clone(), UntypedScheme { root, quantified });
        }
    }

    Ok(schemes)
}

/// One step of the iterative [`reify_scheme`] work stack.
///
/// The interface sibling of [`ZonkTask`]: quantified variables map to
/// CANONICAL tagged ids (deterministic, union-find-numbering-free), and an
/// open record tail is kept as `RowTail::Open` over that canonical id.
pub enum ReifyTask {
    Visit(VarId),
    BuildFun,
    BuildCon {
        module: Vec<Symbol>,
        name: Symbol,
        arity: usize,
    },
    BuildTuple {
        arity: usize,
    },
    BuildRecord {
        names: Vec<Symbol>,
        tail: RowTail,
    },
}

/// Reify one generalized untyped-binding scheme into an owned interface
/// [`Ty`], or report the scheme OPEN.
///
/// A quantified root becomes `Ty::Var(tag_solver_var(k))` where `k` is the
/// root's first-encounter index in this walk — canonical, so the same scheme
/// reifies to the same bytes regardless of union-find numbering (the
/// backdating property a typed interface exists for). A reachable residual
/// variable that is NOT quantified — a plain `Flex` sharable program-wide, a
/// `Super` obligation a later defaulting pass would conceal, a `Rigid`
/// contamination — makes the scheme OPEN (`Ok(None)`): its final type can
/// legitimately be pinned by an importer, so no per-module interface can
/// stand for it. Must run BEFORE numeric/SQL defaulting: defaulting pins
/// residual `Super` flexes to concrete types, which would disguise an open
/// scheme as closed and let a scoped solve disagree with the joint one.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] on a union-find invariant violation or a
/// structure over [`ZONK_NODE_LIMIT`] nodes; [`TypeError::StepBudgetExceeded`]
/// on budget exhaustion.
#[allow(clippy::too_many_lines)] // one task-stack state machine, mirrors `zonk` — splitting would obscure the Visit/Build pairing
pub fn reify_scheme(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    scheme: &UntypedScheme,
) -> DResult<Option<Ty>> {
    let mut work: Vec<ReifyTask> = vec![ReifyTask::Visit(scheme.root)];
    let mut results: Vec<Ty> = Vec::new();
    let mut canonical: BTreeMap<VarId, u32> = BTreeMap::new();
    let mut nodes_left = ZONK_NODE_LIMIT;

    let canonical_raw = |root: VarId, canonical: &mut BTreeMap<VarId, u32>| -> u32 {
        let next = u32::try_from(canonical.len()).unwrap_or(u32::MAX);
        tag_solver_var(*canonical.entry(root).or_insert(next))
    };

    while let Some(task) = work.pop() {
        match task {
            ReifyTask::Visit(v) => {
                budget.tick()?;
                nodes_left = nodes_left
                    .checked_sub(1)
                    .ok_or_else(|| Diagnostic::CompilerBug {
                        where_: STAGE,
                        detail: "type exceeded interface-reification node limit".to_owned(),
                    })?;
                let root = uf.find(v)?;
                match uf.content(root)? {
                    Content::Flex if scheme.quantified.contains_key(&root) => {
                        results.push(Ty::Var(canonical_raw(root, &mut canonical)));
                    }
                    // A residual non-quantified variable: an importer may
                    // still pin it, so the scheme is open.
                    Content::Flex | Content::Rigid | Content::Super { .. } => {
                        return Ok(None);
                    }
                    // `EmptyRecord` is only reachable on a direct call over a
                    // bare tail — records route tails through `BuildRecord`
                    // below — and falls back to `Ty::Unit` like `zonk` does.
                    Content::Structure(FlatType::Unit | FlatType::EmptyRecord) => {
                        results.push(Ty::Unit);
                    }
                    Content::Structure(FlatType::Fun(a, b)) => {
                        work.push(ReifyTask::BuildFun);
                        work.push(ReifyTask::Visit(b));
                        work.push(ReifyTask::Visit(a));
                    }
                    Content::Structure(FlatType::Con { module, name, args }) => {
                        let arity = args.len();
                        work.push(ReifyTask::BuildCon {
                            module,
                            name,
                            arity,
                        });
                        for a in args.into_iter().rev() {
                            work.push(ReifyTask::Visit(a));
                        }
                    }
                    Content::Structure(FlatType::Tuple(elems)) => {
                        let arity = elems.len();
                        work.push(ReifyTask::BuildTuple { arity });
                        for e in elems.into_iter().rev() {
                            work.push(ReifyTask::Visit(e));
                        }
                    }
                    Content::Structure(FlatType::Record(fields, ext)) => {
                        let names: Vec<Symbol> = fields.keys().copied().collect();
                        let ext_root = uf.find(ext)?;
                        let tail = match uf.content(ext_root)? {
                            Content::Structure(FlatType::EmptyRecord) => RowTail::Closed,
                            Content::Flex if scheme.quantified.contains_key(&ext_root) => {
                                RowTail::Open(canonical_raw(ext_root, &mut canonical))
                            }
                            // A residual open tail an importer could still
                            // grow — the scheme is open.
                            _ => return Ok(None),
                        };
                        work.push(ReifyTask::BuildRecord { names, tail });
                        for fv in fields.values().copied().rev() {
                            work.push(ReifyTask::Visit(fv));
                        }
                    }
                }
            }
            ReifyTask::BuildFun => {
                let (Some(b), Some(a)) = (results.pop(), results.pop()) else {
                    return Err(reify_underflow());
                };
                results.push(Ty::Fun(Box::new(a), Box::new(b)));
            }
            ReifyTask::BuildCon {
                module,
                name,
                arity,
            } => {
                let split = results
                    .len()
                    .checked_sub(arity)
                    .ok_or_else(reify_underflow)?;
                let args = results.split_off(split);
                results.push(Ty::Con { module, name, args });
            }
            ReifyTask::BuildTuple { arity } => {
                let split = results
                    .len()
                    .checked_sub(arity)
                    .ok_or_else(reify_underflow)?;
                let elems = results.split_off(split);
                results.push(Ty::Tuple(elems));
            }
            ReifyTask::BuildRecord { names, tail } => {
                let split = results
                    .len()
                    .checked_sub(names.len())
                    .ok_or_else(reify_underflow)?;
                let tys = results.split_off(split);
                let fields: BTreeMap<Symbol, Ty> = names.into_iter().zip(tys).collect();
                results.push(Ty::Record(fields, tail));
            }
        }
    }

    match results.pop() {
        Some(ty) if results.is_empty() => Ok(Some(ty)),
        _ => Err(reify_underflow()),
    }
}

/// The work-stack invariant was violated (only reachable via a compiler bug
/// in `reify_scheme` itself, never from input).
pub fn reify_underflow() -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: STAGE,
        detail: "reify_scheme result stack underflow".to_owned(),
    }
}

/// A single step of the iterative [`zonk`] work stack.
///
/// `Visit` reads one union-find node and pushes either a leaf result or the
/// `Build*` task plus its children's `Visit`s; the `Build*` tasks reassemble a
/// parent [`Ty`] once its children's results sit on the result stack.
pub enum ZonkTask {
    /// Resolve and read back one variable.
    Visit(VarId),
    /// Pop two results (`arg`, then `result`) and push a `Fun`.
    BuildFun,
    /// Pop `arity` results and push a `Con` over them.
    BuildCon {
        module: Vec<Symbol>,
        name: Symbol,
        arity: usize,
    },
    /// Pop `arity` results and push a `Tuple` over them.
    BuildTuple { arity: usize },
    /// Pop one result per field name (in `names` order) and push a `Record` over `tail`.
    ///
    /// The `names` are visited in their `BTreeMap` order, so popping in reverse
    /// pairs each result with its field name. `names` is the union of the
    /// fields along the whole row chain and `tail` is the chain's terminal
    /// ([`zonk_row`]).
    BuildRecord { names: Vec<Symbol>, tail: RowTail },
    /// Record the freshly assembled result on top of the stack as the read-back
    /// of union-find representative `root`, so a later visit to any variable
    /// sharing that representative reuses the cached [`Ty`] instead of walking
    /// the sub-structure again. This is what keeps a shared solver DAG from
    /// expanding as a tree. `start` is the unfolded count the walk had reached
    /// when `root` was first visited, so the cached subtree's own unfolded size
    /// is the count now minus `start`.
    Memoize { root: VarId, start: u64 },
}

/// Read back one union-find node during [`zonk`], driving the shared work
/// stack. Resolves `v` to its representative; a representative already in `memo`
/// is genuine sharing (the structure is acyclic), so its cached [`Ty`] is reused
/// without re-walking or re-charging the node budget, but charged its unfolded
/// size. A first visit charges one
/// node, then either produces a leaf `Ty` (also cached) or pushes the rebuild
/// task, a [`ZonkTask::Memoize`] to cache the assembled parent, and the
/// children's visits.
fn zonk_visit(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    reading: RowReading,
    v: VarId,
    walk: &mut ReadBackWalk,
    nodes_left: &mut u32,
) -> DResult<()> {
    let ReadBackWalk {
        work,
        results,
        memo,
        unfolded,
    } = walk;
    let root = uf.find(v)?;
    if let Some((cached, size)) = memo.get(&root) {
        // A representative already read back: reuse it. Sharing does not
        // re-consume the node budget, so that limit bounds the count of
        // distinct nodes. The clone is still an unfolded tree, so it is
        // charged its unfolded size, against the size ceiling and the shared
        // step budget alike.
        charge_unfolded(unfolded, *size)?;
        for _ in 1..*size {
            budget.tick()?;
        }
        results.push(cached.clone());
        return Ok(());
    }
    charge_node(nodes_left)?;
    let start = *unfolded;
    // Borrow the descriptor: leaf arms need no owned copy, and the structural
    // arms clone only the field they genuinely move into a rebuild task (the
    // module path, the record field names) rather than the whole descriptor.
    match uf.root_content(root)? {
        // A flexible, rigid, or super-typed variable that survives solving reads
        // back as a type variable named by its representative's id. (A
        // super-typed variable is still a variable; its obligations are read
        // separately when generalising — see [`crate::SolvedTypes::bounds`].)
        Content::Flex | Content::Rigid | Content::Super { .. } => {
            // Tag so this solver-representative id can never be mistaken for an
            // annotation-symbol raw if this zonked `Ty` is ever fed back
            // through instantiation.
            let ty = Ty::Var(tag_solver_var(root));
            charge_unfolded(unfolded, 1)?;
            memo.insert(root, (ty.clone(), 1));
            results.push(ty);
        }
        Content::Structure(FlatType::Unit) => {
            charge_unfolded(unfolded, 1)?;
            memo.insert(root, (Ty::Unit, 1));
            results.push(Ty::Unit);
        }
        Content::Structure(FlatType::Fun(a, b)) => {
            // Cache this representative once its children reassemble, then push
            // the rebuild and children so that `a` is visited before `b` and
            // lands lower on `results`.
            let (a, b) = (*a, *b);
            work.push(ZonkTask::Memoize { root, start });
            work.push(ZonkTask::BuildFun);
            work.push(ZonkTask::Visit(b));
            work.push(ZonkTask::Visit(a));
        }
        Content::Structure(FlatType::Con { module, name, args }) => {
            let arity = args.len();
            work.push(ZonkTask::Memoize { root, start });
            work.push(ZonkTask::BuildCon {
                module: module.clone(),
                name: *name,
                arity,
            });
            // Reverse so args land on `results` in source order.
            for a in args.iter().rev() {
                work.push(ZonkTask::Visit(*a));
            }
        }
        Content::Structure(FlatType::Tuple(elems)) => {
            let arity = elems.len();
            work.push(ZonkTask::Memoize { root, start });
            work.push(ZonkTask::BuildTuple { arity });
            // Reverse so elements land on `results` in source order.
            for e in elems.iter().rev() {
                work.push(ZonkTask::Visit(*e));
            }
        }
        Content::Structure(FlatType::Record(fields, ext)) => {
            // Merge the fields of the whole row chain and read its terminal as
            // the tail, then visit each merged field var in reverse so the
            // results land in the same order the names are popped.
            let (mut fields, ext) = (fields.clone(), *ext);
            let tail = zonk_row(uf, budget, reading, nodes_left, &mut fields, ext)?;
            let names: Vec<Symbol> = fields.keys().copied().collect();
            work.push(ZonkTask::Memoize { root, start });
            work.push(ZonkTask::BuildRecord { names, tail });
            for v in fields.values().rev() {
                work.push(ZonkTask::Visit(*v));
            }
        }
        Content::Structure(FlatType::EmptyRecord) => {
            // EmptyRecord is the closed-tail sentinel — it carries no children
            // and does not produce a `Ty` of its own. It should only appear as
            // the extension variable of a `FlatType::Record`, never as the root
            // type of a standalone expression. Push `Ty::Unit` as a safe fallback
            // so the work stack stays balanced (this arm is reachable if zonk is
            // called directly on an extension var, which does not happen in
            // normal code, but must not panic).
            charge_unfolded(unfolded, 1)?;
            memo.insert(root, (Ty::Unit, 1));
            results.push(Ty::Unit);
        }
    }
    Ok(())
}

/// Consume one of the per-call read-back nodes.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] once the [`ZONK_NODE_LIMIT`] nodes are spent.
fn charge_node(nodes_left: &mut u32) -> DResult<()> {
    *nodes_left = nodes_left
        .checked_sub(1)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: STAGE,
            detail: "type exceeded read-back node limit".to_owned(),
        })?;
    Ok(())
}

/// Add `size` read-back nodes to the walk's unfolded count.
///
/// # Errors
/// [`TypeError::TypeTooLarge`] once the count passes [`TYPE_SIZE_LIMIT`].
const fn charge_unfolded(unfolded: &mut u64, size: u64) -> DResult<()> {
    *unfolded = unfolded.saturating_add(size);
    if *unfolded > TYPE_SIZE_LIMIT {
        return Err(type_too_large(Span::DUMMY));
    }
    Ok(())
}

/// The refusal of a type that unfolds past [`TYPE_SIZE_LIMIT`], at `span`.
const fn type_too_large(span: Span) -> Diagnostic {
    Diagnostic::Type {
        span,
        msg: TypeError::TypeTooLarge {
            limit: TYPE_SIZE_LIMIT,
            origin: TypeSizeOrigin::Value,
        },
    }
}

/// How a read-back presents a record row that ends in a variable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RowReading {
    /// Every variable terminal is an open tail ([`zonk`]).
    Faithful,
    /// The record the backend emits ([`zonk_emitted`]).
    ///
    /// A record lowers to the struct of its known fields, so a residual
    /// non-rigid row (a `Flex`, or a non-rigid `Super`) is its zero-extension
    /// and reads closed. A rigid terminal is an annotation's row generic,
    /// emitted as a generic over an unknown rest, and stays open.
    Emitted,
}

/// Walk a record's row extension to its terminal, merging the fields along the chain.
///
/// The tail is [`RowTail::Closed`] exactly when the chain ends in
/// `EmptyRecord` (or, under [`RowReading::Emitted`], in a non-rigid
/// variable), and `RowTail::Open` over the terminal's tagged representative
/// exactly when it ends in any other variable; `fields` gains every
/// field of every record along the way. Each hop ticks the shared [`Budget`]
/// and consumes one read-back node, so a chain is bounded like any other
/// structure.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] when the chain ends in a non-row type, repeats
/// a label, or exceeds [`ZONK_NODE_LIMIT`] nodes; a step-budget error if the
/// shared budget is exhausted.
fn zonk_row(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    reading: RowReading,
    nodes_left: &mut u32,
    fields: &mut BTreeMap<Symbol, VarId>,
    ext: VarId,
) -> DResult<RowTail> {
    let mut ext = ext;
    loop {
        budget.tick()?;
        charge_node(nodes_left)?;
        let tail_root = uf.find(ext)?;
        ext = match uf.root_content(tail_root)? {
            Content::Structure(FlatType::EmptyRecord) => return Ok(RowTail::Closed),
            Content::Flex | Content::Super { rigid: false, .. }
                if reading == RowReading::Emitted =>
            {
                return Ok(RowTail::Closed);
            }
            Content::Flex | Content::Rigid | Content::Super { .. } => {
                return Ok(RowTail::Open(tag_solver_var(tail_root)));
            }
            Content::Structure(FlatType::Record(more, next)) => {
                for (name, var) in more {
                    if fields.insert(*name, *var).is_some() {
                        return Err(row_chain_bug("duplicate record label along a row chain"));
                    }
                }
                *next
            }
            Content::Structure(
                FlatType::Unit | FlatType::Fun(..) | FlatType::Con { .. } | FlatType::Tuple(_),
            ) => return Err(row_chain_bug("record row ends in a non-row type")),
        };
    }
}

/// A record row chain that is not a row: a label repeated along it, or a
/// non-row terminal.
///
/// Reachable from input while a row variable may also stand as a whole type
/// (`a` in `{ a | x : Int } -> a -> Int`): a caller binding it to a record
/// that repeats a chain label, or to a non-row type, builds such a chain. The
/// read-back refuses it, failing closed, rather than drop the clash.
fn row_chain_bug(detail: &str) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: STAGE,
        detail: detail.to_owned(),
    }
}

/// Read a settled union-find variable back into a resolved [`Ty`].
///
/// Called after [`crate::solve::solve`] has discharged every constraint. The
/// occurs check in unification guarantees the structure is acyclic, so the node
/// bound is only ever hit on adversarial input.
///
/// **Iterative.** The walk runs over an explicit heap-allocated work stack
/// (mirroring the iterative `find` in `unionfind.rs`), so it never grows the
/// native call stack regardless of how deep the type is. Each node visited
/// ticks the shared [`Budget`] (a DOS bound) and consumes one of
/// [`ZONK_NODE_LIMIT`] per-call nodes (a stack-safety bound on the renderer that
/// later walks the result).
///
/// # Errors
/// [`Diagnostic::CompilerBug`] on a union-find invariant violation or if the
/// structure has more than [`ZONK_NODE_LIMIT`] nodes; [`TypeError::TypeTooLarge`]
/// (unspanned) if the type unfolds past [`TYPE_SIZE_LIMIT`] nodes;
/// [`TypeError::StepBudgetExceeded`] if the shared budget is exhausted.
pub fn zonk(uf: &mut UnionFind<Content>, budget: &mut Budget, var: VarId) -> DResult<Ty> {
    read_back(uf, budget, RowReading::Faithful, var)
}

/// Read a settled union-find variable back as the type the backend emits for it.
///
/// [`zonk`], except that a record row ending in a non-rigid variable reads
/// [`RowTail::Closed`] ([`RowReading::Emitted`]). A post-solve obligation
/// (equality, show) is judged on this reading: it holds of the emitted value
/// exactly when it holds of the emitted record's fields, while a rigid row
/// generic still reads open and satisfies none.
///
/// # Errors
/// As [`zonk`].
pub fn zonk_emitted(uf: &mut UnionFind<Content>, budget: &mut Budget, var: VarId) -> DResult<Ty> {
    read_back(uf, budget, RowReading::Emitted, var)
}

/// Read `var` back for a diagnostic reported at `span`.
///
/// An error raised before [`measure_type_depth`] runs reads back a type no
/// ceiling has bounded yet, and renders it through the recursive `ty_to_doc`.
/// The type is measured first: past either ceiling, the refusal is the
/// diagnostic, sited at `span`, and the type is never read back or rendered.
///
/// # Errors
/// [`TypeError::TypeTooDeep`] or [`TypeError::TypeTooLarge`] at `span` when
/// the type passes a ceiling; otherwise as [`TypeMeasures::measure`] and
/// [`zonk`].
pub fn zonk_reported(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    var: VarId,
    span: Span,
) -> DResult<Ty> {
    let measure = TypeMeasures::default().measure(uf, budget, var)?;
    measure
        .refusal(span)
        .map_or_else(|| zonk(uf, budget, var), Err)
}

/// The stacks one [`read_back`] walk drives: pending tasks, assembled results,
/// and the read-back cache keyed by union-find representative.
///
/// `memo` holds each cached [`Ty`] with its unfolded node count, and
/// `unfolded` is the node count of every result assembled so far: a reused
/// subtree is a full clone, so it is charged its whole unfolded size.
struct ReadBackWalk {
    work: Vec<ZonkTask>,
    results: Vec<Ty>,
    memo: HashMap<VarId, (Ty, u64)>,
    unfolded: u64,
}

/// The [`zonk`] / [`zonk_emitted`] work-stack walk under `reading`.
fn read_back(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    reading: RowReading,
    var: VarId,
) -> DResult<Ty> {
    let mut nodes_left = ZONK_NODE_LIMIT;
    // Read-back cache keyed by union-find representative. The occurs check in
    // unification guarantees the structure is acyclic, so this is a DAG, not a
    // cyclic graph: a representative reached along two paths is genuine sharing,
    // and reusing its cached `Ty` reproduces the same type while visiting the
    // shared sub-structure only once. Without it a diamond of sharing (e.g.
    // `p = (q, q)` chained) doubles the walk per level and blows the node limit.
    // The reused `Ty` is still a clone, so each reuse is charged its unfolded
    // size against [`TYPE_SIZE_LIMIT`].
    let mut walk = ReadBackWalk {
        work: vec![ZonkTask::Visit(var)],
        results: Vec::new(),
        memo: HashMap::new(),
        unfolded: 0,
    };

    while let Some(task) = walk.work.pop() {
        match task {
            ZonkTask::Visit(v) => {
                budget.tick()?;
                zonk_visit(uf, budget, reading, v, &mut walk, &mut nodes_left)?;
            }
            ZonkTask::Memoize { root, start } => {
                // The parent `Ty` was just assembled and sits on top of the
                // result stack; cache it under its representative, with the
                // nodes assembled since its first visit, so later shared visits
                // reuse it and pay its unfolded size.
                match walk.results.last() {
                    Some(ty) => {
                        let size = walk.unfolded.saturating_sub(start);
                        walk.memo.insert(root, (ty.clone(), size));
                    }
                    None => return Err(zonk_underflow()),
                }
            }
            ZonkTask::BuildFun => {
                charge_unfolded(&mut walk.unfolded, 1)?;
                let (Some(b), Some(a)) = (walk.results.pop(), walk.results.pop()) else {
                    return Err(zonk_underflow());
                };
                walk.results.push(Ty::Fun(Box::new(a), Box::new(b)));
            }
            ZonkTask::BuildCon {
                module,
                name,
                arity,
            } => {
                charge_unfolded(&mut walk.unfolded, 1)?;
                let split = walk
                    .results
                    .len()
                    .checked_sub(arity)
                    .ok_or_else(zonk_underflow)?;
                let args = walk.results.split_off(split);
                walk.results.push(Ty::Con { module, name, args });
            }
            ZonkTask::BuildTuple { arity } => {
                charge_unfolded(&mut walk.unfolded, 1)?;
                let split = walk
                    .results
                    .len()
                    .checked_sub(arity)
                    .ok_or_else(zonk_underflow)?;
                let elems = walk.results.split_off(split);
                walk.results.push(Ty::Tuple(elems));
            }
            ZonkTask::BuildRecord { names, tail } => {
                charge_unfolded(&mut walk.unfolded, 1)?;
                let split = walk
                    .results
                    .len()
                    .checked_sub(names.len())
                    .ok_or_else(zonk_underflow)?;
                let tys = walk.results.split_off(split);
                // `tys` is in the same order as `names` (field var visits were
                // reversed, so the results stack restores `BTreeMap` order).
                let fields: BTreeMap<Symbol, Ty> = names.into_iter().zip(tys).collect();
                walk.results.push(Ty::Record(fields, tail));
            }
        }
    }

    match walk.results.pop() {
        Some(ty) if walk.results.is_empty() => Ok(ty),
        _ => Err(zonk_underflow()),
    }
}

/// The work-stack invariant was violated (only reachable via a compiler bug in
/// `zonk` itself, never from input).
pub fn zonk_underflow() -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: STAGE,
        detail: "zonk result stack underflow".to_owned(),
    }
}

// ===========================================================================
// Type ceiling — depth and unfolded size of every checked type.
// ===========================================================================

/// Depth and unfolded size of one type, as [`measure_type_depth`] counts them.
///
/// A type application with arguments, a tuple and a record (its whole row
/// chain) are one level each, and a function arrow is
/// [`TYPE_LEVELS_PER_ARROW`]. A custom type costs at least its declared level
/// ([`NominalLevels`]), so a nullary one is that many levels deep; a variable,
/// `()` and a builtin nullary type are leaves of depth 0. The size counts every node of the unfolded
/// tree, each occurrence of a shared subtree included, so it is the node count
/// [`zonk`] reads back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TypeMeasure {
    /// Type-former levels, saturated at `u16::MAX`.
    pub depth: u16,
    /// Unfolded node count, saturated at `u64::MAX`.
    pub size: u64,
}

impl TypeMeasure {
    /// The measure of a leaf.
    const LEAF: Self = Self { depth: 0, size: 1 };

    /// The refusal this measure earns at `span`, if it passes a ceiling.
    #[must_use]
    pub const fn refusal(self, span: Span) -> Option<Diagnostic> {
        if self.depth > TYPE_DEPTH_LIMIT {
            Some(Diagnostic::Type {
                span,
                msg: TypeError::TypeTooDeep {
                    depth: self.depth,
                    limit: TYPE_DEPTH_LIMIT,
                },
            })
        } else if self.size > TYPE_SIZE_LIMIT {
            Some(type_too_large(span))
        } else {
            None
        }
    }
}

/// One step of the iterative [`TypeMeasures::measure`] walk.
enum MeasureTask {
    /// Measure one variable's representative.
    Visit(VarId),
    /// Combine the measured `children` (and the row chain's next record, if
    /// any) into the measure of `root`, `own` levels above its deepest child.
    Finish {
        root: VarId,
        own: u16,
        children: Vec<VarId>,
        row: Option<VarId>,
    },
}

/// The memoized type measures of one module's solved union-find graph.
///
/// One memo keyed by representative is shared by every measured variable, so
/// measuring every region costs one walk over the solved graph. A custom type
/// is charged its level in `levels`.
pub struct TypeMeasures<'l> {
    levels: &'l NominalLevels,
    memo: HashMap<VarId, TypeMeasure>,
    in_progress: HashSet<VarId>,
}

/// The table [`TypeMeasures::default`] measures with: no custom type levels,
/// so every type is measured by its structure alone.
static STRUCTURAL: NominalLevels = NominalLevels::EMPTY;

impl Default for TypeMeasures<'_> {
    fn default() -> Self {
        Self::new(&STRUCTURAL)
    }
}

impl<'l> TypeMeasures<'l> {
    /// An empty memo charging each custom type its level in `levels`.
    #[must_use]
    pub fn new(levels: &'l NominalLevels) -> Self {
        Self {
            levels,
            memo: HashMap::new(),
            in_progress: HashSet::new(),
        }
    }

    /// The measure of `var`'s solved type.
    ///
    /// Iterative (an explicit work stack), memoized by representative, and
    /// ticked once per visit against the shared [`Budget`].
    ///
    /// # Errors
    /// [`Diagnostic::CompilerBug`] on a union-find invariant violation or a
    /// cycle (unification's occurs check rules one out);
    /// [`TypeError::StepBudgetExceeded`] if the shared budget is exhausted.
    pub fn measure(
        &mut self,
        uf: &mut UnionFind<Content>,
        budget: &mut Budget,
        var: VarId,
    ) -> DResult<TypeMeasure> {
        let mut work = vec![MeasureTask::Visit(var)];
        while let Some(task) = work.pop() {
            match task {
                MeasureTask::Visit(v) => {
                    budget.tick()?;
                    self.visit(uf, v, &mut work)?;
                }
                MeasureTask::Finish {
                    root,
                    own,
                    children,
                    row,
                } => self.finish(root, own, &children, row)?,
            }
        }
        let root = uf.find(var)?;
        self.memo.get(&root).copied().ok_or_else(measure_bug)
    }

    /// Read one node: memo hit, leaf, or a [`MeasureTask::Finish`] over its
    /// children's visits.
    fn visit(
        &mut self,
        uf: &mut UnionFind<Content>,
        v: VarId,
        work: &mut Vec<MeasureTask>,
    ) -> DResult<()> {
        let root = uf.find(v)?;
        if self.memo.contains_key(&root) {
            return Ok(());
        }
        if !self.in_progress.insert(root) {
            return Err(Diagnostic::CompilerBug {
                where_: STAGE,
                detail: "a solved type reaches itself (cycle) while its depth is measured"
                    .to_owned(),
            });
        }
        let (own, children, ext) = match uf.root_content(root)? {
            Content::Flex
            | Content::Rigid
            | Content::Super { .. }
            | Content::Structure(FlatType::Unit | FlatType::EmptyRecord) => (0, Vec::new(), None),
            Content::Structure(FlatType::Fun(a, b)) => (TYPE_LEVELS_PER_ARROW, vec![*a, *b], None),
            Content::Structure(FlatType::Con { module, name, args }) => (
                self.levels
                    .level(module, *name)
                    .max(u16::from(!args.is_empty())),
                args.clone(),
                None,
            ),
            Content::Structure(FlatType::Tuple(elems)) => (1, elems.clone(), None),
            Content::Structure(FlatType::Record(fields, ext)) => {
                (1, fields.values().copied().collect(), Some(*ext))
            }
        };
        let is_leaf = children.is_empty() && ext.is_none();
        if is_leaf {
            self.in_progress.remove(&root);
            self.memo.insert(
                root,
                TypeMeasure {
                    depth: own,
                    ..TypeMeasure::LEAF
                },
            );
            return Ok(());
        }
        // A record whose extension is itself a record continues one row:
        // the chain reads back as a single record level.
        let row = match ext {
            Some(ext) => {
                let ext_root = uf.find(ext)?;
                matches!(
                    uf.root_content(ext_root)?,
                    Content::Structure(FlatType::Record(..))
                )
                .then_some(ext_root)
            }
            None => None,
        };
        let mut roots = Vec::with_capacity(children.len());
        for child in children {
            roots.push(uf.find(child)?);
        }
        // The finish runs beneath every child visit, so after all of them.
        work.push(MeasureTask::Finish {
            root,
            own,
            children: roots.clone(),
            row,
        });
        for child in roots.iter().rev() {
            work.push(MeasureTask::Visit(*child));
        }
        if let Some(row) = row {
            work.push(MeasureTask::Visit(row));
        }
        Ok(())
    }

    /// Combine the measured children of `root` into its measure.
    fn finish(
        &mut self,
        root: VarId,
        own: u16,
        children: &[VarId],
        row: Option<VarId>,
    ) -> DResult<()> {
        let mut depth: u16 = 0;
        let mut size: u64 = 1;
        for child in children {
            let m = self.memo.get(child).copied().ok_or_else(measure_bug)?;
            depth = depth.max(m.depth);
            size = size.saturating_add(m.size);
        }
        depth = depth.saturating_add(own);
        if let Some(row) = row {
            // The next record of the row chain shares this level: its depth
            // and size each carry one record node this level already counts.
            let m = self.memo.get(&row).copied().ok_or_else(measure_bug)?;
            depth = depth.max(m.depth);
            size = size.saturating_add(m.size.saturating_sub(1));
        }
        self.in_progress.remove(&root);
        self.memo.insert(root, TypeMeasure { depth, size });
        Ok(())
    }
}

/// The measure walk's own invariant failed (a child finished unmeasured).
fn measure_bug() -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: STAGE,
        detail: "a type's depth was read before it was measured".to_owned(),
    }
}

/// Refuse a module whose solved types pass [`TYPE_DEPTH_LIMIT`] or [`TYPE_SIZE_LIMIT`].
///
/// Each custom type is charged its level in `levels`. Every region's, every expected type's and every untyped top-level binding's
/// solved type is measured over one shared memo. A deep type is reported where
/// it is first built: among the spans whose type passes a ceiling, the one
/// that ends first (the innermost, for nested spans), so a `let` chain is
/// refused at the binding whose value crossed the limit, not at the
/// expression that encloses the chain. An untyped binding is reported at its
/// name only when no region refuses first. Runs after solving and before any
/// read-back, so no later walker meets a type past either ceiling.
///
/// # Errors
/// [`InferError::Sited`] carrying [`TypeError::TypeTooDeep`] or
/// [`TypeError::TypeTooLarge`]; [`InferError::Program`] for a union-find
/// invariant violation or step-budget exhaustion.
pub fn measure_type_depth(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    levels: &NominalLevels,
    generated: &Generated,
) -> Result<(), InferError> {
    let mut measures = TypeMeasures::new(levels);
    let mut refused: Option<(RefusalRank<'_>, Diagnostic)> = None;
    for ((home, span), var) in generated.regions.iter().chain(&generated.expected) {
        let measure = measures
            .measure(uf, budget, *var)
            .map_err(InferError::unsited)?;
        if let Some(diag) = measure.refusal(*span) {
            let rank = (
                *span == Span::DUMMY,
                home.as_slice(),
                span.hi,
                Reverse(span.lo),
            );
            if refused.as_ref().is_none_or(|(best, _)| rank < *best) {
                refused = Some((rank, diag));
            }
        }
    }
    if let Some(((_, home, _, _), diag)) = refused {
        return Err(InferError::sited_at_path(diag, home));
    }
    for ((home, _), def) in &generated.untyped {
        let measure = measures
            .measure(uf, budget, def.var)
            .map_err(InferError::unsited)?;
        if let Some(diag) = measure.refusal(def.name_span) {
            return Err(InferError::sited_at_path(diag, home));
        }
    }
    Ok(())
}

/// The order a refused span is reported in: real spans before synthesized
/// ones, then by module, then the span that ends first, the innermost first.
type RefusalRank<'a> = (bool, &'a [Symbol], u32, Reverse<u32>);

// ===========================================================================
// Kernel-registry tripwires
// ===========================================================================

impl<'a> Builder<'a> {
    /// Minimal [`Builder`] for reading kernel schemes
    /// ([`Self::resolve_scheme`]) outside a full inference run. Only `uf`,
    /// `interner`, and `builtins` are load-bearing for that method; every
    /// other field is empty. Pre-intern any needed strings BEFORE taking the
    /// immutable borrow into `interner`.
    ///
    /// Consumers: the registry tripwire tests below and
    /// [`kernel_type_table`] (the salsa Task-9 `kernel_types()` query's
    /// single source of schemes — one code path, so the query can never
    /// drift from what inference actually uses).
    pub const fn for_scheme_table(
        uf: &'a mut UnionFind<Content>,
        interner: &'a Interner,
        builtins: Builtins,
    ) -> Self {
        Self {
            uf,
            interner,
            builtins,
            regions: BTreeMap::new(),
            expected: BTreeMap::new(),
            current_home: None,
            constraints: Vec::new(),
            top_level: BTreeMap::new(),
            untyped: BTreeMap::new(),
            field_accesses: Vec::new(),
            record_updates: Vec::new(),
            routed_web_checks: Vec::new(),
            route_witness_checks: Vec::new(),
            wildcard_any_return_bodies: BTreeMap::new(),
            wildcard_any_return_bindings: BTreeSet::new(),
            wildcard_any_use_results: Vec::new(),
            ctors: BTreeMap::new(),
            sealed_ctors: BTreeSet::new(),
            typed_rigids: Vec::new(),
            scheme_apps: Vec::new(),
            super_vars: Vec::new(),
            signature_wildcards: Vec::new(),
            typed_wildcards: Vec::new(),
            wildcard_log: None,
            pending_instantiations: Vec::new(),
            // Empty: this minimal builder reads the scheme table directly; an
            // empty cache is an all-miss cache, so `resolve_scheme` still
            // resolves each kernel (just unmemoised here, where it is called at
            // most once per kernel by the tripwire lift anyway).
            scheme_cache: RefCell::new(Vec::new()),
        }
    }
}

/// A wired kernel's HM type scheme, or the registry's explicit "no scheme".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelScheme {
    /// The kernel's resolved inference scheme.
    Schemed(Ty),
    /// The registry declares no scheme (a routed / unlowered bucket).
    ///
    /// Not callable from well-typed Ipê: IPE-L0108 refuses it at its call
    /// sites.
    Unschemed,
}

/// The kernel type-scheme table: one row per `StdlibKernel::ALL` member.
///
/// Rows are in `ALL` order and built at one site (`KernelSchemeTable::build`,
/// behind [`kernel_type_table`]); there is no public constructor, so a
/// kernel absent from the table is never "unschemed", only unwired (outside
/// `ALL`). Readers match [`KernelScheme`] instead of inferring schemed-ness
/// from presence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelSchemeTable {
    rows: Vec<(StdlibKernel, KernelScheme)>,
}

impl KernelSchemeTable {
    /// Derive one row per kernel in `all`, in `all` order.
    ///
    /// `resolve` answers each kernel's scheme; `None` becomes an explicit
    /// [`KernelScheme::Unschemed`] row, never a dropped one.
    pub(super) fn build(
        all: &[StdlibKernel],
        resolve: impl Fn(StdlibKernel) -> Option<Ty>,
    ) -> Self {
        Self {
            rows: all
                .iter()
                .map(|&kernel| {
                    let scheme =
                        resolve(kernel).map_or(KernelScheme::Unschemed, KernelScheme::Schemed);
                    (kernel, scheme)
                })
                .collect(),
        }
    }

    /// Every row, in `StdlibKernel::ALL` order.
    #[must_use]
    pub fn rows(&self) -> impl ExactSizeIterator<Item = (StdlibKernel, &KernelScheme)> {
        self.rows.iter().map(|(kernel, scheme)| (*kernel, scheme))
    }

    /// The row for `kernel`.
    ///
    /// `None` only for a kernel outside `StdlibKernel::ALL` (an unwired
    /// variant); an unschemed kernel is `Some(KernelScheme::Unschemed)`.
    #[must_use]
    pub fn scheme(&self, kernel: StdlibKernel) -> Option<&KernelScheme> {
        self.rows
            .iter()
            .find(|(row_kernel, _)| *row_kernel == kernel)
            .map(|(_, scheme)| scheme)
    }

    /// The schemed rows only, in `StdlibKernel::ALL` order.
    pub fn schemed(&self) -> impl Iterator<Item = (StdlibKernel, &Ty)> {
        self.rows
            .iter()
            .filter_map(|(kernel, scheme)| match scheme {
                KernelScheme::Schemed(ty) => Some((*kernel, ty)),
                KernelScheme::Unschemed => None,
            })
    }
}

/// Materialize the full kernel type-scheme table.
///
/// Every `StdlibKernel::ALL` member gets one row, in `ALL` order: its
/// inference scheme, or [`KernelScheme::Unschemed`] for a variant the registry
/// deliberately never schemes (routed / unlowered buckets — those fail closed
/// with IPE-L0108 at their call sites).
///
/// This is the *lift* behind the salsa `kernel_types()` query: the table is
/// read through the SAME [`Builder::resolve_scheme`] adapter inference uses
/// (each schemed kernel's `TyShape` is interpreted), so the memoized table can
/// never drift from what constraint generation actually applies. The schemes are
/// pure functions of the interned builtin names — no union-find state is created
/// or consumed.
///
/// Interning note: [`Builtins::new`] interns the builtin type/constructor
/// names (idempotent lookups when they are already interned — which is the
/// case whenever any parse/canon of stdlib-shaped source has run first).
///
/// # Errors
/// Propagates the interner-capacity diagnostic from [`Builtins::new`] (the
/// only fallible step; the scheme reads themselves are total).
pub fn kernel_type_table(interner: &mut Interner) -> Result<KernelSchemeTable, Diagnostic> {
    let builtins = Builtins::new(interner)?;
    let mut uf: UnionFind<Content> = UnionFind::new();
    let builder = Builder::for_scheme_table(&mut uf, interner, builtins);
    Ok(KernelSchemeTable::build(StdlibKernel::ALL, |k| {
        builder.resolve_scheme(SchemeKey(k))
    }))
}
