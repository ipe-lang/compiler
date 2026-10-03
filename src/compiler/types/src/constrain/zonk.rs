use super::{
    BTreeMap, BTreeSet, Budget, Builder, Builtins, Content, DResult, Diagnostic, FlatType,
    Generated, InferError, Interner, RefCell, RowTail, STAGE, SchemeKey, StdlibKernel, Symbol, Ty,
    UnionFind, VarId, ZONK_NODE_LIMIT, tag_solver_var, unify_at,
};

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
/// (`"a"`, `"b"`, …, never `"any"`). Only plain, obligation-free `Flex` roots
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
/// `"z"`, `"a1"`, …) for a generalized untyped-def scheme — never `"any"`
/// (AUD-13's wildcard sentinel is reserved). `next` is the caller's shared
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
        for (key, &shared) in generated.untyped.iter().filter(|(k, _)| &k.0 == home) {
            let root = lift!(uf.find(shared));
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

/// One step of the iterative [`reify_scheme`] work stack — the interface
/// sibling of [`ZonkTask`], differing in the two places an interface must be
/// faithful where a display read-back need not be: quantified variables map
/// to CANONICAL tagged ids (deterministic, union-find-numbering-free), and an
/// open record tail is PRESERVED as `RowTail::Open` (zonk presents every
/// settled record as closed, which is fine for display but would silently
/// close a row-polymorphic exported scheme).
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
    /// Pop one result per field name (in `names` order) and push a `Record`. The
    /// `names` are visited in their `BTreeMap` order, so popping in reverse pairs
    /// each result with its field name.
    BuildRecord { names: Vec<Symbol> },
    /// Record the freshly assembled result on top of the stack as the read-back
    /// of union-find representative `root`, so a later visit to any variable
    /// sharing that representative reuses the cached [`Ty`] instead of walking
    /// the sub-structure again. This is what keeps a shared solver DAG from
    /// expanding as a tree.
    Memoize { root: VarId },
}

/// Read back one union-find node during [`zonk`], driving the shared work
/// stack. Resolves `v` to its representative; a representative already in `memo`
/// is genuine sharing (the structure is acyclic), so its cached [`Ty`] is reused
/// without re-walking or re-charging the node budget. A first visit charges one
/// node, then either produces a leaf `Ty` (also cached) or pushes the rebuild
/// task, a [`ZonkTask::Memoize`] to cache the assembled parent, and the
/// children's visits.
fn zonk_visit(
    uf: &mut UnionFind<Content>,
    v: VarId,
    work: &mut Vec<ZonkTask>,
    results: &mut Vec<Ty>,
    memo: &mut std::collections::HashMap<VarId, Ty>,
    nodes_left: &mut u32,
) -> DResult<()> {
    let root = uf.find(v)?;
    if let Some(cached) = memo.get(&root) {
        // A representative already read back: reuse it. Sharing does not
        // re-consume the node budget, so the limit now bounds the count of
        // distinct nodes rather than an expanded tree.
        results.push(cached.clone());
        return Ok(());
    }
    *nodes_left = nodes_left
        .checked_sub(1)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: STAGE,
            detail: "type exceeded read-back node limit".to_owned(),
        })?;
    // Borrow the descriptor: leaf arms need no owned copy, and the structural
    // arms clone only the field they genuinely move into a rebuild task (the
    // module path, the record field names) rather than the whole descriptor.
    match uf.root_content(root)? {
        // A flexible, rigid, or super-typed variable that survives solving reads
        // back as a type variable named by its representative's id. (A
        // super-typed variable is still a variable; its obligations are read
        // separately when generalising — see [`crate::SolvedTypes::bounds`].)
        Content::Flex | Content::Rigid | Content::Super { .. } => {
            // AUD-13: tag so this solver-representative id can never be mistaken
            // for an annotation-symbol raw by `instantiate_in`'s wildcard-`"any"`
            // check if this zonked `Ty` is ever fed back through it.
            let ty = Ty::Var(tag_solver_var(root));
            memo.insert(root, ty.clone());
            results.push(ty);
        }
        Content::Structure(FlatType::Unit) => {
            memo.insert(root, Ty::Unit);
            results.push(Ty::Unit);
        }
        Content::Structure(FlatType::Fun(a, b)) => {
            // Cache this representative once its children reassemble, then push
            // the rebuild and children so that `a` is visited before `b` and
            // lands lower on `results`.
            let (a, b) = (*a, *b);
            work.push(ZonkTask::Memoize { root });
            work.push(ZonkTask::BuildFun);
            work.push(ZonkTask::Visit(b));
            work.push(ZonkTask::Visit(a));
        }
        Content::Structure(FlatType::Con { module, name, args }) => {
            let arity = args.len();
            work.push(ZonkTask::Memoize { root });
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
            work.push(ZonkTask::Memoize { root });
            work.push(ZonkTask::BuildTuple { arity });
            // Reverse so elements land on `results` in source order.
            for e in elems.iter().rev() {
                work.push(ZonkTask::Visit(*e));
            }
        }
        Content::Structure(FlatType::Record(fields, _ext)) => {
            // Capture the field names (BTreeMap order) for the rebuild, and visit
            // each field var in reverse so the results land in the same order the
            // names are popped. The extension var is intentionally not zonked
            // here — `Ty::Record` does not carry a RowTail in its resolved form
            // (the tail is a solver artefact consumed only by unify.rs and the
            // `BuildRecord` path). Closed records resolve to fields only; open
            // records show as the same (tail is transparent to diagnostics for
            // now).
            let names: Vec<Symbol> = fields.keys().copied().collect();
            work.push(ZonkTask::Memoize { root });
            work.push(ZonkTask::BuildRecord { names });
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
            memo.insert(root, Ty::Unit);
            results.push(Ty::Unit);
        }
    }
    Ok(())
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
/// structure has more than [`ZONK_NODE_LIMIT`] nodes; [`TypeError::StepBudgetExceeded`]
/// if the shared budget is exhausted.
pub fn zonk(uf: &mut UnionFind<Content>, budget: &mut Budget, var: VarId) -> DResult<Ty> {
    let mut work: Vec<ZonkTask> = vec![ZonkTask::Visit(var)];
    let mut results: Vec<Ty> = Vec::new();
    let mut nodes_left = ZONK_NODE_LIMIT;
    // Read-back cache keyed by union-find representative. The occurs check in
    // unification guarantees the structure is acyclic, so this is a DAG, not a
    // cyclic graph: a representative reached along two paths is genuine sharing,
    // and reusing its cached `Ty` reproduces the same type while visiting the
    // shared sub-structure only once. Without it a diamond of sharing (e.g.
    // `p = (q, q)` chained) doubles the walk per level and blows the node limit.
    let mut memo: std::collections::HashMap<VarId, Ty> = std::collections::HashMap::new();

    while let Some(task) = work.pop() {
        match task {
            ZonkTask::Visit(v) => {
                budget.tick()?;
                zonk_visit(uf, v, &mut work, &mut results, &mut memo, &mut nodes_left)?;
            }
            ZonkTask::Memoize { root } => {
                // The parent `Ty` was just assembled and sits on top of the
                // result stack; cache it under its representative so later shared
                // visits reuse it.
                match results.last() {
                    Some(ty) => {
                        memo.insert(root, ty.clone());
                    }
                    None => return Err(zonk_underflow()),
                }
            }
            ZonkTask::BuildFun => {
                let (Some(b), Some(a)) = (results.pop(), results.pop()) else {
                    return Err(zonk_underflow());
                };
                results.push(Ty::Fun(Box::new(a), Box::new(b)));
            }
            ZonkTask::BuildCon {
                module,
                name,
                arity,
            } => {
                let split = results
                    .len()
                    .checked_sub(arity)
                    .ok_or_else(zonk_underflow)?;
                let args = results.split_off(split);
                results.push(Ty::Con { module, name, args });
            }
            ZonkTask::BuildTuple { arity } => {
                let split = results
                    .len()
                    .checked_sub(arity)
                    .ok_or_else(zonk_underflow)?;
                let elems = results.split_off(split);
                results.push(Ty::Tuple(elems));
            }
            ZonkTask::BuildRecord { names } => {
                let split = results
                    .len()
                    .checked_sub(names.len())
                    .ok_or_else(zonk_underflow)?;
                let tys = results.split_off(split);
                // `tys` is in the same order as `names` (field var visits were
                // reversed, so the results stack restores `BTreeMap` order).
                let fields: BTreeMap<Symbol, Ty> = names.into_iter().zip(tys).collect();
                // Zonked records are always presented as closed — the RowTail
                // is a solver artefact; the resolved `Ty` simply carries the
                // settled field map without advertising openness (consistent
                // with the the compiler reference's read-back behaviour).
                results.push(Ty::Record(fields, RowTail::Closed));
            }
        }
    }

    match results.pop() {
        Some(ty) if results.is_empty() => Ok(ty),
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

/// Materialize the full kernel type-scheme table.
///
/// Every [`StdlibKernel`] variant paired with its inference scheme, in
/// `StdlibKernel::ALL` order, skipping variants the registry deliberately
/// never schemes (routed / unlowered buckets — those fail closed with
/// IPE-L0108 at their call sites).
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
pub fn kernel_type_table(interner: &mut Interner) -> Result<Vec<(StdlibKernel, Ty)>, Diagnostic> {
    let builtins = Builtins::new(interner)?;
    let mut uf: UnionFind<Content> = UnionFind::new();
    let builder = Builder::for_scheme_table(&mut uf, interner, builtins);
    Ok(StdlibKernel::ALL
        .iter()
        .filter_map(|&k| builder.resolve_scheme(SchemeKey(k)).map(|ty| (k, ty)))
        .collect())
}

/// Resolve a single [`SchemeKey`] to its concrete HM type scheme, outside a full
/// inference run.
///
/// This is the free-function entry to the scheme-by-key bridge: a consumer
/// holding a [`ipe_kernels::KernelDef`] reads `def.scheme` (a [`SchemeKey`]) and
/// resolves it here to the same `Ty` inference uses, via the single
/// [`Builder::resolve_scheme`] interpreter. `Ok(None)` means the kernel has no
/// scheme (a routed / unlowered bucket).
///
/// # Errors
/// Propagates the interner-capacity diagnostic from [`Builtins::new`] (the only
/// fallible step; the scheme read itself is total).
pub fn resolve_scheme(key: SchemeKey, interner: &mut Interner) -> Result<Option<Ty>, Diagnostic> {
    let builtins = Builtins::new(interner)?;
    let mut uf: UnionFind<Content> = UnionFind::new();
    let builder = Builder::for_scheme_table(&mut uf, interner, builtins);
    Ok(builder.resolve_scheme(key))
}
