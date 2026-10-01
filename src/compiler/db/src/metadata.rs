//! `program_metadata()`: the coarse, LOCKED whole-program
//! DCE-reachability seam.
//!
//! **Deliberately NOT firewalled behind an interface summary.** The design
//! spec's own locked decision (hazard H6: "Global DCE/mono firewalled behind
//! interfaces → dead-fn-promoted-to-live not re-emitted"): `program_metadata`
//! depends on the FULL lowered-IR set, so it re-executes on every edit that
//! changes [`lower_program`]'s output — including a body-only edit that
//! promotes a previously-dead function to live. A summarized/firewalled
//! dependency would under-invalidate: DCE reachability could go stale exactly
//! when it matters most. This query gets that property BY CONSTRUCTION, with
//! no special mechanism needed: it depends directly on `lower_program`'s
//! return value, itself the coarse per-program seam — any semantic
//! edit anywhere already re-executes `lower_program`, and therefore this
//! query re-executes too. What a downstream consumer gains is NOT skipping
//! this query's *execution* — it gains early-cutting on a BYTE-IDENTICAL
//! [`ProgramMetadata`] output when the recomputed value structurally equals
//! the prior revision's (salsa backdating on `Arc<ProgramMetadata>:
//! PartialEq`), exactly as the design doc describes: "downstream queries can
//! still early-cut on a BYTE-IDENTICAL metadata output even though the query
//! itself always re-executes."
//!
//! **Scope, honestly recorded (materialized, but not yet a dependency of
//! anything that consumes it for real pruning):**
//!
//! - `reachable_funcs` is a genuine fixpoint over the whole-program call
//!   graph (direct [`Callee::Func`] calls AND [`Expr::FuncValue`]
//!   first-class references), seeded from the lowered program's entry
//!   [`FuncId`]. [`ipe_lower::lower`]
//!   always emits exactly one [`ipe_ir::Module`]
//!   (`Program { modules: vec![module] }`,
//!   `crates/ipe_lower/src/lower.rs`), so there is only ever one
//!   program-wide entry to seed from — the def named `main` in the merged
//!   module (`crates/ipe_lower/src/lower.rs`'s `Module.entry` assignment). A
//!   program with no `main` binding (a hand-built IR, or a future non-`main`
//!   entry shape) has no seed to fix-point from; rather than guess, every
//!   function is conservatively treated as reachable — this never
//!   under-reports, which is the sound direction for a set nothing consumes
//!   for pruning yet.
//! - `reachable_types` collects every enum type CONSTRUCTED
//!   ([`Expr::Ctor`]) or PATTERN-MATCHED ([`Pat::Ctor`]) inside a reachable
//!   function's body. It does **NOT** close over declared [`EnumDef`]
//!   variant field types transitively — a type referenced only via an
//!   unconstructed/unmatched payload field (e.g. a value merely passed
//!   through and never taken apart in reachable code) would be missed. This
//!   is a sound gap ONLY because `program_metadata` is a forward seam today,
//!   not yet a dependency of any pruning pass. A future consumer that
//!   actually PRUNES dead code from emission MUST close `reachable_types`
//!   over `EnumDef` field types before treating anything as unreachable —
//!   recorded here so the gap cannot be silently assumed away later.
//!
//! Both walkers (`walk_expr`, `walk_pat`) match every [`Expr`] / [`Pat`]
//! variant explicitly — no wildcard arm — so a future IR variant cannot be
//! silently under-walked (the compiler forces this file to be updated when
//! [`ipe_ir::ir::Expr`] or [`ipe_ir::ir::Pat`] grows a new case).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ipe_diagnostics::Diagnostic;
use ipe_intern::Symbol;
use ipe_ir::{Arm, Callee, Expr, Func, FuncId, ModPath, Pat, Program};

use crate::{Db, SourceFile, SourceRoot, lower_program};

/// Whole-program DCE-reachability metadata. See the module doc for the full
/// design rationale and the honestly-recorded scope limits.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProgramMetadata {
    /// Every [`FuncId`] transitively reachable from the program's entry
    /// function (or every `FuncId` in the program, when no entry exists to
    /// seed a fixpoint from — see the module doc's conservative-fallback
    /// note).
    pub reachable_funcs: BTreeSet<FuncId>,
    /// Every `(home, type name)` pair of an enum type constructed or
    /// pattern-matched inside a reachable function body. NOT closed over
    /// declared field types — see the module doc's scope note.
    pub reachable_types: BTreeSet<(ModPath, Symbol)>,
}

/// The memoized result of computing [`ProgramMetadata`].
///
/// The error case is [`lower_program`]'s own diagnostic, propagated verbatim
/// — this query never fails on its own account; it is a pure structural walk
/// over an already-lowered, already-well-formed IR.
pub type ProgramMetadataResult = Result<Arc<ProgramMetadata>, (Diagnostic, Vec<Symbol>)>;

/// Compute the whole-program DCE-reachability metadata for the program
/// rooted at `entry`.
///
/// Depends on [`lower_program`] directly — see the module doc for why that
/// is exactly the "never firewalled" property the design spec locks in.
#[salsa::tracked]
pub fn program_metadata(db: &dyn Db, root: SourceRoot, entry: SourceFile) -> ProgramMetadataResult {
    let program = lower_program(db, root, entry).clone()?;
    Ok(Arc::new(compute_program_metadata(&program)))
}

/// Pure structural computation, factored out of the tracked query so it can
/// be exercised directly by unit tests without standing up a database.
fn compute_program_metadata(program: &Program) -> ProgramMetadata {
    let mut funcs_by_id: BTreeMap<FuncId, &Func> = BTreeMap::new();
    let mut entries: Vec<FuncId> = Vec::new();
    for module in &program.modules {
        for func in &module.funcs {
            funcs_by_id.insert(func.id, func);
        }
        if let Some(entry_id) = module.entry {
            entries.push(entry_id);
        }
    }

    let mut reachable_types: BTreeSet<(ModPath, Symbol)> = BTreeSet::new();

    if entries.is_empty() {
        // No entry to seed a fixpoint from — conservative fallback: every
        // function is reachable. Never under-report (see module doc).
        for func in funcs_by_id.values() {
            let mut discard = BTreeSet::new();
            walk_expr(&func.body, &mut discard, &mut reachable_types);
        }
        return ProgramMetadata {
            reachable_funcs: funcs_by_id.keys().copied().collect(),
            reachable_types,
        };
    }

    let mut reachable_funcs: BTreeSet<FuncId> = BTreeSet::new();
    let mut worklist: Vec<FuncId> = entries;
    while let Some(id) = worklist.pop() {
        if !reachable_funcs.insert(id) {
            continue;
        }
        // A reference to a `FuncId` absent from this program's function
        // table would be an internal invariant violation elsewhere in the
        // pipeline (the lowerer is the sole producer of `Callee::Func`);
        // staying total here rather than panicking.
        let Some(func) = funcs_by_id.get(&id) else {
            continue;
        };
        let mut direct_calls: BTreeSet<FuncId> = BTreeSet::new();
        walk_expr(&func.body, &mut direct_calls, &mut reachable_types);
        for callee_id in direct_calls {
            if !reachable_funcs.contains(&callee_id) {
                worklist.push(callee_id);
            }
        }
    }

    ProgramMetadata {
        reachable_funcs,
        reachable_types,
    }
}

/// Walk one expression, collecting every direct/[`Expr::FuncValue`] callee
/// into `direct_calls` and every constructed enum identity into `types`. Exhaustive
/// over [`Expr`] — no wildcard arm.
///
/// Long by necessity, not by neglect: one match arm per [`Expr`] variant is
/// exactly the exhaustiveness this file's module doc requires.
#[allow(clippy::too_many_lines)]
fn walk_expr(
    expr: &Expr,
    direct_calls: &mut BTreeSet<FuncId>,
    types: &mut BTreeSet<(ModPath, Symbol)>,
) {
    match expr {
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_) => {}
        Expr::Ctor {
            home,
            ty,
            variant: _,
            args,
        } => {
            types.insert((home.clone(), *ty));
            for arg in args {
                walk_expr(arg, direct_calls, types);
            }
        }
        Expr::BinOp { op: _, lhs, rhs } => {
            walk_expr(lhs, direct_calls, types);
            walk_expr(rhs, direct_calls, types);
        }
        Expr::Let {
            name: _,
            value,
            body,
        } => {
            walk_expr(value, direct_calls, types);
            walk_expr(body, direct_calls, types);
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            walk_pat(binder, types);
            walk_expr(value, direct_calls, types);
            walk_expr(body, direct_calls, types);
        }
        Expr::If { cond, then_, else_ } => {
            walk_expr(cond, direct_calls, types);
            walk_expr(then_, direct_calls, types);
            walk_expr(else_, direct_calls, types);
        }
        Expr::Match(m) => {
            walk_expr(m.scrutinee(), direct_calls, types);
            for arm in m.arms() {
                walk_arm(arm, direct_calls, types);
            }
        }
        Expr::Call { callee, args, .. } => {
            walk_callee(callee, direct_calls);
            for arg in args {
                walk_expr(arg, direct_calls, types);
            }
        }
        Expr::Tuple(items) | Expr::List { elem: _, items } => {
            for item in items {
                walk_expr(item, direct_calls, types);
            }
        }
        Expr::Cons { head, tail } => {
            walk_expr(head, direct_calls, types);
            walk_expr(tail, direct_calls, types);
        }
        Expr::ListIndexClone { list, index: _ }
        | Expr::ListLenCheck {
            list,
            len: _,
            exact: _,
        } => {
            walk_expr(list, direct_calls, types);
        }
        Expr::Record { fields, .. } => {
            for (_, value) in fields {
                walk_expr(value, direct_calls, types);
            }
        }
        Expr::Access {
            record,
            field: _,
            field_ty: _,
        } => {
            walk_expr(record, direct_calls, types);
        }
        Expr::Update { record, fields } => {
            walk_expr(record, direct_calls, types);
            for (_, value) in fields {
                walk_expr(value, direct_calls, types);
            }
        }
        Expr::Lambda {
            params: _,
            ret: _,
            body,
        }
        | Expr::SharedLambda {
            params: _,
            ret: _,
            body,
        }
        | Expr::TailLoop { params: _, body } => {
            walk_expr(body, direct_calls, types);
        }
        Expr::Apply { func, args } => {
            walk_expr(func, direct_calls, types);
            for arg in args {
                walk_expr(arg, direct_calls, types);
            }
        }
        Expr::FuncValue { callee, ty: _ } => {
            walk_callee(callee, direct_calls);
        }
        Expr::TaskSeq { effect, rest } => {
            walk_expr(effect, direct_calls, types);
            walk_expr(rest, direct_calls, types);
        }
        Expr::TailRecur { args } => {
            for arg in args {
                walk_expr(arg, direct_calls, types);
            }
        }
    }
}

/// Walk one match arm: its pattern (for constructed/matched types), its
/// optional guard, and its body.
fn walk_arm(
    arm: &Arm,
    direct_calls: &mut BTreeSet<FuncId>,
    types: &mut BTreeSet<(ModPath, Symbol)>,
) {
    walk_pat(&arm.pat, types);
    if let Some(guard) = &arm.guard {
        walk_expr(guard, direct_calls, types);
    }
    walk_expr(&arm.body, direct_calls, types);
}

/// Record a [`Callee::Func`] reference; kernel and foreign-wrapper callees
/// carry no [`FuncId`].
fn walk_callee(callee: &Callee, direct_calls: &mut BTreeSet<FuncId>) {
    match callee {
        Callee::Func(id) => {
            direct_calls.insert(*id);
        }
        Callee::Kernel(_) | Callee::Ffi { .. } => {}
    }
}

/// Walk a pattern, collecting every matched enum identity into `types`.
/// Exhaustive over [`Pat`] — no wildcard arm, for the same reason as
/// [`walk_expr`].
fn walk_pat(pat: &Pat, types: &mut BTreeSet<(ModPath, Symbol)>) {
    match pat {
        Pat::Var(_) | Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) | Pat::Str(_) => {}
        Pat::Alias(inner, _) => walk_pat(inner, types),
        Pat::Ctor {
            home,
            ty,
            variant: _,
            args,
        } => {
            types.insert((home.clone(), *ty));
            for arg in args {
                walk_pat(arg, types);
            }
        }
        Pat::Tuple(elems) => {
            for elem in elems {
                walk_pat(elem, types);
            }
        }
        Pat::Record(fields) => {
            for (_, sub) in fields {
                walk_pat(sub, types);
            }
        }
        Pat::Slice { prefix, rest } => {
            for p in prefix {
                walk_pat(p, types);
            }
            if let Some(rest) = rest {
                walk_pat(rest, types);
            }
        }
        // An or-pattern's alternatives may each reference distinct enum
        // identities (`Circle r | Square r`), so every alternative is walked.
        Pat::Or(alts) => {
            for alt in alts {
                walk_pat(alt, types);
            }
        }
    }
}
