//! Borrow inference for read-only user-function parameters.
//!
//! Whether a user function takes a parameter by value or by reference is one
//! typed IR fact, [`ParamPass`], carried on the [`Param`] it describes. This
//! module is its only writer: [`analyze`] computes a [`BorrowPlan`] with one
//! whole-program greatest fixpoint, [`apply`] writes the plan into the
//! program, and [`verify`] re-proves the fact at every boundary that reads it
//! (lowering exit and emit entry). Absent proof a parameter is
//! [`ParamPass::Owned`], so the by-value code is what gets emitted.
//!
//! An occurrence of a tracked parameter `p` is a *read* in exactly three
//! positions: the base of a field access whose field holds no effect carrier,
//! a direct argument of a user-function call at a `Borrowed` slot, and the
//! identity tail-recursion argument for `p`'s own slot. Every other occurrence
//! consumes the value, and so does any occurrence under a closure boundary or
//! inside a kernel or FFI argument. A parameter is `Borrowed` only when it is
//! eligible and none of its occurrences consumes it.

use std::collections::{BTreeMap, BTreeSet};

use ipe_diagnostics::{Diagnostic, LowerError, Span};
use ipe_intern::{Interner, Symbol};

use crate::free_vars::pat_bound_symbols;
use crate::once_closure::boundary_kind;
use crate::{
    Callee, EnumPayloadTable, Expr, Func, FuncId, IrType, MAX_IR_RENDER_DEPTH, Program, TypeDef,
    enum_payload_table, ir_type_has_effect_carrier,
};

/// How a user function receives one parameter.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum ParamPass {
    /// By value: the caller moves or clones the argument in.
    Owned,
    /// By shared reference: every use in the body only reads the value.
    Borrowed,
}

/// One parameter of a [`Func`]: its binder, its type and how it is passed.
///
/// The pass is a private field, so outside this module a parameter can only
/// be built [`ParamPass::Owned`] through [`Param::owned`]; only [`apply`]
/// writes a `Borrowed` verdict.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Param {
    pub sym: Symbol,
    pub ty: IrType,
    pass: ParamPass,
}

impl Param {
    /// A by-value parameter.
    #[must_use]
    pub const fn owned(sym: Symbol, ty: IrType) -> Self {
        Self {
            sym,
            ty,
            pass: ParamPass::Owned,
        }
    }

    /// How this parameter is passed.
    #[must_use]
    pub const fn pass(&self) -> ParamPass {
        self.pass
    }
}

/// Whether the emitter renders a `Borrowed` parameter as `&T`.
///
/// Until it does, [`apply`] admits every verdict as [`ParamPass::Owned`], so a
/// `Borrowed` fact can never reach an emitter that would print it by value.
const EMIT_RENDERS_BORROWED: bool = false;

/// The pass of every parameter of every user function in a program.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct PassTable {
    slots: BTreeMap<FuncId, Vec<ParamPass>>,
    /// Ids carried by more than one function, so no single slot list
    /// describes them, each with whether any of those functions borrows.
    ambiguous: BTreeMap<FuncId, bool>,
    /// The number of `Borrowed` entries in `slots` and in the functions
    /// behind `ambiguous`.
    borrowed: usize,
}

impl PassTable {
    /// The passes the functions of `program` carry.
    #[must_use]
    pub fn of_program(program: &Program) -> Self {
        Self::of_funcs(program.modules.iter().flat_map(|m| m.funcs.iter()))
    }

    /// The passes `funcs` carry.
    ///
    /// An id two functions share has no slot ([`Self::pass`] is `None`, so an
    /// argument passed to it consumes) and borrows when any of them borrows.
    #[must_use]
    pub fn of_funcs<'a>(funcs: impl IntoIterator<Item = &'a Func>) -> Self {
        let mut table = Self::default();
        for f in funcs {
            let slots: Vec<ParamPass> = f.params.iter().map(Param::pass).collect();
            let borrows = slots.contains(&ParamPass::Borrowed);
            table.borrowed = table.borrowed.saturating_add(count_borrowed(&slots));
            if let Some(any) = table.ambiguous.get_mut(&f.id) {
                *any |= borrows;
            } else if let Some(first) = table.slots.remove(&f.id) {
                let first_borrows = first.contains(&ParamPass::Borrowed);
                table.ambiguous.insert(f.id, borrows || first_borrows);
            } else {
                table.slots.insert(f.id, slots);
            }
        }
        table
    }

    /// Record `slots` for `id`; `false` when `id` already had an entry, which
    /// is then replaced.
    fn insert(&mut self, id: FuncId, slots: Vec<ParamPass>) -> bool {
        self.borrowed = self.borrowed.saturating_add(count_borrowed(&slots));
        let previous = self.slots.insert(id, slots);
        if let Some(old) = &previous {
            self.borrowed = self.borrowed.saturating_sub(count_borrowed(old));
        }
        previous.is_none()
    }

    /// The pass of parameter `idx` of function `id`, or `None` when there is
    /// no such function or parameter.
    #[must_use]
    pub fn pass(&self, id: FuncId, idx: usize) -> Option<ParamPass> {
        self.slots.get(&id).and_then(|s| s.get(idx)).copied()
    }

    /// The number of parameter slots function `id` has, or `None` when no
    /// single function carries `id`.
    #[must_use]
    pub fn arity(&self, id: FuncId) -> Option<usize> {
        self.slots.get(&id).map(Vec::len)
    }

    /// Whether function `id` takes any parameter by reference.
    #[must_use]
    pub fn borrows_any(&self, id: FuncId) -> bool {
        self.ambiguous.get(&id).copied().unwrap_or(false)
            || self
                .slots
                .get(&id)
                .is_some_and(|s| s.contains(&ParamPass::Borrowed))
    }

    /// The number of `Borrowed` slots in the table.
    #[must_use]
    pub const fn borrowed_count(&self) -> usize {
        self.borrowed
    }

    /// Demote slot `idx` of function `id`; `true` when it was `Borrowed`.
    fn demote(&mut self, id: FuncId, idx: usize) -> bool {
        if let Some(slot) = self.slots.get_mut(&id).and_then(|s| s.get_mut(idx))
            && *slot == ParamPass::Borrowed
        {
            *slot = ParamPass::Owned;
            self.borrowed = self.borrowed.saturating_sub(1);
            return true;
        }
        false
    }

    /// Demote every slot of function `id`; `true` when any was `Borrowed`.
    fn demote_func(&mut self, id: FuncId) -> bool {
        let len = self.slots.get(&id).map_or(0, Vec::len);
        let mut changed = false;
        for idx in 0..len {
            changed |= self.demote(id, idx);
        }
        changed
    }
}

fn count_borrowed(slots: &[ParamPass]) -> usize {
    slots
        .iter()
        .filter(|p| matches!(p, ParamPass::Borrowed))
        .count()
}

/// The verdict of [`analyze`]: the pass each parameter may take.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BorrowPlan {
    table: PassTable,
}

impl BorrowPlan {
    /// The verdicts, one per parameter slot.
    #[must_use]
    pub const fn table(&self) -> &PassTable {
        &self.table
    }
}

/// A broken borrow invariant found by [`verify`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BorrowViolation {
    /// A `Borrowed` parameter has an occurrence that consumes it.
    NonReadUse { func: FuncId, param: Symbol },
    /// A `Borrowed` parameter's binder is bound again inside its function.
    Rebound { func: FuncId, param: Symbol },
    /// A function with a `Borrowed` slot is named as a first-class value.
    BorrowingFuncValue { func: FuncId, callee: FuncId },
    /// The body nests deeper than the walk's ceiling.
    TooDeep { func: FuncId },
}

impl BorrowViolation {
    /// The diagnostic reporting this violation in `owner` from `where_`.
    ///
    /// A body past the walk's ceiling is the emitter's own nesting refusal,
    /// naming the function and its home; every other violation, and a depth
    /// refusal whose function does not resolve through `interner`, is a
    /// compiler bug.
    #[must_use]
    pub fn into_diagnostic(
        self,
        owner: &Func,
        interner: &Interner,
        where_: &'static str,
    ) -> Diagnostic {
        if matches!(self, Self::TooDeep { .. })
            && let Some(site) = owner.emit_site(interner)
        {
            return Diagnostic::Lower {
                span: Span::DUMMY,
                msg: LowerError::BackendNestingTooDeep {
                    limit: MAX_IR_RENDER_DEPTH,
                    func: Some(site),
                },
            };
        }
        let detail = match self {
            Self::NonReadUse { func, param } => format!(
                "function {} takes parameter {param:?} by reference but a use consumes it",
                func.as_raw()
            ),
            Self::Rebound { func, param } => format!(
                "function {} takes parameter {param:?} by reference but rebinds its name",
                func.as_raw()
            ),
            Self::BorrowingFuncValue { func, callee } => format!(
                "function {} names function {} as a value, but that function borrows a parameter",
                func.as_raw(),
                callee.as_raw()
            ),
            Self::TooDeep { func: id } => format!(
                "function {} nests deeper than {MAX_IR_RENDER_DEPTH} levels and its name {:?} or home {:?} does not resolve",
                id.as_raw(),
                owner.name,
                owner.home.0
            ),
        };
        Diagnostic::CompilerBug { where_, detail }
    }
}

/// Analyze, apply and verify borrow passes over a lowered program.
///
/// `eligible` decides whether a parameter type may be borrowed at all; it is
/// the multi-use-clone eligibility the lowerer owns.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] when the program repeats a [`FuncId`], the
/// fixpoint exceeds its declared bound, or the applied program fails
/// [`verify`].
pub fn run(
    program: &mut Program,
    interner: &Interner,
    eligible: impl Fn(&IrType) -> bool,
) -> Result<(), Diagnostic> {
    let plan = analyze(program, eligible)?;
    apply(&plan, program);
    verify_program(program, interner, "ipe_ir::borrow::run")
}

/// The whole-program borrow plan: the greatest fixpoint of "no consuming use".
///
/// Every eligible slot starts `Borrowed`; each round demotes every slot that
/// has a consuming occurrence under the current verdicts, and the walk stops
/// at the first round that demotes nothing. Each round but the last demotes at
/// least one slot, so the declared bound is the eligible slot count plus one.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] when the program repeats a [`FuncId`] or the
/// fixpoint exceeds its bound.
pub fn analyze(
    program: &Program,
    eligible: impl Fn(&IrType) -> bool,
) -> Result<BorrowPlan, Diagnostic> {
    let funcs: Vec<&Func> = program
        .modules
        .iter()
        .flat_map(|m| m.funcs.iter())
        .collect();
    let mut table = PassTable::default();
    for func in &funcs {
        let slots = func
            .params
            .iter()
            .map(|p| {
                if eligible(&p.ty) {
                    ParamPass::Borrowed
                } else {
                    ParamPass::Owned
                }
            })
            .collect();
        if !table.insert(func.id, slots) {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_ir::borrow::analyze",
                detail: format!("function id {} occurs twice", func.id.as_raw()),
            });
        }
    }
    let rounds = table.borrowed_count().saturating_add(1);
    fixpoint(&funcs, table, &program_payloads(program), rounds).map(|(plan, _)| plan)
}

/// Iterate demotion rounds until none demotes, refusing past `max_rounds`;
/// also returns the number of function bodies walked.
///
/// The first round walks every function. A walk's verdict depends on the
/// table only through the slots of the functions it calls, so a later round
/// walks only the callers of a function whose slots the previous round
/// demoted, and the whole fixpoint walks each body once plus once per
/// demoted callee.
///
/// A function named as a first-class value keeps every slot `Owned` (no
/// by-value adapter exists for a borrowing function), and a body past the
/// walk's depth ceiling, which may hide such a value, demotes the whole
/// program.
fn fixpoint(
    funcs: &[&Func],
    mut table: PassTable,
    payloads: &EnumPayloadTable,
    max_rounds: usize,
) -> Result<(BorrowPlan, usize), Diagnostic> {
    let mut callers: BTreeMap<FuncId, BTreeSet<FuncId>> = BTreeMap::new();
    let mut dirty: BTreeSet<FuncId> = funcs.iter().map(|f| f.id).collect();
    let mut walks: usize = 0;
    for _ in 0..max_rounds {
        let mut demoted: Vec<(FuncId, usize)> = Vec::new();
        let mut values: BTreeSet<FuncId> = BTreeSet::new();
        let mut too_deep = false;
        for func in funcs.iter().filter(|f| dirty.contains(&f.id)) {
            walks = walks.saturating_add(1);
            let mut walk = Walk::tracking_borrowed(func, &table, payloads);
            walk.expr(&func.body, Pos::Other, false, 0);
            too_deep |= walk.too_deep;
            demoted.extend(walk.demoted.into_iter().map(|idx| (func.id, idx)));
            values.extend(walk.func_values);
            for callee in walk.callees {
                callers.entry(callee).or_default().insert(func.id);
            }
        }
        let mut changed: BTreeSet<FuncId> = BTreeSet::new();
        if too_deep {
            for func in funcs {
                if table.demote_func(func.id) {
                    changed.insert(func.id);
                }
            }
        }
        for (id, idx) in demoted {
            if table.demote(id, idx) {
                changed.insert(id);
            }
        }
        for id in values {
            if table.demote_func(id) {
                changed.insert(id);
            }
        }
        if changed.is_empty() {
            return Ok((BorrowPlan { table }, walks));
        }
        dirty = changed
            .iter()
            .filter_map(|id| callers.get(id))
            .flatten()
            .copied()
            .collect();
    }
    Err(Diagnostic::CompilerBug {
        where_: "ipe_ir::borrow::analyze",
        detail: format!("borrow fixpoint did not settle within {max_rounds} rounds"),
    })
}

/// Write `plan` into `program`.
///
/// A verdict is admitted only as far as the emitter renders it: while
/// [`EMIT_RENDERS_BORROWED`] is false every parameter stays `Owned`.
pub fn apply(plan: &BorrowPlan, program: &mut Program) {
    for func in program.modules.iter_mut().flat_map(|m| m.funcs.iter_mut()) {
        let id = func.id;
        for (idx, param) in func.params.iter_mut().enumerate() {
            param.pass = match plan.table.pass(id, idx) {
                Some(ParamPass::Borrowed) if EMIT_RENDERS_BORROWED => ParamPass::Borrowed,
                Some(ParamPass::Borrowed | ParamPass::Owned) | None => ParamPass::Owned,
            };
        }
    }
}

/// Re-prove every function of `program` against the passes it carries.
///
/// # Errors
/// The first [`BorrowViolation`], as [`BorrowViolation::into_diagnostic`]
/// renders it from `where_`.
pub fn verify_program(
    program: &Program,
    interner: &Interner,
    where_: &'static str,
) -> Result<(), Diagnostic> {
    let table = PassTable::of_program(program);
    let payloads = program_payloads(program);
    for func in program.modules.iter().flat_map(|m| m.funcs.iter()) {
        verify(func, &table, &payloads).map_err(|v| v.into_diagnostic(func, interner, where_))?;
    }
    Ok(())
}

/// Re-prove that every `Borrowed` parameter of `func` is only read.
///
/// `table` gives the passes of every function `func` calls, and `payloads`
/// the enum payloads the effect-carrier test descends.
///
/// # Errors
/// The first [`BorrowViolation`] found.
pub fn verify(
    func: &Func,
    table: &PassTable,
    payloads: &EnumPayloadTable,
) -> Result<(), BorrowViolation> {
    if table.borrowed_count() == 0 && func.params.iter().all(|p| p.pass == ParamPass::Owned) {
        return Ok(());
    }
    let borrowed: Vec<usize> = func
        .params
        .iter()
        .enumerate()
        .filter(|(_, p)| matches!(p.pass, ParamPass::Borrowed))
        .map(|(i, _)| i)
        .collect();
    let mut walk = Walk::new(func, table, payloads, &borrowed);
    if let Some(&idx) = walk.demoted.first()
        && let Some(param) = func.params.get(idx)
    {
        return Err(BorrowViolation::Rebound {
            func: func.id,
            param: param.sym,
        });
    }
    walk.expr(&func.body, Pos::Other, false, 0);
    if let Some(callee) = walk.borrowing_value {
        return Err(BorrowViolation::BorrowingFuncValue {
            func: func.id,
            callee,
        });
    }
    if walk.too_deep {
        return Err(BorrowViolation::TooDeep { func: func.id });
    }
    walk.demoted
        .first()
        .and_then(|&idx| func.params.get(idx))
        .map_or(Ok(()), |param| {
            Err(BorrowViolation::NonReadUse {
                func: func.id,
                param: param.sym,
            })
        })
}

/// The enum payload table of every enum `program` declares.
fn program_payloads(program: &Program) -> EnumPayloadTable {
    enum_payload_table(
        program
            .modules
            .iter()
            .flat_map(|m| m.types.iter())
            .map(|TypeDef::Enum(def)| def),
    )
}

/// The syntactic position of a direct child, as the occurrence rules read it.
#[derive(Clone, Copy)]
enum Pos {
    /// The base of a field access; `moves` when the field holds an effect
    /// carrier, whose read moves it out of the base.
    AccessBase { moves: bool },
    /// A direct argument of a call to user function `callee` at slot `idx`.
    FuncArg { callee: FuncId, idx: usize },
    /// Any other position.
    Other,
}

/// One classification walk over a function body.
struct Walk<'a> {
    func: &'a Func,
    table: &'a PassTable,
    payloads: &'a EnumPayloadTable,
    /// Tracked parameter binders and their slot.
    tracked: BTreeMap<Symbol, usize>,
    /// Slots with a consuming occurrence (or otherwise not provably read-only).
    demoted: Vec<usize>,
    /// A first-class value of a function that borrows a parameter.
    borrowing_value: Option<FuncId>,
    /// Every user function named as a first-class value.
    func_values: Vec<FuncId>,
    /// Every user function called directly.
    callees: BTreeSet<FuncId>,
    too_deep: bool,
}

impl<'a> Walk<'a> {
    /// A walk tracking slots `slots`, with every slot whose binder is bound
    /// twice already demoted.
    fn new(
        func: &'a Func,
        table: &'a PassTable,
        payloads: &'a EnumPayloadTable,
        slots: &[usize],
    ) -> Self {
        let mut binders = BTreeSet::new();
        collect_binders(func, &func.body, &mut binders, 0);
        let mut tracked = BTreeMap::new();
        let mut demoted = Vec::new();
        for &idx in slots {
            let Some(param) = func.params.get(idx) else {
                continue;
            };
            let repeated = func
                .params
                .iter()
                .filter(|other| other.sym == param.sym)
                .count()
                > 1;
            if repeated || binders.contains(&param.sym) {
                demoted.push(idx);
            } else {
                tracked.insert(param.sym, idx);
            }
        }
        Self {
            func,
            table,
            payloads,
            tracked,
            demoted,
            borrowing_value: None,
            func_values: Vec::new(),
            callees: BTreeSet::new(),
            too_deep: false,
        }
    }

    /// A walk tracking the slots of `func` that are `Borrowed` in `table`.
    fn tracking_borrowed(
        func: &'a Func,
        table: &'a PassTable,
        payloads: &'a EnumPayloadTable,
    ) -> Self {
        let slots: Vec<usize> = (0..func.params.len())
            .filter(|&i| table.pass(func.id, i) == Some(ParamPass::Borrowed))
            .collect();
        Self::new(func, table, payloads, &slots)
    }

    /// Classify one occurrence of `sym` at `pos`.
    fn occur(&mut self, sym: Symbol, pos: Pos, deferred: bool) {
        let Some(&idx) = self.tracked.get(&sym) else {
            return;
        };
        let read = !deferred
            && match pos {
                Pos::AccessBase { moves } => !moves,
                Pos::FuncArg { callee, idx: slot } => {
                    self.table.pass(callee, slot) == Some(ParamPass::Borrowed)
                }
                Pos::Other => false,
            };
        if !read {
            self.demoted.push(idx);
        }
    }

    /// Demote every tracked slot (a shape the walk cannot prove read-only).
    fn demote_all(&mut self) {
        self.demoted.extend(self.tracked.values().copied());
    }

    fn all(&mut self, exprs: &[Expr], deferred: bool, depth: u16) {
        for e in exprs {
            self.expr(e, Pos::Other, deferred, depth);
        }
    }

    /// Walk `expr`, which sits at `pos`; `deferred` marks a subtree under a
    /// closure boundary or inside a kernel or FFI argument.
    #[allow(clippy::too_many_lines)] // one exhaustive arm per `Expr` variant, no wildcard
    fn expr(&mut self, expr: &Expr, pos: Pos, deferred: bool, depth: u16) {
        let Some(next) = depth.checked_add(1).filter(|d| *d <= MAX_IR_RENDER_DEPTH) else {
            self.too_deep = true;
            return;
        };
        let closure = deferred || boundary_kind(expr).is_some();
        match expr {
            Expr::Int(_)
            | Expr::Bool(_)
            | Expr::Float(_)
            | Expr::Str(_)
            | Expr::CustomElementRef { .. }
            | Expr::Char(_)
            | Expr::Unit => {}
            Expr::Var(s) | Expr::CloneVar(s) => self.occur(*s, pos, deferred),
            Expr::FuncValue { callee, .. } => {
                if let Callee::Func(id) = callee {
                    self.func_values.push(*id);
                    if self.table.borrows_any(*id) {
                        self.borrowing_value = Some(*id);
                    }
                }
            }
            Expr::Access {
                record, field_ty, ..
            } => {
                let moves = ir_type_has_effect_carrier(field_ty, self.payloads);
                self.expr(record, Pos::AccessBase { moves }, deferred, next);
            }
            Expr::Call { callee, args, .. } => match callee {
                // Only a call that fills every slot of one known callee
                // passes an argument straight into a slot; any other shape
                // consumes its arguments.
                Callee::Func(id) if self.table.arity(*id) == Some(args.len()) => {
                    self.callees.insert(*id);
                    for (idx, arg) in args.iter().enumerate() {
                        let pos = Pos::FuncArg { callee: *id, idx };
                        self.expr(arg, pos, deferred, next);
                    }
                }
                Callee::Func(id) => {
                    self.callees.insert(*id);
                    self.all(args, deferred, next);
                }
                Callee::Kernel(_) | Callee::Ffi { .. } => self.all(args, true, next),
            },
            Expr::TailLoop { params, body } => {
                let same = params.len() == self.func.params.len()
                    && params
                        .iter()
                        .zip(&self.func.params)
                        .all(|((s, _), p)| *s == p.sym);
                if !same {
                    self.demote_all();
                }
                self.expr(body, Pos::Other, deferred, next);
            }
            Expr::TailRecur { args } => {
                for (idx, arg) in args.iter().enumerate() {
                    let identity = self.func.params.get(idx).is_some_and(
                        |p| matches!(arg, Expr::Var(s) | Expr::CloneVar(s) if *s == p.sym),
                    );
                    if identity && !deferred {
                        continue;
                    }
                    if let Some(p) = self.func.params.get(idx)
                        && let Some(&slot) = self.tracked.get(&p.sym)
                    {
                        self.demoted.push(slot);
                    }
                    self.expr(arg, Pos::Other, deferred, next);
                }
                if args.len() != self.func.params.len() {
                    self.demote_all();
                }
            }
            Expr::Lambda { body, .. }
            | Expr::SharedLambda { body, .. }
            | Expr::OnceLambda { body, .. } => self.expr(body, Pos::Other, closure, next),
            Expr::TaskSeq { effect, rest } => {
                self.expr(effect, Pos::Other, deferred, next);
                self.expr(rest, Pos::Other, closure, next);
            }
            Expr::Ctor { args, .. } | Expr::Tuple(args) | Expr::List { items: args, .. } => {
                self.all(args, deferred, next);
            }
            Expr::BinOp { lhs, rhs, .. }
            | Expr::Cons {
                head: lhs,
                tail: rhs,
            } => {
                self.expr(lhs, Pos::Other, deferred, next);
                self.expr(rhs, Pos::Other, deferred, next);
            }
            Expr::Let { value, body, .. } | Expr::Destructure { value, body, .. } => {
                self.expr(value, Pos::Other, deferred, next);
                self.expr(body, Pos::Other, deferred, next);
            }
            Expr::CaptureClones { syms, body } => {
                for s in syms {
                    self.occur(*s, Pos::Other, deferred);
                }
                self.expr(body, Pos::Other, deferred, next);
            }
            Expr::If { cond, then_, else_ } => {
                self.expr(cond, Pos::Other, deferred, next);
                self.expr(then_, Pos::Other, deferred, next);
                self.expr(else_, Pos::Other, deferred, next);
            }
            Expr::Match(m) => {
                self.expr(m.scrutinee(), Pos::Other, deferred, next);
                for arm in m.arms() {
                    if let Some(guard) = &arm.guard {
                        self.expr(guard, Pos::Other, deferred, next);
                    }
                    self.expr(&arm.body, Pos::Other, deferred, next);
                }
            }
            Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
                self.expr(list, Pos::Other, deferred, next);
            }
            Expr::Record { fields, .. } => {
                for (_, e) in fields {
                    self.expr(e, Pos::Other, deferred, next);
                }
            }
            Expr::Update { record, fields } => {
                self.expr(record, Pos::Other, deferred, next);
                for (_, e) in fields {
                    self.expr(e, Pos::Other, deferred, next);
                }
            }
            Expr::Apply { func, args } => {
                self.expr(func, Pos::Other, deferred, next);
                self.all(args, deferred, next);
            }
        }
    }
}

/// Every name `expr` binds, except a `TailLoop` that rebinds exactly the
/// function's own parameters; the walk stops at the depth ceiling.
#[allow(clippy::too_many_lines)] // one exhaustive arm per `Expr` variant, no wildcard
fn collect_binders(func: &Func, expr: &Expr, out: &mut BTreeSet<Symbol>, depth: u16) {
    let Some(next) = depth.checked_add(1).filter(|d| *d <= MAX_IR_RENDER_DEPTH) else {
        return;
    };
    let go = |e: &Expr, out: &mut BTreeSet<Symbol>| collect_binders(func, e, out, next);
    match expr {
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::FuncValue { .. } => {}
        Expr::Let { name, value, body } => {
            out.insert(*name);
            go(value, out);
            go(body, out);
        }
        Expr::CaptureClones { syms, body } => {
            out.extend(syms.iter().copied());
            go(body, out);
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            pat_bound_symbols(binder, out);
            go(value, out);
            go(body, out);
        }
        Expr::Match(m) => {
            go(m.scrutinee(), out);
            for arm in m.arms() {
                pat_bound_symbols(&arm.pat, out);
                if let Some(guard) = &arm.guard {
                    go(guard, out);
                }
                go(&arm.body, out);
            }
        }
        Expr::Lambda { params, body, .. }
        | Expr::SharedLambda { params, body, .. }
        | Expr::OnceLambda { params, body, .. } => {
            out.extend(params.iter().map(|(s, _)| *s));
            go(body, out);
        }
        Expr::TailLoop { params, body } => {
            let own = params.len() == func.params.len()
                && params
                    .iter()
                    .zip(&func.params)
                    .all(|((s, _), p)| *s == p.sym);
            if !own {
                out.extend(params.iter().map(|(s, _)| *s));
            }
            go(body, out);
        }
        Expr::Ctor { args, .. }
        | Expr::Call { args, .. }
        | Expr::TailRecur { args }
        | Expr::Tuple(args)
        | Expr::List { items: args, .. } => {
            for a in args {
                go(a, out);
            }
        }
        Expr::BinOp { lhs, rhs, .. }
        | Expr::Cons {
            head: lhs,
            tail: rhs,
        }
        | Expr::TaskSeq {
            effect: lhs,
            rest: rhs,
        } => {
            go(lhs, out);
            go(rhs, out);
        }
        Expr::If { cond, then_, else_ } => {
            go(cond, out);
            go(then_, out);
            go(else_, out);
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => go(list, out),
        Expr::Access { record, .. } => go(record, out),
        Expr::Record { fields, .. } => {
            for (_, e) in fields {
                go(e, out);
            }
        }
        Expr::Update { record, fields } => {
            go(record, out);
            for (_, e) in fields {
                go(e, out);
            }
        }
        Expr::Apply { func: f, args } => {
            go(f, out);
            for a in args {
                go(a, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::once_closure::MovedCapture;
    use crate::{Arm, BinOp, CallPin, KernelFn, Match, ModPath, Module, OnFormKind, Pat};
    use ipe_diagnostics::DResult;
    use ipe_intern::Interner;

    const F: FuncId = FuncId::from_raw(0);
    const G: FuncId = FuncId::from_raw(1);

    fn module(funcs: Vec<Func>) -> Module {
        Module {
            name: ModPath(vec![]),
            types: vec![],
            funcs,
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
        }
    }

    fn program(funcs: Vec<Func>) -> Program {
        Program {
            modules: vec![module(funcs)],
            imports_unsafe_submodule: false,
            imported_web_capabilities: BTreeSet::new(),
        }
    }

    fn func(id: FuncId, name: Symbol, params: Vec<Param>, body: Expr) -> Func {
        Func {
            id,
            name,
            home: ModPath(vec![]),
            type_params: vec![],
            row_params: vec![],
            params,
            ret: IrType::Int,
            body,
        }
    }

    /// A parameter carrying a `Borrowed` fact no analysis produced.
    const fn borrowed(sym: Symbol, ty: IrType) -> Param {
        Param {
            sym,
            ty,
            pass: ParamPass::Borrowed,
        }
    }

    fn call(callee: Callee, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee,
            args,
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    fn read(p: Symbol, field: Symbol) -> Expr {
        Expr::Access {
            record: Box::new(Expr::Var(p)),
            field,
            field_ty: IrType::Int,
        }
    }

    fn lambda(param: Symbol, body: Expr) -> Expr {
        Expr::Lambda {
            params: vec![(param, IrType::Int)],
            ret: IrType::Int,
            body: Box::new(body),
        }
    }

    /// The analysis verdict for `f(p) = body` with every type eligible.
    fn verdict_of(
        interner: &mut Interner,
        body: impl FnOnce(Symbol, Symbol) -> Expr,
    ) -> DResult<Option<ParamPass>> {
        let (name, p, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("x")?,
        );
        let params = vec![Param::owned(p, IrType::Str)];
        let prog = program(vec![func(F, name, params, body(p, x))]);
        Ok(analyze(&prog, |_| true)?.table().pass(F, 0))
    }

    #[test]
    fn a_field_read_is_borrowed() -> DResult<()> {
        let mut interner = Interner::new();
        assert_eq!(verdict_of(&mut interner, read)?, Some(ParamPass::Borrowed));
        Ok(())
    }

    #[test]
    fn an_ineligible_type_stays_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let (name, p, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("x")?,
        );
        let params = vec![Param::owned(p, IrType::Str)];
        let prog = program(vec![func(F, name, params, read(p, x))]);
        let plan = analyze(&prog, |_| false)?;
        assert_eq!(plan.table().pass(F, 0), Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn a_capture_under_a_closure_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let y = interner.intern("y")?;
        let v = verdict_of(&mut interner, |p, x| lambda(y, read(p, x)))?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn a_returned_param_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let v = verdict_of(&mut interner, |p, _| Expr::Var(p))?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn a_param_stored_in_a_value_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let v = verdict_of(&mut interner, |p, _| {
            Expr::Tuple(vec![Expr::Var(p), Expr::Int(1)])
        })?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn a_param_compared_by_a_binop_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let v = verdict_of(&mut interner, |p, _| Expr::BinOp {
            op: BinOp::Eq,
            lhs: Box::new(Expr::Var(p)),
            rhs: Box::new(Expr::Var(p)),
        })?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn a_kernel_argument_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let v = verdict_of(&mut interner, |p, x| {
            call(Callee::Kernel(KernelFn::StringFromInt), vec![read(p, x)])
        })?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn an_effect_carrier_field_read_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let v = verdict_of(&mut interner, |p, x| Expr::Access {
            record: Box::new(Expr::Var(p)),
            field: x,
            field_ty: IrType::Task(Box::new(IrType::Unit)),
        })?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn a_rebound_param_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let v = verdict_of(&mut interner, |p, x| Expr::Let {
            name: p,
            value: Box::new(Expr::Int(1)),
            body: Box::new(read(p, x)),
        })?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn a_repeated_param_binder_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let (name, p, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("x")?,
        );
        let params = vec![Param::owned(p, IrType::Str), Param::owned(p, IrType::Str)];
        let prog = program(vec![func(F, name, params, read(p, x))]);
        let plan = analyze(&prog, |_| true)?;
        assert_eq!(plan.table().pass(F, 0), Some(ParamPass::Owned));
        assert_eq!(plan.table().pass(F, 1), Some(ParamPass::Owned));
        Ok(())
    }

    /// `f(p, n) = loop { if true then p.x else recur(next, n) }`.
    fn tail_loop_verdict(
        interner: &mut Interner,
        next: impl FnOnce(Symbol) -> Expr,
    ) -> DResult<Option<ParamPass>> {
        let (name, p, n, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("n")?,
            interner.intern("x")?,
        );
        let body = Expr::TailLoop {
            params: vec![(p, IrType::Str), (n, IrType::Int)],
            body: Box::new(Expr::If {
                cond: Box::new(Expr::Bool(true)),
                then_: Box::new(read(p, x)),
                else_: Box::new(Expr::TailRecur {
                    args: vec![next(p), Expr::Var(n)],
                }),
            }),
        };
        let params = vec![Param::owned(p, IrType::Str), Param::owned(n, IrType::Int)];
        let prog = program(vec![func(F, name, params, body)]);
        let plan = analyze(&prog, |ty| matches!(ty, IrType::Str))?;
        Ok(plan.table().pass(F, 0))
    }

    #[test]
    fn an_identity_tail_recursion_is_borrowed() -> DResult<()> {
        let mut interner = Interner::new();
        let v = tail_loop_verdict(&mut interner, Expr::Var)?;
        assert_eq!(v, Some(ParamPass::Borrowed));
        Ok(())
    }

    #[test]
    fn a_tail_recursion_reassigning_the_param_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let v = tail_loop_verdict(&mut interner, |_| Expr::Str("other".into()))?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    /// `f(p) = g(p)` and `g(q) = g_body(q)`.
    fn mutual(interner: &mut Interner, g_body: impl FnOnce(Symbol) -> Expr) -> DResult<PassTable> {
        let (fname, gname) = (interner.intern("f")?, interner.intern("g")?);
        let (p, q) = (interner.intern("p")?, interner.intern("q")?);
        let f_body = call(Callee::Func(G), vec![Expr::Var(p)]);
        let f = func(F, fname, vec![Param::owned(p, IrType::Str)], f_body);
        let g = func(G, gname, vec![Param::owned(q, IrType::Str)], g_body(q));
        Ok(analyze(&program(vec![f, g]), |_| true)?.table)
    }

    #[test]
    fn a_mutual_recursion_pass_through_is_borrowed() -> DResult<()> {
        let mut interner = Interner::new();
        let t = mutual(&mut interner, |q| call(Callee::Func(F), vec![Expr::Var(q)]))?;
        assert_eq!(t.pass(F, 0), Some(ParamPass::Borrowed));
        assert_eq!(t.pass(G, 0), Some(ParamPass::Borrowed));
        Ok(())
    }

    #[test]
    fn a_mutual_recursion_that_stores_demotes_both_sides() -> DResult<()> {
        let mut interner = Interner::new();
        let t = mutual(&mut interner, |q| Expr::Tuple(vec![Expr::Var(q)]))?;
        assert_eq!(t.pass(F, 0), Some(ParamPass::Owned));
        assert_eq!(t.pass(G, 0), Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn an_unresolved_callee_slot_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let missing = FuncId::from_raw(7);
        let v = verdict_of(&mut interner, |p, _| {
            call(Callee::Func(missing), vec![Expr::Var(p)])
        })?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    /// `f0(p) = f1(p)`, …, `f{n-1}(p) = (p)`: each round demotes one more slot.
    fn chain(interner: &mut Interner, n: u32) -> DResult<Vec<Func>> {
        let p = interner.intern("p")?;
        let mut funcs = Vec::new();
        for k in 0..n {
            let name = interner.intern(&format!("f{k}"))?;
            let next = k.saturating_add(1);
            let body = if next == n {
                Expr::Tuple(vec![Expr::Var(p)])
            } else {
                call(Callee::Func(FuncId::from_raw(next)), vec![Expr::Var(p)])
            };
            let params = vec![Param::owned(p, IrType::Str)];
            funcs.push(func(FuncId::from_raw(k), name, params, body));
        }
        Ok(funcs)
    }

    #[test]
    fn a_demotion_chain_settles_within_the_bound() -> DResult<()> {
        let mut interner = Interner::new();
        let plan = analyze(&program(chain(&mut interner, 8)?), |_| true)?;
        assert_eq!(plan.table().borrowed_count(), 0);
        Ok(())
    }

    #[test]
    fn a_fixpoint_past_its_bound_is_refused() -> DResult<()> {
        let mut interner = Interner::new();
        let funcs = chain(&mut interner, 8)?;
        let refs: Vec<&Func> = funcs.iter().collect();
        let mut table = PassTable::default();
        for f in &funcs {
            table.insert(f.id, vec![ParamPass::Borrowed]);
        }
        let out = fixpoint(&refs, table, &EnumPayloadTable::new(), 3);
        assert!(matches!(out, Err(Diagnostic::CompilerBug { .. })));
        Ok(())
    }

    #[test]
    fn a_repeated_func_id_is_refused() -> DResult<()> {
        let mut interner = Interner::new();
        let (name, p, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("x")?,
        );
        let one = func(F, name, vec![Param::owned(p, IrType::Str)], read(p, x));
        let out = analyze(&program(vec![one.clone(), one]), |_| true);
        assert!(matches!(out, Err(Diagnostic::CompilerBug { .. })));
        Ok(())
    }

    /// `depth` nested additions around a read of `p`.
    fn deep(p: Symbol, x: Symbol, depth: usize) -> Expr {
        let mut e = read(p, x);
        for _ in 0..depth {
            e = Expr::BinOp {
                op: BinOp::Add,
                lhs: Box::new(Expr::Int(0)),
                rhs: Box::new(e),
            };
        }
        e
    }

    #[test]
    fn a_body_past_the_depth_ceiling_is_owned() -> DResult<()> {
        let v = deep_walk(|| {
            let mut interner = Interner::new();
            let depth = usize::from(MAX_IR_RENDER_DEPTH) + 4;
            verdict_of(&mut interner, |p, x| deep(p, x, depth))
        })?;
        assert_eq!(v, Some(ParamPass::Owned));
        Ok(())
    }

    /// Run a walk over a body nested to the IR ceiling on the declared compile
    /// stack, which every production compile thread is spawned with.
    fn deep_walk<T: Send>(body: impl FnOnce() -> DResult<T> + Send) -> DResult<T> {
        crate::on_compile_stack(body).unwrap_or_else(|| {
            Err(Diagnostic::CompilerBug {
                where_: "borrow.tests.deep_walk",
                detail: "the compile-stack thread did not finish".to_owned(),
            })
        })
    }

    #[test]
    fn apply_admits_every_verdict_as_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let (name, p, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("x")?,
        );
        let params = vec![Param::owned(p, IrType::Str)];
        let mut prog = program(vec![func(F, name, params, read(p, x))]);
        let before = prog.clone();
        let plan = analyze(&prog, |_| true)?;
        assert_eq!(
            plan.table().borrowed_count(),
            1,
            "the plan borrows the read-only slot"
        );
        run(&mut prog, &interner, |_| true)?;
        assert_eq!(
            prog, before,
            "while the emitter renders no `&T` the program is unchanged"
        );
        Ok(())
    }

    /// `verify` over one hand-built function whose only parameter is `Borrowed`.
    fn verify_one(
        interner: &mut Interner,
        body: impl FnOnce(Symbol, Symbol) -> Expr,
    ) -> DResult<Result<(), BorrowViolation>> {
        let (name, p, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("x")?,
        );
        let f = func(F, name, vec![borrowed(p, IrType::Str)], body(p, x));
        let table = PassTable::of_funcs([&f]);
        Ok(verify(&f, &table, &EnumPayloadTable::new()))
    }

    #[test]
    fn verify_accepts_a_borrowed_field_read() -> DResult<()> {
        let mut interner = Interner::new();
        assert_eq!(verify_one(&mut interner, read)?, Ok(()));
        Ok(())
    }

    #[test]
    fn verify_rejects_a_borrowed_capture() -> DResult<()> {
        let mut interner = Interner::new();
        let y = interner.intern("y")?;
        let out = verify_one(&mut interner, |p, x| lambda(y, read(p, x)))?;
        assert!(matches!(
            out,
            Err(BorrowViolation::NonReadUse { func: F, .. })
        ));
        Ok(())
    }

    #[test]
    fn verify_rejects_a_borrowed_return() -> DResult<()> {
        let mut interner = Interner::new();
        let out = verify_one(&mut interner, |p, _| Expr::Var(p))?;
        assert!(matches!(out, Err(BorrowViolation::NonReadUse { .. })));
        Ok(())
    }

    #[test]
    fn verify_rejects_a_rebound_borrowed_param() -> DResult<()> {
        let mut interner = Interner::new();
        let out = verify_one(&mut interner, |p, x| Expr::Let {
            name: p,
            value: Box::new(Expr::Int(1)),
            body: Box::new(read(p, x)),
        })?;
        assert!(matches!(out, Err(BorrowViolation::Rebound { .. })));
        Ok(())
    }

    /// A body past the walk's ceiling is the emitter's nesting refusal,
    /// IPE-L0200 naming the function and its home, not a compiler bug that
    /// names a raw function id.
    #[test]
    fn borrow_depth_refusal_names_the_function() -> DResult<()> {
        let refused = deep_walk(|| {
            let mut interner = Interner::new();
            let (home, name, p, x) = (
                interner.intern("Main")?,
                interner.intern("deep")?,
                interner.intern("p")?,
                interner.intern("x")?,
            );
            let depth = usize::from(MAX_IR_RENDER_DEPTH) + 4;
            let mut f = func(F, name, vec![borrowed(p, IrType::Str)], deep(p, x, depth));
            f.home = ModPath(vec![home]);
            Ok(verify_program(&program(vec![f]), &interner, "borrow.tests"))
        })?;
        assert_eq!(
            refused,
            Err(Diagnostic::Lower {
                span: Span::DUMMY,
                msg: LowerError::BackendNestingTooDeep {
                    limit: MAX_IR_RENDER_DEPTH,
                    func: Some(ipe_diagnostics::EmitSite {
                        home: Box::new(["Main".into()]),
                        name: "deep".into(),
                    }),
                },
            })
        );
        Ok(())
    }

    #[test]
    fn verify_rejects_a_body_past_the_depth_ceiling() -> DResult<()> {
        let out = deep_walk(|| {
            let mut interner = Interner::new();
            let depth = usize::from(MAX_IR_RENDER_DEPTH) + 4;
            verify_one(&mut interner, |p, x| deep(p, x, depth))
        })?;
        assert!(matches!(out, Err(BorrowViolation::TooDeep { .. })));
        Ok(())
    }

    #[test]
    fn verify_rejects_a_borrowing_function_as_a_value() -> DResult<()> {
        let mut interner = Interner::new();
        let (fname, gname) = (interner.intern("f")?, interner.intern("g")?);
        let (p, x) = (interner.intern("p")?, interner.intern("x")?);
        let f = func(F, fname, vec![borrowed(p, IrType::Str)], read(p, x));
        let value = Expr::FuncValue {
            callee: Callee::Func(F),
            ty: IrType::Fun(vec![IrType::Str], Box::new(IrType::Int)),
        };
        let g = func(G, gname, vec![], value);
        let table = PassTable::of_funcs([&f, &g]);
        let out = verify(&g, &table, &EnumPayloadTable::new());
        assert!(matches!(
            out,
            Err(BorrowViolation::BorrowingFuncValue { func: G, callee: F })
        ));
        Ok(())
    }

    #[test]
    fn a_function_named_as_a_value_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let (fname, gname) = (interner.intern("f")?, interner.intern("g")?);
        let (p, x) = (interner.intern("p")?, interner.intern("x")?);
        let f = func(F, fname, vec![Param::owned(p, IrType::Str)], read(p, x));
        let value = Expr::FuncValue {
            callee: Callee::Func(F),
            ty: IrType::Fun(vec![IrType::Str], Box::new(IrType::Int)),
        };
        let g = func(G, gname, vec![], value);
        let plan = analyze(&program(vec![f, g]), |_| true)?;
        assert_eq!(plan.table().pass(F, 0), Some(ParamPass::Owned));
        Ok(())
    }

    #[test]
    fn a_too_deep_body_demotes_every_function() -> DResult<()> {
        deep_walk(a_too_deep_body_demotes_every_function_body)
    }

    fn a_too_deep_body_demotes_every_function_body() -> DResult<()> {
        let mut interner = Interner::new();
        let (fname, gname) = (interner.intern("f")?, interner.intern("g")?);
        let (p, q, x) = (
            interner.intern("p")?,
            interner.intern("q")?,
            interner.intern("x")?,
        );
        let shallow = func(F, fname, vec![Param::owned(p, IrType::Str)], read(p, x));
        let depth = usize::from(MAX_IR_RENDER_DEPTH) + 4;
        let nested = func(
            G,
            gname,
            vec![Param::owned(q, IrType::Str)],
            deep(q, x, depth),
        );
        let plan = analyze(&program(vec![shallow, nested]), |_| true)?;
        assert_eq!(plan.table().borrowed_count(), 0);
        Ok(())
    }

    #[test]
    fn verify_accepts_a_deep_all_owned_program() -> DResult<()> {
        deep_walk(verify_accepts_a_deep_all_owned_program_body)
    }

    fn verify_accepts_a_deep_all_owned_program_body() -> DResult<()> {
        let mut interner = Interner::new();
        let (name, p, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("x")?,
        );
        let depth = usize::from(MAX_IR_RENDER_DEPTH) + 4;
        let params = vec![Param::owned(p, IrType::Str)];
        let prog = program(vec![func(F, name, params, deep(p, x, depth))]);
        assert_eq!(verify_program(&prog, &interner, "test"), Ok(()));
        Ok(())
    }

    #[test]
    fn verify_program_reports_a_compiler_bug() -> DResult<()> {
        let mut interner = Interner::new();
        let (name, p) = (interner.intern("f")?, interner.intern("p")?);
        let params = vec![borrowed(p, IrType::Str)];
        let prog = program(vec![func(F, name, params, Expr::Var(p))]);
        let out = verify_program(&prog, &interner, "test");
        assert!(matches!(
            out,
            Err(Diagnostic::CompilerBug { where_: "test", .. })
        ));
        Ok(())
    }

    /// Every position that consumes the value placed there, one body per
    /// shape, each around the only occurrence of `p`.
    fn value_consuming_bodies(p: Symbol, x: Symbol) -> DResult<Vec<(&'static str, Expr)>> {
        let var = || Box::new(Expr::Var(p));
        let int = || Box::new(Expr::Int(0));
        Ok(vec![
            ("clone return", Expr::CloneVar(p)),
            (
                "let alias",
                Expr::Let {
                    name: x,
                    value: var(),
                    body: int(),
                },
            ),
            (
                "destructure value",
                Expr::Destructure {
                    binder: Pat::Wildcard,
                    value: var(),
                    body: int(),
                },
            ),
            (
                "match scrutinee",
                Expr::Match(Match::new(
                    Expr::Var(p),
                    vec![Arm::new(
                        Pat::Ctor {
                            home: ModPath(vec![]),
                            ty: x,
                            variant: x,
                            args: vec![],
                        },
                        Expr::Int(0),
                    )],
                    &[x],
                )?),
            ),
            (
                "if condition",
                Expr::If {
                    cond: var(),
                    then_: int(),
                    else_: int(),
                },
            ),
            (
                "update base",
                Expr::Update {
                    record: var(),
                    fields: vec![],
                },
            ),
            (
                "record field",
                Expr::Record {
                    fields: vec![(x, Expr::Var(p))],
                    ty: None,
                },
            ),
            (
                "constructor argument",
                Expr::Ctor {
                    home: ModPath(vec![]),
                    ty: x,
                    variant: x,
                    args: vec![Expr::Var(p)],
                },
            ),
            (
                "list item",
                Expr::List {
                    elem: IrType::Str,
                    items: vec![Expr::Var(p)],
                },
            ),
            (
                "cons head",
                Expr::Cons {
                    head: var(),
                    tail: Box::new(Expr::List {
                        elem: IrType::Str,
                        items: vec![],
                    }),
                },
            ),
            (
                "list index",
                Expr::ListIndexClone {
                    list: var(),
                    index: 0,
                    elem: IrType::Str,
                },
            ),
        ])
    }

    /// The remaining consuming positions: a list shape check, calls, deferred
    /// reads and loops, one body per shape.
    fn deferring_bodies(p: Symbol, x: Symbol) -> Vec<(&'static str, Expr)> {
        let own_loop = |recur: Vec<Expr>| Expr::TailLoop {
            params: vec![(p, IrType::Str)],
            body: Box::new(Expr::If {
                cond: Box::new(Expr::Bool(true)),
                then_: Box::new(read(p, x)),
                else_: Box::new(Expr::TailRecur { args: recur }),
            }),
        };
        vec![
            (
                "list length check",
                Expr::ListLenCheck {
                    list: Box::new(Expr::Var(p)),
                    len: 0,
                    exact: true,
                },
            ),
            (
                "apply argument",
                Expr::Apply {
                    func: Box::new(Expr::Var(x)),
                    args: vec![Expr::Var(p)],
                },
            ),
            (
                "ffi argument",
                call(
                    Callee::Ffi {
                        ident: x,
                        asserted: false,
                    },
                    vec![read(p, x)],
                ),
            ),
            (
                "task continuation",
                Expr::TaskSeq {
                    effect: Box::new(Expr::Unit),
                    rest: Box::new(read(p, x)),
                },
            ),
            (
                "shared closure",
                Expr::SharedLambda {
                    params: vec![],
                    ret: IrType::Int,
                    body: Box::new(read(p, x)),
                },
            ),
            (
                "once closure",
                Expr::OnceLambda {
                    params: vec![],
                    ret: IrType::Int,
                    body: Box::new(read(p, x)),
                    capture: MovedCapture {
                        name: p,
                        lo: 0,
                        hi: 0,
                    },
                },
            ),
            (
                "foreign loop",
                Expr::TailLoop {
                    params: vec![(x, IrType::Str)],
                    body: Box::new(read(p, x)),
                },
            ),
            ("short tail recursion", own_loop(vec![])),
            (
                "long tail recursion",
                own_loop(vec![Expr::Var(p), Expr::Int(0)]),
            ),
        ]
    }

    #[test]
    fn every_consuming_position_is_owned() -> DResult<()> {
        let mut interner = Interner::new();
        let (name, p, x) = (
            interner.intern("f")?,
            interner.intern("p")?,
            interner.intern("x")?,
        );
        let mut bodies = value_consuming_bodies(p, x)?;
        bodies.extend(deferring_bodies(p, x));
        for (shape, body) in bodies {
            let params = vec![Param::owned(p, IrType::Str)];
            let prog = program(vec![func(F, name, params, body.clone())]);
            let plan = analyze(&prog, |_| true)?;
            assert_eq!(
                plan.table().pass(F, 0),
                Some(ParamPass::Owned),
                "{shape}: the analysis borrows a consumed param"
            );
            let f = func(F, name, vec![borrowed(p, IrType::Str)], body);
            let table = PassTable::of_funcs([&f]);
            assert!(
                matches!(
                    verify(&f, &table, &EnumPayloadTable::new()),
                    Err(BorrowViolation::NonReadUse { .. })
                ),
                "{shape}: verify accepts a consumed borrowed param"
            );
        }
        Ok(())
    }

    /// `f(p) = g(p)` against a `g` with two read-only parameters.
    #[test]
    fn a_call_short_of_its_callee_arity_consumes_its_arguments() -> DResult<()> {
        let mut interner = Interner::new();
        let (fname, gname) = (interner.intern("f")?, interner.intern("g")?);
        let (p, first, second, x) = (
            interner.intern("p")?,
            interner.intern("a")?,
            interner.intern("b")?,
            interner.intern("x")?,
        );
        let g_body = Expr::Tuple(vec![read(first, x), read(second, x)]);
        let g_params = vec![
            Param::owned(first, IrType::Str),
            Param::owned(second, IrType::Str),
        ];
        let pair = func(G, gname, g_params, g_body);
        let f_body = call(Callee::Func(G), vec![Expr::Var(p)]);
        let forwarder = func(F, fname, vec![Param::owned(p, IrType::Str)], f_body.clone());
        let plan = analyze(&program(vec![forwarder, pair.clone()]), |_| true)?;
        assert_eq!(plan.table().pass(G, 0), Some(ParamPass::Borrowed));
        assert_eq!(plan.table().pass(F, 0), Some(ParamPass::Owned));

        let g_borrowing = func(
            G,
            gname,
            vec![borrowed(first, IrType::Str), borrowed(second, IrType::Str)],
            pair.body,
        );
        let f_borrowing = func(F, fname, vec![borrowed(p, IrType::Str)], f_body);
        let table = PassTable::of_funcs([&f_borrowing, &g_borrowing]);
        assert!(matches!(
            verify(&f_borrowing, &table, &EnumPayloadTable::new()),
            Err(BorrowViolation::NonReadUse { func: F, .. })
        ));
        Ok(())
    }

    /// A carried table whose id two functions share answers no slot for it,
    /// so an argument passed under that id consumes.
    #[test]
    fn a_repeated_id_in_a_carried_table_has_no_slot() -> DResult<()> {
        let mut interner = Interner::new();
        let (fname, gname) = (interner.intern("f")?, interner.intern("g")?);
        let (p, q, x) = (
            interner.intern("p")?,
            interner.intern("q")?,
            interner.intern("x")?,
        );
        let owning = func(G, gname, vec![Param::owned(q, IrType::Str)], Expr::Var(q));
        let borrowing = func(G, gname, vec![borrowed(q, IrType::Str)], read(q, x));
        let caller_body = call(Callee::Func(G), vec![Expr::Var(p)]);
        let caller = func(F, fname, vec![borrowed(p, IrType::Str)], caller_body);
        for order in [[&owning, &borrowing], [&borrowing, &owning]] {
            let [first, second] = order;
            let table = PassTable::of_funcs([first, second, &caller]);
            assert_eq!(table.pass(G, 0), None);
            assert!(table.borrows_any(G));
            assert!(matches!(
                verify(&caller, &table, &EnumPayloadTable::new()),
                Err(BorrowViolation::NonReadUse { func: F, .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn the_fixpoint_rewalks_only_callers_of_a_demoted_function() -> DResult<()> {
        let mut interner = Interner::new();
        let n: u32 = 32;
        let funcs = chain(&mut interner, n)?;
        let refs: Vec<&Func> = funcs.iter().collect();
        let mut table = PassTable::default();
        for f in &funcs {
            table.insert(f.id, vec![ParamPass::Borrowed]);
        }
        let rounds = table.borrowed_count().saturating_add(1);
        let (plan, walks) = fixpoint(&refs, table, &EnumPayloadTable::new(), rounds)?;
        assert_eq!(plan.table().borrowed_count(), 0);
        let len = usize::try_from(n).map_err(|_| Diagnostic::CompilerBug {
            where_: "test",
            detail: "chain length".to_owned(),
        })?;
        assert!(
            walks < len.saturating_mul(2),
            "{walks} body walks for a {len}-function chain"
        );
        Ok(())
    }
}
