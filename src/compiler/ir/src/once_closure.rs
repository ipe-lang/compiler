//! The one verdict on whether a closure position calls its closure at most once.
//!
//! A closure that moves a non-`Clone` capture is [`Expr::OnceLambda`]: it is
//! `FnOnce` only. [`admits_once`] is the single table that decides which parent
//! positions may hold one. The lowerer refuses an `OnceLambda` at every other
//! position, and the backend emits one only where this predicate admits it, so
//! the two boundaries cannot disagree.
//!
//! [`boundary_kind`] is the one table of every closure the backend emits from
//! the IR, spelled or synthesized, and [`CaptureScope`] is the path state a
//! capture walker carries across those boundaries in place of a depth count.

use ipe_intern::Symbol;

use crate::{Expr, IrType, KernelFn};

/// The first non-`Clone` capture an [`Expr::OnceLambda`] body moves.
///
/// `lo`/`hi` are the raw byte offsets of the capture's use in the source: the
/// IR carries no `Span`, and the lowerer rebuilds one from these offsets for
/// the refusal diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MovedCapture {
    /// The moved local.
    pub name: Symbol,
    /// Start offset of the capture's use.
    pub lo: u32,
    /// End offset of the capture's use.
    pub hi: u32,
}

/// The position a closure value occupies in its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureSite<'a> {
    /// `Apply { func: <closure>, args }`: `arity` is the closure's parameter
    /// count and `args` the number of arguments applied.
    ImmediateApply {
        /// The closure's parameter count.
        arity: usize,
        /// The number of arguments the apply passes.
        args: usize,
    },
    /// Argument `index` of a kernel call.
    KernelArg {
        /// The called kernel.
        kernel: &'a KernelFn,
        /// The argument position, in Ipê order.
        index: usize,
    },
    /// The continuation of an [`Expr::TaskSeq`]: the backend wraps it in the
    /// `move |_|` closure it hands to the runtime's `FnOnce` `task_and_then`
    /// slot, so it runs at most once.
    TaskSeqRest,
    /// Any other position: let-bound, stored, returned, a constructor field, a
    /// user-function argument, a list element.
    Other,
}

/// Does `site` call the closure it holds at most once?
///
/// * An immediate apply admits exactly when it is saturated with at least one
///   argument: the backend then inlines the closure as `let` bindings, so the
///   closure is never boxed.
/// * A kernel argument admits only `Task.andThen`'s continuation (index 0),
///   which the backend boxes into the runtime's `Box<dyn FnOnce>` slot.
/// * A `TaskSeq` continuation admits: the runtime consumes it once.
/// * Every other position never admits. A user function's parameter is an
///   `impl Fn` or a boxed `Fn`, and its body may call it many times.
#[must_use]
pub const fn admits_once(site: &ClosureSite<'_>) -> bool {
    match site {
        ClosureSite::ImmediateApply { arity, args } => *arity == *args && *args > 0,
        ClosureSite::KernelArg { kernel, index } => {
            matches!(**kernel, KernelFn::TaskAndThen) && *index == 0
        }
        ClosureSite::TaskSeqRest => true,
        ClosureSite::Other => false,
    }
}

/// How often an emitted closure's body may run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureKind {
    /// Called at most once: the closure may move its captures out.
    Once,
    /// Possibly called many times: a capture moved out of its environment
    /// leaves the next call without it.
    Recallable,
}

/// The kind of the closure `expr` emits around a sub-expression, if any.
///
/// A closure literal emits one around its body; a `TaskSeq` emits one around
/// its `rest` continuation, never around its `effect`. A source
/// [`Expr::Lambda`] reads `Recallable` wherever it sits, since the context it
/// is built in can pin its carrier to `Box<dyn Fn>`. Every other node emits no
/// closure. The match is total over [`Expr`], so a new node form must state
/// its boundary here.
#[must_use]
pub const fn boundary_kind(expr: &Expr) -> Option<ClosureKind> {
    match expr {
        Expr::Lambda { .. } | Expr::SharedLambda { .. } => Some(ClosureKind::Recallable),
        Expr::OnceLambda { .. } => Some(ClosureKind::Once),
        Expr::TaskSeq { .. } => {
            if admits_once(&ClosureSite::TaskSeqRest) {
                Some(ClosureKind::Once)
            } else {
                Some(ClosureKind::Recallable)
            }
        }
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::Ctor { .. }
        | Expr::BinOp { .. }
        | Expr::Let { .. }
        | Expr::Destructure { .. }
        | Expr::If { .. }
        | Expr::Match(_)
        | Expr::Call { .. }
        | Expr::Tuple(_)
        | Expr::List { .. }
        | Expr::Cons { .. }
        | Expr::ListIndexClone { .. }
        | Expr::ListLenCheck { .. }
        | Expr::Record { .. }
        | Expr::Access { .. }
        | Expr::Update { .. }
        | Expr::Apply { .. }
        | Expr::FuncValue { .. }
        | Expr::TailLoop { .. }
        | Expr::TailRecur { .. } => None,
    }
}

/// Where a capture read sits relative to the emitted closures around it.
///
/// A walk starts at the binder's own frame, [`Self::Top`], and steps through
/// each closure boundary with [`Self::enter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureScope {
    /// The binder's own frame: no closure crossed.
    Top,
    /// Inside only `Once` closures.
    InOnce,
    /// Inside a `Recallable` closure, with no closure inside it crossed.
    InRecallable,
    /// Inside a closure that is itself inside a `Recallable` closure.
    PastRecallable,
}

impl CaptureScope {
    /// The scope inside a closure of `kind` entered from `self`.
    #[must_use]
    pub const fn enter(self, kind: ClosureKind) -> Self {
        match (self, kind) {
            (Self::Top | Self::InOnce, ClosureKind::Once) => Self::InOnce,
            (Self::Top | Self::InOnce, ClosureKind::Recallable) => Self::InRecallable,
            (Self::InRecallable | Self::PastRecallable, _) => Self::PastRecallable,
        }
    }

    /// The scope inside the closure `expr` emits, or `self` when it emits none.
    #[must_use]
    pub const fn enter_boundary(self, expr: &Expr) -> Self {
        match boundary_kind(expr) {
            Some(kind) => self.enter(kind),
            None => self,
        }
    }

    /// Does a call through the capture here move it out of a `Recallable` environment?
    ///
    /// Only past a `Recallable` closure: building the inner closure moves the
    /// capture in on each call of the outer one.
    #[must_use]
    pub const fn borrow_is_hazard(self) -> bool {
        matches!(self, Self::PastRecallable)
    }

    /// Does a by-value read here move the capture out of a `Recallable` environment?
    #[must_use]
    pub const fn move_is_hazard(self) -> bool {
        matches!(self, Self::InRecallable | Self::PastRecallable)
    }
}

/// A closure's parameters, return type and body, borrowed from its IR node.
pub type ClosureParts<'e> = (&'e [(Symbol, IrType)], &'e IrType, &'e Expr);

/// The parameters, return type and body of an [`Expr::OnceLambda`] at an admitted `site`.
///
/// `None` for any other expression, and for an `OnceLambda` at a position
/// [`admits_once`] refuses. The backend's admitted emit paths read a once
/// closure only through this, so they share the lowerer's verdict.
#[must_use]
pub fn admitted_once_parts<'e>(expr: &'e Expr, site: &ClosureSite<'_>) -> Option<ClosureParts<'e>> {
    if let Expr::OnceLambda {
        params, ret, body, ..
    } = expr
        && admits_once(site)
    {
        Some((params.as_slice(), ret, body))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn immediate(arity: usize, args: usize) -> bool {
        admits_once(&ClosureSite::ImmediateApply { arity, args })
    }

    fn kernel_arg(kernel: KernelFn, index: usize) -> bool {
        admits_once(&ClosureSite::KernelArg {
            kernel: &kernel,
            index,
        })
    }

    #[test]
    fn immediate_apply_admits_only_a_saturated_non_empty_apply() {
        assert!(immediate(1, 1));
        assert!(immediate(2, 2));
        assert!(!immediate(2, 1), "an under-applied closure is a value");
        assert!(!immediate(1, 2), "a curried apply is not inlined");
        assert!(!immediate(0, 0), "a zero-argument apply is boxed");
    }

    #[test]
    fn kernel_arg_admits_only_the_task_and_then_continuation() {
        assert!(kernel_arg(KernelFn::TaskAndThen, 0));
        assert!(!kernel_arg(KernelFn::TaskAndThen, 1));
        assert!(!kernel_arg(KernelFn::TaskMap, 0));
        assert!(!kernel_arg(KernelFn::ListMap, 0));
    }

    #[test]
    fn other_never_admits() {
        assert!(!admits_once(&ClosureSite::Other));
    }

    #[test]
    fn task_seq_rest_admits_once() {
        assert!(admits_once(&ClosureSite::TaskSeqRest));
    }

    #[test]
    fn enter_follows_the_transition_table() {
        use CaptureScope::{InOnce, InRecallable, PastRecallable, Top};
        use ClosureKind::{Once, Recallable};
        let rows = [
            (Top, Once, InOnce),
            (InOnce, Once, InOnce),
            (InRecallable, Once, PastRecallable),
            (PastRecallable, Once, PastRecallable),
            (Top, Recallable, InRecallable),
            (InOnce, Recallable, InRecallable),
            (InRecallable, Recallable, PastRecallable),
            (PastRecallable, Recallable, PastRecallable),
        ];
        for (from, kind, to) in rows {
            assert_eq!(from.enter(kind), to, "{from:?} entering {kind:?}");
        }
    }

    #[test]
    fn hazards_follow_the_read_kind_table() {
        use CaptureScope::{InOnce, InRecallable, PastRecallable, Top};
        for scope in [Top, InOnce, InRecallable] {
            assert!(!scope.borrow_is_hazard(), "{scope:?}");
        }
        assert!(PastRecallable.borrow_is_hazard());
        for scope in [Top, InOnce] {
            assert!(!scope.move_is_hazard(), "{scope:?}");
        }
        for scope in [InRecallable, PastRecallable] {
            assert!(scope.move_is_hazard(), "{scope:?}");
        }
    }

    #[test]
    fn a_run_statement_continuation_is_once_and_past_recallable_inside_a_lambda()
    -> ipe_diagnostics::DResult<()> {
        let mut i = ipe_intern::Interner::new();
        let at = i.intern("at")?;
        let task_seq = Expr::TaskSeq {
            effect: Box::new(Expr::Unit),
            rest: Box::new(Expr::Unit),
        };
        let lambda = Expr::Lambda {
            params: vec![(at, IrType::Str)],
            ret: IrType::Unit,
            body: Box::new(task_seq.clone()),
        };
        assert_eq!(boundary_kind(&task_seq), Some(ClosureKind::Once));
        assert_eq!(boundary_kind(&lambda), Some(ClosureKind::Recallable));
        assert_eq!(boundary_kind(&Expr::Unit), None);
        let in_lambda = CaptureScope::Top.enter_boundary(&lambda);
        assert_eq!(in_lambda, CaptureScope::InRecallable);
        let in_rest = in_lambda.enter_boundary(&task_seq);
        assert_eq!(in_rest, CaptureScope::PastRecallable);
        assert!(in_rest.borrow_is_hazard());
        assert_eq!(
            CaptureScope::Top.enter_boundary(&task_seq),
            CaptureScope::InOnce,
            "a top-level run statement's continuation stays bare"
        );
        Ok(())
    }

    #[test]
    fn admitted_parts_read_only_an_admitted_once_lambda() -> ipe_diagnostics::DResult<()> {
        let mut i = ipe_intern::Interner::new();
        let x = i.intern("x")?;
        let once = Expr::OnceLambda {
            params: vec![(x, IrType::Int)],
            ret: IrType::Int,
            body: Box::new(Expr::Var(x)),
            capture: MovedCapture {
                name: x,
                lo: 0,
                hi: 1,
            },
        };
        let lambda = Expr::Lambda {
            params: vec![(x, IrType::Int)],
            ret: IrType::Int,
            body: Box::new(Expr::Var(x)),
        };
        let admitted = ClosureSite::KernelArg {
            kernel: &KernelFn::TaskAndThen,
            index: 0,
        };
        assert!(admitted_once_parts(&once, &admitted).is_some());
        assert!(admitted_once_parts(&once, &ClosureSite::Other).is_none());
        assert!(admitted_once_parts(&lambda, &admitted).is_none());
        Ok(())
    }
}
