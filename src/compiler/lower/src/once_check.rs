//! The once check: refuse every [`Expr::OnceLambda`] whose parent may call it
//! more than once.
//!
//! A closure that moves a non-`Clone` capture is `FnOnce` only, so the lowerer
//! builds it as an [`Expr::OnceLambda`], a source lambda and an eta-built
//! closure alike. Building an inner closure that captures the value moves it
//! too, so the parent of such a closure is once-only as well. This walk visits every
//! child position of a lowered body, names the position as a [`ClosureSite`],
//! and asks [`admits_once`] — the single verdict the backend reads too. An
//! unadmitted once closure is refused with IPE-L0126 at the moved capture's
//! source span, before any Rust is emitted.

use ipe_diagnostics::{DResult, Diagnostic, Feature, LowerError, Span};
use ipe_ir::once_closure::{ClosureSite, admits_once};
use ipe_ir::{Callee, Expr};

/// Refuse every unadmitted [`Expr::OnceLambda`] in the lowered body `body`.
///
/// # Errors
///
/// IPE-L0126 (`Feature::RebuiltClosureMovesCapture`) at the moved capture's
/// span for the first once closure whose position may call it more than once.
pub fn check_once_closures(body: &Expr) -> DResult<()> {
    check(body, &ClosureSite::Other)
}

/// The parameter count of a closure literal, `0` for any other callee.
const fn closure_arity(func: &Expr) -> usize {
    match func {
        Expr::Lambda { params, .. }
        | Expr::SharedLambda { params, .. }
        | Expr::OnceLambda { params, .. } => params.len(),
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
        | Expr::TaskSeq { .. }
        | Expr::TailLoop { .. }
        | Expr::TailRecur { .. } => 0,
    }
}

/// Check every child of `expr` at [`ClosureSite::Other`].
fn check_all<'e>(children: impl IntoIterator<Item = &'e Expr>) -> DResult<()> {
    for child in children {
        check(child, &ClosureSite::Other)?;
    }
    Ok(())
}

/// Check `expr`, which occupies `site` in its parent.
fn check(expr: &Expr, site: &ClosureSite<'_>) -> DResult<()> {
    match expr {
        Expr::OnceLambda { body, capture, .. } => {
            if !admits_once(site) {
                return Err(Diagnostic::Lower {
                    span: Span {
                        lo: capture.lo,
                        hi: capture.hi,
                    },
                    msg: LowerError::Unsupported(Feature::RebuiltClosureMovesCapture),
                });
            }
            check(body, &ClosureSite::Other)
        }
        Expr::Apply { func, args } => {
            check(
                func,
                &ClosureSite::ImmediateApply {
                    arity: closure_arity(func),
                    args: args.len(),
                },
            )?;
            check_all(args)
        }
        Expr::Call { callee, args, .. } => match callee {
            Callee::Kernel(kernel) => {
                for (index, arg) in args.iter().enumerate() {
                    check(arg, &ClosureSite::KernelArg { kernel, index })?;
                }
                Ok(())
            }
            Callee::Func(_) | Callee::Ffi { .. } => check_all(args),
        },
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::FuncValue { .. } => Ok(()),
        Expr::Ctor { args, .. } | Expr::Tuple(args) | Expr::List { items: args, .. } => {
            check_all(args)
        }
        Expr::TailRecur { args } => check_all(args),
        Expr::BinOp { lhs, rhs, .. } => check_all([lhs.as_ref(), rhs.as_ref()]),
        Expr::Let { value, body, .. } | Expr::Destructure { value, body, .. } => {
            check_all([value.as_ref(), body.as_ref()])
        }
        Expr::If { cond, then_, else_ } => {
            check_all([cond.as_ref(), then_.as_ref(), else_.as_ref()])
        }
        Expr::Match(m) => {
            check(m.scrutinee(), &ClosureSite::Other)?;
            for arm in m.arms() {
                check(&arm.body, &ClosureSite::Other)?;
                if let Some(guard) = &arm.guard {
                    check(guard, &ClosureSite::Other)?;
                }
            }
            Ok(())
        }
        Expr::Cons { head, tail } => check_all([head.as_ref(), tail.as_ref()]),
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            check(list, &ClosureSite::Other)
        }
        Expr::Record { fields, .. } => check_all(fields.iter().map(|(_, e)| e)),
        Expr::Access { record, .. } => check(record, &ClosureSite::Other),
        Expr::Update { record, fields } => {
            check(record, &ClosureSite::Other)?;
            check_all(fields.iter().map(|(_, e)| e))
        }
        Expr::Lambda { body, .. }
        | Expr::SharedLambda { body, .. }
        | Expr::TailLoop { body, .. } => check(body, &ClosureSite::Other),
        Expr::TaskSeq { effect, rest } => check_all([effect.as_ref(), rest.as_ref()]),
    }
}

#[cfg(test)]
mod tests {
    use super::check_once_closures;
    use ipe_diagnostics::{DResult, Diagnostic, Feature, LowerError, Span};
    use ipe_intern::Interner;
    use ipe_ir::once_closure::MovedCapture;
    use ipe_ir::{CallPin, Callee, Expr, IrType, KernelFn, OnFormKind};

    fn once(i: &mut Interner) -> DResult<Expr> {
        let x = i.intern("x")?;
        let h = i.intern("h")?;
        Ok(Expr::OnceLambda {
            params: vec![(x, IrType::Int)],
            ret: IrType::Int,
            body: Box::new(Expr::Apply {
                func: Box::new(Expr::Var(h)),
                args: vec![Expr::Var(x)],
            }),
            capture: MovedCapture {
                name: h,
                lo: 7,
                hi: 8,
            },
        })
    }

    fn kernel_call(kernel: KernelFn, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Callee::Kernel(kernel),
            args,
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    fn refused_at(result: &DResult<()>, lo: u32, hi: u32) -> bool {
        matches!(
            result,
            Err(Diagnostic::Lower {
                span,
                msg: LowerError::Unsupported(Feature::RebuiltClosureMovesCapture),
            }) if *span == Span { lo, hi }
        )
    }

    #[test]
    fn admitted_positions_pass() -> DResult<()> {
        let mut i = Interner::new();
        let applied = Expr::Apply {
            func: Box::new(once(&mut i)?),
            args: vec![Expr::Int(1)],
        };
        assert!(check_once_closures(&applied).is_ok());
        let and_then = kernel_call(KernelFn::TaskAndThen, vec![once(&mut i)?, Expr::Unit]);
        assert!(check_once_closures(&and_then).is_ok());
        Ok(())
    }

    #[test]
    fn unadmitted_positions_refuse_at_the_capture() -> DResult<()> {
        let mut i = Interner::new();
        let bare = once(&mut i)?;
        assert!(refused_at(&check_once_closures(&bare), 7, 8));
        let mapped = kernel_call(KernelFn::ListMap, vec![once(&mut i)?, Expr::Unit]);
        assert!(refused_at(&check_once_closures(&mapped), 7, 8));
        let second = kernel_call(KernelFn::TaskAndThen, vec![Expr::Unit, once(&mut i)?]);
        assert!(refused_at(&check_once_closures(&second), 7, 8));
        let under_applied = Expr::Apply {
            func: Box::new(once(&mut i)?),
            args: vec![],
        };
        assert!(refused_at(&check_once_closures(&under_applied), 7, 8));
        let nested = Expr::Lambda {
            params: vec![],
            ret: IrType::Int,
            body: Box::new(once(&mut i)?),
        };
        assert!(refused_at(&check_once_closures(&nested), 7, 8));
        Ok(())
    }

    /// `Task.andThen (\t -> Task.andThen <once> t)`: a once closure in a once closure.
    #[test]
    fn a_once_closure_inside_an_admitted_once_closure_passes() -> DResult<()> {
        let mut i = Interner::new();
        let t = i.intern("t")?;
        let h = i.intern("h")?;
        let outer = Expr::OnceLambda {
            params: vec![(t, IrType::Int)],
            ret: IrType::Int,
            body: Box::new(kernel_call(
                KernelFn::TaskAndThen,
                vec![once(&mut i)?, Expr::Var(t)],
            )),
            capture: MovedCapture {
                name: h,
                lo: 3,
                hi: 4,
            },
        };
        let admitted = kernel_call(KernelFn::TaskAndThen, vec![outer.clone(), Expr::Unit]);
        assert!(check_once_closures(&admitted).is_ok());
        let mapped = kernel_call(KernelFn::ListMap, vec![outer, Expr::Unit]);
        assert!(
            refused_at(&check_once_closures(&mapped), 3, 4),
            "the outer closure moves the capture its inner one takes, so a recalling slot refuses it"
        );
        Ok(())
    }

    /// `Task.andThen { let m = m.clone(); <once> }`: the backend boxes a wrapped
    /// closure as `dyn Fn`, so the wrap must not hide a once closure from the check.
    #[test]
    fn a_pre_cloned_once_closure_in_an_admitted_slot_refuses() -> DResult<()> {
        let mut i = Interner::new();
        let m = i.intern("m")?;
        let wrapped = Expr::Let {
            name: m,
            value: Box::new(Expr::CloneVar(m)),
            body: Box::new(once(&mut i)?),
        };
        let and_then = kernel_call(KernelFn::TaskAndThen, vec![wrapped, Expr::Unit]);
        assert!(refused_at(&check_once_closures(&and_then), 7, 8));
        Ok(())
    }
}
