//! The one walk over every kernel reference in a lowered program.
//!
//! The whole-program literal refusals (`route_grammar`, `attr_names`) judge a
//! kernel by its literal arguments wherever it sits, including positions no
//! emission reaches (dead code, a dropped `routes` list). Each refusal is a
//! visitor over the [`KernelSite`]s this walk yields, so every refusal sees
//! every child position of every body, and a new IR node is covered by all of
//! them the moment this exhaustive match names it.

use ipe_diagnostics::DResult;
use ipe_ir::{Callee, Expr, KernelFn, Program};

/// One reference to a kernel in a lowered body.
#[derive(Clone, Copy)]
pub enum KernelSite<'e> {
    /// A call of the kernel with `args` in source order.
    Call {
        /// The kernel called.
        kernel: KernelFn,
        /// The call's arguments.
        args: &'e [Expr],
    },
    /// The kernel value applied to `args`.
    Applied {
        /// The kernel applied.
        kernel: KernelFn,
        /// The application's arguments.
        args: &'e [Expr],
    },
    /// The kernel used as a value.
    Value(KernelFn),
}

/// Visit every kernel site of every function in `program`.
///
/// # Errors
///
/// The first refusal `visit` returns.
pub fn each_kernel_site(
    program: &Program,
    visit: &mut impl FnMut(KernelSite<'_>) -> DResult<()>,
) -> DResult<()> {
    program
        .modules
        .iter()
        .flat_map(|module| &module.funcs)
        .try_for_each(|func| each_kernel_site_in(&func.body, visit))
}

/// Visit every kernel site inside `expr`, parents before their children.
///
/// # Errors
///
/// The first refusal `visit` returns.
pub fn each_kernel_site_in(
    expr: &Expr,
    visit: &mut impl FnMut(KernelSite<'_>) -> DResult<()>,
) -> DResult<()> {
    match expr {
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_) => Ok(()),
        Expr::FuncValue { callee, .. } => match callee {
            Callee::Kernel(k) => visit(KernelSite::Value(*k)),
            _ => Ok(()),
        },
        Expr::Call { callee, args, .. } => {
            if let Callee::Kernel(k) = callee {
                visit(KernelSite::Call { kernel: *k, args })?;
            }
            all(args, visit)
        }
        Expr::Ctor { args, .. } | Expr::TailRecur { args } => all(args, visit),
        Expr::BinOp { lhs, rhs, .. } => {
            each_kernel_site_in(lhs, visit)?;
            each_kernel_site_in(rhs, visit)
        }
        Expr::Let { value, body, .. } | Expr::Destructure { value, body, .. } => {
            each_kernel_site_in(value, visit)?;
            each_kernel_site_in(body, visit)
        }
        Expr::If { cond, then_, else_ } => {
            each_kernel_site_in(cond, visit)?;
            each_kernel_site_in(then_, visit)?;
            each_kernel_site_in(else_, visit)
        }
        Expr::Match(m) => {
            each_kernel_site_in(m.scrutinee(), visit)?;
            m.arms().iter().try_for_each(|arm| {
                if let Some(guard) = &arm.guard {
                    each_kernel_site_in(guard, visit)?;
                }
                each_kernel_site_in(&arm.body, visit)
            })
        }
        Expr::Tuple(items) | Expr::List { items, .. } => all(items, visit),
        Expr::Cons { head, tail } => {
            each_kernel_site_in(head, visit)?;
            each_kernel_site_in(tail, visit)
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            each_kernel_site_in(list, visit)
        }
        Expr::Record { fields, .. } => fields
            .iter()
            .try_for_each(|(_, e)| each_kernel_site_in(e, visit)),
        Expr::Access { record, .. } => each_kernel_site_in(record, visit),
        Expr::Update { record, fields } => {
            each_kernel_site_in(record, visit)?;
            fields
                .iter()
                .try_for_each(|(_, e)| each_kernel_site_in(e, visit))
        }
        Expr::Lambda { body, .. }
        | Expr::SharedLambda { body, .. }
        | Expr::OnceLambda { body, .. }
        | Expr::TailLoop { body, .. }
        | Expr::CaptureClones { body, .. } => each_kernel_site_in(body, visit),
        Expr::Apply { func, args } => {
            if let Expr::FuncValue {
                callee: Callee::Kernel(k),
                ..
            } = func.as_ref()
            {
                visit(KernelSite::Applied { kernel: *k, args })?;
            }
            each_kernel_site_in(func, visit)?;
            all(args, visit)
        }
        Expr::TaskSeq { effect, rest } => {
            each_kernel_site_in(effect, visit)?;
            each_kernel_site_in(rest, visit)
        }
    }
}

/// Visit every kernel site inside each of `exprs`.
fn all(exprs: &[Expr], visit: &mut impl FnMut(KernelSite<'_>) -> DResult<()>) -> DResult<()> {
    exprs.iter().try_for_each(|e| each_kernel_site_in(e, visit))
}
