//! The one walk over every kernel reference in a lowered program.
//!
//! The whole-program literal refusals (`route_grammar`, `attr_names`) judge a
//! kernel by its literal arguments wherever it sits, including positions no
//! emission reaches (dead code, a dropped `routes` list). Each refusal is a
//! visitor over the [`KernelSite`]s this walk yields, so every refusal sees
//! every child position of every body, and a new IR node is covered by all of
//! them the moment this exhaustive match names it.

use ipe_diagnostics::DResult;
use ipe_intern::Symbol;
use ipe_ir::{Callee, Expr, KernelFn, Program};

/// One binder in scope at a kernel site.
#[derive(Clone, Copy)]
pub enum Binding<'e> {
    /// A `let` binding the symbol to a string literal.
    Literal(Symbol, &'e str),
    /// A binder naming the symbol with a value the walk does not know.
    Shadow(Symbol),
    /// A pattern scope. Its binders are not listed, so no outer literal is
    /// read through it.
    Opaque,
}

/// One reference to a kernel in a lowered body.
#[derive(Clone, Copy)]
pub enum KernelSite<'e, 's> {
    /// A call of the kernel with `args` in source order.
    Call {
        /// The kernel called.
        kernel: KernelFn,
        /// The call's arguments.
        args: &'e [Expr],
        /// The binders in scope at the call, innermost last.
        scope: &'s [Binding<'e>],
    },
    /// The kernel value applied to `args`.
    Applied {
        /// The kernel applied.
        kernel: KernelFn,
        /// The application's arguments.
        args: &'e [Expr],
        /// The binders in scope at the application, innermost last.
        scope: &'s [Binding<'e>],
    },
    /// The kernel used as a value.
    Value(KernelFn),
}

impl<'e> KernelSite<'e, '_> {
    /// The string literal that argument `index` holds, if any.
    ///
    /// That is a literal written at the site, or a variable an enclosing `let`
    /// binds to one. Partial application lowers a supplied literal to the
    /// second shape (`let __ipe_cap_0 = "…"` around the residual closure), so
    /// a check that read only `Expr::Str` would miss it.
    #[must_use]
    pub fn literal_arg(&self, index: usize) -> Option<&'e str> {
        let (Self::Call { args, scope, .. } | Self::Applied { args, scope, .. }) = self else {
            return None;
        };
        match args.get(index)? {
            Expr::Str(lit) => Some(lit.as_str()),
            Expr::Var(name) | Expr::CloneVar(name) => {
                scope.iter().rev().find_map(|binding| match *binding {
                    Binding::Literal(bound, lit) if bound == *name => Some(Some(lit)),
                    Binding::Shadow(bound) if bound == *name => Some(None),
                    Binding::Opaque => Some(None),
                    Binding::Literal(..) | Binding::Shadow(_) => None,
                })?
            }
            _ => None,
        }
    }
}

/// Visit every kernel site of every function in `program`.
///
/// # Errors
///
/// The first refusal `visit` returns.
pub fn each_kernel_site(
    program: &Program,
    visit: &mut impl FnMut(KernelSite<'_, '_>) -> DResult<()>,
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
    visit: &mut impl FnMut(KernelSite<'_, '_>) -> DResult<()>,
) -> DResult<()> {
    walk(expr, &mut Vec::new(), visit)
}

/// Visit every kernel site inside `expr` with `scope` the binders around it.
fn walk<'e>(
    expr: &'e Expr,
    scope: &mut Vec<Binding<'e>>,
    visit: &mut impl FnMut(KernelSite<'_, '_>) -> DResult<()>,
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
            Callee::Func(_) | Callee::Ffi { .. } => Ok(()),
        },
        Expr::Call { callee, args, .. } => {
            if let Callee::Kernel(k) = callee {
                visit(KernelSite::Call {
                    kernel: *k,
                    args,
                    scope,
                })?;
            }
            all(args, scope, visit)
        }
        Expr::Ctor { args, .. } | Expr::TailRecur { args } => all(args, scope, visit),
        Expr::BinOp { lhs, rhs, .. } => {
            walk(lhs, scope, visit)?;
            walk(rhs, scope, visit)
        }
        Expr::Let { name, value, body } => {
            walk(value, scope, visit)?;
            let binding = match value.as_ref() {
                Expr::Str(lit) => Binding::Literal(*name, lit.as_str()),
                _ => Binding::Shadow(*name),
            };
            within(scope, [binding], |scope| walk(body, scope, visit))
        }
        Expr::Destructure { value, body, .. } => {
            walk(value, scope, visit)?;
            within(scope, [Binding::Opaque], |scope| walk(body, scope, visit))
        }
        Expr::If { cond, then_, else_ } => {
            walk(cond, scope, visit)?;
            walk(then_, scope, visit)?;
            walk(else_, scope, visit)
        }
        Expr::Match(m) => {
            walk(m.scrutinee(), scope, visit)?;
            m.arms().iter().try_for_each(|arm| {
                within(scope, [Binding::Opaque], |scope| {
                    if let Some(guard) = &arm.guard {
                        walk(guard, scope, visit)?;
                    }
                    walk(&arm.body, scope, visit)
                })
            })
        }
        Expr::Tuple(items) | Expr::List { items, .. } => all(items, scope, visit),
        Expr::Cons { head, tail } => {
            walk(head, scope, visit)?;
            walk(tail, scope, visit)
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            walk(list, scope, visit)
        }
        Expr::Record { fields, .. } => fields.iter().try_for_each(|(_, e)| walk(e, scope, visit)),
        Expr::Access { record, .. } => walk(record, scope, visit),
        Expr::Update { record, fields } => {
            walk(record, scope, visit)?;
            fields.iter().try_for_each(|(_, e)| walk(e, scope, visit))
        }
        Expr::Lambda { params, body, .. }
        | Expr::SharedLambda { params, body, .. }
        | Expr::OnceLambda { params, body, .. }
        | Expr::TailLoop { params, body } => within(
            scope,
            params.iter().map(|(name, _)| Binding::Shadow(*name)),
            |scope| walk(body, scope, visit),
        ),
        Expr::CaptureClones { body, .. } => walk(body, scope, visit),
        Expr::Apply { func, args } => {
            if let Expr::FuncValue {
                callee: Callee::Kernel(k),
                ..
            } = func.as_ref()
            {
                visit(KernelSite::Applied {
                    kernel: *k,
                    args,
                    scope,
                })?;
            }
            walk(func, scope, visit)?;
            all(args, scope, visit)
        }
        Expr::TaskSeq { effect, rest } => {
            walk(effect, scope, visit)?;
            walk(rest, scope, visit)
        }
    }
}

/// Run `inner` with `bound` pushed onto `scope`, then pop them.
fn within<'e, R>(
    scope: &mut Vec<Binding<'e>>,
    bound: impl IntoIterator<Item = Binding<'e>>,
    inner: impl FnOnce(&mut Vec<Binding<'e>>) -> R,
) -> R {
    let depth = scope.len();
    scope.extend(bound);
    let out = inner(scope);
    scope.truncate(depth);
    out
}

/// Visit every kernel site inside each of `exprs`.
fn all<'e>(
    exprs: &'e [Expr],
    scope: &mut Vec<Binding<'e>>,
    visit: &mut impl FnMut(KernelSite<'_, '_>) -> DResult<()>,
) -> DResult<()> {
    exprs.iter().try_for_each(|e| walk(e, scope, visit))
}
