//! The capture-clone rewrite for continuation captures, shared by the backend and the lowerer.
//!
//! A `TaskSeq` emits `task_and_then(effect, Box::new(move |_| { rest }))`, and
//! every argument-reversed kernel (`Task.andThen`, `Maybe.map`, …) emits its
//! container before the `move` closure built from its function argument. Every
//! variable the continuation captures that the first-evaluated expression would
//! move is rewritten to a `CloneVar` there ([`clone_targets_in_expr`]). The
//! lowerer's `IPE-L0135` gate must refuse exactly the programs whose rewrite
//! clones a value that has no `Clone` impl ([`seq_rewrite_clones_symbol`]), so
//! both read this one rewrite rather than parallel copies.

use std::collections::BTreeSet;

use ipe_intern::Symbol;

use crate::free_vars::free_vars;
use crate::let_inline::{inlined_let_body, let_value_is_inlined, pat_binds_target};
use crate::{Callee, EnumPayloadTable, Expr};

/// Shadow-aware IR rewrite: replace every free `Var(target)` with `CloneVar(target)`.
///
/// Recursion stops at any subtree where a binder rebinds `target` (that
/// occurrence is a different binding, not the captured one). Structurally
/// identical shadow-skip shape to `ipe_lower::rewrite_var_free_occurrences`,
/// with a `CloneVar` leaf action instead of the caller-supplied leaf.
///
/// Cloning a `Copy` value (Int/Bool/…) compiles to a bitwise copy — harmless —
/// so this never needs a Copy/non-Copy type check to stay sound; it only ever
/// clones a variable that a caller determined is genuinely captured (see
/// [`clone_targets_in_expr`]).
///
/// A read that only BORROWS `target` in an eager position — evaluated in place,
/// before the continuation is built — keeps a bare `Var`: a field read
/// `(w).tag`, a list index or a list length check ends its borrow before the
/// continuation moves `target`, so no whole-carrier clone is needed, and a
/// carrier with no `Clone` impl stays emittable. A borrow inside a closure, a
/// continuation, a match arm, an inlined `let` value, or a kernel/FFI argument
/// (which the emitter may defer into a `move` closure) is cloned. A deferred
/// row-generic receiver becomes a `CloneVar` too; the Access emitter routes it
/// through the borrowing witness getter `ipe_<field>()` all the same, and every
/// row generic is bounded `Clone`.
///
/// A bare `Var` in an [`Expr::Apply`] callee is never rewritten: a call through
/// `Fn` borrows, and an unpromoted `Box<dyn Fn>` has no `clone` (E0599).
///
/// `payloads` is the named enums' variant payload table the inlined-`let`
/// decision reads ([`let_value_is_inlined`]).
#[must_use]
pub fn clone_free_target(expr: Expr, target: Symbol, payloads: &EnumPayloadTable) -> Expr {
    rewrite(expr, target, true, payloads)
}

/// Rewrite the base of a borrowing read: a bare `Var(target)` in an eager position stays a `Var`.
fn borrow_base(base: Expr, target: Symbol, eager: bool, payloads: &EnumPayloadTable) -> Expr {
    match base {
        Expr::Var(s) if eager && s == target => Expr::Var(s),
        other => rewrite(other, target, eager, payloads),
    }
}

/// The [`clone_free_target`] walk; `eager` marks a position evaluated in place.
#[allow(clippy::too_many_lines)] // A recursive tree-walk over a large enum — necessarily long.
fn rewrite(expr: Expr, target: Symbol, eager: bool, payloads: &EnumPayloadTable) -> Expr {
    match expr {
        Expr::Var(s) if s == target => Expr::CloneVar(s),
        Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => expr,
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: Box::new(rewrite(*lhs, target, eager, payloads)),
            rhs: Box::new(rewrite(*rhs, target, eager, payloads)),
        },
        Expr::Let { name, value, body } => {
            // An inlined value is re-evaluated at each use site in `body`,
            // possibly inside a closure, so it is not an eager position.
            let value_eager = eager && !let_value_is_inlined(name, &value, &body, payloads);
            let new_value = Box::new(rewrite(*value, target, value_eager, payloads));
            let new_body = if name == target {
                body
            } else {
                Box::new(rewrite(*body, target, eager, payloads))
            };
            Expr::Let {
                name,
                value: new_value,
                body: new_body,
            }
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            let new_value = Box::new(rewrite(*value, target, eager, payloads));
            let new_body = if pat_binds_target(&binder, target) {
                body
            } else {
                Box::new(rewrite(*body, target, eager, payloads))
            };
            Expr::Destructure {
                binder,
                value: new_value,
                body: new_body,
            }
        }
        Expr::If { cond, then_, else_ } => Expr::If {
            cond: Box::new(rewrite(*cond, target, eager, payloads)),
            then_: Box::new(rewrite(*then_, target, eager, payloads)),
            else_: Box::new(rewrite(*else_, target, eager, payloads)),
        },
        Expr::Match(m) => Expr::Match(m.map_bodies(
            |scrutinee| rewrite(scrutinee, target, eager, payloads),
            // An arm body may be emitted inside a deferred `move` thunk, so
            // arm bodies and guards are never eager positions.
            |pat, body, guard| {
                let binds = pat_binds_target(pat, target);
                let new_body = if binds {
                    body
                } else {
                    rewrite(body, target, false, payloads)
                };
                // Preserve the list-length guard, rewriting it too when the arm
                // pattern does not bind `target`.
                let new_guard = guard.map(|g| {
                    if binds {
                        g
                    } else {
                        rewrite(g, target, false, payloads)
                    }
                });
                (new_body, new_guard)
            },
        )),
        Expr::Call {
            callee,
            args,
            pin,
            on_form,
        } => {
            // A kernel or FFI emitter may wrap an argument in a deferred `move`
            // closure; only a user function's arguments are evaluated in place.
            let args_eager = eager && matches!(callee, Callee::Func(_));
            Expr::Call {
                callee,
                args: args
                    .into_iter()
                    .map(|a| rewrite(a, target, args_eager, payloads))
                    .collect(),
                pin,
                on_form,
            }
        }
        Expr::Tuple(items) => Expr::Tuple(
            items
                .into_iter()
                .map(|e| rewrite(e, target, eager, payloads))
                .collect(),
        ),
        Expr::List { elem, items } => Expr::List {
            elem,
            items: items
                .into_iter()
                .map(|e| rewrite(e, target, eager, payloads))
                .collect(),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(rewrite(*head, target, eager, payloads)),
            tail: Box::new(rewrite(*tail, target, eager, payloads)),
        },
        Expr::ListIndexClone { list, index, elem } => Expr::ListIndexClone {
            list: Box::new(borrow_base(*list, target, eager, payloads)),
            index,
            elem,
        },
        Expr::ListLenCheck { list, len, exact } => Expr::ListLenCheck {
            list: Box::new(borrow_base(*list, target, eager, payloads)),
            len,
            exact,
        },
        Expr::Record { fields, ty } => Expr::Record {
            fields: fields
                .into_iter()
                .map(|(s, e)| (s, rewrite(e, target, eager, payloads)))
                .collect(),
            ty,
        },
        Expr::Access {
            record,
            field,
            field_ty,
        } => Expr::Access {
            record: Box::new(borrow_base(*record, target, eager, payloads)),
            field,
            field_ty,
        },
        Expr::Update { record, fields } => Expr::Update {
            record: Box::new(rewrite(*record, target, eager, payloads)),
            fields: fields
                .into_iter()
                .map(|(s, e)| (s, rewrite(e, target, eager, payloads)))
                .collect(),
        },
        Expr::Lambda { params, ret, body } => {
            let new_body = if params.iter().any(|(s, _)| *s == target) {
                body
            } else {
                Box::new(rewrite(*body, target, false, payloads))
            };
            Expr::Lambda {
                params,
                ret,
                body: new_body,
            }
        }
        Expr::SharedLambda { params, ret, body } => {
            let new_body = if params.iter().any(|(s, _)| *s == target) {
                body
            } else {
                Box::new(rewrite(*body, target, false, payloads))
            };
            Expr::SharedLambda {
                params,
                ret,
                body: new_body,
            }
        }
        Expr::OnceLambda {
            params,
            ret,
            body,
            capture,
        } => {
            let new_body = if params.iter().any(|(s, _)| *s == target) {
                body
            } else {
                Box::new(rewrite(*body, target, false, payloads))
            };
            Expr::OnceLambda {
                params,
                ret,
                body: new_body,
                capture,
            }
        }
        Expr::Apply { func, args } => Expr::Apply {
            func: Box::new(match *func {
                Expr::Var(s) => Expr::Var(s),
                other => rewrite(other, target, eager, payloads),
            }),
            args: args
                .into_iter()
                .map(|a| rewrite(a, target, eager, payloads))
                .collect(),
        },
        Expr::TaskSeq { effect, rest } => Expr::TaskSeq {
            effect: Box::new(rewrite(*effect, target, eager, payloads)),
            // `rest` runs inside the emitted `move |_| { … }` continuation.
            rest: Box::new(rewrite(*rest, target, false, payloads)),
        },
        Expr::Ctor {
            home,
            ty,
            variant,
            args,
        } => Expr::Ctor {
            home,
            ty,
            variant,
            args: args
                .into_iter()
                .map(|a| rewrite(a, target, eager, payloads))
                .collect(),
        },
        Expr::TailLoop { params, body } => {
            let new_body = if params.iter().any(|(s, _)| *s == target) {
                body
            } else {
                Box::new(rewrite(*body, target, false, payloads))
            };
            Expr::TailLoop {
                params,
                body: new_body,
            }
        }
        Expr::TailRecur { args } => Expr::TailRecur {
            args: args
                .into_iter()
                .map(|a| rewrite(a, target, eager, payloads))
                .collect(),
        },
    }
}

/// Fold [`clone_free_target`] over every symbol in `targets`.
///
/// Each fold step only ever rewrites bare `Var` occurrences into `CloneVar` — the passes
/// don't interfere with each other regardless of order (a `CloneVar` leaf is
/// never re-matched by a later target's pass).
#[must_use]
pub fn clone_targets_in_expr(
    expr: Expr,
    targets: &BTreeSet<Symbol>,
    payloads: &EnumPayloadTable,
) -> Expr {
    targets
        .iter()
        .fold(expr, |e, &t| clone_free_target(e, t, payloads))
}

/// Does the continuation-capture clone rewrite clone `sym` anywhere in `expr`?
///
/// Mirrors the emitter exactly: at every `TaskSeq { effect, rest }` and every
/// argument-reversed kernel call `k f container` where `sym` is free in the
/// continuation (`rest` / `f`), the emitter rewrites the first-evaluated
/// expression with [`clone_free_target`]; a `CloneVar(sym)` in that result
/// renders `sym.clone()`. For a value with no `Clone` impl that is an
/// exit-0-then-cargo-fail, so the lowerer refuses it. A `let` the emitter
/// inlines is walked in its inlined form. The walk skips every subtree where a
/// binder shadows `sym`.
#[must_use]
pub fn seq_rewrite_clones_symbol(sym: Symbol, expr: &Expr, payloads: &EnumPayloadTable) -> bool {
    let clones_in = |first: &Expr, continuation: &Expr| {
        free_vars(continuation).contains(&sym)
            && clone_free_target(first.clone(), sym, payloads) != *first
    };
    let walk = |e: &Expr| seq_rewrite_clones_symbol(sym, e, payloads);
    match expr {
        Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => false,
        Expr::TaskSeq { effect, rest } => clones_in(effect, rest) || walk(effect) || walk(rest),
        Expr::Call { callee, args, .. } => {
            let reversed_hazard = callee.evaluates_args_reversed()
                && matches!(args.as_slice(), [func, container] if clones_in(container, func));
            reversed_hazard || args.iter().any(walk)
        }
        Expr::Ctor { args, .. } | Expr::TailRecur { args } => args.iter().any(walk),
        Expr::BinOp { lhs, rhs, .. } => walk(lhs) || walk(rhs),
        Expr::Let { name, value, body } => inlined_let_body(*name, value, body, payloads)
            .map_or_else(
                || walk(value) || (*name != sym && walk(body)),
                |inlined| walk(&inlined),
            ),
        Expr::Destructure {
            binder,
            value,
            body,
        } => walk(value) || (!pat_binds_target(binder, sym) && walk(body)),
        Expr::If { cond, then_, else_ } => walk(cond) || walk(then_) || walk(else_),
        Expr::Match(m) => {
            walk(m.scrutinee())
                || m.arms().iter().any(|arm| {
                    !pat_binds_target(&arm.pat, sym)
                        && (walk(&arm.body) || arm.guard.as_ref().is_some_and(walk))
                })
        }
        Expr::Tuple(items) | Expr::List { items, .. } => items.iter().any(walk),
        Expr::Cons { head, tail } => walk(head) || walk(tail),
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => walk(list),
        Expr::Record { fields, .. } => fields.iter().any(|(_, e)| walk(e)),
        Expr::Access { record, .. } => walk(record),
        Expr::Update { record, fields } => walk(record) || fields.iter().any(|(_, e)| walk(e)),
        Expr::Lambda { params, body, .. }
        | Expr::SharedLambda { params, body, .. }
        | Expr::OnceLambda { params, body, .. }
        | Expr::TailLoop { params, body } => !params.iter().any(|(s, _)| *s == sym) && walk(body),
        Expr::Apply { func, args } => walk(func) || args.iter().any(walk),
    }
}

#[cfg(test)]
mod tests {
    use ipe_intern::{Interner, Symbol};

    use super::{clone_free_target, seq_rewrite_clones_symbol};
    use crate::{
        Arm, CallPin, Callee, EnumPayloadTable, Expr, FuncId, IrType, KernelFn, Match, OnFormKind,
        Pat,
    };

    fn call(callee: Callee, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee,
            args,
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    fn read(record: Expr, field: Symbol) -> Expr {
        Expr::Access {
            record: Box::new(record),
            field,
            field_ty: IrType::Int,
        }
    }

    fn user(args: Vec<Expr>) -> Expr {
        call(Callee::Func(FuncId::from_raw(0)), args)
    }

    fn kernel(args: Vec<Expr>) -> Expr {
        call(Callee::Kernel(KernelFn::StringAppend), args)
    }

    fn seq(effect: Expr, rest: Expr) -> Expr {
        Expr::TaskSeq {
            effect: Box::new(effect),
            rest: Box::new(rest),
        }
    }

    fn thunk(body: Expr) -> Expr {
        Expr::Lambda {
            params: Vec::new(),
            ret: IrType::Int,
            body: Box::new(body),
        }
    }

    fn symbols() -> (Symbol, Symbol) {
        let mut interner = Interner::new();
        let w = interner.intern("w").expect("intern");
        let tag = interner.intern("tag").expect("intern");
        (w, tag)
    }

    /// An eager field read keeps a borrow; a deferred one clones the carrier.
    #[test]
    fn eager_field_read_borrows_deferred_read_clones() {
        let (w, tag) = symbols();
        let rewrite = |e: Expr| clone_free_target(e, w, &EnumPayloadTable::new());
        let borrowed = || read(Expr::Var(w), tag);
        let cloned = || read(Expr::CloneVar(w), tag);

        assert_eq!(rewrite(user(vec![borrowed()])), user(vec![borrowed()]));
        assert_eq!(rewrite(kernel(vec![borrowed()])), kernel(vec![cloned()]));
        assert_eq!(rewrite(thunk(borrowed())), thunk(cloned()));
        assert_eq!(
            rewrite(user(vec![Expr::Var(w)])),
            user(vec![Expr::CloneVar(w)])
        );
    }

    /// The hazard check flags exactly the sequenced tasks whose rewrite clones.
    #[test]
    fn seq_hazard_tracks_the_emitted_rewrite() {
        let (w, tag) = symbols();
        let borrowed = || read(Expr::Var(w), tag);
        let consume = || user(vec![Expr::Var(w)]);
        let hazard = |e: &Expr| seq_rewrite_clones_symbol(w, e, &EnumPayloadTable::new());

        assert!(!hazard(&seq(user(vec![borrowed()]), consume())));
        assert!(hazard(&seq(kernel(vec![borrowed()]), consume())));
        assert!(hazard(&seq(consume(), consume())));
        assert!(!hazard(&seq(kernel(vec![borrowed()]), Expr::Unit)));
        let shadowed_rest = Expr::Lambda {
            params: vec![(w, IrType::Int)],
            ret: IrType::Int,
            body: Box::new(consume()),
        };
        assert!(!hazard(&seq(kernel(vec![borrowed()]), shadowed_rest)));
        let and_then = call(
            Callee::Kernel(KernelFn::TaskAndThen),
            vec![thunk(consume()), kernel(vec![borrowed()])],
        );
        assert!(hazard(&and_then));
    }

    /// A rest mentioning the binding only in an arm guard still triggers the rewrite.
    ///
    /// The emitter's free-variable scan counts arm guards, so it clones the
    /// effect for a guard-only use; the hazard check must agree.
    #[test]
    fn seq_hazard_counts_arm_guards_like_the_emitter() {
        let (w, tag) = symbols();
        let consume = || user(vec![Expr::Var(w)]);
        let hazard_with_rest = |guard: Option<Expr>, body: Expr| {
            let arm = Arm {
                pat: Pat::Wildcard,
                body,
                guard,
            };
            Match::new_flat(Expr::Int(0), vec![arm]).map(|m| {
                let effect = kernel(vec![read(Expr::Var(w), tag)]);
                seq_rewrite_clones_symbol(w, &seq(effect, Expr::Match(m)), &EnumPayloadTable::new())
            })
        };
        assert!(matches!(
            hazard_with_rest(Some(consume()), Expr::Unit),
            Ok(true)
        ));
        assert!(matches!(hazard_with_rest(None, consume()), Ok(true)));
    }

    /// A bare function-variable callee is never cloned, even in a deferred position.
    #[test]
    fn apply_callee_var_stays_bare() {
        let (w, _) = symbols();
        let apply = || Expr::Apply {
            func: Box::new(Expr::Var(w)),
            args: vec![Expr::Int(1)],
        };
        assert_eq!(
            clone_free_target(apply(), w, &EnumPayloadTable::new()),
            apply()
        );
        assert_eq!(
            clone_free_target(thunk(apply()), w, &EnumPayloadTable::new()),
            thunk(apply())
        );
    }

    /// Every argument-reversed kernel is checked, not only `Task.andThen`.
    #[test]
    fn seq_hazard_covers_every_reversed_kernel() {
        let (w, tag) = symbols();
        let consume = || user(vec![Expr::Var(w)]);
        let reversed = |kernel_fn: KernelFn, container: Expr| {
            call(Callee::Kernel(kernel_fn), vec![thunk(consume()), container])
        };
        let hazard = |e: &Expr| seq_rewrite_clones_symbol(w, e, &EnumPayloadTable::new());

        assert!(hazard(&reversed(
            KernelFn::MaybeMap,
            kernel(vec![read(Expr::Var(w), tag)])
        )));
        assert!(!hazard(&reversed(
            KernelFn::MaybeMap,
            user(vec![read(Expr::Var(w), tag)])
        )));
        assert!(!hazard(&call(
            Callee::Kernel(KernelFn::StringAppend),
            vec![thunk(consume()), kernel(vec![read(Expr::Var(w), tag)])],
        )));
    }

    #[test]
    fn clone_free_target_leaves_an_index_read_list_bare() {
        let w = Symbol::from_raw(1);
        let rewritten = clone_free_target(
            Expr::ListIndexClone {
                list: Box::new(Expr::Var(w)),
                index: 0,
                elem: IrType::Int,
            },
            w,
            &EnumPayloadTable::new(),
        );
        assert!(
            matches!(rewritten, Expr::ListIndexClone { ref list, index: 0, .. } if matches!(**list, Expr::Var(s) if s == w)),
            "an index read borrows the list: {rewritten:?}"
        );
    }

    #[test]
    fn clone_free_target_leaves_a_length_check_list_bare() {
        let w = Symbol::from_raw(1);
        let rewritten = clone_free_target(
            Expr::ListLenCheck {
                list: Box::new(Expr::Var(w)),
                len: 2,
                exact: true,
            },
            w,
            &EnumPayloadTable::new(),
        );
        assert!(
            matches!(rewritten, Expr::ListLenCheck { ref list, len: 2, exact: true } if matches!(**list, Expr::Var(s) if s == w)),
            "a length check borrows the list: {rewritten:?}"
        );
    }

    #[test]
    fn clone_free_target_clones_a_consuming_read() {
        let w = Symbol::from_raw(1);
        let rewritten = clone_free_target(
            Expr::Cons {
                head: Box::new(Expr::Var(w)),
                tail: Box::new(Expr::List {
                    elem: IrType::Int,
                    items: Vec::new(),
                }),
            },
            w,
            &EnumPayloadTable::new(),
        );
        assert!(
            matches!(rewritten, Expr::Cons { ref head, .. } if matches!(**head, Expr::CloneVar(s) if s == w)),
            "a cons head moves the value: {rewritten:?}"
        );
    }
}
