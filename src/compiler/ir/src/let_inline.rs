//! The `let`-inlining decision for non-`Clone` values, shared by the lowerer
//! and the backend.
//!
//! The backend emits `let name = value in body` by substituting `value` at
//! every free use of `name` when the value is move-only and used more than
//! once ([`let_value_is_inlined`]). The lowerer's move-order gates must see
//! the same evaluation order the emitter produces, so both read this one
//! predicate and this one substitution rather than parallel copies.

use ipe_intern::Symbol;

use crate::{EnumPayloadTable, Expr, IrType, Pat, ir_type_holds};

/// Does the emitter inline `let name = value in body` — re-evaluating `value`
/// at each free use of `name` instead of binding it once?
///
/// True exactly when `value` is move-only ([`expr_value_is_non_clone`]),
/// `body` reads `name` more than once, and no capture-clone of `name` exists
/// (a `CloneVar` leaf cannot be substituted; see [`scan_free_target`]).
/// `payloads` is the named enums' variant payload table the move-only test
/// descends.
#[must_use]
pub fn let_value_is_inlined(
    name: Symbol,
    value: &Expr,
    body: &Expr,
    payloads: &EnumPayloadTable,
) -> bool {
    let (occurrences, has_clonevar) = scan_free_target(body, name);
    occurrences > 1 && expr_value_is_non_clone(value, payloads) && !has_clonevar
}

/// The body the emitter evaluates for `let name = value in body`.
///
/// It is `body` with `value` substituted for `name` when [`let_value_is_inlined`] holds, `None`
/// when the plain `let` form (value evaluated once, before `body`) is emitted.
#[must_use]
pub fn inlined_let_body(
    name: Symbol,
    value: &Expr,
    body: &Expr,
    payloads: &EnumPayloadTable,
) -> Option<Expr> {
    let_value_is_inlined(name, value, body, payloads)
        .then(|| substitute_var(body.clone(), name, value))
}

/// Returns `true` if the expression produces a value that Rust will MOVE on
/// first use (i.e., a non-`Clone` type), making a multi-use `let` binding
/// cause E0382 "use of moved value".
///
/// The primary case is `Vec<IpeTask<A>>`: a list whose element type is or
/// contains a task.  `IpeTask<A>` is a `Pin<Box<dyn Future …>>` — it has no
/// `Clone` impl because polling a future to completion consumes it.  Ipê's
/// pure semantics guarantee re-evaluation is always correct, so the emitter
/// can safely inline the value expression at every use site.
///
/// The element type is walked through every held component, including tuple,
/// record, and named-enum variant payloads (`payloads`), so a list of
/// `(Task a, Int)` or of an enum wrapping a task is caught too.
///
/// Plain `Clone`/`Copy` values (integers, booleans, strings, records, enums)
/// do NOT trigger this path — their `let` bindings are preserved so the
/// compiler can share the computation.
///
/// Recurses into `Tuple`/`Record` LITERALS so a directly-constructed
/// `(tasks, n)` or `{ tasks = ..., n = ... }` whose task-list is nested one
/// level down is also caught — a purely structural widening of the AUD-04
/// audit's narrower `Expr::List`-only check (#B4). A `let`-bound value that
/// is task-typed only through its declared TYPE (e.g. a `Call` to a
/// Task-returning helper, or a `Var` reference to an already-task-typed
/// binding) is NOT detected here — that needs a real type-of-expression
/// recovery pass this backend does not have; filed as a residual gap rather
/// than guessed at (see AUD-04 follow-up in backlog.md).
#[must_use]
pub fn expr_value_is_non_clone(expr: &Expr, payloads: &EnumPayloadTable) -> bool {
    match expr {
        // A list whose element is a task (or holds one) — Vec<IpeTask<A>>
        // is move-only.
        Expr::List { elem, .. } => ir_type_contains_task(elem, payloads),
        Expr::Tuple(items) => items.iter().any(|e| expr_value_is_non_clone(e, payloads)),
        Expr::Record { fields, .. } => fields
            .iter()
            .any(|(_, e)| expr_value_is_non_clone(e, payloads)),
        _ => false,
    }
}

/// Does a value of type `ty` hold an `IrType::Task`?
///
/// Walks every held component ([`ir_type_holds`]): transparent carriers,
/// tuples, records, and named-enum type arguments and variant payloads from
/// `payloads`.
#[must_use]
pub fn ir_type_contains_task(ty: &IrType, payloads: &EnumPayloadTable) -> bool {
    ir_type_holds(ty, payloads, &|t| matches!(t, IrType::Task(_)))
}

/// Shadow check used by [`scan_free_target`] / [`substitute_var`] (and the
/// backend's capture-clone rewrite): does this irrefutable/refutable binder
/// pattern bind `target`?
#[must_use]
pub fn pat_binds_target(pat: &Pat, target: Symbol) -> bool {
    match pat {
        Pat::Var(s) => *s == target,
        Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) | Pat::Str(_) => false,
        Pat::Alias(inner, s) => *s == target || pat_binds_target(inner, target),
        Pat::Ctor { args, .. } => args.iter().any(|p| pat_binds_target(p, target)),
        Pat::Tuple(elems) => elems.iter().any(|p| pat_binds_target(p, target)),
        Pat::Record(fields) => fields.iter().any(|(_, p)| pat_binds_target(p, target)),
        Pat::Slice { prefix, rest } => {
            prefix.iter().any(|p| pat_binds_target(p, target))
                || rest.as_deref().is_some_and(|p| pat_binds_target(p, target))
        }
        // Every alternative binds the same names, so it binds `target` iff any
        // (equivalently the first) alternative does.
        Pat::Or(alts) => alts.iter().any(|p| pat_binds_target(p, target)),
    }
}

/// Shadow-aware scan of `expr` for a `let`-bound `target`'s free occurrences,
/// used to gate [`Expr::Let`]'s multi-use inline decision. Returns
/// `(var_count, has_clonevar)`:
///
/// * `var_count` — number of free `Expr::Var(target)` reads. Replaces the
///   AUD-04 textual `count_word_occurrences(&body_s, &name_s)`, which counted
///   matches inside ALREADY-RENDERED text (so a match inside a string literal
///   or a record field name inflated the count and could trigger a corrupting
///   inline). Counting over the IR instead only ever sees genuine `Var` reads.
/// * `has_clonevar` — `true` if a free `Expr::CloneVar(target)` occurs (a
///   lambda capture-clone site the lowerer already emitted for this same
///   binding). [`Expr`] has no node for "clone of an arbitrary expression",
///   so [`substitute_var`] cannot cleanly substitute through a `CloneVar`
///   leaf; when this is `true`, `Expr::Let`'s emitter skips inlining and
///   keeps the plain `let` form — always correct, just not move-optimized
///   for that one binding.
#[must_use]
pub fn scan_free_target(expr: &Expr, target: Symbol) -> (usize, bool) {
    let mut count = 0usize;
    let mut has_clonevar = false;
    scan_free_target_into(expr, target, &mut count, &mut has_clonevar);
    (count, has_clonevar)
}

#[allow(clippy::too_many_lines)] // A recursive tree-walk over a large enum — necessarily long.
pub fn scan_free_target_into(
    expr: &Expr,
    target: Symbol,
    count: &mut usize,
    has_clonevar: &mut bool,
) {
    match expr {
        Expr::Var(s) => {
            if *s == target {
                *count += 1;
            }
        }
        Expr::CloneVar(s) => {
            if *s == target {
                *has_clonevar = true;
            }
        }
        Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => {}
        Expr::Ctor { args, .. } | Expr::Call { args, .. } | Expr::TailRecur { args } => {
            for a in args {
                scan_free_target_into(a, target, count, has_clonevar);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            scan_free_target_into(lhs, target, count, has_clonevar);
            scan_free_target_into(rhs, target, count, has_clonevar);
        }
        Expr::Let { name, value, body } => {
            scan_free_target_into(value, target, count, has_clonevar);
            if *name != target {
                scan_free_target_into(body, target, count, has_clonevar);
            }
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            scan_free_target_into(value, target, count, has_clonevar);
            if !pat_binds_target(binder, target) {
                scan_free_target_into(body, target, count, has_clonevar);
            }
        }
        Expr::If { cond, then_, else_ } => {
            scan_free_target_into(cond, target, count, has_clonevar);
            scan_free_target_into(then_, target, count, has_clonevar);
            scan_free_target_into(else_, target, count, has_clonevar);
        }
        Expr::Match(m) => {
            scan_free_target_into(m.scrutinee(), target, count, has_clonevar);
            for arm in m.arms() {
                if !pat_binds_target(&arm.pat, target) {
                    scan_free_target_into(&arm.body, target, count, has_clonevar);
                }
            }
        }
        Expr::Tuple(items) | Expr::List { items, .. } => {
            for e in items {
                scan_free_target_into(e, target, count, has_clonevar);
            }
        }
        Expr::Cons { head, tail } => {
            scan_free_target_into(head, target, count, has_clonevar);
            scan_free_target_into(tail, target, count, has_clonevar);
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            scan_free_target_into(list, target, count, has_clonevar);
        }
        Expr::Record { fields, .. } => {
            for (_, e) in fields {
                scan_free_target_into(e, target, count, has_clonevar);
            }
        }
        Expr::Access { record, .. } => scan_free_target_into(record, target, count, has_clonevar),
        Expr::Update { record, fields } => {
            scan_free_target_into(record, target, count, has_clonevar);
            for (_, e) in fields {
                scan_free_target_into(e, target, count, has_clonevar);
            }
        }
        Expr::Lambda { params, body, .. }
        | Expr::SharedLambda { params, body, .. }
        | Expr::TailLoop { params, body } => {
            if !params.iter().any(|(s, _)| *s == target) {
                scan_free_target_into(body, target, count, has_clonevar);
            }
        }
        Expr::Apply { func, args } => {
            scan_free_target_into(func, target, count, has_clonevar);
            for a in args {
                scan_free_target_into(a, target, count, has_clonevar);
            }
        }
        Expr::TaskSeq { effect, rest } => {
            scan_free_target_into(effect, target, count, has_clonevar);
            scan_free_target_into(rest, target, count, has_clonevar);
        }
    }
}

/// Shadow-aware IR substitution of `replacement` for every free `Var(target)`.
///
/// Recursion stops at any subtree where a binder rebinds `target`. Operating
/// on the IR, not on rendered Rust text, only ever touches genuine `Var` leaf
/// nodes — a string literal is an opaque `Expr::Str`, a record field name is a
/// `Symbol` key never matched against `Expr::Var`.
#[must_use]
#[allow(clippy::too_many_lines)] // A recursive tree-walk over a large enum — necessarily long.
pub fn substitute_var(expr: Expr, target: Symbol, replacement: &Expr) -> Expr {
    match expr {
        Expr::Var(s) if s == target => replacement.clone(),
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
            lhs: Box::new(substitute_var(*lhs, target, replacement)),
            rhs: Box::new(substitute_var(*rhs, target, replacement)),
        },
        Expr::Let { name, value, body } => {
            let new_value = Box::new(substitute_var(*value, target, replacement));
            let new_body = if name == target {
                body
            } else {
                Box::new(substitute_var(*body, target, replacement))
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
            let new_value = Box::new(substitute_var(*value, target, replacement));
            let new_body = if pat_binds_target(&binder, target) {
                body
            } else {
                Box::new(substitute_var(*body, target, replacement))
            };
            Expr::Destructure {
                binder,
                value: new_value,
                body: new_body,
            }
        }
        Expr::If { cond, then_, else_ } => Expr::If {
            cond: Box::new(substitute_var(*cond, target, replacement)),
            then_: Box::new(substitute_var(*then_, target, replacement)),
            else_: Box::new(substitute_var(*else_, target, replacement)),
        },
        Expr::Match(m) => Expr::Match(m.map_bodies(
            |scrutinee| substitute_var(scrutinee, target, replacement),
            |pat, body, guard| {
                let binds = pat_binds_target(pat, target);
                let new_body = if binds {
                    body
                } else {
                    substitute_var(body, target, replacement)
                };
                let new_guard = guard.map(|g| {
                    if binds {
                        g
                    } else {
                        substitute_var(g, target, replacement)
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
        } => Expr::Call {
            callee,
            args: args
                .into_iter()
                .map(|a| substitute_var(a, target, replacement))
                .collect(),
            pin,
            on_form,
        },
        Expr::Tuple(items) => Expr::Tuple(
            items
                .into_iter()
                .map(|e| substitute_var(e, target, replacement))
                .collect(),
        ),
        Expr::List { elem, items } => Expr::List {
            elem,
            items: items
                .into_iter()
                .map(|e| substitute_var(e, target, replacement))
                .collect(),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(substitute_var(*head, target, replacement)),
            tail: Box::new(substitute_var(*tail, target, replacement)),
        },
        Expr::ListIndexClone { list, index } => Expr::ListIndexClone {
            list: Box::new(substitute_var(*list, target, replacement)),
            index,
        },
        Expr::ListLenCheck { list, len, exact } => Expr::ListLenCheck {
            list: Box::new(substitute_var(*list, target, replacement)),
            len,
            exact,
        },
        Expr::Record { fields, ty } => Expr::Record {
            fields: fields
                .into_iter()
                .map(|(s, e)| (s, substitute_var(e, target, replacement)))
                .collect(),
            ty,
        },
        Expr::Access {
            record,
            field,
            field_ty,
        } => Expr::Access {
            record: Box::new(substitute_var(*record, target, replacement)),
            field,
            field_ty,
        },
        Expr::Update { record, fields } => Expr::Update {
            record: Box::new(substitute_var(*record, target, replacement)),
            fields: fields
                .into_iter()
                .map(|(s, e)| (s, substitute_var(e, target, replacement)))
                .collect(),
        },
        Expr::Lambda { params, ret, body } => {
            let new_body = if params.iter().any(|(s, _)| *s == target) {
                body
            } else {
                Box::new(substitute_var(*body, target, replacement))
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
                Box::new(substitute_var(*body, target, replacement))
            };
            Expr::SharedLambda {
                params,
                ret,
                body: new_body,
            }
        }
        Expr::Apply { func, args } => Expr::Apply {
            func: Box::new(substitute_var(*func, target, replacement)),
            args: args
                .into_iter()
                .map(|a| substitute_var(a, target, replacement))
                .collect(),
        },
        Expr::TaskSeq { effect, rest } => Expr::TaskSeq {
            effect: Box::new(substitute_var(*effect, target, replacement)),
            rest: Box::new(substitute_var(*rest, target, replacement)),
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
                .map(|a| substitute_var(a, target, replacement))
                .collect(),
        },
        Expr::TailLoop { params, body } => {
            let new_body = if params.iter().any(|(s, _)| *s == target) {
                body
            } else {
                Box::new(substitute_var(*body, target, replacement))
            };
            Expr::TailLoop {
                params,
                body: new_body,
            }
        }
        Expr::TailRecur { args } => Expr::TailRecur {
            args: args
                .into_iter()
                .map(|a| substitute_var(a, target, replacement))
                .collect(),
        },
    }
}
