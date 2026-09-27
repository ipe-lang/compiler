use super::{Expr, Func, IrType, MAX_IR_RENDER_DEPTH, Pat, Symbol, wants_arc_ctor};

/// The deepest expression nesting the backend will descend before failing fast.
///
/// `emit_expr` recurses one Rust stack frame per IR-expression level (`BinOp`
/// operands, call arguments, match scrutinee/arm bodies). An adversarially or
/// buggily deep IR spine would otherwise overflow the native stack with no
/// diagnostic. The parser already caps *source* nesting at 256 (IPE-P0003);
/// this matching bound is defence-in-depth against an IR produced past that —
/// well below the native stack ceiling (≤ 2 MB default thread stack), so the
/// guard fires first. Sized conservatively to leave headroom for the frame size
/// of `emit_expr_at` in debug builds.
///
/// Shares [`ipe_ir::MAX_IR_RENDER_DEPTH`] rather than a separately-declared
/// copy of the same value — a `--emit-ir` dev-flag dump and the real emitter
/// must refuse a program at the identical depth, not two independently
/// tuned bounds that can drift apart.
pub const MAX_EMIT_DEPTH: u16 = MAX_IR_RENDER_DEPTH;

/// One indentation level: four spaces, matching the golden's formatting.
pub fn indent_of(level: usize) -> String {
    "    ".repeat(level)
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
pub fn expr_value_is_non_clone(expr: &Expr) -> bool {
    match expr {
        // A list whose element is a task (or contains one) — Vec<IpeTask<A>>
        // is move-only.
        Expr::List { elem, .. } => ir_type_contains_task(elem),
        Expr::Tuple(items) => items.iter().any(expr_value_is_non_clone),
        Expr::Record { fields, .. } => fields.iter().any(|(_, e)| expr_value_is_non_clone(e)),
        _ => false,
    }
}

/// Is `ty` a Rust type that is UNCONDITIONALLY `Copy` in every emission this
/// backend produces? Mirrors `ipe_lower::lower::clone_class`'s `CopyLeaf`
/// classification exactly (kept duplicated across the crate boundary per this
/// file's established convention — see [`pat_bound_symbols`]'s doc comment).
///
/// Deliberately conservative: a `Generic(_)` type parameter is bounded only by
/// `Clone` (`emit_func` injects `Clone`, never `Copy`), so it must return
/// `false` even though a caller might monomorphize it to a Copy type at some
/// call site — the backend has no per-call-site visibility here. A user
/// `Enum`/`Record` also returns `false`: synthesized enums/structs derive
/// `Clone`, not `Copy`. `StreamWriter`/`WebSocketServer` are
/// `#[derive(Clone, Copy)]` i64 id wrappers (`server_stream.rs` / websocket
/// server), matching `clone_class`'s own `CopyLeaf` arm for them.
///
/// Used by the `Expr::Access` emission arm for AUD-09's type-directed
/// Copy elision — see
/// `docs/adr/0002-codegen-soundness-and-the-seal.md` §3.
pub const fn ir_type_is_definitely_copy(ty: &IrType) -> bool {
    matches!(
        ty,
        IrType::Int
            | IrType::Float
            | IrType::Bool
            | IrType::Char
            | IrType::Unit
            | IrType::BackoffStrategy
            | IrType::Order
            | IrType::HttpMethod
            | IrType::Decimal
            | IrType::ErrorKind
            | IrType::StreamWriter
            | IrType::WebSocketServer
    )
}

/// Collect every symbol a pattern binds (recursively) into `out`. Mirrors
/// `ipe_lower::pat_binds_symbol`'s traversal shape but gathers the full bound
/// set in one pass rather than testing membership of one target.
pub fn pat_bound_symbols(pat: &Pat, out: &mut std::collections::BTreeSet<Symbol>) {
    match pat {
        Pat::Var(s) => {
            out.insert(*s);
        }
        Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) | Pat::Str(_) => {}
        Pat::Alias(inner, s) => {
            out.insert(*s);
            pat_bound_symbols(inner, out);
        }
        Pat::Ctor { args, .. } => {
            for p in args {
                pat_bound_symbols(p, out);
            }
        }
        Pat::Tuple(elems) => {
            for p in elems {
                pat_bound_symbols(p, out);
            }
        }
        Pat::Record(fields) => {
            for (_, p) in fields {
                pat_bound_symbols(p, out);
            }
        }
        Pat::Slice { prefix, rest } => {
            for p in prefix {
                pat_bound_symbols(p, out);
            }
            if let Some(p) = rest {
                pat_bound_symbols(p, out);
            }
        }
        // Every alternative of an or-pattern binds the same names, so the first
        // alternative's binders are the whole set.
        Pat::Or(alts) => {
            if let Some(first) = alts.first() {
                pat_bound_symbols(first, out);
            }
        }
    }
}

/// Exhaustive, binder-aware free-variable collector over the typed IR
/// `Expr` tree — replaces the AUD-04 textual `clone_captured_vars` /
/// `replace_word_all` passes, which operated on ALREADY-EMITTED Rust source
/// text with no string-literal-state tracking (a captured-variable word
/// appearing mid string literal, or matching a record field name, would get
/// corrupted). Operating on the IR instead means a string literal is an
/// opaque `Expr::Str` leaf and a record field name is a `Symbol` in a
/// `(Symbol, Expr)` pair — neither is ever mistaken for a `Var` occurrence.
///
/// Every binder (`Let`/`Destructure`/`Lambda`/`TailLoop`/`Match` arm
/// patterns) removes its bound name(s) from the free set of the scope it
/// introduces, exactly mirroring `ipe_lower::rewrite_var_free_occurrences`'s
/// shadow-aware recursion shape.
pub fn free_vars(expr: &Expr) -> std::collections::BTreeSet<Symbol> {
    let mut out = std::collections::BTreeSet::new();
    collect_free_vars(expr, &mut out);
    out
}

#[allow(clippy::too_many_lines)] // A recursive tree-walk over a large enum — necessarily long.
pub fn collect_free_vars(expr: &Expr, out: &mut std::collections::BTreeSet<Symbol>) {
    match expr {
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => {}
        Expr::Var(s) | Expr::CloneVar(s) => {
            out.insert(*s);
        }
        Expr::Ctor { args, .. } | Expr::Call { args, .. } | Expr::TailRecur { args } => {
            for a in args {
                collect_free_vars(a, out);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_free_vars(lhs, out);
            collect_free_vars(rhs, out);
        }
        Expr::Let { name, value, body } => {
            collect_free_vars(value, out);
            let mut body_free = std::collections::BTreeSet::new();
            collect_free_vars(body, &mut body_free);
            body_free.remove(name);
            out.extend(body_free);
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            collect_free_vars(value, out);
            let mut bound = std::collections::BTreeSet::new();
            pat_bound_symbols(binder, &mut bound);
            let mut body_free = std::collections::BTreeSet::new();
            collect_free_vars(body, &mut body_free);
            for b in &bound {
                body_free.remove(b);
            }
            out.extend(body_free);
        }
        Expr::If { cond, then_, else_ } => {
            collect_free_vars(cond, out);
            collect_free_vars(then_, out);
            collect_free_vars(else_, out);
        }
        Expr::Match(m) => {
            collect_free_vars(m.scrutinee(), out);
            for arm in m.arms() {
                let mut bound = std::collections::BTreeSet::new();
                pat_bound_symbols(&arm.pat, &mut bound);
                let mut body_free = std::collections::BTreeSet::new();
                collect_free_vars(&arm.body, &mut body_free);
                if let Some(guard) = &arm.guard {
                    collect_free_vars(guard, &mut body_free);
                }
                for b in &bound {
                    body_free.remove(b);
                }
                out.extend(body_free);
            }
        }
        Expr::Tuple(items) | Expr::List { items, .. } => {
            for e in items {
                collect_free_vars(e, out);
            }
        }
        Expr::Cons { head, tail } => {
            collect_free_vars(head, out);
            collect_free_vars(tail, out);
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            collect_free_vars(list, out);
        }
        Expr::Record { fields, .. } => {
            for (_, e) in fields {
                collect_free_vars(e, out);
            }
        }
        Expr::Access { record, .. } => collect_free_vars(record, out),
        Expr::Update { record, fields } => {
            collect_free_vars(record, out);
            for (_, e) in fields {
                collect_free_vars(e, out);
            }
        }
        Expr::Lambda { params, body, .. }
        | Expr::SharedLambda { params, body, .. }
        | Expr::TailLoop { params, body } => {
            let mut body_free = std::collections::BTreeSet::new();
            collect_free_vars(body, &mut body_free);
            for (s, _) in params {
                body_free.remove(s);
            }
            out.extend(body_free);
        }
        Expr::Apply { func, args } => {
            collect_free_vars(func, out);
            for a in args {
                collect_free_vars(a, out);
            }
        }
        Expr::TaskSeq { effect, rest } => {
            collect_free_vars(effect, out);
            collect_free_vars(rest, out);
        }
    }
}

/// Shadow-aware IR rewrite: replace every FREE occurrence of `Expr::Var(target)`
/// in `expr` with `Expr::CloneVar(target)`, stopping recursion into any subtree
/// where a binder rebinds `target` (that occurrence is a different binding, not
/// the captured one). Structurally identical shadow-skip shape to
/// `ipe_lower::rewrite_var_free_occurrences` — the shared precedent for a
/// single-target IR substitution in this codebase — with a `CloneVar` leaf
/// action instead of the caller-supplied leaf.
///
/// Cloning a `Copy` value (Int/Bool/…) compiles to a bitwise copy — harmless —
/// so this never needs a Copy/non-Copy type check to stay sound; it only ever
/// clones a variable that a caller determined is genuinely captured (see
/// `clone_targets_in_expr`).
///
/// Only a CONSUMING position is rewritten. A bare `Var` in a borrowing
/// position stays a `Var`, because the emitted read never moves it and the
/// variable's type may not be `Clone` at all:
///
/// * a direct [`Expr::Apply`] callee — a call through `Fn` borrows (the same
///   exemption as the lowerer's `fn_value_move_walk`); an unpromoted
///   `Box<dyn Fn>` has no `clone` (E0599);
/// * an [`Expr::Access`] receiver — `(rec).field.clone()` borrows the record,
///   which may hold a `Task`, a function, or an opaque handle and derive no
///   `Clone` (E0599); a row-generic receiver must also stay a bare `Var` so the
///   Access emitter routes it through the borrowing witness getter;
/// * the list of an [`Expr::ListIndexClone`] / [`Expr::ListLenCheck`] — an
///   index or length read borrows the `Vec`.
#[allow(clippy::too_many_lines)] // A recursive tree-walk over a large enum — necessarily long.
pub fn clone_free_target(expr: Expr, target: Symbol) -> Expr {
    match expr {
        Expr::Var(s) if s == target => Expr::CloneVar(s),
        Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => expr,
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: Box::new(clone_free_target(*lhs, target)),
            rhs: Box::new(clone_free_target(*rhs, target)),
        },
        Expr::Let { name, value, body } => {
            let new_value = Box::new(clone_free_target(*value, target));
            let new_body = if name == target {
                body
            } else {
                Box::new(clone_free_target(*body, target))
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
            let new_value = Box::new(clone_free_target(*value, target));
            let new_body = if pat_binds_target(&binder, target) {
                body
            } else {
                Box::new(clone_free_target(*body, target))
            };
            Expr::Destructure {
                binder,
                value: new_value,
                body: new_body,
            }
        }
        Expr::If { cond, then_, else_ } => Expr::If {
            cond: Box::new(clone_free_target(*cond, target)),
            then_: Box::new(clone_free_target(*then_, target)),
            else_: Box::new(clone_free_target(*else_, target)),
        },
        Expr::Match(m) => Expr::Match(m.map_bodies(
            |scrutinee| clone_free_target(scrutinee, target),
            |pat, body, guard| {
                let binds = pat_binds_target(pat, target);
                let new_body = if binds {
                    body
                } else {
                    clone_free_target(body, target)
                };
                // Preserve the list-length guard, rewriting it too when the arm
                // pattern does not bind `target`.
                let new_guard = guard.map(|g| {
                    if binds {
                        g
                    } else {
                        clone_free_target(g, target)
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
                .map(|a| clone_free_target(a, target))
                .collect(),
            pin,
            on_form,
        },
        Expr::Tuple(items) => Expr::Tuple(
            items
                .into_iter()
                .map(|e| clone_free_target(e, target))
                .collect(),
        ),
        Expr::List { elem, items } => Expr::List {
            elem,
            items: items
                .into_iter()
                .map(|e| clone_free_target(e, target))
                .collect(),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(clone_free_target(*head, target)),
            tail: Box::new(clone_free_target(*tail, target)),
        },
        Expr::ListIndexClone { list, index } => Expr::ListIndexClone {
            list: Box::new(clone_borrowed_position(*list, target)),
            index,
        },
        Expr::ListLenCheck { list, len, exact } => Expr::ListLenCheck {
            list: Box::new(clone_borrowed_position(*list, target)),
            len,
            exact,
        },
        Expr::Record { fields, ty } => Expr::Record {
            fields: fields
                .into_iter()
                .map(|(s, e)| (s, clone_free_target(e, target)))
                .collect(),
            ty,
        },
        Expr::Access {
            record,
            field,
            field_ty,
        } => Expr::Access {
            record: Box::new(clone_borrowed_position(*record, target)),
            field,
            field_ty,
        },
        Expr::Update { record, fields } => Expr::Update {
            record: Box::new(clone_free_target(*record, target)),
            fields: fields
                .into_iter()
                .map(|(s, e)| (s, clone_free_target(e, target)))
                .collect(),
        },
        Expr::Lambda { params, ret, body } => {
            let new_body = if params.iter().any(|(s, _)| *s == target) {
                body
            } else {
                Box::new(clone_free_target(*body, target))
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
                Box::new(clone_free_target(*body, target))
            };
            Expr::SharedLambda {
                params,
                ret,
                body: new_body,
            }
        }
        Expr::Apply { func, args } => Expr::Apply {
            func: Box::new(clone_borrowed_position(*func, target)),
            args: args
                .into_iter()
                .map(|a| clone_free_target(a, target))
                .collect(),
        },
        Expr::TaskSeq { effect, rest } => Expr::TaskSeq {
            effect: Box::new(clone_free_target(*effect, target)),
            rest: Box::new(clone_free_target(*rest, target)),
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
                .map(|a| clone_free_target(a, target))
                .collect(),
        },
        Expr::TailLoop { params, body } => {
            let new_body = if params.iter().any(|(s, _)| *s == target) {
                body
            } else {
                Box::new(clone_free_target(*body, target))
            };
            Expr::TailLoop {
                params,
                body: new_body,
            }
        }
        Expr::TailRecur { args } => Expr::TailRecur {
            args: args
                .into_iter()
                .map(|a| clone_free_target(a, target))
                .collect(),
        },
    }
}

/// [`clone_free_target`] for a BORROWING position: a bare `Var` there is read by
/// reference, never moved, so it is left as is; any compound expression is
/// still walked for the consuming positions inside it.
fn clone_borrowed_position(expr: Expr, target: Symbol) -> Expr {
    match expr {
        Expr::Var(s) => Expr::Var(s),
        other => clone_free_target(other, target),
    }
}

/// `Pat` version of the shadow check used by [`clone_free_target`] /
/// [`substitute_var`]: does this irrefutable/refutable binder pattern bind
/// `target`? Local twin of `ipe_lower::pat_binds_symbol` (same shape) — kept
/// in this crate rather than shared because `ipe_backend_rust` does not
/// depend on `ipe_lower` (IR flows one way: lower produces it, backends
/// consume it).
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

/// Fold [`clone_free_target`] over every symbol in `targets`. Each fold step
/// only ever rewrites bare `Var` occurrences into `CloneVar` — the passes
/// don't interfere with each other regardless of order (a `CloneVar` leaf is
/// never re-matched by a later target's pass). Borrowing positions are left
/// untouched — see [`clone_free_target`].
pub fn clone_targets_in_expr(expr: Expr, targets: &std::collections::BTreeSet<Symbol>) -> Expr {
    targets.iter().fold(expr, |e, &t| clone_free_target(e, t))
}

/// Does `sym` — a function-typed binder — appear anywhere in `body` in a
/// VALUE position (stored in data, passed as an argument, returned bare,
/// captured by a closure), as opposed to only ever being the callee of a
/// direct application `sym x`? A callee-only symbol can carry a monomorphized
/// generic (`impl Fn`) carrier instead of the erased `Box<dyn Fn>`; any value
/// use pins it to the concrete boxed type at that position, so the answer
/// gates the direct-position monomorphization.
///
/// Local twin of `ipe_lower::count_fn_value_uses` (`> 0` ⟺ a value use exists),
/// kept in this crate for the same one-way-IR reason as [`pat_binds_target`].
/// The traversal is EXHAUSTIVE and fail-closed: the sole exemption is
/// `sym` in direct-callee position of an [`Expr::Apply`]; every other
/// occurrence — including inside a nested lambda, a [`Expr::FuncValue`], or any
/// [`Expr`] variant not special-cased — is a value use, so an unrecognised
/// shape conservatively reports `true` (keep `Box`).
pub fn fn_binder_used_as_value(sym: Symbol, body: &Expr) -> bool {
    match body {
        Expr::Var(s) | Expr::CloneVar(s) => *s == sym,
        // A lambda that references `sym` at all captures it BY VALUE into its
        // closure environment — a value use. (Even a direct call `sym x` inside
        // the lambda body first moves `sym` into the environment.)
        Expr::Lambda { body, .. } | Expr::SharedLambda { body, .. } => {
            expr_refs_symbol(sym, body)
        }
        Expr::Let { name, value, body } => {
            fn_binder_used_as_value(sym, value)
                || (*name != sym && fn_binder_used_as_value(sym, body))
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            fn_binder_used_as_value(sym, value)
                || (!pat_binds_target(binder, sym) && fn_binder_used_as_value(sym, body))
        }
        Expr::If { cond, then_, else_ } => {
            fn_binder_used_as_value(sym, cond)
                || fn_binder_used_as_value(sym, then_)
                || fn_binder_used_as_value(sym, else_)
        }
        Expr::Match(m) => {
            fn_binder_used_as_value(sym, m.scrutinee())
                || m.arms().iter().any(|arm| {
                    !pat_binds_target(&arm.pat, sym) && fn_binder_used_as_value(sym, &arm.body)
                })
        }
        Expr::BinOp { lhs, rhs, .. } => {
            fn_binder_used_as_value(sym, lhs) || fn_binder_used_as_value(sym, rhs)
        }
        // A direct application `sym arg0 …`: the callee position is the ONE
        // exemption — `sym` is invoked, not carried. Its arguments are still
        // scanned (a self-passing `sym sym` is a value use through the arg).
        Expr::Apply { func, args } => {
            let callee_is_value = !matches!(func.as_ref(), Expr::Var(s) | Expr::CloneVar(s) if *s == sym)
                && fn_binder_used_as_value(sym, func);
            callee_is_value || args.iter().any(|a| fn_binder_used_as_value(sym, a))
        }
        Expr::Call { args, .. } | Expr::Ctor { args, .. } | Expr::TailRecur { args } => {
            args.iter().any(|a| fn_binder_used_as_value(sym, a))
        }
        Expr::Tuple(items) | Expr::List { items, .. } => {
            items.iter().any(|e| fn_binder_used_as_value(sym, e))
        }
        Expr::Cons { head, tail } => {
            fn_binder_used_as_value(sym, head) || fn_binder_used_as_value(sym, tail)
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            fn_binder_used_as_value(sym, list)
        }
        Expr::Record { fields, .. } | Expr::Update { fields, .. } => {
            fields.iter().any(|(_, e)| fn_binder_used_as_value(sym, e))
        }
        Expr::TaskSeq { effect, rest } => {
            fn_binder_used_as_value(sym, effect) || fn_binder_used_as_value(sym, rest)
        }
        Expr::TailLoop { params, body } => {
            !params.iter().any(|(s, _)| *s == sym) && fn_binder_used_as_value(sym, body)
        }
        Expr::Access { record, .. } => fn_binder_used_as_value(sym, record),
        // Leaves that cannot mention `sym`.
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        // A `FuncValue` names a TOP-LEVEL function / kernel as a value, never a
        // local binder, so it can never be `sym`.
        | Expr::FuncValue { .. } => false,
    }
}

/// Does `sym` appear ANYWHERE (any position) in `expr`? Used to decide whether a
/// nested lambda captures the function binder — any capture is a value use.
pub fn expr_refs_symbol(sym: Symbol, expr: &Expr) -> bool {
    match expr {
        Expr::Var(s) | Expr::CloneVar(s) => *s == sym,
        Expr::Lambda { body, .. } | Expr::SharedLambda { body, .. } => expr_refs_symbol(sym, body),
        Expr::Let { name, value, body } => {
            expr_refs_symbol(sym, value) || (*name != sym && expr_refs_symbol(sym, body))
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            expr_refs_symbol(sym, value)
                || (!pat_binds_target(binder, sym) && expr_refs_symbol(sym, body))
        }
        Expr::If { cond, then_, else_ } => {
            expr_refs_symbol(sym, cond)
                || expr_refs_symbol(sym, then_)
                || expr_refs_symbol(sym, else_)
        }
        Expr::Match(m) => {
            expr_refs_symbol(sym, m.scrutinee())
                || m.arms()
                    .iter()
                    .any(|arm| !pat_binds_target(&arm.pat, sym) && expr_refs_symbol(sym, &arm.body))
        }
        Expr::BinOp { lhs, rhs, .. } => expr_refs_symbol(sym, lhs) || expr_refs_symbol(sym, rhs),
        Expr::Apply { func, args } => {
            expr_refs_symbol(sym, func) || args.iter().any(|a| expr_refs_symbol(sym, a))
        }
        Expr::Call { args, .. } | Expr::Ctor { args, .. } | Expr::TailRecur { args } => {
            args.iter().any(|a| expr_refs_symbol(sym, a))
        }
        Expr::Tuple(items) | Expr::List { items, .. } => {
            items.iter().any(|e| expr_refs_symbol(sym, e))
        }
        Expr::Cons { head, tail } => expr_refs_symbol(sym, head) || expr_refs_symbol(sym, tail),
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            expr_refs_symbol(sym, list)
        }
        Expr::Record { fields, .. } | Expr::Update { fields, .. } => {
            fields.iter().any(|(_, e)| expr_refs_symbol(sym, e))
        }
        Expr::TaskSeq { effect, rest } => {
            expr_refs_symbol(sym, effect) || expr_refs_symbol(sym, rest)
        }
        Expr::TailLoop { params, body } => {
            !params.iter().any(|(s, _)| *s == sym) && expr_refs_symbol(sym, body)
        }
        Expr::Access { record, .. } => expr_refs_symbol(sym, record),
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => false,
    }
}

/// Is `ty` a plain first-class function type eligible for the direct-position
/// `impl Fn` carrier? Excludes the runtime-carrier special shapes
/// ([`render_type`]'s `ServerHandler` / `WsServerCfg` Arc arms, plus
/// [`IrType::SharedFun`] and [`IrType::FnOnceChain`]), whose rendered types are
/// NOT `Box<dyn Fn>` and must never be re-carriered here.
pub fn is_plain_boxed_fun(ty: &IrType) -> bool {
    matches!(ty, IrType::Fun(..)) && !wants_arc_ctor(ty)
}

/// The 0-based indices of `func`'s parameters that monomorphize from
/// `Box<dyn Fn>` to a fresh generic `impl Fn` carrier: a plain boxed-`Fun`
/// param ([`is_plain_boxed_fun`]) used ONLY as a direct callee in the body
/// (never as a value — [`fn_binder_used_as_value`] is `false`). Any escape keeps
/// the erased `Box` carrier. The result drives BOTH the signature emit
/// ([`emit_func`]) and the call-site unboxing (`Callee::Func` in the call
/// emitter), which read it through [`EmitCtx`] so the two halves never drift.
pub fn impl_fn_param_indices(func: &Func) -> Vec<usize> {
    func.params
        .iter()
        .enumerate()
        .filter(|(_, (sym, ty))| {
            is_plain_boxed_fun(ty) && !fn_binder_used_as_value(*sym, &func.body)
        })
        .map(|(i, _)| i)
        .collect()
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
        | Expr::PathLit(_)
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

/// Shadow-aware IR substitution: replace every FREE occurrence of
/// `Expr::Var(target)` in `body` with a clone of `replacement`, stopping
/// recursion into any subtree where a binder rebinds `target`. Replaces the
/// AUD-04 textual `replace_word_all(&body_s, &name_s, &replacement)`, which
/// pattern-matched the RENDERED Rust source by word-boundary only — so a
/// captured-variable word appearing mid string literal (`"the count is"` →
/// `"the count.clone() is"`) or matching a record field name
/// (`RecCount { count: n }` → `RecCount { count.clone(): n }`, invalid Rust)
/// got corrupted. Operating on the IR instead only ever touches genuine
/// `Var` leaf nodes — a string literal is an opaque `Expr::Str`, a record
/// field name is a `Symbol` key never matched against `Expr::Var`.
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
        | Expr::PathLit(_)
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

/// Returns `true` if `ty` is or structurally contains `IrType::Task`.
pub fn ir_type_contains_task(ty: &IrType) -> bool {
    match ty {
        IrType::Task(_) => true,
        IrType::Maybe(inner) | IrType::List(inner) => ir_type_contains_task(inner),
        IrType::Result(e, a) => ir_type_contains_task(e) || ir_type_contains_task(a),
        _ => false,
    }
}
