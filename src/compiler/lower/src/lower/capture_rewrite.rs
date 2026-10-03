//! The shared-capture pre-clone rewrite: given a lowered IR body and a symbol
//! that needs `Arc`/shared treatment, wrap every `Lambda`/`SharedLambda` (and
//! synthetic `TaskSeq` continuation) that directly reads the symbol in a
//! `let sym = sym.clone() in <node>` shadow, so a `move` closure captures the
//! fresh clone rather than moving the original out of an enclosing `Fn` env
//! (E0507/E0382). The rewrite is over-inclusive by design — a spurious
//! `Arc::clone` is a cheap pointer bump, whereas a missed wrap is a real
//! compile failure.

use ipe_intern::Symbol;
use ipe_ir::{Expr, IrType, Match, Pat};

use super::pat_binds_symbol;

/// Does `sym` appear as a live `Var`/`CloneVar` leaf DIRECTLY in `expr`
/// (i.e. NOT hidden behind a further-nested `Lambda`/`SharedLambda`
/// boundary)? Unlike [`lambda_body_refs_sym`] (which treats nested lambdas
/// as transparent — the right shape for "will the OUTER `move` closure
/// capture this"), this one STOPS at a nested lambda boundary and returns
/// `false` for it.
///
/// This predicate must ALWAYS be evaluated on the ALREADY-PROCESSED body
/// (after [`force_shared_capture_clones`] has recursed into the nested
/// lambdas), never the raw pre-recursion body. Recursion is what makes the
/// predicate sound as a wrap decision: when the inner lambda genuinely
/// captures `sym`, its own wrap plants a `Let { sym, CloneVar(sym), .. }`
/// directly in the enclosing lambda's body, turning what was an
/// only-behind-a-nested-lambda reference into a DIRECT one this predicate
/// now sees — so the pre-clone relays outward through every move-closure
/// boundary between `sym`'s binding and the read. Evaluating it on the
/// pre-recursion body would miss that relay and let an intermediate closure
/// move `sym` out of an `Fn` env (E0507); see
/// [`wrap_shared_lambda_if_needed`].
fn sym_referenced_directly(sym: Symbol, expr: &Expr) -> bool {
    match expr {
        Expr::Var(s) | Expr::CloneVar(s) => *s == sym,
        Expr::Let { name, value, body } => {
            sym_referenced_directly(sym, value)
                || (*name != sym && sym_referenced_directly(sym, body))
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            sym_referenced_directly(sym, value)
                || (!pat_binds_symbol(binder, sym) && sym_referenced_directly(sym, body))
        }
        Expr::Match(m) => {
            sym_referenced_directly(sym, m.scrutinee())
                || m.arms().iter().any(|arm| {
                    !pat_binds_symbol(&arm.pat, sym) && sym_referenced_directly(sym, &arm.body)
                })
        }
        Expr::TailLoop { params, body } => {
            !params.iter().any(|(s, _)| *s == sym) && sym_referenced_directly(sym, body)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            sym_referenced_directly(sym, lhs) || sym_referenced_directly(sym, rhs)
        }
        Expr::If { cond, then_, else_ } => {
            sym_referenced_directly(sym, cond)
                || sym_referenced_directly(sym, then_)
                || sym_referenced_directly(sym, else_)
        }
        Expr::Call { args, .. } => args.iter().any(|a| sym_referenced_directly(sym, a)),
        Expr::Apply { func, args } => {
            sym_referenced_directly(sym, func)
                || args.iter().any(|a| sym_referenced_directly(sym, a))
        }
        Expr::Tuple(items) | Expr::List { items, .. } => {
            items.iter().any(|e| sym_referenced_directly(sym, e))
        }
        Expr::Cons { head, tail } => {
            sym_referenced_directly(sym, head) || sym_referenced_directly(sym, tail)
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            sym_referenced_directly(sym, list)
        }
        Expr::Record { fields, .. } => fields.iter().any(|(_, e)| sym_referenced_directly(sym, e)),
        Expr::Update { record, fields } => {
            sym_referenced_directly(sym, record)
                || fields.iter().any(|(_, e)| sym_referenced_directly(sym, e))
        }
        Expr::Ctor { args, .. } => args.iter().any(|a| sym_referenced_directly(sym, a)),
        Expr::TaskSeq { effect, rest } => {
            sym_referenced_directly(sym, effect) || sym_referenced_directly(sym, rest)
        }
        Expr::TailRecur { args } => args.iter().any(|a| sym_referenced_directly(sym, a)),
        Expr::Access { record, .. } => sym_referenced_directly(sym, record),
        // A further-nested closure boundary — its own captures are its own
        // concern, not a DIRECT reference of the lambda we are testing.
        Expr::Lambda { .. }
        | Expr::SharedLambda { .. }
        | Expr::OnceLambda { .. }
        | Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => false,
    }
}

/// Recursively wrap every `Lambda`/`SharedLambda` node whose body DIRECTLY
/// references `sym` (per [`sym_referenced_directly`]) with a pre-clone
/// shadow binding: `let sym = sym.clone() in <lambda>`. Every `Var(sym)` /
/// `CloneVar(sym)` leaf inside the lambda's body is left COMPLETELY
/// UNCHANGED — ordinary Rust lexical shadowing makes it refer to the fresh
/// local clone once the wrap is in place, so no leaf rewrite is needed.
///
/// This is the actual fix for the E0507 class: a `move` closure ALWAYS
/// takes its captured free variables BY VALUE regardless of how the body
/// subsequently uses them (even a bare `.clone()` read inside the closure
/// does not avoid the closure's OWN move-capture of the ORIGINAL variable).
/// Rewriting `Var(sym)` reads in place to `CloneVar(sym)` therefore does
/// NOT fix the bug on its own — the SECOND (nested/sibling) closure's
/// construction still tries to move the FIRST closure's already-captured
/// copy out through a `&self`-only-borrowed field. The pre-clone-then-shadow
/// pattern sidesteps this: the clone is produced from a plain reference
/// (`Clone::clone(&self)` only needs `&sym`, never ownership) BEFORE the
/// nested closure literal is constructed, so the nested closure's `move`
/// captures the FRESH local clone — leaving the outer binding intact for
/// any other capture site. Mirrors the identical pattern
/// [`rewrite_multiuse_clones`] already uses for `CloneOk` multi-use
/// let-bindings (T5), generalised to the case where EVERY
/// directly-capturing closure needs its own wrap, not just all-but-the-last.
///
/// Applying this unconditionally to every directly-capturing lambda is
/// deliberately over-inclusive rather than a precise minimum-wrap analysis:
/// an unnecessary `Arc::clone` is a cheap, harmless pointer bump, so the
/// safe direction to err is "wrap slightly more than strictly required",
/// never "miss a wrap and leave a real E0507/E0382 unfixed". This function
/// is only ever invoked (from `lower_let`) after
/// [`needs_shared_capture`] has already confirmed `sym` genuinely needs
/// `Arc` treatment, so the common single-capture case (one lambda, no
/// further nesting, no sibling) never reaches here at all — the let-binding
/// stays a plain `Expr::Lambda` (`Box<dyn Fn>`), byte-identical to the
/// pre-fix lowering.
// A recursive tree-walk over a large enum — necessarily long and linear.
#[allow(clippy::too_many_lines)]
pub(super) fn force_shared_capture_clones(sym: Symbol, expr: Expr) -> Expr {
    match expr {
        Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => expr,
        Expr::Lambda { params, ret, body } => {
            wrap_shared_lambda_if_needed(sym, Expr::Lambda { params, ret, body })
        }
        Expr::SharedLambda { params, ret, body } => {
            wrap_shared_lambda_if_needed(sym, Expr::SharedLambda { params, ret, body })
        }
        Expr::OnceLambda {
            params,
            ret,
            body,
            capture,
        } => wrap_shared_lambda_if_needed(
            sym,
            Expr::OnceLambda {
                params,
                ret,
                body,
                capture,
            },
        ),
        Expr::Let { name, value, body } => force_shared_capture_clones_let(sym, name, *value, body),
        Expr::Destructure {
            binder,
            value,
            body,
        } => force_shared_capture_clones_destructure(sym, binder, *value, body),
        Expr::Match(m) => force_shared_capture_clones_match(sym, m),
        Expr::TailLoop { params, body } => force_shared_capture_clones_tail_loop(sym, params, body),
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: Box::new(force_shared_capture_clones(sym, *lhs)),
            rhs: Box::new(force_shared_capture_clones(sym, *rhs)),
        },
        Expr::If { cond, then_, else_ } => Expr::If {
            cond: Box::new(force_shared_capture_clones(sym, *cond)),
            then_: Box::new(force_shared_capture_clones(sym, *then_)),
            else_: Box::new(force_shared_capture_clones(sym, *else_)),
        },
        Expr::Call {
            callee,
            args,
            pin,
            on_form,
        } => Expr::Call {
            callee,
            args: force_shared_capture_clones_all(sym, args),
            pin,
            on_form,
        },
        Expr::Apply { func, args } => Expr::Apply {
            func: Box::new(force_shared_capture_clones(sym, *func)),
            args: force_shared_capture_clones_all(sym, args),
        },
        Expr::Tuple(items) => Expr::Tuple(force_shared_capture_clones_all(sym, items)),
        Expr::List { elem, items } => Expr::List {
            elem,
            items: force_shared_capture_clones_all(sym, items),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: Box::new(force_shared_capture_clones(sym, *head)),
            tail: Box::new(force_shared_capture_clones(sym, *tail)),
        },
        Expr::ListIndexClone { list, index } => Expr::ListIndexClone {
            list: Box::new(force_shared_capture_clones(sym, *list)),
            index,
        },
        Expr::ListLenCheck { list, len, exact } => Expr::ListLenCheck {
            list: Box::new(force_shared_capture_clones(sym, *list)),
            len,
            exact,
        },
        Expr::Record { fields, ty } => Expr::Record {
            fields: force_shared_capture_clones_fields(sym, fields),
            ty,
        },
        Expr::Access {
            record,
            field,
            field_ty,
        } => Expr::Access {
            record: Box::new(force_shared_capture_clones(sym, *record)),
            field,
            field_ty,
        },
        Expr::Update { record, fields } => Expr::Update {
            record: Box::new(force_shared_capture_clones(sym, *record)),
            fields: force_shared_capture_clones_fields(sym, fields),
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
            args: force_shared_capture_clones_all(sym, args),
        },
        // `TaskSeq` (auto-forced `let _ = <task>` continuation) emits as
        // `task_and_then(effect, Box::new(move |_| { rest }))` — the emitter
        // synthesises a `move` closure around `rest` that is NOT an `Expr::Lambda`
        // in the IR, so the ordinary `Lambda`-arm wrap never sees it. When `rest`
        // captures `sym` AND this whole `TaskSeq` is itself inside an enclosing
        // `move` closure, that synthetic inner closure moves `sym` out of the
        // enclosing closure's env → E0507 (07-todo-cli `runApp`'s
        // `initDb conn |> Task.andThen (\_ -> … runCommand conn …)` and every
        // `let _ = println … in <use sym>` continuation). Wrap the whole node in a
        // pre-clone `let sym = sym.clone() in TaskSeq{…}`: the wrap sits OUTSIDE
        // the emitted `task_and_then(…)` (hence outside the synthetic `move |_|`),
        // so the closure captures the fresh clone while the enclosing closure's
        // `sym` is only borrowed by `.clone()` — keeping it `Fn`. `effect` is
        // emitted as the FIRST `task_and_then` arg (outside the closure) and reads
        // the same shadowed clone, sound for a `CloneOk` value. Only wraps when
        // `rest` references `sym`; a no-op otherwise, so non-continuation TaskSeqs
        // stay byte-identical.
        Expr::TaskSeq { effect, rest } => {
            let effect = Box::new(force_shared_capture_clones(sym, *effect));
            let rest = Box::new(force_shared_capture_clones(sym, *rest));
            let node = Expr::TaskSeq { effect, rest };
            wrap_task_seq_rest_capture(sym, node)
        }
        Expr::TailRecur { args } => Expr::TailRecur {
            args: force_shared_capture_clones_all(sym, args),
        },
    }
}

/// Pre-clone `sym` around an already-processed `TaskSeq` whose `rest` reads it.
///
/// The node becomes `let sym = sym.clone() in <TaskSeq>`. This is the one
/// placement of a `CloneOk` capture's pre-clone at the entry of a `TaskSeq`
/// continuation, the `Once` boundary `ipe_ir::once_closure::boundary_kind`
/// names for the node. The emitter renders `TaskSeq { effect, rest }` as
/// `task_and_then(effect, Box::new(move |_| { rest }))`; placing the pre-clone
/// OUTSIDE the whole node emits it BEFORE the `task_and_then(…)` call, hence
/// outside the synthetic `move |_|` closure, so that closure captures the fresh
/// clone and any enclosing `move` closure's `sym` is only borrowed by `.clone()`
/// (kept `Fn`). `sym_referenced_directly` stops at nested `Lambda` boundaries, so
/// a `sym` used ONLY inside a further-nested real lambda inside `rest` is that
/// lambda's own concern (it already got its own wrap during recursion) and does
/// not trigger a redundant `TaskSeq` wrap here.
fn wrap_task_seq_rest_capture(sym: Symbol, node: Expr) -> Expr {
    let Expr::TaskSeq { rest, .. } = &node else {
        return node;
    };
    if sym_referenced_directly(sym, rest) {
        Expr::Let {
            name: sym,
            value: Box::new(Expr::CloneVar(sym)),
            body: Box::new(node),
        }
    } else {
        node
    }
}

/// Map [`force_shared_capture_clones`] over every element of an `Expr` list —
/// shared by every [`force_shared_capture_clones`] arm that just recurses
/// into a `Vec<Expr>` (call/ctor/tail-recur args, tuple/list items).
fn force_shared_capture_clones_all(sym: Symbol, items: Vec<Expr>) -> Vec<Expr> {
    items
        .into_iter()
        .map(|e| force_shared_capture_clones(sym, e))
        .collect()
}

/// Map [`force_shared_capture_clones`] over every field VALUE of a record
/// literal/update (`Record`, `Update.fields`), leaving field names untouched.
fn force_shared_capture_clones_fields(
    sym: Symbol,
    fields: Vec<(Symbol, Expr)>,
) -> Vec<(Symbol, Expr)> {
    fields
        .into_iter()
        .map(|(name, e)| (name, force_shared_capture_clones(sym, e)))
        .collect()
}

/// [`force_shared_capture_clones`]'s `Let` arm: recurse into `value`
/// unconditionally, and into `body` unless this `let` itself shadows `sym`.
fn force_shared_capture_clones_let(
    sym: Symbol,
    name: Symbol,
    value: Expr,
    body: Box<Expr>,
) -> Expr {
    let value = Box::new(force_shared_capture_clones(sym, value));
    let body = if name == sym {
        body
    } else {
        Box::new(force_shared_capture_clones(sym, *body))
    };
    Expr::Let { name, value, body }
}

/// [`force_shared_capture_clones`]'s `Destructure` arm: recurse into `value`
/// unconditionally, and into `body` unless `binder` shadows `sym`.
fn force_shared_capture_clones_destructure(
    sym: Symbol,
    binder: Pat,
    value: Expr,
    body: Box<Expr>,
) -> Expr {
    let value = Box::new(force_shared_capture_clones(sym, value));
    let body = if pat_binds_symbol(&binder, sym) {
        body
    } else {
        Box::new(force_shared_capture_clones(sym, *body))
    };
    Expr::Destructure {
        binder,
        value,
        body,
    }
}

/// [`force_shared_capture_clones`]'s `TailLoop` arm: recurse into `body`
/// unless `params` shadow `sym`.
fn force_shared_capture_clones_tail_loop(
    sym: Symbol,
    params: Vec<(Symbol, IrType)>,
    body: Box<Expr>,
) -> Expr {
    let shadowed = params.iter().any(|(s, _)| *s == sym);
    let body = if shadowed {
        body
    } else {
        Box::new(force_shared_capture_clones(sym, *body))
    };
    Expr::TailLoop { params, body }
}

/// [`force_shared_capture_clones`]'s `Match` arm: recurse into the
/// scrutinee unconditionally, and into each arm's body unless that arm's
/// pattern itself shadows `sym`.
fn force_shared_capture_clones_match(sym: Symbol, m: Match) -> Expr {
    Expr::Match(m.map_bodies(
        |scrutinee| force_shared_capture_clones(sym, scrutinee),
        |pat, body, guard| {
            let body = if pat_binds_symbol(pat, sym) {
                body
            } else {
                force_shared_capture_clones(sym, body)
            };
            (body, guard)
        },
    ))
}

/// Helper for [`force_shared_capture_clones`]'s `Lambda`/`SharedLambda` arms:
/// `lambda_expr` MUST be one of those two variants. Recurses into the body
/// first (so a deeper nested lambda gets its own wrap too), then wraps THIS
/// lambda with a pre-clone shadow IF `sym` is shadowed by neither this
/// lambda's own params NOR referenced directly in its (already-processed)
/// body. Un-referenced or shadowed lambdas pass through with only their body
/// recursively processed (still necessary — a sibling branch deeper in the
/// SAME body may reference `sym` even if this particular lambda does not).
fn wrap_shared_lambda_if_needed(sym: Symbol, lambda_expr: Expr) -> Expr {
    let (shadowed, needs_wrap, rebuilt) = match lambda_expr {
        Expr::Lambda { params, ret, body } => {
            let shadowed = params.iter().any(|(s, _)| *s == sym);
            // Recurse FIRST, then decide on the PROCESSED body. An inner
            // lambda's own wrap plants a direct `CloneVar(sym)` read in THIS
            // lambda's body, so a symbol reached only through a deeper closure
            // (e.g. a pipeline-synthesized intermediate `move |eta_0|`) becomes
            // a direct reference here after recursion — and this lambda gets its
            // relay pre-clone. Deciding on the pre-recursion body would miss it
            // (`sym_referenced_directly` is lambda-opaque), leaving the
            // intermediate closure to move `sym` out of the enclosing `Fn` env
            // (E0507). The relay thus propagates outward through every boundary.
            let body = if shadowed {
                body
            } else {
                Box::new(force_shared_capture_clones(sym, *body))
            };
            let needs_wrap = !shadowed && sym_referenced_directly(sym, &body);
            (shadowed, needs_wrap, Expr::Lambda { params, ret, body })
        }
        Expr::SharedLambda { params, ret, body } => {
            let shadowed = params.iter().any(|(s, _)| *s == sym);
            // Recurse FIRST, then decide on the PROCESSED body — see the
            // `Lambda` arm above for why the relay must be post-recursion.
            let body = if shadowed {
                body
            } else {
                Box::new(force_shared_capture_clones(sym, *body))
            };
            let needs_wrap = !shadowed && sym_referenced_directly(sym, &body);
            (
                shadowed,
                needs_wrap,
                Expr::SharedLambda { params, ret, body },
            )
        }
        Expr::OnceLambda {
            params,
            ret,
            body,
            capture,
        } => {
            let shadowed = params.iter().any(|(s, _)| *s == sym);
            // Recurse FIRST, then decide on the PROCESSED body — see the
            // `Lambda` arm above for why the relay must be post-recursion.
            let body = if shadowed {
                body
            } else {
                Box::new(force_shared_capture_clones(sym, *body))
            };
            let needs_wrap = !shadowed && sym_referenced_directly(sym, &body);
            (
                shadowed,
                needs_wrap,
                Expr::OnceLambda {
                    params,
                    ret,
                    body,
                    capture,
                },
            )
        }
        other => (true, false, other),
    };
    if shadowed || !needs_wrap {
        return rebuilt;
    }
    Expr::Let {
        name: sym,
        value: Box::new(Expr::CloneVar(sym)),
        body: Box::new(rebuilt),
    }
}
