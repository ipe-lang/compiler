//! The Doc-building emit path: a parallel to
//! [`crate::emit_expr::emit_expr_at`] that returns a [`Doc`] instead of a
//! `String`.
//!
//! Every builder carries EXACTLY the token sequence the string emitter produces,
//! so the whitespace-normalized leaf sequence of `build_doc(e)` equals the
//! whitespace-normalized string of `emit_expr_at(e)` — the SEAL.
//!
//! Structured (layout-bearing) arms, each byte-goldened against
//! `rustfmt --edition 2024 --style-edition 2024`:
//!   * the binary-operator chain (`BinOp` Add..Or) → [`Doc::Chain`];
//!   * `if`/`else` → inline or block form by an absolute width threshold;
//!   * the delimited lists — `Tuple`, plain non-empty non-`Ui` `List`, `Cons`,
//!     the plain user-function `Call` (`Callee::Func`, no turbofish pin), the
//!     saturated payload `Ctor` (user-enum, each cyclic-self-field argument boxed,
//!     or runtime-enum `IpeMaybe`/`IpeResult`/…), and the general function-value
//!     `Apply` tail (`({f})(args)`, non-lambda func, non-empty args) — which lay
//!     out flat when they fit and otherwise break one element per line with a
//!     break-conditional trailing comma ([`Doc::IfBroken`]);
//!   * the `let` block (`({ let name = value; body })`) — the one-statement block
//!     always breaks (a `HardLine` per line); its zero-statement multi-use inline
//!     substitution form (`({ inlined_body })`) is a soft group that flattens
//!     when it fits.
//!
//! The call-shaped binops are structured too: `++` → `format!("{}{}", l, r)` (a
//! MACRO delimited group, broken WITHOUT a trailing comma) and `//` →
//! `ipe_runtime::math::ipe_int_div(l, r)` (a plain two-argument delimited group).
//! The named-function value `FuncValue` is the same always-breaking `{ let
//! __ipe_fn: <TypedFn> = <ctor>::new(<name>); __ipe_fn }` block as a boxed lambda,
//! its `let` on the [`Doc::Assign`] RHS-break axis.
//!
//! Every remaining arm is carried as one [`Doc::owned`] leaf holding the string
//! emitter's exact bytes: the literals (Int/Float/Str/…), the empty/`Ui` list and
//! zero-arg call forms, and the context-heavy arms not yet structured
//! (kernel-dispatch / FFI / pinned calls). Field access (`Access`), the constant
//! list-index clone (`ListIndexClone`), and the borrowing length guard
//! (`ListLenCheck`) also stay leaves: their only break point is `rustfmt`'s
//! method-call-chain layout (`.field` / `.clone()` / `.len()` each dropped onto
//! its own line when the BASE breaks), a mechanism the Doc IR does not model — and
//! no corpus fixture ever exercises it, because every base is a single-line
//! `Var` / `CloneVar`. Carrying bytes keeps the SEAL exact by construction; those
//! arms simply do not yet gain multi-line layout.
//!
//! This is the production function-body emit path: [`crate::emit_expr::emit_func`]
//! renders every body through `build_doc` + [`crate::render::render`], so the
//! emitted body is `rustfmt`-clean by construction. The string emitter's
//! [`emit_expr_at`] survives as the leaf builder the structured arms delegate to
//! (and as the SEAL / byte-golden test oracle), not as the body formatter.

use std::borrow::Cow;

use ipe_diagnostics::{DResult, Diagnostic, LowerError, Span};
use ipe_intern::{Interner, Symbol, rust_str_lit};
use ipe_ir::{BinOp, Callee, Expr, IrType, KernelFn, MAX_IR_RENDER_DEPTH, ModPath};

use crate::EmitCtx;
use crate::doc::{ChainOperand, Doc};
use crate::emit_expr::{
    call_has_kernel_special_case, callee_name, clone_targets_in_expr, combine_guards,
    emit_arm_head, emit_binding_stmts, emit_expr_at, emit_match_scrutinee, free_vars, infix,
    inlined_let_body, once_closure_bug, record_struct_name, swapped_container_clone_rewrite,
    wants_arc_ctor,
};
use crate::emit_types::{GenericScope, render_type};
use ipe_ir::once_closure::{ClosureParts, ClosureSite, admitted_once_parts};

/// Build a [`Doc`] for `expr`. Mirrors [`emit_expr_at`]'s arm structure; the
/// token leaves are byte-identical to the string emitter's output.
///
/// `indent`/`depth`/`generics` are threaded exactly as the string emitter
/// threads them, so a leaf that delegates to `emit_expr_at` sees the same
/// context. `depth` is the IR-nesting level of `expr` (0 at a function body),
/// matching `emit_expr_at`'s own `depth` argument.
#[allow(clippy::too_many_lines)] // One arm per expr shape, mirroring `emit_expr_at`.
pub fn build_doc(
    ctx: &EmitCtx,
    expr: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    // The same fail-fast nesting bound the string emitter enforces
    // ([`emit_expr_at`]): one Rust stack frame per IR level, so an
    // adversarially deep spine is rejected with a `Lower` diagnostic before it
    // can overflow the native stack. Shared with the string path via
    // [`MAX_IR_RENDER_DEPTH`] so the two never drift to different ceilings.
    if depth > MAX_IR_RENDER_DEPTH {
        return Err(Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::BackendNestingTooDeep {
                limit: MAX_IR_RENDER_DEPTH,
            },
        });
    }
    let child = depth + 1;
    match expr {
        // A chain-eligible infix operator: flatten the maximal left-nested
        // same-operator run into a `Doc::Chain`, carrying every paren the string
        // emitter emits as a `Text` leaf.
        Expr::BinOp { op, lhs, rhs } if infix(*op).is_some() => {
            build_binop_chain(ctx, *op, lhs, rhs, indent, child, generics)
        }

        // Call-shaped binops: `++` → `format!("{}{}", l, r)` (macro, no
        // trailing comma), `//` → `ipe_int_div(l, r)`, the integer arithmetic
        // helpers `ipe_int_{add,sub,mul}(l, r)`, and the polymorphic wrapping
        // helpers `l.ipe_wrapping_{add,sub,mul}(r)`. All are two-argument
        // delimited groups; `build_call_binop` picks the shape by kind.
        Expr::BinOp { op, lhs, rhs }
            if matches!(
                op,
                BinOp::Append
                    | BinOp::IntDiv
                    | BinOp::IntAdd
                    | BinOp::IntSub
                    | BinOp::IntMul
                    | BinOp::Add
                    | BinOp::Sub
                    | BinOp::Mul
            ) =>
        {
            build_call_binop(ctx, *op, lhs, rhs, indent, child, generics)
        }

        // A parenthesized `if`/`else` expression: a shape-faithful `Doc::IfElse`
        // over the three branch documents. The renderer keeps the whole construct
        // on one line when the `if cond { then } else { else }` text (WITHOUT the
        // outer parens) fits `single_line_if_else_max_width` — an absolute,
        // column-independent threshold — and otherwise breaks each branch body onto
        // its own line in block form.
        Expr::If { cond, then_, else_ } => {
            build_if(ctx, cond, then_, else_, indent, child, generics)
        }

        // A tuple constructor `(e0, e1, …)`: a delimited group that breaks one
        // element per line with a trailing comma when it does not fit.
        Expr::Tuple(elems) => build_tuple(ctx, elems, indent, child, generics),

        // A plain non-empty, non-`Ui` list literal `vec![e0, e1, …]`: a delimited
        // group like the tuple. The empty-list forms and the `Ui`-annotated
        // wrapper carry no positional list layout, so they stay leaves.
        Expr::List { elem, items } if !items.is_empty() && !matches!(elem, IrType::Ui { .. }) => {
            build_list(ctx, items, indent, child, generics)
        }

        // `head :: tail`: the runtime cons call, a two-argument delimited group.
        Expr::Cons { head, tail } => build_cons(ctx, head, tail, indent, child, generics),

        // A constructor application `EnumName::Variant(a0, a1, …)`. A nullary
        // constructor (built-in-runtime or user) stays a leaf (`EnumName::Variant`
        // — no positional payload to break); a saturated payload constructor is a
        // delimited group over its argument docs, each cyclic-self-field argument
        // wrapped in `Box::new(..)` exactly as the string emitter wraps it.
        Expr::Ctor {
            home,
            ty,
            variant,
            args,
        } if !args.is_empty() => {
            build_ctor(ctx, home, *ty, *variant, args, indent, child, generics)
        }

        // `Db.withTransaction conn body`: the transaction wrapper. Its emitted
        // form `db_with_transaction({conn}.clone(), {body})` is a two-argument
        // delimited call whose body argument is a boxed closure value; routing it
        // through the Doc algebra (rather than the flat leaf `emit_db_call`
        // returns) lets that closure and its continuation chain break per
        // `rustfmt`.
        Expr::Call {
            callee: Callee::Kernel(KernelFn::DbWithTransaction),
            args,
            ..
        } if matches!(args.as_slice(), [_conn, _body]) => {
            let [conn, body] = args.as_slice() else {
                // The guard proves the two-element shape; fail closed rather than
                // panic if it ever drifts.
                return leaf(ctx, expr, indent, depth, generics);
            };
            build_db_with_transaction(ctx, conn, body, indent, child, generics)
        }

        // The param-projecting Task-returning Db kernels `db_exec_raw` /
        // `db_exec_params` / `db_query_params`. Structured so their argument list
        // (and `DbExec` / `DbQuery`'s `List SqlValue` → `Vec<SqlParam>` projection
        // method chain) breaks per `rustfmt` when the call is wide — the flat
        // string leaf `emit_db_call` returns could never reach that layout inside a
        // routed `db_with_transaction` continuation. Every OTHER Db kernel keeps its
        // custom projection and stays a byte-carried leaf.
        Expr::Call {
            callee: Callee::Kernel(k @ (KernelFn::DbExecRaw | KernelFn::DbExec | KernelFn::DbQuery)),
            args,
            ..
        } if (matches!(k, KernelFn::DbExecRaw) && args.len() == 2)
            || (!matches!(k, KernelFn::DbExecRaw) && args.len() == 3) =>
        {
            build_db_param_call(ctx, *k, args, indent, child, generics)
        }

        // A function call whose emitted form is the generic fall-through tail
        // `{name}{turbofish}({args})` — the exact shape
        // [`crate::emit_expr::emit_expr_at`] produces once every kernel special
        // case has been ruled out. Structured for any non-empty-arg call
        // (`Callee::Func` / `Ffi` / a kernel with no bespoke wrapping): the plain
        // user call, the FFI wrapper, the turbofish-pinned kernel, and the
        // container-swapping kernel all lower to `{name}{turbofish}(` + a delimited
        // argument list. The `call_has_kernel_special_case` predicate re-runs the
        // ~8 probe helpers + the `Dict.get` clone case; when ANY applies the call
        // stays a byte-carried leaf (its bespoke wrapping is not structured). A
        // zero-arg call also stays a leaf (no positional list to break).
        Expr::Call {
            callee,
            args,
            pin,
            on_form,
        } if !args.is_empty()
            && !call_has_kernel_special_case(
                ctx, callee, args, *on_form, indent, child, generics,
            )?
            && !crate::emit_expr::ffi_call_has_glue(ctx, callee)? =>
        {
            build_generic_call(ctx, callee, args, *pin, indent, child, generics)
        }

        // A named-function value `{ let __ipe_fn: <TypedFn> = <ctor>::new(<name>);
        // __ipe_fn }`. The same always-breaking statement block as a boxed lambda,
        // but the RHS is `<ctor>::new(<name>)` over a bare function name (a leaf,
        // never itself breaking) rather than a closure. The `let` statement uses the
        // [`Doc::Assign`] RHS-break axis (the wide `Box<dyn Fn(…) -> R + …>`
        // annotation pushes the RHS to its own line when the same-line form
        // overflows). See [`build_func_value`].
        Expr::FuncValue { callee, ty } => build_func_value(ctx, callee, ty, generics),

        // A boxed lambda value `{ let __ipe_fn: <TypedFn> = Box::new(move |…| -> R {
        // <body> }); __ipe_fn }` (`Arc` for the runtime handler shapes). A
        // statement block that ALWAYS breaks (it holds the `let`): the assignment
        // and the `__ipe_fn` tail each on their own `HardLine`. The `let` statement
        // uses the [`Doc::Assign`] RHS-break axis (the wide `Box<dyn Fn(…) -> R +
        // Send + 'static>` annotation pushes the RHS to its own line), and the
        // closure body is a braces-always block that breaks when wide.
        Expr::Lambda { params, ret, body } => {
            build_lambda(ctx, params, ret, body, indent, child, generics, false)
        }
        // A shared (`Arc<dyn Fn(…) + Send + Sync>`) lambda value — the same block
        // shape as [`Expr::Lambda`] but with the reference-counted pointer the
        // capture analysis proved it needs. See [`build_lambda`].
        Expr::SharedLambda { params, ret, body } => {
            build_lambda(ctx, params, ret, body, indent, child, generics, true)
        }
        // A once closure is built only by the admitted positions below (an
        // immediate application, `Task.andThen`'s continuation); mirrors
        // [`crate::emit_expr::emit_expr_at`]'s refusal everywhere else.
        Expr::OnceLambda { .. } => Err(once_closure_bug("ipe_backend_rust::emit_doc::build_doc")),

        // An immediately-applied lambda `({ let p0: T0 = a0; … body })`. The string
        // emitter inlines the lambda's params as `let` bindings then the body — a
        // statement block that ALWAYS breaks (it holds the bindings): each binding
        // and the body on their own `HardLine`. Each binding is an [`Doc::Assign`]
        // (its `p: T = arg` may RHS-break when wide); the body is built recursively.
        // Taken exactly when the string emitter inlines: a saturated or curried
        // apply (`args.len() >= params.len()`). An under-applied lambda is boxed and
        // called there, so it takes the general application arm below.
        Expr::Apply { func, args }
            if matches!(
                func.as_ref(),
                Expr::Lambda { params, .. } if !args.is_empty() && args.len() >= params.len()
            ) =>
        {
            let Expr::Lambda {
                params,
                body: lam_body,
                ..
            } = func.as_ref()
            else {
                // The guard already proved `func` is a `Lambda`; unreachable, but
                // fail closed rather than panic.
                return leaf(ctx, expr, indent, depth, generics);
            };
            build_applied_lambda(ctx, params, args, lam_body, indent, child, generics)
        }
        // An immediately-applied once closure: the same block as a `Lambda`,
        // only where the shared once verdict admits the application (mirrors
        // [`crate::emit_expr::emit_apply`]).
        Expr::Apply { func, args } if matches!(func.as_ref(), Expr::OnceLambda { .. }) => {
            let arity = if let Expr::OnceLambda { params, .. } = func.as_ref() {
                params.len()
            } else {
                0
            };
            let site = ClosureSite::ImmediateApply {
                arity,
                args: args.len(),
            };
            let Some((params, _, lam_body)) = admitted_once_parts(func, &site) else {
                return Err(once_closure_bug(
                    "ipe_backend_rust::emit_doc::build_doc(Apply)",
                ));
            };
            build_applied_lambda(ctx, params, args, lam_body, indent, child, generics)
        }

        // A general function-value application `({f})(a0, a1, …)`. Structured ONLY
        // for the non-empty-arg tail: an inlined `Lambda` apply and every
        // `OnceLambda` apply are handled by the arms above, so a `Lambda` here is an
        // under-applied one the string emitter boxes and calls; a zero-arg apply
        // (`({f})()`) has no positional list, so it stays a leaf. The remaining tail
        // is exactly `({f})(` + a delimited argument list; `f` is built recursively
        // so a structured func operand rides inside its parens.
        Expr::Apply { func, args }
            if !matches!(func.as_ref(), Expr::OnceLambda { .. }) && !args.is_empty() =>
        {
            let func_doc = build_doc(ctx, func, indent, child, generics)?;
            let docs = build_args(ctx, args, indent, child, generics)?;
            // The string emitter writes `({f})(args)`; when `f` already renders
            // parenthesized (a `({ … })` block), the outer pair is redundant and
            // `rustfmt` collapses `(( … ))` to `( … )`. `Doc::elidable_paren` carries
            // the parens in the SEAL leaves but drops them at render in that case.
            Ok(delimited(
                Doc::concat(vec![Doc::elidable_paren(func_doc), Doc::text("(")]),
                docs,
                Doc::text(")"),
            ))
        }

        // A `let` expression `({ let name = value; body })`. The one-statement
        // block ALWAYS breaks (rustfmt never inlines a block that holds a `let`):
        // `({`, then the `let` statement and the body each on their own line at
        // one indent step, then `})` dedented back. The multi-use non-clone
        // inline-substitution path (a ZERO-statement block `({ body })`) lays out
        // as a soft group so it flattens when it fits — mirroring
        // [`crate::emit_expr::emit_expr_at`]'s `Expr::Let` arm decision exactly.
        Expr::Let { name, value, body } => {
            build_let(ctx, *name, value, body, indent, child, generics)
        }

        // A `Destructure` block `({ <binding stmts> <body> })`. Like the `let`
        // block, but its binder may expand to MULTIPLE `let` statements
        // (`emit_binding_stmts`: one flat `let <pat> = <value>;` for an alias-free
        // binder, or the clone-split sequence for an aliased one). Each statement
        // and the body go on their own `HardLine`, so the block always breaks —
        // matching `rustfmt`, which never inlines a block that holds a statement.
        Expr::Destructure {
            binder,
            value,
            body,
        } => build_destructure(ctx, binder, value, body, indent, child, generics),

        // A non-empty record literal `StructName { f0: v0, f1: v1 }`: a delimited
        // group over its `field: value` parts that breaks one field per line with a
        // trailing comma when it does not fit, matching rustfmt's struct-literal
        // layout. The struct name is resolved by
        // [`crate::emit_expr::record_struct_name`] (shared with the string
        // emitter). An empty record stays a leaf — rustfmt renders `StructName {}`
        // with no inner break, which the delimited builder is not shaped for.
        Expr::Record { fields, ty } if !fields.is_empty() => {
            build_record(ctx, fields, ty.as_ref(), indent, child, generics)
        }

        // A functional record update `{ let __ipe_upd_i = v; … let mut __ipe_rec
        // = <base>; __ipe_rec.f = __ipe_upd_i; … __ipe_rec }`: a statement block
        // that ALWAYS breaks (it holds statements), each `let`/assignment/tail on
        // its own `HardLine` inside the sole `Nest(4)`, matching rustfmt. Each
        // field value binds to a temporary BEFORE the base is moved, so a field
        // value may read the base. The base is moved into `__ipe_rec` directly;
        // when it is a `CloneVar` the lowerer already inserted `.clone()`.
        Expr::Update { record, fields } => {
            build_update(ctx, record, fields, indent, child, generics)
        }

        // The sync task-sequencing block `{ let _ = task_run(<effect>); <rest> }`.
        // A statement block (it holds the discard `let`), so it ALWAYS breaks: the
        // The auto-force task-sequencing tail
        // `task_and_then(<effect>, Box::new(move |_| { <rest> }))`. The outer
        // `task_and_then(effect, cont)` is a two-argument delimited group (it breaks
        // one argument per line with a trailing comma when it does not fit); the
        // continuation's `<rest>` body is a `BraceBody`, so `rustfmt` strips its
        // braces when the closure body fits (`move |_| rest`) and braces+breaks them
        // when it does not. The effect gets the identical IR-level clone-capture
        // rewrite the string emitter applies (`clone_targets_in_expr` over `rest`'s
        // `free_vars`); both effect and rest are built recursively.
        Expr::TaskSeq { effect, rest } => {
            build_task_seq(ctx, effect, rest, indent, child, generics)
        }

        // A `match scrut { pat => body, … }`. The match skeleton always breaks (a
        // `match` never inlines): the scrutinee and each arm head/guard are carried
        // as byte leaves (single-line, no layout of their own — they reuse the
        // string emitter's `emit_match_scrutinee` / `emit_arm_head`), and only the
        // arm BODIES gain recursive Doc layout. Each arm is wrapped per rustfmt's
        // brace/comma rule (see [`build_match`]). Threaded with the match's own
        // `depth` (not `child`), matching `emit_match`'s own `child = depth + 1`.
        Expr::Match(m) => build_match(ctx, m, indent, depth, generics),

        // A string literal `"…".to_string()`, mirroring
        // [`crate::emit_expr::emit_expr_at`]'s `Expr::Str` arm. Structured as a
        // trailing-`.to_string()` method chain over the string-literal receiver so
        // `rustfmt` drops the `.to_string()` onto its own line at one indent step
        // when the glued `"…".to_string()` overflows the width — the layout a flat
        // leaf could never reach at a deep indent (a wide SQL string inside a broken
        // Db call). Both the receiver and the `.to_string()` are single-line leaves;
        // the SEAL carries `"…".to_string()` adjacently, identical to the string
        // emitter's bytes.
        Expr::Str(s) => Ok(Doc::method_chain(
            Doc::owned(rust_str_lit(s)),
            Doc::text(".to_string()"),
        )),

        // Every remaining arm carries the string emitter's exact bytes as one
        // leaf. Its layout is whatever single-line pre-`rustfmt` form the string
        // emitter produces; structuring the rest (call-arg lists, block-form
        // `let`/destructure, match, lambda, record/update) is the remaining P2
        // work. Carrying bytes keeps the SEAL exact by construction.
        _ => leaf(ctx, expr, indent, depth, generics),
    }
}

/// Emit `expr` through the legacy string emitter and wrap its bytes as one
/// [`Doc::owned`] leaf. Preserves the exact token sequence for any arm not yet
/// structured.
fn leaf(
    ctx: &EmitCtx,
    expr: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    Ok(Doc::owned(emit_expr_at(
        ctx, expr, indent, depth, generics,
    )?))
}

/// One divergent function body.
///
/// Its native Doc render (`render(build_doc)`) differs from the legacy
/// `emit_expr_at` + `rustfmt` bytes; reported by [`native_vs_legacy_sweep`].
#[derive(Debug, Clone)]
pub struct SweepDivergence {
    /// The Rust name of the function the divergent expression is a body of.
    pub func: String,
    /// A short `{:?}`-prefix of the divergent [`Expr`], for identification.
    pub expr_head: String,
    /// The native Doc render (`render(build_doc(e))`).
    pub native: String,
    /// The legacy `rustfmt(emit_expr_at(e))` bytes.
    pub legacy: String,
}

/// The whole-corpus P3-cutover gate.
///
/// For every function body in `program`, render it BOTH ways — the native Doc
/// path (`render(build_doc)`) and the legacy path (`emit_expr_at` then real
/// `rustfmt`) — and return every expression whose two renders disagree. The native
/// path is safe to make the default emit path only when this returns empty for the
/// whole corpus.
///
/// The comparison unit is the whole function body expression: that is the value
/// the native path replaces, and rustfmt formats a sub-expression differently in
/// isolation than in context, so a per-sub-expr diff would report spurious
/// divergences. Each body is wrapped as `fn __sweep() -> Wrap { <body> }` and run
/// through `rustfmt --edition 2024 --style-edition 2024`; a body rustfmt rejects
/// (a non-value shape in this synthetic context — a `let`/`match` statement head,
/// a `TailLoop`) is SKIPPED and counted, mirroring the fixture sweep's skip rule.
///
/// `compared` is the number of bodies actually diffed (rustfmt accepted the
/// wrapper); `skipped` counts the bodies rustfmt rejected. Requires `rustfmt` on
/// `PATH`; a body whose legacy formatting fails is skipped rather than reported.
///
/// # Errors
/// Propagates any [`Diagnostic`] from [`EmitCtx::build`] or the emitters.
pub fn native_vs_legacy_sweep(
    interner: &Interner,
    program: &ipe_ir::Program,
) -> DResult<(Vec<SweepDivergence>, usize, usize)> {
    let ctx = EmitCtx::build(
        interner,
        program,
        crate::DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        crate::MountBase::root(),
        false,
        None,
        false,
        crate::BuildIntent::Release,
        String::new(),
        false,
        false,
        None,
    )?;
    let mut divergences = Vec::new();
    let mut compared = 0usize;
    let mut skipped = 0usize;
    for module in &program.modules {
        for func in &module.funcs {
            let name = ctx.func_name(func.id)?.to_owned();
            let scope_syms: Vec<Symbol> = func.type_params.iter().map(|(s, _)| *s).collect();
            let generics = GenericScope::new(&scope_syms);
            // The body is emitted at fn-body indent 1, depth 0 — exactly the
            // context `emit_func` passes to `emit_expr`.
            let Ok(legacy_raw) = emit_expr_at(&ctx, &func.body, 1, 0, generics) else {
                skipped += 1;
                continue;
            };
            let Some(legacy) = legacy_rustfmt_body(&legacy_raw) else {
                skipped += 1;
                continue;
            };
            let doc = build_doc(&ctx, &func.body, 1, 0, generics)?;
            let native = render_body_dedented(&doc);
            compared += 1;
            if native != legacy {
                divergences.push(SweepDivergence {
                    func: name,
                    expr_head: expr_head(&func.body),
                    native,
                    legacy,
                });
            }
        }
    }
    Ok((divergences, compared, skipped))
}

/// Render a function-body `doc` at the fn-body block indent (level 1 = 4 columns)
/// and dedent every line back to column 0 — the same framing the legacy path is
/// compared at (`legacy_rustfmt_body` strips the `fn __sweep` wrapper's four-space
/// body indent). The body's opening character lands at column 4 (matching the
/// `fn f() {` body column rustfmt measures against), then the four-space prefix is
/// removed from each line so both sides are compared at column 0.
fn render_body_dedented(doc: &Doc) -> String {
    // Seed the render with four spaces so the body starts at column 4, and wrap the
    // doc in `Nest(4)` so every internal newline indents from the block indent —
    // exactly the `render_fn_body` test framing.
    let seeded = Doc::nest(4, Doc::concat(vec![Doc::text("    "), doc.clone()]));
    let rendered = crate::render::render(&seeded, crate::render::RenderConfig::default());
    rendered
        .lines()
        .map(|l| l.strip_prefix("    ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A short identifying prefix of an [`Expr`]'s debug form (the variant name and a
/// little context), for the divergence report.
fn expr_head(expr: &Expr) -> String {
    let dbg = format!("{expr:?}");
    dbg.chars().take(80).collect()
}

/// Format `body_expr` as a `fn __sweep() -> Wrap { <body> }` function body, run
/// real `rustfmt`, and return the formatted body dedented to column 0 — the bytes
/// the legacy `emit + run_rustfmt` path produces for that expression. Returns
/// `None` if `rustfmt` is unavailable or rejects the wrapper.
fn legacy_rustfmt_body(body_expr: &str) -> Option<String> {
    // Spawns `rustfmt` via `posix_spawn`, an unsupported foreign call under miri:
    // any test reaching this fn must carry `#[cfg_attr(miri, ignore)]`.
    use std::io::Write;
    use std::process::{Command, Stdio};

    let source = format!("fn __sweep() -> Wrap {{\n    {body_expr}\n}}\n");
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2024", "--style-edition", "2024"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(source.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let formatted = String::from_utf8(out.stdout).ok()?;
    let mut lines: Vec<&str> = formatted.lines().collect();
    if lines.len() < 2 {
        return None;
    }
    lines.remove(0);
    lines.pop();
    let body = lines
        .iter()
        .map(|l| l.strip_prefix("    ").unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n");
    Some(body)
}

/// Build the `Doc::Chain` for a chain-eligible binop. Walks the left-nested
/// same-operator run (rustfmt groups a left-associative operator run as one
/// chain) into a flat operand list, carrying every wrapping paren.
///
/// The string emitter emits `({l} {op} {r})` recursively, so a run
/// `((a + b) + c)` has the IR shape `Add(Add(a, b), c)` and the string form
/// `((a + b) + c)`. Flattening peels the left spine: the innermost left operand
/// is prefixed by one `(` per spine level, and each right operand is suffixed by
/// one `)`. Operand docs are built recursively, so a higher-precedence sub-expr
/// (or a different operator) stays one atomic operand — its own parens ride
/// along inside its doc.
fn build_binop_chain(
    ctx: &EmitCtx,
    op: BinOp,
    lhs: &Expr,
    rhs: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    // `build_binop_chain` is only reached from the arm that already proved
    // `infix(op).is_some()`; `None` here means that guard and this callee
    // disagree, a real bug, not a routing accident — fail closed with a typed
    // diagnostic rather than a panic or an empty-string sentinel.
    let Some(sym) = infix(op) else {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_doc::build_binop_chain",
            detail: format!("{op:?} reached build_binop_chain but `infix` returned None"),
        });
    };
    let opstr = sym.spelling();

    // Walk down the left spine while it is the SAME operator, collecting the
    // right operands. `spine` ends up outermost..innermost; reverse to source
    // order. `left` is the innermost left operand.
    let mut left = lhs;
    let mut spine: Vec<&Expr> = vec![rhs];
    while let Expr::BinOp {
        op: inner_op,
        lhs: inner_lhs,
        rhs: inner_rhs,
    } = left
    {
        if *inner_op != op {
            break;
        }
        spine.push(inner_rhs);
        left = inner_lhs;
    }
    spine.reverse();

    let depth_count = spine.len(); // one wrapping `(` per chain level

    // The chain flattening collapses a same-operator left spine the string
    // emitter would have recursed through one frame per level. Enforce the shared
    // nesting bound against that collapsed length so a deep chain fails fast with
    // the same `Lower` diagnostic ([`emit_expr_at`]'s IPE-L0200) instead of
    // building a pathologically large `Doc::Chain`.
    if depth.saturating_add(u16::try_from(depth_count).unwrap_or(u16::MAX)) > MAX_IR_RENDER_DEPTH {
        return Err(Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::BackendNestingTooDeep {
                limit: MAX_IR_RENDER_DEPTH,
            },
        });
    }

    let mut operands: Vec<ChainOperand> = Vec::with_capacity(depth_count + 1);

    // First operand: `(` * depth_count, then the innermost left operand's doc.
    let mut first = Vec::with_capacity(depth_count + 1);
    for _ in 0..depth_count {
        first.push(Doc::text("("));
    }
    first.push(build_doc(ctx, left, indent, depth, generics)?);
    operands.push(ChainOperand {
        leading_op: None,
        doc: Doc::concat(first),
    });

    // Each subsequent operand: its own doc followed by ONE `)`.
    for rhs_expr in spine {
        let rhs_doc = build_doc(ctx, rhs_expr, indent, depth, generics)?;
        operands.push(ChainOperand {
            leading_op: Some(Cow::Borrowed(opstr)),
            doc: Doc::concat(vec![rhs_doc, Doc::text(")")]),
        });
    }

    Ok(Doc::Chain { operands })
}

/// Build the `Doc` for a call-shaped binop, mirroring
/// [`crate::emit_expr::emit_expr_at`]'s `BinOp::Append` / `BinOp::IntDiv` arms
/// token-for-token.
///
///   * `Append` (`++`) lowers to `format!("{}{}", l, r)` — a MACRO call. Its
///     first argument is the fixed `"{}{}"` format-string leaf, then the two
///     operand docs. `rustfmt` breaks a wide macro argument list one argument per
///     line with NO trailing comma, so this uses [`delimited_no_trailing_comma`].
///   * `IntDiv` (`//`) lowers to `ipe_runtime::math::ipe_int_div(l, r)` — a plain
///     function call whose two operand docs break with the trailing comma
///     `rustfmt` keeps ([`delimited`]).
///
/// The operands are built recursively so a structured operand rides inside the
/// argument list. The caller has already matched `op` to one of these two.
fn build_call_binop(
    ctx: &EmitCtx,
    op: BinOp,
    lhs: &Expr,
    rhs: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let l = build_doc(ctx, lhs, indent, child, generics)?;
    let r = build_doc(ctx, rhs, indent, child, generics)?;
    match op {
        BinOp::Append => Ok(delimited_no_trailing_comma(
            Doc::text("format!("),
            // The format string is a fixed leaf; the two operands follow it as the
            // macro's positional arguments, exactly as the string emitter writes
            // `format!("{{}}{{}}", {l}, {r})`.
            vec![Doc::text("\"{}{}\""), l, r],
            Doc::text(")"),
        )),
        BinOp::IntDiv => Ok(delimited(
            Doc::text("ipe_runtime::math::ipe_int_div("),
            vec![l, r],
            Doc::text(")"),
        )),
        BinOp::IntAdd => Ok(delimited(
            Doc::text("ipe_runtime::math::ipe_int_add("),
            vec![l, r],
            Doc::text(")"),
        )),
        BinOp::IntSub => Ok(delimited(
            Doc::text("ipe_runtime::math::ipe_int_sub("),
            vec![l, r],
            Doc::text(")"),
        )),
        BinOp::IntMul => Ok(delimited(
            Doc::text("ipe_runtime::math::ipe_int_mul("),
            vec![l, r],
            Doc::text(")"),
        )),
        // Polymorphic `Number a` `+`/`-`/`*`: method-call form `l.ipe_wrapping_*(r)`.
        // The receiver `l` is the doc for the left operand; the trailing
        // `.ipe_wrapping_*(r)` is a method applied to it. Built as a
        // [`Doc::MethodChain`] so it inherits `rustfmt`'s method-chain layout: the
        // method drops onto its own line at the receiver's begin-line indent when the
        // receiver renders multiline (`(if …\n})\n.ipe_wrapping_add(x)`), and a nested
        // arithmetic run breaks one `.ipe_wrapping_*()` per line when the flat chain
        // overflows the width — the shapes a flat concat could never reach. This
        // mirrors the string emitter's `format!("{l}.ipe_wrapping_add({r})")` bytes.
        BinOp::Add => Ok(Doc::method_chain(
            l,
            Doc::concat(vec![Doc::text(".ipe_wrapping_add("), r, Doc::text(")")]),
        )),
        BinOp::Sub => Ok(Doc::method_chain(
            l,
            Doc::concat(vec![Doc::text(".ipe_wrapping_sub("), r, Doc::text(")")]),
        )),
        BinOp::Mul => Ok(Doc::method_chain(
            l,
            Doc::concat(vec![Doc::text(".ipe_wrapping_mul("), r, Doc::text(")")]),
        )),
        // The caller's guard restricts `op` to the call-shaped binops; any
        // other operator is a chain operator built elsewhere. Fail closed rather
        // than emit a wrong shape.
        _ => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::build_call_binop",
            detail: format!(
                "build_call_binop called with non-call-shaped operator {op:?}; \
                 only Append and IntDiv route here"
            ),
        }),
    }
}

/// Build the `let __ipe_fn: <typed> = ` assignment-prefix document. When `typed`
/// is a pointer-wrapped trait object `Ptr<Head + T1 + …>` (`Box<…>` /
/// `::std::sync::Arc<…>`), the angle-bracketed bound is carried as a breakable
/// [`Doc::TypeBound`] so `rustfmt`'s deep-indent type break (`Ptr<\n  Head + …,\n>`)
/// is reproduced; any other annotation stays a single leaf. The top-level `+`
/// splits at outer-angle-bracket depth only, so a nested `Box<… + …>` inside the
/// head keeps its own bounds.
fn typed_let_prefix(typed: &str) -> Doc {
    if let Some(bound) = parse_type_bound(typed) {
        return Doc::concat(vec![Doc::text("let __ipe_fn: "), bound, Doc::text(" = ")]);
    }
    Doc::owned(format!("let __ipe_fn: {typed} = "))
}

/// Parse a pointer-wrapped trait object `Ptr<Head + T1 + …>` into a breakable
/// [`Doc::TypeBound`], or `None` when `typed` is not of that shape (no outer `<…>`,
/// or the bound has no `+`-separated markers — nothing to break). `Ptr` is the text
/// up to and including the first `<`; the inner is split into the head and the
/// marker traits on ` + ` at the outer bracket's depth, so a nested generic's own
/// `+` bounds are not split.
fn parse_type_bound(typed: &str) -> Option<Doc> {
    let open = typed.find('<')?;
    let ptr = typed.get(..=open)?;
    // `Ptr<…>` requires the matching `>`; the inner is the span between them.
    let inner = typed.strip_suffix('>')?.get(open + 1..)?;

    // Split `inner` on a top-level ` + ` — a `+` flanked by spaces at angle/paren/
    // bracket depth 0 — so a nested generic's own `+` bounds are not split. A `>`
    // that follows `-` is the `->` return arrow, NOT a bracket close. Each `Doc::Text`
    // segment is trimmed of its flanking spaces.
    let bytes = inner.as_bytes();
    let mut segments: Vec<&str> = Vec::new();
    let mut depth: i32 = 0;
    let mut seg_start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        let prev = i.checked_sub(1).and_then(|j| bytes.get(j)).copied();
        let next = bytes.get(i + 1).copied();
        match b {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' if prev == Some(b'-') => {}
            b')' | b']' | b'>' => depth -= 1,
            b'+' if depth == 0 && prev == Some(b' ') && next == Some(b' ') => {
                if let Some(seg) = inner.get(seg_start..i.saturating_sub(1)) {
                    segments.push(seg.trim());
                }
                seg_start = i + 2;
            }
            _ => {}
        }
    }
    if let Some(seg) = inner.get(seg_start..) {
        segments.push(seg.trim());
    }

    // A breakable bound needs a head plus at least one `+ Trait` marker.
    let (head, markers) = segments.split_first()?;
    if markers.is_empty() {
        return None;
    }
    let traits = markers
        .iter()
        .map(|s| Doc::owned((*s).to_owned()))
        .collect();
    Some(Doc::type_bound(
        Doc::owned(ptr.to_owned()),
        Doc::owned((*head).to_owned()),
        traits,
        Doc::text(">"),
    ))
}

/// Build the `Doc` for a named-function value, mirroring
/// [`crate::emit_expr::emit_func_value`] token-for-token. The string emitter
/// renders the statement block
/// `{ let __ipe_fn: <TypedFn> = <ctor>::new(<name>); __ipe_fn }` — a block that
/// ALWAYS breaks (it holds the `let`): the assignment and the `__ipe_fn` tail each
/// on their own `HardLine` inside the block's sole `Nest(4)`.
///
/// The assignment is a [`Doc::Assign`]: the wide `Box<dyn Fn(…) -> R + Send +
/// 'static>` (or `Arc<…>`) annotation on the `let __ipe_fn: <TypedFn> = ` prefix
/// pushes the `<ctor>::new(<name>)` RHS onto its own line at `indent + 4` when the
/// same-line form overflows, matching `rustfmt`. The `name` is a bare identifier
/// leaf (it never breaks internally), so the RHS is a plain concatenation — no
/// group around the `(` — exactly like [`build_lambda`]'s RHS but without a
/// closure body. The pointer constructor (`Box::new` / `Arc::new`) is chosen by
/// the same `wants_arc_ctor` structural predicate the string emitter uses.
fn build_func_value(
    ctx: &EmitCtx,
    callee: &Callee,
    ty: &IrType,
    generics: GenericScope,
) -> DResult<Doc> {
    let name = callee_name(ctx, callee)?;
    let typed = render_type(ctx, ty, generics)?;
    let ctor = if wants_arc_ctor(ty) { "Arc" } else { "Box" };
    let rhs = Doc::owned(format!("{ctor}::new({name})"));
    let assign = Doc::assign(
        typed_let_prefix(&typed),
        rhs,
        // The statement's trailing `;`.
        1,
    );
    Ok(Doc::concat(vec![
        Doc::text("{"),
        Doc::nest(
            4,
            Doc::concat(vec![
                Doc::HardLine,
                assign,
                Doc::text(";"),
                Doc::HardLine,
                Doc::text("__ipe_fn"),
            ]),
        ),
        Doc::HardLine,
        Doc::text("}"),
    ]))
}

/// Build the shape-faithful [`Doc::IfElse`] for a parenthesized `if`/`else`. This
/// builder carries only IR shape — the three branch documents, built recursively
/// so a nested chain / `if` inside a branch structures too. The single-line-vs-
/// block-form layout decision (`rustfmt`'s `single_line_if_else_max_width`) belongs
/// to the renderer, which measures the flat construct width and lays the branch
/// bodies out inline or in broken block form.
fn build_if(
    ctx: &EmitCtx,
    cond: &Expr,
    then_: &Expr,
    else_: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    // The branch bodies' visual indentation comes entirely from the renderer's
    // `Nest(4)` wrappers; the builder `indent` is threaded unchanged so a
    // single-line branch leaf carries no embedded indentation that would
    // double-count against the `Nest`.
    let cond_doc = build_doc(ctx, cond, indent, depth, generics)?;
    let then_doc = build_doc(ctx, then_, indent, depth, generics)?;
    let else_doc = build_doc(ctx, else_, indent, depth, generics)?;
    Ok(Doc::if_else(cond_doc, then_doc, else_doc))
}

/// Build a `rustfmt`-canonical delimited list: `{open}{a0}, {a1}, …{close}` when
/// it fits the width, or the broken form with one element per line at one indent
/// step, a break-conditional trailing comma, and the closing delimiter dedented
/// back to the group's start column:
///
/// ```text
/// {open}
///     {a0},
///     {a1},
/// {close}
/// ```
///
/// `open` already includes the opening delimiter (`f(`, `(`, `vec![`); `close` is
/// the matching closer (`)`, `]`). The inter-element separator is a real `,`
/// (which the string emitter emits via `join(", ")`) followed by a soft `Line`
/// (a space when flat, a newline+indent when broken). The TRAILING comma is a
/// [`Doc::IfBroken`] — invisible to the SEAL (the string emitter never emits it)
/// and rendered only in the broken arm, matching `rustfmt`.
///
/// An empty element list is not delimited here (callers handle the zero-arg form
/// as a plain leaf, matching the string emitter's `name()` / `()` output).
///
/// The inner boundary (the break candidate right after `open` and right before
/// `close`) is a zero-width [`Doc::Softline`]: a bracketed list is `(a, b)` /
/// `[a, b]` / `f(a, b)` FLAT — no space hugging the delimiter. For a brace-
/// delimited struct literal, whose flat form hugs the braces WITH a space
/// (`Name { a: 1 }`) and obeys `struct_lit_width`, use [`Doc::struct_lit`].
fn delimited(open: Doc, elems: Vec<Doc>, close: Doc) -> Doc {
    Doc::call_args(open, elems, close, true)
}

/// Like [`delimited`], but the broken one-per-line form carries NO trailing comma.
/// This is the `format!`/`vec!`-style MACRO argument shape: `rustfmt` breaks a wide
/// macro call one argument per line but — unlike a function call — never appends
/// the trailing comma. Used for the `++` append lowering `format!("{}{}", l, r)`.
fn delimited_no_trailing_comma(open: Doc, elems: Vec<Doc>, close: Doc) -> Doc {
    Doc::call_args(open, elems, close, false)
}

/// Build the arg docs for a positional argument list, each at the child depth the
/// string emitter uses. Mirrors the `for arg in args { emit_expr_at(child) }`
/// loops in the string emitter's call / ctor / tuple / list arms.
fn build_args(
    ctx: &EmitCtx,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Vec<Doc>> {
    let mut docs = Vec::with_capacity(args.len());
    for arg in args {
        docs.push(build_doc(ctx, arg, indent, child, generics)?);
    }
    Ok(docs)
}

/// Build the `Doc` for a `Tuple`. The string emitter renders `({parts.join(", ")})`
/// with each part at the child depth; this builder carries the identical tokens in
/// a delimited group so a wide tuple breaks one element per line with a trailing
/// comma, matching `rustfmt`.
fn build_tuple(
    ctx: &EmitCtx,
    elems: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let docs = build_args(ctx, elems, indent, child, generics)?;
    Ok(delimited(Doc::text("("), docs, Doc::text(")")))
}

/// Build the `Doc` for a plain non-empty list literal `vec![e0, e1, …]`. Only the
/// plain path is structured here; the empty-list forms (`Vec::<T>::new()` /
/// `Vec::new()`) and the `Ui`-annotated `{ let __ipe_m: … = vec![…]; __ipe_m }`
/// wrapper carry no positional delimited layout, so those cases stay leaves (the
/// caller checks and delegates). Elements are built at the child depth.
fn build_list(
    ctx: &EmitCtx,
    items: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let docs = build_args(ctx, items, indent, child, generics)?;
    Ok(delimited(Doc::text("vec!["), docs, Doc::text("]")))
}

/// Build the `Doc` for `head :: tail`. The string emitter renders the runtime
/// call `ipe_runtime::list::ipe_list_cons({h}, {t})`; this builder carries the
/// identical tokens in a two-element delimited group so a wide cons breaks its two
/// arguments one per line with a trailing comma, matching `rustfmt`.
fn build_cons(
    ctx: &EmitCtx,
    head: &Expr,
    tail: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let head_doc = build_doc(ctx, head, indent, child, generics)?;
    let tail_doc = build_doc(ctx, tail, indent, child, generics)?;
    Ok(delimited(
        Doc::text("ipe_runtime::list::ipe_list_cons("),
        vec![head_doc, tail_doc],
        Doc::text(")"),
    ))
}

/// Build the `Doc` for the generic call tail `{name}{turbofish}({args})`,
/// mirroring the fall-through of [`crate::emit_expr::emit_expr_at`]'s `Expr::Call`
/// arm token-for-token. The caller has already proved no kernel special case
/// applies (via [`crate::emit_expr::call_has_kernel_special_case`]) and that the
/// argument list is non-empty, so the emitted form is exactly the callee name,
/// then the pin's turbofish (with the `Ipe.Csv` parse `::<IpeError>` override the
/// string emitter applies), then a delimited argument list — with the two
/// arguments pre-swapped for the container-first `Maybe`/`Result`/… kernels that
/// [`ipe_ir::Callee::evaluates_args_reversed`] flags, exactly as the string
/// emitter reverses `parts` before joining.
fn build_generic_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    pin: ipe_ir::CallPin,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let name = callee_name(ctx, callee)?;
    // The pin's turbofish, with the error-channel anchor the string emitter
    // substitutes when the pin is empty (`csv_parse::<IpeError>(…)`). Every
    // kernel here returns `IpeResult<E, _>` generic over the error channel, so a
    // call whose result flows into a polymorphic context needs `E` pinned.
    let pin_turbofish = pin.turbofish();
    let turbofish: &str = if pin_turbofish.is_empty()
        && matches!(
            callee,
            Callee::Kernel(
                KernelFn::CsvParse | KernelFn::CsvParseWithDelimiter | KernelFn::UrlRelativeParse
            )
        ) {
        "::<IpeError>"
    } else {
        pin_turbofish
    };
    // A container-first kernel renders its container before the function
    // closure; clone the function's captures at their container use sites so the
    // closure's capture never reads a moved value (the string emitter's rewrite).
    let mut docs = match swapped_container_clone_rewrite(callee, args, &ctx.enum_variants) {
        Some(container_rw) => {
            let [func, _] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::build_generic_call",
                    detail: "container clone rewrite lost its two args".to_owned(),
                });
            };
            build_call_args_task_and_then(
                ctx,
                callee,
                &[func.clone(), container_rw],
                indent,
                child,
                generics,
            )?
        }
        None => build_call_args_task_and_then(ctx, callee, args, indent, child, generics)?,
    };
    // Container-first kernels take their two arguments in the opposite order to
    // the Ipê call; the string emitter reverses the rendered `parts`, so the Doc
    // builder reverses the built arg docs to carry the identical token sequence.
    if callee.evaluates_args_reversed() {
        docs.reverse();
    }
    Ok(delimited(
        Doc::owned(format!("{name}{turbofish}(")),
        docs,
        Doc::text(")"),
    ))
}

/// Build a positional argument list for a `Task.andThen` call, handling the
/// continuation lambda (Ipê arg index 0) specially: instead of the full
/// `{ let __ipe_fn: Box<dyn Fn...> = Box::new(...); __ipe_fn }` block that
/// [`build_lambda`] produces, emit `Box::new(move |x: T| -> R { body })` directly.
/// The preamble wrapper takes `Box<dyn FnOnce(A) -> IpeTask<B> + Send + 'static>`,
/// so the `Box::new` is still required; dropping the `let __ipe_fn` type-annotation
/// is sufficient because rustc infers the coercion from the parameter position.
/// Removing the explicit annotation is what keeps rustc type-checking linear in the
/// number of chained `Task.andThen` calls (the annotation form causes super-linear
/// work at depth). All other args fall through to [`build_call_args_with_impl_fn`].
fn build_call_args_task_and_then(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Vec<Doc>> {
    if matches!(callee, Callee::Kernel(KernelFn::TaskAndThen))
        && let [cont, effect] = args
        && let Some((params, ret, body)) = and_then_cont(cont)
    {
        let closure = build_closure(ctx, params, ret, body, indent, child, generics)?;
        let cont_doc = Doc::concat(vec![Doc::text("Box::new("), closure, Doc::text(")")]);
        let effect_doc = build_doc(ctx, effect, indent, child, generics)?;
        return Ok(vec![cont_doc, effect_doc]);
    }
    build_call_args_with_impl_fn(ctx, callee, args, indent, child, generics)
}

/// The parts of `Task.andThen`'s continuation when it is built unboxed: a
/// closure literal, or a once closure the shared once verdict admits there.
fn and_then_cont(cont: &Expr) -> Option<ClosureParts<'_>> {
    if let Expr::Lambda { params, ret, body } | Expr::SharedLambda { params, ret, body } = cont {
        Some((params.as_slice(), ret, body.as_ref()))
    } else {
        admitted_once_parts(
            cont,
            &ClosureSite::KernelArg {
                kernel: &KernelFn::TaskAndThen,
                index: 0,
            },
        )
    }
}

/// Build a positional argument list, passing a lambda-literal argument UNBOXED
/// into any parameter the callee monomorphized to an `impl Fn` generic
/// (`EmitCtx::call_arg_is_impl_fn`), so the boxed `{ let __ipe_fn = Box::new(..) }`
/// wrapper is skipped and rustc inlines the closure. Every other argument — and
/// every non-`Callee::Func` call — routes through the ordinary [`build_args`] path
/// unchanged: a non-lambda value already implements `Fn`, so it fills the generic
/// slot with no rewrite. Mirrors the same gate in
/// [`crate::emit_expr::emit_expr_at`]'s `Expr::Call` arm so the native and string
/// emitters stay byte-identical.
fn build_call_args_with_impl_fn(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Vec<Doc>> {
    let Callee::Func(id) = callee else {
        return build_args(ctx, args, indent, child, generics);
    };
    let mut docs = Vec::with_capacity(args.len());
    for (i, arg) in args.iter().enumerate() {
        let doc = if ctx.call_arg_is_impl_fn(*id, i)
            && let Expr::Lambda { params, ret, body } | Expr::SharedLambda { params, ret, body } =
                arg
        {
            build_closure(ctx, params, ret, body, indent, child, generics)?
        } else {
            build_doc(ctx, arg, indent, child, generics)?
        };
        docs.push(doc);
    }
    Ok(docs)
}

/// Build the `Doc` for a saturated payload constructor. Mirrors
/// [`crate::emit_expr::emit_ctor`] token-for-token: the runtime-enum branch
/// (`IpeMaybe::Just(..)`, `IpeResult::Err(..)`, …) and the user-enum branch
/// (`EnumName::Variant(..)`) both build the prefix path, then lay the payload out
/// as a delimited group. Each user-enum argument on a type-size cycle back to its
/// own enum is wrapped in `Box::new(..)` — the exact wrap the string emitter
/// applies (runtime-enum payloads are never self-recursive, so that branch never
/// boxes). The nullary forms never reach here (the caller keeps them leaves).
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors emit_ctor's (home, ty) split"
)]
fn build_ctor(
    ctx: &EmitCtx,
    home: &ModPath,
    ty: Symbol,
    variant: Symbol,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    // A built-in `Maybe` / `Result` / `Order` / `ChunkEvent` constructor routes to
    // the runtime enum; its payload is never a self-recursive user field, so no
    // field-boxing lookup applies (matching the string emitter).
    if let Some(runtime) = ctx.builtin_runtime_enum(home, ty) {
        let path = format!("{runtime}::{}", ctx.emit_ident(variant)?);
        let docs = build_args(ctx, args, indent, child, generics)?;
        return Ok(delimited(
            Doc::owned(format!("{path}(")),
            docs,
            Doc::text(")"),
        ));
    }

    let path = format!("{}::{}", ctx.enum_name(home, ty)?, ctx.emit_ident(variant)?);
    let fields = ctx.variant_fields(home, ty, variant)?;
    if fields.len() != args.len() {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::build_ctor",
            detail: format!(
                "constructor {} of enum {} applied to {} args but declares {} fields; \
                 a constructor application must be saturated",
                variant.as_raw(),
                ty.as_raw(),
                args.len(),
                fields.len()
            ),
        });
    }
    let mut docs = Vec::with_capacity(args.len());
    for (arg, field_ty) in args.iter().zip(fields.iter()) {
        let arg_doc = build_doc(ctx, arg, indent, child, generics)?;
        // A cyclic self-edge field is boxed in the enum, so its construction
        // argument is boxed too: `Box::new(<arg>)`. Carried as a single-argument
        // call so `rustfmt`'s combining rule / `fn_call_width` applies to the wrap
        // (`Box::new(<arg>)` breaks in place when `<arg>` overflows the budget).
        if ctx.is_cyclic_self_field(field_ty, home, ty) {
            docs.push(delimited(
                Doc::text("Box::new("),
                vec![arg_doc],
                Doc::text(")"),
            ));
        } else {
            docs.push(arg_doc);
        }
    }
    Ok(delimited(
        Doc::owned(format!("{path}(")),
        docs,
        Doc::text(")"),
    ))
}

/// Build the `Doc` for a `let` expression, mirroring
/// [`crate::emit_expr::emit_expr_at`]'s `Expr::Let` arm token-for-token.
///
/// Two shapes, chosen by the identical `needs_inline` predicate the string
/// emitter uses (multi-use of a non-`Clone` value, no `CloneVar` capture site):
///
///   * inline-substitution path — a ZERO-statement block `({ inlined_body })`.
///     Laid out as a soft group (`Line`s) so it flattens when it fits and breaks
///     the body onto its own line otherwise, matching rustfmt's zero-statement
///     block.
///   * normal path — a ONE-statement block `({ let name = value; body })`. rustfmt
///     never inlines a block that holds a statement, so this ALWAYS breaks: `({`,
///     the `let` statement and the body each on their own line at one indent step
///     (the renderer's sole `Nest(4)`), then `})` dedented back. `HardLine`s force
///     the break unconditionally.
///
/// `value` and `body` are built recursively; their leaves carry the string
/// emitter's single-line bytes, so no leaf embeds a newline+indent that would
/// double-count against the block's `Nest(4)` (the sole indent source).
fn build_let(
    ctx: &EmitCtx,
    name: Symbol,
    value: &Expr,
    body: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    if let Some(inlined_body) = inlined_let_body(name, value, body, &ctx.enum_variants) {
        // Zero-statement block `({ inlined_body })`: the body with `name`
        // substituted by `value`, laid out as a soft group.
        let body_doc = build_doc(ctx, &inlined_body, indent, child, generics)?;
        return Ok(Doc::group(Doc::concat(vec![
            Doc::text("({"),
            Doc::nest(4, Doc::concat(vec![Doc::Line, body_doc])),
            Doc::Line,
            Doc::text("})"),
        ])));
    }
    let name_s = ctx.emit_ident(name)?;
    let value_doc = build_doc(ctx, value, indent, child, generics)?;
    let body_doc = build_doc(ctx, body, indent, child, generics)?;
    // One-statement block: `let name = value;` then `body`, each on its own line.
    Ok(Doc::concat(vec![
        Doc::text("({"),
        Doc::nest(
            4,
            Doc::concat(vec![
                Doc::HardLine,
                Doc::owned(format!("let {name_s} = ")),
                value_doc,
                Doc::text(";"),
                Doc::HardLine,
                body_doc,
            ]),
        ),
        Doc::HardLine,
        Doc::text("})"),
    ]))
}

/// Build the `Doc` for a `Destructure` block, mirroring
/// [`crate::emit_expr::emit_expr_at`]'s `Expr::Destructure` arm token-for-token.
///
/// The string emitter renders `({ <binding stmts> <body> })` where the binding
/// statements come from [`crate::emit_expr::emit_binding_stmts`]: a SINGLE flat
/// `let <pat> = <value>;` for an alias-free binder, or the clone-split
/// `let name = <value>; let (a, b) = name.clone();` sequence for an aliased one —
/// one or MORE `let` statements. Each statement is carried as its own leaf on its
/// own `HardLine`, and the body (built recursively) follows on a further
/// `HardLine`, all inside the block's sole `Nest(4)`. Like the one-statement
/// `let` block, this always breaks — `rustfmt` never inlines a block that holds a
/// statement.
///
/// The value is rendered through the same `emit_expr_at` call the string emitter
/// uses (`emit_binding_stmts` interpolates the value string into each statement),
/// so the statement leaves carry the string emitter's exact tokens and the SEAL
/// holds by construction. The body is the only structured child.
fn build_destructure(
    ctx: &EmitCtx,
    binder: &ipe_ir::Pat,
    value: &Expr,
    body: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let value_s = emit_expr_at(ctx, value, indent, child, generics)?;
    let stmts = emit_binding_stmts(ctx, binder, &value_s)?;
    let body_doc = build_doc(ctx, body, indent, child, generics)?;
    // Each binding statement on its own `HardLine`, then the body on a further
    // `HardLine`, all at one indent step (the renderer's sole `Nest(4)`).
    let mut inner = Vec::with_capacity(stmts.len() * 2 + 2);
    for stmt in stmts {
        inner.push(Doc::HardLine);
        inner.push(Doc::owned(stmt));
    }
    inner.push(Doc::HardLine);
    inner.push(body_doc);
    Ok(Doc::concat(vec![
        Doc::text("({"),
        Doc::nest(4, Doc::concat(inner)),
        Doc::HardLine,
        Doc::text("})"),
    ]))
}

/// Build the `Doc` for a non-empty record literal, mirroring
/// [`crate::emit_expr::emit_record`] token-for-token. The struct name comes from
/// the shared [`crate::emit_expr::record_struct_name`] resolver; each field
/// renders `{field_ident}: {value}` with the value built recursively, laid out as
/// a delimited group so a wide record breaks one field per line with a trailing
/// comma (rustfmt's struct-literal layout). A `ServerResponse`-shaped literal
/// gains the trailing `cookies: Vec::new()` field the string emitter appends, so
/// the two produce the identical field sequence.
fn build_record(
    ctx: &EmitCtx,
    fields: &[(Symbol, Expr)],
    ty: Option<&IrType>,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let (struct_name, is_server_response) = record_struct_name(ctx, fields, ty)?;
    let mut field_docs = Vec::with_capacity(fields.len() + usize::from(is_server_response));
    for (sym, value) in fields {
        let field_ident = ctx.emit_ident(*sym)?;
        let value_doc = build_doc(ctx, value, indent, child, generics)?;
        field_docs.push(Doc::concat(vec![
            Doc::owned(format!("{field_ident}: ")),
            value_doc,
        ]));
    }
    if is_server_response {
        // The runtime struct's multi-`Set-Cookie` field is not part of the Ipê
        // record alias; the string emitter defaults it, so carry the same leaf.
        field_docs.push(Doc::text("cookies: Vec::new()"));
    }
    Ok(Doc::struct_lit(
        Doc::owned(format!("{struct_name} {{")),
        field_docs,
        Doc::text("}"),
    ))
}

/// Build the `Doc` for a functional record update, mirroring
/// Mirrors [`crate::emit_expr::emit_update`] token-for-token for both code paths
/// (concrete struct and G2 row-generic setter chain).
///
/// **Concrete-struct path** (record type is a known struct):
/// `{ let __ipe_upd_0 = v0; … let mut __ipe_rec = <record>; __ipe_rec.f =
/// __ipe_upd_0; … __ipe_rec }` — each field value is bound to a positional
/// temporary BEFORE the base is moved, so a field value may read the base
/// (`{ r | count = r.count + 1 }`) on a non-`Clone` record. Since it holds
/// statements, it ALWAYS breaks: each field bind, the `let mut` binding, each
/// field assignment, and the `__ipe_rec` tail land on their own `HardLine`
/// inside the block's sole `Nest(4)`, matching rustfmt.
///
/// **G2 row-generic setter-chain path** (record is a row-binder `R{n}`):
/// `{ let __ipe_upd_0 = v0; … <record>.ipe_with_f0(__ipe_upd_0).… }` — each
/// setter call consumes and returns `Self`, so the chain preserves all
/// untouched fields without naming the concrete struct. The chain itself is a
/// single expression, so only the field-value binds and one expression line
/// fill the block.
///
/// The base record and each field value are built recursively; their leaves
/// carry the string emitter's exact tokens, so the SEAL holds.
fn build_update(
    ctx: &EmitCtx,
    record: &Expr,
    fields: &[(Symbol, Expr)],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    // G2: when the record is a row-generic parameter, use setter witnesses.
    let record_sym = match record {
        Expr::Var(s) | Expr::CloneVar(s) => Some(*s),
        _ => None,
    };
    if let Some(sym) = record_sym
        && generics.is_row(sym)
    {
        // Bind each field value before building the chain, so evaluation
        // order matches the concrete-struct path and a field expression
        // that reads the base can observe its pre-update value.
        let mut inner = Vec::new();
        for (i, (_sym, value)) in fields.iter().enumerate() {
            let value_doc = build_doc(ctx, value, indent, child, generics)?;
            inner.push(Doc::HardLine);
            inner.push(Doc::owned(format!("let __ipe_upd_{i} = ")));
            inner.push(value_doc);
            inner.push(Doc::text(";"));
        }
        // Build the setter chain as a single expression leaf.
        let base_doc = build_doc(ctx, record, indent, child, generics)?;
        let mut chain: Doc = base_doc;
        for (i, (field_sym, _value)) in fields.iter().enumerate() {
            let field_name = ctx.resolve_ident(*field_sym)?;
            let setter = crate::naming::field_setter_witness_method_name(field_name);
            chain = Doc::concat(vec![chain, Doc::owned(format!(".{setter}(__ipe_upd_{i})"))]);
        }
        inner.push(Doc::HardLine);
        inner.push(chain);
        return Ok(Doc::concat(vec![
            Doc::text("{"),
            Doc::nest(4, Doc::concat(inner)),
            Doc::HardLine,
            Doc::text("}"),
        ]));
    }

    // Concrete-struct path.
    let mut inner = Vec::new();
    for (i, (_sym, value)) in fields.iter().enumerate() {
        let value_doc = build_doc(ctx, value, indent, child, generics)?;
        inner.push(Doc::HardLine);
        inner.push(Doc::owned(format!("let __ipe_upd_{i} = ")));
        inner.push(value_doc);
        inner.push(Doc::text(";"));
    }
    let base_doc = build_doc(ctx, record, indent, child, generics)?;
    inner.push(Doc::HardLine);
    inner.push(Doc::text("let mut __ipe_rec = "));
    inner.push(base_doc);
    inner.push(Doc::text(";"));
    for (i, (sym, _value)) in fields.iter().enumerate() {
        let field_ident = ctx.emit_ident(*sym)?;
        inner.push(Doc::HardLine);
        inner.push(Doc::owned(format!(
            "__ipe_rec.{field_ident} = __ipe_upd_{i};"
        )));
    }
    inner.push(Doc::HardLine);
    inner.push(Doc::text("__ipe_rec"));
    Ok(Doc::concat(vec![
        Doc::text("{"),
        Doc::nest(4, Doc::concat(inner)),
        Doc::HardLine,
        Doc::text("}"),
    ]))
}

/// Build the `Doc` for the auto-force task-sequencing tail, mirroring
/// [`crate::emit_expr::emit_expr_at`]'s `Expr::TaskSeq` arm token-for-token.
///
/// The string emitter renders
/// `task_and_then(<effect>, Box::new(move |_| {{ <rest> }}))` — the runtime awaits
/// the effect, then runs the continuation closure. The outer
/// `task_and_then(effect, cont)` is a two-argument delimited group, so a wide call
/// breaks one argument per line with a trailing comma. The continuation's `<rest>`
/// body is wrapped in a [`Doc::BraceBody`]: `rustfmt` strips its braces when the
/// closure body fits (`move |_| rest`) and braces+breaks it when it does not
/// (`move |_| {{ <break> rest <break> }}`).
///
/// The continuation's capture plan is already in the lowered `rest`, planned
/// for the `Once` boundary `ipe_ir::once_closure::boundary_kind` names. Before
/// emitting, the effect gets the identical IR-level clone-capture rewrite the
/// string emitter applies (`clone_targets_in_expr` over `rest`'s `free_vars`),
/// the effect/rest sharing rule:
/// any identifier `rest` reads next but `effect`'s own left-to-right evaluation
/// would move is rewritten to a `CloneVar`. Both effect and rest are built
/// recursively; their leaves carry the string emitter's exact tokens, so the SEAL
/// holds.
fn build_task_seq(
    ctx: &EmitCtx,
    effect: &Expr,
    rest: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let rest_captures = free_vars(rest);
    let effect_rw = clone_targets_in_expr(effect.clone(), &rest_captures, &ctx.enum_variants);
    let effect_doc = build_doc(ctx, &effect_rw, indent, child, generics)?;
    let rest_doc = build_doc(ctx, rest, indent, child, generics)?;
    // The continuation `Box::new(move |_| <brace-body>[rest])`: the closure body's
    // braces vanish when it fits flat and brace+break when it does not.
    let cont = Doc::concat(vec![
        Doc::text("Box::new(move |_| "),
        Doc::brace_body(rest_doc),
        Doc::text(")"),
    ]);
    Ok(delimited(
        Doc::text("task_and_then("),
        vec![effect_doc, cont],
        Doc::text(")"),
    ))
}

/// Build the `Doc` for a `Db.withTransaction` call, mirroring the
/// `KernelFn::DbWithTransaction` arm of [`crate::emit_expr::emit_db_call`]
/// token-for-token: `db_with_transaction({conn}.clone(), {body})`. The connection
/// argument is cloned (the pool handle stays usable for calls after the
/// transaction in the same continuation chain); the body is a boxed closure value
/// (`Box<dyn Fn(Db) -> Task e a>`). Both arguments are built recursively and laid
/// out as a two-argument delimited group, so `rustfmt` glues the `{` of the boxed-
/// closure block onto the call's first line and breaks the block in place when the
/// call is wide — the combining rule [`Doc::CallArgs`] already renders. Routing
/// this through the Doc algebra (rather than the flat string leaf `emit_db_call`
/// returns) is what lets the boxed closure's inner `let __ipe_fn = Box::new(…)`
/// and its continuation chain break per `rustfmt`.
fn build_db_with_transaction(
    ctx: &EmitCtx,
    conn: &Expr,
    body: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let conn_doc = build_doc(ctx, conn, indent, child, generics)?;
    // The string emitter appends `.clone()` to the emitted connection expression.
    let conn_clone = Doc::concat(vec![conn_doc, Doc::text(".clone()")]);
    let body_doc = build_doc(ctx, body, indent, child, generics)?;
    Ok(delimited(
        Doc::text("db_with_transaction("),
        vec![conn_clone, body_doc],
        Doc::text(")"),
    ))
}

/// Build the projected `List SqlValue` → `Vec<SqlParam>` params argument document,
/// mirroring `emit_db_call`'s `project_params` token-for-token. The bare empty-list
/// fast path (`Vec::new()`, whose element type Rust cannot infer) becomes the leaf
/// `Vec::<ipe_runtime::db::SqlParam>::new()`; every other params expression is
/// wrapped in a paren pair and followed by the `.into_iter().map(…).collect::<…>()`
/// projection chain. The gate is the params expression's OWN emitted form, exactly
/// as the string emitter's `if s == "Vec::new()"` gate keys off the emitted string.
fn build_db_params_arg(
    ctx: &EmitCtx,
    params: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let params_doc = build_doc(ctx, params, indent, child, generics)?;
    // The string emitter's empty-list fast path: a bare `Vec::new()` gets an explicit
    // element type and skips the projection chain entirely.
    let mut flat = String::new();
    params_doc.collect_leaves(&mut flat);
    if crate::doc::whitespace_normalize(&flat) == "Vec::new()" {
        return Ok(Doc::text("Vec::<ipe_runtime::db::SqlParam>::new()"));
    }
    Ok(build_db_project_params(params_doc))
}

/// The projected-params document `({params}).into_iter().map(::core::convert::Into::into)
/// .collect::<Vec<ipe_runtime::db::SqlParam>>()`, mirroring `emit_db_call`'s
/// `project_params` token-for-token. The params document is wrapped in a paren pair
/// and followed by the three-method projection chain; `rustfmt` breaks the chain one
/// method per line at the receiver's begin-line indent when the whole projection is
/// wide (each method's receiver — the parenthesized params and each preceding
/// `.method()` — renders multiline, so the next method drops to its own line).
fn build_db_project_params(params_doc: Doc) -> Doc {
    let base = Doc::concat(vec![Doc::text("("), params_doc, Doc::text(")")]);
    let iter = Doc::method_chain(base, Doc::text(".into_iter()"));
    let mapped = Doc::method_chain(iter, Doc::text(".map(::core::convert::Into::into)"));
    Doc::method_chain(
        mapped,
        Doc::text(".collect::<Vec<ipe_runtime::db::SqlParam>>()"),
    )
}

/// Build the `Doc` for a param-projecting Task-returning Db kernel call
/// (`DbExecRaw` / `DbExec` / `DbQuery`), mirroring the matching arm of
/// [`crate::emit_expr::emit_db_call`] token-for-token. Each connection argument is
/// cloned; `DbExec` / `DbQuery` project their `List SqlValue` params argument
/// through [`build_db_project_params`]. The whole call is a delimited group so a
/// wide call breaks one argument per line, matching `rustfmt` — the layout the
/// flat string leaf `emit_db_call` returns could never reach. The params argument's
/// projection (or its empty-list fast path) is built by [`build_db_params_arg`].
fn build_db_param_call(
    ctx: &EmitCtx,
    kernel: KernelFn,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let name = crate::naming::kernel_name(kernel);
    let mut docs: Vec<Doc> = Vec::with_capacity(args.len());
    match (kernel, args) {
        // `db_exec_raw(conn.clone(), sql)` — no params projection.
        (KernelFn::DbExecRaw, [conn, sql]) => {
            let conn_doc = build_doc(ctx, conn, indent, child, generics)?;
            docs.push(Doc::concat(vec![conn_doc, Doc::text(".clone()")]));
            docs.push(build_doc(ctx, sql, indent, child, generics)?);
        }
        // `db_exec_params` / `db_query_params`: `(conn.clone(), sql, <projected params>)`.
        (KernelFn::DbExec | KernelFn::DbQuery, [conn, sql, params]) => {
            let conn_doc = build_doc(ctx, conn, indent, child, generics)?;
            docs.push(Doc::concat(vec![conn_doc, Doc::text(".clone()")]));
            docs.push(build_doc(ctx, sql, indent, child, generics)?);
            docs.push(build_db_params_arg(ctx, params, indent, child, generics)?);
        }
        // Unreachable: the caller gates on exactly these three kernels with the
        // matching arity, so any other shape is a wiring bug — fail closed rather
        // than mis-emit.
        _ => {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::build_db_param_call",
                detail: format!(
                    "build_db_param_call reached with unexpected Db kernel {kernel:?} / arity {}",
                    args.len()
                ),
            });
        }
    }
    Ok(delimited(
        Doc::owned(format!("{name}(")),
        docs,
        Doc::text(")"),
    ))
}

/// A braces-always block whose body lays out flat (`{ body }`, a space hugging
/// each brace) when it fits and breaks to a block (`{`, the body at one indent
/// step, `}` dedented) when it does not. This is `rustfmt`'s closure-body block
/// for a return-type-annotated closure (`move |…| -> R { body }`) — UNLIKE
/// [`Doc::BraceBody`], the braces are present in BOTH layouts, because the
/// explicit `-> R` return type stops `rustfmt` from ever stripping them. Modeled
/// as a group over `{`, a soft `Line`-hugged body at `Nest(4)`, and `}`, so a
/// wide body breaks the block while the braces stay put.
fn braced_block(body: Doc) -> Doc {
    Doc::group(Doc::concat(vec![
        Doc::text("{"),
        Doc::nest(4, Doc::concat(vec![Doc::Line, body])),
        Doc::Line,
        Doc::text("}"),
    ]))
}

/// Build the unboxed closure `move |p0: T0, …| -> R <braced-body>` document,
/// mirroring [`crate::emit_expr::emit_lambda_unboxed`] token-for-token. The param
/// list, the `-> R` return type, and the `move |…| -> R ` head are single-line
/// leaves; only the closure body is structured (a [`braced_block`] that breaks
/// when wide). The head's trailing space before the body matches the string
/// emitter's `move |…| -> {ret} {{ … }}`.
fn build_closure(
    ctx: &EmitCtx,
    params: &[(Symbol, IrType)],
    ret: &IrType,
    body: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let child = depth + 1;
    let mut parts = Vec::with_capacity(params.len());
    for (param, ty) in params {
        parts.push(format!(
            "{}: {}",
            ctx.emit_ident(*param)?,
            render_type(ctx, ty, generics)?
        ));
    }
    let ret_s = render_type(ctx, ret, generics)?;
    let head = format!("move |{}| -> {ret_s} ", parts.join(", "));
    // This is a `move` closure: it captures `__ipe_lit` by move, so an
    // appearance style literal inside its body must NOT hoist into the enclosing
    // view's `LiteralTable` (the table is bound in the outer scope; a hoist here
    // would read a slot the closure did not introduce). Fence hoisting off for
    // the whole closure body, mirroring the string path's
    // [`crate::emit_expr::emit_lambda_unboxed`]; literals within emit directly.
    ctx.enter_closure();
    let body_doc = build_doc(ctx, body, indent, child, generics);
    ctx.exit_closure();
    let body_doc = body_doc?;
    Ok(Doc::concat(vec![Doc::owned(head), braced_block(body_doc)]))
}

/// Build the `Doc` for a boxed lambda value, mirroring
/// [`crate::emit_expr::emit_lambda`] / [`crate::emit_expr::emit_shared_lambda`]
/// token-for-token. The string emitter renders the statement block
/// `{ let __ipe_fn: <TypedFn> = <ctor>::new(<closure>); __ipe_fn }` — a block that
/// ALWAYS breaks (it holds the `let`): the assignment and the `__ipe_fn` tail each
/// on their own `HardLine` inside the block's sole `Nest(4)`.
///
/// The assignment is a [`Doc::Assign`]: the `let __ipe_fn: <TypedFn> = ` prefix's
/// wide `Box<dyn Fn(…) -> R + Send + 'static>` (or the `Arc<… + Send + Sync>`
/// shared form) annotation pushes the `<ctor>::new(<closure>)` RHS onto its own
/// line at `indent + 4` when the same-line form overflows, matching `rustfmt`.
/// The `trailer` is the statement's `;`.
///
/// `shared` selects the pointer: an `Arc<dyn Fn(…) + Send + Sync + 'static>`
/// reference-counted closure (`SharedLambda`, whose typed annotation is built
/// directly, NOT through `render_type`'s `Box`-only `Fun` arm) versus the boxed
/// `Box<dyn Fn(…) -> R + Send + 'static>` (`Lambda`, routed through `render_type`
/// with `Arc::new` for the two runtime handler shapes `wants_arc_ctor` flags).
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors emit_lambda's parameters"
)]
fn build_lambda(
    ctx: &EmitCtx,
    params: &[(Symbol, IrType)],
    ret: &IrType,
    body: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
    shared: bool,
) -> DResult<Doc> {
    let closure = build_closure(ctx, params, ret, body, indent, depth, generics)?;
    let (typed, ctor) = if shared {
        // The shared form builds the `+ Sync` trait object directly: `render_type`'s
        // generic `Fun` arm renders `Box<… + Send>` (no `Sync`), which would make
        // the `Arc` wrapper itself neither `Send` nor `Sync`.
        let mut parts = Vec::with_capacity(params.len());
        for (_, ty) in params {
            parts.push(render_type(ctx, ty, generics)?);
        }
        let ret_s = render_type(ctx, ret, generics)?;
        let typed = format!(
            "::std::sync::Arc<dyn Fn({}) -> {ret_s} + Send + Sync + 'static>",
            parts.join(", ")
        );
        (typed, "::std::sync::Arc")
    } else {
        let fun_ty = IrType::Fun(
            params.iter().map(|(_, t)| t.clone()).collect(),
            Box::new(ret.clone()),
        );
        let typed = render_type(ctx, &fun_ty, generics)?;
        let ctor = if wants_arc_ctor(&fun_ty) {
            "Arc"
        } else {
            "Box"
        };
        (typed, ctor)
    };
    // The `<ctor>::new(<closure>)` RHS: a single-argument delimited call over the
    // closure. `rustfmt` glues `Ctor::new(` onto the closure's `move |…| -> R {`
    // head and lets the closure body break in place when the head fits, but breaks
    // the call one-per-line (closure at `indent + 4`) when the head itself overflows
    // — the standard single-argument combine, which `Doc::call_args` renders.
    let rhs = Doc::call_args(
        Doc::owned(format!("{ctor}::new(")),
        vec![closure],
        Doc::text(")"),
        true,
    );
    let assign = Doc::assign(
        typed_let_prefix(&typed),
        rhs,
        // The statement's trailing `;`.
        1,
    );
    Ok(Doc::concat(vec![
        Doc::text("{"),
        Doc::nest(
            4,
            Doc::concat(vec![
                Doc::HardLine,
                assign,
                Doc::text(";"),
                Doc::HardLine,
                Doc::text("__ipe_fn"),
            ]),
        ),
        Doc::HardLine,
        Doc::text("}"),
    ]))
}

/// Build the `Doc` for an immediately-applied lambda, mirroring the
/// `Expr::Lambda` branch of [`crate::emit_expr::emit_apply`] token-for-token. The
/// string emitter inlines the closure as a block `({ let p0: T0 = a0; … body })` —
/// each param becomes a `let p: T = arg;` binding, then the body — so the block
/// ALWAYS breaks (it holds the bindings): each binding and the body on their own
/// `HardLine` inside the block's sole `Nest(4)`. Each binding's `p: T = arg` is a
/// [`Doc::Assign`] (a wide argument RHS-breaks); the argument and the body are
/// built recursively.
fn build_applied_lambda(
    ctx: &EmitCtx,
    params: &[(Symbol, IrType)],
    args: &[Expr],
    body: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    // A CURRIED application of a function-returning lambda binds its OWN params
    // (the flattened prefix) and yields a function value that the SURPLUS args
    // apply to: `(\p0 -> fn-value) a0 a1` is `((\p0 -> fn-value) a0)(a1)`. Bind
    // only the `params.len()` prefix here; any remaining args become a trailing
    // `(block)(rest)` application below. Folding all args into the `let` prefix
    // (as a bare `params.zip(args)` would) drops the surplus applications — the
    // composed-higher-order-combinator SEAL break (`andThen (\x -> … andThen …)`
    // leaves the produced parser unapplied to the threaded state).
    let own = params.len().min(args.len());
    let (own_args, surplus_args) = args.split_at(own);
    let mut inner = Vec::with_capacity(own * 4 + 2);
    for ((param, ty), arg) in params.iter().zip(own_args.iter()) {
        let p = ctx.emit_ident(*param)?;
        let t = render_type(ctx, ty, generics)?;
        let arg_doc = build_doc(ctx, arg, indent, child, generics)?;
        inner.push(Doc::HardLine);
        inner.push(Doc::assign(
            Doc::owned(format!("let {p}: {t} = ")),
            arg_doc,
            1,
        ));
        inner.push(Doc::text(";"));
    }
    let body_doc = build_doc(ctx, body, indent, child, generics)?;
    inner.push(Doc::HardLine);
    inner.push(body_doc);
    let block = Doc::concat(vec![
        Doc::text("({"),
        Doc::nest(4, Doc::concat(inner)),
        Doc::HardLine,
        Doc::text("})"),
    ]);
    if surplus_args.is_empty() {
        return Ok(block);
    }
    // `(block)(surplus)`: the inlined lambda block produces a function value; the
    // surplus args apply to it. `block` already renders parenthesized, so the
    // extra pair is elidable (rustfmt collapses `(( … ))`).
    let docs = build_args(ctx, surplus_args, indent, child, generics)?;
    Ok(delimited(
        Doc::concat(vec![Doc::elidable_paren(block), Doc::text("(")]),
        docs,
        Doc::text(")"),
    ))
}

/// Whether a `match` arm body is a CONTROL/paren-wrapped expression that
/// `rustfmt` wraps in synthesized braces (dropping the trailing comma) when it
/// breaks, rather than a DELIMITED-TAIL expression that breaks inside its own
/// brackets (keeping the comma). This mirrors `rustfmt`'s arm-body rule: a call /
/// constructor / application / tuple / list / cons / record / `task_and_then`
/// tail overflows into its own argument list, so no braces are synthesized; an
/// `if` / binary-operator chain / `let` / destructure / update / sync task block
/// is parenthesized or block-shaped and gets wrapped.
///
/// A body that is not one of the structured shapes (a plain leaf) is treated as
/// delimited-tail: a leaf renders single-line and always fits, so it takes the
/// inline (comma-kept) path regardless — the classification only matters for a
/// body that BREAKS, which a leaf never does.
const fn arm_body_is_control(body: &Expr) -> bool {
    match body {
        // Parenthesized or block-shaped: wrapped in synthesized braces when broken.
        Expr::If { .. } | Expr::Let { .. } | Expr::Destructure { .. } | Expr::Update { .. } => true,
        // A chain-eligible binary operator renders `(a + b)` and wraps when broken;
        // the call-shaped `Append` / `IntDiv` are leaves (delimited-tail).
        Expr::BinOp { op, .. } => infix(*op).is_some(),
        // Delimited-tail (breaks inside its own brackets) or a single-line leaf.
        _ => false,
    }
}

/// Split a rendered arm pattern into its top-level or-alternatives — the
/// segments the pattern renderer joined with ` | ` outside any bracket pair and
/// outside any string literal. A pattern with no top-level alternation comes
/// back as a single segment. A nested alternation stays inside its segment
/// (`(A | B, x)` is one alternative), matching the alternation `rustfmt`'s
/// or-pattern list rule applies to: only the arm's outermost one.
fn split_or_alternatives(pat: &str) -> Vec<String> {
    let mut alts = Vec::new();
    let mut seg = String::new();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    let mut prev = '\0';
    let mut chars = pat.chars().peekable();
    while let Some(c) = chars.next() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else {
            match c {
                '"' => in_str = true,
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                '|' if depth == 0 && prev == ' ' && chars.peek() == Some(&' ') => {
                    // The ` | ` separator: drop its leading space from the
                    // finished segment and consume its trailing space.
                    seg.pop();
                    chars.next();
                    alts.push(std::mem::take(&mut seg));
                    prev = ' ';
                    continue;
                }
                _ => {}
            }
        }
        seg.push(c);
        prev = c;
    }
    alts.push(seg);
    alts
}

/// Build the `Doc` for a `match` expression, mirroring
/// [`crate::emit_expr::emit_match`] token-for-token.
///
/// The `match` skeleton ALWAYS breaks (`rustfmt` never inlines a `match`): the
/// scrutinee and each arm head / guard are single-line, so they reuse the string
/// emitter's [`crate::emit_expr::emit_match_scrutinee`] /
/// [`crate::emit_expr::emit_arm_head`] and are carried as byte leaves. Only the
/// arm BODIES gain recursive Doc layout, each wrapped in a [`Doc::MatchArmTail`]
/// that applies `rustfmt`'s per-arm brace/comma rule ([`arm_body_is_control`]).
///
/// A prelude-carrying arm (a constructor unbox / string-binder rebind) keeps the
/// string emitter's `{{ prelude body }}` block shape: the prelude statements and
/// the body go on their own `HardLine`s inside the braces, so the arm always
/// breaks and the comma is dropped — the same shape `rustfmt` produces for a block
/// arm body.
fn build_match(
    ctx: &EmitCtx,
    m: &ipe_ir::Match,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<Doc> {
    let child = depth + 1;
    let (scrut, mode) = emit_match_scrutinee(ctx, m, indent, depth, generics)?;
    let mut arm_docs = Vec::with_capacity(m.arms().len());
    for arm in m.arms() {
        let (pat, prelude, synth_guard) = emit_arm_head(ctx, &arm.pat, &mode)?;
        // Transition hot-swap (dev-gated): this is the PRODUCTION function-body
        // match path, so the reduction of a data-describable TEA `update` arm to
        // `apply_transition_hot("<baked datum>", model)` must fire here. Under the
        // armed `hot_appearance` ctx an arm whose whole effect is one field change
        // with `Cmd.none` reduces to that single compiled reader over the baked
        // datum (dev == prod); every other arm returns `None` and stays compiled.
        // The reduced body is a single-line tuple leaf, so it is not control-shaped
        // (no synthesized braces). The same [`emit_transition_arm`] backs the
        // string-path mirror in [`crate::emit_expr::emit_match`], keeping the SEAL
        // exact. `None` falls through to the ordinary Doc body emit, byte-identical
        // to the flag-off form.
        let hot_arm = crate::emit_expr::emit_transition_arm(ctx, &arm.body)?;
        // The Cmd-wiring rewrite (a single literal `Cmd.perform` arm's Cmd position
        // → `fire_cmd_wiring` over the arm's compiled effect table). It shares the
        // string-path mirror in [`crate::emit_expr::emit_match`] via the same
        // produced string, keeping the SEAL exact. At most one of the two hot
        // rewrites fires (a `Cmd.none` transition arm is never a `Cmd.perform` arm).
        let wired_arm = if hot_arm.is_some() {
            None
        } else {
            crate::emit_expr::emit_cmd_wiring_arm(ctx, &arm.body, indent, depth, generics)?
        };
        // The body is emitted at one indent step past the `match` (the arm indent),
        // exactly as the string emitter passes `indent + 1`.
        let body_doc = match (&hot_arm, &wired_arm) {
            (Some(hot), _) => Doc::owned(hot.clone()),
            (None, Some(wired)) => Doc::owned(wired.clone()),
            (None, None) => build_doc(ctx, &arm.body, indent + 1, child, generics)?,
        };
        let ir_guard = match &arm.guard {
            Some(g) => Some(emit_expr_at(ctx, g, indent + 1, child, generics)?),
            None => None,
        };
        // A multi-alternative or-pattern head gets `rustfmt`'s flat-vs-vertical
        // or-pattern layout ([`Doc::OrPattern`]); any other head is a single-line
        // byte leaf. The ` => ` (with any guard) stays a separate leaf glued to
        // the pattern's last line in either layout.
        let alts = split_or_alternatives(&pat);
        let pat_doc = if alts.len() > 1 {
            Doc::or_pattern(alts.into_iter().map(Cow::Owned).collect())
        } else {
            Doc::owned(pat)
        };
        let arrow = combine_guards(synth_guard, ir_guard).map_or_else(
            || Doc::text(" => "),
            |guard| Doc::owned(format!(" if {guard} => ")),
        );
        let head = Doc::concat(vec![pat_doc, arrow]);
        let tail = if prelude.is_empty() {
            // Plain body: the arm-tail token applies the brace/comma rule by the
            // body's head kind. A hot-swap reduction (transition or Cmd-wiring) is a
            // tuple leaf, never control-shaped, so no braces are synthesized for it.
            let control =
                hot_arm.is_none() && wired_arm.is_none() && arm_body_is_control(&arm.body);
            Doc::match_arm_tail(body_doc, control)
        } else {
            // Prelude present: the string emitter wraps `{{ prelude body }}`. Keep
            // that block — each prelude statement and the body on their own
            // `HardLine`s inside the braces (always breaks, comma dropped), matching
            // `rustfmt`. The prelude is a run of `let …; ` statements the rebind /
            // unbox helpers build with a trailing `"; "` each, so splitting on it
            // recovers one statement per line (a trailing empty segment is skipped).
            let mut inner = Vec::new();
            for stmt in prelude.split_inclusive("; ") {
                let stmt = stmt.trim_end();
                if stmt.is_empty() {
                    continue;
                }
                inner.push(Doc::HardLine);
                inner.push(Doc::owned(stmt.to_owned()));
            }
            inner.push(Doc::HardLine);
            inner.push(body_doc);
            Doc::concat(vec![
                Doc::text("{"),
                Doc::nest(4, Doc::concat(inner)),
                Doc::HardLine,
                Doc::text("}"),
            ])
        };
        arm_docs.push(Doc::concat(vec![Doc::HardLine, head, tail]));
    }
    // The `match <scrut> {` head keeps the opening brace glued when the whole line
    // fits `max_width`; when `match <scrut> {` overflows, `rustfmt` drops the `{`
    // onto its own line at the `match` keyword's indent (`match <scrut>\n{`) — the
    // scrutinee itself is never broken. A `Group` over `match <scrut>` + a `Line` +
    // `{` reproduces exactly that: the `Line` is a space when the head fits flat and
    // a newline-plus-indent when it does not.
    let head = Doc::group(Doc::concat(vec![
        Doc::owned(format!("match {scrut}")),
        Doc::Line,
        Doc::text("{"),
    ]));
    Ok(Doc::concat(vec![
        head,
        Doc::nest(4, Doc::concat(arm_docs)),
        Doc::HardLine,
        Doc::text("}"),
    ]))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, reason = "test assertions")]
mod tests {
    //! P1 acceptance: the SEAL leaf-sequence property (every builder carries the
    //! string emitter's exact tokens) and per-builder byte-goldens through the
    //! renderer. The goldens are captured from `rustfmt --edition 2024
    //! --style-edition 2024`; the renderer is fixed to match, never the reverse.

    use std::borrow::Cow;

    use ipe_intern::Interner;
    use ipe_ir::{
        Arm, BinOp, CallPin, Callee, EnumDef, Expr, Func, FuncId, IrType, KernelFn, Match, ModPath,
        Module, OnFormKind, Pat, Program, TypeDef, Variant,
    };

    use ipe_diagnostics::Diagnostic;
    use ipe_ir::once_closure::MovedCapture;

    use super::build_doc;
    use crate::doc::{ChainOperand, Doc, whitespace_normalize};
    use crate::emit_expr::emit_expr_at;
    use crate::emit_types::GenericScope;
    use crate::render::{RenderConfig, render};
    use crate::{DbDriver, EmitCtx};

    /// A minimal one-module `Program` whose interner carries a handful of value
    /// identifiers (`a`, `b`, `c`, `x`) so `Expr::Var` fixtures resolve. The
    /// module declares one nullary enum so `EmitCtx::build` has a type to key on.
    struct Fixture {
        interner: Interner,
        program: Program,
        syms: Vec<ipe_intern::Symbol>,
        /// `Main` module path — the `home` of the fixture enum, for `Ctor` fixtures.
        main_mod: ipe_intern::Symbol,
        /// The `Msg` enum type symbol, for `Ctor` fixtures.
        msg_ty: ipe_intern::Symbol,
        /// The `Wrap` payload-variant symbol (`Wrap(Int)`), for `Ctor` fixtures.
        wrap_ctor: ipe_intern::Symbol,
        /// The `Triple` three-field-variant symbol (`Triple(Int, Int, Int)`), for
        /// the wide (breaking) `Ctor` byte-golden.
        triple_ctor: ipe_intern::Symbol,
        /// The `Unit` nullary-variant symbol, for the nullary `Ctor` fixture.
        unit_ctor: ipe_intern::Symbol,
        /// The built-in `Maybe` type symbol (no `EnumDef`), for the runtime-enum
        /// `Ctor` fixture.
        maybe_ty: ipe_intern::Symbol,
        /// The built-in `Just` variant symbol, for the runtime-enum `Ctor` fixture.
        just_ctor: ipe_intern::Symbol,
    }

    #[allow(clippy::too_many_lines)] // exhaustive `Module` literal (every `uses_*` flag)
    fn fixture() -> Fixture {
        let mut interner = Interner::new();
        let main_mod = interner.intern("Main").expect("intern Main");
        let msg_ty = interner.intern("Msg").expect("intern Msg");
        let unit_ctor = interner.intern("Unit").expect("intern Unit");
        // A one-field variant so a saturated payload-`Ctor` fixture resolves its
        // field types (`Msg::Wrap(Int)`).
        let wrap_ctor = interner.intern("Wrap").expect("intern Wrap");
        // A three-field variant for the wide (breaking) `Ctor` byte-golden
        // (`Msg::Triple(Int, Int, Int)`).
        let triple_ctor = interner.intern("Triple").expect("intern Triple");
        // Built-in `Maybe`/`Just` symbols: NO `EnumDef` is injected for them, so
        // `builtin_runtime_enum` routes their constructor to `IpeMaybe`.
        let maybe_ty = interner.intern("Maybe").expect("intern Maybe");
        let just_ctor = interner.intern("Just").expect("intern Just");
        // A zero-arg helper function so a `Callee::Func(FuncId 0)` call fixture
        // resolves a Rust name; its body is never emitted by these builder tests.
        let helper_fn = interner.intern("helper").expect("intern helper");
        // The two record field names (`a`, `b`) — interning is idempotent, so these
        // are the same symbols as `syms[0]`/`syms[1]` a `Record` fixture uses.
        let rec_field_a = interner.intern("a").expect("intern a");
        let rec_field_b = interner.intern("b").expect("intern b");
        let syms = [
            "a",
            "b",
            "c",
            "x",
            // Wide identifiers for the broken-`if` byte-golden: their combined
            // width pushes the `if cond { then } else { else }` construct past the
            // single-line threshold so the builder emits block form.
            "some_condition_variable",
            "first_branch_value",
            "second_branch_value_here",
            // Wide identifiers for the broken tuple / list / cons byte-goldens:
            // three of these in a delimited list overflow width 100.
            "argument_that_is_quite_long_enough_to_matter_x",
            "argument_that_is_quite_long_enough_to_matter_y",
            "argument_that_is_quite_long_enough_to_matter_z",
        ]
        .iter()
        .map(|n| interner.intern(n).expect("intern var"))
        .collect::<Vec<_>>();
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    name: msg_ty,
                    home: ModPath(vec![main_mod]),
                    type_params: vec![],
                    variants: vec![
                        Variant {
                            name: unit_ctor,
                            fields: vec![],
                        },
                        Variant {
                            name: wrap_ctor,
                            fields: vec![IrType::Int],
                        },
                        Variant {
                            name: triple_ctor,
                            fields: vec![IrType::Int, IrType::Int, IrType::Int],
                        },
                    ],
                })],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: helper_fn,
                    home: ModPath(vec![main_mod]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![],
                    ret: IrType::Int,
                    body: Expr::Int(0),
                }],
                entry: None,
                // A two-field record `{ a : Int, b : Int }` so a `Record` literal
                // fixture over the `a`/`b` field names resolves a synthesised
                // struct name via `record_struct_name`.
                records: vec![IrType::Record(std::collections::BTreeMap::from([
                    (rec_field_a, IrType::Int),
                    (rec_field_b, IrType::Int),
                ]))],
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
            }],
        };
        Fixture {
            interner,
            program,
            syms,
            main_mod,
            msg_ty,
            wrap_ctor,
            triple_ctor,
            unit_ctor,
            maybe_ty,
            just_ctor,
        }
    }

    fn with_ctx<R>(fx: &Fixture, f: impl FnOnce(&EmitCtx) -> R) -> R {
        let ctx = EmitCtx::build(
            &fx.interner,
            &fx.program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )
        .expect("EmitCtx::build");
        f(&ctx)
    }

    fn sym(fx: &Fixture, i: usize) -> ipe_intern::Symbol {
        fx.syms.get(i).copied().expect("fixture var symbol")
    }

    fn var(fx: &Fixture, i: usize) -> Expr {
        Expr::Var(sym(fx, i))
    }

    fn binop(op: BinOp, l: Expr, r: Expr) -> Expr {
        Expr::BinOp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        }
    }

    /// The all-variant-shape fixture matrix. Every fixture that `build_doc`
    /// structures (or explicitly delegates as a leaf) appears here so a missing
    /// or drifted builder fails the SEAL property, not a runtime `unreachable!`.
    #[allow(clippy::too_many_lines, reason = "one entry per expr shape under test")]
    fn seal_fixtures(fx: &Fixture) -> Vec<Expr> {
        vec![
            // Leaves.
            Expr::Int(42),
            Expr::Float(3.0),
            Expr::Str("hi".to_owned()),
            Expr::Char("z".to_owned()),
            Expr::Bool(true),
            Expr::Unit,
            var(fx, 0),
            Expr::CloneVar(sym(fx, 0)),
            // Chain-eligible binops (structured): generic `Add`/`Mul` use Rust
            // infix via trait bounds and participate in the chain layout.
            binop(BinOp::Add, var(fx, 0), var(fx, 1)),
            binop(
                BinOp::Add,
                binop(BinOp::Add, var(fx, 0), var(fx, 1)),
                var(fx, 2),
            ),
            binop(
                BinOp::Add,
                binop(BinOp::Mul, var(fx, 0), var(fx, 1)),
                var(fx, 2),
            ),
            binop(BinOp::Eq, var(fx, 0), var(fx, 1)),
            binop(BinOp::And, var(fx, 0), var(fx, 1)),
            // Call-shaped binops (structured): `++` → `format!("{}{}", a, b)` (a
            // macro, no trailing comma), `//` → `ipe_int_div(a, b)`, and the
            // integer arithmetic helpers (plain function calls, trailing comma kept).
            binop(BinOp::Append, var(fx, 0), var(fx, 1)),
            binop(BinOp::IntDiv, var(fx, 0), var(fx, 1)),
            binop(BinOp::IntAdd, var(fx, 0), var(fx, 1)),
            binop(BinOp::IntSub, var(fx, 0), var(fx, 1)),
            binop(BinOp::IntMul, var(fx, 0), var(fx, 1)),
            // Call-shaped binops, wide → break. The SEAL must hold across the
            // break/flat boundary; the append macro drops its trailing comma while
            // function calls keep one.
            binop(BinOp::Append, var(fx, 7), var(fx, 8)),
            binop(BinOp::IntDiv, var(fx, 7), var(fx, 8)),
            binop(BinOp::IntAdd, var(fx, 7), var(fx, 8)),
            // If (structured) — narrow, stays inline.
            Expr::If {
                cond: Box::new(var(fx, 0)),
                then_: Box::new(Expr::Int(1)),
                else_: Box::new(Expr::Int(2)),
            },
            // If (structured) — wide, breaks to block form; the SEAL must hold
            // across the break/flat boundary (same tokens, different layout).
            Expr::If {
                cond: Box::new(var(fx, 4)),
                then_: Box::new(var(fx, 5)),
                else_: Box::new(var(fx, 6)),
            },
            // Composite: a chain-eligible binop whose operands are themselves
            // `if` expressions — exercises the structured `if` builder nested
            // inside the structured `Chain` builder. Uses generic `Add` (infix).
            binop(
                BinOp::Add,
                Expr::If {
                    cond: Box::new(var(fx, 0)),
                    then_: Box::new(Expr::Int(1)),
                    else_: Box::new(Expr::Int(2)),
                },
                Expr::If {
                    cond: Box::new(var(fx, 1)),
                    then_: Box::new(Expr::Int(3)),
                    else_: Box::new(Expr::Int(4)),
                },
            ),
            // Composite: an `if` whose branches are chain-eligible binops —
            // exercises the structured `Chain` builder nested inside the `if`.
            Expr::If {
                cond: Box::new(var(fx, 0)),
                then_: Box::new(binop(BinOp::Add, var(fx, 1), var(fx, 2))),
                else_: Box::new(binop(BinOp::Mul, var(fx, 1), var(fx, 2))),
            },
            // Composite: a chain whose first operand is a WIDE (block-form) `if`,
            // so that operand renders multiline inside the chain — the glue-after-
            // multiline-operand path. The SEAL must hold across the break.
            binop(
                BinOp::Add,
                Expr::If {
                    cond: Box::new(var(fx, 4)),
                    then_: Box::new(var(fx, 5)),
                    else_: Box::new(var(fx, 6)),
                },
                var(fx, 3),
            ),
            // Tuple (structured, inline).
            Expr::Tuple(vec![var(fx, 0), var(fx, 1)]),
            // Tuple (structured, wide → breaks). SEAL holds across the boundary.
            Expr::Tuple(vec![var(fx, 7), var(fx, 8), var(fx, 9)]),
            // Cons onto the empty list (structured; tail is a leaf empty-list).
            Expr::Cons {
                head: Box::new(var(fx, 0)),
                tail: Box::new(Expr::List {
                    elem: IrType::Int,
                    items: vec![],
                }),
            },
            // Cons (structured, wide → breaks both arguments).
            Expr::Cons {
                head: Box::new(var(fx, 7)),
                tail: Box::new(var(fx, 8)),
            },
            // Non-empty list (structured, inline).
            Expr::List {
                elem: IrType::Int,
                items: vec![var(fx, 0), var(fx, 1)],
            },
            // Non-empty list (structured, wide → breaks).
            Expr::List {
                elem: IrType::Int,
                items: vec![var(fx, 7), var(fx, 8), var(fx, 9)],
            },
            // Empty list (leaf: `Vec::<i64>::new()`, no positional layout).
            Expr::List {
                elem: IrType::Int,
                items: vec![],
            },
            // Nullary user constructor (leaf: `Msg::Unit`, no positional payload).
            Expr::Ctor {
                home: ModPath(vec![fx.main_mod]),
                ty: fx.msg_ty,
                variant: fx.unit_ctor,
                args: vec![],
            },
            // Saturated payload user constructor (structured): `Msg::Wrap(a)`.
            Expr::Ctor {
                home: ModPath(vec![fx.main_mod]),
                ty: fx.msg_ty,
                variant: fx.wrap_ctor,
                args: vec![var(fx, 0)],
            },
            // Built-in runtime-enum constructor (structured): `IpeMaybe::Just(a)`.
            Expr::Ctor {
                home: ModPath(vec![]),
                ty: fx.maybe_ty,
                variant: fx.just_ctor,
                args: vec![var(fx, 0)],
            },
            // Plain user-function call (structured, inline).
            Expr::Call {
                callee: Callee::Func(FuncId::from_raw(0)),
                args: vec![var(fx, 0), var(fx, 1)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            },
            // Plain user-function call (structured, wide → breaks args).
            Expr::Call {
                callee: Callee::Func(FuncId::from_raw(0)),
                args: vec![var(fx, 7), var(fx, 8), var(fx, 9)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            },
            // Zero-arg call (leaf: `crate::…()`, no positional layout).
            Expr::Call {
                callee: Callee::Func(FuncId::from_raw(0)),
                args: vec![],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            },
            // Container-swapping kernel call (structured generic tail): `Maybe.map`
            // reverses its two arguments to the runtime's container-first order,
            // so the Doc builder must reverse the arg docs to match the string
            // emitter's `parts.reverse()`. No probe matches `MaybeMap`.
            Expr::Call {
                callee: Callee::Kernel(KernelFn::MaybeMap),
                args: vec![var(fx, 0), var(fx, 1)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            },
            // Csv parse kernel call (structured generic tail): the empty pin gets
            // the `::<IpeError>` error-channel anchor between the name and `(`.
            Expr::Call {
                callee: Callee::Kernel(KernelFn::CsvParse),
                args: vec![var(fx, 0)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            },
            // `Task.andThen cont effect` where `effect` MOVES a var `cont` also
            // captures: the effect's `a` is rewritten to `a.clone()` so the
            // continuation can still read it (the reused non-Copy handle SEAL).
            // The args are also reversed to the runtime's effect-first order. The
            // SEAL must match the string emitter's identical clone-and-reverse.
            Expr::Call {
                callee: Callee::Kernel(KernelFn::TaskAndThen),
                args: vec![
                    Expr::Lambda {
                        params: vec![(sym(fx, 1), IrType::Unit)],
                        ret: IrType::Int,
                        body: Box::new(var(fx, 0)),
                    },
                    Expr::Call {
                        callee: Callee::Func(FuncId::from_raw(0)),
                        args: vec![var(fx, 0)],
                        pin: CallPin::None,
                        on_form: OnFormKind::NotForm,
                    },
                ],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            },
            // General function-value application (structured, inline): `(a)(b, c)`.
            Expr::Apply {
                func: Box::new(var(fx, 0)),
                args: vec![var(fx, 1), var(fx, 2)],
            },
            // General application (structured, wide → breaks args).
            Expr::Apply {
                func: Box::new(var(fx, 0)),
                args: vec![var(fx, 7), var(fx, 8), var(fx, 9)],
            },
            // Immediately-applied lambda (structured block): rewrites to a
            // `({ let x: i64 = 1; x })` block — each param a `let p: T = arg;`
            // binding, then the body.
            Expr::Apply {
                func: Box::new(Expr::Lambda {
                    params: vec![(sym(fx, 3), IrType::Int)],
                    ret: IrType::Int,
                    body: Box::new(var(fx, 3)),
                }),
                args: vec![Expr::Int(1)],
            },
            // Zero-arg application (leaf: `(f)()`, no positional layout).
            Expr::Apply {
                func: Box::new(var(fx, 0)),
                args: vec![],
            },
            // Boxed lambda value (structured block): `{ let __ipe_fn: Box<…> =
            // Box::new(move |x: i64| -> i64 { x }); __ipe_fn }`.
            Expr::Lambda {
                params: vec![(sym(fx, 3), IrType::Int)],
                ret: IrType::Int,
                body: Box::new(var(fx, 3)),
            },
            // Boxed lambda whose body is a chain-eligible binop — the closure body
            // is a structured `Chain` inside the braces-always block. Uses generic
            // `Add` (infix) to exercise the chain path.
            Expr::Lambda {
                params: vec![(sym(fx, 3), IrType::Int)],
                ret: IrType::Int,
                body: Box::new(binop(BinOp::Add, var(fx, 3), var(fx, 0))),
            },
            // Shared (`Arc<… + Send + Sync>`) lambda value (structured block): the
            // same block shape, the shared trait-object annotation and `Arc::new`.
            Expr::SharedLambda {
                params: vec![(sym(fx, 3), IrType::Int)],
                ret: IrType::Int,
                body: Box::new(var(fx, 3)),
            },
            // Named-function value (structured block): `{ let __ipe_fn: Box<…> =
            // Box::new(<name>); __ipe_fn }` — the same always-breaking block as a
            // boxed lambda, its RHS a bare `Box::new(<name>)` over the helper fn.
            Expr::FuncValue {
                callee: Callee::Func(FuncId::from_raw(0)),
                ty: IrType::Fun(vec![], Box::new(IrType::Int)),
            },
            // `let` normal path (structured block): `({ let a = b; c })`. The body
            // references `a` zero times, so `needs_inline` is false — the plain
            // one-statement block form.
            Expr::Let {
                name: sym(fx, 0),
                value: Box::new(var(fx, 1)),
                body: Box::new(var(fx, 2)),
            },
            // `let` with a body that uses the binding (still normal path — the
            // value `b` is a plain Clone `Var`, so `needs_inline` is false).
            // Uses generic `Add` (infix) to exercise the body-is-chain path.
            Expr::Let {
                name: sym(fx, 0),
                value: Box::new(var(fx, 1)),
                body: Box::new(binop(BinOp::Add, var(fx, 0), var(fx, 2))),
            },
            // `Destructure` block, alias-free tuple binder (structured): a SINGLE
            // flat `let (a, b) = c;` statement, then the body.
            Expr::Destructure {
                binder: Pat::Tuple(vec![Pat::Var(sym(fx, 0)), Pat::Var(sym(fx, 1))]),
                value: Box::new(var(fx, 2)),
                body: Box::new(var(fx, 0)),
            },
            // `Destructure` block, ALIASED tuple binder (structured): the clone-
            // split MULTI-statement sequence (`let x = c; let (a, b) = x.clone();`),
            // each statement on its own line, then the body. Exercises the
            // multiple-`let` path the plain `let` block never hits.
            Expr::Destructure {
                binder: Pat::Alias(
                    Box::new(Pat::Tuple(vec![Pat::Var(sym(fx, 0)), Pat::Var(sym(fx, 1))])),
                    sym(fx, 3),
                ),
                value: Box::new(var(fx, 2)),
                body: Box::new(var(fx, 0)),
            },
            // Record literal (structured, inline): `RecXY { a: 1, b: 2 }` over the
            // fixture's registered two-field struct.
            Expr::Record {
                fields: vec![(sym(fx, 0), Expr::Int(1)), (sym(fx, 1), Expr::Int(2))],
                ty: None,
            },
            // Record literal (structured, wide → breaks fields one per line).
            Expr::Record {
                fields: vec![(sym(fx, 0), var(fx, 7)), (sym(fx, 1), var(fx, 8))],
                ty: None,
            },
            // Record update (structured statement block): clone the base, reassign
            // one field, return the temp. Always breaks (holds statements).
            Expr::Update {
                record: Box::new(var(fx, 2)),
                fields: vec![(sym(fx, 0), Expr::Int(9))],
            },
            // Record update with TWO reassigned fields — multiple assignment lines.
            Expr::Update {
                record: Box::new(var(fx, 2)),
                fields: vec![(sym(fx, 0), Expr::Int(9)), (sym(fx, 1), Expr::Int(8))],
            },
            // Auto-force task-sequencing tail (structured): the continuation's rest
            // body is a `BraceBody`, and the outer `task_and_then(effect, cont)` is a
            // two-argument delimited group. Distinct vars, so no clone-capture fires.
            Expr::TaskSeq {
                effect: Box::new(var(fx, 0)),
                rest: Box::new(var(fx, 1)),
            },
            // Auto-force task-seq whose `rest` re-reads the var the `effect` moves:
            // the IR-level clone-capture rewrite turns the effect's `a` into a
            // `CloneVar` (`a.clone()`), so effect and rest carry DIFFERENT leaves —
            // the SEAL must still match the string emitter's rewritten tokens.
            Expr::TaskSeq {
                effect: Box::new(Expr::Call {
                    callee: Callee::Func(FuncId::from_raw(0)),
                    args: vec![var(fx, 0)],
                    pin: CallPin::None,
                    on_form: OnFormKind::NotForm,
                }),
                rest: Box::new(var(fx, 0)),
            },
            // A `match` (structured): three constructor arms — a fits-inline body, a
            // wide delimited-tail call (comma kept), and a wide binop chain (synth
            // braces, comma dropped). The SEAL must hold across all three arm shapes:
            // the synthesized braces are leaf-invisible, the per-arm comma is a leaf.
            Expr::Match(
                Match::new_flat(
                    var(fx, 3),
                    vec![
                        Arm {
                            pat: Pat::Ctor {
                                home: ModPath(vec![fx.main_mod]),
                                ty: fx.msg_ty,
                                variant: fx.unit_ctor,
                                args: vec![],
                            },
                            body: Expr::Call {
                                callee: Callee::Func(FuncId::from_raw(0)),
                                args: vec![var(fx, 7), var(fx, 8), var(fx, 9)],
                                pin: CallPin::None,
                                on_form: OnFormKind::NotForm,
                            },
                            guard: None,
                        },
                        Arm {
                            pat: Pat::Ctor {
                                home: ModPath(vec![fx.main_mod]),
                                ty: fx.msg_ty,
                                variant: fx.wrap_ctor,
                                args: vec![Pat::Var(sym(fx, 0))],
                            },
                            body: binop(
                                BinOp::Add,
                                binop(BinOp::Add, var(fx, 7), var(fx, 8)),
                                var(fx, 9),
                            ),
                            guard: None,
                        },
                    ],
                )
                .expect("Match::new_flat"),
            ),
        ]
    }

    #[test]
    fn seal_leaf_sequence_matches_emit_expr_at_over_all_variants() {
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            for expr in seal_fixtures(&fx) {
                let scope = GenericScope::new(&[]);
                let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
                let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
                assert_eq!(
                    doc.normalized_leaves(),
                    whitespace_normalize(&string),
                    "\nSEAL mismatch for {expr:?}\n  doc leaves : {}\n  emit string: {}",
                    doc.normalized_leaves(),
                    whitespace_normalize(&string),
                );
            }
        });
    }

    /// A closure over `x` as a `Lambda`, or as an `OnceLambda` moving `a`.
    fn closure(fx: &Fixture, once: bool) -> Expr {
        let params = vec![(sym(fx, 3), IrType::Int)];
        let body = Box::new(binop(BinOp::Add, var(fx, 3), var(fx, 0)));
        if once {
            Expr::OnceLambda {
                params,
                ret: IrType::Int,
                body,
                capture: MovedCapture {
                    name: sym(fx, 0),
                    lo: 0,
                    hi: 1,
                },
            }
        } else {
            Expr::Lambda {
                params,
                ret: IrType::Int,
                body,
            }
        }
    }

    fn kernel_call(kernel: KernelFn, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Callee::Kernel(kernel),
            args,
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    /// The positions `once_closure::admits_once` admits, holding `closure(fx, once)`.
    fn admitted_once_sites(fx: &Fixture, once: bool) -> Vec<Expr> {
        vec![
            Expr::Apply {
                func: Box::new(closure(fx, once)),
                args: vec![Expr::Int(1)],
            },
            kernel_call(KernelFn::TaskAndThen, vec![closure(fx, once), var(fx, 1)]),
        ]
    }

    #[test]
    fn once_lambda_emits_like_lambda_at_admitted_sites() {
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let lambdas = admitted_once_sites(&fx, false);
            let onces = admitted_once_sites(&fx, true);
            for (lambda, once) in lambdas.iter().zip(&onces) {
                let want = emit_expr_at(ctx, lambda, 0, 0, scope).expect("lambda emits");
                let got = emit_expr_at(ctx, once, 0, 0, scope).expect("once closure emits");
                assert_eq!(got, want, "a once closure must emit as its `Lambda` twin");
                let doc = build_doc(ctx, once, 0, 0, scope).expect("once closure builds");
                assert_eq!(
                    doc.normalized_leaves(),
                    whitespace_normalize(&got),
                    "SEAL mismatch for {once:?}"
                );
                let lambda_doc = build_doc(ctx, lambda, 0, 0, scope).expect("lambda builds");
                assert_eq!(
                    render(&doc, RenderConfig::default()),
                    render(&lambda_doc, RenderConfig::default()),
                    "a once closure must render as its `Lambda` twin"
                );
            }
        });
    }

    /// An under-applied lambda is boxed and called by the string emitter, never
    /// inlined: the Doc builder must produce the same leaves, not a `let` block
    /// that binds only the supplied prefix and leaves the rest unbound.
    #[test]
    fn under_applied_lambda_doc_matches_string_emitter() {
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Apply {
                func: Box::new(Expr::Lambda {
                    params: vec![(sym(&fx, 3), IrType::Int), (sym(&fx, 4), IrType::Int)],
                    ret: IrType::Int,
                    body: Box::new(binop(BinOp::Add, var(&fx, 3), var(&fx, 4))),
                }),
                args: vec![Expr::Int(1)],
            };
            let want = emit_expr_at(ctx, &expr, 0, 0, scope).expect("string emitter");
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("doc builder");
            assert_eq!(
                doc.normalized_leaves(),
                whitespace_normalize(&want),
                "SEAL mismatch for an under-applied lambda"
            );
        });
    }

    #[test]
    fn once_lambda_elsewhere_is_a_compiler_bug() {
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let refused = [
                closure(&fx, true),
                Expr::Apply {
                    func: Box::new(closure(&fx, true)),
                    args: vec![],
                },
                Expr::Apply {
                    func: Box::new(closure(&fx, true)),
                    args: vec![Expr::Int(1), Expr::Int(2)],
                },
                kernel_call(KernelFn::ListMap, vec![closure(&fx, true), var(&fx, 1)]),
                kernel_call(KernelFn::TaskAndThen, vec![var(&fx, 1), closure(&fx, true)]),
            ];
            for expr in &refused {
                assert!(
                    matches!(
                        emit_expr_at(ctx, expr, 0, 0, scope),
                        Err(Diagnostic::CompilerBug { .. })
                    ),
                    "emit_expr_at must refuse {expr:?}"
                );
                assert!(
                    matches!(
                        build_doc(ctx, expr, 0, 0, scope),
                        Err(Diagnostic::CompilerBug { .. })
                    ),
                    "build_doc must refuse {expr:?}"
                );
            }
        });
    }

    #[test]
    fn chain_builder_carries_every_paren() {
        // `((a + b) + c)` — the string emitter wraps each level; the chain
        // builder must carry both `(` and both `)` as leaves so the SEAL holds.
        // Uses `BinOp::FloatAdd` (infix / chain-eligible) to exercise the chain
        // layout path. (`BinOp::Add` is now call-shaped via `ipe_wrapping_add`.)
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = binop(
                BinOp::FloatAdd,
                binop(BinOp::FloatAdd, var(&fx, 0), var(&fx, 1)),
                var(&fx, 2),
            );
            let scope = GenericScope::new(&[]);
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let mut leaves = String::new();
            doc.collect_leaves(&mut leaves);
            let opens = leaves.matches('(').count();
            let closes = leaves.matches(')').count();
            assert_eq!(opens, 2, "two wrapping open-parens: {leaves}");
            assert_eq!(closes, 2, "two wrapping close-parens: {leaves}");
            // Renders inline (fits width): `((a + b) + c)`.
            let rendered = render(&doc, RenderConfig::default());
            assert_eq!(rendered, "((a + b) + c)");
        });
    }

    #[test]
    fn generic_add_emits_wrapping_method_call() {
        // `BinOp::Add` (polymorphic `Number a`) now emits
        // `a.ipe_wrapping_add(b).ipe_wrapping_add(c)` — a method call, not an
        // infix chain — so overflow-checks=on cannot panic on i64.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = binop(
                BinOp::Add,
                binop(BinOp::Add, var(&fx, 0), var(&fx, 1)),
                var(&fx, 2),
            );
            let scope = GenericScope::new(&[]);
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let rendered = render(&doc, RenderConfig::default());
            assert_eq!(rendered, "a.ipe_wrapping_add(b).ipe_wrapping_add(c)");
            // SEAL: doc leaves equal the string emitter's bytes.
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            assert_eq!(doc.normalized_leaves(), whitespace_normalize(&string));
        });
    }

    #[test]
    fn chain_breaks_tail_to_shared_indent_when_too_wide() {
        // A chain wider than 100 cols in a `let z = ` statement at block indent 4
        // breaks its tail operators one-per-line to col 8 (block indent 4 + chain
        // step 4), the param_patterns golden's chain shape. The statement is
        // wrapped in `nest(4)` so the renderer's block indent is 4 (matching the
        // golden's `    let z = ` origin) while the mid-line `let z = ` prefix
        // stays on the statement's first column. Driven through the public
        // `render` entry — no private renderer hook needed.
        let operands = vec![
            ChainOperand {
                leading_op: None,
                doc: Doc::owned(
                    "((((longfunctioncallnamehere_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                ),
            },
            ChainOperand {
                leading_op: Some(Cow::Borrowed("+")),
                doc: Doc::owned("bbbbbbbbbbb)".to_owned()),
            },
            ChainOperand {
                leading_op: Some(Cow::Borrowed("+")),
                doc: Doc::owned("cc)".to_owned()),
            },
            ChainOperand {
                leading_op: Some(Cow::Borrowed("+")),
                doc: Doc::owned("dd)".to_owned()),
            },
            ChainOperand {
                leading_op: Some(Cow::Borrowed("+")),
                doc: Doc::owned("ee)".to_owned()),
            },
        ];
        let doc = Doc::nest(
            4,
            Doc::concat(vec![Doc::text("let z = "), Doc::Chain { operands }]),
        );
        let out = render(&doc, RenderConfig::default());
        // Line 1 packs the maximal prefix that fits width 100: the long first
        // operand, `+ bbbbbbbbbbb)`, and the tiny `+ cc)` all fit (~99 cols);
        // `+ dd` overflows and breaks, and from there `+ ee` breaks too — every
        // post-boundary operator to the shared col-8 indent (block 4 + step 4).
        let expected = "let z = ((((longfunctioncallnamehere_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa + bbbbbbbbbbb) + cc)\n        + dd)\n        + ee)";
        assert_eq!(
            out, expected,
            "\n--- got ---\n{out}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn if_expr_fits_inline() {
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::If {
                cond: Box::new(var(&fx, 0)),
                then_: Box::new(Expr::Int(1)),
                else_: Box::new(Expr::Int(2)),
            };
            let scope = GenericScope::new(&[]);
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let rendered = render(&doc, RenderConfig::default());
            assert_eq!(rendered, "(if a { 1i64 } else { 2i64 })");
        });
    }

    #[test]
    fn if_expr_at_threshold_boundary_stays_inline() {
        // An `if cond { then } else { else }` construct exactly 50 columns wide
        // (the threshold) stays inline; 51 breaks. `cond1234567890` + `thenvalab`
        // + `elsevalab` is the pinned 50-wide construct captured from rustfmt.
        let mut interner = Interner::new();
        let main_mod = interner.intern("Main").expect("intern Main");
        let cond = interner.intern("cond1234567890").expect("intern");
        let thenv = interner.intern("thenvalab").expect("intern");
        let elsev = interner.intern("elsevalab").expect("intern");
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![],
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
            }],
        };
        let ctx = EmitCtx::build(
            &interner,
            &program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )
        .expect("EmitCtx::build");
        let scope = GenericScope::new(&[]);
        let expr = Expr::If {
            cond: Box::new(Expr::Var(cond)),
            then_: Box::new(Expr::Var(thenv)),
            else_: Box::new(Expr::Var(elsev)),
        };
        let doc = build_doc(&ctx, &expr, 4, 0, scope).expect("build_doc");
        assert_eq!(
            render(&doc, RenderConfig::default()),
            "(if cond1234567890 { thenvalab } else { elsevalab })",
            "a 50-wide construct must stay inline"
        );
    }

    #[test]
    fn if_expr_breaks_to_block_form_when_over_threshold() {
        // `(if some_condition_variable { first_branch_value } else {
        // second_branch_value_here })` — the construct is 83 cols (> 50), so
        // rustfmt breaks each branch onto its own line. Golden captured from
        // `rustfmt --edition 2024 --style-edition 2024` at block indent 4.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::If {
                cond: Box::new(var(&fx, 4)),  // some_condition_variable
                then_: Box::new(var(&fx, 5)), // first_branch_value
                else_: Box::new(var(&fx, 6)), // second_branch_value_here
            };
            let doc = build_doc(ctx, &expr, 4, 0, scope).expect("build_doc");
            // Rendered inside a `let z = ` statement at block indent 4, matching the
            // captured golden's origin column.
            let stmt = Doc::nest(4, Doc::concat(vec![Doc::text("let z = "), doc]));
            let got = render(&stmt, RenderConfig::default());
            let expected = "let z = (if some_condition_variable {\n        first_branch_value\n    } else {\n        second_branch_value_here\n    })";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn tuple_and_cons_render_flat() {
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let tup = Expr::Tuple(vec![var(&fx, 0), var(&fx, 1)]);
            let doc = build_doc(ctx, &tup, 0, 0, scope).expect("build_doc");
            assert_eq!(render(&doc, RenderConfig::default()), "(a, b)");

            let cons = Expr::Cons {
                head: Box::new(var(&fx, 0)),
                tail: Box::new(Expr::List {
                    elem: IrType::Int,
                    items: vec![],
                }),
            };
            let doc = build_doc(ctx, &cons, 0, 0, scope).expect("build_doc");
            assert_eq!(
                render(&doc, RenderConfig::default()),
                "ipe_runtime::list::ipe_list_cons(a, Vec::<i64>::new())"
            );
        });
    }

    /// Render `expr` as the value of a `let z = ` statement at block indent 4,
    /// returning the whole statement line(s) so a mid-line delimited group starts
    /// at the same column `rustfmt` captured its golden from.
    fn render_let_stmt(ctx: &EmitCtx, expr: &Expr) -> String {
        let scope = GenericScope::new(&[]);
        let doc = build_doc(ctx, expr, 4, 0, scope).expect("build_doc");
        let stmt = Doc::nest(4, Doc::concat(vec![Doc::text("let z = "), doc]));
        render(&stmt, RenderConfig::default())
    }

    #[test]
    fn tuple_breaks_one_element_per_line_with_trailing_comma() {
        // `(x, y, z)` with three wide elements overflows width 100, so rustfmt
        // breaks each element onto its own line at nest+4 with a trailing comma and
        // dedents the closing paren to the statement indent. Golden captured from
        // `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Tuple(vec![var(&fx, 7), var(&fx, 8), var(&fx, 9)]);
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = (\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y,\n        argument_that_is_quite_long_enough_to_matter_z,\n    )";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn list_breaks_one_element_per_line_with_trailing_comma() {
        // `vec![x, y, z]` with three wide elements overflows; rustfmt breaks each
        // onto its own line with a trailing comma and dedents `]` to the statement
        // indent. Golden captured from rustfmt.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::List {
                elem: IrType::Int,
                items: vec![var(&fx, 7), var(&fx, 8), var(&fx, 9)],
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = vec![\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y,\n        argument_that_is_quite_long_enough_to_matter_z,\n    ]";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn cons_breaks_both_arguments_with_trailing_comma() {
        // A cons whose two arguments together overflow width 100 breaks each onto
        // its own line with a trailing comma; `)` dedents to the statement indent.
        // Golden captured from rustfmt.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Cons {
                head: Box::new(var(&fx, 7)),
                tail: Box::new(var(&fx, 8)),
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = ipe_runtime::list::ipe_list_cons(\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y,\n    )";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn user_call_breaks_args_one_per_line_with_trailing_comma() {
        // A plain user-function call whose three wide args overflow width 100
        // breaks each arg onto its own line at nest+4 with a trailing comma, `)`
        // dedented to the statement indent — rustfmt's call-arg layout. The prefix
        // is `callee_name(callee)(` (the exact Rust name the emitter uses); the
        // layout (breaks, trailing comma, indent) is what this golden pins.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let callee = Callee::Func(FuncId::from_raw(0));
            let name = super::callee_name(ctx, &callee).expect("callee_name");
            let expr = Expr::Call {
                callee,
                args: vec![var(&fx, 7), var(&fx, 8), var(&fx, 9)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = format!(
                "let z = {name}(\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y,\n        argument_that_is_quite_long_enough_to_matter_z,\n    )"
            );
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn user_call_fits_inline() {
        // A short user-function call stays inline: `name(a, b)`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let callee = Callee::Func(FuncId::from_raw(0));
            let name = super::callee_name(ctx, &callee).expect("callee_name");
            let expr = Expr::Call {
                callee,
                args: vec![var(&fx, 0), var(&fx, 1)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            };
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            assert_eq!(
                render(&doc, RenderConfig::default()),
                format!("{name}(a, b)")
            );
        });
    }

    #[test]
    fn swapping_kernel_call_reverses_args_inline() {
        // `Maybe.map f m` lowers container-first: the runtime call reverses the two
        // arguments. The Doc builder's inline render must equal the string
        // emitter's byte-for-byte (same reversed order).
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Call {
                callee: Callee::Kernel(KernelFn::MaybeMap),
                args: vec![var(&fx, 0), var(&fx, 1)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            };
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            assert_eq!(render(&doc, RenderConfig::default()), string);
            // The runtime container comes first: `b` (the container arg) precedes
            // `a` (the mapped function) in the emitted call.
            assert!(
                string.contains("(b, a)"),
                "swapped arg order expected, got {string}"
            );
        });
    }

    #[test]
    fn csv_parse_kernel_call_carries_turbofish_inline() {
        // `Csv.parse` gets the `::<IpeError>` error-channel anchor between the name
        // and its `(` argument list. The Doc builder must carry it identically.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Call {
                callee: Callee::Kernel(KernelFn::CsvParse),
                args: vec![var(&fx, 0)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            };
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            assert_eq!(render(&doc, RenderConfig::default()), string);
            assert!(
                string.contains("::<IpeError>("),
                "turbofish anchor expected, got {string}"
            );
        });
    }

    #[test]
    fn chain_operand_that_breaks_multiline_glues_following_operator() {
        // A Float chain `(broadIf + tail)` whose FIRST operand is a block-form
        // (wide) `if` renders the `if` multiline; the single `+ tail)` operator
        // glues to the `if`'s closing-line column (chain has not broken, glued
        // operand fits). Exercises `render_chain`'s multiline-operand glue path.
        // Uses `BinOp::FloatAdd` (infix/chain-eligible); `BinOp::Add` is now the
        // call-shaped `ipe_wrapping_add` path.
        // Golden captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let wide_if = Expr::If {
                cond: Box::new(var(&fx, 4)),  // some_condition_variable
                then_: Box::new(var(&fx, 5)), // first_branch_value
                else_: Box::new(var(&fx, 6)), // second_branch_value_here
            };
            let expr = binop(BinOp::FloatAdd, wide_if, var(&fx, 3)); // + x (a placeholder tail)
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = ((if some_condition_variable {\n        first_branch_value\n    } else {\n        second_branch_value_here\n    }) + x)";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn delimited_trailing_comma_is_seal_invisible() {
        // The break-conditional trailing comma is NOT part of the SEAL leaf
        // sequence (the string emitter never emits it), so a broken tuple's
        // normalized leaves must still equal the string emitter's normalized bytes.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Tuple(vec![var(&fx, 7), var(&fx, 8), var(&fx, 9)]);
            let doc = build_doc(ctx, &expr, 4, 0, scope).expect("build_doc");
            let string = emit_expr_at(ctx, &expr, 4, 0, scope).expect("emit_expr_at");
            assert_eq!(doc.normalized_leaves(), whitespace_normalize(&string));
        });
    }

    #[test]
    fn append_fits_inline() {
        // A short `++` append stays inline: `format!("{}{}", a, b)`. The render must
        // equal the string emitter's already-rustfmt-shaped bytes.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = binop(BinOp::Append, var(&fx, 0), var(&fx, 1));
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            assert_eq!(render(&doc, RenderConfig::default()), string);
            assert_eq!(
                render(&doc, RenderConfig::default()),
                "format!(\"{}{}\", a, b)"
            );
        });
    }

    #[test]
    fn append_macro_breaks_args_without_a_trailing_comma() {
        // A wide `++` append breaks its macro argument list one argument per line —
        // but, being a MACRO, `rustfmt` appends NO trailing comma (unlike a fn call).
        // The format string `"{}{}"` is the first argument. Golden captured from
        // `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = binop(BinOp::Append, var(&fx, 7), var(&fx, 8));
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = format!(\n        \"{}{}\",\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y\n    )";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn int_div_call_breaks_args_with_a_trailing_comma() {
        // A wide `//` int-div breaks its two arguments one per line WITH the trailing
        // comma `rustfmt` keeps on a plain function call (the macro/call divergence
        // this pins against `append_macro_breaks_args_without_a_trailing_comma`).
        // Golden captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = binop(BinOp::IntDiv, var(&fx, 7), var(&fx, 8));
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = ipe_runtime::math::ipe_int_div(\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y,\n    )";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn call_binop_seal_holds_across_the_break() {
        // SEAL: both call-shaped binops' normalized leaves equal the string
        // emitter's normalized bytes even when broken — the macro's absent trailing
        // comma and the call's break-conditional comma are both SEAL-invisible.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            for expr in [
                binop(BinOp::Append, var(&fx, 7), var(&fx, 8)),
                binop(BinOp::IntDiv, var(&fx, 7), var(&fx, 8)),
            ] {
                let doc = build_doc(ctx, &expr, 4, 0, scope).expect("build_doc");
                let string = emit_expr_at(ctx, &expr, 4, 0, scope).expect("emit_expr_at");
                assert_eq!(doc.normalized_leaves(), whitespace_normalize(&string));
            }
        });
    }

    #[test]
    fn func_value_block_always_breaks_but_assignment_stays_flat() {
        // A named-function value whose narrow `let` annotation (`Fun([], Int)` →
        // `Box<dyn Fn() -> i64 + …>`) keeps the assignment on one line: the block
        // still ALWAYS breaks (it holds the `let`), but the `= Box::new(<name>)`
        // RHS does NOT drop to its own line. Golden captured from
        // `rustfmt --edition 2024 --style-edition 2024`, with the emitter's chosen
        // `Box::new(<name>)` RHS recovered from the flat string form.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::FuncValue {
                callee: Callee::Func(FuncId::from_raw(0)),
                ty: IrType::Fun(vec![], Box::new(IrType::Int)),
            };
            let flat = emit_expr_at(ctx, &expr, 1, 0, scope).expect("emit_expr_at");
            let rhs = flat
                .split_once("= ")
                .and_then(|(_, r)| r.split_once(';'))
                .map(|(r, _)| r.trim())
                .expect("func value has a `= <rhs>;`");
            let got = render_fn_body(ctx, &expr);
            let expected = format!(
                "    {{\n        let __ipe_fn: Box<dyn Fn() -> i64 + Send + Sync + 'static> = {rhs};\n        __ipe_fn\n    }}"
            );
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn func_value_block_rhs_breaks_the_wide_type_annotation() {
        // A named-function value whose `let __ipe_fn: <wide Box type> = ` prefix
        // pushes the `Box::new(<name>)` RHS onto its own line at col 12 (the
        // assignment-RHS-break axis), exactly like the boxed lambda. The wide
        // three-arg fn type overflows the same-line form. Golden captured from
        // `rustfmt --edition 2024 --style-edition 2024`, with the emitter's chosen
        // helper name recovered from the flat string form.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::FuncValue {
                callee: Callee::Func(FuncId::from_raw(0)),
                ty: IrType::Fun(
                    vec![IrType::Int, IrType::Int, IrType::Int],
                    Box::new(IrType::Int),
                ),
            };
            // Recover the emitter's `Box::new(<name>)` RHS from the flat form.
            let flat = emit_expr_at(ctx, &expr, 1, 0, scope).expect("emit_expr_at");
            let rhs = flat
                .split_once("= ")
                .and_then(|(_, r)| r.split_once(';'))
                .map(|(r, _)| r.trim())
                .expect("func value has a `= <rhs>;`");
            let got = render_fn_body(ctx, &expr);
            let expected = format!(
                "    {{\n        let __ipe_fn: Box<dyn Fn(i64, i64, i64) -> i64 + Send + Sync + 'static> =\n            {rhs};\n        __ipe_fn\n    }}"
            );
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn ctor_fits_inline() {
        // A short saturated user constructor stays inline: `<EnumName>::Wrap(a)`.
        // A nullary constructor is a bare path leaf: `<EnumName>::Unit`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let payload = Expr::Ctor {
                home: ModPath(vec![fx.main_mod]),
                ty: fx.msg_ty,
                variant: fx.wrap_ctor,
                args: vec![var(&fx, 0)],
            };
            // The exact Rust enum name the emitter chooses for `Main.Msg`.
            let string = emit_expr_at(ctx, &payload, 0, 0, scope).expect("emit_expr_at");
            let doc = build_doc(ctx, &payload, 0, 0, scope).expect("build_doc");
            assert_eq!(render(&doc, RenderConfig::default()), string);
            assert!(string.ends_with("::Wrap(a)"), "got {string}");

            let nullary = Expr::Ctor {
                home: ModPath(vec![fx.main_mod]),
                ty: fx.msg_ty,
                variant: fx.unit_ctor,
                args: vec![],
            };
            let ns = emit_expr_at(ctx, &nullary, 0, 0, scope).expect("emit_expr_at");
            let nd = build_doc(ctx, &nullary, 0, 0, scope).expect("build_doc");
            assert_eq!(render(&nd, RenderConfig::default()), ns);
            assert!(ns.ends_with("::Unit"), "got {ns}");
        });
    }

    #[test]
    fn ctor_breaks_fields_one_per_line_with_trailing_comma() {
        // A saturated three-field constructor whose args overflow width 100 breaks
        // each field onto its own line at nest+4 with a trailing comma, `)` dedented
        // to the statement indent — rustfmt's tuple-variant-call layout. The prefix
        // is `<EnumName>::Triple(` (the exact Rust name the emitter chooses); the
        // layout is what this golden pins. Golden captured from
        // `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Ctor {
                home: ModPath(vec![fx.main_mod]),
                ty: fx.msg_ty,
                variant: fx.triple_ctor,
                args: vec![var(&fx, 7), var(&fx, 8), var(&fx, 9)],
            };
            // Recover the emitter's chosen prefix from the flat string form
            // (`<EnumName>::Triple(` up to the first `(`).
            let flat = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            let prefix = flat.split_once('(').expect("ctor has an open paren").0;
            let got = render_let_stmt(ctx, &expr);
            let expected = format!(
                "let z = {prefix}(\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y,\n        argument_that_is_quite_long_enough_to_matter_z,\n    )"
            );
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn apply_fits_inline() {
        // A short general application stays inline: `(a)(b, c)`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Apply {
                func: Box::new(var(&fx, 0)),
                args: vec![var(&fx, 1), var(&fx, 2)],
            };
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            assert_eq!(render(&doc, RenderConfig::default()), "(a)(b, c)");
        });
    }

    #[test]
    fn apply_breaks_args_one_per_line_with_trailing_comma() {
        // A general application whose three wide args overflow width 100 breaks each
        // arg onto its own line at nest+4 with a trailing comma, `)` dedented to the
        // statement indent — rustfmt's call-arg layout with an `(f)(` prefix. Golden
        // captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Apply {
                func: Box::new(var(&fx, 0)),
                args: vec![var(&fx, 7), var(&fx, 8), var(&fx, 9)],
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = (a)(\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y,\n        argument_that_is_quite_long_enough_to_matter_z,\n    )";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    /// Render `expr` as a function-body value at block indent 4: the block's
    /// opening `{` lands at col 4, and every newline inside the value indents from
    /// there — matching the column `rustfmt` captured a golden from for a
    /// `fn f() -> R { <expr> }` body. The `Nest(4)` makes the renderer's block
    /// indent 4; the leading four-space seed places the opening `{` at col 4.
    fn render_fn_body(ctx: &EmitCtx, expr: &Expr) -> String {
        let scope = GenericScope::new(&[]);
        let doc = build_doc(ctx, expr, 1, 0, scope).expect("build_doc");
        let stmt = Doc::nest(4, Doc::concat(vec![Doc::text("    "), doc]));
        render(&stmt, RenderConfig::default())
    }

    #[test]
    fn boxed_lambda_block_rhs_breaks_the_wide_type_annotation() {
        // A trivial boxed lambda `{ let __ipe_fn: Box<…> = Box::new(move |x: i64| ->
        // i64 { x }); __ipe_fn }` at a fn-body indent: the block always breaks, and
        // the `let __ipe_fn: <wide Box type> = ` prefix pushes the `Box::new(closure)`
        // RHS onto its own line at col 12 (the assignment-RHS-break axis). Golden
        // captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Lambda {
                params: vec![(sym(&fx, 3), IrType::Int)],
                ret: IrType::Int,
                body: Box::new(var(&fx, 3)),
            };
            let got = render_fn_body(ctx, &expr);
            let expected = "    {\n        let __ipe_fn: Box<dyn Fn(i64) -> i64 + Send + Sync + 'static> =\n            Box::new(move |x: i64| -> i64 { x });\n        __ipe_fn\n    }";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn boxed_lambda_wide_body_breaks_the_closure_block_not_the_assignment() {
        // A boxed lambda whose closure BODY is wide: the `let … = Box::new(move |…|
        // -> i64 {` head stays on one line (the closure body block gives rustfmt the
        // room), and the body breaks to its own line inside the braces. Golden
        // captured from `rustfmt --edition 2024 --style-edition 2024`. The wide body
        // is a single long identifier interned just for this test.
        let mut interner = Interner::new();
        let main_mod = interner.intern("Main").expect("intern Main");
        let x = interner.intern("x").expect("intern x");
        let wide = interner
            .intern(
                "a_very_long_body_expression_that_definitely_exceeds_the_available_width_padding",
            )
            .expect("intern wide");
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![],
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
            }],
        };
        let ctx = EmitCtx::build(
            &interner,
            &program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )
        .expect("EmitCtx::build");
        let expr = Expr::Lambda {
            params: vec![(x, IrType::Int)],
            ret: IrType::Int,
            body: Box::new(Expr::Var(wide)),
        };
        let got = render_fn_body(&ctx, &expr);
        let expected = "    {\n        let __ipe_fn: Box<dyn Fn(i64) -> i64 + Send + Sync + 'static> =\n            Box::new(move |x: i64| -> i64 {\n                a_very_long_body_expression_that_definitely_exceeds_the_available_width_padding\n            });\n        __ipe_fn\n    }";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn shared_lambda_block_uses_arc_pointer_and_sync_bound() {
        // A shared lambda `{ let __ipe_fn: ::std::sync::Arc<dyn Fn(i64) -> i64 + Send
        // + Sync + 'static> = ::std::sync::Arc::new(move |x: i64| -> i64 { x });
        // __ipe_fn }`: the reference-counted pointer and the `+ Sync` trait object.
        // The render must equal the string emitter's bytes byte-for-byte (its flat
        // form is already the rustfmt-canonical single-line closure body).
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::SharedLambda {
                params: vec![(sym(&fx, 3), IrType::Int)],
                ret: IrType::Int,
                body: Box::new(var(&fx, 3)),
            };
            let doc = build_doc(ctx, &expr, 1, 0, scope).expect("build_doc");
            let got = render(&doc, RenderConfig::default());
            // The shared annotation is wide, so the RHS breaks to its own line at
            // col 12. Golden captured from `rustfmt --edition 2024`.
            let expected = "{\n    let __ipe_fn: ::std::sync::Arc<dyn Fn(i64) -> i64 + Send + Sync + 'static> =\n        ::std::sync::Arc::new(move |x: i64| -> i64 { x });\n    __ipe_fn\n}";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn applied_lambda_block_binds_args_then_body() {
        // An immediately-applied lambda `({ let x: i64 = 1; x })`: the param becomes
        // a `let` binding, then the body — a block that always breaks. Golden
        // captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Apply {
                func: Box::new(Expr::Lambda {
                    params: vec![(sym(&fx, 3), IrType::Int)],
                    ret: IrType::Int,
                    body: Box::new(var(&fx, 3)),
                }),
                args: vec![Expr::Int(1)],
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = ({\n        let x: i64 = 1i64;\n        x\n    })";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn lambda_render_equals_string_emitter_when_flat() {
        // A lambda whose whole block fits: the Doc render must equal the string
        // emitter's bytes (which are already single-line and rustfmt-shaped). This
        // pins that the braces-always closure body and the block leaves reproduce the
        // string emitter exactly when nothing breaks. The block always breaks (it
        // holds the `let`), so "flat" here means every non-statement piece is inline.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            // A lambda short enough that the assignment does NOT RHS-break: a short
            // return type keeps `prefix rhs;` within width. `Unit -> Unit` renders a
            // narrow `Box<dyn Fn() -> () + Send + 'static>`.
            let expr = Expr::Lambda {
                params: vec![],
                ret: IrType::Unit,
                body: Box::new(Expr::Unit),
            };
            let doc = build_doc(ctx, &expr, 1, 0, scope).expect("build_doc");
            let got = render(&doc, RenderConfig::default());
            // The block still breaks its statements; the closure body `{ () }` stays
            // inline. This is the rustfmt shape of the string emitter's bytes.
            assert!(
                got.contains("Box::new(move || -> () { () })"),
                "closure body should stay inline with braces:\n{got}"
            );
        });
    }

    #[test]
    fn let_block_always_breaks_to_statements() {
        // A `let` block ALWAYS breaks (rustfmt never inlines a block that holds a
        // statement), even when short: `({`, the `let` statement and body each on
        // their own line at block+4 (col 8), `})` dedented to the statement indent.
        // Golden captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Let {
                name: sym(&fx, 0),            // a
                value: Box::new(var(&fx, 1)), // b
                body: Box::new(var(&fx, 2)),  // c
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = ({\n        let a = b;\n        c\n    })";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn nested_let_blocks_indent_by_the_renderer_nest_only() {
        // A `let` whose body is another `let` block: the inner block indents one
        // further step (col 12 = block 4 + outer Nest 4 + inner Nest 4), the inner
        // `})` sits at col 8. This pins that the renderer's `Nest(4)` is the SOLE
        // indent source — no leaf embeds indentation that would double-count.
        // Golden captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let inner = Expr::Let {
                name: sym(&fx, 0),
                value: Box::new(var(&fx, 1)),
                body: Box::new(var(&fx, 2)),
            };
            let expr = Expr::Let {
                name: sym(&fx, 0),
                value: Box::new(var(&fx, 1)),
                body: Box::new(inner),
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = ({\n        let a = b;\n        ({\n            let a = b;\n            c\n        })\n    })";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn destructure_block_single_statement_always_breaks() {
        // A `Destructure` with an alias-free tuple binder is a ONE-statement block:
        // `({`, the flat `let (a, b) = c;`, the body `a`, `})` — each on its own
        // line, `})` dedented to the statement indent. Always breaks, like the
        // `let` block. Golden captured from `rustfmt --edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Destructure {
                binder: Pat::Tuple(vec![Pat::Var(sym(&fx, 0)), Pat::Var(sym(&fx, 1))]),
                value: Box::new(var(&fx, 2)), // c
                body: Box::new(var(&fx, 0)),  // a
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = ({\n        let (a, b) = c;\n        a\n    })";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn destructure_block_aliased_binder_emits_multiple_statements() {
        // An ALIASED tuple binder expands to the clone-split MULTI-statement
        // sequence: `let x = c;` then `let (a, b) = x.clone();`, each on its own
        // `HardLine`, then the body — the path the plain `let` block never takes.
        // Golden captured from `rustfmt --edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Destructure {
                binder: Pat::Alias(
                    Box::new(Pat::Tuple(vec![
                        Pat::Var(sym(&fx, 0)),
                        Pat::Var(sym(&fx, 1)),
                    ])),
                    sym(&fx, 3), // x
                ),
                value: Box::new(var(&fx, 2)), // c
                body: Box::new(var(&fx, 0)),  // a
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = ({\n        let x = c;\n        let (a, b) = x.clone();\n        a\n    })";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn record_fits_inline_with_spaces_inside_braces() {
        // A short record literal stays inline with a space hugging each brace:
        // `<StructName> { a: 1, b: 2 }`. This is the brace-delimited flat shape
        // (`delimited_spaced`), distinct from the space-free bracketed lists.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Record {
                fields: vec![(sym(&fx, 0), Expr::Int(1)), (sym(&fx, 1), Expr::Int(2))],
                ty: None,
            };
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            // The string emitter's flat form is already the rustfmt-canonical
            // inline shape (`Name { a: 1, b: 2 }`), so the render matches it.
            assert_eq!(render(&doc, RenderConfig::default()), string);
            assert!(string.ends_with(" { a: 1i64, b: 2i64 }"), "got {string}");
        });
    }

    #[test]
    fn record_breaks_fields_one_per_line_with_trailing_comma() {
        // A record whose two wide fields overflow width 100 breaks each field onto
        // its own line at nest+4 with a trailing comma, `}` dedented to the
        // statement indent — rustfmt's struct-literal layout. Golden captured from
        // `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Record {
                fields: vec![(sym(&fx, 0), var(&fx, 7)), (sym(&fx, 1), var(&fx, 8))],
                ty: None,
            };
            // Recover the emitter's chosen struct name from the flat form
            // (everything up to the first ` {`).
            let flat = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            let name = flat.split_once(" {").expect("record has a brace").0;
            let got = render_let_stmt(ctx, &expr);
            let expected = format!(
                "let z = {name} {{\n        a: argument_that_is_quite_long_enough_to_matter_x,\n        b: argument_that_is_quite_long_enough_to_matter_y,\n    }}"
            );
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn update_block_single_field_always_breaks() {
        // A record update is a bind-then-reassign statement block: `{`, the field
        // temporary `let __ipe_upd_0 = 9;`, the `let mut __ipe_rec = c;` base move,
        // the `__ipe_rec.a = __ipe_upd_0;` assignment, the `__ipe_rec` tail, `}` —
        // each on its own line. Always breaks. Golden captured from
        // `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Update {
                record: Box::new(var(&fx, 2)), // c
                fields: vec![(sym(&fx, 0), Expr::Int(9))],
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = {\n        let __ipe_upd_0 = 9i64;\n        let mut __ipe_rec = c;\n        __ipe_rec.a = __ipe_upd_0;\n        __ipe_rec\n    }";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn update_block_multiple_fields_emit_one_assignment_per_line() {
        // Two fields → two `let __ipe_upd_i` binds before the base move and two
        // assignment lines after it, before the `__ipe_rec` tail. Golden captured
        // from rustfmt.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::Update {
                record: Box::new(var(&fx, 2)), // c
                fields: vec![(sym(&fx, 0), Expr::Int(9)), (sym(&fx, 1), Expr::Int(8))],
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = {\n        let __ipe_upd_0 = 9i64;\n        let __ipe_upd_1 = 8i64;\n        let mut __ipe_rec = c;\n        __ipe_rec.a = __ipe_upd_0;\n        __ipe_rec.b = __ipe_upd_1;\n        __ipe_rec\n    }";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn task_seq_fits_inline_with_braces_stripped() {
        // A short auto-force task-seq stays inline and `rustfmt` strips the closure
        // body's braces: `task_and_then(a, Box::new(move |_| b))`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::TaskSeq {
                effect: Box::new(var(&fx, 0)), // a
                rest: Box::new(var(&fx, 1)),   // b
            };
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            assert_eq!(
                render(&doc, RenderConfig::default()),
                "task_and_then(a, Box::new(move |_| b))"
            );
        });
    }

    #[test]
    fn task_seq_outer_breaks_but_closure_body_stays_flat() {
        // A task-seq whose two arguments together overflow width 100 breaks the
        // outer `task_and_then(...)` one argument per line with a trailing comma,
        // while the closure body still fits on its own line — braces stay stripped.
        // Golden captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let expr = Expr::TaskSeq {
                effect: Box::new(var(&fx, 7)), // …_x
                rest: Box::new(var(&fx, 8)),   // …_y
            };
            let got = render_let_stmt(ctx, &expr);
            let expected = "let z = task_and_then(\n        argument_that_is_quite_long_enough_to_matter_x,\n        Box::new(move |_| argument_that_is_quite_long_enough_to_matter_y),\n    )";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn task_seq_closure_body_breaks_to_a_braced_block() {
        // A task-seq whose closure body alone is wide: the outer call breaks, and
        // the closure body braces+breaks to a block (`move |_| {\n body\n}`). Golden
        // captured from `rustfmt --edition 2024 --style-edition 2024`. The wide body
        // is a single long identifier interned just for this test.
        let mut interner = ipe_intern::Interner::new();
        let main_mod = interner.intern("Main").expect("intern Main");
        let short_eff = interner.intern("short_eff").expect("intern");
        let wide_body = interner
            .intern("a_body_wide_enough_to_break_only_the_closure_body_padding_padding_padding_pad")
            .expect("intern");
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![],
                funcs: vec![],
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
            }],
        };
        let ctx = EmitCtx::build(
            &interner,
            &program,
            DbDriver::Sqlite,
            None,
            ipe_ir::Target::Native,
            Vec::new(),
            crate::MountBase::root(),
            false,
            None,
            false,
            crate::BuildIntent::Release,
            String::new(),
            false,
            false,
            None,
        )
        .expect("EmitCtx::build");
        let scope = GenericScope::new(&[]);
        let expr = Expr::TaskSeq {
            effect: Box::new(Expr::Var(short_eff)),
            rest: Box::new(Expr::Var(wide_body)),
        };
        let doc = build_doc(&ctx, &expr, 4, 0, scope).expect("build_doc");
        let stmt = Doc::nest(4, Doc::concat(vec![Doc::text("let z = "), doc]));
        let got = render(&stmt, RenderConfig::default());
        let expected = "let z = task_and_then(\n        short_eff,\n        Box::new(move |_| {\n            a_body_wide_enough_to_break_only_the_closure_body_padding_padding_padding_pad\n        }),\n    )";
        assert_eq!(
            got, expected,
            "\n--- got ---\n{got}\n--- want ---\n{expected}"
        );
    }

    #[test]
    fn task_seq_brace_body_is_seal_visible() {
        // The closure body's braces ARE part of the SEAL leaf sequence — the string
        // emitter always writes `move |_| { rest }` with braces — so the doc's
        // normalized leaves equal the string emitter's normalized bytes even when
        // the flat render strips the braces.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::TaskSeq {
                effect: Box::new(var(&fx, 0)),
                rest: Box::new(var(&fx, 1)),
            };
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            assert_eq!(doc.normalized_leaves(), whitespace_normalize(&string));
        });
    }

    /// A constructor arm head over the fixture's `Msg` enum.
    fn ctor_arm(fx: &Fixture, variant: ipe_intern::Symbol, args: Vec<Pat>, body: Expr) -> Arm {
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![fx.main_mod]),
                ty: fx.msg_ty,
                variant,
                args,
            },
            body,
            guard: None,
        }
    }

    /// A `Match` over the fixture's `Msg` enum scrutinee `x` (syms[3]) with the
    /// given constructor arms, built through the flat all-ctor-headed path.
    fn match_expr(fx: &Fixture, arms: Vec<Arm>) -> Expr {
        Expr::Match(Match::new_flat(var(fx, 3), arms).expect("Match::new_flat"))
    }

    #[test]
    fn match_skeleton_always_breaks_arms_fit_inline_with_comma() {
        // Constructor arms whose bodies fit inline: the `match` always breaks its
        // arms one per line, each `Pat => body,` with the comma kept. The Doc render
        // must reproduce the string emitter's already-rustfmt-shaped output exactly.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let arms = vec![
                ctor_arm(
                    &fx,
                    fx.unit_ctor,
                    vec![],
                    binop(BinOp::Add, var(&fx, 2), Expr::Int(1)),
                ),
                ctor_arm(&fx, fx.wrap_ctor, vec![Pat::Var(sym(&fx, 0))], var(&fx, 0)),
            ];
            let expr = match_expr(&fx, arms);
            let scope = GenericScope::new(&[]);
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("string");
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("doc");
            // Every arm body fits, so the Doc render equals the string emitter's
            // bytes (the string emitter's arm bodies are already single-line and
            // rustfmt-shaped, so no layout differs) — an exact byte match.
            assert_eq!(
                render(&doc, RenderConfig::default()),
                string,
                "the fits-inline match render must equal the string emitter's bytes"
            );
        });
    }

    #[test]
    fn match_wide_delimited_tail_arm_keeps_comma() {
        // An arm whose body is a wide user-function CALL (a delimited tail) breaks
        // inside its own argument list and keeps its trailing comma — no synthesized
        // braces. Golden captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let wide_call = Expr::Call {
                callee: Callee::Func(FuncId::from_raw(0)),
                args: vec![var(&fx, 7), var(&fx, 8), var(&fx, 9)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            };
            let arms = vec![
                ctor_arm(&fx, fx.unit_ctor, vec![], wide_call),
                ctor_arm(&fx, fx.wrap_ctor, vec![Pat::Var(sym(&fx, 0))], var(&fx, 0)),
            ];
            let expr = match_expr(&fx, arms);
            let scope = GenericScope::new(&[]);
            let name = super::callee_name(ctx, &Callee::Func(FuncId::from_raw(0))).expect("name");
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("doc");
            let got = render(&doc, RenderConfig::default());
            // The scrutinee `x` and the enum name `MainMsg` are the fixture's stable
            // Rust names. The `Unit` arm's wide call breaks inside its own argument
            // list with the trailing comma kept; the fitting `Wrap` arm keeps its
            // comma too. Golden captured from `rustfmt --edition 2024`.
            let expected = format!(
                "match x {{\n    MainMsg::Unit => {name}(\n        argument_that_is_quite_long_enough_to_matter_x,\n        argument_that_is_quite_long_enough_to_matter_y,\n        argument_that_is_quite_long_enough_to_matter_z,\n    ),\n    MainMsg::Wrap(a) => a,\n}}"
            );
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn match_wide_control_arm_synthesizes_braces_and_drops_comma() {
        // An arm whose body is a wide Float infix chain (a control body) is
        // wrapped in synthesized braces and the trailing comma is dropped.
        // Uses `BinOp::FloatAdd` (infix/chain-eligible) since `BinOp::Add` is
        // now the call-shaped `ipe_wrapping_add` path.
        // Golden captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            // `(…_x + …_y + …_z)` — a three-operand chain wide enough to break.
            let wide_chain = binop(
                BinOp::FloatAdd,
                binop(BinOp::FloatAdd, var(&fx, 7), var(&fx, 8)),
                var(&fx, 9),
            );
            let arms = vec![
                ctor_arm(&fx, fx.unit_ctor, vec![], wide_chain),
                ctor_arm(&fx, fx.wrap_ctor, vec![Pat::Var(sym(&fx, 0))], var(&fx, 0)),
            ];
            let expr = match_expr(&fx, arms);
            let scope = GenericScope::new(&[]);
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("doc");
            let got = render(&doc, RenderConfig::default());
            // The chain body braces and breaks; the `Unit` arm has no trailing comma
            // (dropped by synthesized braces), while the fitting `Wrap` arm keeps its
            // comma. Golden captured from `rustfmt --edition 2024`.
            let expected = "match x {\n    MainMsg::Unit => {\n        ((argument_that_is_quite_long_enough_to_matter_x\n            + argument_that_is_quite_long_enough_to_matter_y)\n            + argument_that_is_quite_long_enough_to_matter_z)\n    }\n    MainMsg::Wrap(a) => a,\n}";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    #[test]
    fn match_seal_holds_over_arm_bodies() {
        // SEAL: the Doc's normalized leaves equal the string emitter's normalized
        // bytes across every arm shape (fits, wide-delimited, wide-control), because
        // the synthesized braces are leaf-invisible and the trailing comma is a leaf
        // matching the string emitter's per-arm comma.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let wide_call = Expr::Call {
                callee: Callee::Func(FuncId::from_raw(0)),
                args: vec![var(&fx, 7), var(&fx, 8), var(&fx, 9)],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            };
            let wide_chain = binop(
                BinOp::Add,
                binop(BinOp::Add, var(&fx, 7), var(&fx, 8)),
                var(&fx, 9),
            );
            let arms = vec![
                ctor_arm(&fx, fx.unit_ctor, vec![], wide_call),
                ctor_arm(&fx, fx.wrap_ctor, vec![Pat::Var(sym(&fx, 0))], wide_chain),
                ctor_arm(
                    &fx,
                    fx.triple_ctor,
                    vec![
                        Pat::Var(sym(&fx, 0)),
                        Pat::Var(sym(&fx, 1)),
                        Pat::Var(sym(&fx, 2)),
                    ],
                    var(&fx, 0),
                ),
            ];
            let expr = match_expr(&fx, arms);
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("doc");
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("string");
            assert_eq!(
                doc.normalized_leaves(),
                whitespace_normalize(&string),
                "\nSEAL mismatch\n  doc leaves : {}\n  emit string: {}",
                doc.normalized_leaves(),
                whitespace_normalize(&string),
            );
        });
    }

    #[test]
    fn match_str_mode_variable_arm_carries_a_rebind_prelude_block() {
        // A string-mode `match` (an arm carries a `Pat::Str`) forces the scrutinee to
        // `(x).as_str()`, and a trailing variable catch-all binds that `&str`. The
        // arm-head helper emits a rebind PRELUDE `let v = v.to_string(); ` so the arm
        // body sees an owned `String` — the multi-statement `{ prelude body }` arm
        // shape `build_match` builds. It ALWAYS breaks (it holds the prelude
        // statement): the prelude and the body each on their own line inside the
        // braces, the comma dropped. This independently goldens the prelude-arm
        // split. Golden captured from `rustfmt --edition 2024 --style-edition 2024`.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            // Arm 1: `"go" => a` (a `Pat::Str` head, which triggers str_mode).
            // Arm 2: `v => v` (the variable catch-all whose binder rebinds `&str`).
            let arms = vec![
                Arm {
                    pat: Pat::Str("go".to_owned()),
                    body: var(&fx, 0), // a
                    guard: None,
                },
                Arm {
                    pat: Pat::Var(sym(&fx, 1)), // v-binder over syms[1] (`b`)
                    body: var(&fx, 1),
                    guard: None,
                },
            ];
            let expr = Expr::Match(Match::new_flat(var(&fx, 3), arms).expect("Match::new_flat"));
            // Confirm the string emitter really produced the rebind prelude — the
            // path this golden is here to lock.
            let string = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
            assert!(
                string.contains(".to_string();"),
                "expected a str-binder rebind prelude, got:\n{string}"
            );
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            let got = render(&doc, RenderConfig::default());
            // The `"go"` literal arm keeps its comma (a fitting delimited-tail body);
            // the `b` variable arm carries the `{ let b = b.to_string(); b }` prelude
            // block, which breaks and drops the comma. Golden captured from
            // `rustfmt --edition 2024`.
            let expected = "match (x).as_str() {\n    \"go\" => a,\n    b => {\n        let b = b.to_string();\n        b\n    }\n}";
            assert_eq!(
                got, expected,
                "\n--- got ---\n{got}\n--- want ---\n{expected}"
            );
        });
    }

    /// Format `body_expr` (the string-emitter form of a fixture) the legacy way:
    /// wrap it as a function body, run real `rustfmt`, and return the formatted
    /// body dedented to column 0 — the bytes the legacy `emit + run_rustfmt` path
    /// produces for that expression. Returns `None` if `rustfmt` is unavailable or
    /// rejects the wrapper (a non-value expression shape).
    fn legacy_rustfmt_body(body_expr: &str) -> Option<String> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let source = format!("fn __sweep() -> Wrap {{\n    {body_expr}\n}}\n");
        let mut child = Command::new("rustfmt")
            .args(["--edition", "2024", "--style-edition", "2024"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(source.as_bytes()).ok()?;
        let out = child.wait_with_output().ok()?;
        if !out.status.success() {
            return None;
        }
        let formatted = String::from_utf8(out.stdout).ok()?;
        // Strip the `fn __sweep() -> Wrap {` first line and the closing `}` last
        // line, then dedent the body by four columns to column 0.
        let mut lines: Vec<&str> = formatted.lines().collect();
        if lines.len() < 2 {
            return None;
        }
        lines.remove(0);
        lines.pop();
        let body = lines
            .iter()
            .map(|l| l.strip_prefix("    ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n");
        Some(body)
    }

    #[test]
    #[cfg_attr(miri, ignore)] // spawns `rustfmt`; `posix_spawn` is an unsupported foreign call under miri
    fn native_vs_legacy_corpus_diff_sweep() {
        // The native-vs-legacy equivalence gate: render every fixture BOTH ways — the
        // native Doc path (`render(build_doc)`) and the legacy path (`emit_expr_at`
        // then real `rustfmt`) — and assert they agree byte-for-byte. Any divergence
        // is a native-renderer layout bug (it spawns `rustfmt` per fixture, so a
        // `rustfmt` on PATH is required).
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let mut divergences = Vec::new();
            let mut compared = 0usize;
            for expr in seal_fixtures(&fx) {
                let legacy_raw = emit_expr_at(ctx, &expr, 0, 0, scope).expect("emit_expr_at");
                let Some(legacy) = legacy_rustfmt_body(&legacy_raw) else {
                    // rustfmt rejected the wrapper (an expression that is not a bare
                    // value in this synthetic context) — skip; the real corpus formats
                    // it in its true position.
                    continue;
                };
                let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
                let native = render(&doc, RenderConfig::default());
                compared += 1;
                if native != legacy {
                    divergences.push(format!(
                        "DIVERGES: {expr:?}\n  native:\n{native}\n  legacy:\n{legacy}\n"
                    ));
                }
            }
            eprintln!(
                "native-vs-legacy sweep: compared {compared} fixtures, {} diverged",
                divergences.len()
            );
            for d in &divergences {
                eprintln!("{d}");
            }
            assert!(
                divergences.is_empty(),
                "{} fixture(s) diverge between native render and legacy rustfmt \
                 (see stderr) — a native-renderer layout bug",
                divergences.len()
            );
        });
    }

    #[test]
    fn ctor_runtime_enum_just_renders_inline() {
        // A built-in `Maybe` constructor routes to the runtime enum
        // `IpeMaybe::Just(a)` — same delimited group, no field-boxing.
        let fx = fixture();
        with_ctx(&fx, |ctx| {
            let scope = GenericScope::new(&[]);
            let expr = Expr::Ctor {
                home: ModPath(vec![]),
                ty: fx.maybe_ty,
                variant: fx.just_ctor,
                args: vec![var(&fx, 0)],
            };
            let doc = build_doc(ctx, &expr, 0, 0, scope).expect("build_doc");
            assert_eq!(render(&doc, RenderConfig::default()), "IpeMaybe::Just(a)");
        });
    }

    /// An eager Access receiver stays a bare `Var` under the capture-clone rewrite.
    ///
    /// The field read borrows and ends before the continuation moves the
    /// receiver, so a whole-record clone is spurious; keeping it bare also keeps
    /// a non-`Clone` record receiver emittable (E0599).
    #[test]
    fn clone_capture_leaves_row_access_receiver_a_var() {
        let fx = fixture();
        let row = sym(&fx, 0); // `a` stands in for the row binder `rec`.
        let field = sym(&fx, 1); // `b` stands in for the read field `name`.
        // `rec` is captured by the continuation, so it lands in the target set.
        let captures: std::collections::BTreeSet<ipe_intern::Symbol> =
            std::iter::once(row).collect();
        let effect = Expr::Access {
            record: Box::new(Expr::Var(row)),
            field,
            field_ty: IrType::Str,
        };
        let rewritten = crate::emit_expr::clone_targets_in_expr(
            effect,
            &captures,
            &ipe_ir::EnumPayloadTable::new(),
        );
        match rewritten {
            Expr::Access { record, .. } => assert!(
                matches!(*record, Expr::Var(s) if s == row),
                "eager Access receiver must stay a bare Var, not a CloneVar"
            ),
            other => panic!("expected an Access, got {other:?}"),
        }
    }

    /// A captured variable read in a CONSUMING position of an effect is still
    /// cloned (the ordinary left-to-right move hazard). Only borrowing positions
    /// are exempt; a String/record moved into the effect is not double-moved by
    /// the continuation.
    #[test]
    fn clone_capture_still_clones_non_row_var() {
        let fx = fixture();
        let plain = sym(&fx, 2); // `c`: a captured non-row value.
        let captures: std::collections::BTreeSet<ipe_intern::Symbol> =
            std::iter::once(plain).collect();
        let effect = Expr::Var(plain);
        let rewritten = crate::emit_expr::clone_targets_in_expr(
            effect,
            &captures,
            &ipe_ir::EnumPayloadTable::new(),
        );
        assert!(
            matches!(rewritten, Expr::CloneVar(s) if s == plain),
            "a captured non-row variable must be rewritten to CloneVar"
        );
    }
}
