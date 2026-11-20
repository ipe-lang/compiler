//! Emission for the view-less `Ipe.Tea.Worker.tea` app-entry.
//!
//! * [`KernelFn::TeaWorker`] — `Ipe.Tea.Worker.tea cfg` →
//!   `ipe_runtime::tea::WorkerApp(ipe_runtime::worker_app(init, update, subscriptions))`.
//!   A view-less TEA loop (Elm `Platform.worker` shape): no `view`, no input
//!   handler — output is `Cmd msg` (effects) and input is `Sub msg`. 3-field
//!   closed cfg: init / update / subscriptions.
//!
//! # Correctness constraints (MAKE INVALID STATES UNREPRESENTABLE)
//!
//! * All three required cfg fields are looked up with `lookup_field` (fail-closed
//!   on miss — a missing field here is a compiler bug, not user error, because the
//!   constrain scheme already enforces the 3-field shape upstream).
//! * Function fields are emitted via `emit_worker_fn` (raw function name for
//!   `FuncValue`, fallback to `emit_expr_at` for lambdas). A named `fn` item
//!   satisfies `Send + Sync + 'static` via the blanket impl; a `Box<dyn Fn>` does
//!   not without explicit bound annotation.
//! * No store/env/stdin plumbing: a worker renders nothing and reads no input
//!   stream — its only inputs are its own `Sub`s and the results of its `Cmd`s.

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_ir::{Callee, Expr, KernelFn};

use crate::EmitCtx;
use crate::emit_expr::emit_expr_at;
use crate::emit_types::GenericScope;

/// Dispatch an `Ipe.Tea.Worker.tea` kernel call.
///
/// Returns `Some(emitted)` for `TeaWorker`; `None` for any other variant
/// (defensive — the caller already guards on `k.is_worker()`).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn emit_worker_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    let Callee::Kernel(k) = callee else {
        return Ok(None);
    };

    match k {
        // ── Ipe.Tea.Worker.tea { init, update, subscriptions } ─
        //
        // Runtime entry: `ipe_runtime::worker_app(init, update, subs)`
        KernelFn::TeaWorker => {
            let [cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_worker_call::TeaWorker",
                    detail: format!("Ipe.Tea.Worker.tea requires 1 argument, got {}", args.len()),
                });
            };
            // Unreachable for well-typed source: a non-literal cfg is rejected
            // at lower with IPE-L0119 (Feature::LetBoundAppCfg); this guard is a
            // defensive invariant, mirroring the `TerminalAppLines` precedent.
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_worker_call::TeaWorker",
                    detail: "Ipe.Tea.Worker.tea cfg must be an inline record literal; \
                             a non-literal cfg is rejected at lower with IPE-L0119"
                        .into(),
                });
            };
            emit_worker_inner(ctx, fields, indent, child, generics)
        }

        // Any non-worker kernel variant: let the standard path handle it.
        _ => Ok(None),
    }
}

// ── Internal ──────────────────────────────────────────────────────────────────

/// Emit `ipe_runtime::worker_app(init, update, subs)`.
fn emit_worker_inner(
    ctx: &EmitCtx,
    fields: &[(ipe_intern::Symbol, Expr)],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    // All three fields are required — fail-closed on any miss (compiler bug, not
    // user error: the constrain scheme enforces the 3-field shape upstream).
    let init_e = lookup_field(ctx, fields, "init")?;
    let update_e = lookup_field(ctx, fields, "update")?;
    let subs_e = lookup_field(ctx, fields, "subscriptions")?;

    let init_s = emit_worker_fn(ctx, init_e, indent, child, generics)?;
    let update_s = emit_worker_fn(ctx, update_e, indent, child, generics)?;
    let subs_s = emit_worker_fn(ctx, subs_e, indent, child, generics)?;
    let codec_s = session_codec_suffix(ctx, update_e, subs_e)?;

    Ok(Some(format!(
        "ipe_runtime::tea::WorkerApp(ipe_runtime::worker_app(\
         {init_s}, \
         {update_s}, \
         {subs_s}{codec_s}\
         ))"
    )))
}

/// The trailing session-codec argument of a `--debugger` build, else nothing.
///
/// The runtime's `worker_app` takes the codec only under its `debugger`
/// feature, which `ctx.debugger` selects, so the arity always matches. The
/// `Model` is read from `update`'s second parameter, falling back to
/// `subscriptions`' first.
fn session_codec_suffix(ctx: &EmitCtx, update_e: &Expr, subs_e: &Expr) -> DResult<String> {
    if !ctx.debugger {
        return Ok(String::new());
    }
    let msg_ty = crate::emit_model_gate::msg_ty_of_update(update_e);
    let model_ty = crate::emit_model_gate::fn_param_ty(update_e, 1)
        .or_else(|| crate::emit_model_gate::fn_param_ty(subs_e, 0));
    let codec = crate::emit_model_schema::session_codec_arg(ctx, msg_ty, model_ty)?;
    Ok(format!(", {codec}"))
}

/// Emit a cfg-field expression for the worker app-entry kernel.
///
/// Mirrors `emit_console_fn` exactly: for a named function reference
/// ([`Expr::FuncValue`]), emits the raw callee name rather than a boxed closure.
/// A named function item satisfies `Fn(…) + Send + Sync + 'static` via the
/// compiler's blanket impl; a `Box<dyn Fn(…)>` does NOT carry these bounds
/// without explicit annotation. For any other expression falls back to the
/// general [`emit_expr_at`] emitter.
fn emit_worker_fn(
    ctx: &EmitCtx,
    e: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<String> {
    if let Expr::FuncValue { callee, .. } = e {
        return crate::emit_expr::func_value_name(ctx, callee);
    }
    emit_expr_at(ctx, e, indent, child, generics)
}

/// Find a record field by its Ipê source name in an IR field list.
///
/// Fail-closed: a missing required field surfaces a [`Diagnostic::CompilerBug`]
/// rather than silently emitting wrong code (MAKE INVALID STATES UNREPRESENTABLE).
fn lookup_field<'f>(
    ctx: &EmitCtx,
    fields: &'f [(ipe_intern::Symbol, Expr)],
    name: &str,
) -> DResult<&'f Expr> {
    for (sym, expr) in fields {
        if ctx.resolve_ident(*sym)? == name {
            return Ok(expr);
        }
    }
    Err(Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::emit_worker_call",
        detail: format!(
            "required worker cfg field `{name}` not found; \
             available fields: [{}]",
            fields
                .iter()
                .filter_map(|(s, _)| ctx.resolve_ident(*s).ok())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}
