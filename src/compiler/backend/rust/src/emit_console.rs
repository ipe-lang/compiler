//! Emission for the `Ipe.Terminal` line-oriented app-entry.
//!
//! * [`KernelFn::TerminalAppLines`] — `Cli.tea cfg` →
//!   `ipe_runtime::console_app(init, update, view, subscriptions)`.
//!   View returns a `Lines msg` value (`ipe_runtime::tui::LinesView`), which the
//!   runtime rasterizes to a styled terminal string on each state change.
//!   Canonical 4-field closed cfg: init / update / view / subscriptions. Line
//!   input is a subscription (`Cli.Sub.onLine`), dispatched by the runtime to
//!   every line handler the current `subscriptions` declares.
//! * [`line_handler_bridge`] — the `Cli.Sub.onLine` handler bridge, used by the
//!   TEA kernel emitter for [`KernelFn::CliSubOnLine`].
//!
//! # Line-handler bridge
//!
//! `ipe_runtime::cli_sub_on_line` takes a generic `F: Fn(String) -> Msg`. A
//! handler read out of a storage carrier is an `Arc<dyn Fn>`, which is callable
//! but does not itself implement `Fn`, so the emitter binds the handler once and
//! passes a fresh closure that calls it:
//!
//! ```text
//! // Ipê source:  Sub.onLine Line
//! // Emitted:
//! cli_sub_on_line({ let __ipe_on_line = <handler>;
//!     move |line: String| __ipe_on_line(line) })
//! ```
//!
//! The wrapper applies to EVERY handler expression — a named function, a
//! lambda, a constructor, a partial application, a local, a stored `Arc` — so
//! no handler carrier reaches the runtime's `Fn` bound unwrapped.
//!
//! # Correctness constraints (MAKE INVALID STATES UNREPRESENTABLE)
//!
//! * All four required cfg fields are looked up with `lookup_field` (fail-closed
//!   on miss — a missing field here is a compiler bug, not user error, because the
//!   constrain scheme already enforces the shape).
//! * Function fields are emitted via `emit_console_fn` (raw function name for
//!   `FuncValue`, fallback to `emit_expr_at` for lambdas).  A named `fn` item
//!   satisfies `Send + Sync + 'static` via the blanket impl; a `Box<dyn Fn>` does
//!   not without explicit bound annotation.
//! * No store/env plumbing: the Cli runtime reads stdin lines from the OS and has
//!   no session store.

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_ir::{Callee, Expr, KernelFn};

use crate::EmitCtx;
use crate::emit_expr::emit_expr_at;
use crate::emit_types::GenericScope;

/// Wrap an emitted `Cli.Sub.onLine` handler as the runtime's line handler.
///
/// `handler_src` is the handler expression as already emitted. It is bound
/// once (evaluated once, not per line) and called from a fresh `move` closure,
/// which implements `Fn(String) -> Msg` whatever the handler's own carrier
/// (`fn` item, `Box<dyn Fn>`, `Arc<dyn Fn>`, closure).
#[must_use]
pub fn line_handler_bridge(handler_src: &str) -> String {
    format!(
        "{{ let __ipe_on_line = {handler_src}; \
         move |line: String| __ipe_on_line(line) }}"
    )
}

/// Dispatch an `Ipe.Terminal` line-oriented kernel call.
///
/// Returns `Some(emitted)` for `TerminalAppLines`; `None` for any other variant
/// (defensive — the caller already guards on `k.is_console()`).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn emit_console_call(
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
        // ── Cli.tea { init, update, view, subscriptions } ─
        //
        // view : Model -> Lines Msg
        // Runtime entry: `ipe_runtime::console_app(init, update, view, subs)`
        KernelFn::TerminalAppLines => {
            let [cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_console_call::TerminalAppLines",
                    detail: format!("Cli.tea requires 1 argument, got {}", args.len()),
                });
            };
            // Unreachable for well-typed source: a non-literal cfg is rejected
            // at lower with IPE-L0119 (Feature::LetBoundAppCfg); this guard is a
            // defensive invariant, mirroring the `WebAppRouted` precedent.
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_console_call::TerminalAppLines",
                    detail: "Cli.tea cfg must be an inline record literal; \
                             a non-literal cfg is rejected at lower with IPE-L0119"
                        .into(),
                });
            };
            emit_console_inner(ctx, fields, indent, child, generics)
        }

        // Any non-Cli kernel variant: let the standard path handle it.
        _ => Ok(None),
    }
}

// ── Internal ──────────────────────────────────────────────────────────────────

/// Emit `ipe_runtime::console_app(init, update, view, subs)`.
///
/// # Function-field emission
///
/// Same discipline as `emit_tui_inner`: named `fn` items are emitted via
/// `emit_console_fn` (raw identifier), which satisfies `Send + Sync + 'static` via
/// the blanket impl.  A `Box<dyn Fn>` (from the fallback `emit_expr_at` path)
/// does NOT carry these bounds without explicit annotation.
fn emit_console_inner(
    ctx: &EmitCtx,
    fields: &[(ipe_intern::Symbol, Expr)],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    // All four fields are required — fail-closed on any miss (compiler bug, not
    // user error: the constrain scheme enforces the closed 4-field shape upstream).
    let init_e = lookup_field(ctx, fields, "init")?;
    let update_e = lookup_field(ctx, fields, "update")?;
    let view_e = lookup_field(ctx, fields, "view")?;
    let subs_e = lookup_field(ctx, fields, "subscriptions")?;

    // seal: gate the Model against `console_app`'s `Clone` bound. A
    // non-clonable (non-derivable) Model — a field of type `Cmd`/`Sub`/`Task`/
    // `Decoder`/`Db`/function — would otherwise `ipe`-succeed then
    // `cargo`-fail; the gate makes it a fail-closed `IPE-L0120` error.
    if let Some(model_ty) = crate::emit_model_gate::model_ty_of_view(view_e) {
        crate::emit_model_gate::check_admissible_model(
            ctx,
            model_ty,
            ipe_diagnostics::AppShape::Cli,
        )?;
    }

    let init_s = emit_console_fn(ctx, init_e, indent, child, generics)?;
    let update_s = emit_console_fn(ctx, update_e, indent, child, generics)?;
    let view_s = emit_console_fn(ctx, view_e, indent, child, generics)?;
    let subs_s = emit_console_fn(ctx, subs_e, indent, child, generics)?;
    let codec_s = session_codec_suffix(ctx, update_e, view_e)?;

    Ok(Some(format!(
        "ipe_runtime::tea::CliApp(ipe_runtime::console_app(\
         {init_s}, \
         {update_s}, \
         {view_s}, \
         {subs_s}{codec_s}\
         ))"
    )))
}

/// The trailing session-codec argument of a `--debugger` build, else nothing.
///
/// The runtime's `console_app` takes the codec only under its `debugger`
/// feature, which `ctx.debugger` selects, so the arity always matches. The
/// `Model` is read from `view`'s parameter, falling back to `update`'s second.
fn session_codec_suffix(ctx: &EmitCtx, update_e: &Expr, view_e: &Expr) -> DResult<String> {
    if !ctx.debugger {
        return Ok(String::new());
    }
    let msg_ty = crate::emit_model_gate::msg_ty_of_update(update_e);
    let model_ty = crate::emit_model_gate::model_ty_of_view(view_e)
        .or_else(|| crate::emit_model_gate::fn_param_ty(update_e, 1));
    let codec = crate::emit_model_schema::session_codec_arg(ctx, msg_ty, model_ty)?;
    Ok(format!(", {codec}"))
}

/// Emit a cfg-field expression for the Cli app-entry kernel.
///
/// Mirrors `emit_tui_fn` exactly: for a named function reference
/// ([`Expr::FuncValue`]), emits the raw callee name (e.g. `Main_update`)
/// rather than a boxed closure.  A named function item satisfies
/// `Fn(…) + Send + Sync + 'static` via the compiler's blanket impl; a
/// `Box<dyn Fn(…)>` does NOT carry these bounds without explicit annotation.
///
/// For any other expression (lambda, local variable, etc.) falls back to the
/// general [`emit_expr_at`] emitter.
fn emit_console_fn(
    ctx: &EmitCtx,
    e: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<String> {
    if let Expr::FuncValue { callee, .. } = e {
        // Raw function-item reference: satisfies Send + Sync + 'static implicitly.
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
        where_: "ipe_backend_rust::emit_console_call",
        detail: format!(
            "required Cli cfg field `{name}` not found; \
             available fields: [{}]",
            fields
                .iter()
                .filter_map(|(s, _)| ctx.resolve_ident(*s).ok())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::line_handler_bridge;

    /// The `onLine` handler never reaches `cli_sub_on_line`'s `F: Fn(String)`
    /// bound unwrapped: a stored `Arc<dyn Fn>` handler (`eta_0` here) is bound
    /// once and called from a fresh closure, which does implement `Fn`.
    #[test]
    fn line_handler_bridge_wraps_every_handler_in_a_fresh_closure() {
        assert_eq!(
            line_handler_bridge("eta_0"),
            "{ let __ipe_on_line = eta_0; move |line: String| __ipe_on_line(line) }"
        );
    }
}
