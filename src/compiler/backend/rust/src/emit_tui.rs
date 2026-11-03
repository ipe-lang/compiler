//! Emission for the `Ipe.Terminal` full-screen app-entry and its key input.
//!
//! * [`KernelFn::TerminalAppScreen`] — `Tui.tea cfg` →
//!   `ipe_runtime::tui::tui_app_ui(…)`. View returns `Element<Msg>` (the Ipe.Ui
//!   typed element tree, rendered to ANSI cells by the runtime). The cfg is the
//!   canonical, closed 4-field TEA record (init / update / view /
//!   subscriptions); key input is a subscription.
//! * [`key_event_bridge`] — the `Tui.Sub.onKey` handler bridge, used by the TEA
//!   kernel emitter for [`KernelFn::TuiSubOnKey`].
//!
//! # `KeyEvent` bridge
//!
//! The runtime delivers each key as two bare `String`s — its `kind` and `value`
//! (`ipe_runtime::tui_sub_on_key` takes `Fn(String, String) -> Msg`). Ipê code
//! writes `Tui.Sub.onKey : (KeyEvent -> msg) -> Sub msg`, whose scheme pins
//! `KeyEvent` to the closed record `{ kind : String, value : String }`. The
//! emitter binds the handler once and wraps it in a closure that builds that
//! record from the two strings:
//!
//! ```text
//! // Ipê source:  Sub.onKey KeyPressed
//! // Emitted:
//! tui_sub_on_key({ let __ipe_on_key = <handler>;
//!     move |kind: String, value: String| __ipe_on_key(RecKindValue { kind, value }) })
//! ```
//!
//! The wrapper applies to EVERY handler expression — a named function, a
//! lambda, a constructor, a partial application, a local — because the record
//! shape comes from the pinned scheme, not from the handler's syntax. There is
//! no unwrapped fallback whose arity the runtime bound would reject at `cargo`
//! time.
//!
//! # Correctness constraints (MAKE INVALID STATES UNREPRESENTABLE)
//!
//! * Function fields are emitted via [`emit_tui_fn`] (raw function name for
//!   `FuncValue`, fallback to `emit_expr_at` for lambdas).  A named `fn` item
//!   satisfies `Send + Sync + 'static` via the blanket impl; a `Box<dyn Fn>` does
//!   not without explicit bound annotation.
//! * No store/env plumbing: the Tui runtime reads the terminal size from the OS at
//!   each paint and has no session store.

use std::collections::BTreeMap;

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_ir::{Callee, Expr, IrType, KernelFn};

use crate::EmitCtx;
use crate::emit_expr::{callee_name, emit_expr_at};
use crate::emit_types::GenericScope;

/// Dispatch an `Ipe.Terminal` full-screen kernel call.
///
/// Returns `Some(emitted)` for `TerminalAppScreen`; `None` for any other
/// variant (defensive — the caller already guards on `k.is_tui()`).
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn emit_tui_call(
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
        // ── Tui.tea { init, update, view, subscriptions } ─
        //
        // view : Model -> Screen Msg
        // Runtime entry: `ipe_runtime::tui::tui_app_ui(init, update, view, subs)`
        KernelFn::TerminalAppScreen => {
            let [cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_tui_call::TerminalAppScreen",
                    detail: format!("Tui.tea requires 1 argument, got {}", args.len()),
                });
            };
            // Unreachable for well-typed source: a non-literal cfg is rejected
            // at lower with IPE-L0119 (Feature::LetBoundAppCfg); this guard is a
            // defensive invariant, mirroring the `WebAppRouted` precedent.
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_tui_call::TerminalAppScreen",
                    detail: "Tui.tea cfg must be an inline record literal; \
                             a non-literal cfg is rejected at lower with IPE-L0119"
                        .into(),
                });
            };
            emit_tui_inner(ctx, fields, indent, child, generics)
        }

        // Any non-Terminal kernel variant: let the standard path handle it.
        _ => Ok(None),
    }
}

/// Wrap an emitted `Tui.Sub.onKey` handler as the runtime's flat key handler.
///
/// The user's handler is `KeyEvent -> msg`; the runtime calls
/// `Fn(String, String) -> msg`. `handler_src` is the handler expression as already emitted. It is bound once
/// (so it is evaluated once, not per key) and applied to the `KeyEvent` struct
/// built from the runtime's `(kind, value)` pair. The struct is the one the
/// backend synthesised for the scheme-pinned `{ kind : String, value : String }`
/// record — the lowerer surfaces it from the kernel's solved type.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if the `KeyEvent` field names were never interned
/// or no struct was synthesised for the record shape — both internal invariant
/// violations for a program that type-checked a `Tui.Sub.onKey` call.
pub fn key_event_bridge(ctx: &EmitCtx, handler_src: &str) -> DResult<String> {
    let struct_name = key_event_struct_name(ctx)?;
    Ok(format!(
        "{{ let __ipe_on_key = {handler_src}; \
         move |kind: String, value: String| \
         __ipe_on_key({struct_name} {{ kind, value }}) }}"
    ))
}

/// The generated Rust struct name for the pinned `KeyEvent` record.
///
/// The record is `{ kind : String, value : String }`.
fn key_event_struct_name(ctx: &EmitCtx) -> DResult<String> {
    let shape: BTreeMap<ipe_intern::Symbol, IrType> = [
        (ctx.lookup_symbol("kind")?, IrType::Str),
        (ctx.lookup_symbol("value")?, IrType::Str),
    ]
    .into_iter()
    .collect();
    let field_names = ["kind".to_owned(), "value".to_owned()];
    let name = ctx.record_name_for_literal(&field_names, Some(&IrType::Record(shape)))?;
    Ok(name.to_owned())
}

// ── Internal ──────────────────────────────────────────────────────────────────

/// Emit `ipe_runtime::tui::tui_app_ui(init, update, view, subs)`.
///
/// # Function-field emission
///
/// Same discipline as `emit_web_app_inner`: named `fn` items are emitted via
/// `emit_tui_fn` (raw identifier), which satisfies `Send + Sync + 'static` via
/// the blanket impl.  A `Box<dyn Fn>` (from the fallback `emit_expr_at` path)
/// does NOT carry these bounds without explicit annotation.
fn emit_tui_inner(
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

    // seal: gate the Model against `tui_app`'s `Clone` bound. A non-clonable
    // (non-derivable) Model — a field of type `Cmd`/`Sub`/`Task`/`Decoder`/`Db`/
    // function — would otherwise `ipe`-succeed then `cargo`-fail; the gate makes
    // it a fail-closed `IPE-L0120` error. (Tui needs only `Clone`, not serde, so
    // an `Html`/`Color` field is admissible here.)
    if let Some(model_ty) = crate::emit_model_gate::model_ty_of_view(view_e) {
        crate::emit_model_gate::check_admissible_model(
            ctx,
            model_ty,
            ipe_diagnostics::AppShape::Tui,
        )?;
    }

    // seal: gate the Msg type against `tui_app`'s Clone+Send bound.
    // Same derivable predicate as Web — Msg is never persisted.
    if let Some(msg_ty) = crate::emit_model_gate::msg_ty_of_update(update_e) {
        crate::emit_model_gate::check_admissible_msg(ctx, msg_ty, ipe_diagnostics::AppShape::Tui)?;
    }

    let init_s = emit_tui_fn(ctx, init_e, indent, child, generics)?;
    let update_s = emit_tui_fn(ctx, update_e, indent, child, generics)?;
    let view_s = emit_tui_fn(ctx, view_e, indent, child, generics)?;
    let subs_s = emit_tui_fn(ctx, subs_e, indent, child, generics)?;

    Ok(Some(format!(
        "ipe_runtime::tea::TuiApp(ipe_runtime::tui::tui_app_ui(\
         {init_s}, \
         {update_s}, \
         {view_s}, \
         {subs_s}\
         ))"
    )))
}

/// Emit a cfg-field expression for a Tui app-entry kernel.
///
/// Mirrors `emit_web_fn` in `emit_web.rs` exactly: for a named function
/// reference ([`Expr::FuncValue`]), emits the raw callee name (e.g.
/// `Main_update`) rather than a boxed closure.  A named function item satisfies
/// `Fn(…) + Send + Sync + 'static` via the compiler's blanket impl; a
/// `Box<dyn Fn(…)>` does NOT carry these bounds without explicit annotation.
///
/// For any other expression (lambda, local variable, etc.) falls back to the
/// general [`emit_expr_at`] emitter.
fn emit_tui_fn(
    ctx: &EmitCtx,
    e: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<String> {
    if let Expr::FuncValue { callee, .. } = e {
        // Raw function-item reference: satisfies Send + Sync + 'static implicitly.
        return callee_name(ctx, callee);
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
        where_: "ipe_backend_rust::emit_tui_call",
        detail: format!(
            "required Tui cfg field `{name}` not found; \
             available fields: [{}]",
            fields
                .iter()
                .filter_map(|(s, _)| ctx.resolve_ident(*s).ok())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}
