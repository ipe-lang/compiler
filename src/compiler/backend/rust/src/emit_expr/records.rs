use super::{DResult, Diagnostic, Expr, GenericScope, IrType, Symbol, emit_expr_at, indent_of};
use crate::EmitCtx;
use core::fmt::Write as _;
use ipe_ir::record_shapes as shapes;

// The runtime-shape field-NAME sets are the single source of truth in
// `ipe_ir::record_shapes`; this crate consumes them through `shapes::*`. They
// drive the FALLBACK below in [`record_struct_name`]: when
// [`EmitCtx::has_record_struct_for`] finds no registered struct for a literal's
// field-name set, the shape is matched against these sets to reconstruct the
// nominal runtime struct name (the runtime types live in `ipe_runtime`, not
// emitted here). The registry-first / name-only-second ordering matters: this
// crate has no access to `ipe_lower`'s `Ty` / `canon::Type`, so it cannot
// re-run the lowerer's now-TYPE-AWARE shape tests directly — deferring to the
// registry is how this call site stays in sync with them without duplicating
// them. The shared SSOT closes the remaining gap: a lower-side name rename
// updates every consumer at once and fails the build if a bound name-column
// drifts (see `ipe_lower`'s `const _: ()` name-equality assertions).

/// Emit a record literal `{ x = e1, ... }` as a named struct literal
/// `RecXY { x: <e1>, ... }`. `depth` is the literal's own IR-nesting level; its
/// field values are emitted one level deeper. Kept out of the `emit_expr_at`
/// match (`#[inline(never)]`) so its locals don't inflate the recursive frame.
#[inline(never)]
pub fn emit_record(
    ctx: &EmitCtx,
    fields: &[(Symbol, Expr)],
    ty: Option<&IrType>,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    let child = depth + 1;
    let (struct_name, is_server_response) = record_struct_name(ctx, fields, ty)?;
    let mut parts = Vec::with_capacity(fields.len() + usize::from(is_server_response));
    for (sym, value) in fields {
        let field_ident = ctx.emit_ident(*sym)?;
        let rendered = emit_expr_at(ctx, value, indent, child, generics)?;
        parts.push(format!("{field_ident}: {rendered}"));
    }
    if is_server_response {
        // The runtime struct's multi-`Set-Cookie` field is not part of the Ipê
        // record alias; default it so the struct literal is complete.
        parts.push("cookies: Vec::new()".to_owned());
    }
    if parts.is_empty() {
        return Ok(format!("{struct_name} {{}}"));
    }
    Ok(format!("{struct_name} {{ {} }}", parts.join(", ")))
}

/// Resolve the Rust struct name a record literal constructs. The literal's
/// field-name set (Rust names struct-literal fields, so field write order is
/// free) picks the candidate struct(s); when the set is shared by two distinct
/// shapes, the literal's solved `ty` (an [`IrType::Record`], threaded from the
/// lowerer) disambiguates to the exact one. Returns the struct name and whether
/// it folds to the runtime `ServerResponse` struct (which carries an extra
/// `cookies: Vec<String>` field the Ipê record alias omits, so the caller
/// appends a `cookies: Vec::new()` field). Shared by [`emit_record`] and the
/// native Doc emitter so the two agree on the struct name exactly.
pub fn record_struct_name(
    ctx: &EmitCtx,
    fields: &[(Symbol, Expr)],
    ty: Option<&IrType>,
) -> DResult<(String, bool)> {
    // The struct is resolved by the literal's field-name set (Rust names
    // struct-literal fields, so write order is free); the field idents are
    // keyword-mangled to match the struct definition.
    let mut key = Vec::with_capacity(fields.len());
    for (sym, _) in fields {
        key.push(ctx.resolve_ident(*sym)?.to_owned());
    }
    // `true` when the shape folds to the runtime `ServerResponse` struct, which
    // carries an extra `cookies: Vec<String>` field the Ipê record alias omits.
    let mut is_server_response = false;
    let struct_name: String = {
        // Prefer an actual synthesised struct when one is registered for
        // this exact field-name set — that reflects `ipe_lower`'s
        // authoritative, TYPE-AWARE decision (see
        // `EmitCtx::has_record_struct_for`'s doc comment). Only fall back to
        // the field-NAME-only `HttpRequest` heuristic when NO struct is
        // registered, which is precisely the signature of a genuine
        // `HttpRequest` literal (the lowerer intercepts it into the opaque
        // `IrType::HttpRequest` before it ever reaches the struct registry).
        // This ordering closes the false-positive class where an unrelated
        // record sharing the 7 canonical field NAMES with unrelated field
        // TYPES (e.g. all-`Int`) would be mislabelled `HttpRequest` here
        // even after `ipe_lower` had already registered a correctly-typed
        // struct for it — a two-path divergence the registry check avoids.
        if ctx.has_record_struct_for(&key) {
            ctx.record_name_for_literal(&key, ty)?.to_owned()
        } else {
            let mut sorted = key.clone();
            sorted.sort();
            let is_http_request = sorted.len() == shapes::HTTP_REQUEST_FIELDS.len()
                && sorted
                    .iter()
                    .zip(shapes::HTTP_REQUEST_FIELDS.iter())
                    .all(|(a, b)| a.as_str() == *b);
            // same fall-through as HttpRequest — a `ProcessRunWithCfg`-shaped
            // literal has no registered struct (folded to
            // `IrType::ProcessRunWithCfg`), so it constructs the runtime
            // `ProcessRunWithCfg` (re-exported bare via the glob).
            let is_process_run_with_cfg = sorted.len() == shapes::PROCESS_RUN_WITH_CFG_FIELDS.len()
                && sorted
                    .iter()
                    .zip(shapes::PROCESS_RUN_WITH_CFG_FIELDS.iter())
                    .all(|(a, b)| a.as_str() == *b);
            // same fall-through as `ProcessRunWithCfg` — a `ProcessRunInPtyCfg`-shaped
            // literal has no registered struct (folded to
            // `IrType::ProcessRunInPtyCfg`), so it constructs the runtime
            // `ProcessRunInPtyCfg` (re-exported bare via the glob).
            let is_process_run_in_pty_cfg = sorted.len()
                == shapes::PROCESS_RUN_IN_PTY_CFG_FIELDS.len()
                && sorted
                    .iter()
                    .zip(shapes::PROCESS_RUN_IN_PTY_CFG_FIELDS.iter())
                    .all(|(a, b)| a.as_str() == *b);
            // same fall-through as HttpRequest — a `CacheCfg`-shaped literal
            // has no registered struct (folded to `IrType::CacheCfg`), so it
            // constructs the runtime `CacheCfg` (re-exported bare via the glob).
            let is_cache_cfg = sorted.len() == shapes::CACHE_CFG_FIELDS.len()
                && sorted
                    .iter()
                    .zip(shapes::CACHE_CFG_FIELDS.iter())
                    .all(|(a, b)| a.as_str() == *b);
            // same fall-through — a `Csv`-shaped literal has no registered
            // struct (folded to `IrType::CsvDoc`), so it constructs the runtime
            // `CsvDoc` (re-exported bare via the `pub use csv::*` glob).
            let is_csv_doc = sorted.len() == shapes::CSV_DOC_FIELDS.len()
                && sorted
                    .iter()
                    .zip(shapes::CSV_DOC_FIELDS.iter())
                    .all(|(a, b)| a.as_str() == *b);
            // same fall-through — a `WebSocketCfg`-shaped literal has no
            // registered struct (folded to `IrType::WebSocketClientCfg`), so it
            // constructs the runtime `WsClientCfg` (re-exported bare via the
            // `pub use ws_client::*` glob).
            let is_websocket_cfg = sorted.len() == shapes::WEBSOCKET_CFG_FIELDS.len()
                && sorted
                    .iter()
                    .zip(shapes::WEBSOCKET_CFG_FIELDS.iter())
                    .all(|(a, b)| a.as_str() == *b);
            // same fall-through — a `Response`-shaped literal has no
            // registered struct (folded to `IrType::ServerResponse`), so it
            // constructs the runtime `ServerResponse` (re-exported bare via the
            // `pub use server::*` glob).
            is_server_response = sorted.len() == shapes::SERVER_RESPONSE_FIELDS.len()
                && sorted
                    .iter()
                    .zip(shapes::SERVER_RESPONSE_FIELDS.iter())
                    .all(|(a, b)| a.as_str() == *b);
            // Ipe.Email fall-throughs — same rationale as `CsvDoc`: a
            // `defaultMessage`/`defaultAttachment`/… built literal has no
            // registered struct (folded to the matching `IrType::Email*`), so it
            // constructs the runtime struct (re-exported bare via `pub use
            // email::*`). The Ipê `Attachment` alias maps to `EmailAttachment`.
            let name_set_is = |expected: &[&str]| {
                sorted.len() == expected.len()
                    && sorted
                        .iter()
                        .zip(expected.iter())
                        .all(|(a, b)| a.as_str() == *b)
            };
            if is_http_request {
                "HttpRequest".to_owned()
            } else if is_process_run_with_cfg {
                "ProcessRunWithCfg".to_owned()
            } else if is_process_run_in_pty_cfg {
                "ProcessRunInPtyCfg".to_owned()
            } else if is_cache_cfg {
                "CacheCfg".to_owned()
            } else if is_csv_doc {
                "CsvDoc".to_owned()
            } else if is_websocket_cfg {
                "WsClientCfg".to_owned()
            } else if is_server_response {
                "ServerResponse".to_owned()
            } else if name_set_is(shapes::EMAIL_MESSAGE_FIELDS) {
                "EmailMessage".to_owned()
            } else if name_set_is(shapes::EMAIL_ATTACHMENT_FIELDS) {
                "EmailAttachment".to_owned()
            } else if name_set_is(shapes::EMAIL_SES_FIELDS) {
                "SesConfig".to_owned()
            } else if name_set_is(shapes::EMAIL_SMTP_FIELDS) {
                "SmtpConfig".to_owned()
            } else {
                ctx.record_name_for_literal(&key, ty)?.to_owned()
            }
        }
    };
    Ok((struct_name, is_server_response))
}

/// Emit a functional record update `{ record | f = v, ... }` as a
/// bind-fields-then-move-and-reassign block:
/// `{ let __ipe_upd_0 = v0; …; let mut __ipe_rec = <base>; __ipe_rec.f = __ipe_upd_0; …; __ipe_rec }`.
///
/// Each field value is bound to a positional temporary BEFORE the base is moved
/// into `__ipe_rec`. This lets a field value read the base itself — the
/// canonical functional-update idiom `{ record | count = record.count + 1 }` —
/// on a non-`Clone` base: the read happens while the base is still owned, and
/// the move follows. Evaluating the field values into `let` bindings in source
/// order runs each value expression exactly once, in order, so a side-effecting
/// value is not duplicated or reordered.
///
/// The base expression is emitted by [`emit_expr_at`], which already inserts
/// `.clone()` when the base variable appears in multiple positions — the reuse
/// gate rewrites such variables to [`Expr::CloneVar`] before emission. No extra
/// `.clone()` is added here:
///
/// * If the base is a bare [`Expr::Var`] (single use), moving it into
///   `__ipe_rec` is correct for both `Clone`-able and non-`Clone` record types.
///   A non-`Clone` effect-carrier (`Task`/`Cmd`/`Sub`-bearing record) can be
///   moved but not cloned; a single-use `Clone`-able record is equally well
///   moved.
/// * If the base is a [`Expr::CloneVar`] (multi-use), `emit_expr_at` emits
///   `base.clone()`, and the assignment binds that single clone.
///
/// A base reused OUTSIDE the update (a later borrow or move of a non-`Clone`
/// base) has no sound rewrite and is rejected fail-closed at lower time
/// (`IPE-L0135`); it never reaches this emitter.
///
/// Kept `#[inline(never)]` for the same frame-size reason as [`emit_record`].
#[inline(never)]
pub fn emit_update(
    ctx: &EmitCtx,
    record: &Expr,
    fields: &[(Symbol, Expr)],
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    let child = depth + 1;

    // G2 (update-through-row): when the base record is a row-generic parameter
    // (type `R{n}`, a rustc generic bound by `IpeHasF + IpeWithF`), direct
    // field-mutation is unsound — rustc does not know the concrete struct layout
    // behind `R{n}`. Emit a chain of setter-witness calls instead:
    //   `rec.ipe_with_f1(v1).ipe_with_f2(v2)`
    // Each setter consumes `self` and returns `Self`, so the chain preserves
    // all untouched fields through the `..self` impl body without naming the
    // concrete struct. The base record is moved into the first call and the
    // chain returns `R{n}` — exactly the return type required by G1.
    let record_sym = match record {
        Expr::Var(s) | Expr::CloneVar(s) => Some(*s),
        _ => None,
    };
    if let Some(sym) = record_sym
        && generics.is_row(sym)
    {
        // Evaluate each new field value as a binding first so evaluation
        // order is left-to-right and matches the concrete-struct path.
        let mut binds = Vec::with_capacity(fields.len());
        let mut chain = emit_expr_at(ctx, record, indent, child, generics)?;
        for (i, (field_sym, value)) in fields.iter().enumerate() {
            let field_name = ctx.resolve_ident(*field_sym)?;
            let setter = crate::naming::field_setter_witness_method_name(field_name);
            let rendered = emit_expr_at(ctx, value, indent, child, generics)?;
            binds.push(format!(" let __ipe_upd_{i} = {rendered};"));
            chain = format!("{chain}.{setter}(__ipe_upd_{i})");
        }
        return Ok(format!("{{{} {chain} }}", binds.concat()));
    }

    // Concrete struct path: the record type is a known struct, so direct field
    // mutation via a `let mut __ipe_rec` shadow is sound.
    let mut binds = Vec::with_capacity(fields.len());
    let mut assigns = Vec::with_capacity(fields.len());
    for (i, (sym, value)) in fields.iter().enumerate() {
        let field_ident = ctx.emit_ident(*sym)?;
        let rendered = emit_expr_at(ctx, value, indent, child, generics)?;
        binds.push(format!(" let __ipe_upd_{i} = {rendered};"));
        assigns.push(format!(" __ipe_rec.{field_ident} = __ipe_upd_{i};"));
    }
    let base = emit_expr_at(ctx, record, indent, child, generics)?;
    Ok(format!(
        "{{{} let mut __ipe_rec = {base};{} __ipe_rec }}",
        binds.concat(),
        assigns.concat()
    ))
}

/// Lay a match-arm rebind `prelude` out one statement per line at `indent`.
///
/// The prelude is a run of `let …; ` binder-rebind statements the clone-split
/// helpers build joined by `"; "`; `rustfmt` puts each on its own line. Split on
/// the separator, re-indent each, and return the block (with its trailing
/// newline) — a trailing empty segment is skipped.
pub fn tail_arm_prelude_lines(prelude: &str, indent: usize) -> DResult<String> {
    let pad = indent_of(indent);
    let mut out = String::new();
    for stmt in prelude.split_inclusive("; ") {
        let stmt = stmt.trim_end();
        if stmt.is_empty() {
            continue;
        }
        writeln!(out, "{pad}{stmt}").map_err(|e| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::tail_arm_prelude_lines",
            detail: format!("writing TCO arm prelude failed: {e}"),
        })?;
    }
    Ok(out)
}
