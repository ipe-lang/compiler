use super::{
    ArgPlan, Callee, DResult, Diagnostic, Expr, GenericScope, Guard, IrType, KernelClass, KernelFn,
    LitKind, LowerError, NativeUiEmit, Span, Symbol, UiDelegate, UiEmitPlan,
    appearance_literal_record_fields, callee_name, clone_targets_in_expr, collect_free_vars,
    emit_expr_at, emit_lambda_unboxed, emit_shared_lambda, emit_sub_arm, float_literal, free_vars,
    kernel_name, render_type, shape_appearance_literal_args, ui_call_shape,
};
use crate::EmitCtx;
use core::fmt::Write as _;

/// The clone-rewritten container argument of a call whose runtime takes its
/// arguments reversed ([`Callee::evaluates_args_reversed`], the single source of
/// truth the argument reversal and the lowerer's use-ordering share).
///
/// The reversal renders `k f container` as `k(container, f)`, so `container` is
/// evaluated before `f`'s closure captures. The lowerer's last-use clone rewrite
/// walks the same evaluation order, so a `Clone` binding both use is already
/// cloned at its container read. This rewrite is the backstop for a binding the
/// lowerer's rewrite does not cover: every variable `f` captures is cloned at a
/// CONSUMING read in `container` (borrowing reads stay bare — see
/// [`clone_targets_in_expr`]), so the original survives into the closure
/// instead of being moved first (E0382).
///
/// `None` when the callee does not reverse, the call is not the two-argument
/// `f container` shape, or `f` captures none of `container`'s free variables —
/// the caller then emits `container` unchanged.
pub fn swapped_container_clone_rewrite(callee: &Callee, args: &[Expr]) -> Option<Expr> {
    if !callee.evaluates_args_reversed() {
        return None;
    }
    let [func, container] = args else {
        return None;
    };
    // `container` is typically the small head; collect its vars first so the
    // whole-`func` walk is skipped when it has none.
    let container_vars = free_vars(container);
    if container_vars.is_empty() {
        return None;
    }
    let targets: std::collections::BTreeSet<Symbol> = free_vars(func)
        .intersection(&container_vars)
        .copied()
        .collect();
    if targets.is_empty() {
        return None;
    }
    Some(clone_targets_in_expr(container.clone(), &targets))
}

/// Whether a `Call` node hits one of the bespoke kernel special cases the
/// generic `{name}{turbofish}({args})` tail below does NOT cover — the JSON /
/// Http / Http-builder / Task-retry / Db / TEA / Server / UI probe helpers, or
/// the `Dict.get` clone-arg case. Every one of those probes gates on
/// `Callee::Kernel`, so a non-kernel callee is trivially `false`.
///
/// This is the p'does any special case apply?' predicate the native Doc emitter
/// ([`crate::emit_doc`]) consults to decide whether a `Call` can be structured as
/// the generic delimited tail (special case absent) or must stay a byte-carried
/// leaf (special case present). It re-runs the probes rather than duplicating
/// their per-kernel `KernelFn` matches, so it can never drift from them; the
/// probes take `&EmitCtx` immutably and have no side effects, so re-running them
/// is safe. The rendered strings they return are discarded here.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the emit_expr_at Call arm's probe-chain arguments verbatim"
)]
pub fn call_has_kernel_special_case(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    on_form: ipe_ir::OnFormKind,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<bool> {
    // Only kernels have special cases; every probe would gate out immediately.
    let Callee::Kernel(k) = callee else {
        return Ok(false);
    };
    // These `emit_*_call` invocations are discard-only *probes* — their emitted
    // text is thrown away; only whether they fire matters. Suppress style-literal
    // hoisting for the duration so a probe does not append a literal the real
    // emit will append again (which would double-count it in the view's table).
    //
    // Routed on `KernelFn::def().class` in the SAME wildcard-free shape as the
    // real dispatcher (`emit_expr_at`'s `Expr::Call` arm), so this predicate can
    // never drift from it: each arm probes only the emitters that arm dispatches,
    // and a new `KernelClass` variant is a compile error here too. (The two
    // `Ipe.Ui`/`Ipe.Html` hot-swap template probes the real dispatcher runs
    // before `emit_ui_call` are omitted: they only fire under
    // `IPE_WATCH_HOT_APPEARANCE`, which the Doc emitter never has armed, so they
    // return `None` and cannot change this predicate's answer.)
    ctx.enter_probe();
    let probe: DResult<bool> = (|| {
        Ok(match k.def().class {
            // `DbDecSucceed` is `class = Db` but its special case lives in
            // `emit_json_decoder_call` (shared `decode_succeed` currying), which
            // `emit_db_call` returns `None` for — probe it first, as the real
            // dispatcher does.
            KernelClass::Db => {
                emit_json_decoder_call(ctx, callee, args, indent, child, generics)?.is_some()
                    || emit_db_call(ctx, callee, args, indent, child, generics)?.is_some()
            }
            KernelClass::Server => {
                emit_server_call(ctx, callee, args, indent, child, generics)?.is_some()
            }
            // `TeaWorker` is `class = Tea` but emits through the UI delegate
            // chain (`emit_ui_call` → `Delegate(Worker)`); probe it first, exactly
            // as the real dispatcher does, then fall back to the standard TEA emit.
            KernelClass::Tea => {
                emit_ui_call(ctx, callee, args, on_form, indent, child, generics)?.is_some()
                    || emit_tea_call(ctx, callee, args, indent, child, generics)?.is_some()
            }
            // `Ui`/`Web` kernels and the `Terminal` app-entries
            // (`TerminalAppScreen` / `TerminalAppLines`, which route to the
            // Tui/Console delegate emitters inside `emit_ui_call`) all have a
            // bespoke special case.
            KernelClass::Ui | KernelClass::Web | KernelClass::Terminal => {
                emit_ui_call(ctx, callee, args, on_form, indent, child, generics)?.is_some()
            }
            // Reserved tier: no kernel is classed Ffi. Present (not a wildcard) so
            // adding one without a decision here breaks the build rather than
            // silently reporting "no special case".
            KernelClass::Ffi => {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::call_has_kernel_special_case",
                    detail: "reached KernelClass::Ffi probe arm; no kernel is classed Ffi, \
                         so this call site should be unreachable — a new FFI kernel needs \
                         an explicit probe decision here"
                        .to_owned(),
                });
            }
            KernelClass::Pure => {
                emit_json_decoder_call(ctx, callee, args, indent, child, generics)?.is_some()
                    || emit_http_call(ctx, callee, args, indent, child, generics)?.is_some()
                    || emit_process_run_with_call(ctx, callee, args, indent, child, generics)?
                        .is_some()
                    || emit_process_run_in_pty_call(ctx, callee, args, indent, child, generics)?
                        .is_some()
                    || emit_http_builder_call(ctx, callee, args, indent, child, generics)?
                        .is_some()
                    || emit_task_retry_call(ctx, callee, args, indent, child, generics)?.is_some()
                    // `Db.defaultMigration` is `class = Pure` but `emit_db_call`
                    // synthesises its `Migration` record literal — probe it here, as
                    // the real dispatcher does. Every other Pure kernel is not a Db
                    // kernel and returns `None`.
                    || emit_db_call(ctx, callee, args, indent, child, generics)?.is_some()
                    || emit_config_ctor_call(callee).is_some()
                    // The `TermColor*` palette constructors are `class = Pure` but
                    // classified by `ui_call_shape`, so `emit_ui_call` is their
                    // special case (appearance-literal hoisting). Every other Pure
                    // kernel is not UI-family and returns `None` here. (The two
                    // hot-swap template probes are omitted for the same reason as in
                    // the Ui/Web arm: the Doc emitter never arms `hot_appearance`.)
                    || emit_ui_call(ctx, callee, args, on_form, indent, child, generics)?.is_some()
                    || emit_css_value_call(ctx, callee, args, indent, child, generics)?.is_some()
                    // `PubSub.topic` is the identity function — `Topic a` erases to
                    // `Str`, so the call renders as its argument directly (the
                    // `KernelFn::PubSubTopic` arm in `emit_expr_at`). No `pubsub_topic`
                    // runtime fn exists to route the generic tail to; routing this
                    // through `leaf` keeps the erasure uniform across the direct-call
                    // and CAF/`OnceLock` paths.
                    || matches!(k, KernelFn::PubSubTopic)
                    // `Dict.get` clones its dict arg — the generic tail would drop the
                    // `.clone()`.
                    || matches!(k, KernelFn::DictGet)
            }
        })
    })();
    ctx.exit_probe();
    probe
}

/// Handle Http kernel calls that require custom argument wrapping.
///
/// Returns `Some(emitted)` for the three network-effect kernels
/// (`HttpGet` / `HttpPost` / `HttpRequest`), which need a `task_map`
/// closure that converts `ipe_runtime::HttpResponse` into the synthesised
/// Ipê record struct for `{body, headers, status}`.
///
/// `HttpParseQuery` returns `HashMap<String,String>` which is exactly
/// `Dict String String` — the standard `Expr::Call` emitter is correct
/// and this function returns `None` for it.
///
/// The conversion is a PURE FIELD-FOR-FIELD MOVE — no validation, no
/// second parse boundary. All guards (SSRF, body cap, timeout, error
/// redaction) live inside the runtime entry points; the emitter only
/// wraps the response record.
///
/// All three network kernels emit explicit `::<IpeError>` turbofish so
/// Rust can infer the error channel even when the `Err` arm is discarded.
/// The closure parameter is typed `|r: ipe_runtime::HttpResponse|` so
/// the closure's input type is never ambiguous.
///
/// Factored out of `emit_expr_at` to keep that function's stack frame
/// small (matching the `emit_json_decoder_call` pattern).
/// Emit the typed-target request builders — `Http.defaultRequest` (Url) /
/// `Http.defaultRequestFromString` (String) / `Http.withUrl` (Url, req). Each
/// returns `Result Error HttpRequest`; the error channel appears only in the
/// result, so an explicit `::<IpeError>` turbofish anchors `E`. The
/// fail-closed http/https scheme narrowing lives in the runtime fns these call.
/// Returns `None` for any other callee.
#[inline(never)]
pub fn emit_http_typed_target_builder(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    match callee {
        Callee::Kernel(
            k @ (KernelFn::HttpDefaultRequest | KernelFn::HttpDefaultRequestFromString),
        ) => {
            let arg = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_typed_target_builder",
                detail: "typed-target builder expects exactly 1 argument".to_owned(),
            })?;
            let arg_str = emit_expr_at(ctx, arg, indent, child, generics)?;
            let name = kernel_name(*k);
            Ok(Some(format!(
                "ipe_runtime::http_client::{name}::<IpeError>({arg_str})"
            )))
        }
        Callee::Kernel(KernelFn::HttpWithUrl) => {
            let url = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_typed_target_builder",
                detail: "HttpWithUrl expects 2 arguments (url, req)".to_owned(),
            })?;
            let req = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_typed_target_builder",
                detail: "HttpWithUrl expects 2 arguments (url, req)".to_owned(),
            })?;
            let url_str = emit_expr_at(ctx, url, indent, child, generics)?;
            let req_str = emit_expr_at(ctx, req, indent, child, generics)?;
            Ok(Some(format!(
                "ipe_runtime::http_client::http_with_url::<IpeError>({url_str}, {req_str})"
            )))
        }
        _ => Ok(None),
    }
}

#[inline(never)]
pub fn emit_http_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    // The three network kernels plus the three typed-target builders need
    // special treatment: all carry an error channel that appears only in the
    // `Result Error _` / `Task Error _` result, so Rust cannot infer the `E`
    // type parameter when the `Err` arm is discarded. Each is emitted with an
    // explicit `::<IpeError>` turbofish. The typed-target builders return a
    // `Result Error HttpRequest` directly (no `task_map` wrapping), so they are
    // handled by `emit_http_typed_target_builder` before the response-shaping
    // network kernels below.
    if let Some(emitted) =
        emit_http_typed_target_builder(ctx, callee, args, indent, child, generics)?
    {
        return Ok(Some(emitted));
    }
    let Callee::Kernel(k @ (KernelFn::HttpGet | KernelFn::HttpPost | KernelFn::HttpRequest)) =
        callee
    else {
        return Ok(None);
    };

    // Resolve the synthesised struct name for the HttpResponse field set
    // {body, headers, status}. The field set is sorted alphabetically;
    // these three names are already in alphabetical order.
    let resp_key: Vec<String> = vec!["body".to_owned(), "headers".to_owned(), "status".to_owned()];
    let resp_struct =
        ctx.record_struct_by_key(&resp_key, None)
            .map_err(|_| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_call",
                detail: "no synthesised struct for HttpResponse fieldset {body, headers, status}; \
                     the lowerer must surface the HttpResponse record type before emission"
                    .to_owned(),
            })?;
    let resp_name = &resp_struct.name;

    // Build the task_map conversion closure shared by all three variants.
    // The closure is a pure field-for-field move — soundness note: all
    // fields are owned (String / i64 / HashMap), no borrows, no boxing.
    let conv = format!(
        "|r: ipe_runtime::HttpResponse| {resp_name} {{ \
         body: r.body, headers: r.headers, status: r.status }}"
    );

    match k {
        KernelFn::HttpGet => {
            // Http.get : Url -> Task Error HttpResponse
            // args[0] = url : Url (already-sealed; emits as ipe_runtime::url::Url)
            let url = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_call",
                detail: "HttpGet expects exactly 1 argument (url)".to_owned(),
            })?;
            let url_s = emit_expr_at(ctx, url, indent, child, generics)?;
            Ok(Some(format!(
                "task_map(Box::new({conv}), \
                 ipe_runtime::http_client::http_get::<IpeError>({url_s}))"
            )))
        }
        KernelFn::HttpPost => {
            // Http.post : Url -> String -> Task Error HttpResponse
            // args[0] = url : Url (already-sealed), args[1] = body : String
            let url = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_call",
                detail: "HttpPost expects 2 arguments (url, body)".to_owned(),
            })?;
            let body_arg = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_call",
                detail: "HttpPost expects 2 arguments (url, body)".to_owned(),
            })?;
            let url_s = emit_expr_at(ctx, url, indent, child, generics)?;
            let body_s = emit_expr_at(ctx, body_arg, indent, child, generics)?;
            Ok(Some(format!(
                "task_map(Box::new({conv}), \
                 ipe_runtime::http_client::http_post::<IpeError>({url_s}, {body_s}))"
            )))
        }
        KernelFn::HttpRequest => {
            // Http.request : HttpRequest -> Task Error HttpResponse
            // args[0] = req : HttpRequest
            //
            // `HttpRequest` is the opaque nominal type `ir_type_from_ty`
            // folds any solved record shape matching the canonical
            // {body, headers, method, redirects, timeout, url} field set into
            // (`ipe_lower::lower::ir_type_from_ty`'s HTTP_REQUEST_FIELDS special
            // case) — it is ALWAYS backed by `ipe_runtime::HttpRequest`, never a
            // backend-synthesised `record_by_fieldset` struct.  So `req_expr`'s
            // emitted Rust value already has the runtime's field names —
            // no `record_struct_by_key` lookup needed here.
            let req_expr = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_call",
                detail: "HttpRequest expects exactly 1 argument (req record)".to_owned(),
            })?;
            let req_s = emit_expr_at(ctx, req_expr, indent, child, generics)?;
            // Bind the synthesised request struct once (`__req`) and move each
            // field exactly once into `ipe_runtime::HttpRequest`.
            Ok(Some(format!(
                "({{ let __req = {req_s}; task_map(Box::new({conv}), \
                 ipe_runtime::http_client::http_request::<IpeError>(\
                 ipe_runtime::HttpRequest {{ \
                 body: __req.body, headers: __req.headers, method: __req.method, \
                 redirects: __req.redirects, timeout: __req.timeout, \
                 url: __req.url }}))\
                 }})"
            )))
        }
        // The non-network Http kernels (HttpParseQuery) fall through to
        // `None` — handled above by the `match k` guard.
        _ => Ok(None),
    }
}

/// Handle `Process.runWith` kernel calls.
///
/// `process_run_with` in the runtime returns `ipe_runtime::system::ProcessRunOutput`
/// (a runtime-owned struct with fields `exitCode`, `stdout`, `stderr`), while the
/// emitted user code treats the result as the synthesised record struct for
/// `{ exitCode, stderr, stdout }`.  A `task_map` closure converts one to the other
/// at the call site — the same Design B used by `emit_http_call` for `HttpResponse`.
///
/// Returns `None` for any other callee.
#[inline(never)]
pub fn emit_process_run_with_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    let Callee::Kernel(KernelFn::ProcessRunWith) = callee else {
        return Ok(None);
    };

    // Resolve the synthesised struct name for the `{ exitCode, stderr, stdout }` field set.
    // Fields are sorted alphabetically: exitCode < stderr < stdout.
    let resp_key: Vec<String> = vec![
        "exitCode".to_owned(),
        "stderr".to_owned(),
        "stdout".to_owned(),
    ];
    let resp_struct =
        ctx.record_struct_by_key(&resp_key, None)
            .map_err(|_| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_process_run_with_call",
                detail: "no synthesised struct for ProcessRunOutput fieldset \
                     {exitCode, stderr, stdout}; the lowerer must surface the \
                     runWith return record type before emission"
                    .to_owned(),
            })?;
    let resp_name = &resp_struct.name;

    // Build the task_map conversion closure: pure field-for-field move.
    // All fields are owned (i64 / String), no borrows, no boxing.
    let conv = format!(
        "|__r: ipe_runtime::system::ProcessRunOutput| {resp_name} {{ \
         exitCode: __r.exitCode, stderr: __r.stderr, stdout: __r.stdout }}"
    );

    let cfg_arg = args.first().ok_or_else(|| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::emit_process_run_with_call",
        detail: "ProcessRunWith expects exactly 1 argument (cfg record)".to_owned(),
    })?;
    let cfg_s = emit_expr_at(ctx, cfg_arg, indent, child, generics)?;

    Ok(Some(format!(
        "task_map(Box::new({conv}), \
         ipe_runtime::system::process_run_with::<IpeError>({cfg_s}))"
    )))
}

/// `process_run_in_pty` in the runtime returns `ipe_runtime::system::ProcessPtyOutput`
/// (fields `exitCode`, `output`), while emitted user code treats the result as the
/// synthesised record struct for `{ exitCode, output }`. A `task_map` closure
/// converts one to the other at the call site — same Design B as
/// [`emit_process_run_with_call`].
///
/// Returns `None` for any other callee.
#[inline(never)]
pub fn emit_process_run_in_pty_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    let Callee::Kernel(KernelFn::ProcessRunInPty) = callee else {
        return Ok(None);
    };

    // Resolve the synthesised struct name for the `{ exitCode, output }` field
    // set. Fields are sorted alphabetically: exitCode < output.
    let resp_key: Vec<String> = vec!["exitCode".to_owned(), "output".to_owned()];
    let resp_struct =
        ctx.record_struct_by_key(&resp_key, None)
            .map_err(|_| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_process_run_in_pty_call",
                detail: "no synthesised struct for ProcessPtyOutput fieldset \
                     {exitCode, output}; the lowerer must surface the \
                     runInPty return record type before emission"
                    .to_owned(),
            })?;
    let resp_name = &resp_struct.name;

    // Build the task_map conversion closure: pure field-for-field move.
    // All fields are owned (i64 / String), no borrows, no boxing.
    let conv = format!(
        "|__r: ipe_runtime::system::ProcessPtyOutput| {resp_name} {{ \
         exitCode: __r.exitCode, output: __r.output }}"
    );

    let cfg_arg = args.first().ok_or_else(|| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::emit_process_run_in_pty_call",
        detail: "ProcessRunInPty expects exactly 1 argument (cfg record)".to_owned(),
    })?;
    let cfg_s = emit_expr_at(ctx, cfg_arg, indent, child, generics)?;

    Ok(Some(format!(
        "task_map(Box::new({conv}), \
         ipe_runtime::system::process_run_in_pty::<IpeError>({cfg_s}))"
    )))
}

/// Handle Http builder kernel calls that emit inline struct construction or
/// clone-and-reassign record updates.
///
/// Returns `Some(emitted)` for the eight pure builder kernels:
///
/// The typed-target builders (`HttpDefaultRequest` /
/// `HttpDefaultRequestFromString` / `HttpWithUrl`) are NOT handled here: they go
/// through the standard call path to runtime fns that perform the fail-closed
/// http/https scheme narrowing and return `Result Error HttpRequest`.
///
/// * **`HttpWithMethod m req`**, **`HttpWithTimeout t req`**,
///   **`HttpWithBody b req`**, **`HttpWithRedirects p req`**
///   — each emits a clone-and-reassign
///   block
///   (`{ let mut __ipe_rec = (req).clone(); __ipe_rec.field = val; __ipe_rec }`)
///   matching the `emit_update` pattern so the source record is moved once.
///
/// * **`HttpWithHeader k v req`** — emits a prepend:
///   `{ let mut __ipe_rec = (req).clone(); __ipe_rec.headers.insert(0, (k, v)); __ipe_rec }`.
///   PREPEND (cons-prepend) matches the the reference implementation in `Http.ipe`
///   (`{ req | headers = (k, v) :: req.headers }`), so `withHeader "B" "2"` after
///   `withHeader "A" "1"` yields `B:2,A:1` in iteration order.
///
/// Returns `None` for any other callee — the caller falls through to the
/// standard call path. Factored out of `emit_expr_at` to keep its stack frame
/// small (same rationale as `emit_http_call`).
#[inline(never)]
#[allow(clippy::too_many_lines)] // 8 match arms × ~20 lines = inherently verbose but linear
pub fn emit_http_builder_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    let Callee::Kernel(
        k @ (KernelFn::HttpWithMethod
        | KernelFn::HttpWithTimeout
        | KernelFn::HttpWithBody
        | KernelFn::HttpWithHeader
        | KernelFn::HttpWithRedirects),
    ) = callee
    else {
        return Ok(None);
    };

    // `HttpRequest` is the opaque nominal type `ir_type_from_ty` folds any
    // solved record shape matching the canonical {body, headers, method,
    // redirects, timeout, url} field set into
    // (`ipe_lower::lower::ir_type_from_ty`'s HTTP_REQUEST_FIELDS special
    // case) — it is ALWAYS backed by `ipe_runtime::HttpRequest`, never a
    // backend-synthesised `record_by_fieldset` struct. So `HttpDefaultRequest`
    // emits the fixed runtime type name directly rather than looking up a
    // synthesised struct: that struct only exists incidentally (when some OTHER
    // signature in the program happens to also carry the same 7-field shape as
    // a plain, non-opaque record — e.g. an explicitly-annotated function
    // parameter). A program whose only `HttpRequest` consumer reads a field or
    // calls `Http.request`/`HttpStream.open` — never spelling the fieldset out
    // in an annotation — synthesises no such struct, and a lookup would hit
    // IPE-I0001. Emitting the fixed runtime type name removes the dependency
    // entirely.
    match k {
        KernelFn::HttpWithMethod => {
            // withMethod : HttpMethod -> HttpRequest -> HttpRequest
            let m = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithMethod expects 2 arguments (method, req)".to_owned(),
            })?;
            let req = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithMethod expects 2 arguments (method, req)".to_owned(),
            })?;
            let m_s = emit_expr_at(ctx, m, indent, child, generics)?;
            let req_s = emit_expr_at(ctx, req, indent, child, generics)?;
            Ok(Some(format!(
                "{{ let mut __ipe_rec = ({req_s}).clone(); \
                 __ipe_rec.method = {m_s}; __ipe_rec }}"
            )))
        }
        KernelFn::HttpWithTimeout => {
            // withTimeout : Duration -> HttpRequest -> HttpRequest
            //
            // The timeout is a typed `Ipe.Duration` (opaque, non-negative); the
            // transport DTO's `timeout` field is raw `i64` milliseconds. Unwrap
            // the span through the compiled-module accessor `Ipe.Duration.toMillis`
            // before it lands in the field — the same unwrap the pure-`.ipe`
            // siblings (`WebSocket.withTimeout` / `Cache.withTTL`) perform in
            // source. `module_value` is the naming SSOT shared with the accessor's
            // definition site, so the emitted call name matches by construction.
            let t = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithTimeout expects 2 arguments (timeout, req)".to_owned(),
            })?;
            let req = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithTimeout expects 2 arguments (timeout, req)".to_owned(),
            })?;
            let t_s = emit_expr_at(ctx, t, indent, child, generics)?;
            let req_s = emit_expr_at(ctx, req, indent, child, generics)?;
            let to_millis = crate::naming::module_value(&["Ipe", "Duration"], "toMillis");
            Ok(Some(format!(
                "{{ let mut __ipe_rec = ({req_s}).clone(); \
                 __ipe_rec.timeout = crate::{to_millis}({t_s}); __ipe_rec }}"
            )))
        }
        KernelFn::HttpWithBody => {
            // withBody : String -> HttpRequest -> HttpRequest
            let b = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithBody expects 2 arguments (body, req)".to_owned(),
            })?;
            let req = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithBody expects 2 arguments (body, req)".to_owned(),
            })?;
            let b_s = emit_expr_at(ctx, b, indent, child, generics)?;
            let req_s = emit_expr_at(ctx, req, indent, child, generics)?;
            Ok(Some(format!(
                "{{ let mut __ipe_rec = ({req_s}).clone(); \
                 __ipe_rec.body = {b_s}; __ipe_rec }}"
            )))
        }
        KernelFn::HttpWithRedirects => {
            // withRedirects : RedirectPolicy -> HttpRequest -> HttpRequest
            let policy = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithRedirects expects 2 arguments (policy, req)".to_owned(),
            })?;
            let req = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithRedirects expects 2 arguments (policy, req)".to_owned(),
            })?;
            let policy_src = emit_expr_at(ctx, policy, indent, child, generics)?;
            let req_s = emit_expr_at(ctx, req, indent, child, generics)?;
            Ok(Some(format!(
                "{{ let mut __ipe_rec = ({req_s}).clone(); \
                 __ipe_rec.redirects = {policy_src}; __ipe_rec }}"
            )))
        }
        KernelFn::HttpWithHeader => {
            // withHeader : String -> String -> HttpRequest -> HttpRequest
            // PREPENDS (key, value) — matches the reference `(k,v) :: req.headers`.
            let k_arg = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithHeader expects 3 arguments (key, value, req)".to_owned(),
            })?;
            let v_arg = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithHeader expects 3 arguments (key, value, req)".to_owned(),
            })?;
            let req = args.get(2).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_http_builder_call",
                detail: "HttpWithHeader expects 3 arguments (key, value, req)".to_owned(),
            })?;
            let k_s = emit_expr_at(ctx, k_arg, indent, child, generics)?;
            let v_s = emit_expr_at(ctx, v_arg, indent, child, generics)?;
            let req_s = emit_expr_at(ctx, req, indent, child, generics)?;
            Ok(Some(format!(
                "{{ let mut __ipe_rec = ({req_s}).clone(); \
                 __ipe_rec.headers.insert(0, ({k_s}, {v_s})); __ipe_rec }}"
            )))
        }
        // Unreachable: the guard at the top of this function constrains `k` to the
        // record-update builder variants matched above. The `_ =>` arm keeps Rust's
        // exhaustiveness checker satisfied without introducing a catch-all over the
        // full `KernelFn` set (which would violate the no-catch-all principle for
        // the logic above).
        _ => Ok(None),
    }
}

/// Handle Db kernel calls that require `SqlValue` / `SqlField` boundary
/// projection.
///
/// The Ipê surface for parameterised Db calls (`Db.exec`, `Db.query`,
/// `Db.queryDecode`, `Db.insertFields`, `Db.updateFields`, `Db.upsertFields`,
/// `Db.insertFieldsReturning`) passes a `List SqlValue` or
/// `List (String, SqlField)` as a plain Ipê argument. The runtime's typed-param
/// functions (`db_exec_params`, `db_query_params`, …) expect `Vec<SqlParam>` /
/// `Vec<(String, Option<SqlParam>)>`. The projection is emitted INLINE at the
/// call site — the Ipê list is converted with a short `.into_iter().map(…)`
/// chain so the compiler never needs separate IR types for the two.
///
/// Kernels that accept only `Db` / `String` / `Int` / plain Dict arguments (no
/// `SqlValue` / `SqlField` in the parameter list) return `None` here and fall
/// through to the standard `name(args)` path.
///
/// Factored out of `emit_expr_at` to keep that function's stack frame small
/// (same rationale as `emit_http_call`).
#[inline(never)]
#[allow(clippy::too_many_lines)]
// linear dispatch over many projection cases
/// Emit `Task.retryWith` and all `RetryPolicy` builder kernels.
///
/// Design rationale:
/// - `RetryPolicy e` is a closed record with a function field `shouldRetry : e ->
///   Bool`.  The synthesised struct stores that field on the record-field
///   function carrier — `Arc<dyn Fn(E) -> bool + Send + Sync>` — so the struct
///   derives `Clone`.  Every `shouldRetry` value this emitter constructs must
///   therefore be produced ON that carrier (`Arc::new` for a literal predicate,
///   `Arc::from` to promote an already-boxed predicate expression), or the field
///   assignment is an `Arc`-vs-`Box` type mismatch (`E0308`).  The builder
///   updates still MOVE the record (`let mut __ipe_rec = (rec); __ipe_rec.field =
///   val; __ipe_rec`) — an `Arc<dyn Fn>` is `Clone`, but a move is cheaper and
///   the record is single-use here.
/// - `Task.retryWith` decomposes the policy and calls the runtime function
///   `ipe_runtime::task::task_retry_with`, adapting the `Arc<dyn Fn(E) -> bool>`
///   field to the `impl Fn(&E) -> bool` expected by the runtime via a cloning
///   adapter closure (an `Arc<dyn Fn>` is directly callable).
pub fn emit_task_retry_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    let Callee::Kernel(
        k @ (KernelFn::TaskRetryWith
        | KernelFn::TaskLinearBackoff
        | KernelFn::TaskExponentialBackoff
        | KernelFn::TaskWithJitter
        | KernelFn::TaskRetryOn
        | KernelFn::TaskWithRetryOn
        | KernelFn::TaskDefaultRetryPolicy
        | KernelFn::TaskWithMaxAttempts
        | KernelFn::TaskWithBaseMs
        | KernelFn::BackoffLinear
        | KernelFn::BackoffLinearWithJitter
        | KernelFn::BackoffExponential
        | KernelFn::BackoffExponentialWithJitter),
    ) = callee
    else {
        return Ok(None);
    };

    // `RetryPolicy e = { baseMs, maxAttempts, shouldRetry, strategy }` —
    // alphabetical BTreeMap order matches the emitted struct name.
    let rp_key: Vec<String> = vec![
        "baseMs".to_owned(),
        "maxAttempts".to_owned(),
        "shouldRetry".to_owned(),
        "strategy".to_owned(),
    ];
    // Only builders that construct a new struct need the struct name.
    // For the pure move-update builders (TaskWithJitter etc.) we look it up too
    // so the pattern is consistent; a missing struct signals a lowering bug.
    let rp_name = ctx
        .record_struct_by_key(&rp_key, None)
        .map_err(|_| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_task_retry_call",
            detail: "no synthesised struct for RetryPolicy fieldset \
                 {baseMs, maxAttempts, shouldRetry, strategy}; \
                 the lowerer must surface the RetryPolicy record type before emission"
                .to_owned(),
        })?
        .name
        .clone();

    match k {
        KernelFn::TaskDefaultRetryPolicy => {
            // `defaultRetryPolicy : RetryPolicy e` — 0-arg, emit inline literal.
            // 3 attempts, 500 ms, exponential with jitter, always-retry.
            Ok(Some(format!(
                "{rp_name} {{ baseMs: 500i64, maxAttempts: 3i64, \
                 shouldRetry: ::std::sync::Arc::new(|_: IpeError| true), \
                 strategy: ipe_runtime::task::BackoffStrategy::ExponentialWithJitter }}"
            )))
        }
        KernelFn::TaskLinearBackoff => {
            // `linearBackoff maxAttempts delayMs` — constant delay, Linear strategy.
            let n = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskLinearBackoff expects 2 arguments (maxAttempts, delayMs)".to_owned(),
            })?;
            let ms = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskLinearBackoff expects 2 arguments (maxAttempts, delayMs)".to_owned(),
            })?;
            let n_s = emit_expr_at(ctx, n, indent, child, generics)?;
            let ms_s = emit_expr_at(ctx, ms, indent, child, generics)?;
            Ok(Some(format!(
                "{rp_name} {{ baseMs: {ms_s}, maxAttempts: {n_s}, \
                 shouldRetry: ::std::sync::Arc::new(|_: IpeError| true), \
                 strategy: ipe_runtime::task::BackoffStrategy::Linear }}"
            )))
        }
        KernelFn::TaskExponentialBackoff => {
            // `exponentialBackoff maxAttempts baseMs` — exponential, Exponential strategy.
            let n = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskExponentialBackoff expects 2 arguments (maxAttempts, baseMs)"
                    .to_owned(),
            })?;
            let ms = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskExponentialBackoff expects 2 arguments (maxAttempts, baseMs)"
                    .to_owned(),
            })?;
            let n_s = emit_expr_at(ctx, n, indent, child, generics)?;
            let ms_s = emit_expr_at(ctx, ms, indent, child, generics)?;
            Ok(Some(format!(
                "{rp_name} {{ baseMs: {ms_s}, maxAttempts: {n_s}, \
                 shouldRetry: ::std::sync::Arc::new(|_: IpeError| true), \
                 strategy: ipe_runtime::task::BackoffStrategy::Exponential }}"
            )))
        }
        KernelFn::TaskWithJitter => {
            // `withJitter policy` — upgrade strategy to its jitter variant.
            // Linear → LinearWithJitter, Exponential → ExponentialWithJitter.
            let policy = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskWithJitter expects 1 argument (policy)".to_owned(),
            })?;
            let policy_s = emit_expr_at(ctx, policy, indent, child, generics)?;
            Ok(Some(format!(
                "{{ \
                 let mut __ipe_rec = ({policy_s}); \
                 __ipe_rec.strategy = match __ipe_rec.strategy {{ \
                 ipe_runtime::task::BackoffStrategy::Linear => \
                     ipe_runtime::task::BackoffStrategy::LinearWithJitter, \
                 ipe_runtime::task::BackoffStrategy::Exponential => \
                     ipe_runtime::task::BackoffStrategy::ExponentialWithJitter, \
                 other => other, \
                 }}; \
                 __ipe_rec }}"
            )))
        }
        KernelFn::TaskWithMaxAttempts => {
            // `withMaxAttempts n policy` — move-update maxAttempts.
            let n = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskWithMaxAttempts expects 2 arguments (n, policy)".to_owned(),
            })?;
            let policy = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskWithMaxAttempts expects 2 arguments (n, policy)".to_owned(),
            })?;
            let n_s = emit_expr_at(ctx, n, indent, child, generics)?;
            let policy_s = emit_expr_at(ctx, policy, indent, child, generics)?;
            Ok(Some(format!(
                "{{ let mut __ipe_rec = ({policy_s}); __ipe_rec.maxAttempts = {n_s}; __ipe_rec }}"
            )))
        }
        KernelFn::TaskWithBaseMs => {
            // `withBaseMs ms policy` — move-update baseMs.
            let ms = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskWithBaseMs expects 2 arguments (ms, policy)".to_owned(),
            })?;
            let policy = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskWithBaseMs expects 2 arguments (ms, policy)".to_owned(),
            })?;
            let ms_s = emit_expr_at(ctx, ms, indent, child, generics)?;
            let policy_s = emit_expr_at(ctx, policy, indent, child, generics)?;
            Ok(Some(format!(
                "{{ let mut __ipe_rec = ({policy_s}); __ipe_rec.baseMs = {ms_s}; __ipe_rec }}"
            )))
        }
        KernelFn::BackoffLinear => Ok(Some(
            "ipe_runtime::task::BackoffStrategy::Linear".to_owned(),
        )),
        KernelFn::BackoffLinearWithJitter => Ok(Some(
            "ipe_runtime::task::BackoffStrategy::LinearWithJitter".to_owned(),
        )),
        KernelFn::BackoffExponential => Ok(Some(
            "ipe_runtime::task::BackoffStrategy::Exponential".to_owned(),
        )),
        KernelFn::BackoffExponentialWithJitter => Ok(Some(
            "ipe_runtime::task::BackoffStrategy::ExponentialWithJitter".to_owned(),
        )),
        KernelFn::TaskRetryOn | KernelFn::TaskWithRetryOn => {
            // `retryOn pred policy` / `withRetryOn pred policy` — move-update shouldRetry.
            let pred = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskRetryOn/TaskWithRetryOn expects 2 arguments (pred, policy)".to_owned(),
            })?;
            let policy = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskRetryOn/TaskWithRetryOn expects 2 arguments (pred, policy)".to_owned(),
            })?;
            let pred_s = emit_expr_at(ctx, pred, indent, child, generics)?;
            let policy_s = emit_expr_at(ctx, policy, indent, child, generics)?;
            // The `shouldRetry` field carrier is `Arc<dyn Fn(IpeError) -> bool>`
            // (record-field function carrier). Re-wrap the predicate — carried as
            // a `Box<dyn Fn>` (or a bare closure) — in a fresh `Arc` closure of
            // the field's exact signature so the move-update assigns the field's
            // own carrier type, not a `Box` (which would be an `E0308`).
            Ok(Some(format!(
                "{{ let mut __ipe_rec = ({policy_s}); \
                 __ipe_rec.shouldRetry = ::std::sync::Arc::new(\
                 move |__ipe_x: IpeError| ({pred_s})(__ipe_x)); __ipe_rec }}"
            )))
        }
        KernelFn::TaskRetryWith => {
            // `retryWith policy task` — decompose policy, call runtime.
            // The `shouldRetry` field is `Arc<dyn Fn(IpeError) -> bool>` (directly
            // callable) but `task_retry_with` expects `impl Fn(&IpeError) -> bool`.
            // The adapter closure bridges the gap by cloning the (cheap String)
            // error ref.
            let policy = args.first().ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskRetryWith expects 2 arguments (policy, task)".to_owned(),
            })?;
            let task = args.get(1).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_task_retry_call",
                detail: "TaskRetryWith expects 2 arguments (policy, task)".to_owned(),
            })?;
            let policy_s = emit_expr_at(ctx, policy, indent, child, generics)?;
            let task_s = emit_expr_at(ctx, task, indent, child, generics)?;
            Ok(Some(format!(
                "{{ \
                 let __ipe_p = {policy_s}; \
                 let __ipe_sr = __ipe_p.shouldRetry; \
                 ipe_runtime::task::task_retry_with(\
                 __ipe_p.maxAttempts, \
                 __ipe_p.baseMs, \
                 __ipe_p.strategy, \
                 move |__ipe_e: &IpeError| (__ipe_sr)(__ipe_e.clone()), \
                 move || {{ {task_s} }}\
                 ) }}"
            )))
        }
        _ => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_task_retry_call",
            detail: "non-retry kernel reached retry dispatch arm — guard should have excluded it"
                .to_owned(),
        }),
    }
}

// The match below lists standard-path Db kernels explicitly (same Ok(None) body
// as the wildcard) so that any future param-taking Db kernel added to `KernelFn`
// that NEEDS a custom arm causes a *compile error* here — not a silent
// exit-0-then-cargo-fail when `_ => Ok(None)` swallows it.
// `match_same_arms` fires because both the list and `_` return `Ok(None)`; the
// documentation value justifies the suppression.  `too_many_lines` fires because
// the function explicitly enumerates every Db kernel arm for compile-time
// completeness; extracting sub-helpers would hide the intentional coverage.
#[allow(clippy::match_same_arms, clippy::too_many_lines)]
pub fn emit_db_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    // Fast path: not a Db kernel at all.
    let Callee::Kernel(k) = callee else {
        return Ok(None);
    };

    // Helper: emit a single arg by index, returning a CompilerBug on miss.
    macro_rules! arg {
        ($idx:expr, $name:literal) => {
            args.get($idx).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_db_call",
                detail: format!("Db kernel {:?} missing arg[{}] ({})", k, $idx, $name),
            })
        };
    }

    // Projection snippets.
    //
    // `project_params(s)` — `List a` → `Vec<SqlParam>`
    //
    // Maps via `Into::into` (NOT `SqlParam::from`) and collects into the
    // EXPLICIT `Vec<ipe_runtime::db::SqlParam>` (not `Vec<_>`), so the
    // projection compiles both for a concrete element type AND for a still-
    // generic one:
    //   • `String` / `i64` / `f64` / `bool` / `StdDbSqlValue` — each has a
    //     `From<T> for SqlParam` impl in the runtime (the generated one is
    //     emitted by `ipe_backend_rust::project::emit_db_projection_impls`);
    //     std's blanket `impl<T, U: From<T>> Into<U> for T` makes `.into()`
    //     resolve identically to the old `SqlParam::from(x)` call for every
    //     one of them — no behaviour change for a concrete element type.
    //   • A still-generic `T{n}` (a Ipê wrapper function forwarding its own
    //     `List a` parameter into `Db.exec` / `Db.query` / `Db.queryDecode`,
    //     e.g. `Database.exec label sql args` in `examples/17-ipemon`) can
    //     only be bounded via the STANDARD `<T{n}: Trait>` generic-parameter
    //     list — a `where SqlParam: From<T{n}>` clause bounds the WRONG type
    //     (`SqlParam`, not `T{n}`) and cannot be expressed that way. The
    //     lowerer's `BoundSet::SQL_PARAM` instead emits `T{n}: …
    //     Into<ipe_runtime::db::SqlParam>` (see `render_bounds`), which
    //     `.into()` — but NOT `SqlParam::from` — can actually call inside a
    //     still-generic function body.
    // This mirrors `exec : Db -> String -> List a -> Task Error Int` (polymorphic
    // `List a`, not fixed to `List SqlValue`).
    let project_params = |s: &str| {
        // Empty-list fast path: `Vec::new()` has no elements, so Rust cannot
        // infer which `Into<SqlParam>` impl to use — the turbofish form names
        // the element type explicitly and skips the map/collect entirely.
        // Kept as defence-in-depth (the type-checker's defaulting normally
        // gives an empty Ipê `[]` literal a concrete `SqlValue` element type
        // before it ever reaches this closure — see the `sql_param` arm of
        // the numeric-defaulting loop in `ipe_types::lib` — but a bare
        // `Vec::new()` remains a possible input from any other empty-list
        // source, e.g. a Ipê-level `List.filter (always False) xs`).
        if s == "Vec::new()" {
            return "Vec::<ipe_runtime::db::SqlParam>::new()".to_string();
        }
        format!(
            "({s}).into_iter().map(::core::convert::Into::into)\
             .collect::<Vec<ipe_runtime::db::SqlParam>>()"
        )
    };
    // `project_fields(s)` — `List (String, SqlField)` → `Vec<(String, Option<SqlParam>)>`
    let project_fields = |s: &str| {
        format!(
            "({s}).into_iter().map(|(__k, __v)| (__k, __v.into_field_param()))\
             .collect::<Vec<_>>()"
        )
    };
    // `project_where(s)` — `List (String, SqlValue)` → `Vec<(String, SqlParam)>`
    // `SqlValue` elements here are always the concrete generated type (not
    // polymorphic), so we keep the explicit `into_sql_param()` call.
    let project_where = |s: &str| {
        format!(
            "({s}).into_iter().map(|(__k, __v)| (__k, __v.into_sql_param()))\
             .collect::<Vec<_>>()"
        )
    };

    match k {
        // ── DbExecRaw: (conn, sql) — DDL / no-param statements ──────────────
        //
        // The connection is cloned here (and in every other task-returning Db
        // kernel below) because the emitter wraps sequential Db calls in nested
        // `task_and_then(effect, move |_| { … })` continuations.  Rust evaluates
        // function arguments left-to-right: the EFFECT is built first (arg 0),
        // which would MOVE the `conn` binding, leaving the continuation closure
        // unable to capture it.  Cloning at each call site is the idiomatic fix
        // for `Arc`-backed handles; the `Db` type wraps an `Arc<Pool<…>>` so
        // cloning is cheap (pointer increment only).
        KernelFn::DbExecRaw => {
            let conn_e = arg!(0, "conn")?;
            let sql_e = arg!(1, "sql")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let sql_s = emit_expr_at(ctx, sql_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!("{fn_name}({conn_s}.clone(), {sql_s})")))
        }
        // ── DbExec / DbQuery: (conn, sql, List SqlValue) ────────────────────
        KernelFn::DbExec | KernelFn::DbQuery => {
            let conn_e = arg!(0, "conn")?;
            let sql_e = arg!(1, "sql")?;
            let params_e = arg!(2, "params")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let sql_s = emit_expr_at(ctx, sql_e, indent, child, generics)?;
            let params_s = emit_expr_at(ctx, params_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {sql_s}, {})",
                project_params(&params_s)
            )))
        }
        // ── DbQueryDecode / DbConnQueryDecode: (conn, sql, List SqlValue, decoder) ─
        // The external `queryDecodeOn` takes a `Connection` handle instead of a
        // `Db`, but both are `Clone` scalar values, so the projection is identical
        // — `conn.clone()`, `sql`, projected params, decoder.
        KernelFn::DbQueryDecode | KernelFn::DbConnQueryDecode => {
            let conn_e = arg!(0, "conn")?;
            let sql_e = arg!(1, "sql")?;
            let params_e = arg!(2, "params")?;
            let dec_e = arg!(3, "decoder")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let sql_s = emit_expr_at(ctx, sql_e, indent, child, generics)?;
            let params_s = emit_expr_at(ctx, params_e, indent, child, generics)?;
            let dec_s = emit_expr_at(ctx, dec_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {sql_s}, {}, {dec_s})",
                project_params(&params_s)
            )))
        }
        // ── DbInsertFields: (conn, table, List (String, SqlField)) ───────────
        KernelFn::DbInsertFields => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let fields_e = arg!(2, "fields")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let fields_s = emit_expr_at(ctx, fields_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {})",
                project_fields(&fields_s)
            )))
        }
        // ── DbUpdateFields: (conn, table, List (String,SqlValue), List (String,SqlField)) ─
        KernelFn::DbUpdateFields => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let where_e = arg!(2, "where_cols")?;
            let set_e = arg!(3, "set_fields")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let where_s = emit_expr_at(ctx, where_e, indent, child, generics)?;
            let set_s = emit_expr_at(ctx, set_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {}, {})",
                project_where(&where_s),
                project_fields(&set_s)
            )))
        }
        // ── DbUpsertFields: (conn, table, target: List String, List (String,SqlField)) ─
        //
        // The conflict target is a plain `List String` (`Vec<String>`), passed
        // through; the field list is projected exactly like `DbInsertFields`'.
        KernelFn::DbUpsertFields => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let target_e = arg!(2, "conflict_target")?;
            let fields_e = arg!(3, "fields")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let target_s = emit_expr_at(ctx, target_e, indent, child, generics)?;
            let fields_s = emit_expr_at(ctx, fields_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {target_s}, {})",
                project_fields(&fields_s)
            )))
        }
        // ── DbUpdateWhere: (conn, table, List (String,SqlField), frag: SqlFragment) ─
        //
        // The SET list is projected exactly like `DbUpdateFields`' set argument;
        // the WHERE `frag` is a bare `SqlFragment` value, passed through like
        // `DbDeleteWhere`'s fragment (no `List` projection).
        KernelFn::DbUpdateWhere => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let set_e = arg!(2, "set_fields")?;
            let frag_e = arg!(3, "frag")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let set_s = emit_expr_at(ctx, set_e, indent, child, generics)?;
            let frag_s = emit_expr_at(ctx, frag_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {}, {frag_s})",
                project_fields(&set_s)
            )))
        }
        // ── DbInsertFieldsReturning: (conn, table, List (String, SqlField), projection, decoder) ─
        KernelFn::DbInsertFieldsReturning => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let fields_e = arg!(2, "fields")?;
            let proj_e = arg!(3, "projection")?;
            let dec_e = arg!(4, "decoder")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let fields_s = emit_expr_at(ctx, fields_e, indent, child, generics)?;
            let proj_s = emit_expr_at(ctx, proj_e, indent, child, generics)?;
            let dec_s = emit_expr_at(ctx, dec_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {}, {proj_s}, {dec_s})",
                project_fields(&fields_s)
            )))
        }
        // ── DbInsertRow: (conn, table, row: Dict String String) ────────────────
        // The Ipe surface is upstream-parity `Dict String String` (bdbc572);
        // `Dict String String` already lowers to `HashMap<String, String>`
        // (the runtime function's own parameter type), so `row_s` passes
        // straight through with no conversion.
        KernelFn::DbInsertRow => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let row_e = arg!(2, "row")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let row_s = emit_expr_at(ctx, row_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {row_s})"
            )))
        }
        // ── DbUpdateById: (conn, table, id, row: Dict String String) ───────────
        // Same no-conversion-needed rationale as DbInsertRow above.
        KernelFn::DbUpdateById => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let id_e = arg!(2, "id")?;
            let row_e = arg!(3, "row")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let id_s = emit_expr_at(ctx, id_e, indent, child, generics)?;
            let row_s = emit_expr_at(ctx, row_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {id_s}, {row_s})"
            )))
        }
        // ── DbWithTransaction: (conn, body: Db -> Task e a) → Task e a ────────
        // Clone ensures the pool handle remains usable for any Db calls that
        // follow the `withTransaction` in the same continuation chain.  The body
        // closure itself receives its own pool copy through the task-local routing
        // (see `db_with_transaction` in the runtime), so the clone never causes an
        // extra SQLite connection.
        KernelFn::DbWithTransaction => {
            let conn_e = arg!(0, "conn")?;
            let body_e = arg!(1, "body")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let body_s = emit_expr_at(ctx, body_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!("{fn_name}({conn_s}.clone(), {body_s})")))
        }
        // ── DbMigrate: (conn, List Migration) → Task e (List String) ──
        // `Migration` is the record alias `{ name : String, sql : String }`
        // (reference `Ipe/Db.ipe:237`), lowered to the synthesised struct with
        // those two fields. The runtime `db_migrate_apply` takes `Vec<(String,
        // String)>`, so map each record to a `(name, sql)` tuple — the exact
        // shape the reference's pure-Ipê `migrate` produces via `List.map (\m ->
        // (m.name, m.sql))`.
        KernelFn::DbMigrate => {
            let conn_e = arg!(0, "conn")?;
            let migrations_e = arg!(1, "migrations")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let migrations_s = emit_expr_at(ctx, migrations_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {migrations_s}.into_iter()\
                 .map(|__m| (__m.name, __m.sql)).collect::<Vec<(String, String)>>())"
            )))
        }
        // ── DbDefaultMigration: String -> Migration ──────────────────────────
        // Pure record builder — a `Migration` named with an empty SQL body
        // (reference `Ipe/Db.ipe:246`). Emitted inline as the synthesised
        // `{ name, sql }` struct literal so no runtime kernel is required.
        KernelFn::DbDefaultMigration => {
            let name_e = arg!(0, "name")?;
            let name_s = emit_expr_at(ctx, name_e, indent, child, generics)?;
            let key = vec!["name".to_owned(), "sql".to_owned()];
            let struct_name = ctx.record_name_for_literal(&key, None)?.to_owned();
            Ok(Some(format!(
                "{struct_name} {{ name: {name_s}, sql: String::new() }}"
            )))
        }
        // ── DbGetById / DbConnGetById: (conn, table, id) ────────────────────
        // Conn must be cloned so subsequent Db calls in the same continuation
        // chain can still capture it (Pool<Sqlite> is not Copy). `getByIdOn`'s
        // external `Connection` handle is also `Clone`, so the arm is shared.
        KernelFn::DbGetById | KernelFn::DbConnGetById => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let id_e = arg!(2, "id")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let id_s = emit_expr_at(ctx, id_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {id_s})"
            )))
        }
        // ── DbDeleteById: (conn, table, id) ─────────────────────────────────
        KernelFn::DbDeleteById => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let id_e = arg!(2, "id")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let id_s = emit_expr_at(ctx, id_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {id_s})"
            )))
        }
        // ── DbFindOneByField: (conn, table, field, value) ────────────────────
        KernelFn::DbFindOneByField => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let field_e = arg!(2, "field")?;
            let value_e = arg!(3, "value")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let field_s = emit_expr_at(ctx, field_e, indent, child, generics)?;
            let value_s = emit_expr_at(ctx, value_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {field_s}, {value_s})"
            )))
        }
        // ── DbFindManyByField: (conn, table, field, value) ───────────────────
        KernelFn::DbFindManyByField => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let field_e = arg!(2, "field")?;
            let value_e = arg!(3, "value")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let field_s = emit_expr_at(ctx, field_e, indent, child, generics)?;
            let value_s = emit_expr_at(ctx, value_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {field_s}, {value_s})"
            )))
        }
        // ── DbGet*: (field, row) — row is passed by reference so the same row
        // binding can be used in multiple consecutive accessor calls within a
        // single expression (e.g. inside a `list_map_consume` lambda that reads
        // several columns). The runtime functions take `row: &R where R: IpeRow`.
        KernelFn::DbGetString | KernelFn::DbGetInt | KernelFn::DbGetBool | KernelFn::DbGetField => {
            let field_e = arg!(0, "field")?;
            let row_e = arg!(1, "row")?;
            let field_s = emit_expr_at(ctx, field_e, indent, child, generics)?;
            let row_s = emit_expr_at(ctx, row_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!("{fn_name}({field_s}, &({row_s}))")))
        }
        // ── DbFindByConditions: (conn, table, conditions: Dict String String) ──
        //
        // The runtime `db_find_by_conditions` takes `HashMap<String, String>` —
        // identical to the IR's `Dict String String` representation — so no
        // conversion is needed beyond passing the value through.
        KernelFn::DbFindByConditions => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let conditions_e = arg!(2, "conditions")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let conditions_s = emit_expr_at(ctx, conditions_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {conditions_s})"
            )))
        }
        // ── Db.findWhere / Db.deleteWhere: (conn, table, frag: SqlFragment) ──
        //
        // The `SqlFragment`-typed replacement for the removed `unsafeFindWhere`
        // `frag` is a bare struct value (no `List` projection
        // needed) — only the `conn.clone()` treatment (shared by every other
        // Task-returning Db kernel here) is special-cased.
        // `DbConnFindWhere` (`findWhereOn`) shares the arm: an external
        // `Connection` handle is a `Clone` scalar, same as a `Db`.
        KernelFn::DbFindWhere | KernelFn::DbDeleteWhere | KernelFn::DbConnFindWhere => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let frag_e = arg!(2, "frag")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let frag_s = emit_expr_at(ctx, frag_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {frag_s})"
            )))
        }
        // ── Db.findWhereMasked: (conn, table, List SqlFragment, frag, decoder) ─
        //
        // The NULL-preserving projected masked read. `projections` is a
        // `List SqlFragment` (each a validated `Sql.column`/`Sql.maskedColumn`
        // term), emitted as a `vec![…]` of bare `SqlFragment` structs — no `List
        // SqlValue` projection is involved; `frag` is the bare WHERE struct and
        // `decoder` a `Decoder` value. Only the `conn.clone()` treatment is
        // special (shared with every Db kernel).
        KernelFn::DbFindWhereMasked => {
            let conn_e = arg!(0, "conn")?;
            let table_e = arg!(1, "table")?;
            let projections_e = arg!(2, "projections")?;
            let frag_e = arg!(3, "frag")?;
            let dec_e = arg!(4, "decoder")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let table_s = emit_expr_at(ctx, table_e, indent, child, generics)?;
            let projections_s = emit_expr_at(ctx, projections_e, indent, child, generics)?;
            let frag_s = emit_expr_at(ctx, frag_e, indent, child, generics)?;
            let dec_s = emit_expr_at(ctx, dec_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {table_s}, {projections_s}, {frag_s}, {dec_s})"
            )))
        }
        // ── Db.findJoin: (conn, lt, la, lcols, rt, ra, rcols, frag) ──────────
        //
        // Eight flat args, one per validated identifier group. The two `List
        // String` column lists emit as `vec![…]` (a `Vec<String>`), the two
        // tables / two aliases as plain `String`, and `frag` as the bare
        // `SqlFragment` struct — no `List SqlValue` projection is needed. Only
        // the `conn.clone()` treatment is special (shared with every Db kernel).
        KernelFn::DbFindJoin => {
            let conn_e = arg!(0, "conn")?;
            let left_table_e = arg!(1, "leftTable")?;
            let left_alias_e = arg!(2, "leftAlias")?;
            let left_cols_e = arg!(3, "leftColumns")?;
            let right_table_e = arg!(4, "rightTable")?;
            let right_alias_e = arg!(5, "rightAlias")?;
            let right_cols_e = arg!(6, "rightColumns")?;
            let frag_e = arg!(7, "frag")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let left_table_s = emit_expr_at(ctx, left_table_e, indent, child, generics)?;
            let left_alias_s = emit_expr_at(ctx, left_alias_e, indent, child, generics)?;
            let left_cols_s = emit_expr_at(ctx, left_cols_e, indent, child, generics)?;
            let right_table_s = emit_expr_at(ctx, right_table_e, indent, child, generics)?;
            let right_alias_s = emit_expr_at(ctx, right_alias_e, indent, child, generics)?;
            let right_cols_s = emit_expr_at(ctx, right_cols_e, indent, child, generics)?;
            let frag_s = emit_expr_at(ctx, frag_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {left_table_s}, {left_alias_s}, {left_cols_s}, \
                 {right_table_s}, {right_alias_s}, {right_cols_s}, {frag_s})"
            )))
        }
        // ── Db.findProjection: (conn, lt, la, rt, ra, frag, projections) ─────
        //
        // Seven flat args. The two tables / two aliases emit as plain `String`,
        // `frag` as the bare `SqlFragment` struct, and `projections`
        // (`List (String, String)`) as `vec![(String, String), …]`, a
        // `Vec<(String, String)>` — no `List SqlValue` param projection is
        // needed. Only the `conn.clone()` treatment is special (shared with
        // every Db kernel).
        KernelFn::DbFindProjection => {
            let conn_e = arg!(0, "conn")?;
            let left_table_e = arg!(1, "leftTable")?;
            let left_alias_e = arg!(2, "leftAlias")?;
            let right_table_e = arg!(3, "rightTable")?;
            let right_alias_e = arg!(4, "rightAlias")?;
            let frag_e = arg!(5, "frag")?;
            let projections_e = arg!(6, "projections")?;
            let extra_binds_e = arg!(7, "extraBinds")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let left_table_s = emit_expr_at(ctx, left_table_e, indent, child, generics)?;
            let left_alias_s = emit_expr_at(ctx, left_alias_e, indent, child, generics)?;
            let right_table_s = emit_expr_at(ctx, right_table_e, indent, child, generics)?;
            let right_alias_s = emit_expr_at(ctx, right_alias_e, indent, child, generics)?;
            let frag_s = emit_expr_at(ctx, frag_e, indent, child, generics)?;
            let projections_s = emit_expr_at(ctx, projections_e, indent, child, generics)?;
            let extra_binds_s = emit_expr_at(ctx, extra_binds_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {left_table_s}, {left_alias_s}, \
                 {right_table_s}, {right_alias_s}, {frag_s}, {projections_s}, {})",
                project_params(&extra_binds_s)
            )))
        }
        // ── Db.findJoinOrdered: (conn, lt, la, lcols, rt, ra, rcols, frag,
        //                         orderAlias, orderCol, orderAsc) ──────────────
        //
        // Eleven flat args: the eight from `DbFindJoin` plus the three ORDER BY
        // arguments (alias String, column String, ascending Bool).
        KernelFn::DbFindJoinOrdered => {
            let conn_e = arg!(0, "conn")?;
            let left_table_e = arg!(1, "leftTable")?;
            let left_alias_e = arg!(2, "leftAlias")?;
            let left_cols_e = arg!(3, "leftColumns")?;
            let right_table_e = arg!(4, "rightTable")?;
            let right_alias_e = arg!(5, "rightAlias")?;
            let right_cols_e = arg!(6, "rightColumns")?;
            let frag_e = arg!(7, "frag")?;
            let order_alias_e = arg!(8, "orderAlias")?;
            let order_col_e = arg!(9, "orderCol")?;
            let order_asc_e = arg!(10, "orderAsc")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let left_table_s = emit_expr_at(ctx, left_table_e, indent, child, generics)?;
            let left_alias_s = emit_expr_at(ctx, left_alias_e, indent, child, generics)?;
            let left_cols_s = emit_expr_at(ctx, left_cols_e, indent, child, generics)?;
            let right_table_s = emit_expr_at(ctx, right_table_e, indent, child, generics)?;
            let right_alias_s = emit_expr_at(ctx, right_alias_e, indent, child, generics)?;
            let right_cols_s = emit_expr_at(ctx, right_cols_e, indent, child, generics)?;
            let frag_s = emit_expr_at(ctx, frag_e, indent, child, generics)?;
            let order_alias_s = emit_expr_at(ctx, order_alias_e, indent, child, generics)?;
            let order_col_s = emit_expr_at(ctx, order_col_e, indent, child, generics)?;
            let order_asc_s = emit_expr_at(ctx, order_asc_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {left_table_s}, {left_alias_s}, {left_cols_s}, \
                 {right_table_s}, {right_alias_s}, {right_cols_s}, {frag_s}, \
                 {order_alias_s}, {order_col_s}, {order_asc_s})"
            )))
        }
        // ── Db.findProjectionOrdered: (conn, lt, la, rt, ra, frag, projections,
        //                              extraBinds, orderAlias, orderCol, orderAsc)
        //
        // Eleven flat args: the eight from `DbFindProjection` (including
        // `extraBinds`) plus the three ORDER BY arguments (alias String, column
        // String, ascending Bool).
        KernelFn::DbFindProjectionOrdered => {
            let conn_e = arg!(0, "conn")?;
            let left_table_e = arg!(1, "leftTable")?;
            let left_alias_e = arg!(2, "leftAlias")?;
            let right_table_e = arg!(3, "rightTable")?;
            let right_alias_e = arg!(4, "rightAlias")?;
            let frag_e = arg!(5, "frag")?;
            let projections_e = arg!(6, "projections")?;
            let extra_binds_e = arg!(7, "extraBinds")?;
            let order_alias_e = arg!(8, "orderAlias")?;
            let order_col_e = arg!(9, "orderCol")?;
            let order_asc_e = arg!(10, "orderAsc")?;
            let conn_s = emit_expr_at(ctx, conn_e, indent, child, generics)?;
            let left_table_s = emit_expr_at(ctx, left_table_e, indent, child, generics)?;
            let left_alias_s = emit_expr_at(ctx, left_alias_e, indent, child, generics)?;
            let right_table_s = emit_expr_at(ctx, right_table_e, indent, child, generics)?;
            let right_alias_s = emit_expr_at(ctx, right_alias_e, indent, child, generics)?;
            let frag_s = emit_expr_at(ctx, frag_e, indent, child, generics)?;
            let projections_s = emit_expr_at(ctx, projections_e, indent, child, generics)?;
            let extra_binds_s = emit_expr_at(ctx, extra_binds_e, indent, child, generics)?;
            let order_alias_s = emit_expr_at(ctx, order_alias_e, indent, child, generics)?;
            let order_col_s = emit_expr_at(ctx, order_col_e, indent, child, generics)?;
            let order_asc_s = emit_expr_at(ctx, order_asc_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({conn_s}.clone(), {left_table_s}, {left_alias_s}, \
                 {right_table_s}, {right_alias_s}, {frag_s}, {projections_s}, {}, \
                 {order_alias_s}, {order_col_s}, {order_asc_s})",
                project_params(&extra_binds_s)
            )))
        }
        // ── Sql.inList: (frag: SqlFragment, values: List SqlValue) ───────────
        //
        // `values` needs the same `List SqlValue` → `Vec<SqlParam>` projection
        // as `DbExec`/`DbQuery`'s params argument.
        KernelFn::SqlInList => {
            let frag_e = arg!(0, "frag")?;
            let values_e = arg!(1, "values")?;
            let frag_s = emit_expr_at(ctx, frag_e, indent, child, generics)?;
            let values_s = emit_expr_at(ctx, values_e, indent, child, generics)?;
            let fn_name = crate::naming::kernel_name(*k);
            Ok(Some(format!(
                "{fn_name}({frag_s}, {})",
                project_params(&values_s)
            )))
        }
        // ── Standard-path Db kernels ────────────────────────────────────────────
        //
        // The kernels below route through `emit_call`'s standard path — their
        // argument types emit correctly without special-case projection.  List
        // them explicitly so any future param-taking Db kernel that needs a custom
        // arm is a compile error here, not a silent exit-0-then-cargo-fail.
        KernelFn::DbConnect
        | KernelFn::DbOpen
        | KernelFn::DbClose
        // External Connection — `open`/`close`/`unsafeExecRawOn` take plain
        // `Dsn` / `Connection` / `String` scalar args (the phantom access mode
        // is erased, so the `Connection` handle is one concrete type); no `Db`
        // handle projection, no List projection — the standard call path.
        | KernelFn::DbConnOpen
        | KernelFn::DbConnClose
        | KernelFn::DbConnUnsafeExecRawOn
        // `Db.Dsn.*` — the parse surface takes plain `String` / `Int` / `Secret`
        // / `Dsn` scalar args (no `Db` handle, no List projection), so they route
        // through the standard call path unchanged.
        | KernelFn::DsnParse
        | KernelFn::DsnBuild
        | KernelFn::DsnDriverTag
        | KernelFn::DsnHost
        | KernelFn::DsnPort
        | KernelFn::DsnDatabase
        | KernelFn::DsnUser
        | KernelFn::DsnTlsTag
        | KernelFn::DsnRedacted
        | KernelFn::DbDecString
        | KernelFn::DbDecInt
        | KernelFn::DbDecFloat
        | KernelFn::DbDecBool
        | KernelFn::DbDecNullable
        | KernelFn::DbDecMap
        | KernelFn::DbDecAndThen
        | KernelFn::DbDecSucceed
        | KernelFn::DbDecFail
        | KernelFn::DbDecMap2
        | KernelFn::DbDecMap3
        | KernelFn::DbDecMap4
        | KernelFn::DbDecRequired
        | KernelFn::DbDecOptional
        | KernelFn::DbDecMoney
        | KernelFn::DbDecDecimal
        | KernelFn::DbDecBytes
        // `Sql.column`/`param`/`int`/`string`/`float`/`bool`/`eq`/`ne`/`gt`/`lt`/
        // `gte`/`lte`/`and`/`or`/`not`/`isNull`/`isNotNull`/`like` take plain
        // scalar or `SqlFragment` args — no `Db` handle, no List projection.
        | KernelFn::SqlColumn
        | KernelFn::SqlUnsafeFragment
        | KernelFn::SqlParam
        | KernelFn::SqlInt
        | KernelFn::SqlString
        | KernelFn::SqlFloat
        | KernelFn::SqlBool
        | KernelFn::SqlEq
        | KernelFn::SqlNe
        | KernelFn::SqlGt
        | KernelFn::SqlLt
        | KernelFn::SqlGte
        | KernelFn::SqlLte
        | KernelFn::SqlAnd
        | KernelFn::SqlOr
        | KernelFn::SqlNot
        | KernelFn::SqlIsNull
        | KernelFn::SqlIsNotNull
        | KernelFn::SqlLike
        // `Sql.exists : String -> SqlFragment -> SqlFragment` takes a plain
        // `String` table name and a `SqlFragment` — no `Db` handle, no List
        // projection, so the standard call path emits it correctly.
        | KernelFn::SqlExists
        // `Sql.maskedColumn : SqlFragment -> String -> SqlFragment` takes a
        // `SqlFragment` predicate and a plain `String` column — no `Db` handle,
        // no List projection, so the standard call path emits it correctly.
        | KernelFn::SqlMaskedColumn => Ok(None),
        // A Db kernel that reached this arm is a compiler bug: either add a
        // custom projection arm above, or add it to the standard-path list.
        // This arm is unreachable for any KernelFn variant listed above, so
        // its only way to fire is a newly-added Db* variant that was not wired
        // into either list — making the miss a compile-time-hard error rather
        // than a silent exit-0-then-cargo-fail.
        _ if k.is_db() => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_db_call",
            detail: format!(
                "unprojected Db kernel {k:?}: add a custom projection arm \
                 or a standard-path entry to emit_db_call"
            ),
        }),
        // Non-Db kernel: let the standard call path handle it.
        _ => Ok(None),
    }
}

/// Handle TEA (`Cmd` / `Sub` / `Time.every`) kernel calls that require custom
/// argument wiring.
///
/// Returns `Some(emitted)` for:
///
/// * **`CmdNone` / `SubNone`** — zero-arg constructors; the runtime functions
///   take no arguments, so we emit `cmd_none()` / `sub_none()` rather than
///   going through the default N-arg path.
///
/// * **`CmdBatch` / `SubBatch`** — `List (Cmd msg) -> Cmd msg`; the list
///   argument is passed directly to the runtime (its `IrType::List` renders as
///   a Rust `Vec`), so we emit `cmd_batch(<list_expr>)` /
///   `sub_batch(<list_expr>)`.  (A previous version of this doc stated that the
///   argument was materialised via `vec_from_ipe_list`; that was never the
///   actual code path — the emitted list expression already has `Vec` type.)
///
/// * **`CmdPerform`** — `Task Error a -> (Result Error a -> msg) -> Cmd msg`;
///   the callback must be boxed as a `Box<dyn Fn(IpeResult<A>) -> M + Send + 'static>`.
///   Emits `cmd_perform(<task>, Box::new(<f>))`.
///
/// * **`SubEvery` / `TimeEvery`** — `Int -> msg -> Sub msg`; these pass
///   through the standard N-arg path (no custom boxing needed), returning
///   `Ok(None)` so the standard emitter handles them.
///
/// Returns `Err(CompilerBug)` for any `k.is_tea()` variant that is:
///
/// * **reserved, not emittable here** (`CmdPublish`, `CmdPublishNoEcho`,
///   `SubSubscribeTopic`) — guard fires if a program somehow reaches one (e.g.
///   if `lower_callee` mis-routes it); not user-reachable.
///
/// Returns `Ok(None)` for non-TEA callees so the standard path handles them.
/// Emit a config-tag ADT constructor (`Host.loopback` / `Level.warn` /
/// `Web.strict` / …) as its raw `Int` tag literal.
///
/// The closed `HostMode` / `LogLevel` / `CsrfMode` / `RevocationMode` types exist
/// only in the type system to reject an out-of-range tag at compile time; at runtime
/// each value is the integer the setting builder consumes.
/// `CsrfMode` has no disabling variant; `RevocationMode::Off = 0` / `Store = 1`.
///
/// Returns `Some(literal)` for the eleven constructor kernels and `None` for every
/// other callee, so the standard call path handles the rest.
pub fn emit_config_ctor_call(callee: &Callee) -> Option<String> {
    let Callee::Kernel(k) = callee else {
        return None;
    };
    // One arm per constructor for readability; distinct tags across the three
    // ADTs coincide numerically (each ADT's first variant is `0`), which is not a
    // shared meaning to merge.
    #[allow(clippy::match_same_arms)]
    let tag: i64 = match k {
        KernelFn::HostLoopback => 0,
        KernelFn::HostAllInterfaces => 1,
        KernelFn::HostEnvDriven => 2,
        KernelFn::LevelDebug => 0,
        KernelFn::LevelInfo => 1,
        KernelFn::LevelWarn => 2,
        KernelFn::LevelError => 3,
        KernelFn::WebCsrfStrict => 0,
        KernelFn::WebCsrfInherit => 1,
        // `RevocationMode`: Off=0 (default, zero-overhead), Store=1 (arms the gate).
        KernelFn::WebRevocationOff => 0,
        KernelFn::WebRevocationStore => 1,
        _ => return None,
    };
    Some(format!("{tag}i64"))
}

#[allow(clippy::match_same_arms, clippy::too_many_lines)]
pub fn emit_tea_call(
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
    if !k.is_tea() {
        return Ok(None);
    }

    macro_rules! arg {
        ($idx:expr, $name:literal) => {
            args.get($idx).ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_tea_call",
                detail: format!("TEA kernel {:?} missing arg[{}] ({})", k, $idx, $name),
            })
        };
    }

    match k {
        // ── Arity-0: nullary TEA constructors ──────────────────────────────────
        // `Cmd.none : Cmd msg`  →  `cmd_none()`
        KernelFn::CmdNone => Ok(Some("cmd_none()".to_owned())),
        // `Sub.none : Sub msg`  →  `sub_none()`
        KernelFn::SubNone => Ok(Some("sub_none()".to_owned())),
        // ── Arity-1: list-of-cmds / list-of-subs ────────────────────────────────
        // `Cmd.batch : List (Cmd msg) -> Cmd msg`
        KernelFn::CmdBatch => {
            let list_e = arg!(0, "list")?;
            let list_s = emit_expr_at(ctx, list_e, indent, child, generics)?;
            Ok(Some(format!("cmd_batch({list_s})")))
        }
        // `Sub.batch : List (Sub msg) -> Sub msg`
        KernelFn::SubBatch => {
            let list_e = arg!(0, "list")?;
            let list_s = emit_expr_at(ctx, list_e, indent, child, generics)?;
            Ok(Some(format!("sub_batch({list_s})")))
        }
        // ── Arity-2: Cmd.perform (requires boxing the callback) ─────────────────
        // `Cmd.perform : Task Error a -> (Result Error a -> msg) -> Cmd msg`
        // Emits: `cmd_perform(<task>, <f>)`
        // The runtime's `cmd_perform` signature already boxes the callback,
        // so we can pass the emitted closure expression directly.
        KernelFn::CmdPerform => {
            let task_e = arg!(0, "task")?;
            let handler_expr = arg!(1, "to_msg")?;
            let task_s = emit_expr_at(ctx, task_e, indent, child, generics)?;
            let handler_src = emit_expr_at(ctx, handler_expr, indent, child, generics)?;
            Ok(Some(format!("cmd_perform({task_s}, {handler_src})")))
        }
        // ── Task.attempt : (Result Error a -> msg) -> Task Error a -> Cmd msg ──
        // Elm's arg order is `(to_msg, task)`; the runtime `cmd_perform` takes
        // `(task, to_msg)` (the exact `Cmd.perform` bridge), so the two args are
        // emitted swapped. Reuses `cmd_perform` — no dedicated runtime symbol.
        KernelFn::TaskAttempt => {
            let handler_expr = arg!(0, "to_msg")?;
            let task_e = arg!(1, "task")?;
            let handler_src = emit_expr_at(ctx, handler_expr, indent, child, generics)?;
            let task_s = emit_expr_at(ctx, task_e, indent, child, generics)?;
            Ok(Some(format!("cmd_perform({task_s}, {handler_src})")))
        }
        // ── Arity-2: Cmd.map / Sub.map (retag a sub-component's effects) ─────────
        // `Cmd.map : (a -> msg) -> Cmd a -> Cmd msg`  →  `cmd_map(<cmd>, <f>)`
        // `Sub.map : (a -> msg) -> Sub a -> Sub msg`  →  `sub_map(<sub>, <f>)`
        // The Ipê argument order is `(f, effect)`; the runtime takes
        // `(effect, f)` (effect first so `f` infers its `A` from the effect's
        // message type), so the two args are emitted swapped. `f` is passed
        // through unboxed — `cmd_map`/`sub_map` are generic over `F: Fn(A) -> M`
        // and share it via `Arc` internally, so the emitted closure value binds
        // directly with no re-wrap.
        KernelFn::CmdMap | KernelFn::SubMap => {
            let handler_expr = arg!(0, "f")?;
            let effect_e = arg!(1, "effect")?;
            let handler_src = emit_expr_at(ctx, handler_expr, indent, child, generics)?;
            let effect_s = emit_expr_at(ctx, effect_e, indent, child, generics)?;
            let name = kernel_name(*k); // "cmd_map" / "sub_map"
            Ok(Some(format!("{name}({effect_s}, {handler_src})")))
        }
        // ── Arity-2: tick subscriptions — standard path ──────────────────────────
        // `Sub.every : Int -> msg -> Sub msg` and
        // `Time.every : Int -> msg -> Sub msg`
        // Under an armed TEA `subscriptions` body (`hot_appearance` on), a
        // data-describable tick entry (a literal interval + a serde-encodable
        // literal message) reduces to `sub_every_hot("<baked datum>")`, read by the
        // ONE compiled sub-runner over the baked datum (dev == prod). Both spellings
        // share the same [`emit_sub_arm`], so their tokens agree and the SEAL stays
        // exact. Otherwise (flag off, not a subscriptions body, or a
        // non-describable entry) it passes through the default N-arg emitter
        // (`Ok(None)`), byte-identical to the flag-off form — no boxing needed.
        KernelFn::SubEvery | KernelFn::TimeEvery => Ok(emit_sub_arm(ctx, *k, args)),
        // ── Arity-2: pub/sub subscription — standard path ────────────────────────
        // `Sub.subscribeTopic : String -> (any -> msg) -> Sub msg`
        // The runtime `sub_subscribe_topic` is in live/pubsub.rs (live-feature
        // gated). The payload type T is resolved by Rust's type inference from
        // the matching `cmd_publish` call site; no boxing required here.
        KernelFn::SubSubscribeTopic => Ok(None),
        // `Http.Stream.chunks : Int -> (ChunkEvent -> msg) -> Sub msg`
        // Uses the same generic N-arg emit path as SubSubscribeTopic.
        // The runtime symbol `sub_subscribe_stream` is defined in http_stream.rs.
        //
        // This arm passes the boxed handler through unchanged (`Ok(None)`).
        // `to_msg` is moved exclusively into one detached `tokio::spawn` task,
        // never shared behind an `Arc`, so `Sync` is not structurally required;
        // the runtime signature bounds the handler `Send`-only (matching
        // `sub_subscribe_topic` — see `sub_subscribe_stream`'s doc comment in
        // `http_stream.rs`), so a plain `Box<dyn Fn(..) + Send>` satisfies it
        // with no re-wrap (avoiding E0277). Contrast with the sibling
        // `KernelFn::StreamStream` (`emit_server_call`), which DOES need the
        // re-wrap-in-a-fresh-closure technique because its runtime consumer
        // genuinely stores the handler behind a shared `Arc`.
        KernelFn::HttpStreamChunks => Ok(None),
        // ── Cmd.publish / Cmd.publishNoEcho ──────────────────────────────────────
        // `Cmd.publish : String -> Dict String String -> Cmd msg`
        // `Cmd.publishNoEcho : String -> Dict String String -> Cmd msg`
        // Both map to the standard N-arg emit path (runtime live/pubsub.rs).
        KernelFn::CmdPublish | KernelFn::CmdPublishNoEcho => Ok(None),
        // ── Ipe.Ffi.Js ports: Js.send / Js.subscribe ─────────────────────────────────
        // `Js.send : a -> Cmd msg`  →  `js_send(<payload>)`
        // `Js.subscribe : Decoder a -> (a -> msg) -> Sub msg`
        //   →  `js_subscribe(<decoder>, <to_msg>)`
        // Both take their surface args in the runtime fn's order, so the default
        // N-arg emit path renders the call verbatim. The payload's concrete type
        // (`T: serde::Serialize`) and the decoder's `Decoder<IpeError, T>` are
        // resolved by Rust inference at the call site; no boxing or re-wrap is
        // needed — `js_send`/`js_subscribe` bound the handler `Send`-only, moving
        // it into one detached task, the same shape `sub_subscribe_topic` uses.
        KernelFn::JsSend | KernelFn::JsSubscribe => Ok(None),
        // `Js.request : a -> Decoder b -> Task b`  →  `js_request(<payload>, <decoder>)`
        // The correlated one-shot kernel takes its args in the runtime fn's order, so
        // the default N-arg emit path renders the call verbatim. Rust generic inference
        // resolves the payload's concrete seal type and the decoder's `Decoder<IpeError, T>`
        // at the call site; no boxing or re-wrap is needed.
        KernelFn::JsRequest => Ok(None),
        // ── Ipe.Ffi.Js session-stream primitive ──────────────────────────────────
        // `openSession   : openCmd -> Decoder frame -> Task SessionHandle`
        //     →  `js_open_session(<openCmd>, <decoder>)`
        // `sessionFrames : SessionHandle -> Decoder frame -> (frame -> msg) -> Sub msg`
        //     →  `js_session_frames(<handle>, <decoder>, <to_msg>)` — the explicit
        //        frame decoder is the fail-closed inbound gate, same idiom as
        //        `subscribe`; the runtime fn takes (handle, decoder, to_msg) in order.
        // `sendToSession : SessionHandle -> sessionCmd -> Cmd msg`
        //     →  `js_send_to_session(<handle>, <sessionCmd>)`
        // `closeSession  : SessionHandle -> closeCmd -> Decoder terminal -> Task terminal`
        //     →  `js_close_session(<handle>, <closeCmd>, <decoder>)`
        // All take their surface args in the runtime fn's order, so the default
        // N-arg emit path renders each verbatim; Rust generic inference resolves the
        // concrete seal types and decoders at the call site.
        KernelFn::JsOpenSession
        | KernelFn::JsSessionFrames
        | KernelFn::JsSendToSession
        | KernelFn::JsCloseSession => Ok(None),
        // (`Ipe.PubSub.publish` / `publishNoEcho` are `class = Web`, Task-shaped —
        // emitted in `emit_ui_call`, not here. They are not TEA-loop kernels.)
        // ── Ipe.WebSocket: onOpen / onMessage / onClose / onError ───────────
        // `Sub_subscribeWebSocket : Int -> String -> (any -> msg) -> Sub msg`.
        //
        // The four `on*` stdlib wrappers all funnel through this single
        // `any`-typed kernel with a compile-time-literal `kind`
        // ("open" / "message" / "close" / "error"), because their heterogeneous
        // toMsg shapes (bare `msg` / `WebSocketMessage -> msg` / `CloseCode -> msg`
        // / `Error -> msg`) can't share one bounded Rust fn. This peephole does the
        // split a stdlib override would otherwise do: route by the literal `kind`
        // to a per-kind TYPED runtime fn (`sub_subscribe_ws_{open,message,close,
        // error}`), passing only the socket id + toMsg (the `kind` arg is consumed
        // here, never emitted). Matches the
        // `ExprEmitter.hs` peephole. Each runtime fn moves `to_msg` into exactly
        // one detached `tokio::spawn` task (never behind a shared `Arc`), so the
        // generic `Box<dyn Fn(..) -> .. + Send + 'static>` codegen value passes
        // straight through — no re-wrap needed (unlike `StreamStream`).
        KernelFn::SubSubscribeWebSocket => {
            let raw_e = arg!(0, "socketId")?;
            let kind_e = arg!(1, "kind")?;
            let to_msg_e = arg!(2, "toMsg")?;
            // The `kind` MUST be a compile-time string literal — the four stdlib
            // wrappers always pass one. A non-literal is a malformed call the
            // stdlib can't produce; fail closed (SEAL) rather than guess a kind.
            let Expr::Str(kind) = kind_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_tea_call::SubSubscribeWebSocket",
                    detail: "Sub.subscribeWebSocket requires a compile-time-literal kind \
                             (\"open\"/\"message\"/\"close\"/\"error\") — the four on* stdlib \
                             wrappers always pass one"
                        .to_owned(),
                });
            };
            let fn_name = match kind.as_str() {
                "open" => "sub_subscribe_ws_open",
                "message" => "sub_subscribe_ws_message",
                "close" => "sub_subscribe_ws_close",
                "error" => "sub_subscribe_ws_error",
                other => {
                    return Err(Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::emit_tea_call::SubSubscribeWebSocket",
                        detail: format!(
                            "Sub.subscribeWebSocket got unknown kind {other:?} — \
                             expected \"open\"/\"message\"/\"close\"/\"error\""
                        ),
                    });
                }
            };
            let raw_s = emit_expr_at(ctx, raw_e, indent, child, generics)?;
            let to_msg_s = emit_expr_at(ctx, to_msg_e, indent, child, generics)?;
            Ok(Some(format!("{fn_name}({raw_s}, {to_msg_s})")))
        }
        // Any other `k.is_tea()` variant not listed above is a new wired variant
        // that needs an explicit arm.  The `is_tea()` guard at the top of this
        // function means this arm is a hard compile-time-visible gap rather than
        // a silent `Ok(None)` pass-through.
        _ => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_tea_call",
            detail: format!(
                "TEA kernel {k:?} is_tea() but has no emit arm — \
                 add it to emit_tea_call"
            ),
        }),
    }
}

/// Build the capture-clone prologue for the `StreamStream` re-wrap closure.
///
/// The `StreamStream` arm wraps the handler in `move |_x| (handler)(_x)` to
/// recover the runtime's `+Sync` bound by rebuilding the handler box as SOURCE
/// per call (see the `UiOnSubmit` doc). But the handler's own `move` captures
/// its enclosing non-`Copy` locals (the `header`/`body` `String`s of a
/// Csv-stream handler); the re-embedded box steals them from the `move |_x|`
/// wrapper's env on the first call, so the wrapper degrades to `FnOnce` and
/// `server_stream_stream`'s `Fn` bound rejects it (`E0507` after `ipe` exit
/// 0 — a SEAL break). The lowerer's capture-clone rewrite only reaches INTO
/// the handler body; this synthesized wrapper is emit-only, invisible to it.
///
/// So this returns a `let <v> = <v>.clone(); …` prologue for every free local
/// `v` the handler captures, spliced INSIDE the wrapper body: the box moves the
/// fresh shadowing clones, the wrapper keeps its originals for the next call.
/// Same shape as the `TaskSeq` clone-capture prologue, applied at
/// an emit-synthesized closure. Every captured free local is `Clone`: an
/// enclosing value (`Clone` by its carrier type), a `let`-bound handler
/// promoted to `SharedLambda` (`Arc`, `Clone` — `StreamStream` is in
/// `requires_sync_capture`), or a `Copy` leaf (whose `.clone()` is a bitwise
/// copy).
pub fn stream_handler_capture_prologue(ctx: &EmitCtx, handler: &Expr) -> DResult<String> {
    capture_clone_prologue(ctx, [handler])
}

/// A `let <v> = <v>.clone(); …` prologue for every free local of `exprs`, each named once.
///
/// Spliced ahead of emitted code that `move`-captures those locals while the
/// originals must stay available afterwards — the prologue's shadowing clones
/// are what the captures consume.
pub fn capture_clone_prologue<'e>(
    ctx: &EmitCtx,
    exprs: impl IntoIterator<Item = &'e Expr>,
) -> DResult<String> {
    let mut captured = std::collections::BTreeSet::new();
    for expr in exprs {
        collect_free_vars(expr, &mut captured);
    }
    let mut prologue = String::new();
    for sym in captured {
        let id = ctx.emit_ident(sym)?;
        write!(prologue, "let {id} = {id}.clone(); ").map_err(|_| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::capture_clone_prologue",
            detail: "writing capture-clone prologue failed".to_owned(),
        })?;
    }
    Ok(prologue)
}

/// Handle a `Ipe.Http.Server` / `Middleware` / `RateLimit` kernel call.
///
/// Returns `Ok(None)` for all wired server kernels (they all use the standard
/// N-arg call path — no boxing or special argument transformation needed).
/// Returns a hard [`Diagnostic::CompilerBug`] for any `is_server()` variant
/// not listed here, so a future addition that forgets this function fails at
/// compile time.
#[allow(clippy::too_many_lines)] // exhaustive declarative per-kernel dispatch table
pub fn emit_server_call(
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
    if !k.is_server() {
        return Ok(None);
    }
    match k {
        // ── Request accessor kernels that take `ServerRequest` by value ───────
        //
        // `ServerRequest: Clone` (see `src/runtime/rust/src/server.rs`).
        // When a handler calls more than one accessor on the same `req` binding,
        // the first call would move `req` and subsequent calls would fail with
        // E0382 "use of moved value". Emitting `req.clone()` for the request
        // argument keeps the binding alive across all reads — identical pattern
        // to `DictGet` (see the DictGet arm below `emit_server_call`).
        //
        // Server.body   : Request -> String   — req is the only arg (index 0)
        // Server.path   : Request -> String   — req is the only arg (index 0)
        // Server.method : Request -> String   — req is the only arg (index 0)
        KernelFn::ServerBody | KernelFn::ServerPath | KernelFn::ServerMethod => {
            let [req_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_server_call",
                    detail: format!("{k:?} requires exactly 1 argument, got {}", args.len()),
                });
            };
            let fn_name = kernel_name(*k);
            let req_s = emit_expr_at(ctx, req_e, indent, child, generics)?;
            Ok(Some(format!("{fn_name}({req_s}.clone())")))
        }

        // Server.param      : String -> Request -> Maybe String — req is arg 1
        // Server.queryParam : String -> Request -> Maybe String — req is arg 1
        // Server.header     : String -> Request -> Maybe String — req is arg 1
        // Server.getCookie  : String -> Request -> Maybe String — req is arg 1
        KernelFn::ServerParam
        | KernelFn::ServerQueryParam
        | KernelFn::ServerHeader
        | KernelFn::ServerGetCookie => {
            let [name_e, req_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_server_call",
                    detail: format!("{k:?} requires exactly 2 arguments, got {}", args.len()),
                });
            };
            let fn_name = kernel_name(*k);
            let name_s = emit_expr_at(ctx, name_e, indent, child, generics)?;
            let req_s = emit_expr_at(ctx, req_e, indent, child, generics)?;
            Ok(Some(format!("{fn_name}({name_s}, {req_s}.clone())")))
        }

        // `Ipe.Http.Server.Stream.stream : String -> (StreamWriter -> Task Error ()) -> Task Error Response`
        //
        // `server_stream_stream`'s bound is
        // `H: Fn(StreamWriter) -> IpeTask<E, ()> + Send + Sync + 'static`,
        // and unlike `sub_subscribe_stream` (relaxed to Send-only — see that
        // fn's doc comment in `http_stream.rs`), THIS `+Sync` bound is
        // genuinely required: `server_stream_stream` internally does
        // `Arc::new(move |w| { let task = handler(w); .. })` and stores that
        // `Arc` in a process-global `pending_handlers()` registry, popped and
        // driven later by whichever axum worker thread services the
        // eventual request (`server_stream.rs`'s `serve_streaming_sentinel`).
        // Unsizing `Arc<ConcreteClosure>` to the registry's
        // `Arc<dyn Fn(..) -> .. + Send + Sync>` slot requires the captured
        // `handler: H` to itself be `Sync` — the same "value must legitimately
        // live behind a shared `Arc`" shape as `html_on_raw_`'s `Event::OnForm`
        // slot, not the "moved into exactly one spawned task" shape of
        // `sub_subscribe_stream` / `sub_subscribe_topic`. But this kernel
        // reaches codegen through the SAME shared generic N-arg call-emit
        // fallback that passes the codegen's `Box<dyn Fn(..) -> .. + Send +
        // 'static>` value straight through as `H` — a trait object's
        // auto-trait set is exactly its bound list, so that box can never
        // satisfy `+Sync` regardless of what the boxed closure captures.
        // Fix: apply the SAME re-wrap technique used for
        // `html_on_raw_`/`ui_on_submit_` — re-embed the box construction as
        // SOURCE inside a freshly-declared closure built anew at the call
        // site, so the wrapper's own Send+Sync-ness depends only on the Ipê
        // closure's legitimate `move` captures, never the erased trait-object
        // type.
        KernelFn::StreamStream => {
            let [ct_e, handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_server_call::StreamStream",
                    detail: format!("Stream.stream requires exactly 2 arguments, got {}", args.len()),
                });
            };
            let fn_name = kernel_name(*k);
            let ct_s = emit_expr_at(ctx, ct_e, indent, child, generics)?;
            let handler_src = emit_expr_at(ctx, handler_expr, indent, child, generics)?;
            let prologue = stream_handler_capture_prologue(ctx, handler_expr)?;
            Ok(Some(format!(
                "{fn_name}({ct_s}, move |_x| {{ {prologue}({handler_src})(_x) }})"
            )))
        }

        // All remaining server kernels use the standard N-arg call path — no
        // special boxing or argument projection is needed.
        KernelFn::ServerGet
        | KernelFn::ServerPost
        | KernelFn::ServerPut
        | KernelFn::ServerDelete
        | KernelFn::ServerAny
        | KernelFn::ServerApi
        | KernelFn::ServerStatic
        // `Server.mountApp prefix webApp` → `server_mount_app(prefix, webApp)`
        // via the standard 2-arg call path; the `WebApp` arg is the leaf value
        // built by `Web.embed` (a `WebApp(web_app(...))` handle).
        | KernelFn::ServerMountApp
        | KernelFn::ServerListen
        | KernelFn::ServerText
        | KernelFn::ServerJson
        | KernelFn::ServerHtml
        | KernelFn::ServerWithStatus
        | KernelFn::ServerWithHeader
        | KernelFn::ServerRedirect
        | KernelFn::ServerCookieNew
        | KernelFn::ServerWithCookie
        // Authed-route config + token-source constructors use the standard
        // N-arg call path.
        | KernelFn::ServerAuthConfig
        | KernelFn::ServerTokenBearer
        | KernelFn::ServerCookieToken
        | KernelFn::MiddlewareWithCors
        | KernelFn::MiddlewareWithLogging
        | KernelFn::MiddlewareWithBasicAuth
        | KernelFn::MiddlewareWithRateLimit
        | KernelFn::MiddlewareWithCsrf
        | KernelFn::RateLimitAllow
        // ── Ipe.Http.Server.Stream (server-side streaming) ─────────────
        | KernelFn::StreamEmit
        | KernelFn::StreamFinish
        | KernelFn::StreamWithContentType
        // ── Ipe.Http.Stream (client-side relay) ───────────────────
        | KernelFn::HttpStreamOpen
        | KernelFn::HttpStreamForEachChunk
        | KernelFn::HttpStreamClose
        // ── Ipe.Http.Server.WebSocket (12 kernels) ─────────────────────
        | KernelFn::WsDefaultCfg
        | KernelFn::WsWithOnConnect
        | KernelFn::WsWithOnMessage
        | KernelFn::WsWithOnClose
        | KernelFn::WsWithOnError
        | KernelFn::WsWithMaxMessageBytes
        | KernelFn::WsWithOriginPatterns
        | KernelFn::WsUpgrade
        | KernelFn::WsSendToClient
        | KernelFn::WsSendBinaryToClient
        | KernelFn::WsBroadcast
        | KernelFn::WsCloseClient
        // Authed routes take a two-argument handler `Request -> Principal ->
        // Task Error Response`; the shared N-arg call path emits it as a
        // `Box<dyn Fn(ServerRequest, Principal) -> IpeTask<ServerResponse>>`,
        // matching `server_*_authed`'s `F: Fn(ServerRequest, Principal)` bound.
        | KernelFn::ServerGetAuthed
        | KernelFn::ServerPostAuthed
        | KernelFn::ServerPutAuthed
        | KernelFn::ServerDeleteAuthed => Ok(None),
        // Any is_server() variant not listed above is a gap — hard error so
        // the Rust compiler's exhaustiveness check catches it at compile time.
        _ => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_server_call",
            detail: format!(
                "server kernel {k:?} is_server() but has no emit arm — \
                 add it to emit_server_call"
            ),
        }),
    }
}

/// Find a record field by its Ipê source name in an IR field list.
///
/// Searches `fields` linearly for the entry whose interned symbol resolves to
/// `name`.  Returns a reference to the field's value expression on success.
///
/// # Errors
///
/// Returns [`Diagnostic::CompilerBug`] when no field with the requested name
/// is present in the list.  Fail-closed — never silently drops a missing
/// required field (MAKE INVALID STATES UNREPRESENTABLE principle).
/// Render a UI kernel call whose inline cfg-record fields map to POSITIONAL
/// runtime arguments: every argument is hoisted into a block local in IR walk
/// order — `leading` args first, then the cfg fields in their STORED
/// (name-sorted) record order, then `trailing` args — and the call composes
/// the locals in the runtime's positional order (`leading…`, then
/// `positional_fields` by name, then `trailing…`).
///
/// The hoist is load-bearing: the multi-use-clone rewrite walks the record in
/// stored order and leaves the walk-order-LAST use of a value as a bare move.
/// Rendering the fields positionally without the hoist reorders evaluation,
/// so that bare move could run BEFORE an earlier use's `.clone()` (E0382 on
/// `Ui.button`'s `{ onPress, label }`, whose stored order is `label` first
/// but whose positional order passes `onPress` first).
///
/// Appearance hot-swap for record-native kernels: `hoist_fields` names the cfg
/// fields (by Ipê source name + literal kind) whose *direct literal* is an inert
/// appearance value — the [`appearance_literal_record_fields`] companion of the
/// positional [`appearance_literal_args`] registry. When such a field is a direct
/// literal AND the emit is a web shape (the `LiteralTable` is a web-runtime type),
/// its value is hoisted into the per-view table and the field local reads its slot
/// (`__ipe_lit.get(N).to_string()`) instead of the inline literal — the same hoist
/// and read shape the positional path uses, so the baked default renders
/// byte-identically to the direct emit (dev == prod). `hoist_style_literal` further
/// fences hoisting to a function body's top level (never inside a `move` closure)
/// and to the armed flag; a `Model`-dependent or computed field never matches the
/// direct-literal guard and emits directly. A caller with no appearance field
/// passes `&[]` and this path is inert.
#[allow(clippy::too_many_arguments)] // one hoist site per cfg-record kernel; the args mirror emit_expr_at's
pub fn emit_cfg_record_call(
    ctx: &EmitCtx,
    leading: &[&Expr],
    fields: &[(Symbol, Expr)],
    trailing: &[&Expr],
    positional_fields: &[&str],
    hoist_fields: &[(&str, LitKind)],
    callee: &str,
    where_: &'static str,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<String> {
    use std::fmt::Write as _;
    let mut hoist = String::new();
    for (i, e) in leading.iter().enumerate() {
        let rendered = emit_expr_at(ctx, e, indent, child, generics)?;
        // Writing into a String is infallible.
        let _ = write!(hoist, "let __ui_lead{i} = {rendered}; ");
    }
    let mut local_of: Vec<(String, String)> = Vec::with_capacity(fields.len());
    for (i, (sym, fe)) in fields.iter().enumerate() {
        let fname = ctx.resolve_ident(*sym)?;
        // Appearance hot-swap: a registered appearance field holding a direct
        // `Str` literal hoists into the per-view `LiteralTable` (web shape only),
        // reading its slot exactly as the positional path does; every other field
        // — and the whole call in a non-web shape or with the flag off — emits
        // directly, byte-identically to before.
        let hoisted = if ctx.uses_web {
            hoist_fields
                .iter()
                .find(|&&(name, _)| name == fname)
                .and_then(|&(_, kind)| match (kind, fe) {
                    (LitKind::Str, Expr::Str(s)) => ctx
                        .hoist_style_literal(s)
                        .map(|slot| format!("__ipe_lit.get({slot}).to_string()")),
                    // Only `Str` cfg fields are registered today; a non-`Str`
                    // kind or a non-literal field emits directly (never hoists).
                    _ => None,
                })
        } else {
            None
        };
        let rendered = match hoisted {
            Some(read) => read,
            None => emit_expr_at(ctx, fe, indent, child, generics)?,
        };
        let local = format!("__ui_f{i}");
        let _ = write!(hoist, "let {local} = {rendered}; ");
        local_of.push((fname.to_owned(), local));
    }
    for (i, e) in trailing.iter().enumerate() {
        let rendered = emit_expr_at(ctx, e, indent, child, generics)?;
        let _ = write!(hoist, "let __ui_trail{i} = {rendered}; ");
    }
    let mut call_args: Vec<String> = (0..leading.len())
        .map(|i| format!("__ui_lead{i}"))
        .collect();
    for name in positional_fields {
        let local = local_of
            .iter()
            .find(|(f, _)| f == name)
            .map(|(_, l)| l.clone())
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_,
                detail: format!("cfg record is missing required field `{name}`"),
            })?;
        call_args.push(local);
    }
    call_args.extend((0..trailing.len()).map(|i| format!("__ui_trail{i}")));
    Ok(format!("{{ {hoist}{callee}({}) }}", call_args.join(", ")))
}

pub fn lookup_field<'f>(
    ctx: &EmitCtx,
    fields: &'f [(Symbol, Expr)],
    name: &str,
    where_: &'static str,
) -> DResult<&'f Expr> {
    for (sym, expr) in fields {
        if ctx.resolve_ident(*sym)? == name {
            return Ok(expr);
        }
    }
    Err(Diagnostic::CompilerBug {
        where_,
        detail: format!(
            "required field `{name}` not found in Ui.layoutWith cfg record literal; \
             available fields: [{}]",
            fields
                .iter()
                .filter_map(|(s, _)| ctx.resolve_ident(*s).ok())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

/// Arc-wrap an already-emitted callback expression so it fills a runtime
/// `Arc<dyn Fn(_) -> _ + Send + Sync>` slot.
///
/// The `Ipe.Ui.Input.*` runtime functions (`input_text_`, `input_slider_`,
/// `input_checkbox_`, `input_radio_`, …) take their callback fields (`onChange`,
/// checkbox `icon`) as `Arc<dyn Fn(_) -> _ + Send + Sync + 'static>` — the same
/// shared-callback shape every Ipe.Ui / Ipe.Web event slot uses. But an
/// `onChange` field expression lowers as an ordinary value: a bare
/// `Msg`-constructor eta-expands to a plain lambda, and both [`emit_lambda`] and
/// [`emit_func_value`] pin `Box::new(..)` for every non-Server/WS `Fun` shape
/// (see [`wants_arc_ctor`]). Passing that `Box<dyn Fn(_) -> _ + Send>` into the
/// `Arc<.. + Send + Sync>` parameter is an E0308 — a SEAL break.
///
/// Rather than special-casing every callback-carrying shape at the box site,
/// this mirrors the existing `ui_on_input_` / `ui_on_change_` arms (this same
/// file): eta-wrap the emitted callback in a fresh `Arc`-owned closure
/// `::std::sync::Arc::new(move |_x| (f)(_x))`. Rust infers `_x`, so ONE wrap
/// serves every arity-1 callback regardless of arg type (`String` or `bool`) or
/// return type (`Msg` or `Element<Msg>`). The wrap is sound: an emitted Ipê
/// callback is always `'static` (it captures no borrow-lifetime context), so the
/// `move` capture yields a `Send + Sync` `Arc`. This is the reference's uniform
/// Arc-callback policy applied at the call-argument boundary.
pub fn arc_callback_wrap(handler_src: &str) -> String {
    format!("::std::sync::Arc::new(move |_x| ({handler_src})(_x))")
}

/// Emit a `Ipe.Ui.Input.*` callback field, Arc-wrapping it for the runtime's
/// `Arc<dyn Fn(_) -> _ + Send + Sync>` slot (see [`arc_callback_wrap`]) while
/// HOISTING any leading capture-clone `let`s OUTSIDE the `Arc`'s `move` closure.
///
/// the lowerer's multi-use-capture rewrite
/// ([`rewrite_multiuse_clones`]) wraps a callback lambda that captures a
/// non-`Copy` binding used again by a sibling in a pre-clone
/// `let sym = sym.clone() in Lambda { … }`. Emitted naively, that whole block
/// is the string `arc_callback_wrap` wraps, giving
/// `Arc::new(move |_x| (({ let habit = habit.clone(); … }))(_x))`. The `.clone()`
/// reads the FREE outer `habit`, but the enclosing `move |_x|` still
/// move-captures that same outer `habit` — so a later sibling use
/// (`StateMsg::RemoveHabit((habit).id)`) hits use-after-move (E0382). The
/// hoist was already correct for a plain (un-Arc-wrapped) callback arg — the
/// pre-clone `let` sat in the enclosing scope, and only the INNER `move`
/// captured the clone; the `Arc` re-wrap is what re-introduced the outer
/// `move`.
///
/// Fix: peel the leading pure-alias `let`s (`let n = <Var/CloneVar>`; each a
/// value-preserving re-bind) off the callback expression and emit them as a
/// prefix OUTSIDE the `Arc::new`, so the Arc closure owns the pre-made clone
/// and the original binding survives for later sibling uses:
///
/// ```text
/// { let habit = habit.clone(); ::std::sync::Arc::new(move |_x| ((INNER))(_x)) }
/// ```
///
/// Only a `let` whose value is a bare `Var`/`CloneVar` is peeled — a pure
/// alias/clone of an outer symbol whose hoist out of the `move` closure is
/// always semantics-preserving (Ipê values are immutable). A `let` binding a
/// COMPUTED value stays inside, untouched, so no re-ordering of effects or
/// widening of a capture's scope can occur. When there are no such leading
/// `let`s the output is byte-identical to the previous
/// `arc_callback_wrap(&emit_expr_at(..))`.
/// Peel the leading pure-alias capture-clone `let`s off a synthesised callback
/// expression, returning the hoisted bindings and the innermost expression.
///
/// The lowerer's multi-use-capture rewrite ([`rewrite_multiuse_clones`]) wraps a
/// callback lambda that captures a non-`Copy` binding also read by a sibling in
/// a pre-clone `let sym = sym.clone() in Lambda { … }`. Every synthesised event
/// arm emits its handler inside a `move` closure; if that pre-clone `let` is
/// rendered INSIDE the `move`, the closure move-captures the outer binding while
/// the `.clone()` also reads it, and a sibling field/arg reading the same
/// binding then hits use-after-move (E0382 — an accept-then-cargo-fail SEAL
/// break). Peeling the `let` here lets each arm emit it OUTSIDE its `move`
/// closure, so the closure owns the pre-made clone and the original survives.
///
/// Only a `let` whose value is a bare `Var`/`CloneVar` is peeled — a pure
/// alias/clone of an outer symbol whose hoist out of the `move` closure is
/// always semantics-preserving (Ipê values are immutable). A `let` binding a
/// COMPUTED value stays inside, so no re-ordering of effects can occur.
pub fn peel_callback_capture_clones(field: &Expr) -> (Vec<(Symbol, &Expr)>, &Expr) {
    let mut hoisted: Vec<(Symbol, &Expr)> = Vec::new();
    let mut inner = field;
    while let Expr::Let { name, value, body } = inner {
        if matches!(value.as_ref(), Expr::Var(_) | Expr::CloneVar(_)) {
            hoisted.push((*name, value.as_ref()));
            inner = body.as_ref();
        } else {
            break;
        }
    }
    (hoisted, inner)
}

/// Render the peeled capture-clone `let`s ([`peel_callback_capture_clones`]) as
/// a `let n = <value>; ` prefix. Empty when there are no leading pure-alias
/// `let`s, so a capture-free callback's emitted text is byte-identical to the
/// un-peeled form.
pub fn render_hoisted_clone_prefix(
    ctx: &EmitCtx,
    hoisted: &[(Symbol, &Expr)],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<String> {
    let mut prefix = String::new();
    for &(name, value) in hoisted {
        let name_s = ctx.emit_ident(name)?;
        let value_s = emit_expr_at(ctx, value, indent, child, generics)?;
        write!(prefix, "let {name_s} = {value_s}; ").map_err(|e| Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::render_hoisted_clone_prefix",
            detail: format!("fmt::Write into String failed: {e}"),
        })?;
    }
    Ok(prefix)
}

pub fn emit_arc_callback_field(
    ctx: &EmitCtx,
    field: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<String> {
    // Peel leading pure-alias `let`s (`let n = Var(v)` / `let n = CloneVar(v)`).
    let (hoisted, inner) = peel_callback_capture_clones(field);
    // An inline lambda literal goes STRAIGHT into the `Arc` — one closure
    // boundary. The generic wrap-and-redispatch below builds a fresh boxed
    // closure per call of the `Arc` closure, so a callee-position capture of
    // a `Box<dyn Fn>` param would be moved out of the `Fn` env per call
    // (E0507); the direct form moves the capture ONCE at `Arc` construction
    // and every call merely borrows it.
    let arc = if let Expr::Lambda { params, ret, body } | Expr::SharedLambda { params, ret, body } =
        inner
    {
        let closure = emit_lambda_unboxed(ctx, params, ret, body, indent, child, generics)?;
        format!("::std::sync::Arc::new({closure})")
    } else {
        let inner_s = emit_expr_at(ctx, inner, indent, child, generics)?;
        arc_callback_wrap(&inner_s)
    };
    if hoisted.is_empty() {
        return Ok(arc);
    }
    let prefix = render_hoisted_clone_prefix(ctx, &hoisted, indent, child, generics)?;
    Ok(format!("{{ {prefix}{arc} }}"))
}

/// Appearance hot-swap for the one `Ipe.Css` value that reaches Rust: the value
/// sanitizer `CssSafety.safeValue : String -> Maybe String`, emitted as
/// `safe_value(<arg>)` on the generic kernel-call path (it is a `Pure` kernel,
/// not UI-family, so it never reaches the UI-plan positional hoist site).
///
/// When the argument is a **direct string literal** in a web build with hoisting
/// armed, and the literal passes the SHARED CSS-value safety policy
/// (`ipe_kernels::css_value_is_safe` — the exact decision the runtime sanitizer
/// makes), the literal is hoisted into the per-view [`LiteralTable`] and the call
/// becomes `safe_value(__ipe_lit.get(N).to_string())`. Two independent
/// guarantees keep this as safe as the direct emit:
///
/// 1. **Sanitize-before-hoist.** Only a literal the shared policy ACCEPTS is
///    baked; an unsafe literal returns `None` here and falls to the generic tail
///    (`safe_value("expression(…)")`, which the runtime drops) — so an
///    un-sanitized value can never reach the table.
/// 2. **Re-sanitize-on-read.** The `safe_value(…)` wrapper is preserved verbatim,
///    so the runtime re-runs the identical policy on whatever the slot holds —
///    the baked default OR a dev-pushed patch. A hot-swapped value is therefore
///    gated exactly as a compiled one; the hoist can never bypass `CssSafety`.
///
/// Because the policy keeps the caller's ORIGINAL bytes on success, the baked
/// default is byte-identical to the direct literal, so a prod build (never
/// patched) renders exactly as the direct emit — dev == prod. Returns `None`
/// (falls through to the generic tail, byte-identical) for any non-web build,
/// hoisting-disarmed context, non-literal argument, or unsafe literal.
///
/// The selector sanitizer (`safeSelector`) is deliberately absent: a selector is
/// structure (what a rule targets), not an appearance value, and never hoists.
pub fn emit_css_value_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    let Callee::Kernel(k @ KernelFn::CssSafetySafeValue) = callee else {
        return Ok(None);
    };
    // Only applies to a single direct string literal in a web build; every other
    // shape (a non-literal / Model-dependent value, a non-web build) returns
    // `None` so the generic tail emits it exactly as before.
    let [arg_expr @ Expr::Str(s)] = args else {
        return Ok(None);
    };
    if !ctx.uses_web {
        return Ok(None);
    }
    // Sanitize-before-hoist: only a value the shared policy accepts is
    // hoist-eligible. An unsafe literal returns `None` so the generic tail emits
    // `safe_value(<lit>)` verbatim (the runtime drops it) — the table can hold
    // only sanitized values.
    if !ipe_kernels::css_value_is_safe(s) {
        return Ok(None);
    }
    let name = kernel_name(*k);
    // The `safe_value(…)` wrapper is preserved in BOTH forms, so the runtime
    // re-runs the identical policy on whatever the argument evaluates to (a baked
    // default OR a dev-pushed patch) — the hoist cannot bypass `CssSafety`.
    //
    // Returning `Some` for the applicable case (even when hoisting is disarmed)
    // keeps this a stable "special case": the classifier
    // ([`call_has_kernel_special_case`]) probes with hoisting suppressed, so a
    // hoist-conditional `None` would mis-route the real emit. When disarmed (flag
    // off, no active body, or inside a `move` closure) the direct literal is
    // emitted, byte-identical to the generic tail.
    if let Some(slot) = ctx.hoist_style_literal(s) {
        Ok(Some(format!("{name}(__ipe_lit.get({slot}).to_string())")))
    } else {
        let arg = emit_expr_at(ctx, arg_expr, indent, child, generics)?;
        Ok(Some(format!("{name}({arg})")))
    }
}

/// Handle `Ipe.Ui` / `Ipe.Html` kernel calls.
///
/// Two steps: [`ui_call_shape`] classifies the kernel into a pure
/// [`UiEmitPlan`] (or `None` for a non-UI-family kernel), then [`emit_ui_plan`]
/// interprets the plan into emitted Rust. The uniform majority — a call to one
/// runtime path with N positionally emitted arguments — needs no per-kernel
/// code; the capability and security leaves (record configs, event-handler
/// wiring, the HTML serialiser, deferred-subtree wrappers, the `Ui.cells` seal,
/// and the shape-router delegations) are dispatched by their plan's native tag.
///
/// Emit a provably-static `Ipe.Html` subtree as a hoisted template read, or
/// `None` to fall through to the ordinary inline emit.
///
/// Fires ONLY when every gate holds: a web shape (`uses_web` — the template
/// table is a web-runtime type), the subtree is templatable
/// ([`crate::emit_template::template_of_expr`]), and hoisting is armed
/// ([`EmitCtx::hoist_style_literal`] returns a slot — which it does not under
/// the flag-off / production emit, nor inside a `move` closure or a discard
/// probe). Under any of those the function returns `None` and the subtree emits
/// inline, byte-for-byte as before — so release / `ipe build` output is
/// unchanged (golden-verified) and dev == prod at the emit level (the baked
/// default IS the serialized template).
///
/// The whole subtree collapses into ONE literal slot (its serialized JSON), so
/// a structural edit is a single-slot value change the shipped emit-diff
/// classifier already routes to the zero-compile hot-swap path.
pub fn emit_html_template(ctx: &EmitCtx, expr: &Expr) -> Option<String> {
    if !ctx.uses_web {
        return None;
    }
    // Only an ELEMENT node (`Html.node` / `Html.voidNode`) is templated at the
    // top level. A bare `Html.text` / `Html.titleNode` leaf is already covered by
    // the appearance-literal registry (its string value hoists as a leaf), so
    // leaving it to that path keeps the leaf emit — and the registry's
    // self-enforcing conformance tests — unchanged. A text/title node NESTED
    // inside a templated element is still absorbed into that element's template
    // (via the child walk), never emitted separately.
    match expr {
        Expr::Call {
            callee: Callee::Kernel(KernelFn::HtmlNode | KernelFn::HtmlVoidNode),
            ..
        } => {}
        _ => return None,
    }
    let template = crate::emit_template::template_of_expr(expr)?;
    let slot = ctx.hoist_style_literal(&template.to_json())?;
    // `M` is inferred from the surrounding element/return position, exactly as
    // an inline `html_node_(…)` infers it — no turbofish.
    Some(format!(
        "ipe_runtime::web::template::materialize_template_str(__ipe_lit.get({slot}))"
    ))
}

/// Emit a mostly-static `Ipe.Ui` subtree as a hoisted template read, or `None`
/// to fall through to the ordinary inline emit — the `Ipe.Ui` analogue of
/// [`emit_html_template`].
///
/// Fires ONLY when every gate holds: a web shape (`uses_web`), the subtree
/// partitions ([`crate::emit_ui_template::ui_template_of_expr_holes`]), and
/// hoisting is armed ([`EmitCtx::hoist_style_literal`] returns a slot — which it
/// does not under the flag-off / production emit, nor inside a `move` closure or a
/// discard probe). Under any of those the function returns `None` and the subtree
/// emits inline, byte-for-byte as before — so release / `ipe build` output is
/// unchanged (golden-verified) and dev == prod at the emit level (the baked
/// default IS the serialized template).
///
/// ## Holes
///
/// A fully-static subtree emits `materialize_str(slot, TemplateFills::default())`.
/// A subtree with `Model`-derived **holes** (a value leaf, an `if` / `case`
/// control-flow result, or a `List.map` comprehension) emits the same
/// `materialize_str(slot, TemplateFills::default().with_*(…))` with one `with_*`
/// builder per hole kind present: the static skeleton (with numbered hole markers)
/// rides the hoisted slot and hot-swaps on a structural edit, while each hole's
/// fill is emitted here as ordinary compiled code and stays compiled.
///
/// Control-flow branches templatize by composition: a fill is emitted through the
/// normal [`emit_expr_at`], so a static `Ipe.Ui` branch of the compiled `if`/`case`
/// hits THIS emitter recursively and hoists into its own slot — editing that
/// branch's static structure is itself a template patch, while the condition stays
/// compiled. The whole-template JSON (markers included) rides one baked-defaults
/// string, so the appearance classifier needs no change: a skeleton edit moves
/// only that string (hot-swap), and a change to the hole COUNT moves the compiled
/// `vec![…]` (recompile) — conservative by construction.
///
/// The materialized read returns an `Element<M>` (not `Html`), exactly what an
/// inline `ui_node_(…)` yields, so it drops into the surrounding element position
/// unchanged; `M` is inferred from that position.
/// Compile list-hole fills for [`emit_ui_template`]. Each fill is an iterator
/// expression that yields one `Vec<Element<M>>` per item — the per-item
/// element-fill vec for one materialization of the list hole's item template.
pub fn compile_list_fills(
    ctx: &EmitCtx,
    list_holes: &[crate::emit_ui_template::ListHoleFill],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Vec<String>> {
    let mut v = Vec::with_capacity(list_holes.len());
    for lh in list_holes {
        let xs_code = emit_expr_at(ctx, &lh.xs, indent, child, generics)?;
        let item_name = format!("__ipe_li_{}", lh.item_sym.as_raw());
        let mut fills = Vec::with_capacity(lh.item_fills.len());
        for fill_expr in &lh.item_fills {
            fills.push(emit_expr_at(ctx, fill_expr, indent, child, generics)?);
        }
        let fills_vec = if fills.is_empty() {
            "vec![]".to_string()
        } else {
            format!("vec![{}]", fills.join(", "))
        };
        v.push(format!(
            "({xs_code}).iter().map(|{item_name}| {fills_vec}).collect::<Vec<_>>()"
        ));
    }
    Ok(v)
}

pub fn emit_ui_template(
    ctx: &EmitCtx,
    expr: &Expr,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    if !ctx.uses_web {
        return Ok(None);
    }
    // Accept a direct element-node kernel call (`Ui.node` / `Ui.taggedNode`),
    // or a structural wrapper func whose id is registered in the wrapper table.
    // A bare `Ui.text` leaf is already covered by the appearance-literal
    // registry (`KernelFn::UiText`), so leaving it to that path keeps the leaf
    // emit unchanged. A text/none/nested node inside a templated element is
    // still absorbed into that element's template.
    let Expr::Call { callee, .. } = expr else {
        return Ok(None);
    };
    match callee {
        Callee::Kernel(KernelFn::UiNode | KernelFn::UiTaggedNode) => {}
        Callee::Func(id) if ctx.ui_structural_wrappers.contains_key(id) => {}
        _ => return Ok(None),
    }
    // The mostly-static partition: a fully-static subtree yields an empty hole
    // set (the shipped path); a subtree with `Model`-derived value / control-flow
    // / `List.map` holes yields hole markers plus the compiled fills. `None` keeps
    // the subtree compiled (conservative).
    let Some(partition) =
        crate::emit_ui_template::ui_template_of_expr_holes(expr, Some(&ctx.ui_structural_wrappers))
    else {
        return Ok(None);
    };
    let Some(slot) = ctx.hoist_style_literal(&partition.template.to_json()) else {
        return Ok(None);
    };
    let has_holes = !partition.holes.is_empty();
    let has_handlers = !partition.handlers.is_empty();
    let has_cf = !partition.cf_holes.is_empty();
    // Compile handler Msg expressions (shared by the handler-only and combined paths).
    let handler_msgs: Vec<String> = if has_handlers {
        let mut v = Vec::with_capacity(partition.handlers.len());
        for msg in &partition.handlers {
            v.push(emit_expr_at(ctx, msg, indent, child, generics)?);
        }
        v
    } else {
        Vec::new()
    };
    // Compile value/children hole fills (shared by the holes-only and combined paths).
    let (element_fills, children_fills): (Vec<String>, Vec<String>) = if has_holes {
        let mut elem: Vec<String> = Vec::new();
        let mut kids: Vec<String> = Vec::new();
        for hole in &partition.holes {
            let code = emit_expr_at(ctx, &hole.expr, indent, child, generics)?;
            match hole.kind {
                crate::emit_ui_template::HoleKind::Element => elem.push(code),
                crate::emit_ui_template::HoleKind::Children => kids.push(code),
                crate::emit_ui_template::HoleKind::ControlFlow
                | crate::emit_ui_template::HoleKind::FloatAttr => {
                    // ControlFlow fills live in cf_holes; FloatAttr fills live in
                    // float_attr_holes — neither can appear in `partition.holes`
                    // by construction.
                }
            }
        }
        (elem, kids)
    } else {
        (Vec::new(), Vec::new())
    };
    // Compile control-flow arm-selector expressions. Each fill evaluates to an
    // integer arm index; we cast it to `usize` in the emitted code so the runtime
    // materializer receives the correct type for its `cf_selectors` vec.
    let cf_selectors: Vec<String> = if has_cf {
        let mut v = Vec::with_capacity(partition.cf_holes.len());
        for cf in &partition.cf_holes {
            let code = emit_expr_at(ctx, &cf.expr, indent, child, generics)?;
            // Wrap in an `as usize` cast: the selector expression yields `i64`
            // (Ipê's integer type), the runtime vec expects `usize`.
            v.push(format!("({code}) as usize"));
        }
        v
    } else {
        Vec::new()
    };
    let list_fills: Vec<String> = if partition.list_holes.is_empty() {
        Vec::new()
    } else {
        compile_list_fills(ctx, &partition.list_holes, indent, child, generics)?
    };
    // Compile float-attr hole fills. Each expression evaluates to an `f64`
    // (Ipê's `Float` type) — no cast needed, `f64` is the runtime's slot type.
    let float_attr_fills: Vec<String> = if partition.float_attr_holes.is_empty() {
        Vec::new()
    } else {
        let mut v = Vec::with_capacity(partition.float_attr_holes.len());
        for fa in &partition.float_attr_holes {
            v.push(emit_expr_at(ctx, &fa.expr, indent, child, generics)?);
        }
        v
    };
    Ok(Some(select_ui_materializer_call(
        slot,
        &CompiledFills {
            element_fills: &element_fills,
            children_fills: &children_fills,
            handler_msgs: &handler_msgs,
            cf_selectors: &cf_selectors,
            list_fills: &list_fills,
            float_attr_fills: &float_attr_fills,
        },
    )))
}

/// Pre-compiled fill vecs for each hole kind in a templatized `Ui` subtree.
pub struct CompiledFills<'a> {
    element_fills: &'a [String],
    children_fills: &'a [String],
    handler_msgs: &'a [String],
    cf_selectors: &'a [String],
    list_fills: &'a [String],
    float_attr_fills: &'a [String],
}

/// Format the one runtime materializer call: `materialize_str(slot, fills)` over
/// a [`TemplateFills`] built from whichever fill kinds are present. Each non-empty
/// fill vec appends one `with_*` builder; an absent kind is simply left at its
/// `Default` empty. Every combination is representable and resolved in one pass —
/// no fill kind is ever dropped for coexisting with another (the pre-fold
/// materializer front doors silently excluded handler×list and float×other).
pub fn select_ui_materializer_call(slot: usize, f: &CompiledFills<'_>) -> String {
    use std::fmt::Write as _;
    let mut call = String::from("ipe_runtime::ui::template::TemplateFills::default()");
    // `write!` into a `String` is infallible; the `Result` is discarded by design.
    if !f.element_fills.is_empty() {
        let _ = write!(call, ".with_elements(vec![{}])", f.element_fills.join(", "));
    }
    if !f.children_fills.is_empty() {
        let _ = write!(
            call,
            ".with_children(vec![{}])",
            f.children_fills.join(", ")
        );
    }
    if !f.list_fills.is_empty() {
        let _ = write!(call, ".with_list_items(vec![{}])", f.list_fills.join(", "));
    }
    if !f.cf_selectors.is_empty() {
        let _ = write!(
            call,
            ".with_control_flow(vec![{}])",
            f.cf_selectors.join(", ")
        );
    }
    if !f.float_attr_fills.is_empty() {
        let _ = write!(
            call,
            ".with_float_attrs(vec![{}])",
            f.float_attr_fills.join(", ")
        );
    }
    if !f.handler_msgs.is_empty() {
        let _ = write!(
            call,
            ".with_handlers(ipe_runtime::ui::template::UiHandlerMap::from_msgs(vec![{}]))",
            f.handler_msgs.join(", "),
        );
    }
    format!("ipe_runtime::ui::template::materialize_str(__ipe_lit.get({slot}), {call})")
}

/// Returns `None` for any kernel that is not a `Ui` / `Web` / `Terminal` /
/// `WebView` variant, letting the standard call path handle it.
pub fn emit_ui_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    on_form: ipe_ir::OnFormKind,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    let Callee::Kernel(k) = callee else {
        return Ok(None);
    };
    let Some(plan) = ui_call_shape(*k) else {
        return Ok(None);
    };
    emit_ui_plan(
        ctx, &plan, *k, callee, args, on_form, indent, child, generics,
    )
    .map(Some)
}

/// Interpret one [`UiEmitPlan`] into the emitted Rust the call lowers to.
///
/// A [`ArgPlan::Positional`] plan emits each argument in order and formats them
/// into the plan's runtime path — the uniform shape that subsumes the majority
/// of UI kernels. A [`ArgPlan::Native`] plan dispatches to the bespoke emission
/// for that capability or security leaf. The single [`Guard::RejectInWebShape`]
/// check runs first, fail-closed.
#[allow(clippy::too_many_lines)] // the capability-leaf emitters, gathered under one native dispatch
#[allow(clippy::many_single_char_names)] // r/g/b/a are the conventional colour-channel names in moved arms
#[allow(clippy::too_many_arguments)] // the emit thread-through (ctx, callee, on_form, indent, child, generics)
pub fn emit_ui_plan(
    ctx: &EmitCtx,
    plan: &UiEmitPlan,
    k: KernelFn,
    callee: &Callee,
    args: &[Expr],
    on_form: ipe_ir::OnFormKind,
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<String> {
    // Guard first — fail closed. `Ui.cells` paints raw terminal cells and has
    // no browser denotation; in a Web/WebView build its runtime helper degrades
    // to plain text, so it would ipe-succeed and silently render wrong. Reject
    // it here — the one point it is emitted — converting a wrong render into a
    // shape-keyed ipe error.
    if plan.guard == Guard::RejectInWebShape
        && (ctx.uses_web || ctx.uses_webview || ctx.uses_console)
    {
        let app = if ctx.uses_webview {
            ipe_diagnostics::AppShape::WebView
        } else if ctx.uses_web {
            ipe_diagnostics::AppShape::Web
        } else {
            ipe_diagnostics::AppShape::Cli
        };
        let msg = if ctx.uses_console {
            LowerError::UiCellsInCliShape(app)
        } else {
            LowerError::UiCellsInWebShape(app)
        };
        return Err(Diagnostic::Lower {
            span: Span::DUMMY,
            msg,
        });
    }

    // The inverse seal: `CustomElement.node`'s up-event handler rides the seal codec,
    // which lives only in a browser build (`web` / `webview` force the `json`
    // runtime feature — `Terminal` / `Program` never do). Emitting it in a
    // non-browser shape would produce an inert node (a widget with no transport)
    // and trip the non-`json` runtime fallback whose up-event type parameter is
    // unconstrained (rustc E0282). Reject it here — the one point it is emitted —
    // converting a would-be dead element (and cargo failure) into a shape-keyed
    // ipe error. A browser shape sets `uses_web` (forced true under `uses_webview`).
    if plan.guard == Guard::RejectInNonWebShape && !(ctx.uses_web || ctx.uses_webview) {
        return Err(Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::UiWidgetInNonWebShape,
        });
    }

    let native = match plan.args {
        // The uniform majority: emit each argument in order, join, format into
        // the runtime path. `arity == 0` emits `path()`. A wrong argument count
        // is a compiler bug — the lowerer already enforced the kernel's arity.
        ArgPlan::Positional { path, arity } => {
            if args.len() != usize::from(arity) {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_plan",
                    detail: format!(
                        "{k:?} requires exactly {arity} arguments, got {}",
                        args.len()
                    ),
                });
            }
            // Appearance hot-swap: when this argument sits in a hoist-eligible
            // position of the appearance-literal registry AND is a direct literal
            // of the registered kind, route it through the per-view
            // `LiteralTable` instead of emitting the literal inline. The registry
            // (`appearance_literal_args`) is the single SSOT across every
            // appearance-only surface — `Ipe.Ui` style/attribute/text values,
            // `Ipe.Html`, `Ipe.Css`. The table is a web-runtime type, so this
            // fires only in a web shape; `hoist_style_literal` further fences it
            // to a function body's top level (never inside a `move` closure) and
            // only when hoisting is armed. Every other argument — and the whole
            // call with the flag off — emits exactly as before.
            //
            // Each entry names its literal kind. A `Str` value bakes as itself
            // and reads back as a `String`. A typed `Int`/`Float` value bakes as
            // its canonical decimal string (the numeric constant the style
            // renders) and reads back through `parse::<T>().unwrap_or(<literal>)`
            // — the baked default parses to the identical value, so the built
            // node/`Attribute`/`Color` and its rendered HTML/CSS are byte-identical
            // to the direct emit (dev == prod); the total `unwrap_or` fallback is
            // the original literal, so a stale or malformed patch can neither
            // panic nor change the built value.
            // Gate on the shape-aware `hot_appearance` flag (armed for a web or
            // tui view under `ipe watch`), NOT `uses_web`: the table now lives in
            // `ipe_runtime::literal_table`, present for a terminal dev-loop build
            // (`control-wire`) as well as a web one (`web-core`), so a `Tui.tea`
            // appearance literal hoists too. WHICH kernels hoist is itself
            // shape-aware: a web shape hoists every appearance literal, a terminal
            // shape hoists only the terminal-appearance kernels
            // (`shape_appearance_literal_args`), so a web-DOM / CSS literal
            // (`Ui.text`, `Font.family`) reaching a tui shape emits inline — a tui
            // view never routes a web-content construct through the table. With
            // the flag off no position is marked, and every argument emits inline
            // exactly as before (dev == prod by absence).
            let positions: &[(usize, LitKind)] = if ctx.hot_appearance {
                shape_appearance_literal_args(k, ctx.uses_web, ctx.uses_tui)
            } else {
                &[]
            };
            let mut rendered = Vec::with_capacity(args.len());
            for (i, a) in args.iter().enumerate() {
                let kind = positions
                    .iter()
                    .find_map(|&(pos, kind)| (pos == i).then_some(kind));
                let hoisted = match (kind, a) {
                    (Some(LitKind::Str), Expr::Str(s)) => ctx
                        .hoist_style_literal(s)
                        .map(|slot| format!("__ipe_lit.get({slot}).to_string()")),
                    (Some(LitKind::Int), Expr::Int(n)) => {
                        ctx.hoist_style_literal(&n.to_string()).map(|slot| {
                            format!("__ipe_lit.get({slot}).parse::<i64>().unwrap_or({n}i64)")
                        })
                    }
                    (Some(LitKind::Float), Expr::Float(f)) if f.is_finite() => {
                        ctx.hoist_style_literal(&format!("{f}")).map(|slot| {
                            format!(
                                "__ipe_lit.get({slot}).parse::<f64>().unwrap_or({})",
                                float_literal(*f)
                            )
                        })
                    }
                    _ => None,
                };
                match hoisted {
                    Some(read) => rendered.push(read),
                    None => rendered.push(emit_expr_at(ctx, a, indent, child, generics)?),
                }
            }
            return Ok(format!("{path}({})", rendered.join(", ")));
        }
        ArgPlan::Native(native) => native,
    };

    match native {
        // `Ui.layoutWith : { wrapperAttrs : ..., rootAttrs : ... } -> Element msg -> Html msg`
        //
        // Emits: `ipe_runtime::ui::render::ui_layout_with_vecs::<M>(wrapper, root, elem)`
        //
        // DESIGN: the runtime's generic `ui_layout_with<M, C>` stub was the
        // silent-drop path (`_cfg` ignored, falls back to `ui_layout(vec![], …)`).
        // That path is deleted (MAKE INVALID STATES UNREPRESENTABLE).
        //
        // We delegate at the emit site instead: extract `wrapperAttrs` and
        // `rootAttrs` directly from the IR record literal and pass them as
        // `Vec<Attribute<M>>` to `ui_layout_with_vecs`, bypassing the unsynthesised
        // record struct that would trigger IPE-I0001 if materialised.
        //
        // Non-literal cfg (e.g. `let cfg = { … } in Ui.layoutWith cfg elem`) is
        // rejected fail-closed with `CompilerBug` (unsupported).
        NativeUiEmit::LayoutWith => {
            let [cfg_e, elem_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiLayoutWith",
                    detail: format!(
                        "Ui.layoutWith requires exactly 2 arguments, got {}",
                        args.len()
                    ),
                });
            };
            // Extract fields from the IR literal rather than materialising a
            // synthesised Rust struct (which would ICE with IPE-I0001 because
            // no struct for the {wrapperAttrs, rootAttrs} shape is registered).
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiLayoutWith",
                    detail: "Ui.layoutWith cfg must be an inline record literal \
                             in Phase 0; non-literal cfg is deferred to Phase 1"
                        .into(),
                });
            };
            // Same bottom-up M inference as UiLayout — no turbofish.
            Ok(emit_cfg_record_call(
                ctx,
                &[],
                fields,
                &[elem_e],
                &["wrapperAttrs", "rootAttrs"],
                &[],
                "ipe_runtime::ui::render::ui_layout_with_vecs",
                "ipe_backend_rust::emit_ui_call::UiLayoutWith",
                indent,
                child,
                generics,
            )?)
        }

        // `Html.render : Html msg -> String`
        //
        // Emits: `ipe_runtime::html::render_html(&html)`
        NativeUiEmit::HtmlSerialise => {
            let [html_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::HtmlRender",
                    detail: format!(
                        "Html.render requires exactly 1 argument, got {}",
                        args.len()
                    ),
                });
            };
            let html_s = emit_expr_at(ctx, html_e, indent, child, generics)?;
            Ok(format!("ipe_runtime::html::render_html(&{html_s})"))
        }

        // `Ui.button : List (Attribute msg) -> { onPress : Maybe msg, label : Element msg } -> Element msg`
        //
        // Emits: `ipe_runtime::ui::helpers::ui_button_(attrs, on_press, label)`
        NativeUiEmit::Button => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiButton",
                    detail: format!("Ui.button requires 2 arguments, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiButton",
                    detail: "Ui.button cfg must be an inline record literal \
                             in Phase 0; non-literal cfg is deferred to Phase 1"
                        .into(),
                });
            };
            Ok(emit_cfg_record_call(
                ctx,
                &[attrs_e],
                fields,
                &[],
                &["onPress", "label"],
                &[],
                "ipe_runtime::ui::helpers::ui_button_",
                "ipe_backend_rust::emit_ui_call::UiButton",
                indent,
                child,
                generics,
            )?)
        }

        // `Ui.link : List (Attribute msg) -> { url : String, label : Element msg } -> Element msg`
        NativeUiEmit::Link => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiLink",
                    detail: format!("Ui.link requires 2 arguments, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiLink",
                    detail: "Ui.link cfg must be an inline record literal \
                             in Phase 0; non-literal cfg is deferred to Phase 1"
                        .into(),
                });
            };
            Ok(emit_cfg_record_call(
                ctx,
                &[attrs_e],
                fields,
                &[],
                &["url", "label"],
                &[],
                "ipe_runtime::ui::helpers::ui_link_",
                "ipe_backend_rust::emit_ui_call::UiLink",
                indent,
                child,
                generics,
            )?)
        }

        // `Ui.image : List (Attribute msg) -> { src : String, description : String } -> Element msg`
        NativeUiEmit::Image => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiImage",
                    detail: format!("Ui.image requires 2 arguments, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiImage",
                    detail: "Ui.image cfg must be an inline record literal \
                             in Phase 0; non-literal cfg is deferred to Phase 1"
                        .into(),
                });
            };
            Ok(emit_cfg_record_call(
                ctx,
                &[attrs_e],
                fields,
                &[],
                &["src", "description"],
                // Appearance hot-swap: `src` and `description` are inert `<img>`
                // attribute values; a direct literal in either hoists into the
                // per-view `LiteralTable` (web shape only), read back as a
                // `String` byte-identically to the direct emit.
                appearance_literal_record_fields(KernelFn::UiImage),
                "ipe_runtime::ui::helpers::ui_image_",
                "ipe_backend_rust::emit_ui_call::UiImage",
                indent,
                child,
                generics,
            )?)
        }

        // `Ui.paddingEach : { top : Int, right : Int, bottom : Int, left : Int } -> Attribute msg`
        NativeUiEmit::PaddingEach => {
            let [rec_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiPaddingEach",
                    detail: format!("Ui.paddingEach requires 1 argument, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = rec_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiPaddingEach",
                    detail: "Ui.paddingEach arg must be an inline record literal".into(),
                });
            };
            let top_e = lookup_field(
                ctx,
                fields,
                "top",
                "ipe_backend_rust::emit_ui_call::UiPaddingEach::top",
            )?;
            let right_e = lookup_field(
                ctx,
                fields,
                "right",
                "ipe_backend_rust::emit_ui_call::UiPaddingEach::right",
            )?;
            let bottom_e = lookup_field(
                ctx,
                fields,
                "bottom",
                "ipe_backend_rust::emit_ui_call::UiPaddingEach::bottom",
            )?;
            let left_e = lookup_field(
                ctx,
                fields,
                "left",
                "ipe_backend_rust::emit_ui_call::UiPaddingEach::left",
            )?;
            let top = emit_expr_at(ctx, top_e, indent, child, generics)?;
            let right = emit_expr_at(ctx, right_e, indent, child, generics)?;
            let bottom = emit_expr_at(ctx, bottom_e, indent, child, generics)?;
            let left = emit_expr_at(ctx, left_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::helpers::ui_padding_each_({top}, {right}, {bottom}, {left})"
            ))
        }

        // `Border.widthEach : { top : Int, right : Int, bottom : Int, left : Int } -> Attribute msg`
        NativeUiEmit::BorderWidthEach => {
            let [rec_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::BorderWidthEach",
                    detail: format!("Border.widthEach requires 1 argument, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = rec_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::BorderWidthEach",
                    detail: "Border.widthEach arg must be an inline record literal".into(),
                });
            };
            let top_e = lookup_field(
                ctx,
                fields,
                "top",
                "ipe_backend_rust::emit_ui_call::BorderWidthEach::top",
            )?;
            let right_e = lookup_field(
                ctx,
                fields,
                "right",
                "ipe_backend_rust::emit_ui_call::BorderWidthEach::right",
            )?;
            let bottom_e = lookup_field(
                ctx,
                fields,
                "bottom",
                "ipe_backend_rust::emit_ui_call::BorderWidthEach::bottom",
            )?;
            let left_e = lookup_field(
                ctx,
                fields,
                "left",
                "ipe_backend_rust::emit_ui_call::BorderWidthEach::left",
            )?;
            let top = emit_expr_at(ctx, top_e, indent, child, generics)?;
            let right = emit_expr_at(ctx, right_e, indent, child, generics)?;
            let bottom = emit_expr_at(ctx, bottom_e, indent, child, generics)?;
            let left = emit_expr_at(ctx, left_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::helpers::ui_border_width_each_({top}, {right}, {bottom}, {left})"
            ))
        }

        // `Border.shadow : { offsetX : Int, offsetY : Int, blur : Int, spread : Int, color : Color } -> Attribute msg`
        NativeUiEmit::BorderShadow => {
            let [rec_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::BorderShadow",
                    detail: format!("Border.shadow requires 1 argument, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = rec_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::BorderShadow",
                    detail: "Border.shadow arg must be an inline record literal".into(),
                });
            };
            // Distinct binding names (`horiz`/`vert` rather than `offset_x`/
            // `offset_y`) keep clippy::similar_names quiet — the source record
            // fields are still `offsetX`/`offsetY`.
            let horiz_e = lookup_field(
                ctx,
                fields,
                "offsetX",
                "ipe_backend_rust::emit_ui_call::BorderShadow::offsetX",
            )?;
            let vert_e = lookup_field(
                ctx,
                fields,
                "offsetY",
                "ipe_backend_rust::emit_ui_call::BorderShadow::offsetY",
            )?;
            let blur_e = lookup_field(
                ctx,
                fields,
                "blur",
                "ipe_backend_rust::emit_ui_call::BorderShadow::blur",
            )?;
            let spread_e = lookup_field(
                ctx,
                fields,
                "spread",
                "ipe_backend_rust::emit_ui_call::BorderShadow::spread",
            )?;
            let color_e = lookup_field(
                ctx,
                fields,
                "color",
                "ipe_backend_rust::emit_ui_call::BorderShadow::color",
            )?;
            let horiz = emit_expr_at(ctx, horiz_e, indent, child, generics)?;
            let vert = emit_expr_at(ctx, vert_e, indent, child, generics)?;
            let blur = emit_expr_at(ctx, blur_e, indent, child, generics)?;
            let spread = emit_expr_at(ctx, spread_e, indent, child, generics)?;
            let color = emit_expr_at(ctx, color_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::helpers::ui_border_shadow_({horiz}, {vert}, {blur}, {spread}, {color})"
            ))
        }

        // `Border.innerShadow : { offsetX : Int, offsetY : Int, blur : Int, spread : Int, color : Color } -> Attribute msg`
        // Same record destructure as `Border.shadow`, emitting the INSET helper.
        NativeUiEmit::BorderInnerShadow => {
            let [rec_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::BorderInnerShadow",
                    detail: format!("Border.innerShadow requires 1 argument, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = rec_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::BorderInnerShadow",
                    detail: "Border.innerShadow arg must be an inline record literal".into(),
                });
            };
            // Distinct binding names (`horiz`/`vert` rather than `offset_x`/
            // `offset_y`) keep clippy::similar_names quiet — the source record
            // fields are still `offsetX`/`offsetY`.
            let horiz_e = lookup_field(
                ctx,
                fields,
                "offsetX",
                "ipe_backend_rust::emit_ui_call::BorderInnerShadow::offsetX",
            )?;
            let vert_e = lookup_field(
                ctx,
                fields,
                "offsetY",
                "ipe_backend_rust::emit_ui_call::BorderInnerShadow::offsetY",
            )?;
            let blur_e = lookup_field(
                ctx,
                fields,
                "blur",
                "ipe_backend_rust::emit_ui_call::BorderInnerShadow::blur",
            )?;
            let spread_e = lookup_field(
                ctx,
                fields,
                "spread",
                "ipe_backend_rust::emit_ui_call::BorderInnerShadow::spread",
            )?;
            let color_e = lookup_field(
                ctx,
                fields,
                "color",
                "ipe_backend_rust::emit_ui_call::BorderInnerShadow::color",
            )?;
            let horiz = emit_expr_at(ctx, horiz_e, indent, child, generics)?;
            let vert = emit_expr_at(ctx, vert_e, indent, child, generics)?;
            let blur = emit_expr_at(ctx, blur_e, indent, child, generics)?;
            let spread = emit_expr_at(ctx, spread_e, indent, child, generics)?;
            let color = emit_expr_at(ctx, color_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::helpers::ui_border_inner_shadow_({horiz}, {vert}, {blur}, {spread}, {color})"
            ))
        }

        // ── Ipe.Ui.Input — text-family controls ────────────────────────
        NativeUiEmit::InputText => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputText",
                    detail: format!(
                        "Input.text/email/… requires 2 arguments, got {}",
                        args.len()
                    ),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputText",
                    detail: "Input.text cfg must be an inline record literal in Phase 0; \
                             non-literal cfg is deferred to Phase 1"
                        .into(),
                });
            };
            let on_change_e = lookup_field(
                ctx,
                fields,
                "onChange",
                "ipe_backend_rust::emit_ui_call::InputText::onChange",
            )?;
            let text_e = lookup_field(
                ctx,
                fields,
                "text",
                "ipe_backend_rust::emit_ui_call::InputText::text",
            )?;
            let placeholder_e = lookup_field(
                ctx,
                fields,
                "placeholder",
                "ipe_backend_rust::emit_ui_call::InputText::placeholder",
            )?;
            let label_e = lookup_field(
                ctx,
                fields,
                "label",
                "ipe_backend_rust::emit_ui_call::InputText::label",
            )?;
            let attrs_s = emit_expr_at(ctx, attrs_e, indent, child, generics)?;
            let on_change_s = emit_arc_callback_field(ctx, on_change_e, indent, child, generics)?;
            let text_s = emit_expr_at(ctx, text_e, indent, child, generics)?;
            let placeholder_s = emit_expr_at(ctx, placeholder_e, indent, child, generics)?;
            let label_s = emit_expr_at(ctx, label_e, indent, child, generics)?;
            let fn_name = match k {
                KernelFn::InputEmail => "input_email_",
                KernelFn::InputUsername => "input_username_",
                KernelFn::InputSearch => "input_search_",
                KernelFn::InputCurrentPassword => "input_current_password_",
                KernelFn::InputNewPassword => "input_new_password_",
                _ => "input_text_",
            };
            Ok(format!(
                "ipe_runtime::ui::input::{fn_name}({attrs_s}, {on_change_s}, {text_s}, {placeholder_s}, {label_s})"
            ))
        }

        NativeUiEmit::InputMultiline => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputMultiline",
                    detail: format!("Input.multiline requires 2 arguments, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputMultiline",
                    detail: "Input.multiline cfg must be an inline record literal in Phase 0"
                        .into(),
                });
            };
            let on_change_e = lookup_field(
                ctx,
                fields,
                "onChange",
                "ipe_backend_rust::emit_ui_call::InputMultiline::onChange",
            )?;
            let text_e = lookup_field(
                ctx,
                fields,
                "text",
                "ipe_backend_rust::emit_ui_call::InputMultiline::text",
            )?;
            let placeholder_e = lookup_field(
                ctx,
                fields,
                "placeholder",
                "ipe_backend_rust::emit_ui_call::InputMultiline::placeholder",
            )?;
            let label_e = lookup_field(
                ctx,
                fields,
                "label",
                "ipe_backend_rust::emit_ui_call::InputMultiline::label",
            )?;
            let spellcheck_e = lookup_field(
                ctx,
                fields,
                "spellcheck",
                "ipe_backend_rust::emit_ui_call::InputMultiline::spellcheck",
            )?;
            let attrs_s = emit_expr_at(ctx, attrs_e, indent, child, generics)?;
            let on_change_s = emit_arc_callback_field(ctx, on_change_e, indent, child, generics)?;
            let text_s = emit_expr_at(ctx, text_e, indent, child, generics)?;
            let placeholder_s = emit_expr_at(ctx, placeholder_e, indent, child, generics)?;
            let label_s = emit_expr_at(ctx, label_e, indent, child, generics)?;
            let spellcheck_s = emit_expr_at(ctx, spellcheck_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::input::input_multiline_({attrs_s}, {on_change_s}, {text_s}, {placeholder_s}, {label_s}, {spellcheck_s})"
            ))
        }

        NativeUiEmit::InputCheckbox => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputCheckbox",
                    detail: format!("Input.checkbox requires 2 arguments, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputCheckbox",
                    detail: "Input.checkbox cfg must be an inline record literal in Phase 0".into(),
                });
            };
            let on_change_e = lookup_field(
                ctx,
                fields,
                "onChange",
                "ipe_backend_rust::emit_ui_call::InputCheckbox::onChange",
            )?;
            let icon_e = lookup_field(
                ctx,
                fields,
                "icon",
                "ipe_backend_rust::emit_ui_call::InputCheckbox::icon",
            )?;
            let checked_e = lookup_field(
                ctx,
                fields,
                "checked",
                "ipe_backend_rust::emit_ui_call::InputCheckbox::checked",
            )?;
            let label_e = lookup_field(
                ctx,
                fields,
                "label",
                "ipe_backend_rust::emit_ui_call::InputCheckbox::label",
            )?;
            let attrs_s = emit_expr_at(ctx, attrs_e, indent, child, generics)?;
            let on_change_s = emit_arc_callback_field(ctx, on_change_e, indent, child, generics)?;
            let icon_s = emit_arc_callback_field(ctx, icon_e, indent, child, generics)?;
            let checked_s = emit_expr_at(ctx, checked_e, indent, child, generics)?;
            let label_s = emit_expr_at(ctx, label_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::input::input_checkbox_({attrs_s}, {on_change_s}, {icon_s}, {checked_s}, {label_s})"
            ))
        }

        // `Input.slider attrs { onChange, value, min, max, step, label }`
        NativeUiEmit::InputSlider => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputSlider",
                    detail: format!("Input.slider requires 2 arguments, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputSlider",
                    detail: "Input.slider cfg must be an inline record literal in Phase 0".into(),
                });
            };
            let on_change_e = lookup_field(
                ctx,
                fields,
                "onChange",
                "ipe_backend_rust::emit_ui_call::InputSlider::onChange",
            )?;
            let value_e = lookup_field(
                ctx,
                fields,
                "value",
                "ipe_backend_rust::emit_ui_call::InputSlider::value",
            )?;
            let min_e = lookup_field(
                ctx,
                fields,
                "min",
                "ipe_backend_rust::emit_ui_call::InputSlider::min",
            )?;
            let max_e = lookup_field(
                ctx,
                fields,
                "max",
                "ipe_backend_rust::emit_ui_call::InputSlider::max",
            )?;
            let step_e = lookup_field(
                ctx,
                fields,
                "step",
                "ipe_backend_rust::emit_ui_call::InputSlider::step",
            )?;
            let label_e = lookup_field(
                ctx,
                fields,
                "label",
                "ipe_backend_rust::emit_ui_call::InputSlider::label",
            )?;
            let attrs_s = emit_expr_at(ctx, attrs_e, indent, child, generics)?;
            let on_change_s = emit_arc_callback_field(ctx, on_change_e, indent, child, generics)?;
            let value_s = emit_expr_at(ctx, value_e, indent, child, generics)?;
            let min_s = emit_expr_at(ctx, min_e, indent, child, generics)?;
            let max_s = emit_expr_at(ctx, max_e, indent, child, generics)?;
            let step_s = emit_expr_at(ctx, step_e, indent, child, generics)?;
            let label_s = emit_expr_at(ctx, label_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::input::input_slider_({attrs_s}, {on_change_s}, {value_s}, {min_s}, {max_s}, {step_s}, {label_s})"
            ))
        }

        // `Input.radio attrs { onChange, options, selected, label }`
        NativeUiEmit::InputRadio => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputRadio",
                    detail: format!("Input.radio requires 2 arguments, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputRadio",
                    detail: "Input.radio cfg must be an inline record literal in Phase 0".into(),
                });
            };
            let on_change_e = lookup_field(
                ctx,
                fields,
                "onChange",
                "ipe_backend_rust::emit_ui_call::InputRadio::onChange",
            )?;
            let options_e = lookup_field(
                ctx,
                fields,
                "options",
                "ipe_backend_rust::emit_ui_call::InputRadio::options",
            )?;
            let selected_e = lookup_field(
                ctx,
                fields,
                "selected",
                "ipe_backend_rust::emit_ui_call::InputRadio::selected",
            )?;
            let label_e = lookup_field(
                ctx,
                fields,
                "label",
                "ipe_backend_rust::emit_ui_call::InputRadio::label",
            )?;
            let attrs_s = emit_expr_at(ctx, attrs_e, indent, child, generics)?;
            let on_change_s = emit_arc_callback_field(ctx, on_change_e, indent, child, generics)?;
            let options_s = emit_expr_at(ctx, options_e, indent, child, generics)?;
            let selected_s = emit_expr_at(ctx, selected_e, indent, child, generics)?;
            let label_s = emit_expr_at(ctx, label_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::input::input_radio_({attrs_s}, {on_change_s}, {options_s}, {selected_s}, {label_s})"
            ))
        }

        // `Input.radioRow attrs { onChange, options, selected, label }`
        NativeUiEmit::InputRadioRow => {
            let [attrs_e, cfg_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputRadioRow",
                    detail: format!("Input.radioRow requires 2 arguments, got {}", args.len()),
                });
            };
            let Expr::Record { fields, .. } = cfg_e else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::InputRadioRow",
                    detail: "Input.radioRow cfg must be an inline record literal in Phase 0".into(),
                });
            };
            let on_change_e = lookup_field(
                ctx,
                fields,
                "onChange",
                "ipe_backend_rust::emit_ui_call::InputRadioRow::onChange",
            )?;
            let options_e = lookup_field(
                ctx,
                fields,
                "options",
                "ipe_backend_rust::emit_ui_call::InputRadioRow::options",
            )?;
            let selected_e = lookup_field(
                ctx,
                fields,
                "selected",
                "ipe_backend_rust::emit_ui_call::InputRadioRow::selected",
            )?;
            let label_e = lookup_field(
                ctx,
                fields,
                "label",
                "ipe_backend_rust::emit_ui_call::InputRadioRow::label",
            )?;
            let attrs_s = emit_expr_at(ctx, attrs_e, indent, child, generics)?;
            let on_change_s = emit_arc_callback_field(ctx, on_change_e, indent, child, generics)?;
            let options_s = emit_expr_at(ctx, options_e, indent, child, generics)?;
            let selected_s = emit_expr_at(ctx, selected_e, indent, child, generics)?;
            let label_s = emit_expr_at(ctx, label_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::input::input_radio_row_({attrs_s}, {on_change_s}, {options_s}, {selected_s}, {label_s})"
            ))
        }

        // `Html.voidNode : String -> List Attr -> Html msg` — the generic
        // void counterpart of `Html.node`: arbitrary runtime tag, no children
        // arg. Shares the same `html_node_` sink with an emit-baked empty
        // children vec.
        NativeUiEmit::HtmlVoidNode => {
            let [tag_e, attrs_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::HtmlVoidNode",
                    detail: format!("Html.voidNode requires 2 arguments, got {}", args.len()),
                });
            };
            let tag = emit_expr_at(ctx, tag_e, indent, child, generics)?;
            let attrs = emit_expr_at(ctx, attrs_e, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::helpers::html_node_({tag}, {attrs}, ::std::vec::Vec::new())"
            ))
        }

        // `Ui.onInput : (String -> msg) -> Attribute msg`  (Arc-wrap the fn)
        //
        // D5: route through `emit_arc_callback_field` so any lowerer-hoisted
        // capture-clone `let`s (pre-clone `Let { value: CloneVar }` wrapping the
        // Lambda) are peeled OUTSIDE the synthesized `Arc::new(move |_x| …)`.
        // Without this, the outer `move` still move-captures the free outer binding
        // and a sibling use hits E0382 — the same move-capture bug shape the
        // on_change FIELD path guards against, applied to the inline-wrap sites.
        // When there are no leading pure-alias `let`s, `emit_arc_callback_field`
        // produces output byte-identical to a plain `arc_callback_wrap` call.
        NativeUiEmit::OnInput => {
            let [handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiOnInput",
                    detail: format!("Ui.onInput requires 1 argument, got {}", args.len()),
                });
            };
            // Peel any leading capture-clone `let`s outside the Arc closure.
            let peeled = emit_arc_callback_field(ctx, handler_expr, indent, child, generics)?;
            Ok(format!("ipe_runtime::ui::helpers::ui_on_input_({peeled})"))
        }

        // `Ui.onChange : (String -> msg) -> Attribute msg`  (Arc-wrap)
        // D5: same peel-hoist as UiOnInput above.
        NativeUiEmit::OnChange => {
            let [handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiOnChange",
                    detail: format!("Ui.onChange requires 1 argument, got {}", args.len()),
                });
            };
            let peeled = emit_arc_callback_field(ctx, handler_expr, indent, child, generics)?;
            Ok(format!("ipe_runtime::ui::helpers::ui_on_change_({peeled})"))
        }

        // `Ui.onKeyDown : (String -> msg) -> Attribute msg`  (Arc-wrap)
        //
        // D5: route through `emit_arc_callback_field` so any lowerer-hoisted
        // capture-clone `let`s are peeled OUTSIDE the synthesized Arc closure.
        // Without this, a sibling attribute sharing the same capture hits E0382
        // (use after move) — a SEAL break.
        NativeUiEmit::OnKeyDown => {
            let [handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiOnKeyDown",
                    detail: format!("Ui.onKeyDown requires 1 argument, got {}", args.len()),
                });
            };
            let peeled = emit_arc_callback_field(ctx, handler_expr, indent, child, generics)?;
            Ok(format!(
                "ipe_runtime::ui::helpers::ui_on_key_down_({peeled})"
            ))
        }

        // `Ui.onKeyUp : (String -> msg) -> Attribute msg`  (Arc-wrap)
        // D5: same peel-hoist as OnKeyDown above.
        NativeUiEmit::OnKeyUp => {
            let [handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiOnKeyUp",
                    detail: format!("Ui.onKeyUp requires 1 argument, got {}", args.len()),
                });
            };
            let peeled = emit_arc_callback_field(ctx, handler_expr, indent, child, generics)?;
            Ok(format!("ipe_runtime::ui::helpers::ui_on_key_up_({peeled})"))
        }

        // `Ui.onFile : (String -> msg) -> Attribute msg`  (Arc-wrap)
        // D5: same peel-hoist as OnKeyDown above.
        NativeUiEmit::OnFile => {
            let [handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiOnFile",
                    detail: format!("Ui.onFile requires 1 argument, got {}", args.len()),
                });
            };
            let peeled = emit_arc_callback_field(ctx, handler_expr, indent, child, generics)?;
            Ok(format!("ipe_runtime::ui::helpers::ui_on_file_({peeled})"))
        }

        // `Event.onBool : (Bool -> msg) -> Attribute msg`  (Arc-wrap, bool arg)
        // D5: same peel-hoist as OnKeyDown above.
        NativeUiEmit::OnBool => {
            let [handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiOnBool",
                    detail: format!("Event.onBool requires 1 argument, got {}", args.len()),
                });
            };
            let peeled = emit_arc_callback_field(ctx, handler_expr, indent, child, generics)?;
            Ok(format!("ipe_runtime::ui::helpers::ui_on_bool_({peeled})"))
        }

        // `Ui.onSubmit : (a -> msg) -> Attribute msg`
        // `ui_on_submit_` builds `Event::OnForm` with the concrete argument
        // type recovered by Rust generic inference on the emitted handler
        // closure `handler_src` — this emit site is generic over that type, and the
        // runtime function's signature carries it (never `Arc<dyn Any>`).
        //
        // `ui_on_submit_`'s generic bound is `F: Fn(T) -> M + Send +
        // Sync + 'static`, but `handler_src` here is a `Box<dyn Fn(T) -> M + Send +
        // 'static>` trait object (the generic `IrType::Fun` rendering in
        // `emit_types.rs` never claims `+Sync`) — passed straight through as
        // `F`, that box can never satisfy `+ Sync` regardless of what the
        // closure inside captures (a trait object's auto-trait set is
        // exactly its bound list). Wrap in a freshly-declared closure
        // (`move |_x| ({handler_src})(_x)`) the same way the `HtmlEvent` String/Bool
        // arms above do: `handler_src`'s box-construction is re-embedded as SOURCE
        // inside the wrapper's body, so it is built anew on every call
        // rather than captured — the wrapper's own Send+Sync-ness then
        // depends only on the Ipê closure's legitimate `move` captures
        // (Send+'static by construction), not on the erased trait-object
        // type.
        //
        // this re-wrap ONLY helps when `handler_expr` is an INLINE
        // `Lambda`/`FuncValue` here (the box is rebuilt as source inside the
        // wrapper body, never captured). When `handler_expr` is `Expr::Var(sym)`
        // referencing a PREVIOUSLY `let`-bound closure, `handler_src` is the bare
        // identifier, and `move |_x| (handler)(_x)` MOVES the already-built
        // `Box<dyn Fn + Send>` into the wrapper's captures — a non-`Sync`
        // capture makes the wrapper non-`Sync`, so no emit-site fix is
        // possible for that shape (the box already exists by the time this arm
        // runs). The real fix is upstream in `ipe_lower::lower_let_pvar`:
        // `flows_into_sync_kernel_call` promotes the LET-BOUND VALUE itself to
        // `Expr::SharedLambda` (`Arc<dyn Fn + Send + Sync>`), so `handler_src` here is
        // already `Send + Sync` — no change needed in this arm.
        NativeUiEmit::OnSubmit => {
            let [handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiOnSubmit",
                    detail: format!("Ui.onSubmit requires 1 argument, got {}", args.len()),
                });
            };
            // Peel any lowerer-hoisted capture-clone `let`s OUT of the `move`
            // closure so a sibling attribute reading the same captured binding
            // survives (E0382 — accept-then-cargo-fail SEAL break). The FixedValue
            // handler is a bare value, not a `move` closure, so it never needs the
            // hoist; only the Decoder path wraps in `move |_x| …`.
            let (hoisted, peeled_handler) = peel_callback_capture_clones(handler_expr);
            let handler_src = emit_expr_at(ctx, peeled_handler, indent, child, generics)?;
            // Type-directed dispatch. The lowerer classified the handler
            // by its SOLVED type; a non-arrow value routes to the fixed-dispatch
            // runtime helper (no `(m)(_x)` call against a non-callable value —
            // the reported cargo `E0618` after `ipe` exit 0). An arrow handler
            // keeps the decode-and-map path. `NotForm` is unreachable for the
            // onSubmit kernel and fails closed rather than guessing.
            let call = match on_form {
                ipe_ir::OnFormKind::Decoder => {
                    let prefix =
                        render_hoisted_clone_prefix(ctx, &hoisted, indent, child, generics)?;
                    let inner = format!(
                        "ipe_runtime::ui::helpers::ui_on_submit_(move |_x| ({handler_src})(_x))"
                    );
                    if prefix.is_empty() {
                        inner
                    } else {
                        format!("{{ {prefix}{inner} }}")
                    }
                }
                ipe_ir::OnFormKind::FixedValue => {
                    let handler_src = emit_expr_at(ctx, handler_expr, indent, child, generics)?;
                    format!("ipe_runtime::ui::helpers::ui_on_submit_fixed_({handler_src})")
                }
                ipe_ir::OnFormKind::NotForm => {
                    return Err(Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::emit_ui_call::UiOnSubmit",
                        detail: "Ui.onSubmit lowered without a form-handler classification"
                            .to_owned(),
                    });
                }
            };
            Ok(call)
        }

        // `CustomElement.node ce state on_up` — the server-driven custom-element node.
        NativeUiEmit::Widget => {
            let [ce_expr, state_expr, handler_expr] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::UiWidget",
                    detail: format!(
                        "CustomElement.node requires 3 arguments, got {}",
                        args.len()
                    ),
                });
            };
            let ce_src = emit_expr_at(ctx, ce_expr, indent, child, generics)?;
            let state_src = emit_expr_at(ctx, state_expr, indent, child, generics)?;
            // The handler carries `F: Fn(Up) -> M + Send + Sync + 'static`, which
            // the codegen's default `Box<dyn Fn + Send>` fn-value rendering does
            // NOT satisfy (a boxed trait object is `Sync` only if its bound list
            // says so). Re-wrap its SOURCE in a freshly-declared closure at the
            // call site — `move |_x| ({handler})(_x)` — so the box is built anew
            // inside the wrapper's body and never captured, exactly as the
            // `OnSubmit` / `String` / `Bool` event arms do. Peel any
            // lowerer-hoisted capture-clone `let`s OUT of the wrapping `move` so a
            // sibling attribute reading the same captured binding survives (E0382,
            // an accept-then-cargo-fail SEAL break).
            let (hoisted, peeled_handler) = peel_callback_capture_clones(handler_expr);
            let handler_src = emit_expr_at(ctx, peeled_handler, indent, child, generics)?;
            let prefix = render_hoisted_clone_prefix(ctx, &hoisted, indent, child, generics)?;
            let inner = format!(
                "ipe_runtime::ui::widget::ui_widget_({ce_src}, {state_src}, \
                 move |_x| ({handler_src})(_x))"
            );
            let call = if prefix.is_empty() {
                inner
            } else {
                format!("{{ {prefix}{inner} }}")
            };
            Ok(call)
        }

        // ── Ipe.Html.Events builders ────────────────────────────────────
        // Produce a `html::Attribute::EventAttr(Event::On*)` via a dedicated
        // runtime constructor. The fixed wire event name (`"click"`, `"input"`,
        // …) is a compile-time constant from `html_event_wire_name`; the payload
        // shape (Msg / String / Bool / Raw) comes from `html_event_shape`. The
        // `String`/`Bool` forms Arc-wrap the emitted Ipê fn (`f` is a 'static
        // closure); the `Raw` (onSubmit) form (`html_on_raw_`) builds
        // `Event::OnForm` with the concrete payload type recovered by Rust
        // generic inference on the emitted closure — never a type-erased
        // handler.
        NativeUiEmit::HtmlEvent => {
            let (Some(shape), Some(name)) = (k.html_event_shape(), k.html_event_wire_name()) else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::HtmlEvent",
                    detail: format!("{k:?} is not a fully-classified Html event kernel"),
                });
            };
            let [payload_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::HtmlEvent",
                    detail: format!("{k:?} requires exactly 1 argument, got {}", args.len()),
                });
            };
            let payload_s = emit_expr_at(ctx, payload_e, indent, child, generics)?;
            // The `String`/`Bool` (and `Raw` decoder) forms wrap the handler in a
            // `move |_x| …` closure; peel any lowerer-hoisted capture-clone `let`s
            // OUT of that closure so a sibling attribute reading the same captured
            // binding survives (E0382 — accept-then-cargo-fail SEAL break). The
            // `Msg` and `Raw` fixed-value forms pass the payload as a plain value,
            // never a `move` closure, so they need no peel and keep `payload_s`.
            let (payload_hoisted, peeled_payload) = peel_callback_capture_clones(payload_e);
            let peeled_payload_src = emit_expr_at(ctx, peeled_payload, indent, child, generics)?;
            let payload_prefix =
                render_hoisted_clone_prefix(ctx, &payload_hoisted, indent, child, generics)?;
            let wrap_hoisted = |wrapped: String| {
                if payload_prefix.is_empty() {
                    wrapped
                } else {
                    format!("{{ {payload_prefix}{wrapped} }}")
                }
            };
            let call = match shape {
                ipe_ir::HtmlEventShape::Msg => {
                    format!("ipe_runtime::html::html_on_msg_({name:?}.to_owned(), {payload_s})")
                }
                ipe_ir::HtmlEventShape::String => wrap_hoisted(format!(
                    "ipe_runtime::html::html_on_string_({name:?}.to_owned(), \
                     ::std::sync::Arc::new(move |_x| ({peeled_payload_src})(_x)))"
                )),
                ipe_ir::HtmlEventShape::Bool => wrap_hoisted(format!(
                    "ipe_runtime::html::html_on_bool_({name:?}.to_owned(), \
                     ::std::sync::Arc::new(move |_x| ({peeled_payload_src})(_x)))"
                )),
                // `html_on_raw_`'s own signature requires
                // `F: Fn(T) -> M + Send + Sync + 'static` (the runtime's
                // `Event::OnForm` slot is `Arc<dyn Fn(FormData) -> Option<M> +
                // Send + Sync>`, shared across the live session's dispatch
                // table — see `html.rs`'s `Event` doc comment). But
                // `payload_s` here is a `Box<dyn Fn(T) -> M + Send + 'static>`
                // trait object (the generic `IrType::Fun` rendering in
                // `emit_types.rs`, which never claims `+Sync` for a boxed
                // first-class function value) — a trait object's auto-trait
                // set is exactly what its bound lists, so passing that Box
                // value THROUGH unchanged as `F` can never satisfy `+ Sync`
                // regardless of what the closure inside actually captures.
                // The `String`/`Bool` arms above dodge this by re-embedding
                // `payload_s`'s SOURCE inside a freshly-declared wrapping
                // closure (`move |_x| ({payload_s})(_x)`) rather than passing
                // the boxed VALUE itself — the box is constructed anew each
                // call, inside the wrapping closure's body, so it is never
                // part of the wrapping closure's captured environment and
                // the wrapping closure's own Send+Sync-ness depends only on
                // whatever the Ipê closure itself legitimately captures
                // (`move` locals, all Send+'static by construction). Apply
                // the same technique here so `F` is this freshly-Sync outer
                // closure, not the non-Sync boxed trait object.
                //
                // `onSubmit`'s Ipê-level scheme (`constrain.rs`'s
                // `HtmlEventShape::Raw` arm) deliberately leaves the argument
                // type UNCONSTRAINED (decoupled from `msg`) so the typed-
                // record decode idiom above works. That also legitimately
                // types a BARE (non-function) `msg` value — the canonical
                // "form fields already synced into Model via onInput/
                // onChange; submit just triggers a fixed action" idiom
                // (`onSubmit DoSignUp` with `DoSignUp : Msg` carrying no
                // payload — `examples/12-ipevote`'s Auth/Submit/Detail
                // pages). `payload_s` there renders as the bare enum value
                // itself (e.g. `MainMsg::DoSignUp`), which is NOT callable —
                // `(payload_s)(_x)` is E0618 ("expected function, found
                // MainMsg"), a ipe-exit-0-then-cargo-fail SEAL violation.
                // `lower_expr`'s `VarCtor` arm already proves the shape: a
                // NULLARY constructor reference lowers straight to
                // `Expr::Ctor { args: [] }` (a saturated value), while a
                // PAYLOAD constructor reference used as a value is
                // eta-expanded into a genuine `Expr::Lambda` there — so
                // `Expr::Ctor` reaching this position (any arity — `Ctor`
                // is always fully saturated by construction, see its doc)
                // is PROVABLY not a function. Route it (and the other
                // leaf-literal shapes that are equally provably not
                // callable) to `html_on_raw_fixed_`, which dispatches the
                // fixed value directly and never attempts to decode
                // `FormData` into a placeholder type (that would risk a
                // spurious decode failure silently swallowing a real
                // form's submit — see that fn's doc). Every other shape
                // (`Lambda`, `FuncValue`, `Var`, `Apply`, `Call`, …) keeps
                // today's wrap-and-call path unchanged — conservative
                // default, since those CAN legitimately be a function
                // value (a let-bound handler, a named decoder function).
                // `onSubmit` (the only `Raw`-shape kernel). The
                // decode-vs-fixed decision is TYPE-DIRECTED: the lowerer read
                // the handler's SOLVED type and recorded the verdict on the
                // `Call` (`on_form`), so acceptance never depends on the
                // payload's syntactic shape — a `Var` bound to a bare `Msg`
                // and a `Var` bound to a decoder fn read identically
                // here, but the solver told them apart upstream.
                //
                // FixedValue → dispatch the value directly via
                // `html_on_raw_fixed_` (no `(payload_s)(_x)` call against a
                // non-callable value — the reported cargo `E0618` after `ipe`
                // exit 0). Decoder → the wrap-and-call path: `payload_s` (a
                // `Box<dyn Fn(T) -> M + Send + 'static>` trait object) is
                // re-embedded as SOURCE inside a freshly-declared wrapper
                // closure so its box is rebuilt per call rather than captured,
                // laundering the missing `+Sync` the `html_on_raw_` bound
                // (`F: Fn(T) -> M + Send + Sync + 'static`) requires.
                ipe_ir::HtmlEventShape::Raw => match on_form {
                    ipe_ir::OnFormKind::FixedValue => format!(
                        "ipe_runtime::html::html_on_raw_fixed_({name:?}.to_owned(), {payload_s})"
                    ),
                    ipe_ir::OnFormKind::Decoder => wrap_hoisted(format!(
                        "ipe_runtime::html::html_on_raw_({name:?}.to_owned(), move |_x| ({peeled_payload_src})(_x))"
                    )),
                    ipe_ir::OnFormKind::NotForm => {
                        return Err(Diagnostic::CompilerBug {
                            where_: "ipe_backend_rust::emit_ui_call::HtmlOnSubmit",
                            detail: "onSubmit lowered without a form-handler classification"
                                .to_owned(),
                        });
                    }
                },
            };
            Ok(call)
        }

        // ── Ipe.Ui.Lazy — deferred subtree helpers ───────────────────────────
        // Each variant carries (f, a..e) — f is a function-valued Ipê expr;
        // we eta-wrap it so any callable shape (fn item, Box<dyn Fn>, closure)
        // is accepted by the `impl Fn` bound without Arc overhead.
        // Arg order MUST match the runtime signature; a swap is a silent bug.
        //
        // The eta-wrap is a `move |_a…| …` thunk closure; peel any lowerer-hoisted
        // capture-clone `let`s OUT of it ([`peel_callback_capture_clones`]) so a
        // positional key arg (`a..e`) that legitimately `.clone()`s the same
        // captured binding survives (E0382 — accept-then-cargo-fail SEAL break).
        // The key args are emitted from their ORIGINAL exprs, untouched.
        NativeUiEmit::LazyLazy => {
            let [handler_expr, a_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::LazyLazy",
                    detail: format!("Lazy.lazy requires 2 arguments, got {}", args.len()),
                });
            };
            let (hoisted, peeled_handler) = peel_callback_capture_clones(handler_expr);
            let handler_src = emit_expr_at(ctx, peeled_handler, indent, child, generics)?;
            let a_s = emit_expr_at(ctx, a_e, indent, child, generics)?;
            let prefix = render_hoisted_clone_prefix(ctx, &hoisted, indent, child, generics)?;
            let call =
                format!("ipe_runtime::ui::lazy::lazy_lazy_(move |_a| ({handler_src})(_a), {a_s})");
            Ok(if prefix.is_empty() {
                call
            } else {
                format!("{{ {prefix}{call} }}")
            })
        }

        NativeUiEmit::LazyLazy2 => {
            let [handler_expr, a_e, b_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::LazyLazy2",
                    detail: format!("Lazy.lazy2 requires 3 arguments, got {}", args.len()),
                });
            };
            let (hoisted, peeled_handler) = peel_callback_capture_clones(handler_expr);
            let handler_src = emit_expr_at(ctx, peeled_handler, indent, child, generics)?;
            let a_s = emit_expr_at(ctx, a_e, indent, child, generics)?;
            let b_s = emit_expr_at(ctx, b_e, indent, child, generics)?;
            let prefix = render_hoisted_clone_prefix(ctx, &hoisted, indent, child, generics)?;
            let call = format!(
                "ipe_runtime::ui::lazy::lazy_lazy2_(move |_a, _b| ({handler_src})(_a, _b), {a_s}, {b_s})"
            );
            Ok(if prefix.is_empty() {
                call
            } else {
                format!("{{ {prefix}{call} }}")
            })
        }

        NativeUiEmit::LazyLazy3 => {
            let [handler_expr, a_e, b_e, c_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::LazyLazy3",
                    detail: format!("Lazy.lazy3 requires 4 arguments, got {}", args.len()),
                });
            };
            let (hoisted, peeled_handler) = peel_callback_capture_clones(handler_expr);
            let handler_src = emit_expr_at(ctx, peeled_handler, indent, child, generics)?;
            let a_s = emit_expr_at(ctx, a_e, indent, child, generics)?;
            let b_s = emit_expr_at(ctx, b_e, indent, child, generics)?;
            let c_s = emit_expr_at(ctx, c_e, indent, child, generics)?;
            let prefix = render_hoisted_clone_prefix(ctx, &hoisted, indent, child, generics)?;
            let call = format!(
                "ipe_runtime::ui::lazy::lazy_lazy3_(move |_a, _b, _c| ({handler_src})(_a, _b, _c), {a_s}, {b_s}, {c_s})"
            );
            Ok(if prefix.is_empty() {
                call
            } else {
                format!("{{ {prefix}{call} }}")
            })
        }

        NativeUiEmit::LazyLazy4 => {
            let [handler_expr, a_e, b_e, c_e, d_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::LazyLazy4",
                    detail: format!("Lazy.lazy4 requires 5 arguments, got {}", args.len()),
                });
            };
            let (hoisted, peeled_handler) = peel_callback_capture_clones(handler_expr);
            let handler_src = emit_expr_at(ctx, peeled_handler, indent, child, generics)?;
            let a_s = emit_expr_at(ctx, a_e, indent, child, generics)?;
            let b_s = emit_expr_at(ctx, b_e, indent, child, generics)?;
            let c_s = emit_expr_at(ctx, c_e, indent, child, generics)?;
            let d_s = emit_expr_at(ctx, d_e, indent, child, generics)?;
            let prefix = render_hoisted_clone_prefix(ctx, &hoisted, indent, child, generics)?;
            let call = format!(
                "ipe_runtime::ui::lazy::lazy_lazy4_(move |_a, _b, _c, _d| ({handler_src})(_a, _b, _c, _d), {a_s}, {b_s}, {c_s}, {d_s})"
            );
            Ok(if prefix.is_empty() {
                call
            } else {
                format!("{{ {prefix}{call} }}")
            })
        }

        NativeUiEmit::LazyLazy5 => {
            let [handler_expr, a_e, b_e, c_e, d_e, e_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::LazyLazy5",
                    detail: format!("Lazy.lazy5 requires 6 arguments, got {}", args.len()),
                });
            };
            let (hoisted, peeled_handler) = peel_callback_capture_clones(handler_expr);
            let handler_src = emit_expr_at(ctx, peeled_handler, indent, child, generics)?;
            let a_s = emit_expr_at(ctx, a_e, indent, child, generics)?;
            let b_s = emit_expr_at(ctx, b_e, indent, child, generics)?;
            let c_s = emit_expr_at(ctx, c_e, indent, child, generics)?;
            let d_s = emit_expr_at(ctx, d_e, indent, child, generics)?;
            let e_s = emit_expr_at(ctx, e_e, indent, child, generics)?;
            let prefix = render_hoisted_clone_prefix(ctx, &hoisted, indent, child, generics)?;
            let call = format!(
                "ipe_runtime::ui::lazy::lazy_lazy5_(move |_a, _b, _c, _d, _e| ({handler_src})(_a, _b, _c, _d, _e), {a_s}, {b_s}, {c_s}, {d_s}, {e_s})"
            );
            Ok(if prefix.is_empty() {
                call
            } else {
                format!("{{ {prefix}{call} }}")
            })
        }

        // ── Ipe.PubSub.publish / publishNoEcho ────────────────────────────
        // `pubsub_publish<T, E>(topic, payload) -> IpeTask<E, i64>` — T (payload)
        // infers from arg 1; E (error) appears ONLY in the IpeTask<E, i64> result,
        // so anchor it to IpeError with `<_, IpeError>` (T first, E second).
        // Mirror of the CsvParse `::<IpeError>` anchor; two generic slots because T
        // precedes E.  `pubsub_publish` is re-exported at ipe_runtime root via
        // `pub use web::*`, so no full path needed in the emitted crate. These are
        // `class = Web` (Task-shaped), not TEA-loop kernels — the runtime bus lives
        // in the `web` module's `web::pubsub`, hence their home here.
        NativeUiEmit::PubSubPublish => {
            let [topic_e, payload_e] = args else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call::PubSubPublish",
                    detail: format!(
                        "PubSub.publish requires exactly 2 arguments, got {}",
                        args.len()
                    ),
                });
            };
            let topic_s = emit_expr_at(ctx, topic_e, indent, child, generics)?;
            let payload_s = emit_expr_at(ctx, payload_e, indent, child, generics)?;
            let name = kernel_name(k); // "pubsub_publish" / "pubsub_publish_no_echo"
            Ok(format!("{name}::<_, IpeError>({topic_s}, {payload_s})"))
        }

        // ── Web app-entry kernels ─────────────────────────────────────────────
        // Delegate to `emit_web::emit_web_call`; it returns `Some(s)` for the
        // four Web variants and `None` for anything else (the `_ => None` arm).
        // A `None` here is an internal error (the `is_web()` guard above already
        // filtered to Web variants), so promote it to a `CompilerBug`.
        NativeUiEmit::Delegate(UiDelegate::Web) => {
            let s = crate::emit_web::emit_web_call(ctx, callee, args, indent, child, generics)?
                .ok_or_else(|| Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call",
                    detail: format!("emit_web returned None for Web kernel {k:?} — missing arm"),
                })?;
            Ok(s)
        }

        // ── Terminal full-screen app-entry ───────────────────────────────────
        // Delegate to `emit_tui::emit_tui_call`; it returns `Some(s)` for the
        // `Tui.tea` variant and `None` for anything else. A `None` here is an
        // internal error (the `k.is_tui()` guard already filtered), so promote
        // it to a `CompilerBug`.
        NativeUiEmit::Delegate(UiDelegate::Tui) => {
            let s = crate::emit_tui::emit_tui_call(ctx, callee, args, indent, child, generics)?
                .ok_or_else(|| Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call",
                    detail: format!(
                        "emit_tui returned None for Terminal kernel {k:?} — missing arm"
                    ),
                })?;
            Ok(s)
        }

        // ── Terminal line-oriented app-entry ─────────────────────────────────
        // Delegate to `emit_console::emit_console_call`; it returns `Some(s)` for
        // the `Cli.tea` variant and `None` for anything else. A `None` here is
        // an internal error (the `k.is_console()` guard above already filtered),
        // so promote it to a `CompilerBug`.
        NativeUiEmit::Delegate(UiDelegate::Console) => {
            let s =
                crate::emit_console::emit_console_call(ctx, callee, args, indent, child, generics)?
                    .ok_or_else(|| Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::emit_ui_call",
                        detail: format!(
                            "emit_console returned None for Terminal kernel {k:?} — missing arm"
                        ),
                    })?;
            Ok(s)
        }

        // ── View-less worker app-entry ────────────────────────────────────────
        // Delegate to `emit_worker::emit_worker_call`; it returns `Some(s)` for
        // the `Ipe.Tea.Worker.tea` variant and `None` for anything else. A `None`
        // here is an internal error (the `k.is_worker()` guard above already
        // filtered), so promote it to a `CompilerBug`.
        NativeUiEmit::Delegate(UiDelegate::Worker) => {
            let s =
                crate::emit_worker::emit_worker_call(ctx, callee, args, indent, child, generics)?
                    .ok_or_else(|| Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_ui_call",
                    detail: format!(
                        "emit_worker returned None for Worker kernel {k:?} — missing arm"
                    ),
                })?;
            Ok(s)
        }
    }
}

/// Handle JSON / Db decoder kernel calls that require custom argument wrapping.
///
/// Returns `Some(emitted)` for the four special cases:
///
/// * **Arity-0 primitive decoders** (`JsonDecString/Int/Float/Bool`) — these
///   carry a free `E: From<String>` type parameter that Rust cannot infer when
///   passed to another polymorphic function (e.g. `decode_from_json_string`).
///   Emits with an explicit `IpeError` turbofish.
///
/// * **`JsonDecSucceed | DbDecSucceed`** applied to any argument — `decode_succeed`
///   expects a `Box<dyn Fn() -> A + Send>` FACTORY (not a raw value).
///   Three sub-cases:
///   1. Named N-arg function (`FuncValue`) → `decode_succeed(curry{n}(fn_name))`
///   2. Lambda with N params → `decode_succeed(curry{n}(move |p1: T1, …| -> R { body }))`
///   3. Any other value → `decode_succeed({ let __ipe_succeed = <arg>; Box::new(move || __ipe_succeed.clone()) })`
///
///   Cases 1+2 are fail-closed when N > 10 via [`LowerError::DecodeSucceedArityTooHigh`]
///   (no `curry11` exists in the runtime).
///
/// * **`JsonDecList`** — `decode_list` expects `impl Fn() -> Decoder<E, T> + Send`
///   (a factory) rather than the decoder value. Wraps the argument in a
///   `move` closure: `decode_list(move || { inner })`.
///
/// Returns `None` for all other `Expr::Call` shapes, which fall through to the
/// standard emitter.  Factored out of `emit_expr_at` to avoid inflating that
/// function's stack frame (the depth-guard test relies on a bounded frame size).
#[inline(never)]
pub fn emit_json_decoder_call(
    ctx: &EmitCtx,
    callee: &Callee,
    args: &[Expr],
    indent: usize,
    child: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    // ── Arity-0 primitives — turbofish IpeError ──────────────────────────────
    if args.is_empty()
        && matches!(
            callee,
            Callee::Kernel(
                ipe_ir::KernelFn::JsonDecString
                    | ipe_ir::KernelFn::JsonDecInt
                    | ipe_ir::KernelFn::JsonDecFloat
                    | ipe_ir::KernelFn::JsonDecBool
                    // `Json.Decode.value` — the identity decoder carries the
                    // same free `E: From<String>` and needs the turbofish.
                    | ipe_ir::KernelFn::JsonDecValue
                    // `Config.{string,int,float,bool}` share the JSON primitive
                    // decoder fns — same arity-0 turbofish treatment.
                    | ipe_ir::KernelFn::ConfigString
                    | ipe_ir::KernelFn::ConfigInt
                    | ipe_ir::KernelFn::ConfigFloat
                    | ipe_ir::KernelFn::ConfigBool
            )
        )
    {
        let name = callee_name(ctx, callee)?;
        return Ok(Some(format!("{name}::<IpeError>()")));
    }
    // ── succeed(arg) — JsonDecSucceed / DbDecSucceed / ConfigSucceed share
    //    decode_succeed (Config over the same carrier).
    if matches!(
        callee,
        Callee::Kernel(KernelFn::JsonDecSucceed | KernelFn::DbDecSucceed | KernelFn::ConfigSucceed)
    ) && let Some(arg) = args.first()
    {
        match arg {
            // Case 1: named function (FuncValue) — curry{n}(fn_name)
            Expr::FuncValue {
                callee: fn_callee,
                ty: IrType::Fun(params, _),
            } if !params.is_empty() => {
                let n = params.len();
                if n > 10 {
                    return Err(Diagnostic::Lower {
                        span: Span::DUMMY,
                        msg: LowerError::DecodeSucceedArityTooHigh { n },
                    });
                }
                let fn_name = callee_name(ctx, fn_callee)?;
                return Ok(Some(format!("decode_succeed(curry{n}({fn_name}))")));
            }
            // Case 2: lambda — curry{n}(move |params| -> ret { body })
            Expr::Lambda { params, ret, body } if !params.is_empty() => {
                let n = params.len();
                if n > 10 {
                    return Err(Diagnostic::Lower {
                        span: Span::DUMMY,
                        msg: LowerError::DecodeSucceedArityTooHigh { n },
                    });
                }
                let closure = emit_lambda_unboxed(ctx, params, ret, body, indent, child, generics)?;
                return Ok(Some(format!("decode_succeed(curry{n}({closure}))")));
            }
            // Case 2b: an `Arc`-carried function payload (the lowerer eta-expands
            // a non-literal function-value leaf here — a let-bound name, a field
            // read, a call result — into a `SharedLambda` so the boxed `Box<dyn
            // Fn>` leaf is moved into an `Arc` once, never clone-forwarded).
            // `Arc<dyn Fn>` is `Clone` but is not itself `Fn`, so it is wrapped
            // in a fresh `move |p0, …| (arc)(p0, …)` closure — `Fn + Clone +
            // Send`, satisfying `curry{n}`'s bound — before currying.
            //
            // `emit_shared_lambda` pins the `Arc` payload to `+ Send + Sync`, so
            // the wrapper closure that move-captures it is `Send`, and the
            // `Arc::new` construction inside it is valid (a `Send`-only leaf
            // would fail the `Arc: Send` obligation `curry{n}` forwards).
            // Every function leaf renders with `+ Send + Sync` (`emit_types`
            // `IrType::Fun`), so this holds by construction.
            Expr::SharedLambda { params, ret, body } if !params.is_empty() => {
                let n = params.len();
                if n > 10 {
                    return Err(Diagnostic::Lower {
                        span: Span::DUMMY,
                        msg: LowerError::DecodeSucceedArityTooHigh { n },
                    });
                }
                let arc = emit_shared_lambda(ctx, params, ret, body, indent, child, generics)?;
                let mut param_decls = Vec::with_capacity(params.len());
                let mut param_names = Vec::with_capacity(params.len());
                for (idx, (_, ty)) in params.iter().enumerate() {
                    let name = format!("__ipe_succeed_p{idx}");
                    param_decls.push(format!("{name}: {}", render_type(ctx, ty, generics)?));
                    param_names.push(name);
                }
                let ret_s = render_type(ctx, ret, generics)?;
                let wrapper = format!(
                    "{{ let __ipe_succeed = {arc}; move |{}| -> {ret_s} {{ (__ipe_succeed)({}) }} }}",
                    param_decls.join(", "),
                    param_names.join(", ")
                );
                return Ok(Some(format!("decode_succeed(curry{n}({wrapper}))")));
            }
            // Case 3: any other value — factory-wrap so it is called per run.
            // Turbofish `<IpeError, _>` pins the error type when there is no
            // surrounding pipeline to drive inference (E0283 otherwise).
            other => {
                let val = emit_expr_at(ctx, other, indent, child, generics)?;
                return Ok(Some(format!(
                    "decode_succeed::<IpeError, _>({{ let __ipe_succeed = {val}; Box::new(move || __ipe_succeed.clone()) }})"
                )));
            }
        }
    }
    // ── JsonDecList / ConfigList — forward the element decoder by value ───────
    // `decode_list` takes `Decoder<E, T>` by value and borrows it across every
    // element of every document it runs (`Decoder::run` is `Fn`), so a stored
    // bare decoder (`Codec a`'s `dec`) is passed straight through — no reuse
    // factory closure that would have to move a non-`Copy` `Decoder` out of an
    // `Fn` capture. Config shares the runtime fn.
    if matches!(
        callee,
        Callee::Kernel(ipe_ir::KernelFn::JsonDecList | ipe_ir::KernelFn::ConfigList)
    ) && let Some(inner) = args.first()
    {
        let inner_s = emit_expr_at(ctx, inner, indent, child, generics)?;
        return Ok(Some(format!("decode_list({inner_s})")));
    }
    // ── ConfigKeyValuePairs / ConfigDict — same by-value element decoder as
    // `decode_list`; both take `Decoder<E, T>` by value.
    if let Callee::Kernel(
        k @ (ipe_ir::KernelFn::ConfigKeyValuePairs | ipe_ir::KernelFn::ConfigDict),
    ) = callee
        && let Some(inner) = args.first()
    {
        let inner_s = emit_expr_at(ctx, inner, indent, child, generics)?;
        let name = kernel_name(*k); // "decode_key_value_pairs" / "config_dict"
        return Ok(Some(format!("{name}({inner_s})")));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use ipe_ir::{KernelClass, KernelFn};

    /// The kernels `emit_json_decoder_call` special-cases (`decode_succeed`
    /// currying, primitive-decoder turbofish, by-value element forwarding). The
    /// class dispatcher (`emit_expr_at`'s `Expr::Call` arm and its
    /// `call_has_kernel_special_case` mirror) reaches this emitter under the
    /// `Pure` arm and, for the single `Db.Decode.succeed` app-entry, the `Db` arm.
    const JSON_DECODER_DOMAIN: &[KernelFn] = &[
        KernelFn::JsonDecString,
        KernelFn::JsonDecInt,
        KernelFn::JsonDecFloat,
        KernelFn::JsonDecBool,
        KernelFn::JsonDecValue,
        KernelFn::JsonDecList,
        KernelFn::JsonDecSucceed,
        KernelFn::DbDecSucceed,
        KernelFn::ConfigString,
        KernelFn::ConfigInt,
        KernelFn::ConfigFloat,
        KernelFn::ConfigBool,
        KernelFn::ConfigList,
        KernelFn::ConfigSucceed,
        KernelFn::ConfigKeyValuePairs,
        KernelFn::ConfigDict,
    ];

    /// Every kernel `emit_json_decoder_call` special-cases is reached by the
    /// class dispatcher: its class is `Pure`, or it is `DbDecSucceed` (`class =
    /// Db`, probed in the `Db` arm before `emit_db_call`). A future decoder
    /// special case landing in another class would silently miss this emitter and
    /// fall through to the generic tail (a `decode_succeed(curryN(f))` becomes a
    /// boxed `dyn Fn`, an emit divergence); this pins the class/emitter-domain
    /// relation so that drift is a red, not a silent miscompile.
    #[test]
    fn json_decoder_domain_is_reached_by_the_dispatcher() {
        for &k in JSON_DECODER_DOMAIN {
            let class = k.def().class;
            let reachable = class == KernelClass::Pure
                || (class == KernelClass::Db && k == KernelFn::DbDecSucceed);
            assert!(
                reachable,
                "{k:?} is special-cased by emit_json_decoder_call but has class \
                 {class:?} — the dispatcher probes that emitter only under the \
                 Pure arm (+ DbDecSucceed in the Db arm), so this kernel would \
                 miss it and emit through the generic tail. Add its class to the \
                 dispatch arms (expr.rs + kernel_calls.rs) and to this list.",
            );
        }
    }

    /// `Db.defaultMigration` (`DbDefaultMigration`) is the one kernel
    /// `emit_db_call` synthesises a `Migration` record literal for that is NOT
    /// `class = Db`: it is `class = Pure` (a pure record builder that must not
    /// force the `db` runtime feature). The dispatcher therefore probes
    /// `emit_db_call` in BOTH the `Db` arm (for the projection kernels) and the
    /// `Pure` arm (for this builder). If it is ever reclassified to `Db`, the
    /// `Pure`-arm probe becomes dead and this test flags it; if some other Db
    /// emitter kernel becomes `Pure`, the same probe must cover it. Pinning the
    /// class keeps the two-arm routing honest — the alternative is the IPE-I0001
    /// ICE (no synthesised struct) the generic tail produces when this builder
    /// misses its emitter.
    #[test]
    fn db_default_migration_is_pure_and_reached_in_the_pure_arm() {
        assert_eq!(
            KernelFn::DbDefaultMigration.def().class,
            KernelClass::Pure,
            "DbDefaultMigration's class changed; the dispatcher probes emit_db_call \
             in the Pure arm for it — revisit that probe (expr.rs + kernel_calls.rs).",
        );
    }
}
