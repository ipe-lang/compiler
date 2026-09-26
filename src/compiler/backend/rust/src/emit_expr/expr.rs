use super::{
    BinOp, Callee, DResult, Diagnostic, Expr, GenericScope, IrType, KernelClass, KernelFn,
    LowerError, MAX_EMIT_DEPTH, Match, ModPath, Span, Symbol, callee_name, clone_targets_in_expr,
    combine_guards, emit_apply, emit_arm_head, emit_binding_stmts, emit_config_ctor_call,
    emit_css_value_call, emit_db_call, emit_ffi_glued_call, emit_func_value, emit_html_template,
    emit_http_builder_call, emit_http_call, emit_json_decoder_call, emit_lambda,
    emit_lambda_unboxed, emit_match_scrutinee, emit_process_run_in_pty_call,
    emit_process_run_with_call, emit_record, emit_server_call, emit_shared_lambda,
    emit_task_retry_call, emit_tea_call, emit_ui_call, emit_ui_template, emit_update,
    expr_value_is_non_clone, float_literal, free_vars, indent_of, ir_type_is_definitely_copy,
    kernel_swaps_first_two, op_str, render_type, rust_string_literal, scan_free_target,
    substitute_var,
};
use crate::EmitCtx;

/// Depth-tracked recursion behind [`emit_expr`]. `depth` is the IR-nesting level
/// of `expr` (0 at the function body); it gates the bounded-emit guard and is
/// independent of `indent` (the textual indentation of `match` arms).
///
/// `pub(crate)` so that `emit_web` can call it directly (Web kernel bodies
/// emit sub-expressions at the same depth level as their enclosing expression).
#[allow(clippy::too_many_lines)]
pub fn emit_expr_at(
    ctx: &EmitCtx,
    expr: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    if depth > MAX_EMIT_DEPTH {
        return Err(Diagnostic::Lower {
            span: Span::DUMMY,
            msg: LowerError::BackendNestingTooDeep {
                limit: MAX_EMIT_DEPTH,
            },
        });
    }
    let child = depth + 1;
    match expr {
        // Ipe `Int` is Rust `i64`; suffix every integer literal so the type is
        // explicit even when rustc cannot infer it from context alone (e.g. a
        // polymorphic value argument whose type parameter is not constrained by
        // the return type — as in `Cache.put cache key 42` where `T2` is only
        // constrained by the stored value, not the result).
        Expr::Int(n) => Ok(format!("{n}i64")),
        // A float literal renders as an f64-typed Rust literal. A whole-number
        // value keeps its decimal point (`3.0`) so Rust never types it as an
        // integer; see [`float_literal`].
        Expr::Float(f) => Ok(float_literal(*f)),
        // A string literal renders as an owned `String` (Ipê `String` is Rust
        // `String`, never `&str`). The `{:?}` Debug form produces a valid Rust
        // string literal with deterministic escaping.
        Expr::Str(s) => Ok(format!("{s:?}.to_string()")),
        // A compile-time-validated `path "…"` literal. The string was already
        // validated and cleaned by the canonicaliser; emit a direct call to
        // `path_literal` (the compiler-only bypass constructor) so no runtime
        // re-validation is performed — the type is the proof.
        Expr::PathLit(s) => Ok(format!(
            "ipe_runtime::path::path_literal({s:?}.to_string())"
        )),
        // The reserved `CustomElement.fromFile` constructor value: a widget handle built
        // from its generated content-addressed tag. The tag was minted at
        // lowering from the sealed, in-project JS path (never raw user input);
        // `js_path` is retained on the node for the WP5 serving stage but is not
        // part of the handle's runtime representation here.
        Expr::CustomElementRef { tag, js_path: _ } => Ok(format!(
            "ipe_runtime::ui::widget::custom_element_({tag:?}.to_string())"
        )),
        // A character literal renders as a Rust `char`. The carried text is a
        // single character (lexer invariant); `{:?}` escapes it deterministically.
        // A malformed (non-single-char) value fails closed as a `CompilerBug`:
        // a string-literal fallback in `char` position is NOT a safe total
        // fallback — it emits Rust that `cargo` rejects (E0308), the exact
        // exit-0-then-cargo-fail shape THE SEAL forbids.
        Expr::Char(c) => {
            let mut chars = c.chars();
            match (chars.next(), chars.next()) {
                (Some(ch), None) => Ok(format!("{ch:?}")),
                _ => Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_expr_at(Expr::Char)",
                    detail: format!(
                        "Expr::Char carried {} characters ({c:?}), not the single \
                         character the lexer's char-literal invariant guarantees",
                        c.chars().count()
                    ),
                }),
            }
        }
        // A boolean value renders as the Rust keyword constant.
        Expr::Bool(b) => Ok(if *b { "true" } else { "false" }.to_owned()),
        // The unit value renders as the Rust unit expression `()`.
        Expr::Unit => Ok("()".to_owned()),
        Expr::Var(sym) => ctx.emit_ident(*sym),
        Expr::CloneVar(sym) => Ok(format!("{}.clone()", ctx.emit_ident(*sym)?)),
        Expr::Ctor {
            home,
            ty,
            variant,
            args,
        } => emit_ctor(ctx, home, *ty, *variant, args, indent, depth, generics),
        Expr::BinOp { op, lhs, rhs } => {
            let l = emit_expr_at(ctx, lhs, indent, child, generics)?;
            let r = emit_expr_at(ctx, rhs, indent, child, generics)?;
            // Exhaustive match — no wildcard. Adding a new `BinOp` variant
            // without wiring it here is a compile error, not a silent gap.
            match op {
                // `++` (string append) has no Rust infix form for two owned
                // `String`s; `format!` borrows both via `Display` and yields a
                // fresh `String` — no ownership or clone obligation.
                BinOp::Append => Ok(format!("format!(\"{{}}{{}}\", {l}, {r})")),
                // `//` (integer division). Raw Rust `/` on `i64` panics on
                // `b == 0` AND on `i64::MIN / -1`; `//` is itself a Rust line
                // comment, so raw infix emit is doubly unsound. Route through
                // the total helper for integer division semantics:
                // b==0 → panic("attempt to divide by zero") (abort, exit 101);
                // i64::MIN / -1 → i64::MIN (wrapping, no abort).
                BinOp::IntDiv => Ok(format!("ipe_runtime::math::ipe_int_div({l}, {r})")),
                // Integer `+`/`-`/`*` on `i64`: raw Rust infix panics on
                // overflow when `overflow-checks = true`. Route through total
                // wrapping helpers so the two's-complement wrap contract holds
                // regardless of any Cargo profile flag.
                BinOp::IntAdd => Ok(format!("ipe_runtime::math::ipe_int_add({l}, {r})")),
                BinOp::IntSub => Ok(format!("ipe_runtime::math::ipe_int_sub({l}, {r})")),
                BinOp::IntMul => Ok(format!("ipe_runtime::math::ipe_int_mul({l}, {r})")),
                // Float `+`/`-`/`*` on `f64`: IEEE 754, total (overflow → ±∞,
                // never panics). Safe Rust infix.
                BinOp::FloatAdd
                | BinOp::FloatSub
                | BinOp::FloatMul
                // Float `/` on `f64`: total (x/0.0 = ±∞, never panics).
                | BinOp::Div
                // Comparison and boolean operators are total on all types.
                | BinOp::Eq
                | BinOp::Neq
                | BinOp::Lt
                | BinOp::Gt
                | BinOp::Le
                | BinOp::Ge
                | BinOp::And
                | BinOp::Or => Ok(format!("({} {} {})", l, op_str(*op), r)),
                // Generic (polymorphic `Number a`) `+`/`-`/`*`: route through
                // `IpeWrappingAdd/Sub/Mul` method calls. The bound in
                // `render_bounds` is already set to the wrapping trait, so the
                // call type-checks. This prevents a panic under
                // `overflow-checks=on` when the call site monomorphises to i64.
                // Concrete Int routes through `ipe_int_add/sub/mul` (above);
                // Float's `IpeWrappingAdd` impl is the plain IEEE op.
                BinOp::Add => Ok(format!("{l}.ipe_wrapping_add({r})")),
                BinOp::Sub => Ok(format!("{l}.ipe_wrapping_sub({r})")),
                BinOp::Mul => Ok(format!("{l}.ipe_wrapping_mul({r})")),
            }
        }
        Expr::Let { name, value, body } => {
            // A `let` expression renders as a parenthesised Rust block so it
            // composes inline anywhere an expression is expected:
            // `({ let <name> = <value>; <body> })`.
            //
            // `Vec<IpeTask<A>>` (a list of tasks) is non-Clone: using the binding
            // more than once causes E0382 "use of moved value" because the first
            // call moves the Vec.  Ipê has pure/immutable semantics so re-
            // evaluating the value at each use site is always correct — inline it
            // when the value is a task-containing list AND the body uses the name
            // more than once.  Plain Clone/Copy bindings (Int, Bool, records, …)
            // keep the let form so the compiler can share the computation.
            //
            // AUD-04: the multi-use count and the inline substitution both
            // operate on the IR (`scan_free_target` / `substitute_var`), not on
            // rendered Rust text — see those functions' doc comments for why
            // the old text-level passes could corrupt a string literal or a
            // record field name that happened to spell the same identifier.
            let (occurrences, has_clonevar) = scan_free_target(body, *name);
            let needs_inline = occurrences > 1 && expr_value_is_non_clone(value) && !has_clonevar;
            if needs_inline {
                let inlined_body = substitute_var((**body).clone(), *name, value);
                let inlined_s = emit_expr_at(ctx, &inlined_body, indent, child, generics)?;
                Ok(format!("({{ {inlined_s} }})"))
            } else {
                let name_s = ctx.emit_ident(*name)?;
                let value_s = emit_expr_at(ctx, value, indent, child, generics)?;
                let body_s = emit_expr_at(ctx, body, indent, child, generics)?;
                Ok(format!("({{ let {name_s} = {value_s}; {body_s} }})"))
            }
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            // An irrefutable destructuring binding renders as a parenthesised
            // Rust block, exactly like `Let`, but with a pattern binder:
            // `({ <binding stmts> <body> })`. The binder is irrefutable (the
            // lowerer guarantees it — vars / wildcards / tuples / aliases / a
            // top-level record), so the `let`s are exhaustive Rust.
            // `emit_binding_stmts` renders a bare binder as the single flat
            // `let <pat> = <value>;` and an aliased binder as the clone-split
            // sequence that closes the by-value partial-move (E0382) hole.
            let value = emit_expr_at(ctx, value, indent, child, generics)?;
            let stmts = emit_binding_stmts(ctx, binder, &value)?;
            let body = emit_expr_at(ctx, body, indent, child, generics)?;
            Ok(format!("({{ {} {body} }})", stmts.join(" ")))
        }
        Expr::If { cond, then_, else_ } => {
            // Parenthesised so the whole `if`/`else` is a single expression
            // value, independent of surrounding precedence.
            let cond = emit_expr_at(ctx, cond, indent, child, generics)?;
            let then_ = emit_expr_at(ctx, then_, indent, child, generics)?;
            let else_ = emit_expr_at(ctx, else_, indent, child, generics)?;
            Ok(format!("(if {cond} {{ {then_} }} else {{ {else_} }})"))
        }
        Expr::Call {
            callee,
            args,
            pin,
            on_form,
        } => {
            // Structural wrapper hot-swap for `Ipe.Ui`: a `Callee::Func` whose
            // id is a registered structural wrapper (`row` / `column` / …) and
            // whose arguments are all static literals is hoisted here, BEFORE the
            // kernel-only dispatch block below. This runs only when
            // `IPE_WATCH_HOT_APPEARANCE` is armed (checked inside
            // `emit_ui_template`); for non-web or flag-off builds it is a
            // no-op `None` and falls through immediately.
            if let Callee::Func(id) = callee
                && ctx.ui_structural_wrappers.contains_key(id)
                && let Some(result) = emit_ui_template(ctx, expr, indent, child, generics)?
            {
                return Ok(result);
            }
            // Kernel-dispatch special cases apply ONLY to `Callee::Kernel` —
            // every probe below starts with a `let Callee::Kernel(..) = callee
            // else { return Ok(None) }` gate, so a plain user-function call
            // (`Callee::Func`) provably falls straight through all of them.
            // Gating once here skips eight non-inlined probe calls per
            // user-function call node (efficiency-audit §4 medium); kernel
            // calls still traverse the probes in the same order.
            if let Callee::Kernel(k) = callee {
                // Kernel-call emission is dispatched on the kernel's own
                // emit-ownership class (`KernelDef::class`), a wildcard-free
                // `match`: a new `KernelClass` variant with no arm here is a
                // compile error, not a silent fall-through to the generic tail
                // (which would ship an ipe-exit-0-then-cargo-fail SEAL breach or
                // a wrong-emitter miscompile). Each arm calls only the emitters
                // whose bespoke `KernelFn` gate can fire for that class, in the
                // same relative order the former linear probe chain ran them —
                // the probes overlap on `Callee::Kernel`, so their order decides
                // which emitter wins and is load-bearing. Every emitter keeps its
                // own internal `is_db()`/`is_tea()`/`is_server()`/`is_ui()` (or
                // `KernelFn`-variant) gate as defence in depth: a kernel routed to
                // the wrong arm returns `None` and does not miscompile.
                match k.def().class {
                    KernelClass::Db => {
                        // `Db.Decode.succeed` (`DbDecSucceed`) is `class = Db` but
                        // shares the `decode_succeed` special case with its `Json` /
                        // `Config` siblings: `emit_json_decoder_call` curries a
                        // function argument (`decode_succeed(curryN(f))`), which the
                        // generic tail cannot reproduce. `emit_db_call` returns `None`
                        // for it (it is a decoder combinator, not a projection
                        // kernel), so probe the JSON-decoder emitter first, exactly
                        // as the former linear chain did. Every other `Db` kernel is
                        // not a decoder special case, so this probe returns `None`.
                        if let Some(result) =
                            emit_json_decoder_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // Db projection kernels: DbExec / DbQuery / DbQueryDecode /
                        // DbInsertFields / DbUpdateFields / DbUpsertFields / DbInsertFieldsReturning need
                        // `List SqlValue` / `List (String, SqlField)` projected to
                        // `Vec<SqlParam>` / `Vec<(String, Option<SqlParam>)>` at the call
                        // site via the generated `into_sql_param` / `into_field_param` methods.
                        if let Some(result) =
                            emit_db_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                    }
                    KernelClass::Server => {
                        if let Some(result) =
                            emit_server_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                    }
                    KernelClass::Tea => {
                        // `Ipe.Tea.Worker.tea` (`TeaWorker`) is `class = Tea` but
                        // its emit path is the UI delegate chain
                        // (`emit_ui_call` → `Delegate(Worker)` → `emit_worker_call`):
                        // `ui_call_shape` classifies it, and `emit_tea_call` has no
                        // arm for it. Probe `emit_ui_call` first so the worker
                        // app-entry reaches its emitter; every other `Tea` kernel
                        // is not UI-family, so `emit_ui_call` returns `None` and the
                        // standard TEA emit runs.
                        if let Some(result) =
                            emit_ui_call(ctx, callee, args, *on_form, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        if let Some(result) =
                            emit_tea_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                    }
                    // `Ui`/`Web` UI kernels and the `Terminal` app-entries
                    // (`TerminalAppScreen` / `TerminalAppLines`) all emit through
                    // `emit_ui_call`: `ui_call_shape` classifies each, and the
                    // Terminal app-entries route to the Tui/Console delegate
                    // emitters (`Delegate(Tui)` / `Delegate(Console)`) inside it.
                    // The two hot-swap template probes fire only for provably-static
                    // `Ipe.Html` / `Ipe.Ui` subtrees under `hot_appearance`; a
                    // Terminal app-entry kernel never matches them, so they return
                    // `None` and the shared arm stays byte-identical for Terminal.
                    KernelClass::Ui | KernelClass::Web | KernelClass::Terminal => {
                        // Structural hot-swap: under `hot_appearance`, a provably-static
                        // `Ipe.Html` subtree is hoisted whole as ONE serialized template
                        // into the per-view literal table and emitted as a
                        // `materialize_template_str` read, so a structural edit
                        // (add/remove/reorder a static element, static attribute, static
                        // text) becomes a zero-compile data patch. Off (release / `ipe
                        // build`) it never fires — the subtree falls through to the inline
                        // emit below and the output is byte-identical. `None` for any
                        // non-static subtree → keep it compiled.
                        if let Some(result) = emit_html_template(ctx, expr) {
                            return Ok(result);
                        }
                        // Structural hot-swap for `Ipe.Ui`: under `hot_appearance`, a
                        // provably-static `Ipe.Ui` element subtree is hoisted whole as ONE
                        // serialized template and emitted as a `materialize_str`
                        // read (returning an `Element`), so a structural edit becomes a
                        // zero-compile data patch. Off (release / `ipe build`) it never
                        // fires — the subtree falls through to the inline emit below and the
                        // output is byte-identical. `None` for any non-static subtree.
                        if let Some(result) = emit_ui_template(ctx, expr, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // Ipe.Ui / Ipe.Html / Ipe.Web / Ipe.Tui / Ipe.WebView kernels.
                        if let Some(result) =
                            emit_ui_call(ctx, callee, args, *on_form, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                    }
                    // The FFI kernel tier is reserved: no `KernelFn` carries
                    // `class = Ffi`, so this arm is structurally unreachable. It is
                    // present (rather than folded into a wildcard) so the exhaustive
                    // `match` fails the build the moment an FFI kernel is added
                    // without an emit path — fail closed rather than fall through to
                    // the generic tail.
                    KernelClass::Ffi => {
                        return Err(Diagnostic::CompilerBug {
                            where_: "ipe_backend_rust::emit_expr_at",
                            detail: "reached KernelClass::Ffi dispatch arm; no kernel is \
                                 classed Ffi, so this call site should be unreachable — a \
                                 new FFI kernel needs an explicit emit path here"
                                .to_owned(),
                        });
                    }
                    KernelClass::Pure => {
                        // JSON decoder kernel special cases are factored into a separate
                        // `#[inline(never)]` helper to keep the `emit_expr_at` stack frame
                        // small enough for the depth-guard test (IPE-L0200). The helper
                        // returns `None` when no special case applies.
                        if let Some(result) =
                            emit_json_decoder_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // Http network kernel special cases: Http.get / Http.post /
                        // Http.request need a task_map conversion closure (Design B).
                        // Http.parseQuery falls through (standard path is correct).
                        if let Some(result) =
                            emit_http_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // Process.runWith returns `ProcessRunOutput` (runtime struct); a
                        // task_map closure converts it to the synthesised user record struct
                        // for `{ exitCode, stderr, stdout }` — same Design B as Http.get.
                        if let Some(result) =
                            emit_process_run_with_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // Process.runInPty returns `ProcessPtyOutput` (runtime struct); a
                        // task_map closure converts it to the synthesised user record struct
                        // for `{ exitCode, output }` — same Design B as Process.runWith.
                        if let Some(result) = emit_process_run_in_pty_call(
                            ctx, callee, args, indent, child, generics,
                        )? {
                            return Ok(result);
                        }
                        // Http builder kernels: Http.defaultRequest / Http.withMethod /
                        // Http.withTimeout / Http.withBody / Http.withHeader emit inline
                        // struct construction or clone-and-reassign record updates.
                        if let Some(result) =
                            emit_http_builder_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // Task.RetryPolicy builders and Task.retryWith: inline struct
                        // construction / move-update / runtime call.
                        if let Some(result) =
                            emit_task_retry_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // `Db.defaultMigration` (`DbDefaultMigration`) is `class =
                        // Pure` (a pure record builder that must not force the `db`
                        // runtime feature) but `emit_db_call` synthesises its
                        // `Migration` record literal (`{ name, sql }`) — the generic
                        // tail cannot, and would ICE (IPE-I0001, no synthesised
                        // struct for that record shape). Probe `emit_db_call` here,
                        // as the former linear chain did. Every other Pure kernel is
                        // not a Db kernel, so this probe returns `None`.
                        if let Some(result) =
                            emit_db_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // Config-tag ADT constructors: nullary values emitted inline as the
                        // raw `Int` tag the setting builders consume.
                        if let Some(result) = emit_config_ctor_call(callee) {
                            return Ok(result);
                        }
                        // The `Ipe.Color.Ansi` palette constructors (`TermColor*`)
                        // are `class = Pure` but classified by `ui_call_shape`: they
                        // emit through `emit_ui_call` so their appearance literals
                        // (`TermColor.rgb` / `rgba`) hoist into the per-view literal
                        // table under `hot_appearance`, exactly as the former linear
                        // probe chain routed them. The two hot-swap template probes
                        // run first (they only fire under `hot_appearance` and return
                        // `None` for a non-`Ipe.Html`/`Ipe.Ui` subtree — a palette
                        // constructor never matches). Every other `Pure` kernel is not
                        // UI-family, so `emit_ui_call` returns `None`.
                        if let Some(result) = emit_html_template(ctx, expr) {
                            return Ok(result);
                        }
                        if let Some(result) = emit_ui_template(ctx, expr, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        if let Some(result) =
                            emit_ui_call(ctx, callee, args, *on_form, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // Ipe.Css value sanitizer (`CssSafety.safeValue`): hoist a direct
                        // safe literal into the view's appearance literal table for the
                        // dev hot-swap, keeping the runtime `safe_value` wrapper so the
                        // slot is always re-sanitized. `None` for anything else → the
                        // generic tail emits `safe_value(<arg>)` unchanged.
                        if let Some(result) =
                            emit_css_value_call(ctx, callee, args, indent, child, generics)?
                        {
                            return Ok(result);
                        }
                        // `PubSub.topic : String -> Topic a` erases to the identity
                        // function at runtime — `Topic a` lowers to `Str`, so the
                        // call emits as the argument directly (no Rust runtime call needed).
                        if matches!(k, KernelFn::PubSubTopic)
                            && let [name_arg] = args.as_slice()
                        {
                            return emit_expr_at(ctx, name_arg, indent, child, generics);
                        }
                        // Dict.get borrows semantics: the runtime takes the HashMap by
                        // value, but Ipê dicts are persistent — the same dict binding may
                        // be passed to multiple Dict.get calls in one let-chain (e.g.
                        // `let a = Dict.get "a" d; let b = Dict.get "b" d`).  Cloning the
                        // dict arg before each call keeps the original binding alive and
                        // avoids the "use of moved value" Rust compile error.
                        if matches!(k, KernelFn::DictGet)
                            && let [key_arg, dict_arg] = args.as_slice()
                        {
                            let key_s = emit_expr_at(ctx, key_arg, indent, child, generics)?;
                            let dict_s = emit_expr_at(ctx, dict_arg, indent, child, generics)?;
                            return Ok(format!("dict_get({key_s}, {dict_s}.clone())"));
                        }
                    }
                }
            }
            // A transparent-typed FFI call converts at the seam: arguments
            // the wrapper's glue map marks render as foreign struct/enum
            // constructions, and a glued result converts back to the
            // app-side record/union. Wrappers without glue fall through to
            // the generic tail unchanged.
            if let Callee::Ffi { ident, .. } = callee
                && let Some(glue) = ctx.ffi_wrapper_glue(*ident)?
            {
                return emit_ffi_glued_call(ctx, *ident, glue, args, indent, child, generics);
            }
            let name = callee_name(ctx, callee)?;
            // a polymorphic-kernel turbofish the lowerer set because the
            // solver left this call's result type parameter genuinely
            // unconstrained (a discarded / empty / phantom position). Empty for
            // every other call — `CallPin::None::turbofish()` is `""` — so an
            // unpinned call emits no turbofish suffix. The
            // suffix goes between the kernel name and its `(` argument list:
            // `dict_empty::<String, i64>(…)`.
            let pin_turbofish = pin.turbofish();
            // `Ipe.Csv` parse kernels are generic over the error channel
            // (`csv_parse<E: From<String>>(...) -> IpeResult<E, CsvDoc>`); a
            // `Result`-returning call whose `Err` arm is often discarded leaves
            // `E` unconstrained (E0283). Anchor it to `IpeError`, mirroring the
            // network kernels (`http_get::<IpeError>`) and the arity-0 JSON
            // decoders. Only the `E`-free parse entries need it; `encode`
            // returns a bare `String` (no `E`).
            // `Ipe.Db.Dsn.parse` / `.build` are likewise generic over the error
            // channel (`dsn_parse<E: From<String>>(...) -> IpeResult<E, Dsn>`) and
            // are called in a PURE `Result Error Dsn` context whose `Err` arm is
            // often discarded, leaving `E` unconstrained (E0283). Anchor `E` to
            // `IpeError`, exactly like the Csv parse kernels above.
            let turbofish: &str = if pin_turbofish.is_empty()
                && matches!(
                    callee,
                    Callee::Kernel(
                        KernelFn::CsvParse
                            | KernelFn::CsvParseWithDelimiter
                            | KernelFn::DsnParse
                            | KernelFn::DsnBuild
                            | KernelFn::UrlRelativeParse
                    )
                ) {
                "::<IpeError>"
            } else {
                pin_turbofish
            };
            // `Task.andThen cont effect` renders (after the `swaps_first_two`
            // reverse below) as `task_and_then(effect, cont)`. Rust evaluates the
            // args left-to-right, so `effect` runs BEFORE `cont`'s closure is
            // built. A non-Copy handle that `effect` MOVES (e.g. an
            // `IpeCacheHandle` passed by value into `Cache.put cache …`) is gone
            // by the time `cont` tries to capture the same binding — the
            // `let h = h.clone()` the lowerer inserts for `cont`'s capture then
            // borrows a moved value (E0382). Clone every var `cont` captures at
            // its `effect` use site so the original survives into the closure —
            // the same IR-level `clone_targets_in_expr` rewrite the `TaskSeq` arm
            // applies to its auto-forced continuation. `effect` (args[1] in Ipê
            // order) is the only arg rewritten; a no-op when `cont` captures none
            // of `effect`'s vars, so non-reusing chains stay byte-identical.
            let rewritten_effect: Option<Expr> =
                if matches!(callee, Callee::Kernel(KernelFn::TaskAndThen))
                    && let [cont, effect] = args.as_slice()
                {
                    // Only `effect`'s own free vars can be rewritten, and only if
                    // `cont` also captures them. Collect `effect`'s vars first (it
                    // is the small head task); when it has none there is nothing to
                    // clone, so the whole-continuation `free_vars(cont)` walk is
                    // skipped. Otherwise the rewrite targets are exactly the shared
                    // vars — folding over that subset instead of all of `cont`'s
                    // captures is a proven no-op difference (a target absent from
                    // `effect` never matches), so the emitted bytes are identical.
                    let effect_vars = free_vars(effect);
                    let targets: std::collections::BTreeSet<Symbol> = if effect_vars.is_empty() {
                        std::collections::BTreeSet::new()
                    } else {
                        free_vars(cont)
                            .intersection(&effect_vars)
                            .copied()
                            .collect()
                    };
                    if targets.is_empty() {
                        None
                    } else {
                        let row_binders: std::collections::BTreeSet<Symbol> =
                            generics.row_binders().iter().copied().collect();
                        Some(clone_targets_in_expr(
                            effect.clone(),
                            &targets,
                            &row_binders,
                        ))
                    }
                } else {
                    None
                };
            let mut parts = Vec::with_capacity(args.len());
            for (i, arg) in args.iter().enumerate() {
                // For a `Task.andThen`, substitute the clone-rewritten effect (the
                // second Ipê arg) so its shared-handle reads clone rather than move.
                let arg: &Expr = match (&rewritten_effect, i) {
                    (Some(rw), 1) => rw,
                    _ => arg,
                };
                // A `Fun` param this callee monomorphized to an `impl Fn`
                // generic accepts the closure UNBOXED, so a lambda-literal
                // argument skips the `Box::new(..)` wrapper and rustc inlines it
                // (the direct-position perf win). Any NON-lambda argument (a
                // `Var` holding a `Box<dyn Fn>`, a named function value, a
                // partial application) is left as-is: those already produce a
                // value that itself implements `Fn`, so it fills the generic
                // slot with no change and no risk.
                //
                // `Task.andThen cont effect` — the continuation lambda (Ipê arg
                // index 0) must still be boxed because the preamble wrapper takes
                // `Box<dyn FnOnce(A) -> IpeTask<B> + Send + 'static>`. Emitting
                // `Box::new(move |x| -> R { body })` directly (without the
                // `let __ipe_fn: Box<dyn Fn...> = Box::new(...)` type-annotation
                // wrapper that `emit_lambda` produces) is sufficient: rustc infers
                // the trait-object coercion from the parameter position, and the
                // absence of the explicit annotation is what keeps rustc's
                // type-checking linear in the number of chained `Task.andThen`
                // calls (the annotation form causes super-linear work at depth).
                let rendered = if matches!(callee, Callee::Kernel(KernelFn::TaskAndThen))
                    && i == 0
                    && let Expr::Lambda { params, ret, body }
                    | Expr::SharedLambda { params, ret, body } = arg
                {
                    let inner =
                        emit_lambda_unboxed(ctx, params, ret, body, indent, child, generics)?;
                    // Splice the already-built child into a pre-sized buffer rather
                    // than re-copying it through `format!` — same bytes, one alloc.
                    let mut rendered = String::with_capacity(inner.len() + "Box::new()".len());
                    rendered.push_str("Box::new(");
                    rendered.push_str(&inner);
                    rendered.push(')');
                    rendered
                } else {
                    let unboxed = if let Callee::Func(id) = callee
                        && ctx.call_arg_is_impl_fn(*id, i)
                        && let Expr::Lambda { params, ret, body }
                        | Expr::SharedLambda { params, ret, body } = arg
                    {
                        Some(emit_lambda_unboxed(
                            ctx, params, ret, body, indent, child, generics,
                        )?)
                    } else {
                        None
                    };
                    unboxed.map_or_else(|| emit_expr_at(ctx, arg, indent, child, generics), Ok)?
                };
                parts.push(rendered);
            }
            // A handful of Maybe/Result kernels take the container BEFORE the
            // function in the runtime (`ipe_maybe_map(m, f)`) whereas Ipê passes
            // the function first (`Maybe.map f m`). The lowerer keeps the Ipê
            // order; re-point the two arguments here so the runtime call is
            // well-formed.
            if matches!(callee, Callee::Kernel(k) if kernel_swaps_first_two(*k)) {
                parts.reverse();
            }
            Ok(format!("{name}{turbofish}({})", parts.join(", ")))
        }
        Expr::Tuple(elems) => {
            // A tuple constructor renders inline as `(e1, e2, ...)`. The IR
            // invariant guarantees arity ≥ 2, so this is always a genuine Rust
            // tuple; the emission stays total over any vector regardless.
            let mut parts = Vec::with_capacity(elems.len());
            for elem in elems {
                parts.push(emit_expr_at(ctx, elem, indent, child, generics)?);
            }
            Ok(format!("({})", parts.join(", ")))
        }
        Expr::List { elem, items } => emit_list(ctx, elem, items, indent, depth, generics),
        Expr::Cons { head, tail } => {
            // `head :: tail` renders through the runtime's move-only list prepend.
            let h = emit_expr_at(ctx, head, indent, child, generics)?;
            let t = emit_expr_at(ctx, tail, indent, child, generics)?;
            Ok(format!("ipe_runtime::list::ipe_list_cons({h}, {t})"))
        }
        Expr::ListIndexClone { list, index } => {
            // Clone the element at a constant index — the arm guard already
            // proved `list.len() > index`, so the Rust index is in
            // bounds by construction. `.clone()` keeps the list intact for the
            // sibling tail binder.
            let l = emit_expr_at(ctx, list, indent, child, generics)?;
            Ok(format!("({l})[{index}].clone()"))
        }
        Expr::ListLenCheck { list, len, exact } => {
            // Borrowing list-length guard. `.len()` never moves the
            // bound `Vec`, so this is legal in an arm-guard position.
            let l = emit_expr_at(ctx, list, indent, child, generics)?;
            let op = if *exact { "==" } else { ">=" };
            Ok(format!("({l}).len() {op} {len}"))
        }
        // The record arms own several `Vec`/`String` locals; keeping their
        // bodies in dedicated functions (not inlined into this match) holds
        // `emit_expr_at`'s own stack frame small, so the depth guard — not a
        // native overflow — is what bounds a deep `BinOp`/`Call` spine.
        Expr::Record { fields, ty } => {
            emit_record(ctx, fields, ty.as_ref(), indent, depth, generics)
        }
        Expr::Access {
            record,
            field,
            field_ty,
        } => {
            // Field access `<record>.<field>`. The base is parenthesised so a
            // record literal in record position (`{ ... }.field`) is never
            // misparsed; the field ident is keyword-mangled to match the struct.
            //
            // Type-directed Copy elision (AUD-09 — see
            // `docs/adr/0002-codegen-soundness-and-the-seal.md`
            // §3): Ipê is a purely-functional language with value semantics,
            // so every field read is logically a copy.  A field whose solved
            // type is UNCONDITIONALLY `Copy` in the emitted Rust (Int / Float
            // / Bool / Char / Unit / Order / Decimal / ErrorKind / the Copy
            // id-wrapper opaques) is read bare — the read IS the copy.  Every
            // other field (heap-backed String / Vec / synthesized structs /
            // generics) keeps `.clone()`: rustc does NOT elide a `.clone()`
            // call on a heap type, and the clone is what prevents partial-move
            // errors when the same owner or field is accessed more than once
            // (e.g. `view` and `update` both read `model.someField`).  The
            // audit's second half — last-use analysis to elide the clone on a
            // heap field's FINAL read — is explicitly deferred (spec §3.5).
            let base = emit_expr_at(ctx, record, indent, child, generics)?;
            // A field read on a row-generic parameter cannot name a struct field
            // (the concrete struct is unknown at emit time): it routes through the
            // field's witness getter `ipe_<field>()`, which rustc resolves to the
            // monomorphised struct's field. Any other base keeps the ordinary
            // struct-field read.
            if let Expr::Var(sym) = record.as_ref()
                && generics.is_row(*sym)
            {
                let getter = crate::naming::field_witness_getter_name(ctx.resolve_ident(*field)?);
                if ir_type_is_definitely_copy(field_ty) {
                    // The getter borrows; a `Copy` field is copied out by deref.
                    return Ok(format!("*({base}).{getter}()"));
                }
                return Ok(format!("({base}).{getter}().clone()"));
            }
            let field = ctx.emit_ident(*field)?;
            if ir_type_is_definitely_copy(field_ty) {
                Ok(format!("({base}).{field}"))
            } else {
                Ok(format!("({base}).{field}.clone()"))
            }
        }
        Expr::Update { record, fields } => {
            emit_update(ctx, record, fields, indent, depth, generics)
        }
        Expr::Lambda { params, ret, body } => {
            emit_lambda(ctx, params, ret, body, indent, depth, generics)
        }
        Expr::SharedLambda { params, ret, body } => {
            emit_shared_lambda(ctx, params, ret, body, indent, depth, generics)
        }
        Expr::Apply { func, args } => emit_apply(ctx, func, args, indent, depth, generics),
        Expr::FuncValue { callee, ty } => emit_func_value(ctx, callee, ty, generics),
        Expr::Match(m) => emit_match(ctx, m, indent, depth, generics),
        // F1 (auto-force): a discarded Task binding becomes
        //   task_and_then(<effect>, Box::new(move |_| { <rest> }))
        // so the future is properly awaited rather than silently dropped.
        //
        // ARGUMENT ORDER: the runtime `task_and_then(task, f)` takes the effect
        // FIRST and the continuation SECOND. Rust evaluates function arguments
        // left-to-right, so the effect expression is evaluated before the
        // continuation closure is constructed. This matters when the same `Db`
        // pool handle is used in both the effect (e.g. `db_exec_raw(conn, ...)`)
        // and the continuation (`move |_| { ... conn ... }`): placing the effect
        // first lets the continuation capture the pool handle by move without a
        // double-move error, provided that Db kernels emit `conn.clone()` for the
        // pool argument (see `emit_db_call`).
        //
        // The closure parameter type and return type are inferred by Rust from
        // the task_and_then signature — `effect_s: IpeTask<A>` pins A (the
        // discarded type) and `rest_s: IpeTask<B>` pins B (the result type),
        // avoiding the incorrect hardcoded `()` that would fail for any non-unit
        // effect type or non-unit rest type.
        Expr::TaskSeq { effect, rest } => {
            let child = depth + 1;
            // Clone any identifier that `rest` (the move-closure continuation)
            // would capture but `effect` already moves.  Rust evaluates function
            // args left-to-right, so a String/record passed by value into
            // `effect_s` is moved before the closure in the second argument is
            // constructed.
            //
            // AUD-04: this rewrite runs on the IR, BEFORE `effect` is emitted to
            // text — `free_vars`/`clone_targets_in_expr` only ever touch genuine
            // `Var` nodes, so a captured-variable word inside a string literal or
            // a record field name in `effect` can never be corrupted (the prior
            // text-level `clone_captured_vars` pass matched on rendered source
            // and could rewrite either).
            // `effect` is the small head task; collect its free vars first. When it
            // has none, nothing can be cloned, so both the whole-`rest`
            // `free_vars(rest)` walk and the deep `effect` clone are skipped and
            // `effect` is emitted directly. Otherwise the rewrite targets are the
            // vars shared with `rest`'s captures — the same subset the full
            // `clone_targets_in_expr` would have touched, so the emitted text is
            // byte-identical.
            let effect_vars = free_vars(effect);
            let targets: std::collections::BTreeSet<Symbol> = if effect_vars.is_empty() {
                std::collections::BTreeSet::new()
            } else {
                free_vars(rest)
                    .intersection(&effect_vars)
                    .copied()
                    .collect()
            };
            let effect_s = if targets.is_empty() {
                emit_expr_at(ctx, effect, indent, child, generics)?
            } else {
                let row_binders: std::collections::BTreeSet<Symbol> =
                    generics.row_binders().iter().copied().collect();
                let effect_rw = clone_targets_in_expr((**effect).clone(), &targets, &row_binders);
                emit_expr_at(ctx, &effect_rw, indent, child, generics)?
            };
            let rest_s = emit_expr_at(ctx, rest, indent, child, generics)?;
            // Splice the two already-built child strings into one pre-sized buffer
            // in the same token order — byte-identical to the nested `format!`, but
            // it avoids re-copying `effect_s`/`rest_s` through a growing scratch. The
            // fixed wrapper `task_and_then(, Box::new(move |_| {  }))` is 40 bytes.
            let mut out = String::with_capacity(effect_s.len() + rest_s.len() + 40);
            out.push_str("task_and_then(");
            out.push_str(&effect_s);
            out.push_str(", Box::new(move |_| { ");
            out.push_str(&rest_s);
            out.push_str(" }))");
            Ok(out)
        }
        // Sync variant of TaskSeq: blocks on `effect` (discarding the result),
        // then evaluates `rest` in the same sync context. Used when a
        // `let _ = <task>` binding appears inside a non-Task (sync) function,
        // e.g. a helper that returns Vec<Row> or () but still wants to fire a
        // logging side-effect. `task_run` is the blocking scheduler entry point
        // in ipe_runtime (`pub fn task_run<E,A>(task: IpeTask<E,A>) -> IpeResult<E,A>`).
        // TCO nodes are produced by the lowerer's rewrite and consumed by
        // `emit_func` / `emit_expr_tail`; reaching one on the ordinary value-emit
        // path means the rewrite left a jump/loop outside a tail context — a
        // compiler bug, surfaced fail-closed (never a panic, never a wildcard).
        Expr::TailLoop { .. } | Expr::TailRecur { .. } => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_expr_at",
            detail: "TailLoop/TailRecur reached the non-tail emit path".to_string(),
        }),
    }
}

/// Emit a list literal. A non-empty list renders as `vec![e0, e1, …]`; the empty
/// list as a typed `Vec::<T>::new()` so its element type is never ambiguous (a
/// bare `vec![]` could fail to infer in a polymorphic position). Kept out of the
/// `emit_expr_at` match (`#[inline(never)]`) so its locals don't inflate the
/// recursive frame.
#[inline(never)]
pub fn emit_list(
    ctx: &EmitCtx,
    elem: &IrType,
    items: &[Expr],
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    let child = depth + 1;
    if items.is_empty() {
        // For `IrType::Json` (unresolved / wildcard `Value = any`) the type
        // annotation `Vec::<JsonVal>::new()` CONFLICTS with callers that expect
        // `Vec<Attribute<M>>` / `Vec<Element<M>>` etc. — Rust's type checker
        // rejects the explicit annotation even though it would accept an
        // unannotated `Vec::new()` via inference.  Emit the bare form and let
        // Rust infer the element type from the surrounding call's expected type.
        // All other element types are precise enough that an explicit annotation
        // resolves ambiguity without breaking callers.
        if matches!(elem, IrType::Json) {
            return Ok("Vec::new()".to_owned());
        }
        let ty = render_type(ctx, elem, generics)?;
        return Ok(format!("Vec::<{ty}>::new()"));
    }
    let mut parts = Vec::with_capacity(items.len());
    for item in items {
        parts.push(emit_expr_at(ctx, item, indent, child, generics)?);
    }
    // Non-empty lists whose element type is a parametric Ui type (`Attribute<M>`
    // / `Element<M>` / `Html<M>` / …) need an explicit type annotation on the
    // emitted Rust `Vec` so that the `M` type parameter can be inferred by the
    // Rust compiler.  Without this, callers like `Ui.layoutWith` whose attrs
    // lists are always non-empty (no empty-list turbofish to anchor M) produce
    // E0283 because every helper (`ui_padding_`, `ui_spacing_`, …) is itself
    // generic in M and no concrete M appears elsewhere in the expression.
    //
    // The annotation wraps the vec in a typed `let` block:
    //   `{ let __ipe_m: Vec<Attribute<()>> = vec![ui_padding_(12)]; __ipe_m }`
    // The variable name `__ipe_m` is scoped to the anonymous block and cannot
    // shadow user-visible bindings.  The block is a Rust expression, valid in
    // every argument position.
    //
    // This path is skipped for `IrType::Json` (the elem type is unresolved)
    // because annotating with `Vec<JsonVal>` would CONFLICT with callers that
    // expect `Vec<Attribute<M>>` — the same reason empty Json lists emit bare
    // `Vec::new()` rather than a typed form.
    if matches!(elem, IrType::Ui { .. }) {
        let ty = render_type(ctx, elem, generics)?;
        return Ok(format!(
            "{{ let __ipe_m: Vec<{ty}> = vec![{}]; __ipe_m }}",
            parts.join(", ")
        ));
    }
    Ok(format!("vec![{}]", parts.join(", ")))
}

/// Emit a constructor application. A nullary constructor renders as the bare
/// path `EnumName::Variant`; a payload constructor renders
/// `EnumName::Variant(arg0, arg1, …)`. A payload position on a type-size cycle
/// back to its own enum is wrapped in `Box::new(…)` to balance the boxed enum
/// field (see [`crate::EmitCtx::is_cyclic_self_field`]). Kept out of the
/// `emit_expr_at` match (`#[inline(never)]`) so its locals don't inflate the
/// recursive frame.
#[inline(never)]
// The extra `home` param is the type's nominal-identity half `(home, ty)`;
// splitting the ctor emitter would obscure the boxing/runtime-enum flow.
#[allow(clippy::too_many_arguments)]
pub fn emit_ctor(
    ctx: &EmitCtx,
    home: &ModPath,
    ty: Symbol,
    variant: Symbol,
    args: &[Expr],
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    let child = depth + 1;
    // A built-in `Maybe` / `Result` constructor routes to the runtime enum
    // (`IpeMaybe::Just(..)`, `IpeResult::Err(..)`); its payload is never a
    // self-recursive user field, so no field-boxing lookup applies.
    if let Some(runtime) = ctx.builtin_runtime_enum(home, ty) {
        let path = format!("{runtime}::{}", ctx.emit_ident(variant)?);
        if args.is_empty() {
            return Ok(path);
        }
        let mut parts = Vec::with_capacity(args.len());
        for arg in args {
            parts.push(emit_expr_at(ctx, arg, indent, child, generics)?);
        }
        return Ok(format!("{path}({})", parts.join(", ")));
    }
    let path = format!("{}::{}", ctx.enum_name(home, ty)?, ctx.emit_ident(variant)?);
    if args.is_empty() {
        return Ok(path);
    }
    let fields = ctx.variant_fields(home, ty, variant)?;
    if fields.len() != args.len() {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_ctor",
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
    let mut parts = Vec::with_capacity(args.len());
    for (arg, field_ty) in args.iter().zip(fields.iter()) {
        let rendered = emit_expr_at(ctx, arg, indent, child, generics)?;
        // A cyclic self-edge field is boxed in the enum, so its construction
        // argument is boxed too.
        if ctx.is_cyclic_self_field(field_ty, home, ty) {
            parts.push(format!("Box::new({rendered})"));
        } else {
            parts.push(rendered);
        }
    }
    Ok(format!("{path}({})", parts.join(", ")))
}

/// Emit a `match`. An arm head is a constructor pattern (exhaustive
/// over the enum's variants) or — for a flat refutable match — a literal
/// (`0` / `'a'` / `"hi"` / `true` / `false`), a wildcard / variable binder, or
/// an alias. A cyclic self-edge constructor payload field is boxed in the enum,
/// so a variable bound to such a field is unboxed (`let x = *x;`) at the top of
/// the arm body, giving the binder the enum's own (owned) type rather than
/// `Box<…>`.
///
/// `String` scrutinees match against `scrut.as_str()` because Rust string
/// literal patterns are `&str`; any top-level binder in such an arm is rebound
/// to an owned `String` (`let name = name.to_string();`) so the arm body sees
/// the Ipê `String` type, keeping the lowering sound. Kept out of the
/// `emit_expr_at` match (`#[inline(never)]`) for the same frame-size reason as
/// the neighbouring helpers.
#[inline(never)]
pub fn emit_match(
    ctx: &EmitCtx,
    m: &Match,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    let child = depth + 1;
    let (scrut, mode) = emit_match_scrutinee(ctx, m, indent, depth, generics)?;
    let arm_indent = indent_of(indent + 1);
    let close_indent = indent_of(indent);
    let mut arms = Vec::with_capacity(m.arms().len());
    for arm in m.arms() {
        let (pat, prelude, synth_guard) = emit_arm_head(ctx, &arm.pat, &mode)?;
        // Transition hot-swap (dev-gated) — the string-path mirror of the
        // production reduction in [`crate::emit_doc::build_match`]. A TEA `update`
        // arm whose whole effect is one data-describable field change with
        // `Cmd.none` reduces to a call into the transition table read by the ONE
        // compiled `apply_transition_hot` over the baked datum. Both paths call
        // the same [`emit_transition_arm`], so their token sequences agree and the
        // SEAL stays exact. `None` (flag off, not an update body, or a
        // non-describable arm) falls through to the ordinary arm-body emit below,
        // byte-identical.
        //
        // A second dev-gated hot rewrite of a TEA `update` arm shares the same
        // produced-string mirror with the Doc path: the Cmd-wiring rewrite (a single
        // literal `Cmd.perform` arm's Cmd position → `fire_cmd_wiring` over the arm's
        // compiled effect table). At most one of the two fires (a `Cmd.none` arm is
        // never a `Cmd.perform` arm); `None` from both falls through to the ordinary
        // arm-body emit, byte-identical to the flag-off form.
        let body = match emit_transition_arm(ctx, &arm.body)? {
            Some(hot) => hot,
            None => match emit_cmd_wiring_arm(ctx, &arm.body, indent, depth, generics)? {
                Some(wired) => wired,
                None => emit_expr_at(ctx, &arm.body, indent + 1, child, generics)?,
            },
        };
        let arm_body = if prelude.is_empty() {
            body
        } else {
            format!("{{ {prelude}{body} }}")
        };
        // A guard (a list-length arm guard and/or the synthesized `as_str()`
        // string-column guard) renders as a native Rust `if <guard>` on the arm —
        // `false` falls through to the next arm, matching the `case`'s refutable
        // semantics. When both are present they are ANDed. A guardless arm keeps
        // the plain `{pat} => …` shape.
        let ir_guard = match &arm.guard {
            Some(g) => Some(emit_expr_at(ctx, g, indent + 1, child, generics)?),
            None => None,
        };
        match combine_guards(synth_guard, ir_guard) {
            Some(guard) => arms.push(format!("{arm_indent}{pat} if {guard} => {arm_body},")),
            None => arms.push(format!("{arm_indent}{pat} => {arm_body},")),
        }
    }
    Ok(format!(
        "match {scrut} {{\n{}\n{close_indent}}}",
        arms.join("\n")
    ))
}

/// Reduce a TEA `update` arm body to an `apply_transition_hot` call when the
/// transition rewrite is armed (a TEA `update` body under `hot_appearance`) AND
/// the body is a data-describable single-field change with `Cmd.none`. `None`
/// otherwise — the caller emits the arm body normally, byte-identically.
///
/// The emitted body is `(ipe_runtime::web::apply_transition_hot("<baked datum
/// JSON>", <model>), cmd_none())`: the compiled reader decodes and applies the
/// baked datum (dev == prod), or a live replacement when the dev overlay holds.
/// The baked JSON is [`crate::transition_classify::CompileTransition::to_json`],
/// byte-identical to the runtime `Transition`'s serde form (pinned by the
/// classifier's conformance test), so the reader round-trips it exactly.
///
/// The classifier is conservative: only the four faithful shapes classify; every
/// other arm returns `None` and stays compiled. Fail-closed by construction — a
/// false `None` is merely a recompile, never a wrong result.
///
/// Shared with [`crate::emit_doc::build_match`], the production function-body
/// match emitter: the same reduction fires whether a body is rendered through the
/// Doc path (production) or the string path (the SEAL / byte-golden oracle), so
/// both carry the identical token sequence and the SEAL stays exact.
pub fn emit_transition_arm(ctx: &EmitCtx, body: &Expr) -> DResult<Option<String>> {
    let Some(model_param) = ctx.transition_model_param() else {
        return Ok(None);
    };
    // Resolve a field symbol to its serde key — the emitted Rust field ident,
    // which (no serde rename) is exactly the key the runtime Model JSON object is
    // keyed by. `None` for an unresolved symbol refuses (never a guessed key).
    let resolve = |sym: Symbol| ctx.emit_ident(sym).ok();
    let Some(ct) = crate::transition_classify::transition_of_arm(body, model_param, &resolve)
    else {
        return Ok(None);
    };
    // The model parameter's emitted ident, consumed by value by the arm (only one
    // match branch runs, so the move is sound).
    let model_ident = ctx.emit_ident(model_param)?;
    // The baked datum, as a Rust string literal. `to_json` emits only the JSON
    // grammar's own escapes; wrap it as a Rust string with the escapes a Rust
    // string literal needs (`"` and `\`), which the JSON writer already produced,
    // so the literal is the exact JSON bytes the runtime decodes.
    let json = ct.to_json();
    let json_lit = rust_string_literal(&json);
    Ok(Some(format!(
        "(ipe_runtime::web::apply_transition_hot({json_lit}, {model_ident}), cmd_none())"
    )))
}

/// Reduce a TEA `subscriptions` entry to a `sub_every_hot` call when the
/// sub-description rewrite is armed (a TEA `subscriptions` body under
/// `hot_appearance`) AND the entry is a data-describable tick source
/// (`Time.every <lit> <msg>` / `Sub.every <lit> <msg>`). `None` otherwise — the
/// caller emits the entry normally, byte-identically.
///
/// The emitted expression is `ipe_runtime::web::sub_every_hot::<Msg>("<baked datum
/// JSON>")`: the compiled reader decodes and builds the baked datum (dev == prod),
/// or a live replacement when the dev overlay holds. The baked JSON is
/// [`crate::sub_classify::CompileSubDescription::to_json`], byte-identical to the
/// runtime `SubDescription`'s serde form (pinned by the classifier's conformance
/// test), so the reader round-trips it exactly. `Msg` is left to Rust inference
/// (the `subscriptions` function's `Sub Msg` return type fixes it), so no type
/// annotation is emitted.
///
/// The classifier is conservative: only a literal tick source with a
/// serde-encodable literal message classifies; every other entry returns `None`
/// and stays compiled. Fail-closed by construction — a false `None` is merely a
/// recompile, never a wrong result.
pub fn emit_sub_arm(ctx: &EmitCtx, kernel: KernelFn, args: &[Expr]) -> Option<String> {
    if !ctx.subs_hot_active() {
        return None;
    }
    // Resolve a variant symbol to its serde tag — the emitted Rust variant ident,
    // which (no serde rename) is exactly the tag serde uses for the enum's
    // externally-tagged form. `None` for an unresolved symbol refuses (never a
    // guessed tag).
    let resolve_variant = |sym: Symbol| ctx.emit_ident(sym).ok();
    let cs = crate::sub_classify::sub_of_call(kernel, args, &resolve_variant)?;
    // The baked datum, as a Rust string literal. `to_json` emits only the JSON
    // grammar's own escapes; wrap it as a Rust string with the escapes a Rust
    // string literal needs (`"` and `\`), so the literal is the exact JSON bytes
    // the runtime decodes.
    let json = cs.to_json();
    let json_lit = rust_string_literal(&json);
    Some(format!("ipe_runtime::web::sub_every_hot({json_lit})"))
}

/// Reduce a TEA `init` body to an `apply_init_hot` call when the init rewrite is
/// armed (a `hot_appearance` build) AND the body is a data-describable record
/// literal with `Cmd.none`. `None` otherwise — the caller emits the body
/// normally, byte-identically.
///
/// The emitted body is
/// `(ipe_runtime::web::apply_init_hot("<baked datum JSON>", <compiled record>),
/// cmd_none())`: at session creation the compiled reader decodes the baked datum
/// (dev == prod), or a live replacement when the dev overlay holds. The
/// `<compiled record>` is the SAME record the direct compiled `init` produces —
/// the fail-closed fallback the reader returns if a datum ever fails to decode,
/// so the emitted body is behaviour-identical to the direct compiled `init` even
/// on a corrupt datum.
///
/// The baked JSON is
/// [`crate::transition_classify::CompileInitDatum::to_json`], byte-identical to
/// the runtime `InitDatum`'s serde form (pinned by the classifier's conformance
/// test), so the reader round-trips it exactly.
///
/// The classifier is conservative: only a record literal of closed leaf values
/// with `Cmd.none` classifies; every other `init` (and every `update` body, which
/// is a `msg` match, never a bare record tuple) returns `None` and stays
/// compiled. Fail-closed by construction — a false `None` is merely a recompile,
/// never a wrong result.
///
/// `indent`/`depth`/`generics` thread the record sub-expression's emission
/// context so the compiled record renders exactly as the direct body would.
pub fn emit_init_datum(
    ctx: &EmitCtx,
    body: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    let resolve = |sym: Symbol| ctx.emit_ident(sym).ok();
    let Some(cd) = crate::transition_classify::init_datum_of_body(body, &resolve) else {
        return Ok(None);
    };
    // The classifier proved the body is `(Record { .. }, Cmd.none)`; re-extract
    // the record sub-expression to emit as the compiled fallback. A shape that
    // does not match here would mean the classifier and this extraction drifted;
    // it fails closed (`None` → ordinary emit), never a wrong rewrite.
    let Expr::Tuple(elems) = body else {
        return Ok(None);
    };
    let [record_expr, _cmd] = elems.as_slice() else {
        return Ok(None);
    };
    let compiled_record = emit_expr_at(ctx, record_expr, indent, depth, generics)?;
    let json = cd.to_json();
    let json_lit = rust_string_literal(&json);
    Ok(Some(format!(
        "(ipe_runtime::web::apply_init_hot({json_lit}, {compiled_record}), cmd_none())"
    )))
}

/// Compose a TEA `update` arm's Cmd WIRING at the arm's Cmd position: reduce a
/// data-describable arm whose Cmd fires a single literal `Cmd.perform` effect to a
/// `fire_cmd_wiring` dispatch over the arm's OWN compiled effect table, or `None`
/// when the arm's Cmd is not an enumerable wiring (the arm stays compiled).
///
/// Emits the whole arm body as
/// `(<compiled model>, ipe_runtime::web::fire_cmd_wiring("<baked wiring JSON>",
/// vec![Box::new(move || <compiled effect 0>), ...]))`: the model half is the arm's
/// OWN compiled model (unchanged), and the Cmd half is the wiring dispatch. Each
/// effect thunk builds ONE of the arm's compiled effects; the runtime selector
/// picks WHICH id fires (dev overlay under the dev gate, the baked id otherwise —
/// dev == prod) and runs only that thunk. The effect BODIES are compiled exactly as
/// written — only the WIRING (which id fires) is data.
///
/// The baked JSON is
/// [`crate::transition_classify::CompileCmdWiring::to_json`], byte-identical to the
/// runtime `CmdWiring`'s serde form (pinned by the classifier's conformance test),
/// so the selector round-trips it exactly. The effect count passed to the runtime
/// is the compiled table length, so `select_effect`'s `id < effect_count` bound and
/// `fire_cmd_wiring`'s `nth(id)` bound both agree with the table — an id past it
/// fires no effect (fail-closed), never an out-of-range access.
///
/// Only fires under an armed `update` body (`transition_model_param` set, i.e.
/// `hot_appearance` on): with the flag off this returns `None` and the arm is
/// emitted normally, byte-identical. Conservative: only the closed wiring
/// vocabulary (`Cmd.none`, a single literal `Cmd.perform`) classifies; the
/// `Cmd.none` no-effect case is left to the transition path (which fires no effect
/// already), so only the genuinely-new `Cmd.perform` wiring composes here. A
/// non-enumerable Cmd returns `None` and keeps the arm compiled.
///
/// Shared with [`crate::emit_doc::build_match`] via the same produced string, so the
/// Doc (production) and string (SEAL / byte-golden) paths carry identical tokens and
/// the SEAL stays exact.
pub fn emit_cmd_wiring_arm(
    ctx: &EmitCtx,
    body: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<Option<String>> {
    // Only compose under an armed `update` body — the same gate the transition
    // rewrite uses. With `hot_appearance` off this is `None` and the arm emits
    // normally (byte-identical).
    if ctx.transition_model_param().is_none() {
        return Ok(None);
    }
    let Some(arm) = crate::transition_classify::arm_wiring_of_arm(body) else {
        return Ok(None);
    };
    // The `Cmd.none` no-effect wiring is already handled by the transition path
    // (which emits `cmd_none()` at the Cmd position, fail-closed to no effect);
    // wiring it here would only churn its emit for zero behaviour gain. Compose only
    // when the arm names at least one compiled effect (a real `Cmd.perform`).
    if arm.effects.is_empty() {
        return Ok(None);
    }
    // The arm body is `(Model, Cmd)`; re-extract the model sub-expression to emit as
    // the arm's own compiled model. A shape that does not match here would mean the
    // classifier and this extraction drifted; it fails closed (`None` → ordinary
    // emit), never a wrong rewrite.
    let Expr::Tuple(elems) = body else {
        return Ok(None);
    };
    let [model_expr, _cmd] = elems.as_slice() else {
        return Ok(None);
    };
    let child = depth + 1;
    let model_s = emit_expr_at(ctx, model_expr, indent + 1, child, generics)?;
    // The ordered compiled-effect table: each effect wrapped in a `move` thunk so
    // only the wiring-selected one is built and fired (the rest drop unrun). A
    // `move` closure lets the effect capture the arm's bindings by value, sound
    // because only one match arm runs.
    let mut thunks = Vec::with_capacity(arm.effects.len());
    for effect in &arm.effects {
        let effect_s = emit_expr_at(ctx, effect, indent + 1, child, generics)?;
        thunks.push(format!("Box::new(move || {effect_s})"));
    }
    let table = thunks.join(", ");
    let json = arm.wiring.to_json();
    let json_lit = rust_string_literal(&json);
    Ok(Some(format!(
        "({model_s}, ipe_runtime::web::fire_cmd_wiring({json_lit}, vec![{table}]))"
    )))
}
