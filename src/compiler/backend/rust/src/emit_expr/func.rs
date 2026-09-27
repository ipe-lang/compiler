use super::{
    BoundSet, Callee, DResult, Diagnostic, Doc, Expr, Func, GenericScope, IrType, KernelFn,
    RenderConfig, Symbol, callee_name, combine_guards, emit_arm_head, emit_binding_stmts,
    emit_expr_at, emit_init_datum, emit_match_scrutinee, impl_fn_param_indices, indent_of,
    render_seeded, render_type, tail_arm_prelude_lines,
};
use crate::EmitCtx;
use core::fmt::Write as _;

/// Emit an `Expr` in TAIL/STATEMENT context — the interior of a `TailLoop`'s
/// `loop { … }`. Every path ends in either a `return <expr>;` (a leaf
/// tail position) or a `continue;` (a `TailRecur` jump), so the `loop` types as
/// `!` and unifies with any `-> R` return type (no `break value`). The tail
/// propagators (`If` / `Match` / `Let` / `Destructure`) recurse in-tail; every
/// other node is a leaf whose VALUE is `return`ed. `loop_params` gives each
/// `TailRecur.args[i]` its destination parameter name.
///
/// The `other => return` arm is the intended value/statement split (the
/// reference's `walk True` leaf case), NOT a wildcard over `Expr` variants for
/// exhaustiveness purposes — `emit_expr_at` inside it is the exhaustive,
/// fail-closed walker: a stray `TailLoop`/`TailRecur` reaching it routes to the
/// `CompilerBug` arm (never a panic, never a silent swallow).
#[inline(never)]
pub fn emit_expr_tail(
    ctx: &EmitCtx,
    expr: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
    loop_params: &[(Symbol, IrType)],
) -> DResult<String> {
    let pad = indent_of(indent);
    let child = depth + 1;
    match expr {
        Expr::If { cond, then_, else_ } => {
            let c = emit_expr_at(ctx, cond, indent, child, generics)?;
            let t = emit_expr_tail(ctx, then_, indent + 1, child, generics, loop_params)?;
            let e = emit_expr_tail(ctx, else_, indent + 1, child, generics, loop_params)?;
            Ok(format!(
                "{pad}if {c} {{\n{t}\n{pad}}} else {{\n{e}\n{pad}}}"
            ))
        }
        Expr::Match(m) => {
            let (scrut, mode) = emit_match_scrutinee(ctx, m, indent, depth, generics)?;
            let arm_indent = indent_of(indent + 1);
            let close_indent = indent_of(indent);
            let mut arms = Vec::with_capacity(m.arms().len());
            for arm in m.arms() {
                let (patstr, prelude, synth_guard) = emit_arm_head(ctx, &arm.pat, &mode)?;
                // The arm body is a STATEMENT sequence ending in return/continue;
                // any binder-rebind prelude precedes it inside the arm's block.
                let body =
                    emit_expr_tail(ctx, &arm.body, indent + 2, child, generics, loop_params)?;
                let inner = if prelude.is_empty() {
                    body
                } else {
                    format!("{}{body}", tail_arm_prelude_lines(&prelude, indent + 2)?)
                };
                // Same `if <guard>` fall-through as the value-context emitter: the
                // list-length arm guard and the synthesized `as_str()` string-
                // column guard are ANDed; `None` leaves the arm guardless.
                let ir_guard = match &arm.guard {
                    Some(g) => Some(emit_expr_at(ctx, g, indent + 1, child, generics)?),
                    None => None,
                };
                let guard_clause = combine_guards(synth_guard, ir_guard)
                    .map_or_else(String::new, |guard| format!(" if {guard}"));
                arms.push(format!(
                    "{arm_indent}{patstr}{guard_clause} => {{\n{inner}\n{arm_indent}}}"
                ));
            }
            Ok(format!(
                "{pad}match {scrut} {{\n{}\n{close_indent}}}",
                arms.join("\n")
            ))
        }
        Expr::Let { name, value, body } => {
            let n = ctx.emit_ident(*name)?;
            let v = emit_expr_at(ctx, value, indent, child, generics)?;
            let b = emit_expr_tail(ctx, body, indent, child, generics, loop_params)?;
            Ok(format!("{pad}let {n} = {v};\n{b}"))
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            let v = emit_expr_at(ctx, value, indent, child, generics)?;
            let stmts = emit_binding_stmts(ctx, binder, &v)?;
            let b = emit_expr_tail(ctx, body, indent, child, generics, loop_params)?;
            let joined = stmts
                .iter()
                .map(|s| format!("{pad}{s}"))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(format!("{joined}\n{b}"))
        }
        // The jump: temporaries-first reassignment + `continue`. Reading EVERY
        // next-iteration argument into a fresh `__tco_<i>` temp BEFORE any
        // parameter write forecloses the arg-swap clobber (`go b a rest` must not
        // read an already-overwritten `a`); each temp reads the CURRENT params.
        Expr::TailRecur { args } => {
            if args.len() != loop_params.len() {
                // Invariant broken by the rewrite — fail closed, never panic.
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_expr_tail",
                    detail: format!(
                        "TailRecur has {} args but the enclosing TailLoop has {} params",
                        args.len(),
                        loop_params.len()
                    ),
                });
            }
            let mut temps = String::new();
            for (idx, arg) in args.iter().enumerate() {
                let a = emit_expr_at(ctx, arg, indent, child, generics)?;
                writeln!(temps, "{pad}let __tco_{idx} = {a};").map_err(|e| {
                    Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::emit_expr_tail",
                        detail: format!("writing TCO jump temp failed: {e}"),
                    }
                })?;
            }
            let mut writes = String::new();
            for (idx, (name, _ty)) in loop_params.iter().enumerate() {
                let n = ctx.emit_ident(*name)?;
                writeln!(writes, "{pad}{n} = __tco_{idx};").map_err(|e| {
                    Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::emit_expr_tail",
                        detail: format!("writing TCO param reassignment failed: {e}"),
                    }
                })?;
            }
            Ok(format!("{temps}{writes}{pad}continue;"))
        }
        // Every other node is a leaf tail position → return its value.
        other => {
            let v = emit_expr_at(ctx, other, indent, child, generics)?;
            Ok(format!("{pad}return {v};"))
        }
    }
}

/// Emit an application of a first-class function value, `(<func>)(<args>)`. The
/// callee is parenthesised so a boxed `dyn Fn` (or any expression value) is
/// applied uniformly — a `Box<dyn Fn(..)>` auto-derefs at the call. `depth` is
/// the application's own IR-nesting level; its callee and arguments are emitted
/// one level deeper. Kept out of the `emit_expr_at` match (`#[inline(never)]`)
/// so its `Vec`/`String` locals don't inflate the recursive frame.
#[inline(never)]
pub fn emit_apply(
    ctx: &EmitCtx,
    func: &Expr,
    args: &[Expr],
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    // ── Immediately-applied lambda inlining (Bug 3a / T4) ──────────────────
    // Pattern: `(Box::new(move |p0: T0, …| -> R { body }))(arg0, …)`
    //
    // Rust requires the closure inside `Box::new(…)` to implement `Fn` (not
    // just `FnOnce`) so that `(Box::new(closure))(arg)` can call it via
    // `Fn::call` (auto-deref path).  When the body creates an inner `move`
    // closure that captures a non-Copy variable from the outer closure's
    // environment (e.g. a `Box<dyn Fn>` HOF arg, or a `String` that is moved
    // into an inner `Box::new(move |…| …)`), the outer closure becomes
    // `FnOnce` — triggering E0525.
    //
    // When a lambda is *immediately applied* (`(lambda)(arg)`), the `Box::new`
    // wrapper is unnecessary.  Inlining as:
    //   `({ let p0: T0 = arg0; … body … })`
    // avoids the `Fn` requirement entirely.  Semantics are identical: the args
    // are evaluated and bound, then the body executes in the same scope.  Free
    // variables from the outer scope are used directly — no capture, no
    // ownership transfer.
    if let Expr::Lambda {
        params,
        ret: _,
        body,
    } = func
        && args.len() == params.len()
    {
        // Immediately-applied-lambda inlining, only when the arg count EQUALS the
        // lambda's arity — the ordinary saturated `(\p0,… -> body) a0 …` shape.
        // `args.len() > params.len()` is a CURRIED application of a
        // function-returning lambda (`(\p -> fn-value) a b`): the body yields a
        // function that the surplus args apply to, so it must NOT be inlined here —
        // the zip would drop the surplus and silently discard those applications
        // (the composed-higher-order-combinator SEAL break). That case is handled
        // by the split path below.
        let child = depth + 1;
        let mut bindings = String::new();
        for ((param, ty), arg) in params.iter().zip(args.iter()) {
            let p = ctx.emit_ident(*param)?;
            let t = render_type(ctx, ty, generics)?;
            let a = emit_expr_at(ctx, arg, indent, child, generics)?;
            // write! to String is infallible (String::write_fmt delegates to push_str).
            let _ = write!(bindings, "let {p}: {t} = {a}; ");
        }
        let body_s = emit_expr_at(ctx, body, indent, child, generics)?;
        return Ok(format!("({{ {bindings}{body_s} }})"));
    }
    let child = depth + 1;
    // Curried application of a function-returning lambda: `(\p0,… -> fn-value) a0
    // … aN` where the arg count EXCEEDS the lambda's own arity. The lambda yields
    // a function value once its own params are bound; the surplus args apply to
    // THAT value. Emit `(lambda)(own-args)(surplus-args)` so the two application
    // stages stay distinct — folding them into one call list would pass too many
    // args to the lambda (E0057/E0308). Every other `func` shape (a `Box<dyn Fn>`
    // read, a top-level `FuncValue`, …) carries the flattened arity the single
    // call list expects, so it takes the plain path below.
    if let Expr::Lambda { params, .. } = func
        && args.len() > params.len()
    {
        let (own_args, surplus) = args.split_at(params.len());
        let stage1 = emit_apply(ctx, func, own_args, indent, child, generics)?;
        let mut rest = Vec::with_capacity(surplus.len());
        for arg in surplus {
            rest.push(emit_expr_at(ctx, arg, indent, child, generics)?);
        }
        return Ok(format!("({stage1})({})", rest.join(", ")));
    }
    let f = emit_expr_at(ctx, func, indent, child, generics)?;
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        parts.push(emit_expr_at(ctx, arg, indent, child, generics)?);
    }
    Ok(format!("({f})({})", parts.join(", ")))
}

/// Emit a top-level function (or kernel) named as a first-class *value* as a
/// type-pinned smart-pointer closure.
///
/// For the server-handler shape (`ServerRequest -> Task Error ServerResponse`,
/// which renders as `ServerHandler<IpeError>` — an `Arc<dyn Fn(…)>` alias in
/// the runtime), emits `Arc::new(<name>)` so the coercion produces the correct
/// runtime type.  For every other `Fun` shape, emits `Box::new(<name>)` as
/// before (`Box<dyn Fn(..) -> R + Send + 'static>`).
///
/// The explicit binding type drives the unsized coercion of the named `fn`
/// item (a zero-sized `Fn` implementor) to the smart-pointer trait object, so
/// the value fills the slot uniformly in every position — argument, return, or
/// let-binding — rather than relying on a coercion site that an `if`/`match`
/// branch or a bare `let` would not provide.
///
/// `ty` is the value's `Fun` IR type; [`render_type`] renders it as the typed
/// smart-pointer.  Kept `#[inline(never)]` for the same frame-size reason as
/// the neighbouring helpers.
/// Does a function value / lambda of IR type `ty` fill one of the runtime's
/// `Arc<dyn Fn + Send + Sync>` callback slots (so it must be boxed with
/// `Arc::new`, not `Box::new`)? The shapes:
///   • `ServerHandler<E>`: `Fn(ServerRequest) -> IpeTask<E, ServerResponse>`
///   • `WsServerCfg` callbacks, `-> IpeTask<E, ()>`:
///       - `Fn(WsHandle)`           (onConnect / onClose)
///       - `Fn(WsHandle, String)`   (onMessage)
///       - `Fn(WsHandle, Error)`    (onError — 2nd param is the error type,
///         NOT String; its setter `ws_server_with_on_error` takes `Arc<…>`)
///
/// This MUST dispatch on the `IrType` STRUCTURE, never on the rendered type
/// string. `render_type` renders `ServerHandler<E>` as the type-ALIAS name
/// `"ServerHandler<IpeError>"` — NOT the expanded `"Arc<dyn Fn…>"` — so a
/// `starts_with("Arc<")` string test silently misclassifies every handler shape
/// as `Box` and reintroduces the E0308 seal break for inline
/// `Server.post path (\req -> …)` handler lambdas (the regression this shared
/// helper closes). The param patterns are kept in LOCK-STEP with `render_type`'s
/// WS/ServerHandler Arc arms (`emit_types.rs`) — a shape rendered as `Arc<…>`
/// there but boxed with `Box::new` here (or vice-versa) is an E0308. Both
/// `emit_func_value` and `emit_lambda` route through here so the two emit paths
/// can never drift.
pub fn wants_arc_ctor(ty: &IrType) -> bool {
    // A promoted `SharedFun` slot renders `Arc<dyn Fn>` (`render_type`), so its
    // value must be built with `Arc::new`, not `Box::new` — the two carriers are
    // distinct Rust types and mixing them is an E0308.
    if matches!(ty, IrType::SharedFun(_, _)) {
        return true;
    }
    matches!(ty,
        IrType::Fun(params, ret)
            if (matches!(params.as_slice(), [IrType::ServerRequest])
                && matches!(ret.as_ref(), IrType::Task(inner)
                    if matches!(inner.as_ref(), IrType::ServerResponse)))
               || (matches!(
                    params.as_slice(),
                    [IrType::WebSocketServer]
                        | [IrType::WebSocketServer, IrType::Str | IrType::Error]
                ) && matches!(ret.as_ref(), IrType::Task(inner)
                    if matches!(inner.as_ref(), IrType::Unit)))
    )
}

#[inline(never)]
pub fn emit_func_value(
    ctx: &EmitCtx,
    callee: &Callee,
    ty: &IrType,
    generics: GenericScope,
) -> DResult<String> {
    let name = callee_name(ctx, callee)?;
    let typed = render_type(ctx, ty, generics)?;
    let ctor = if wants_arc_ctor(ty) { "Arc" } else { "Box" };
    Ok(format!(
        "{{ let __ipe_fn: {typed} = {ctor}::new({name}); __ipe_fn }}"
    ))
}

/// Emit the unboxed inner `move |p0: T0, …| -> R { <body> }` closure expression.
/// Used by both [`emit_lambda`] (wraps it in `Box::new(…)`) and the `succeed`
/// curry path in [`emit_json_decoder_call`] (wraps it in `curry{n}(…)` instead).
/// `depth` is the lambda's own IR-nesting level; the body is emitted one level
/// deeper.
pub fn emit_lambda_unboxed(
    ctx: &EmitCtx,
    params: &[(Symbol, IrType)],
    ret: &IrType,
    body: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
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
    // This is a `move` closure: it captures `__ipe_lit` by move, so a style
    // literal inside its body must NOT hoist into the enclosing view's table
    // (it would contend with the binding's other uses). Fence hoisting off for
    // the closure body; literals within emit directly, unchanged.
    ctx.enter_closure();
    let body_result = emit_expr_at(ctx, body, indent, child, generics);
    ctx.exit_closure();
    let body_s = body_result?;
    Ok(format!(
        "move |{}| -> {ret_s} {{ {body_s} }}",
        parts.join(", ")
    ))
}

/// Emit a lambda `\p0 p1 ... -> body` as a boxed closure whose static type is
/// pinned to the trait-object form
/// `{ let __ipe_fn: Box<dyn Fn(T0, ...) -> R + Send + 'static> = Box::new(move
/// |p0: T0, ...| -> R { <body> }); __ipe_fn }`. The `move` capture takes any
/// free locals by value; the explicit return type pins the closure's signature.
///
/// The `let`-binding type annotation is load-bearing: `Box::new(closure)` on
/// its own infers `Box<{closure@…}>` — a box of the CONCRETE, unnameable
/// closure type — which only unsize-coerces to `Box<dyn Fn(..) -> ..>` when the
/// surrounding position supplies the trait-object target (a kernel call arg, a
/// return slot, …). A lambda that flows into a `let` binding first, or into a
/// built-in `Ok`/`Just` payload (which routes to the runtime `IpeResult`/
/// `IpeMaybe` enum whose generic argument is inferred from the constructor arg,
/// NOT from a field type), has no such target at the box site, so Rust pins the
/// concrete closure type and a LATER use against `Box<dyn Fn>` fails as E0308.
/// Pinning the trait object HERE — the same technique [`emit_func_value`] uses
/// for a named function value — makes every lambda's static type the boxed
/// trait object regardless of where it flows, closing the IPE-L0114
/// `let f = Ok (\x -> …)` seal hole with no lowering / type-check change.
///
/// The pointer constructor matches the rendered type: a lambda filling one of
/// the runtime's `Arc<dyn Fn + Send + Sync>` slots (a `ServerHandler` /
/// `WsServerCfg` callback shape — see [`render_type`]'s special-case arms) is
/// boxed with `Arc::new`, everything else with `Box::new`. `depth` is the
/// lambda's own IR-nesting level; its body is emitted one level deeper. Kept
/// out of the `emit_expr_at` match (`#[inline(never)]`) for the same frame-size
/// reason as [`emit_record`] / [`emit_update`].
#[inline(never)]
pub fn emit_lambda(
    ctx: &EmitCtx,
    params: &[(Symbol, IrType)],
    ret: &IrType,
    body: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    let inner = emit_lambda_unboxed(ctx, params, ret, body, indent, depth, generics)?;
    let fun_ty = IrType::Fun(
        params.iter().map(|(_, t)| t.clone()).collect(),
        Box::new(ret.clone()),
    );
    let typed = render_type(ctx, &fun_ty, generics)?;
    // The pointer constructor must match the smart pointer of the annotated
    // type: `Arc::new` for the two runtime handler shapes (ServerHandler /
    // WsServerCfg callbacks, whose fields are `Arc<dyn Fn + Send + Sync>`),
    // `Box::new` otherwise. Dispatch on the IR STRUCTURE via `wants_arc_ctor`,
    // NOT on the rendered string — `render_type` emits `ServerHandler<E>` as the
    // alias name, so a `starts_with("Arc<")` test would misclassify it as Box
    // and E0308 the handler-lambda shape.
    let ctor = if wants_arc_ctor(&fun_ty) {
        "Arc"
    } else {
        "Box"
    };
    Ok(format!(
        "{{ let __ipe_fn: {typed} = {ctor}::new({inner}); __ipe_fn }}"
    ))
}

/// Emit a `let`-bound closure literal that [`ipe_lower`]'s capture analysis
/// (`needs_shared_capture`, which prevents E0507) proved is captured-by-move
/// into 2+ nested/sibling closures, and therefore must be reference-counted
/// (`Arc`) rather than uniquely owned (`Box`) so the corresponding
/// `Expr::CloneVar` reads at every extra capture site (`Arc::clone`, a cheap
/// pointer bump) actually compile.
///
/// Unlike [`emit_lambda`], this does NOT go through `wants_arc_ctor` /
/// `render_type`'s generic `IrType::Fun` arm — that arm renders
/// `Box<dyn Fn(..) -> R + Send + 'static>` (no `Sync`), which would make the
/// `Arc<..>` wrapper itself neither `Send` nor `Sync` (`impl Send/Sync for
/// Arc<T>` both require `T: Send + Sync`) — silently breaking every
/// enclosing closure's OWN `Send + Sync` bound. The trait-object bound here
/// is built directly with the `+ Sync` `Arc<dyn Fn>` needs, mirroring the
/// runtime's existing `ServerHandler` / `WsServerCfg` Arc-callback shapes
/// (`emit_types.rs`) at the type-string level.
#[inline(never)]
pub fn emit_shared_lambda(
    ctx: &EmitCtx,
    params: &[(Symbol, IrType)],
    ret: &IrType,
    body: &Expr,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    let inner = emit_lambda_unboxed(ctx, params, ret, body, indent, depth, generics)?;
    let mut parts = Vec::with_capacity(params.len());
    for (_, ty) in params {
        parts.push(render_type(ctx, ty, generics)?);
    }
    let ret_s = render_type(ctx, ret, generics)?;
    let typed = format!(
        "::std::sync::Arc<dyn Fn({}) -> {ret_s} + Send + Sync + 'static>",
        parts.join(", ")
    );
    Ok(format!(
        "{{ let __ipe_fn: {typed} = ::std::sync::Arc::new({inner}); __ipe_fn }}"
    ))
}

/// Render one type parameter's trailing bound clause for the generic list:
/// `: ::core::ops::Add<Output = T{n}> + Copy` and the like, or the empty string
/// for an unbounded variable (so a structurally-parametric function emits a
/// bare `T{n}` with no bound clause).
///
/// `n` is the variable's 1-based position, which is also its own Rust name
/// `T{n}` — the arithmetic `::core::ops` traits take `Output = T{n}` so the
/// operation stays closed over the parameter's type (`x + x : T{n}`). The trait
/// order is fixed (`Add`, `Sub`, `Mul`, `PartialOrd`, `PartialEq`, `Ord`,
/// `Hash`, `Copy`, `Clone`, `Into<SqlParam>`) so the emission is deterministic
/// regardless of how the bound set was assembled.
///
/// `target` resolves the target-relative effect-carrier `Send`
/// ([`BoundSet::requires_send_on`]): `Send` on a native host, only `'static` on
/// wasm32, whose `Cmd` / `Sub` / `Task` carriers are not `Send`.
pub fn render_bounds(bounds: BoundSet, n: usize, target: ipe_ir::Target) -> String {
    if bounds.is_unbounded() {
        return String::new();
    }
    let mut traits = Vec::new();
    if bounds.has_static() {
        // Boxed-callback `'static` lifetime bound: a generic type-param
        // that flows into a value boxed as `Box<dyn Fn(..) -> .. + Send +
        // 'static>` (a callback passed to `List.map` etc.) whose own type still
        // mentions that type-param requires `tv: 'static` for the trait-object
        // coercion. A LIFETIME bound — Rust requires it to PRECEDE every trait
        // bound in the list (`T{n}: 'static + Clone`), so it is pushed FIRST.
        // Satisfied by every concrete Ipê type (emitted values never borrow),
        // so no caller-side failure — see `BoundSet::STATIC`.
        traits.push("'static".to_owned());
    }
    if bounds.requires_send_on(target) {
        // `Send` auto-trait: an unconditional obligation (a `Decoder` / `Task` element, a
        // boxed `+ Send` callback), or a `Cmd` / `Sub` payload on a target whose
        // effect carriers are `Send`. Pushed after the `'static` lifetime bound
        // (a lifetime must precede trait bounds).
        traits.push("Send".to_owned());
    }
    if bounds.has_sync() {
        // `Sync` auto-trait: a generic type-param whose value is captured behind
        // a `Send + Sync` shared carrier that requires the element `Sync` — the
        // optional-decoder runtime slots (`decode_pipeline_optional`,
        // `db_decode_optional`), whose element param is bounded `Send + Sync`.
        // Pushed right after `Send` (auto-traits precede the operator traits);
        // fully qualified since `Sync` — like `Send` — is in the prelude, so the
        // bare name is enough. Satisfied by every concrete Ipê type (owned data
        // is trivially `Sync`).
        traits.push("Sync".to_owned());
    }
    if bounds.has_add() {
        // Wrapping addition so `T{n} + T{n}` in a generic body does not panic
        // under `overflow-checks=on` when the call site monomorphises to i64.
        // The trait is `pub use`-re-exported at the runtime crate root
        // (`ipe_runtime::IpeWrappingAdd`) via `mod.rs`'s `pub use basics::*`.
        traits.push(format!(
            "ipe_runtime::basics::IpeWrappingAdd<Output = T{n}>"
        ));
    }
    if bounds.has_sub() {
        traits.push(format!(
            "ipe_runtime::basics::IpeWrappingSub<Output = T{n}>"
        ));
    }
    if bounds.has_mul() {
        traits.push(format!(
            "ipe_runtime::basics::IpeWrappingMul<Output = T{n}>"
        ));
    }
    if bounds.has_ord() {
        traits.push("PartialOrd".to_owned());
    }
    if bounds.has_eq() {
        traits.push("PartialEq".to_owned());
    }
    if bounds.has_show() {
        // Ipê `toString` / `Log.*With`: the value must render. Fully qualified —
        // the trait is not in the Rust prelude. Every emitted record/ADT + every
        // scalar has a `IpeStringify` impl.
        traits.push("crate::ipe_runtime::stringify::IpeStringify".to_owned());
    }
    if bounds.has_ord_total() {
        // `Ord` (total order) for a `Set` element / sorted `Dict` op; carries
        // `Eq` + `PartialOrd` + `PartialEq` as supertraits, so a `Dict` key's
        // `HashMap` `Eq` requirement is met without a separate `Eq` bound.
        traits.push("Ord".to_owned());
    }
    if bounds.has_hash() {
        // `Hash` for a `Dict` key's `HashMap` backing. Fully qualified — the
        // trait (unlike its derive macro) is not in the Rust prelude.
        traits.push("::core::hash::Hash".to_owned());
    }
    if bounds.has_copy() {
        traits.push("Copy".to_owned());
    }
    if bounds.has_clone() {
        traits.push("Clone".to_owned());
    }
    if bounds.has_sql_param() {
        // SQL-bind-parameter obligation: the runtime's `SqlParam::from`
        // family is realised as `Into<SqlParam>` on the emitted generic (not a
        // `where SqlParam: From<T{n}>` clause) so it composes with the ordinary
        // `<T{n}: Bound1 + Bound2>` list this function already builds — no
        // separate `where`-clause plumbing needed in [`emit_func`].
        traits.push("Into<ipe_runtime::db::SqlParam>".to_owned());
    }
    if bounds.has_ipe_row() {
        // Db field-accessor row obligation: a wildcard `any` generic that
        // flows into a `Db.get*` accessor gains `IpeRow` so the runtime's generic
        // `db_get_*<R: IpeRow>(field, &row)` call type-checks and monomorphises
        // per call site. Fully qualified — the trait is not re-exported at the
        // emitted crate's `pub use ipe_runtime::*` root. Added ONLY to the `any`
        // var and ONLY when the body calls `db_get_*` (see [`emit_func`]).
        traits.push("ipe_runtime::db::IpeRow".to_owned());
    }
    format!(": {}", traits.join(" + "))
}

/// Recursively elide a `Task.run` / `Task.perform` call in EVERY tail
/// position of `expr`, returning the rewritten expression only when ALL tail
/// leaves are such a call. `None` when even one tail leaf is not — a partial
/// elision would leave some arms `Task<A>`-shaped and others
/// `Result<E, A>`-shaped, which cannot render as one Rust `match`/`if` with a
/// single type, so this is deliberately all-or-nothing.
///
/// Mirrors [`emit_func`]'s original flat single-call elision (a bare
/// `Call(TaskRun, [inner])` whole-function body) generalised through the
/// control-flow constructs that legally appear in a tail position: `Match`
/// (`case`), `If`, and `Let` / `Destructure` (only their BODY is a tail
/// position — the bound `value` is left untouched and un-recursed-into).
/// `Match` is rebuilt via [`Match::from_parts_unchecked`]: only arm BODIES
/// change here, never the arm patterns, so the exhaustiveness proof
/// [`Match::new`] / [`Match::new_flat`] already ran stays valid.
pub fn elide_task_run_tail(expr: &Expr) -> Option<Expr> {
    match expr {
        Expr::Call {
            callee: Callee::Kernel(KernelFn::TaskRun | KernelFn::TaskPerform),
            args,
            ..
        } => {
            let [inner] = args.as_slice() else {
                return None;
            };
            Some(inner.clone())
        }
        Expr::If { cond, then_, else_ } => {
            let then_e = elide_task_run_tail(then_)?;
            let else_e = elide_task_run_tail(else_)?;
            Some(Expr::If {
                cond: cond.clone(),
                then_: Box::new(then_e),
                else_: Box::new(else_e),
            })
        }
        Expr::Let { name, value, body } => {
            let body_e = elide_task_run_tail(body)?;
            Some(Expr::Let {
                name: *name,
                value: value.clone(),
                body: Box::new(body_e),
            })
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            let body_e = elide_task_run_tail(body)?;
            Some(Expr::Destructure {
                binder: binder.clone(),
                value: value.clone(),
                body: Box::new(body_e),
            })
        }
        Expr::Match(m) => {
            // Sealed rebuild via `try_map_bodies` (AUD-09): the scrutinee and
            // every arm's pattern/guard pass through UNCHANGED (by
            // construction, not by convention), so exhaustiveness is
            // preserved with no re-derivation needed — only each arm's body
            // is transformed, and any single arm declining the elision
            // (`elide_task_run_tail` returning `None`) must fail the WHOLE
            // match's elision, matching this function's existing `?`-based
            // all-or-nothing contract on every other tail-position arm.
            m.clone()
                .try_map_bodies(Ok::<_, ()>, |_pat, body, guard| {
                    let new_body = elide_task_run_tail(&body).ok_or(())?;
                    Ok((new_body, guard))
                })
                .ok()
                .map(Expr::Match)
        }
        // Every other expression shape is a genuine value in tail position
        // (not a control-flow construct that merely forwards to a nested tail
        // position), so it either IS the whole elidable call (handled above)
        // or it is not elidable at all.
        _ => None,
    }
}

/// [`emit_func`]'s `ipe_main` synchronous-body wrap decision.
///
/// When `ipe_main` was NOT elided (its body is not — or not uniformly in
/// every tail position — a `Task.run` call), the function currently returns
/// its declared value type directly, but the entry-point epilogue calls
/// `block_on(ipe_main())`, which requires `ipe_main` to return `IpeTask<A>`
/// (an unevaluated future), never a resolved value.
///
/// Two declared-return shapes reach here, and BOTH wrap the body rather than
/// change its VALUE — `ipe_main`'s body already runs to completion
/// synchronously either way (a bare `task_run()` call blocks in place); the
/// wrap only reshapes the return type so `block_on` type-checks:
///
/// * `func.ret == Unit` — Ipê CLI programs that use synchronous `task_run()`
///   calls (instead of building a top-level Task pipeline). The caller wraps:
///   `let _r = { <original body> }; task_succeed(())` — `ipe_main` returns
///   `IpeTask<()>`, discarding the body's (unit) value. Signalled by the
///   returned `wrap_unit = true`.
/// * `func.ret == Result(_, A)` with elision declined — the argv-dispatch
///   idiom's MIXED-arm sibling gap (adversarial-review Finding B): some
///   `case` tail leaves call `Task.run` (blocks synchronously, producing a
///   real `Result e a`), OTHER tail leaves are a plain `Result`-typed
///   expression with no `Task.run` at all (`Err e -> Err e` in a
///   validate-then-run idiom, e.g. `case validate () of Err e -> Err e; Ok
///   cfg -> app cfg |> Task.run`). `elide_task_run_tail` correctly declines a
///   partial elision (mismatched Task/Result arm shapes cannot render as one
///   `match` of a single type) — but the body AS A WHOLE already evaluates
///   synchronously to one uniform `Result e a`. The caller wraps:
///   `task_from_result({ <original body> })` — `ipe_main` returns `IpeTask<A>`,
///   an ALREADY-RESOLVED future carrying the body's actual computed
///   `Ok`/`Err`, so `block_on` unwraps it back to the exact `IpeResult<E, A>`
///   the un-wrapped body would have produced directly; `fn main`'s
///   `Ok(_)`/`Err(e)` epilogue match sees identical values. Signalled by
///   `Some(Task(ok_ty))` in the returned `Option`.
///
/// Returns `(wrap_unit, wrap_result_ok_ty)` — at most one is ever set (`Unit`
/// and `Result` are disjoint [`IrType`] shapes).
pub fn ipe_main_wrap_decision(
    name: &str,
    elided_ret: Option<&IrType>,
    func_ret: &IrType,
) -> (bool, Option<IrType>) {
    if name != "ipe_main" || elided_ret.is_some() {
        return (false, None);
    }
    match func_ret {
        IrType::Unit => (true, None),
        IrType::Result(_err_ty, ok_ty) => (false, Some(IrType::Task(ok_ty.clone()))),
        _ => (false, None),
    }
}

/// Emit a whole function item, including its trailing newline.
///
/// Shape: `pub fn <name>[<generics>](<params>) -> <ret> {\n    <body>\n}\n`. A
/// monomorphic function (empty `type_params`) emits no generic clause, so its
/// output is byte-identical to the golden `main_update` / `ipe_main`. A
/// fully-parametric function quantifying `[a, b]` emits `pub fn name<T1, T2>(..)`
/// and renders every [`IrType::Generic`] in its signature / body through the
/// matching scope. A variable carrying a [`BoundSet`] gains its
/// `: <bounds>` clause at its position. The body is an expression rendered
/// at indentation level 1; the closing brace sits at column 0.
pub fn emit_func(ctx: &EmitCtx, func: &Func) -> DResult<String> {
    emit_func_vis(ctx, func, "pub fn ")
}

/// The `Model` parameter symbol of a TEA `update` function, or `None` for any
/// other function.
///
/// A TEA `update` is `Msg -> Model -> (Model, Cmd Msg)` (curried), so at the IR
/// level it returns a two-element tuple whose SECOND element is a `Cmd` and
/// takes the `Model` as its LAST parameter. Recognised by exactly that shape;
/// any function returning something other than `(_, Cmd _)`, or taking no
/// parameter, is not an update and returns `None` — the arm rewrite stays off.
///
/// The returned symbol is only an ARMING hint: the transition classifier
/// independently proves the arm updates THIS parameter (`is_var(record,
/// model_param)`) and resolves each field, so a mis-identified parameter (a
/// non-update function that coincidentally returns `(_, Cmd _)` — e.g. a helper)
/// simply yields no classifiable arm, never a wrong rewrite. Conservative by
/// construction.
pub fn tea_update_model_param(func: &ipe_ir::Func) -> Option<Symbol> {
    let IrType::Tuple(elems) = &func.ret else {
        return None;
    };
    let [_model_ty, second] = elems.as_slice() else {
        return None;
    };
    if !matches!(second, IrType::Cmd(_)) {
        return None;
    }
    func.params.last().map(|(sym, _)| *sym)
}

/// Whether `func` is a TEA `subscriptions` function — `Model -> Sub Msg`. The
/// return type must be a `Sub` and the function must take at least one parameter
/// (the Model). Used to arm the `subscriptions`-entry sub-description rewrite for
/// this body; a non-subscriptions function is never sub-rewritten.
pub const fn is_tea_subs_function(func: &ipe_ir::Func) -> bool {
    matches!(&func.ret, IrType::Sub(_)) && !func.params.is_empty()
}

/// Whether `func`'s return type is the TEA producer shape `(_, Cmd _)` — the
/// arming gate for the `init` datum rewrite. This admits both `init` and
/// `update` (both return `(Model, Cmd _)`); the body classifier
/// ([`crate::transition_classify::init_datum_of_body`]) then refuses an `update`
/// body (a `msg` match, never a bare record-literal tuple) and every non-`init`
/// helper, so the arming is only a cheap pre-filter, never the correctness gate.
pub const fn func_returns_cmd_tuple(func: &ipe_ir::Func) -> bool {
    let IrType::Tuple(elems) = &func.ret else {
        return false;
    };
    let [_model_ty, second] = elems.as_slice() else {
        return false;
    };
    matches!(second, IrType::Cmd(_))
}

/// The reduced body for a data-describable TEA `init`, or `None` to keep the
/// ordinary body emit.
///
/// Reduces `init _ = ({ f = lit, … }, Cmd.none)` to an `apply_init_hot` call so an
/// `init` edit is session-scoped (a FRESH session decodes the edited datum; a LIVE
/// session keeps its Model). Armed only under `hot_appearance`, only for a
/// function whose return type is `(_, Cmd _)` (the TEA producer shape), and only
/// when the body classifies as a record literal of closed leaves with `Cmd.none`.
/// An `update` body is a `msg` match (never a bare record tuple), so it never
/// classifies; with the flag off (or an `ipe_main`-wrapped entry-point body) this
/// returns `None` and the body is byte-identical to the direct form.
pub fn emit_init_hot_for_func(
    ctx: &EmitCtx,
    func: &Func,
    body_expr: &Expr,
    ipe_main_wrap: bool,
    generics: GenericScope,
) -> DResult<Option<String>> {
    if ctx.hot_appearance && !ipe_main_wrap && func_returns_cmd_tuple(func) {
        emit_init_datum(ctx, body_expr, 1, 0, generics)
    } else {
        Ok(None)
    }
}

/// Emit a whole function item with the given visibility prefix (`"pub fn "` for
/// the single-file layout, `"pub fn "` for a split `IpeModule` file where
/// the item lives inside a `mod` block). The prefix is threaded through to
/// [`render_fn_signature`] so the signature's flat-vs-broken width decision
/// measures against the prefix the emitted line actually carries — the
/// `pub(crate)` form is seven columns wider than `pub`, so a borderline signature
/// breaks under one and not the other.
#[allow(
    clippy::too_many_lines,
    reason = "one linear emit pipeline (elision, wraps, per-function literal + transition + \
              sub-description arming + init hot rewrite, body render, signature); the cohesive \
              sub-decisions are already extracted (e.g. `emit_init_hot_for_func`, \
              `ipe_main_wrap_decision`), and splitting the rest would thread a dozen locals \
              through helpers without clarifying the single straight-line flow"
)]
pub fn emit_func_vis(ctx: &EmitCtx, func: &Func, vis_prefix: &str) -> DResult<String> {
    let name = ctx.func_name(func.id)?.to_owned();

    // ── Entry-point Task.run elision ──────────────────────────────────────────
    // When `ipe_main` is `main = someTask |> Task.run`, the lowerer sets:
    //   func.body = Call(TaskRun | TaskPerform, [inner_task])
    //   func.ret  = IrType::Result(IrType::Error, A)
    //
    // The Rust epilogue calls `block_on(ipe_main())`, which requires `ipe_main`
    // to return `IpeTask<A>` (an unevaluated future), NOT `IpeResult<E, A>`.
    // Elide the outer `task_run(...)` wrapper: use the inner task expression as
    // the body and convert the return type from `Result(Error, A)` to `Task(A)`.
    //
    // This is not always a FLAT `Call(TaskRun, …)` body — the Ipe.Terminal /
    // Ipe.Web `argv`-dispatch idiom branches on `System.args` before picking which
    // app to run, e.g. `main = case List.head argsList of Just "live" -> Web.tea
    // cfg |> Task.run; _ -> Tui.tea cfg |> Task.run`. Every arm still
    // tail-calls
    // `Task.run`, so the SAME elision must apply — otherwise `ipe_main` keeps
    // its `IpeResult<E, A>` return type and `block_on(ipe_main())` mismatches
    // exactly as the flat case would (a real SEAL violation found on
    // `examples/24-tui-kitchen-sink`, BACKLOG "24-tui-kitchen-sink").
    // `elide_task_run_tail` recurses through every tail-position control-flow
    // construct (`Match` / `If` / `Let` / `Destructure`) and elides ONLY when
    // EVERY leaf in tail position is a `Task.run` / `Task.perform` call — a
    // partial elision is never produced, so the rewritten body always has a
    // single uniform `Task<A>` shape.
    let elided: Option<(Expr, IrType)> = if name == "ipe_main"
        && let IrType::Result(_, ok_ty) = &func.ret
    {
        elide_task_run_tail(&func.body).map(|body| (body, IrType::Task(ok_ty.clone())))
    } else {
        None
    };
    let (body_expr, elided_ret): (&Expr, Option<IrType>) = match &elided {
        Some((body, ret)) => (body, Some(ret.clone())),
        None => (&func.body, None),
    };

    // ── ipe_main synchronous-body wrap ────────────────────────────────────────
    // When ipe_main was NOT elided, `block_on(ipe_main())` still needs
    // `IpeTask<A>`. See `ipe_main_wrap_decision`'s doc comment for the full
    // rationale (the CLI `task_run()`-calls idiom AND Finding B's mixed-arm
    // sibling gap).
    let (ipe_main_wrap_unit, ipe_main_wrap_result_ok_ty) =
        ipe_main_wrap_decision(&name, elided_ret.as_ref(), &func.ret);
    let ipe_main_wrap = ipe_main_wrap_unit || ipe_main_wrap_result_ok_ty.is_some();
    let wrapped_task_owned: Option<IrType> = if ipe_main_wrap_unit {
        Some(IrType::Task(Box::new(IrType::Unit)))
    } else {
        ipe_main_wrap_result_ok_ty
    };
    let ret_ty: &IrType = wrapped_task_owned
        .as_ref()
        .unwrap_or_else(|| elided_ret.as_ref().unwrap_or(&func.ret));

    // The generic scope resolves an `IrType::Generic` to its positional Rust
    // name; only the variable symbols participate, so project them out of the
    // `(Symbol, BoundSet)` pairs.
    let scope_syms: Vec<Symbol> = func.type_params.iter().map(|(sym, _)| *sym).collect();
    // The row variables this function quantifies, in order, projected out of
    // `row_params` so an `IrType::RowGeneric` renders to its positional `R{n}`.
    let row_syms: Vec<Symbol> = func.row_params.iter().map(|r| r.var).collect();
    // The parameter binders carrying a row-generic type — the value-level names
    // whose field reads must route through the witness getters.
    let row_binder_syms: Vec<Symbol> = func
        .params
        .iter()
        .filter(|(_, ty)| matches!(ty, IrType::RowGeneric(_)))
        .map(|(sym, _)| *sym)
        .collect();
    let generics = GenericScope::with_rows(&scope_syms, &row_syms, &row_binder_syms);

    let ret_is_task = matches!(ret_ty, IrType::Task(_));

    // Direct-position function-value monomorphization: a `Fun` param used only
    // as a direct callee renders as a fresh generic `FN{i}` (declared with a
    // `Fn(..) -> R + Send + Sync + 'static` bound in the generic clause) rather
    // than the erased `Box<dyn Fn>`, so rustc monomorphizes and inlines the
    // caller's concrete closure with zero heap allocation or vtable dispatch.
    // The same index set drives the call-site unboxing, so a caller passes the
    // bare closure into the generic slot.
    let impl_fn_params = impl_fn_param_indices(func);

    let mut params = Vec::with_capacity(func.params.len());
    for (i, (param, ty)) in func.params.iter().enumerate() {
        let rendered = if impl_fn_params.contains(&i) {
            impl_fn_generic_name(i)
        } else {
            render_type(ctx, ty, generics)?
        };
        params.push(format!("{}: {rendered}", ctx.emit_ident(*param)?));
    }
    let ret = render_type(ctx, ret_ty, generics)?;

    // M is inferred bottom-up from concrete element/attrs types
    // propagated by the region-type–sourced lowerer; `generics` is used
    // directly.
    // TCO: a `TailLoop` body emits `let mut`-shadowed params + a
    // `loop { … }` whose interior ends only in `return`/`continue`. Mutability is
    // introduced ONLY by the local `let mut p = p;` shadow, so the public `fn`
    // signature stays byte-identical to the non-TCO form (load-bearing for
    // `FuncValue` boxing / trait-object slots). The loop types as `!` (it never
    // falls through), so it unifies with any `-> R` — no `break value`. A
    // non-`TailLoop` body (the common case) routes to the ordinary value emitter,
    // which is exhaustive and fail-closed for any stray TCO node.
    // Arm the per-function style-literal accumulator for this body. Under
    // `hot_appearance` an allowlisted style literal emitted below hoists into
    // this function's table; with the flag off it stays inert and nothing hoists,
    // so the emitted body is byte-identical to the direct-literal form. The
    // previous accumulator is restored after the body is rendered so nested
    // function emission (a lambda that itself emits a helper `fn`) does not leak
    // its slots into this frame's table.
    let saved_literals = ctx.begin_function_literals();
    // Arm the `update`-arm transition rewrite for a TEA `update` body. Only a
    // function whose return type is `(Model, Cmd _)` and whose last parameter is
    // that Model record is a TEA update; its `Model` parameter arms
    // `emit_match` to reduce a data-describable arm to an `apply_transition_hot`
    // call. Inert unless `hot_appearance` (the shared dev gate) is on — with the
    // flag off no arm is ever rewritten and the body is byte-identical. Restored
    // after the body so nested function emission never inherits the arming.
    let tea_update_param = if ctx.hot_appearance {
        tea_update_model_param(func)
    } else {
        None
    };
    let saved_transition = ctx.begin_transition_update(tea_update_param);
    // Arm the sub-description rewrite for a TEA `subscriptions` body; inert off.
    let saved_subs_hot = ctx.begin_subs_hot(ctx.hot_appearance && is_tea_subs_function(func));
    let body = if let Some(init_body) =
        emit_init_hot_for_func(ctx, func, body_expr, ipe_main_wrap, generics)?
    {
        init_body
    } else if ipe_main_wrap_unit {
        // Wrap the synchronous body so ipe_main returns IpeTask<()>; the
        // body's own (unit) value is discarded, only its side effects matter.
        let inner = emit_body_native(ctx, body_expr, generics)?;
        format!("let _r = {{ {inner} }};\n    task_succeed(())")
    } else if ipe_main_wrap {
        // Mixed-arm Task.run-elision-declined wrap (Finding B): the body
        // already evaluates synchronously to a `Result e a` — carry that
        // ACTUAL value into an already-resolved `IpeTask<a>` rather than
        // discarding it, so `fn main`'s Ok/Err match sees the real outcome.
        let inner = emit_body_native(ctx, body_expr, generics)?;
        format!("task_from_result({{ {inner} }})")
    } else {
        match body_expr {
            Expr::TailLoop {
                params: loop_params,
                body: loop_body,
            } => {
                let mut shadows = String::new();
                for (param, _ty) in loop_params {
                    let p = ctx.emit_ident(*param)?;
                    write!(shadows, "let mut {p} = {p};\n    ").map_err(|e| {
                        Diagnostic::CompilerBug {
                            where_: "ipe_backend_rust::emit_func",
                            detail: format!("writing TCO param shadow failed: {e}"),
                        }
                    })?;
                }
                let inner = emit_expr_tail(ctx, loop_body, 2, 1, generics, loop_params)?;
                format!("{shadows}loop {{\n{inner}\n    }}")
            }
            _ => emit_body_native(ctx, body_expr, generics)?,
        }
    };

    // the IpeRow bound (for a wildcard `any` param flowing into a
    // `Db.get*` accessor) is decided STRUCTURALLY at lowering time and carried
    // in the param's `BoundSet` — the generic clause just renders the BoundSet.
    // Any direct-position `Fn` params contribute their fresh `FN{i}: Fn(..)`
    // generics, appended after the ordinary `T{n}` type variables.
    let generic_clause = render_fn_generics(ctx, func, ret_is_task, &impl_fn_params, generics)?;

    // A zero-parameter top-level binding is a CAF (constant applicative form) — a
    // shared VALUE, not a function. Ipê (like Elm) evaluates it once and shares
    // the result; emitting the body inline re-evaluates it on every reference,
    // which reallocates a fresh value per use and, for a binding whose body
    // reads live runtime state, can observe a different value each time. Emit the
    // body behind a lazily-initialised, thread-safe cell so first use evaluates
    // it exactly once and every later use returns a clone of that one value.
    //
    // The gate is deliberately conservative (fail closed): a static cell requires
    // the value type to be `Sync + Send + Clone + 'static`, and the closure must
    // capture nothing type-parametric, so the wrapper applies only to a
    // monomorphic CAF whose return type is a plain shareable data type
    // ([`is_share_once_safe`]). `ipe_main` is excluded — the epilogue's
    // `block_on(ipe_main())` needs a fresh future each call. Every other binding
    // keeps the direct inline emission.
    let is_caf = func.params.is_empty()
        && func.type_params.is_empty()
        && name != "ipe_main"
        && is_share_once_safe(ret_ty);
    let body = if is_caf {
        let call_line = emit_caf_get_or_init(ctx, body_expr, generics)?;
        format!(
            "static CELL: std::sync::OnceLock<{ret}> = std::sync::OnceLock::new();\n    \
             {call_line}"
        )
    } else {
        body
    };
    // The body (the only place a TEA `update`'s arms are emitted) is rendered;
    // disarm the transition rewrite so no sibling / nested function inherits it.
    ctx.end_transition_update(saved_transition);
    ctx.end_subs_hot(saved_subs_hot);

    // Close the accumulator and, if any style literal hoisted, prepend the
    // per-view table binding. Its baked defaults are exactly the hoisted source
    // values in emit order, so `__ipe_lit.get(N)` reads render byte-identically
    // to the direct literals (dev == prod). Empty ⇒ no prologue ⇒ byte-identical
    // to the flag-off body.
    let hoisted = ctx.end_function_literals(saved_literals);
    let lit_prologue = literal_table_prologue(&hoisted);

    let signature = render_fn_signature(vis_prefix, &name, &generic_clause, &params, &ret);
    // Recursion guard prologue: one RAII line at the top of every user function
    // body converts an uncatchable native stack-overflow abort (unbounded direct,
    // mutual, or function-value recursion) into a classifiable, containable panic.
    // The `crate::`-qualified path binds from both the single-file layout (the
    // shim lives at crate root) and a split `IpeModule` file (inside a `mod`
    // block), matching the call convention every cross-module user call uses. The
    // binding MUST be a named `_`-prefixed local, never `let _ = …`, which would
    // drop — and decrement — the guard immediately. A `TailLoop` body carries the
    // guard outside its `loop`, so a tail-recursive function pays it once at entry
    // (§tail-call exemption). See `ipe_runtime::core::recursion_guard`.
    Ok(format!(
        "{signature} {{\n    let _ipe_recursion_guard = crate::recursion_guard();\n    {lit_prologue}{body}\n}}\n"
    ))
}

/// The per-view `LiteralTable` binding for a function whose body hoisted style
/// literals, or the empty string when none did.
///
/// Each default is rendered with the same `{:?}` Rust-string escaping a direct
/// `Expr::Str` uses, so the baked default is byte-for-byte the source value and
/// a `__ipe_lit.get(N)` read is indistinguishable from the direct literal. The
/// binding is emitted immediately after the recursion guard, in scope for every
/// hoisted read in the body.
pub fn literal_table_prologue(defaults: &[String]) -> String {
    if defaults.is_empty() {
        return String::new();
    }
    let rendered: Vec<String> = defaults.iter().map(|d| format!("{d:?}")).collect();
    format!(
        "let __ipe_lit = ipe_runtime::literal_table::LiteralTable::from_defaults(&[{}]);\n    ",
        rendered.join(", ")
    )
}

/// Is `ty` a value type that a top-level CAF may share through a `static`
/// [`std::sync::OnceLock`] cell — i.e. unconditionally `Clone + Send + Sync +
/// 'static`?
///
/// A function-local `static OnceLock<T>` requires `T: Sync`, `get_or_init`
/// stores the value for the process lifetime (`'static`), and the emitted fn
/// returns `T` by value so the shared value must be `Clone`. This recognises
/// only the plain immutable data core plus structural composites built from it —
/// every leaf whose Rust rendering is known to satisfy all three bounds. It
/// fails closed: any effectful, opaque-handle, function-carrying, task, or
/// type-parametric leaf makes the whole type ineligible, so the caller keeps the
/// direct inline emission for that binding. A `Box<dyn Fn>` carrier
/// ([`IrType::Fun`]/[`IrType::FnOnceChain`]) is neither `Sync` nor `Clone`; an
/// [`IrType::Task`] future is single-poll and not `Sync`; an
/// [`IrType::Generic`] cannot appear in a `static` type at all.
pub fn is_share_once_safe(ty: &IrType) -> bool {
    match ty {
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes => true,
        IrType::Maybe(inner) | IrType::List(inner) | IrType::Set(inner) => {
            is_share_once_safe(inner)
        }
        IrType::Result(a, b) | IrType::Dict(a, b) => is_share_once_safe(a) && is_share_once_safe(b),
        IrType::Tuple(items) => items.iter().all(is_share_once_safe),
        // A closed record carries its whole field-type set, so recursing over it
        // is complete: a field holding a `Box<dyn Fn>` (`Fun`) or any other
        // non-shareable leaf makes the record ineligible.
        IrType::Record(fields) => fields.values().all(is_share_once_safe),
        // Everything else keeps the direct inline emission — Task/Cmd/Sub futures
        // and command descriptors, `Box<dyn Fn>` function carriers, opaque runtime
        // handles (Db, Decoder, server/web/UI/websocket types), the
        // Json/Decimal/Order/Error family, and `Generic` type variables. A user
        // `Enum` is excluded too: its `IrType` exposes only the type ARGUMENTS,
        // not the variant field types, so a variant carrying a `Box<dyn Fn>`
        // (neither `Send`/`Sync` nor `Clone`) cannot be ruled out from the type
        // alone — the conservative choice is to leave every enum-typed CAF inline.
        _ => false,
    }
}

/// Render a function signature `pub fn NAME<GEN>(PARAMS) -> RET`, laid out to the
/// exact bytes `rustfmt --edition 2024 --style-edition 2024` produces — flat when
/// it fits, otherwise broken to match rustfmt's fn-signature layout. The returned
/// string has NO trailing ` {`; the caller appends the body block.
///
/// `rustfmt`'s three tiers, keyed off `max_width` (100), reproduced here because
/// the native body path removed the whole-file `rustfmt` pass that used to reflow
/// these lines:
///
/// * **flat** — the whole `pub fn NAME<GEN>(P0, P1, …) -> RET {` line (counting
///   the trailing ` {` the caller adds) is at most 100 columns.
/// * **params broken** — otherwise, if the `pub fn NAME<GEN>(` opening line fits:
///   each parameter on its own line indented four columns with a trailing comma
///   (every parameter, including the last), then `) -> RET {` at column 0.
/// * **generics broken** — otherwise each generic on its own line indented four
///   columns with a trailing comma, `>(` at column 0, then the params-broken body.
///
/// The ` {` the caller appends is included in every fit test (rustfmt measures the
/// opening brace as part of the line), so the flat/broken decision matches the
/// formatter's own boundary — verified flat at width 100, broken at 101.
pub fn render_fn_signature(
    vis_prefix: &str,
    name: &str,
    generic_clause: &str,
    params: &[String],
    ret: &str,
) -> String {
    // `rustfmt` `max_width`; `BRACE` is the trailing ` {` the caller appends after
    // the return type, which rustfmt counts as part of the signature line.
    //
    // `vis_prefix` is the leading `pub fn ` / `pub fn ` the signature carries
    // BEFORE the name. It is threaded here — rather than prepended by the caller — so
    // the flat-vs-broken width decision measures against the SAME prefix the emitted
    // line carries: a split-module `pub fn ` is seven columns wider than the
    // single-file `pub fn `, so a signature that fits flat under `pub fn ` may still
    // overflow under `pub fn ` and must break.
    const MAX_WIDTH: usize = 100;
    const BRACE: usize = 2;
    let flat = format!(
        "{vis_prefix}{name}{generic_clause}({}) -> {ret}",
        params.join(", ")
    );
    if flat.len() + BRACE <= MAX_WIDTH {
        return flat;
    }

    // A zero-parameter signature never breaks its empty `()` — `rustfmt` keeps
    // `NAME() -> ` glued and instead wraps the RETURN TYPE at its outermost angle
    // brackets: `NAME() -> Ptr<\n    Inner,\n>`. Only a return type that is itself a
    // single angle-bracketed generic can wrap; anything else (or a return type whose
    // opening line still overflows) stays on the one line `rustfmt` cannot shorten.
    if params.is_empty() {
        let open = format!("{vis_prefix}{name}{generic_clause}() -> ");
        if let Some(wrapped) = wrap_return_type(&open, ret) {
            return wrapped;
        }
        return format!("{open}{ret}");
    }

    // The `pub fn NAME<GEN>(` opening line, with generics still flat.
    let params_open = format!("{vis_prefix}{name}{generic_clause}(");
    let broken_params = || {
        let mut out = String::new();
        for p in params {
            out.push_str("\n    ");
            out.push_str(p);
            out.push(',');
        }
        out.push_str("\n) -> ");
        out.push_str(ret);
        out
    };
    if params_open.len() <= MAX_WIDTH {
        return format!("{params_open}{}", broken_params());
    }

    // Both the flat and params-broken openings overflow: break the generic
    // clause too. `generic_clause` is `<T1: …, T2: …>` (or empty, but an empty
    // clause cannot overflow the opening line, so this branch is generics-only).
    let inner = generic_clause
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(generic_clause);
    let mut out = format!("{vis_prefix}{name}<");
    for g in inner.split(", ") {
        out.push_str("\n    ");
        out.push_str(g);
        out.push(',');
    }
    out.push_str("\n>(");
    out.push_str(&broken_params());
    out
}

/// Wrap a zero-parameter signature's RETURN TYPE at its outermost angle brackets when
/// the flat `open` + `ret` line overflows, matching `rustfmt`: `NAME() -> Ptr<\n
/// Inner,\n>`. Returns `None` when the return type is not a single top-level
/// angle-bracketed generic (`Ptr<…>` with the `<` after a path and the matching `>`
/// at the end) — `rustfmt` has no shorter layout for such a type, so the caller keeps
/// the flat line. The `Inner` is placed at one indent step with a trailing comma and
/// the `>` dedented to column 0, the same one-per-line break the params path uses.
pub fn wrap_return_type(open: &str, ret: &str) -> Option<String> {
    const MAX_WIDTH: usize = 100;
    const BRACE: usize = 2;
    if open.len() + ret.len() + BRACE <= MAX_WIDTH {
        return None;
    }
    // A single top-level generic: `Head<Inner>` where the first `<` opens the sole
    // bracket group and the matching `>` is the final character. A leading `Box<` /
    // `Decoder<` head with the whole remainder as one `Inner` argument.
    let lt = ret.find('<')?;
    if !ret.ends_with('>') {
        return None;
    }
    let head = &ret[..lt];
    let inner = &ret[lt + 1..ret.len() - 1];
    // The head must be a plain path (no earlier bracket / comma), and the wrapped
    // opening line `NAME() -> Head<` must itself fit; otherwise no shortening applies.
    if head.contains([',', '<', '>', '(', ')']) || open.len() + head.len() + 1 + BRACE > MAX_WIDTH {
        return None;
    }
    Some(format!("{open}{head}<\n    {inner},\n>"))
}

/// Render the CAF `CELL.get_or_init(|| body).clone()` line with the native Doc
/// path, so the closure body's braces are elided when the line fits the width —
/// matching `rustfmt`'s closure-body rule (`move |_| expr` when it fits, `move |_|
/// { … }` when it breaks). The returned string has no leading whitespace; it is
/// spliced after the `\n    ` the caller writes.
///
/// [`Doc::BraceBody`] carries the closure body's braces as SEAL-visible leaves
/// (the string emitter always writes `|| { body }`) but omits them from the render
/// when the body fits flat — matching the golden's `|| expr` form exactly. The
/// outer [`Doc::CallArgs`] tests the full `CELL.get_or_init(|| body).clone()` line
/// against `max_width` (100) and `fn_call_width` (60) before choosing flat.
pub fn emit_caf_get_or_init(
    ctx: &EmitCtx,
    body_expr: &Expr,
    generics: GenericScope,
) -> DResult<String> {
    let body_doc = crate::emit_doc::build_doc(ctx, body_expr, 1, 0, generics)?;
    // `|| BraceBody(body)` — the single closure argument. `BraceBody` renders
    // the body WITHOUT braces when it fits flat, and WITH braces on a new line
    // when it does not, matching `rustfmt`'s closure body layout.
    let closure_arg = Doc::concat(vec![Doc::text("|| "), Doc::brace_body(body_doc)]);
    // `CELL.get_or_init(closure)` — a single-argument function call whose sole
    // closure argument `rustfmt` combines onto the call head: `get_or_init(|| {`
    // on one line, the body broken inside, `})` at the call's indent, no trailing
    // comma.
    let receiver = Doc::call_args(
        Doc::text("CELL.get_or_init("),
        vec![closure_arg],
        Doc::text(")"),
        // A function-call argument list keeps a trailing comma when it breaks.
        true,
    );
    // `.clone()` glued when the receiver stays single-line, dropped onto its own
    // line at the call's indent when the receiver's closure body broke — `rustfmt`'s
    // method-chain layout after a multiline receiver.
    let call = Doc::method_chain(receiver, Doc::text(".clone()"));
    // Seeded at column 4 (fn-body indent) so the fit test measures from the
    // position where the line starts in the emitted file.
    Ok(render_seeded(&call, RenderConfig::default(), 4, 4))
}

/// Render a value body expression to the exact bytes a `rustfmt`-formatted
/// function body carries, laid out by the native [`crate::emit_doc::build_doc`] +
/// [`crate::render::render_seeded`] path instead of the flat string emitter.
///
/// The body opens at column 4 — right after the four-space prefix the caller
/// writes before `{body}` in `pub fn … {\n    {body}\n}` — and every line it
/// breaks onto nests from the fn-body block indent (4 columns). This is the same
/// framing the whole-corpus native-vs-legacy sweep proved byte-identical to
/// `emit_expr_at` + `rustfmt` for every function body in the corpus, so splicing
/// its result makes the emitted body `rustfmt`-clean by construction.
///
/// `build_doc` is threaded the fn-body context the string emitter used: block
/// indent 1, IR depth 0.
pub fn emit_body_native(
    ctx: &EmitCtx,
    body_expr: &Expr,
    generics: GenericScope,
) -> DResult<String> {
    let doc = crate::emit_doc::build_doc(ctx, body_expr, 1, 0, generics)?;
    Ok(render_seeded(&doc, RenderConfig::default(), 4, 4))
}

/// Render a function's generic clause `<T1, T2: <bounds>, ..>` — one entry per
/// quantified variable in declaration order, the position fixing its `T{i+1}`
/// name. Empty string for a monomorphic function.
///
/// `Clone` is always included: Ipê has value semantics so every type must be
/// cloneable (field reads emit `.clone()` to prevent partial-move errors). For
/// `Copy` types (`i64`, `bool`, …) the bound is trivially satisfied.
///
/// `Send + 'static` is injected only when `ret_is_task`: futures require their
/// captured values to be `Send + 'static`, but plain record/ADT-returning
/// functions have no such requirement. Adding the bounds unconditionally would
/// over-constrain callers of pure record-constructors (e.g. `wrap : a -> {
/// value : a }` must accept any `Clone` type, not only `Send + 'static` ones).
///
/// The `IpeRow` bound (for a wildcard `any` param that flows into a
/// `Db.get*` accessor) is already recorded in the relevant param's [`BoundSet`]
/// by the lowerer's structural IR walk (`ipe_lower`'s `apply_db_row_bounds` /
/// `body_calls_db_get_on_param`), so this function simply renders whatever
/// bounds each param carries.
pub fn render_fn_generics(
    ctx: &EmitCtx,
    func: &Func,
    ret_is_task: bool,
    impl_fn_params: &[usize],
    generics: GenericScope,
) -> DResult<String> {
    if func.type_params.is_empty() && impl_fn_params.is_empty() && func.row_params.is_empty() {
        return Ok(String::new());
    }

    let mut entries: Vec<String> = func
        .type_params
        .iter()
        .enumerate()
        .map(|(i, (sym, bounds))| {
            let n = i.saturating_add(1);
            // Always inject `Clone` — field reads emit `.clone()` to prevent
            // partial-move errors. `with_*` are idempotent, so folding the same
            // flag the solver already recorded is a no-op.
            let mut bounds = bounds.with_clone();
            // A task return, or a type var inside a first-class-function-value
            // PARAMETER, moves the value into a spawned / boxed
            // `Box<dyn Fn(..) -> R + Send + Sync + 'static>` consumer, so it
            // needs `Send + 'static` (`with_send` sets both). Example: a
            // generic-over-`msg` helper taking an `onEdit : String -> msg`
            // callback and forwarding it into `input_multiline_`.
            if ret_is_task || type_var_in_fn_param(func, *sym) {
                bounds = bounds.with_send();
            }
            // A type var that is the `msg` of a `Ipe.Ui` / `Ipe.Html` carrier in
            // the RETURN type needs only `'static`: such a function is a leaf
            // renderer boxed by its caller's `List.map` into a
            // `Box<dyn Fn(..) -> Element<msg> + 'static>`, and a boxed `fn` item
            // is `Send + Sync` regardless of `msg`, so `'static` alone lets the
            // coercion type-check (`with_static`, not `with_send`). Without it
            // the leaf renderer is an E0310 (`msg may not live long enough`).
            if type_var_in_ui_carrier(&func.ret, *sym) {
                bounds = bounds.with_static();
            }
            // ONE render pass: `render_bounds` orders the lifetime bound first
            // and de-duplicates, so `'static` never doubles even when the
            // lowerer's `BoundSet::STATIC` already set it.
            let clause = render_bounds(bounds, n, ctx.target);
            if clause.is_empty() {
                format!("T{n}")
            } else {
                format!("T{n}{clause}")
            }
        })
        .collect();

    // Fresh `FN{i}: Fn(P0, …) -> R + Send + Sync + 'static` generics for the
    // direct-call `Fun` params monomorphized away from `Box<dyn Fn>`. The bound
    // is the exact trait-object bound the `Box` carrier used (`render_type`'s
    // `IrType::Fun` arm), so every capture the boxed form admitted the generic
    // admits too, and forwarding the param into a runtime `Arc<dyn Fn + Send +
    // Sync>` slot still type-checks.
    for &idx in impl_fn_params {
        let Some((_, IrType::Fun(params, ret))) = func.params.get(idx) else {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::render_fn_generics",
                detail: "impl-Fn param index did not point at an IrType::Fun".to_owned(),
            });
        };
        let mut parts = Vec::with_capacity(params.len());
        for p in params {
            parts.push(render_type(ctx, p, generics)?);
        }
        let ret_s = render_type(ctx, ret, generics)?;
        entries.push(format!(
            "{}: Fn({}) -> {ret_s} + Send + Sync + 'static",
            impl_fn_generic_name(idx),
            parts.join(", ")
        ));
    }

    // Row generics: each `R{n}` is bounded by one per-field witness trait —
    // `IpeHasField<Field = FieldTy>` — plus `Clone` (field reads emit `.clone()`
    // for value semantics, §4.4). The bounds are exactly the field obligations
    // the solver already proved at every call site, so exit-0 ⇒ cargo-green.
    for (i, row) in func.row_params.iter().enumerate() {
        let n = i.saturating_add(1);
        let mut bounds: Vec<String> = Vec::with_capacity(row.fields.len() + 3);
        // A task-returning function moves its row-generic parameter into the
        // boxed continuation of its `task_and_then` tail — a
        // `Box<dyn FnOnce(..) -> Pin<Box<.. + Send>> + Send>` — so the row generic
        // needs `Send + 'static`, exactly as a task-flowing `T{n}` does above.
        // The lifetime bound must precede every trait bound (`R{n}: 'static + …`),
        // so it is pushed first. Both auto-traits hold for every concrete Ipê
        // record (owned, never borrows), so exit-0 ⇒ cargo-green is preserved.
        if ret_is_task {
            bounds.push("'static".to_owned());
            bounds.push("Send".to_owned());
        }
        for (field_sym, field_ty) in &row.fields {
            let field_name = ctx.resolve_ident(*field_sym)?;
            let trait_name = crate::naming::field_witness_trait_name(field_name);
            let assoc = crate::naming::field_witness_assoc_type_name(field_name);
            // The field type is rendered in the SAME scope as the signature, so a
            // field carrying a generic (`{ r | value : a }`) resolves its `a` to
            // the function's `T{n}`. Each field of a multi-field row contributes
            // one such witness bound; for a concrete field type this is a plain
            // scalar/struct type.
            let field_ty_s = render_type(ctx, field_ty, generics)?;
            if row.updated_fields.contains(field_sym) {
                // G2: this field is updated in the body — require the setter
                // witness (`IpeWithF`), which supertraits the getter witness
                // (`IpeHasF`). Emit the setter bound so rustc can resolve the
                // setter method at the call site. The getter bound with the
                // associated-type constraint follows unconditionally below.
                let setter_trait = crate::naming::field_setter_witness_trait_name(field_name);
                bounds.push(setter_trait);
            }
            bounds.push(format!("{trait_name}<{assoc} = {field_ty_s}>"));
        }
        bounds.push("Clone".to_owned());
        entries.push(format!("R{n}: {}", bounds.join(" + ")));
    }

    Ok(format!("<{}>", entries.join(", ")))
}

/// The fresh Rust generic name a direct-call `Fun` parameter at 0-based
/// position `idx` monomorphizes to — `FN0`, `FN1`, … . The `FN` prefix cannot
/// collide with the ordinary type variables (`T1`, `T2`, …) rendered from
/// [`Func::type_params`].
pub fn impl_fn_generic_name(idx: usize) -> String {
    format!("FN{idx}")
}

/// `true` if the type variable `sym` appears anywhere inside a
/// first-class-function-value (`IrType::Fun` / `IrType::FnOnceChain`)
/// parameter of `func`.
///
/// Such a parameter is emitted as a boxed `dyn Fn` trait object carrying a
/// `+ 'static` bound (`emit_types::render_type`), so any type variable it
/// mentions must itself be `'static`. This predicate drives the `Send +
/// 'static` bound injection in [`render_fn_generics`] for exactly those
/// variables — narrower than the blanket `ret_is_task` gate so that a pure,
/// non-callback-taking generic function keeps a bare `Clone` bound.
pub fn type_var_in_fn_param(func: &Func, sym: Symbol) -> bool {
    func.params
        .iter()
        .any(|(_, ty)| ty_mentions_var_under_fn(ty, sym, false))
}

/// `true` if the type variable `sym` is the message parameter of a `Ipe.Ui` /
/// `Ipe.Html` carrier (`Element msg`, `Attribute msg`, `Html msg`, …) anywhere
/// in the return type `ret`.
///
/// A carrier over `msg` holds event handlers as `Arc<dyn Fn(..) -> msg + Send +
/// Sync + 'static>` (`Attribute`'s `AttrEvent` / `HtmlAttribute`), so a
/// `msg`-generic function returning one is boxable into a `Box<dyn Fn(..) ->
/// Element<msg> + 'static>` slot — precisely how `List.map renderCell cells`
/// forwards a leaf renderer. Without a `msg: 'static` bound that box is an
/// E0310 (`msg may not live long enough`) even though the leaf's own body names
/// no function-typed parameter. Pinning exactly the carried `msg` var mirrors
/// the boxed-`dyn Fn` treatment and leaves pure record/ADT-returning generics
/// unconstrained.
pub fn type_var_in_ui_carrier(ret: &IrType, sym: Symbol) -> bool {
    match ret {
        IrType::Ui { msg, .. } => ty_mentions_var(msg, sym),
        IrType::Task(inner)
        | IrType::Maybe(inner)
        | IrType::List(inner)
        | IrType::Set(inner)
        | IrType::Decoder(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::WebRoute(inner) => type_var_in_ui_carrier(inner, sym),
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            type_var_in_ui_carrier(a, sym) || type_var_in_ui_carrier(b, sym)
        }
        IrType::Tuple(items) => items.iter().any(|t| type_var_in_ui_carrier(t, sym)),
        IrType::Enum { args, .. } => args.iter().any(|t| type_var_in_ui_carrier(t, sym)),
        IrType::Record(fields) => fields.values().any(|t| type_var_in_ui_carrier(t, sym)),
        _ => false,
    }
}

/// `true` if `IrType::Generic(sym)` occurs anywhere in `ty` — the carrier's
/// message argument may itself be a nested structure (`List msg`, `(msg, a)`),
/// so the whole sub-tree is scanned.
pub fn ty_mentions_var(ty: &IrType, sym: Symbol) -> bool {
    match ty {
        IrType::Generic(s) => *s == sym,
        IrType::Ui { msg, .. } => ty_mentions_var(msg, sym),
        IrType::Task(inner)
        | IrType::Maybe(inner)
        | IrType::List(inner)
        | IrType::Set(inner)
        | IrType::Decoder(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::WebRoute(inner) => ty_mentions_var(inner, sym),
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            params.iter().any(|p| ty_mentions_var(p, sym)) || ty_mentions_var(ret, sym)
        }
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            ty_mentions_var(a, sym) || ty_mentions_var(b, sym)
        }
        IrType::Tuple(items) => items.iter().any(|t| ty_mentions_var(t, sym)),
        IrType::Enum { args, .. } => args.iter().any(|t| ty_mentions_var(t, sym)),
        IrType::Record(fields) => fields.values().any(|t| ty_mentions_var(t, sym)),
        _ => false,
    }
}

/// Walk `ty`, returning `true` if `IrType::Generic(sym)` occurs while `under_fn`
/// is set (i.e. inside a `Fun` / `FnOnceChain` sub-tree). Once a function-typed
/// node is entered, `under_fn` stays set for the whole sub-tree — the entire
/// boxed trait object is `'static`, so every variable it names needs the bound.
pub fn ty_mentions_var_under_fn(ty: &IrType, sym: Symbol, under_fn: bool) -> bool {
    match ty {
        IrType::Generic(s) => under_fn && *s == sym,
        // `SharedFun` shares `Fun`'s `+ 'static` boxed/`Arc` carrier, so entering
        // it pins every type it names to `'static` just as `Fun` does.
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            params
                .iter()
                .any(|p| ty_mentions_var_under_fn(p, sym, true))
                || ty_mentions_var_under_fn(ret, sym, true)
        }
        IrType::Task(inner)
        | IrType::Maybe(inner)
        | IrType::List(inner)
        | IrType::Set(inner)
        | IrType::Decoder(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::WebRoute(inner) => ty_mentions_var_under_fn(inner, sym, under_fn),
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            ty_mentions_var_under_fn(a, sym, under_fn) || ty_mentions_var_under_fn(b, sym, under_fn)
        }
        IrType::Tuple(items) => items
            .iter()
            .any(|t| ty_mentions_var_under_fn(t, sym, under_fn)),
        IrType::Enum { args, .. } => args
            .iter()
            .any(|t| ty_mentions_var_under_fn(t, sym, under_fn)),
        IrType::Record(fields) => fields
            .values()
            .any(|t| ty_mentions_var_under_fn(t, sym, under_fn)),
        _ => false,
    }
}
