use super::{Expr, Func, IrType, MAX_IR_RENDER_DEPTH, Symbol, wants_arc_ctor};

pub use ipe_ir::free_vars::{collect_free_vars, free_vars};
pub use ipe_ir::let_inline::inlined_let_body;
use ipe_ir::let_inline::pat_binds_target;
pub use ipe_ir::seq_clone::clone_targets_in_expr;

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

/// Is `ty` a Rust type that is UNCONDITIONALLY `Copy` in every emission this
/// backend produces? Mirrors `ipe_lower::lower::clone_class`'s `CopyLeaf`
/// classification exactly.
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

/// Does `sym` — a function-typed binder — appear anywhere in `body` in a
/// VALUE position (stored in data, passed as an argument, returned bare,
/// captured by a closure), as opposed to only ever being the callee of a
/// direct application `sym x`? A callee-only symbol can carry a monomorphized
/// generic (`impl Fn`) carrier instead of the erased `Box<dyn Fn>`; any value
/// use pins it to the concrete boxed type at that position, so the answer
/// gates the direct-position monomorphization.
///
/// Local twin of `ipe_lower::count_fn_value_uses` (`> 0` ⟺ a value use exists),
/// kept in this crate because `ipe_backend_rust` does not depend on
/// `ipe_lower` (IR flows one way: lower produces it, backends consume it).
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
