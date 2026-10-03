use super::{
    BinOp, Callee, DResult, Diagnostic, Expr, GenericScope, Symbol, emit_expr_at, kernel_name,
};
use crate::EmitCtx;

/// A `BinOp` with a single Rust infix spelling: an operator the backend
/// emits literally between its two operands.
///
/// `Add`/`Sub`/`Mul` (polymorphic `Number a`), `IntAdd`/`IntSub`/`IntMul`,
/// `IntDiv` and `Append` route through a helper or `format!` instead (see
/// [`infix`]), so they have no variant here and no spelling to call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InfixOp {
    FloatAdd,
    FloatSub,
    FloatMul,
    Div,
    Eq,
    Neq,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
}

impl InfixOp {
    /// The Rust spelling this operator emits literally between its operands.
    pub const fn spelling(self) -> &'static str {
        match self {
            Self::FloatAdd => "+",
            Self::FloatSub => "-",
            Self::FloatMul => "*",
            Self::Div => "/",
            Self::Eq => "==",
            Self::Neq => "!=",
            Self::Lt => "<",
            Self::Gt => ">",
            Self::Le => "<=",
            Self::Ge => ">=",
            Self::And => "&&",
            Self::Or => "||",
        }
    }
}

/// Classifies a `BinOp` by whether it has a single Rust infix spelling.
///
/// The single source of truth for which operators are infix-shaped, shared by
/// the string emitter ([`crate::emit_expr::expr`]'s `emit_expr_at`) and the
/// `Doc` emitter (`emit_doc`'s `build_doc`/`build_binop_chain`): both go
/// through this function instead of keeping their own copy of the operator
/// list, so the two paths cannot drift. Every `BinOp` variant is listed so
/// adding one without wiring it here is a compile error, not a silent gap.
/// The call-shaped operators (`Add`/`Sub`/`Mul`/`IntAdd`/`IntSub`/`IntMul`/
/// `IntDiv`/`Append`) route through a helper or `format!` before reaching any
/// infix path; they have no infix spelling, so `None` has no sentinel string
/// to fall back on — a caller that reaches `None` on a path that assumed
/// `Some` has a real bug, not a routing accident.
pub const fn infix(op: BinOp) -> Option<InfixOp> {
    match op {
        BinOp::FloatAdd => Some(InfixOp::FloatAdd),
        BinOp::FloatSub => Some(InfixOp::FloatSub),
        BinOp::FloatMul => Some(InfixOp::FloatMul),
        BinOp::Div => Some(InfixOp::Div),
        BinOp::Eq => Some(InfixOp::Eq),
        BinOp::Neq => Some(InfixOp::Neq),
        BinOp::Lt => Some(InfixOp::Lt),
        BinOp::Gt => Some(InfixOp::Gt),
        BinOp::Le => Some(InfixOp::Le),
        BinOp::Ge => Some(InfixOp::Ge),
        BinOp::And => Some(InfixOp::And),
        BinOp::Or => Some(InfixOp::Or),
        BinOp::Add
        | BinOp::Sub
        | BinOp::Mul
        | BinOp::IntAdd
        | BinOp::IntSub
        | BinOp::IntMul
        | BinOp::IntDiv
        | BinOp::Append => None,
    }
}

/// Resolve an FFI wrapper symbol to its fully-qualified `crate::ffi::<name>`
/// path, rejecting any resolved string that is not a legal Rust identifier.
///
/// Both [`callee_name`] (for direct FFI calls) and [`emit_ffi_glued_call`]
/// (for transparent-conversion calls) splice the wrapper name into emitted
/// Rust source via `crate::ffi::{name}`.  A shared validation point ensures
/// neither site can silently emit an illegal identifier regardless of how the
/// symbol was originally interned.
///
/// An illegal name is a compiler invariant failure (the lowerer must have
/// admitted a bad wrapper ident), so this returns [`Diagnostic::CompilerBug`]
/// rather than a user-facing error.
pub fn ffi_path(ctx: &EmitCtx, sym: Symbol) -> DResult<String> {
    let name = ctx.resolve_ident(sym)?;
    let mut chars = name.chars();
    let head_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    if head_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(format!("crate::ffi::{name}"))
    } else {
        Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::ffi_path",
            detail: format!(
                "FFI wrapper ident {name:?} is not a legal Rust identifier; \
                 it must contain only ascii alphanumeric characters and \
                 underscores, starting with a letter or underscore"
            ),
        })
    }
}

/// The Rust name of a call target.
pub fn callee_name(ctx: &EmitCtx, callee: &Callee) -> DResult<String> {
    match callee {
        // Absolute `crate::` path so the call ALWAYS binds to the top-level
        // `fn`, never to a local `let` binder of the same folded name. A local
        // cannot shadow an absolute path, so a local spelled like a top-level
        // fn's Rust name (`let main_update = …` vs `fn main_update`) can no
        // longer intercept the call — closing the E0618 / silent-wrong-call
        // shadow class for every name at once. The `ipe_main` entry point and
        // FFI wrappers are already crate-root, so this is uniform.
        Callee::Func(id) => Ok(format!("crate::{}", ctx.func_name(*id)?)),
        // An intercept-only `Store.*` placeholder has no runtime function; its
        // name is never defined, so naming it would emit Rust `cargo` rejects
        // (E0425). Lowering refuses every such call (IPE-L0146); reaching here
        // means that gate was bypassed, a compiler invariant failure.
        Callee::Kernel(k) if k.is_accessor_intercept_placeholder() => {
            Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::callee_name",
                detail: format!(
                    "intercept-only kernel {k:?} reached emission; it has no runtime \
                     function and must be rewritten or refused at lowering"
                ),
            })
        }
        Callee::Kernel(k) => Ok(kernel_name(*k).to_owned()),
        // A foreign wrapper lives in the emitted `src/ffi.rs` module. The
        // shared `ffi_path` helper validates the identifier and constructs the
        // absolute path — an illegal name is a compiler invariant failure.
        Callee::Ffi { ident, .. } => ffi_path(ctx, *ident),
    }
}

/// Does this call target an FFI wrapper with transparent conversion glue?
/// The doc builder keeps such calls as byte-carried leaves so the string
/// emitter's glued rendering is the single source of the emitted text.
pub fn ffi_call_has_glue(ctx: &EmitCtx, callee: &Callee) -> DResult<bool> {
    if let Callee::Ffi { ident, .. } = callee {
        Ok(ctx.ffi_wrapper_glue(*ident)?.is_some())
    } else {
        Ok(false)
    }
}

/// Emit a [`Callee::Ffi`] call through its transparent conversion glue.
///
/// Marked arguments convert Ipê→foreign inline; a glued result converts
/// foreign→Ipê around the call — under the `IpeResult` Ok arm for a fallible
/// wrapper, or over the bare value for an infallible accessor. Unmarked
/// positions render exactly as the generic tail would.
pub fn emit_ffi_glued_call(
    ctx: &EmitCtx,
    wrapper: Symbol,
    glue: &crate::FfiWrapperGlue,
    args: &[Expr],
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<String> {
    let name = ffi_path(ctx, wrapper)?;
    let mut parts = Vec::with_capacity(args.len());
    for (i, arg) in args.iter().enumerate() {
        let rendered = emit_expr_at(ctx, arg, indent, depth, generics)?;
        match glue.params.get(i).and_then(Option::as_ref) {
            None => parts.push(rendered),
            Some(t) => parts.push(ffi_to_foreign(ctx, t, &rendered)?),
        }
    }
    let call = format!("{name}({})", parts.join(", "));
    let Some(result) = &glue.result else {
        return Ok(call);
    };
    let conv = ffi_from_foreign(ctx, &result.ty, "__ipe_ffi_v")?;
    if result.in_result {
        Ok(format!(
            "match {call} {{ IpeResult::Ok(__ipe_ffi_v) => IpeResult::Ok({conv}), \
             IpeResult::Err(__ipe_ffi_e) => IpeResult::Err(__ipe_ffi_e) }}"
        ))
    } else {
        Ok(format!("{{ let __ipe_ffi_v = {call}; {conv} }}"))
    }
}

/// Render the Ipê→foreign conversion of `value` (a rendered expression) for
/// one transparent type: a record moves field-for-field into the foreign
/// struct literal; a union matches the app enum into the foreign enum.
pub fn ffi_to_foreign(ctx: &EmitCtx, ty: &crate::FfiGlueType, value: &str) -> DResult<String> {
    match ty {
        crate::FfiGlueType::Record { rust_path, fields } => {
            let moves: Vec<String> = fields
                .iter()
                .map(|f| format!("{f}: __ipe_ffi_r.{f}"))
                .collect();
            Ok(format!(
                "{{ let __ipe_ffi_r = {value}; {rust_path} {{ {} }} }}",
                moves.join(", ")
            ))
        }
        crate::FfiGlueType::Union {
            module,
            name,
            rust_path,
            variants,
        } => {
            let app = ffi_union_app_name(ctx, module, name)?;
            let arms: Vec<String> = variants
                .iter()
                .map(|v| ffi_union_arm(&app, rust_path, v, Direction::ToForeign))
                .collect();
            Ok(format!("match ({value}) {{ {} }}", arms.join(", ")))
        }
    }
}

/// Render the foreign→Ipê conversion of the bound variable `value` for one
/// transparent type: a struct moves field-for-field into the synthesised
/// record struct; an enum matches the foreign enum into the app enum.
pub fn ffi_from_foreign(ctx: &EmitCtx, ty: &crate::FfiGlueType, value: &str) -> DResult<String> {
    match ty {
        crate::FfiGlueType::Record { fields, .. } => {
            // An FFI glue record has a foreign-type-unique field-name set, so
            // field-name resolution is unambiguous — no shape is threaded.
            let rec = ctx.record_name_for_literal(fields, None)?;
            let moves: Vec<String> = fields.iter().map(|f| format!("{f}: {value}.{f}")).collect();
            Ok(format!("{rec} {{ {} }}", moves.join(", ")))
        }
        crate::FfiGlueType::Union {
            module,
            name,
            rust_path,
            variants,
        } => {
            let app = ffi_union_app_name(ctx, module, name)?;
            let arms: Vec<String> = variants
                .iter()
                .map(|v| ffi_union_arm(&app, rust_path, v, Direction::FromForeign))
                .collect();
            Ok(format!("match {value} {{ {} }}", arms.join(", ")))
        }
    }
}

/// Which way a transparent-union match arm converts.
#[derive(Clone, Copy)]
pub enum Direction {
    ToForeign,
    FromForeign,
}

/// One `match` arm converting a transparent enum variant between the app
/// enum (always tuple-shaped — the positional Ipê constructor surface) and
/// the foreign enum (its declared unit/tuple/struct shape).
pub fn ffi_union_arm(
    app: &str,
    rust_path: &str,
    v: &crate::FfiGlueVariant,
    direction: Direction,
) -> String {
    let vn = &v.name;
    let binders: Vec<String> = match &v.payload {
        crate::FfiGluePayload::Unit => Vec::new(),
        crate::FfiGluePayload::Tuple(n) => (0..*n).map(|i| format!("__ipe_ffi_p{i}")).collect(),
        crate::FfiGluePayload::Struct(members) => (0..members.len())
            .map(|i| format!("__ipe_ffi_p{i}"))
            .collect(),
    };
    // The app side is positional; the foreign side re-attaches struct-variant
    // member names.
    let app_side = if binders.is_empty() {
        format!("{app}::{vn}")
    } else {
        format!("{app}::{vn}({})", binders.join(", "))
    };
    let foreign_side = match &v.payload {
        crate::FfiGluePayload::Unit => format!("{rust_path}::{vn}"),
        crate::FfiGluePayload::Tuple(_) => format!("{rust_path}::{vn}({})", binders.join(", ")),
        crate::FfiGluePayload::Struct(members) => {
            let named: Vec<String> = members
                .iter()
                .zip(&binders)
                .map(|(m, b)| format!("{m}: {b}"))
                .collect();
            format!("{rust_path}::{vn} {{ {} }}", named.join(", "))
        }
    };
    match direction {
        Direction::ToForeign => format!("{app_side} => {foreign_side}"),
        Direction::FromForeign => format!("{foreign_side} => {app_side}"),
    }
}

/// The app-side Rust enum name for a transparent union, resolved through the
/// registered `EnumDef` exactly as every other reference to it.
pub fn ffi_union_app_name(ctx: &EmitCtx, module: &[String], name: &str) -> DResult<String> {
    let mut segs = Vec::with_capacity(module.len());
    for m in module {
        segs.push(ctx.lookup_symbol(m)?);
    }
    let name_sym = ctx.lookup_symbol(name)?;
    Ok(ctx.enum_name(&ipe_ir::ModPath(segs), name_sym)?.to_owned())
}

#[cfg(test)]
mod infix_tests {
    use super::{BinOp, InfixOp, infix};

    const ALL: [InfixOp; 12] = [
        InfixOp::FloatAdd,
        InfixOp::FloatSub,
        InfixOp::FloatMul,
        InfixOp::Div,
        InfixOp::Eq,
        InfixOp::Neq,
        InfixOp::Lt,
        InfixOp::Gt,
        InfixOp::Le,
        InfixOp::Ge,
        InfixOp::And,
        InfixOp::Or,
    ];

    /// Every `InfixOp` spelling is a literal Rust operator token: non-empty,
    /// and never opens a line or block comment or reads as a call. This is
    /// the property that made the old `op_str`/`chain_op_str` sentinels
    /// (`"//"` for `IntDiv`, `unwrap_or("")` for a call-shaped op) unsound —
    /// `InfixOp` has no variant that could stand for a call-shaped `BinOp`,
    /// so no spelling here can be one of those sentinels.
    #[test]
    fn infix_spelling_never_comment_or_call() {
        for op in ALL {
            let s = op.spelling();
            assert!(!s.is_empty(), "{op:?} spelling is empty");
            assert!(
                !s.contains("//"),
                "{op:?} spelling {s:?} opens a line comment"
            );
            assert!(
                !s.contains("/*"),
                "{op:?} spelling {s:?} opens a block comment"
            );
            assert!(!s.contains('('), "{op:?} spelling {s:?} reads as a call");
        }
    }

    /// `infix` returns `None` for exactly the 8 call-shaped `BinOp` variants
    /// (no single Rust infix spelling) and `Some` for every other variant —
    /// the classification both emitters share.
    #[test]
    fn call_shaped_ops_have_no_infix() {
        let call_shaped = [
            BinOp::Add,
            BinOp::Sub,
            BinOp::Mul,
            BinOp::IntAdd,
            BinOp::IntSub,
            BinOp::IntMul,
            BinOp::IntDiv,
            BinOp::Append,
        ];
        for op in call_shaped {
            assert!(
                infix(op).is_none(),
                "{op:?} unexpectedly has an infix spelling"
            );
        }

        let infix_shaped = [
            BinOp::FloatAdd,
            BinOp::FloatSub,
            BinOp::FloatMul,
            BinOp::Div,
            BinOp::Eq,
            BinOp::Neq,
            BinOp::Lt,
            BinOp::Gt,
            BinOp::Le,
            BinOp::Ge,
            BinOp::And,
            BinOp::Or,
        ];
        for op in infix_shaped {
            assert!(
                infix(op).is_some(),
                "{op:?} unexpectedly has no infix spelling"
            );
        }
    }
}
