// Cmd-wiring composition is also exercised in [`crate::emit_web`]'s
// `hot_appearance_tests` and its vocabulary in [`crate::transition_classify`]'s
// `tests`; the units here pin the thunk's capture and the closure-body disarm.

use super::{
    AdaptedHandler, Arm, BoxedSub, Callee, DResult, Expr, GenericScope, IrType, KernelFn, Match,
    ModPath, Pat,
};
use crate::{EmitCtx, RustBackend};
use ipe_diagnostics::Diagnostic;
use ipe_intern::{Interner, Symbol};
use ipe_ir::once_closure::MovedCapture;
use ipe_ir::{CallPin, OnFormKind, Program, SharedAlts, SliceOwnership};

#[test]
fn every_pattern_shape_has_one_boxed_field_class() -> DResult<()> {
    let mut interner = Interner::new();
    let x = interner.intern("x")?;
    let node = interner.intern("Node")?;
    let left = interner.intern("left")?;
    let var = Pat::Var(x);
    let pair = Pat::Tuple(vec![Pat::Var(x), Pat::Wildcard]);
    let record = Pat::Record(vec![(left, Pat::Var(x))]);
    let alias = Pat::Alias(Box::new(Pat::Wildcard), x);
    let blank_pair = Pat::Tuple(vec![Pat::Wildcard, Pat::Wildcard]);
    assert_eq!(BoxedSub::of(&Pat::Wildcard), BoxedSub::Ignore);
    assert_eq!(BoxedSub::of(&blank_pair), BoxedSub::Ignore);
    assert_eq!(BoxedSub::of(&var), BoxedSub::Bind(x));
    assert_eq!(BoxedSub::of(&pair), BoxedSub::Destructure(&pair));
    assert_eq!(BoxedSub::of(&record), BoxedSub::Destructure(&record));
    assert_eq!(BoxedSub::of(&alias), BoxedSub::Destructure(&alias));
    let literal_alts =
        SharedAlts::new(vec![Pat::Int(0), Pat::Int(1)]).ok_or_else(|| Diagnostic::CompilerBug {
            where_: "emit_expr::tests",
            detail: "two Int alternatives are a valid SharedAlts".to_owned(),
        })?;
    let dispatching = [
        Pat::Ctor {
            home: ModPath(Vec::new()),
            ty: node,
            variant: node,
            args: Vec::new(),
        },
        Pat::Slice {
            prefix: Vec::new(),
            rest: None,
            own: SliceOwnership::BorrowClone,
            elem: IrType::Int,
        },
        Pat::Int(0),
        Pat::Bool(true),
        Pat::Char("c".to_owned()),
        Pat::Str("s".to_owned()),
        Pat::Or(literal_alts),
    ];
    for pat in &dispatching {
        assert_eq!(BoxedSub::of(pat), BoxedSub::Dispatch, "{pat:?}");
    }
    Ok(())
}

#[test]
fn a_test_nested_in_a_boxed_destructure_dispatches() -> DResult<()> {
    let mut interner = Interner::new();
    let x = interner.intern("x")?;
    let whole = interner.intern("whole")?;
    let done = interner.intern("Done")?;
    let left = interner.intern("left")?;
    let nested_ctor = Pat::Tuple(vec![
        Pat::Ctor {
            home: ModPath(Vec::new()),
            ty: done,
            variant: done,
            args: Vec::new(),
        },
        Pat::Var(x),
    ]);
    let nested_literal = Pat::Tuple(vec![Pat::Var(x), Pat::Int(0)]);
    let alias_over_literal = Pat::Alias(Box::new(Pat::Int(0)), whole);
    let record_with_alias = Pat::Record(vec![(left, Pat::Alias(Box::new(Pat::Wildcard), whole))]);
    for pat in [
        &nested_ctor,
        &nested_literal,
        &alias_over_literal,
        &record_with_alias,
    ] {
        assert_eq!(BoxedSub::of(pat), BoxedSub::Dispatch, "{pat:?}");
    }
    let alias_over_pair = Pat::Alias(
        Box::new(Pat::Tuple(vec![Pat::Var(x), Pat::Wildcard])),
        whole,
    );
    assert_eq!(
        BoxedSub::of(&alias_over_pair),
        BoxedSub::Destructure(&alias_over_pair)
    );
    Ok(())
}

/// An adapted slot is read only in handler normal form: `let`s around one closure literal.
#[test]
fn an_adapted_slot_outside_handler_normal_form_is_a_compiler_bug() -> DResult<()> {
    let mut interner = Interner::new();
    let f = interner.intern("f")?;
    let key = interner.intern("key")?;
    let t = interner.intern("t")?;
    let params = vec![(key, IrType::Str)];
    let lambda = Expr::Lambda {
        params: params.clone(),
        ret: IrType::Unit,
        body: Box::new(Expr::Unit),
    };
    let let_wrapped = Expr::Let {
        name: t,
        value: Box::new(Expr::Var(f)),
        body: Box::new(lambda.clone()),
    };
    assert!(AdaptedHandler::from_ir(&lambda, "emit_expr::tests").is_ok());
    assert!(AdaptedHandler::from_ir(&let_wrapped, "emit_expr::tests").is_ok());
    let once = Expr::Let {
        name: t,
        value: Box::new(Expr::Var(f)),
        body: Box::new(Expr::OnceLambda {
            params,
            ret: IrType::Unit,
            body: Box::new(Expr::Var(t)),
            capture: MovedCapture {
                name: t,
                lo: 0,
                hi: 1,
            },
        }),
    };
    let variable_core = Expr::Let {
        name: t,
        value: Box::new(Expr::Unit),
        body: Box::new(Expr::Var(f)),
    };
    for slot in [&Expr::Var(f), &Expr::Unit, &variable_core, &once] {
        assert!(
            matches!(
                AdaptedHandler::from_ir(slot, "emit_expr::tests"),
                Err(Diagnostic::CompilerBug { .. })
            ),
            "{slot:?} is not in handler normal form"
        );
    }
    Ok(())
}

/// A program with no modules: enough context for emitting a closed expression.
fn empty_program() -> Program {
    Program {
        modules: vec![],
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
    }
}

/// `Cmd.perform t f` over the locals `t` and `f`.
fn cmd_perform(t: Symbol, f: Symbol) -> Expr {
    Expr::Call {
        callee: Callee::Kernel(KernelFn::CmdPerform),
        args: vec![Expr::Var(t), Expr::Var(f)],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    }
}

/// `case msg of 0 -> (m, Cmd.perform t f); _ -> (m, Cmd.perform t f)`.
fn perform_case(msg: Symbol, m: Symbol, t: Symbol, f: Symbol) -> DResult<Expr> {
    let arm = |pat| Arm {
        pat,
        body: Expr::Tuple(vec![Expr::Var(m), cmd_perform(t, f)]),
        guard: None,
    };
    Ok(Expr::Match(Match::new_flat(
        Expr::Var(msg),
        vec![arm(Pat::Int(0)), arm(Pat::Wildcard)],
    )?))
}

/// Emit `expr` on the string path and the Doc path with the `update` rewrite
/// armed on `m`.
fn emit_armed(ctx: &EmitCtx, m: Symbol, expr: &Expr) -> DResult<(String, String)> {
    let saved = ctx.begin_transition_update(Some(m));
    let generics = GenericScope::new(&[]);
    let string = super::emit_expr_at(ctx, expr, 1, 0, generics);
    let doc = crate::emit_doc::build_doc(ctx, expr, 1, 0, generics);
    ctx.end_transition_update(saved);
    let doc = crate::render::render(&doc?, crate::render::RenderConfig::default());
    Ok((string?, doc))
}

/// The wired thunk captures only the fresh effect binding, built before it.
#[test]
fn cmd_wiring_effect_binds_before_its_thunk() -> DResult<()> {
    let mut interner = Interner::new();
    let [m, t, f] = [
        interner.intern("m")?,
        interner.intern("t")?,
        interner.intern("f")?,
    ];
    let backend = RustBackend::new(&interner).with_hot_appearance(true);
    let program = empty_program();
    let ctx = backend.emit_ctx_for_tests(&program)?;
    let saved = ctx.begin_transition_update(Some(m));
    let body = Expr::Tuple(vec![Expr::Var(m), cmd_perform(t, f)]);
    let wired = super::emit_cmd_wiring_arm(&ctx, &body, 1, 0, GenericScope::new(&[]));
    ctx.end_transition_update(saved);
    let out = wired?.ok_or_else(|| Diagnostic::CompilerBug {
        where_: "emit_expr::tests",
        detail: "a literal `Cmd.perform` arm is wired under an armed `update`".to_owned(),
    })?;
    let bind = out.find("let __ipe_eff = ");
    let thunk = out.find("Box::new(move || __ipe_eff) }");
    assert!(
        matches!((bind, thunk), (Some(bind_at), Some(head_at)) if bind_at < head_at),
        "the effect is bound before its thunk, got:\n{out}"
    );
    assert_eq!(
        out.matches("move ||").count(),
        1,
        "one thunk head, got:\n{out}"
    );
    assert!(
        out.split_once("move ||")
            .is_some_and(|(_, after)| after.starts_with(" __ipe_eff)")),
        "the thunk body names only `__ipe_eff`, got:\n{out}"
    );
    Ok(())
}

/// A `case` inside a lambda in an armed `update` is compiled as written on both
/// emit paths, while the same `case` at the top of the body is wired.
#[test]
fn nested_lambda_arm_is_not_wired() -> DResult<()> {
    let mut interner = Interner::new();
    let [m, t, f, msg] = [
        interner.intern("m")?,
        interner.intern("t")?,
        interner.intern("f")?,
        interner.intern("msg")?,
    ];
    let backend = RustBackend::new(&interner).with_hot_appearance(true);
    let program = empty_program();
    let ctx = backend.emit_ctx_for_tests(&program)?;
    let case = perform_case(msg, m, t, f)?;
    let lambda = Expr::Lambda {
        params: vec![(msg, IrType::Int)],
        ret: IrType::Tuple(vec![IrType::Int, IrType::Cmd(Box::new(IrType::Int))]),
        body: Box::new(case.clone()),
    };
    let (top_string, top_doc) = emit_armed(&ctx, m, &case)?;
    assert!(
        top_string.contains("fire_cmd_wiring") && top_doc.contains("fire_cmd_wiring"),
        "the top `case` of an armed `update` is wired, got:\n{top_string}\n{top_doc}"
    );
    let (nested_string, nested_doc) = emit_armed(&ctx, m, &lambda)?;
    assert!(
        !nested_string.contains("fire_cmd_wiring") && !nested_doc.contains("fire_cmd_wiring"),
        "a `case` inside a lambda is not an overlay arm, got:\n{nested_string}\n{nested_doc}"
    );
    assert_eq!(
        ctx.transition_model_param(),
        None,
        "the arming is restored after the closure body"
    );
    Ok(())
}

/// With `hot_appearance` off nothing is armed, so the lambda emits the same text
/// whether or not the caller tried to arm the rewrite.
#[test]
fn flag_off_nested_lambda_emit_is_unchanged() -> DResult<()> {
    let mut interner = Interner::new();
    let [m, t, f, msg] = [
        interner.intern("m")?,
        interner.intern("t")?,
        interner.intern("f")?,
        interner.intern("msg")?,
    ];
    let backend = RustBackend::new(&interner).with_hot_appearance(false);
    let program = empty_program();
    let ctx = backend.emit_ctx_for_tests(&program)?;
    let lambda = Expr::Lambda {
        params: vec![(msg, IrType::Int)],
        ret: IrType::Tuple(vec![IrType::Int, IrType::Cmd(Box::new(IrType::Int))]),
        body: Box::new(perform_case(msg, m, t, f)?),
    };
    let generics = GenericScope::new(&[]);
    let plain = super::emit_expr_at(&ctx, &lambda, 1, 0, generics)?;
    let body = Expr::Tuple(vec![Expr::Var(m), cmd_perform(t, f)]);
    assert!(
        super::emit_cmd_wiring_arm(&ctx, &body, 1, 0, generics)?.is_none(),
        "flag off: no arm is wired"
    );
    assert!(
        !plain.contains("fire_cmd_wiring") && !plain.contains("__ipe_eff"),
        "flag off: the lambda emits the plain `case`, got:\n{plain}"
    );
    Ok(())
}
