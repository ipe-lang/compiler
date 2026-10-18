//! TCO emission goldens: a `TailLoop` body emits `let mut`-shadowed
//! params + `loop { … }` with temporaries-first `continue` jumps; an ordinary
//! (non-`TailLoop`) recursive body emits ordinary recursion, no loop.

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    BinOp, CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind,
    Program,
};

const COUNT_ID: FuncId = FuncId::from_raw(0);
const MAIN_ID: FuncId = FuncId::from_raw(1);

fn missing(detail: &str) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "tail_call test",
        detail: detail.to_owned(),
    }
}

/// Build the emitted `src/main.rs` for a program whose `count` function has a
/// tail-recursive body — as a `TailLoop` when `tco` is true (post-rewrite shape),
/// or an ordinary `If` with a self-`Call` when false (the un-rewritten shape).
// A single cohesive IR fixture builder: constructing the two full `Program`s
// inline is inherently long; splitting it would scatter one fixture.
#[allow(clippy::too_many_lines)]
fn emit_count_main_rs(tco: bool) -> DResult<String> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let count = interner.intern("count")?;
    let main = interner.intern("main")?;
    let n = interner.intern("n")?;
    let acc = interner.intern("acc")?;

    let params: Vec<(Symbol, IrType)> = vec![(n, IrType::Int), (acc, IrType::Int)];

    // The two next-iteration argument expressions: `n - 1`, `acc + 1`.
    let next_n = Expr::BinOp {
        op: BinOp::IntSub,
        lhs: Box::new(Expr::Var(n)),
        rhs: Box::new(Expr::Int(1)),
    };
    let next_acc = Expr::BinOp {
        op: BinOp::IntAdd,
        lhs: Box::new(Expr::Var(acc)),
        rhs: Box::new(Expr::Int(1)),
    };
    let cond = Expr::BinOp {
        op: BinOp::Eq,
        lhs: Box::new(Expr::Var(n)),
        rhs: Box::new(Expr::Int(0)),
    };

    let count_body = if tco {
        Expr::TailLoop {
            params: params.clone(),
            body: Box::new(Expr::If {
                cond: Box::new(cond),
                then_: Box::new(Expr::Var(acc)),
                else_: Box::new(Expr::TailRecur {
                    args: vec![next_n, next_acc],
                }),
            }),
        }
    } else {
        Expr::If {
            cond: Box::new(cond),
            then_: Box::new(Expr::Var(acc)),
            else_: Box::new(Expr::Call {
                callee: Callee::Func(COUNT_ID),
                args: vec![next_n, next_acc],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            }),
        }
    };

    let count_fn = Func {
        id: COUNT_ID,
        name: count,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: params
            .into_iter()
            .map(|(sym, ty)| ipe_ir::Param::owned(sym, ty))
            .collect(),
        ret: IrType::Int,
        body: count_body,
    };

    // main = Io.println (String.fromInt (count 5 0))
    let main_fn = Func {
        id: MAIN_ID,
        name: main,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: Expr::Call {
            callee: Callee::Kernel(KernelFn::IoPrintln),
            args: vec![Expr::Call {
                callee: Callee::Kernel(KernelFn::StringFromInt),
                args: vec![Expr::Call {
                    callee: Callee::Func(COUNT_ID),
                    args: vec![Expr::Int(5), Expr::Int(0)],
                    pin: CallPin::None,
                    on_form: OnFormKind::NotForm,
                }],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    };

    let program = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![count_fn, main_fn],
            entry: Some(MAIN_ID),
            records: vec![],
            uses_tea: false,
            uses_server: false,
            uses_http: false,
            uses_config: false,
            uses_compression: false,
            uses_csv: false,
            uses_cache: false,
            uses_encoding: false,
            uses_regex: false,
            uses_uuid: false,
            uses_random: false,
            uses_log: false,
            uses_decimal: false,
            uses_char_category: false,
            uses_crypto_core: false,
            uses_secret: false,
            uses_json: false,
            uses_crypto: false,
            uses_jwt: false,
            uses_url: false,
            uses_ui: false,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: false,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_email: false,
            uses_locale: false,
            uses_time: false,
            uses_env_public: false,
            uses_debug: false,
            uses_ffi: false,
            uses_async_runtime: false,
        }],
    };

    let backend = RustBackend::new(&interner);
    let emitted = backend.emit(&program)?;
    emitted
        .files
        .get("src/main.rs")
        .cloned()
        .ok_or_else(|| missing("no src/main.rs emitted"))
}

/// Slice out one `pub fn <sig>…` definition up to the next `pub fn ` so an
/// assertion about the count FUNCTION's body isn't confused by `main`'s call to
/// it. Returns `""` when the signature is absent (the caller asserts on the
/// slice, so a missing fn surfaces as a failed `contains`).
fn slice_fn<'a>(src: &'a str, sig: &str) -> &'a str {
    let Some(start) = src.find(sig) else {
        return "";
    };
    let after = src.get(start + sig.len()..).unwrap_or("");
    let end = after
        .find("\npub fn ")
        .map_or(src.len(), |e| start + sig.len() + e);
    src.get(start..end).unwrap_or("")
}

/// The BODY of a sliced function, excluding its signature line (which naturally
/// contains the fn name and would confuse a "self-call leaked?" check).
fn body_of(fn_src: &str) -> &str {
    fn_src.split_once('\n').map_or("", |x| x.1)
}

#[test]
fn tco_emits_loop_continue_and_mut_shadows() -> DResult<()> {
    let src = emit_count_main_rs(true)?;
    let count_src = slice_fn(&src, "pub fn main_count");
    assert!(count_src.contains("loop {"), "no loop:\n{count_src}");
    assert!(count_src.contains("continue;"), "no continue:\n{count_src}");
    assert!(
        count_src.contains("let mut n = n;"),
        "no mut shadow n:\n{count_src}"
    );
    assert!(
        count_src.contains("let mut acc = acc;"),
        "no mut shadow acc:\n{count_src}"
    );
    // Temporaries-first jump.
    assert!(count_src.contains("__tco_0"), "no jump temp:\n{count_src}");
    // No self-recursive call survives in the BODY (the signature line naturally
    // contains `main_count(`, so exclude it).
    assert!(
        !body_of(count_src).contains("main_count("),
        "self-call leaked into the TCO'd body:\n{count_src}"
    );
    Ok(())
}

#[test]
fn non_tail_body_is_untouched() -> DResult<()> {
    // The SAME function without the `TailLoop` wrapper (the un-rewritten shape a
    // non-tail-recursive fn keeps) emits ordinary recursion — no loop, and the
    // self-`Call` is preserved as a real recursive call.
    let src = emit_count_main_rs(false)?;
    let count_src = slice_fn(&src, "pub fn main_count");
    assert!(
        !count_src.contains("loop {"),
        "unexpected loop in non-TailLoop fn:\n{count_src}"
    );
    // The self-`Call` is preserved as a real recursive call in the BODY.
    assert!(
        body_of(count_src).contains("main_count("),
        "expected an ordinary recursive self-call in the body:\n{count_src}"
    );
    Ok(())
}
