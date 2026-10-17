//! Top-level nullary bindings (CAFs) emit as evaluate-once shared values.
//!
//! A zero-parameter top-level binding is a constant applicative form — a shared
//! VALUE, not a function. Ipê evaluates it once and shares the result, so the
//! backend must emit its body behind a lazily-initialised, thread-safe cell
//! rather than re-run the body on every reference. These tests pin the emitted
//! shape for a qualifying CAF, and confirm the gate leaves non-qualifying
//! bindings (functions, `ipe_main`, non-shareable return types) untouched.

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind, Program,
};

const fn empty_module(name: ModPath, funcs: Vec<Func>, entry: Option<FuncId>) -> Module {
    Module {
        name,
        types: vec![],
        funcs,
        entry,
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
    }
}

/// A nullary binding `name : ret` whose body is `body`, owned by the main home.
const fn caf(id: u32, name: Symbol, ret: IrType, body: Expr) -> Func {
    Func {
        id: FuncId::from_raw(id),
        name,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret,
        body,
    }
}

fn missing(detail: &str) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "caf_share_once test",
        detail: detail.to_owned(),
    }
}

/// Emit a single-module program and return its `src/main.rs`.
fn emit_main_rs(interner: &Interner, program: &Program) -> DResult<String> {
    let backend = RustBackend::new(interner);
    let emitted = backend.emit(program)?;
    emitted
        .files
        .get("src/main.rs")
        .cloned()
        .ok_or_else(|| missing("no src/main.rs"))
}

/// A minimal `ipe_main` returning `IpeTask<()>`, printing `"hi"`. Every program
/// needs an entry point; this one references nothing, so it never perturbs a
/// CAF's emitted shape.
fn ipe_main(id: u32, main_sym: Symbol) -> Func {
    caf(
        id,
        main_sym,
        IrType::Task(Box::new(IrType::Unit)),
        Expr::Call {
            callee: Callee::Kernel(KernelFn::IoPrintln),
            args: vec![Expr::Str("hi".to_owned())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    )
}

#[test]
fn nullary_int_caf_is_wrapped_in_a_share_once_cell() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let answer = interner.intern("answer")?;
    let main = interner.intern("main")?;

    let answer_fn = caf(0, answer, IrType::Int, Expr::Int(42));
    let main_fn = ipe_main(1, main);

    let program = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![empty_module(
            ModPath(vec![main_mod]),
            vec![answer_fn, main_fn],
            Some(FuncId::from_raw(1)),
        )],
    };

    let main_rs = emit_main_rs(&interner, &program)?;

    // The qualifying CAF wraps its body in a process-lifetime `OnceLock` cell,
    // evaluates it once, and returns a clone — the signature stays a nullary fn
    // so every call site is unchanged.
    assert!(
        main_rs.contains("pub fn main_answer() -> i64 {"),
        "CAF keeps its nullary signature:\n{main_rs}"
    );
    assert!(
        main_rs.contains("static CELL: std::sync::OnceLock<i64> = std::sync::OnceLock::new();"),
        "CAF body is guarded by a OnceLock cell:\n{main_rs}"
    );
    assert!(
        main_rs.contains("CELL.get_or_init(|| 42i64).clone()"),
        "CAF body is evaluated once through get_or_init and cloned out:\n{main_rs}"
    );
    Ok(())
}

#[test]
fn ipe_main_is_never_wrapped() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let main = interner.intern("main")?;

    let main_fn = ipe_main(0, main);
    let program = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![empty_module(
            ModPath(vec![main_mod]),
            vec![main_fn],
            Some(FuncId::from_raw(0)),
        )],
    };

    let main_rs = emit_main_rs(&interner, &program)?;

    assert!(
        main_rs.contains("pub fn ipe_main()"),
        "ipe_main is emitted:\n{main_rs}"
    );
    // `block_on(ipe_main())` needs a fresh future each call — the entry point is
    // never memoised.
    assert!(
        !main_rs.contains("static CELL"),
        "ipe_main must not be wrapped in a share-once cell:\n{main_rs}"
    );
    Ok(())
}

#[test]
fn nullary_task_caf_is_not_wrapped() -> DResult<()> {
    // A `Task`-typed value is a `Pin<Box<dyn Future + Send>>`: single-poll, not
    // `Clone`, not `Sync`. It cannot live in a `static` cell, so the gate must
    // fail closed and keep the direct inline emission.
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let job = interner.intern("job")?;
    let main = interner.intern("main")?;

    let job_fn = caf(
        0,
        job,
        IrType::Task(Box::new(IrType::Unit)),
        Expr::Call {
            callee: Callee::Kernel(KernelFn::IoPrintln),
            args: vec![Expr::Str("work".to_owned())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    );
    let main_fn = ipe_main(1, main);

    let program = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![empty_module(
            ModPath(vec![main_mod]),
            vec![job_fn, main_fn],
            Some(FuncId::from_raw(1)),
        )],
    };

    let main_rs = emit_main_rs(&interner, &program)?;

    assert!(
        main_rs.contains("pub fn main_job()"),
        "the Task-typed binding is emitted:\n{main_rs}"
    );
    assert!(
        !main_rs.contains("static CELL"),
        "a Task-typed CAF must not be wrapped in a share-once cell:\n{main_rs}"
    );
    Ok(())
}

#[test]
fn a_function_with_parameters_is_not_wrapped() -> DResult<()> {
    // A binding WITH a value parameter is a function, not a CAF: it is re-run per
    // call by definition, so it must never be memoised.
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let identity = interner.intern("identity")?;
    let x = interner.intern("x")?;
    let main = interner.intern("main")?;

    let identity_fn = Func {
        id: FuncId::from_raw(0),
        name: identity,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![ipe_ir::Param::owned(x, IrType::Int)],
        ret: IrType::Int,
        body: Expr::Var(x),
    };
    let main_fn = ipe_main(1, main);

    let program = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![empty_module(
            ModPath(vec![main_mod]),
            vec![identity_fn, main_fn],
            Some(FuncId::from_raw(1)),
        )],
    };

    let main_rs = emit_main_rs(&interner, &program)?;

    assert!(
        main_rs.contains("pub fn main_identity(x: i64) -> i64 {"),
        "the function keeps its parameter:\n{main_rs}"
    );
    assert!(
        !main_rs.contains("static CELL"),
        "a parameterised function must not be wrapped:\n{main_rs}"
    );
    Ok(())
}
