//! The backend refuses to name an intercept-only `Store.*` placeholder kernel.
//!
//! Lowering refuses every off-intercept use of these kernels (IPE-L0146). This
//! is the second boundary: an IR call to `Store.add` that reaches emission is a
//! compiler invariant failure, reported as a `CompilerBug`, never the emitted
//! name `store_add`, which no runtime defines.

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::Interner;
use ipe_ir::{
    CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind, Program,
};

const MAIN_ID: FuncId = FuncId::from_raw(0);

/// A kernel call with no pin.
const fn call(kernel: KernelFn, args: Vec<Expr>) -> Expr {
    Expr::Call {
        callee: Callee::Kernel(kernel),
        args,
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    }
}

/// Emit `main = Io.println (String.fromInt <inner>)` and return `src/main.rs`.
// One cohesive IR fixture: the `Module` literal lists every capability flag.
#[allow(clippy::too_many_lines)]
fn emit_main_printing(inner: Expr) -> DResult<Option<String>> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let main = interner.intern("main")?;

    let main_fn = Func {
        id: MAIN_ID,
        name: main,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: call(
            KernelFn::IoPrintln,
            vec![call(KernelFn::StringFromInt, vec![inner])],
        ),
    };

    let program = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![main_fn],
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
    Ok(emitted.files.get("src/main.rs").cloned())
}

/// An IR call to a placeholder kernel is a `CompilerBug` at emission.
#[test]
fn placeholder_kernel_call_is_a_compiler_bug() {
    for kernel in [KernelFn::StoreAdd, KernelFn::StoreSub, KernelFn::StoreMul] {
        let outcome = emit_main_printing(call(kernel, vec![Expr::Int(1), Expr::Int(2)]));
        assert!(
            matches!(
                &outcome,
                Err(Diagnostic::CompilerBug { detail, .. }) if detail.contains("intercept-only kernel")
            ),
            "{kernel:?}: the backend must refuse to name a placeholder kernel, got {outcome:?}"
        );
    }
}

/// The same program without the placeholder call still emits.
#[test]
fn program_without_placeholder_still_emits() -> DResult<()> {
    let main_rs = emit_main_printing(Expr::Int(3))?;
    assert!(
        main_rs.is_some(),
        "the control program must emit `src/main.rs`"
    );
    Ok(())
}
