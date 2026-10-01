//! Fully-parametric top-level function emission for the Rust backend.
//!
//! Exercises the generic-codegen spine added by the IR's [`IrType::Generic`] +
//! `Func::type_params`: a structurally-parametric function `identity : a -> a`
//! emits `pub fn main_identity<T1: Clone>(x: T1) -> T1 { x }`, every `IrType::Generic`
//! in its signature / body renders as the deterministic Rust generic name
//! (`a` → `T1` by quantification position), and a same-module use at two
//! distinct concrete types (`Int` and `Bool`) resolves to the ONE generic
//! function, which Rust monomorphises.
//!
//! Behavioural-parity oracle: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the
//! equivalent program
//!
//! ```text
//! identity : a -> a
//! identity x = x
//! main =
//!     let n = identity 40
//!         flag = identity (1 == 1)
//!     in Io.println (String.fromInt (if flag then n + 2 else n))
//! ```
//!
//! to stdout `42\n`, exit 0 (hand-verified in a temp dir; the backend emits
//! the matching `func identity[T1 any](x T1) T1`, confirming the `a` → `T1`
//! naming convention). The `end_to_end_*` test (gated on `IPE_E2E=1`) drives
//! the hand-built IR through the Rust backend, builds the emitted crate, and
//! asserts the identical `42`.

mod seal_e2e;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::Interner;
use ipe_ir::{
    BinOp, BoundSet, CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module,
    OnFormKind, Program,
};

/// Build the canonical generic program:
///
/// ```ipe
/// identity : a -> a
/// identity x = x
/// main =
///     let n = identity 40
///         flag = identity (1 == 1)
///     in Io.println (String.fromInt (if flag then n + 2 else n))
/// ```
///
/// `identity` quantifies the single type variable `a` (used structurally, pure
/// pass-through), so it lowers to a generic `Func` (`type_params = [a]`). `main`
/// uses it at `Int` and `Bool` in the same module — the ONE generic function,
/// monomorphised by Rust at each call.
#[allow(clippy::too_many_lines)] // straight-line IR fixture builder
fn build_identity_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let identity = interner.intern("identity")?;
    let main = interner.intern("main")?;
    let a = interner.intern("a")?;
    let x = interner.intern("x")?;
    let n = interner.intern("n")?;
    let flag = interner.intern("flag")?;

    let identity_id = FuncId::from_raw(0);
    let main_id = FuncId::from_raw(1);

    // identity x = x — body is the bare parameter, the var typed `Generic(a)`.
    let identity_fn = Func {
        id: identity_id,
        name: identity,
        home: ModPath(vec![]),
        type_params: vec![(a, BoundSet::UNBOUNDED)],
        row_params: vec![],
        params: vec![(x, IrType::Generic(a))],
        ret: IrType::Generic(a),
        body: Expr::Var(x),
    };

    // identity 40 — T1 = Int.
    let call_int = Expr::Call {
        callee: Callee::Func(identity_id),
        args: vec![Expr::Int(40)],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    };
    // identity (1 == 1) — T1 = Bool, the second concrete instantiation.
    let call_bool = Expr::Call {
        callee: Callee::Func(identity_id),
        args: vec![Expr::BinOp {
            op: BinOp::Eq,
            lhs: Box::new(Expr::Int(1)),
            rhs: Box::new(Expr::Int(1)),
        }],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    };
    // if flag then n + 2 else n
    let chosen = Expr::If {
        cond: Box::new(Expr::Var(flag)),
        then_: Box::new(Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(Expr::Var(n)),
            rhs: Box::new(Expr::Int(2)),
        }),
        else_: Box::new(Expr::Var(n)),
    };
    // Io.println (String.fromInt <chosen>)
    let print = Expr::Call {
        callee: Callee::Kernel(KernelFn::IoPrintln),
        args: vec![Expr::Call {
            callee: Callee::Kernel(KernelFn::StringFromInt),
            args: vec![chosen],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    };
    // let n = identity 40 in let flag = identity (1 == 1) in <print>
    let main_body = Expr::Let {
        name: n,
        value: Box::new(call_int),
        body: Box::new(Expr::Let {
            name: flag,
            value: Box::new(call_bool),
            body: Box::new(print),
        }),
    };
    let main_fn = Func {
        id: main_id,
        name: main,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: main_body,
    };

    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![identity_fn, main_fn],
            entry: Some(main_id),
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
    })
}

#[test]
fn emits_generic_function_signature() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = build_identity_program(&mut interner)?;
    let emitted = RustBackend::new(&interner).emit(&prog)?;
    let main_rs = emitted
        .files
        .get(&ipe_backend::RelPath::new("src/main.rs")?)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "generics test",
            detail: "emitted project is missing src/main.rs".to_owned(),
        })?;

    // The generic clause + the `Generic(a)` → `T1` rendering in both the
    // parameter and the return position.
    assert!(
        main_rs.contains("pub fn main_identity<T1: Clone>(x: T1) -> T1 {"),
        "generic function emits a `<T1>` clause with T1-typed param and return:\n{main_rs}"
    );
    // Its body is the recursion-guard prologue followed by the bare pass-through
    // parameter.
    assert!(
        main_rs.contains(
            "pub fn main_identity<T1: Clone>(x: T1) -> T1 {\n    let _ipe_recursion_guard = crate::recursion_guard();\n    x\n}"
        ),
        "identity's body is the guard prologue then the bare parameter `x`:\n{main_rs}"
    );
    // The monomorphic entry carries NO generic clause — the empty `type_params`
    // path emits no generic clause.
    assert!(
        main_rs.contains("pub fn ipe_main() -> IpeTask<()> {"),
        "monomorphic `main` emits no generic clause:\n{main_rs}"
    );
    // Exactly ONE generic function is emitted; both call sites target it and
    // Rust monomorphises (no per-type duplicate definition).
    assert_eq!(
        main_rs.matches("pub fn main_identity").count(),
        1,
        "one generic fn, shared across both concrete instantiations"
    );
    Ok(())
}

/// Build a program with two super-typed generic functions, exercising the
/// bound clauses:
///
/// ```ipe
/// double x = x + x          -- Number  → T1: Add<Output = T1> + Copy
/// max a b = if a > b then a else b  -- Comparable → T1: PartialOrd + Copy
/// main = Io.println (String.fromInt (double (max 20 21)))
/// ```
#[allow(clippy::too_many_lines)] // fixture builder — length is the enumerated IR it constructs
fn build_bounded_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let double = interner.intern("double")?;
    let max = interner.intern("max")?;
    let main = interner.intern("main")?;
    let a = interner.intern("a")?;
    let x = interner.intern("x")?;
    // `max`'s value parameters — distinct symbols from the type variable `a`.
    let p = interner.intern("p")?;
    let q = interner.intern("q")?;

    let double_id = FuncId::from_raw(0);
    let max_id = FuncId::from_raw(1);
    let main_id = FuncId::from_raw(2);

    // double x = x + x — the body adds `x` to itself, so `a` carries Add and is
    // reused (Copy). A reused (Copy) numeric-add variable.
    let num_bounds = BoundSet::UNBOUNDED.with_add().with_copy();
    let double_fn = Func {
        id: double_id,
        name: double,
        home: ModPath(vec![]),
        type_params: vec![(a, num_bounds)],
        row_params: vec![],
        params: vec![(x, IrType::Generic(a))],
        ret: IrType::Generic(a),
        body: Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(Expr::Var(x)),
            rhs: Box::new(Expr::Var(x)),
        },
    };

    // max a b = if a > b then a else b — `a` is ordered and reused.
    let ord_bounds = BoundSet::UNBOUNDED.with_ord().with_copy();
    let max_fn = Func {
        id: max_id,
        name: max,
        home: ModPath(vec![]),
        type_params: vec![(a, ord_bounds)],
        row_params: vec![],
        params: vec![(p, IrType::Generic(a)), (q, IrType::Generic(a))],
        ret: IrType::Generic(a),
        body: Expr::If {
            cond: Box::new(Expr::BinOp {
                op: BinOp::Gt,
                lhs: Box::new(Expr::Var(p)),
                rhs: Box::new(Expr::Var(q)),
            }),
            then_: Box::new(Expr::Var(p)),
            else_: Box::new(Expr::Var(q)),
        },
    };

    // main = Io.println (String.fromInt (double (max 20 21)))
    let max_call = Expr::Call {
        callee: Callee::Func(max_id),
        args: vec![Expr::Int(20), Expr::Int(21)],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    };
    let double_call = Expr::Call {
        callee: Callee::Func(double_id),
        args: vec![max_call],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    };
    let main_body = Expr::Call {
        callee: Callee::Kernel(KernelFn::IoPrintln),
        args: vec![Expr::Call {
            callee: Callee::Kernel(KernelFn::StringFromInt),
            args: vec![double_call],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    };
    let main_fn = Func {
        id: main_id,
        name: main,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: main_body,
    };

    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![double_fn, max_fn, main_fn],
            entry: Some(main_id),
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
    })
}

#[test]
fn emits_super_typed_bound_clauses() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = build_bounded_program(&mut interner)?;
    let emitted = RustBackend::new(&interner).emit(&prog)?;
    let main_rs = emitted
        .files
        .get(&ipe_backend::RelPath::new("src/main.rs")?)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "bounded generics test",
            detail: "emitted project is missing src/main.rs".to_owned(),
        })?;

    // Number → the wrapping-add trait (`IpeWrappingAdd`) plus `Copy`, with
    // `Output` closed over the parameter's own generic name. The wrapping trait
    // (not `::core::ops::Add`) ensures `i64` arithmetic in a generic body does
    // not panic under `overflow-checks=on`.
    assert!(
        main_rs.contains(
            "pub fn main_double<T1: ipe_runtime::basics::IpeWrappingAdd<Output = T1> + Copy + Clone>"
        ),
        "double emits a Number bound (IpeWrappingAdd + Copy):\n{main_rs}"
    );
    // Comparable → `PartialOrd` plus `Copy`.
    assert!(
        main_rs.contains("pub fn main_max<T1: PartialOrd + Copy + Clone>(p: T1, q: T1) -> T1 {"),
        "max emits a Comparable bound (PartialOrd + Copy):\n{main_rs}"
    );
    Ok(())
}

/// Full spine: build the generic IR, emit the Cargo project, vendor the runtime,
/// `cargo build`, run, and assert the program prints `42` — the expected value/// backend produces for the equivalent program. Gated on `IPE_E2E=1` so the
/// default `cargo test` stays fast and offline.
#[test]
fn end_to_end_builds_and_prints_forty_two() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let mut interner = Interner::new();
    let prog = build_identity_program(&mut interner)?;
    let emitted = RustBackend::new(&interner).emit(&prog)?;

    let out = ipe_test_temp::temp_root().join("ipe_backend_generics_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let src = out.join("src");
    std::fs::create_dir_all(&src).map_err(|e| seal_e2e::io_bug(&src, &e))?;
    seal_e2e::copy_dir(&runtime, &src.join("ipe_runtime"))?;

    let cargo_toml = out.join("Cargo.toml");
    std::fs::write(&cargo_toml, &emitted.cargo_toml)
        .map_err(|e| seal_e2e::io_bug(&cargo_toml, &e))?;
    for (rel, contents) in &emitted.files {
        let path = out.join(rel.as_str());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| seal_e2e::io_bug(parent, &e))?;
        }
        std::fs::write(&path, contents).map_err(|e| seal_e2e::io_bug(&path, &e))?;
    }

    let target_dir = seal_e2e::emitted_run_target_dir(&out);
    let status = std::process::Command::new("cargo")
        .arg("build")
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status();
    assert!(
        matches!(&status, Ok(s) if s.success()),
        "emitted generic project must build: {status:?}"
    );

    let bin = target_dir.join("debug").join("ipe-app");
    let output = std::process::Command::new(&bin)
        .output()
        .map_err(|e| seal_e2e::io_bug(&bin, &e))?;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "42\n",
        "generic program prints 42"
    );
    assert!(output.status.success(), "exit 0");
    if target_dir == out.join("target") {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
    Ok(())
}
