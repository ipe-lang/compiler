//! Overflow-wrap end-to-end proof for `Int` arithmetic and `negate`.
//!
//! The two's-complement wrap contract of `Int` arithmetic must live in the
//! emitted code path (the `ipe_runtime::math::ipe_int_{add,sub,mul}` total
//! helpers, `basics_negate` via `IpeWrappingNeg`, and `IpeWrappingAdd/Sub/Mul`
//! for polymorphic `Number a` generics), NOT in an `overflow-checks = false`
//! Cargo profile flag. To prove that, these tests build the emitted crate with
//! `RUSTFLAGS=-Coverflow-checks=on` — the exact condition the profile flag was
//! silently relied upon to avoid — and assert the boundary arithmetic wraps
//! and the process exits 0.
//!
//! Under the old raw-infix / raw-`-x` emit, `overflow-checks=on` makes
//! `i64::MAX + 1` and `-(i64::MIN)` panic (exit 101); these tests FAIL on
//! that code and PASS only once the wrapping helpers are on the emit path —
//! the definitive proof the class is closed independently of any manifest flag.
//!
//! Gated on `IPE_E2E=1` so the default `cargo test` stays fast and offline.

mod seal_e2e;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::DResult;
use ipe_intern::Interner;
use ipe_ir::{
    BinOp, BoundSet, CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module,
    OnFormKind, Program,
};

/// `main = Io.println (String.fromInt (lhs <op> rhs))` at `FuncId(0)`.
fn wrap_main(interner: &mut Interner, op: BinOp, lhs: i64, rhs: i64) -> DResult<Func> {
    let main = interner.intern("main")?;
    Ok(Func {
        id: FuncId::from_raw(0),
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
                args: vec![Expr::BinOp {
                    op,
                    lhs: Box::new(Expr::Int(lhs)),
                    rhs: Box::new(Expr::Int(rhs)),
                }],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    })
}

fn wrap_program(interner: &mut Interner, op: BinOp, lhs: i64, rhs: i64) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let main_fn = wrap_main(interner, op, lhs, rhs)?;
    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![main_fn],
            entry: Some(FuncId::from_raw(0)),
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

/// Emit the program, vendor the runtime beside it, `cargo build` it with
/// `overflow-checks` FORCED ON, run the binary, and assert stdout == `expected`
/// with a clean (exit-0) termination.
fn build_overflow_checked_and_assert(
    interner: &Interner,
    prog: &Program,
    slot: &str,
    expected: &str,
) -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let emitted = RustBackend::new(interner).emit(prog)?;

    let out = ipe_test_temp::temp_root().join(slot);
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

    // Force `overflow-checks=on` regardless of the emitted crate's dev profile.
    // Under raw-infix i64 arithmetic this makes the boundary op panic on build-
    // then-run; the wrapping helpers keep it total.
    let target_dir = seal_e2e::emitted_run_target_dir(&out);
    let status = std::process::Command::new("cargo")
        .arg("build")
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("RUSTFLAGS", "-Coverflow-checks=on")
        .status();
    assert!(
        matches!(&status, Ok(s) if s.success()),
        "emitted int-wrap project must build under overflow-checks=on: {status:?}"
    );

    let bin = target_dir.join("debug").join("ipe-app");
    let output = std::process::Command::new(&bin)
        .output()
        .map_err(|e| seal_e2e::io_bug(&bin, &e))?;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected,
        "int arithmetic must wrap (two's-complement), not panic, under overflow-checks=on"
    );
    assert!(
        output.status.success(),
        "exit 0 under overflow-checks=on — wrap semantics live in the emitted code, \
         not the Cargo profile flag; got {:?}",
        output.status.code()
    );
    if target_dir == out.join("target") {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
    Ok(())
}

fn run_wrap(op: BinOp, lhs: i64, rhs: i64, slot: &str, expected: &str) -> DResult<()> {
    let mut interner = Interner::new();
    let prog = wrap_program(&mut interner, op, lhs, rhs)?;
    build_overflow_checked_and_assert(&interner, &prog, slot, expected)
}

/// `i64::MAX + 1` wraps to `i64::MIN` (no "attempt to add with overflow").
#[test]
fn end_to_end_int_add_wraps_at_max() -> DResult<()> {
    run_wrap(
        BinOp::IntAdd,
        i64::MAX,
        1,
        "ipe_int_wrap_add_e2e",
        "-9223372036854775808\n",
    )
}

/// `i64::MIN - 1` wraps to `i64::MAX`.
#[test]
fn end_to_end_int_sub_wraps_at_min() -> DResult<()> {
    run_wrap(
        BinOp::IntSub,
        i64::MIN,
        1,
        "ipe_int_wrap_sub_e2e",
        "9223372036854775807\n",
    )
}

/// `i64::MAX * 2` wraps to `-2`.
#[test]
fn end_to_end_int_mul_wraps_on_overflow() -> DResult<()> {
    run_wrap(BinOp::IntMul, i64::MAX, 2, "ipe_int_wrap_mul_e2e", "-2\n")
}

// ── negate ───────────────────────────────────────────────────────────────────

/// `main = Io.println (String.fromInt (Basics.negate x))` where `x = value`.
fn negate_main(interner: &mut Interner, value: i64) -> DResult<Func> {
    let main = interner.intern("main")?;
    Ok(Func {
        id: FuncId::from_raw(0),
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
                    callee: Callee::Kernel(KernelFn::BasicsNegate),
                    args: vec![Expr::Int(value)],
                    pin: CallPin::None,
                    on_form: OnFormKind::NotForm,
                }],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    })
}

fn negate_program(interner: &mut Interner, value: i64) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let main_fn = negate_main(interner, value)?;
    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![main_fn],
            entry: Some(FuncId::from_raw(0)),
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

/// `negate(i64::MIN)` must wrap to `i64::MIN` (no panic) under overflow-checks=on.
#[test]
fn end_to_end_negate_min_i64_wraps() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let mut interner = Interner::new();
    let prog = negate_program(&mut interner, i64::MIN)?;
    build_overflow_checked_and_assert(
        &interner,
        &prog,
        "ipe_negate_min_e2e",
        "-9223372036854775808\n",
    )
}

// ── polymorphic Number a (`BinOp::Add`) ──────────────────────────────────────

/// Build a two-function program:
///   `double : a -> a` where `body = x + x` (`BinOp::Add`, polymorphic)
///   `main   = Io.println (String.fromInt (double i64::MAX))`
///
/// `double` is `FuncId(0)`; `main` is `FuncId(1)` and is the entry.
fn generic_double_program(interner: &mut Interner, arg: i64) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let sym_double = interner.intern("double")?;
    let sym_main = interner.intern("main")?;
    let sym_a = interner.intern("a")?;
    let sym_x = interner.intern("x")?;

    // `double<T1: IpeWrappingAdd + Copy + Clone>(x: T1) -> T1 { x + x }`
    let double_fn = Func {
        id: FuncId::from_raw(0),
        name: sym_double,
        home: ModPath(vec![main_mod]),
        type_params: vec![(
            sym_a,
            BoundSet::UNBOUNDED.with_add().with_copy().with_clone(),
        )],
        row_params: vec![],
        params: vec![(sym_x, IrType::Generic(sym_a))],
        ret: IrType::Generic(sym_a),
        body: Expr::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expr::Var(sym_x)),
            rhs: Box::new(Expr::Var(sym_x)),
        },
    };

    // `main = Io.println (String.fromInt (double arg))`
    let main_fn = Func {
        id: FuncId::from_raw(1),
        name: sym_main,
        home: ModPath(vec![main_mod]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: Expr::Call {
            callee: Callee::Kernel(KernelFn::IoPrintln),
            args: vec![Expr::Call {
                callee: Callee::Kernel(KernelFn::StringFromInt),
                args: vec![Expr::Call {
                    callee: Callee::Func(FuncId::from_raw(0)),
                    args: vec![Expr::Int(arg)],
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

    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![double_fn, main_fn],
            entry: Some(FuncId::from_raw(1)),
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

/// Polymorphic `double i64::MAX` wraps to `-2` under overflow-checks=on.
///
/// The `BinOp::Add` path emits `.ipe_wrapping_add(r)` so the generic body
/// does not panic when monomorphised to `i64`. On the old raw-infix emit
/// `(x + x)` in a generic `<T1: Add<Output=T1>>` body, `overflow-checks=on`
/// would panic at the monomorphised `i64` call site (exit 101) — this test
/// proves the wrapping path is now in place.
#[test]
fn end_to_end_generic_add_wraps_at_max() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let mut interner = Interner::new();
    let prog = generic_double_program(&mut interner, i64::MAX)?;
    // i64::MAX + i64::MAX wraps to -2 (same as 2*i64::MAX == -2).
    build_overflow_checked_and_assert(&interner, &prog, "ipe_generic_add_wrap_e2e", "-2\n")
}
