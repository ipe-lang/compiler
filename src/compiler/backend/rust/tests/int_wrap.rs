//! End-to-end proof that `Int` overflow ends in a typed error, never a panic or a wrap.
//!
//! The overflow contract of `Int` arithmetic lives in the emitted code path —
//! the `ipe_runtime::math::ipe_int_{add,sub,mul,div}` helpers, `basics_negate`
//! via `IpeNegate`, and `IpeWrappingAdd/Sub/Mul` for polymorphic `Number a`
//! generics — not in a Cargo profile flag. These tests build the emitted crate
//! with `RUSTFLAGS=-Coverflow-checks=on` and assert:
//!
//! * a result outside the 64-bit range trips `IntOverflow`, which the task
//!   step's boundary turns into the program's typed error: nothing printed,
//!   exit 1 — not 101 (a foreign panic, which raw `+` under `overflow-checks`
//!   would give) and not 0 with a wrapped value;
//! * an in-range result at the boundary prints exactly, exit 0.
//!
//! Each `main` runs its arithmetic inside a `Task.andThen` step, the position
//! where a runtime trip becomes a typed error.
//!
//! Gated on `IPE_E2E=1` so the default `cargo test` stays fast and offline.

mod seal_e2e;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::DResult;
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    BinOp, BoundSet, CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module,
    OnFormKind, Program,
};

/// The exit code of a program that ends in a typed error.
const TYPED_ERROR_EXIT: i32 = 1;

/// `callee(args)` with no pin, outside a form.
fn call(callee: Callee, args: Vec<Expr>) -> Expr {
    Expr::Call {
        callee,
        args,
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    }
}

/// `main = Task.andThen (\_ -> Io.println (String.fromInt int)) (Task.succeed ())`.
fn deferred_main(interner: &mut Interner, id: FuncId, home: ModPath, int: Expr) -> DResult<Func> {
    let main = interner.intern("main")?;
    let unit = interner.intern("unit")?;
    let task_unit = IrType::Task(Box::new(IrType::Unit));
    let print = call(
        Callee::Kernel(KernelFn::IoPrintln),
        vec![call(Callee::Kernel(KernelFn::StringFromInt), vec![int])],
    );
    Ok(Func {
        id,
        name: main,
        home,
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: task_unit.clone(),
        body: call(
            Callee::Kernel(KernelFn::TaskAndThen),
            vec![
                Expr::Lambda {
                    params: vec![(unit, IrType::Unit)],
                    ret: task_unit,
                    body: Box::new(print),
                },
                call(Callee::Kernel(KernelFn::TaskSucceed), vec![Expr::Unit]),
            ],
        ),
    })
}

/// A one-module program `Main` holding `funcs`, entered at `entry`.
fn program(main_mod: Symbol, funcs: Vec<Func>, entry: FuncId) -> Program {
    Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs,
            entry: Some(entry),
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
    }
}

/// A program whose deferred `main` prints `int`.
fn single_main_program(interner: &mut Interner, int: Expr) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let entry = FuncId::from_raw(0);
    let main_fn = deferred_main(interner, entry, ModPath(vec![]), int)?;
    Ok(program(main_mod, vec![main_fn], entry))
}

/// `lhs <op> rhs` over two `Int` literals.
fn bin_op(op: BinOp, lhs: i64, rhs: i64) -> Expr {
    Expr::BinOp {
        op,
        lhs: Box::new(Expr::Int(lhs)),
        rhs: Box::new(Expr::Int(rhs)),
    }
}

/// How the emitted program must end.
enum Ending<'a> {
    /// Exit 0 after printing exactly this stdout.
    Prints(&'a str),
    /// The typed `IntOverflow` error: exit 1, nothing printed.
    IntOverflow,
}

/// Emits the program, builds it with `overflow-checks` forced on, runs it,
/// and asserts it ends as `ending` says.
fn build_overflow_checked_and_assert(
    interner: &Interner,
    prog: &Program,
    slot: &str,
    ending: &Ending<'_>,
) -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let emitted = RustBackend::new(interner).emit(prog)?;

    let run = seal_e2e::build_and_run_emitted_with_env(
        &emitted,
        &runtime,
        slot,
        &[("RUSTFLAGS", "-Coverflow-checks=on")],
    )?
    .map_err(seal_e2e::build_bug)?;
    match ending {
        Ending::Prints(expected) => {
            assert_eq!(run.exit_code, Some(0), "an in-range result exits 0");
            assert_eq!(run.stdout, *expected, "an in-range result prints exactly");
        }
        Ending::IntOverflow => {
            assert_eq!(
                run.exit_code,
                Some(TYPED_ERROR_EXIT),
                "Int overflow must end in the typed IntOverflow error (exit 1), never a panic (101) or a wrapped value (0)"
            );
            assert_eq!(run.stdout, "", "no value is printed once IntOverflow fires");
        }
    }
    Ok(())
}

fn run_bin_op(op: BinOp, lhs: i64, rhs: i64, slot: &str, ending: &Ending<'_>) -> DResult<()> {
    let mut interner = Interner::new();
    let prog = single_main_program(&mut interner, bin_op(op, lhs, rhs))?;
    build_overflow_checked_and_assert(&interner, &prog, slot, ending)
}

/// `maxInt + 1` trips `IntOverflow`.
#[test]
fn end_to_end_int_add_trips_at_max() -> DResult<()> {
    run_bin_op(
        BinOp::IntAdd,
        i64::MAX,
        1,
        "ipe_int_overflow_add_e2e",
        &Ending::IntOverflow,
    )
}

/// `minInt - 1` trips `IntOverflow`.
#[test]
fn end_to_end_int_sub_trips_at_min() -> DResult<()> {
    run_bin_op(
        BinOp::IntSub,
        i64::MIN,
        1,
        "ipe_int_overflow_sub_e2e",
        &Ending::IntOverflow,
    )
}

/// `maxInt * 2` trips `IntOverflow`.
#[test]
fn end_to_end_int_mul_trips_on_overflow() -> DResult<()> {
    run_bin_op(
        BinOp::IntMul,
        i64::MAX,
        2,
        "ipe_int_overflow_mul_e2e",
        &Ending::IntOverflow,
    )
}

/// `minInt // -1` trips `IntOverflow`.
#[test]
fn end_to_end_int_div_min_by_neg_one_trips() -> DResult<()> {
    run_bin_op(
        BinOp::IntDiv,
        i64::MIN,
        -1,
        "ipe_int_overflow_div_e2e",
        &Ending::IntOverflow,
    )
}

/// A negative literal left operand of generic `Add` must emit parenthesised.
///
/// Generic (polymorphic `Number a`) `Add` routes through `.ipe_wrapping_add`,
/// a method call: a negative left operand must emit as a parenthesised
/// primary expression (`(-5i64).ipe_wrapping_add(r)`), never a bare
/// `-5i64.ipe_wrapping_add(r)` (which parses as `-(5i64.ipe_wrapping_add(r))`,
/// the wrong value, or as `-(9223372036854775808i64…)` for `minInt`, which
/// trips the deny-by-default `overflowing_literals` lint and fails the build).
#[test]
fn generic_add_negative_literal_receiver() -> DResult<()> {
    run_bin_op(
        BinOp::Add,
        -5,
        3,
        "ipe_generic_add_neg_lit_e2e",
        &Ending::Prints("-2\n"),
    )?;
    run_bin_op(
        BinOp::Add,
        i64::MIN,
        1,
        "ipe_generic_add_min_lit_e2e",
        &Ending::Prints("-9223372036854775807\n"),
    )
}

// ── negate ───────────────────────────────────────────────────────────────────

/// `negate minInt` trips `IntOverflow`: `2^63` has no `Int` value.
#[test]
fn end_to_end_negate_min_i64_trips() -> DResult<()> {
    let mut interner = Interner::new();
    let negate = call(
        Callee::Kernel(KernelFn::BasicsNegate),
        vec![Expr::Int(i64::MIN)],
    );
    let prog = single_main_program(&mut interner, negate)?;
    build_overflow_checked_and_assert(&interner, &prog, "ipe_negate_min_e2e", &Ending::IntOverflow)
}

// ── polymorphic Number a (`BinOp::Add`) ──────────────────────────────────────

/// A two-function program: generic `double x = x + x` and a deferred `main`
/// printing `double arg`.
///
/// `double` is `FuncId(0)`; `main` is `FuncId(1)` and is the entry.
fn generic_double_program(interner: &mut Interner, arg: i64) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let sym_double = interner.intern("double")?;
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
        params: vec![ipe_ir::Param::owned(sym_x, IrType::Generic(sym_a))],
        ret: IrType::Generic(sym_a),
        body: Expr::BinOp {
            op: BinOp::Add,
            lhs: Box::new(Expr::Var(sym_x)),
            rhs: Box::new(Expr::Var(sym_x)),
        },
    };

    let entry = FuncId::from_raw(1);
    let doubled = call(Callee::Func(FuncId::from_raw(0)), vec![Expr::Int(arg)]);
    let main_fn = deferred_main(interner, entry, ModPath(vec![main_mod]), doubled)?;
    Ok(program(main_mod, vec![double_fn, main_fn], entry))
}

/// Polymorphic `double maxInt` trips `IntOverflow` once monomorphised to `Int`.
///
/// The `BinOp::Add` path emits `.ipe_wrapping_add(r)`, whose `Int` impl is the
/// exact `ipe_int_add`: the generic body trips like the inline `+`, never a
/// raw-infix panic under `overflow-checks` and never a wrapped `-2`.
#[test]
fn end_to_end_generic_add_trips_at_max() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = generic_double_program(&mut interner, i64::MAX)?;
    build_overflow_checked_and_assert(
        &interner,
        &prog,
        "ipe_generic_add_overflow_e2e",
        &Ending::IntOverflow,
    )
}

/// Polymorphic `double` of an in-range value prints the exact sum.
#[test]
fn end_to_end_generic_add_in_range_prints() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = generic_double_program(&mut interner, i64::MAX / 2)?;
    build_overflow_checked_and_assert(
        &interner,
        &prog,
        "ipe_generic_add_in_range_e2e",
        &Ending::Prints("9223372036854775806\n"),
    )
}
