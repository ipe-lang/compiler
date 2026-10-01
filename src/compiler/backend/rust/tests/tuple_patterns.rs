//! Tuple-pattern and unit-value tests for the Rust backend.
//!
//! These exercise the two IR additions the backend learned to emit:
//!
//! * a TUPLE PATTERN [`Pat::Tuple`] as a constructor-payload sub-pattern — a
//!   variant carrying a tuple field (`type Wrap = MkWrap (Int, Int)`), matched
//!   with `MkWrap (a, b) -> a`, emits the Rust arm `Main::MkWrap((a, b)) => a`,
//!   and the construction `MkWrap (3, 4)` emits `Main::MkWrap((3, 4))`,
//! * the UNIT VALUE [`Expr::Unit`] — Ipê's `()` literal — emits the Rust unit
//!   expression `()`, and [`IrType::Unit`] renders as `()`.
//!
//! Behavioural-parity oracle: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the
//! shape-equivalent program
//!
//! ```text
//! type alias IntPair = (Int, Int)
//! type Wrap = MkWrap IntPair
//! fstOf w = case w of MkWrap (a, b) -> a
//! main = Io.println (String.fromInt (fstOf (MkWrap (3, 4))))      -- prints 3
//! ```
//!
//! to stdout `3\n`, exit 0 (hand-verified in a temp dir). The `end_to_end_*`
//! test (gated on `IPE_E2E=1`) drives the same hand-built IR through the Rust
//! backend, builds the emitted crate, runs it, and asserts the identical `3` —
//! the soundness-floor regression for a value laundered through a tuple-carrying
//! payload destructured by a tuple pattern.

mod seal_e2e;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::Interner;
use ipe_ir::{
    Arm, CallPin, Callee, EnumDef, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module,
    OnFormKind, Pat, Program, TypeDef, Variant,
};

fn emit(interner: &Interner, prog: &Program) -> DResult<String> {
    let emitted = RustBackend::new(interner).emit(prog)?;
    emitted
        .files
        .get("src/main.rs")
        .cloned()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "tuple_patterns test",
            detail: "no src/main.rs".to_owned(),
        })
}

/// The `Wrap` program: a single-variant enum whose payload is a `(Int, Int)`
/// tuple, a `fstOf` that destructures it with a tuple pattern, and a `main` that
/// prints `fstOf (MkWrap (3, 4))`.
#[allow(clippy::too_many_lines)] // straight-line IR fixture builder
fn wrap_program(i: &mut Interner) -> DResult<Program> {
    let main_mod = i.intern("Main")?;
    let wrap = i.intern("Wrap")?;
    let mk_wrap = i.intern("MkWrap")?;
    let fst_of = i.intern("fstOf")?;
    let main = i.intern("main")?;
    let w = i.intern("w")?;
    let a = i.intern("a")?;
    let b = i.intern("b")?;

    let def = EnumDef {
        name: wrap,
        type_params: vec![],
        variants: vec![Variant {
            name: mk_wrap,
            fields: vec![IrType::Tuple(vec![IrType::Int, IrType::Int])],
        }],
        home: ModPath(vec![]),
    };

    // fstOf w = case w of MkWrap (a, b) -> a
    let arms = vec![Arm {
        pat: Pat::Ctor {
            home: ModPath(vec![]),
            ty: wrap,
            variant: mk_wrap,
            args: vec![Pat::Tuple(vec![Pat::Var(a), Pat::Var(b)])],
        },
        body: Expr::Var(a),
        guard: None,
    }];
    let fst_of_fn = Func {
        id: FuncId::from_raw(0),
        name: fst_of,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(
            w,
            IrType::Enum {
                home: ModPath(vec![]),
                name: wrap,
                args: vec![],
            },
        )],
        ret: IrType::Int,
        body: Expr::Match(ipe_ir::Match::new(Expr::Var(w), arms, &[mk_wrap])?),
    };

    // main = Io.println (String.fromInt (fstOf (MkWrap (3, 4))))
    let main_fn = Func {
        id: FuncId::from_raw(1),
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
                    callee: Callee::Func(FuncId::from_raw(0)),
                    args: vec![Expr::Ctor {
                        home: ModPath(vec![]),
                        ty: wrap,
                        variant: mk_wrap,
                        args: vec![Expr::Tuple(vec![Expr::Int(3), Expr::Int(4)])],
                    }],
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
            types: vec![TypeDef::Enum(def)],
            funcs: vec![fst_of_fn, main_fn],
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

#[test]
fn tuple_subpattern_in_ctor_arm_renders() -> DResult<()> {
    let mut i = Interner::new();
    let prog = wrap_program(&mut i)?;
    let src = emit(&i, &prog)?;

    // The constructor pattern's tuple sub-pattern renders as `(a, b)`.
    assert!(
        src.contains("MainWrap::MkWrap((a, b)) => a"),
        "tuple sub-pattern must render as a Rust tuple pattern; got:\n{src}"
    );
    // The matching tuple construction wraps the tuple literal inside the ctor.
    // Rustfmt may split `(3, 4)` across lines; assert the structural fragments.
    assert!(
        src.contains("MainWrap::MkWrap(("),
        "tuple-field construction must use ctor wrapper; got:\n{src}"
    );
    assert!(
        src.contains("3i64") && src.contains("4i64"),
        "tuple literal elements missing from ctor construction; got:\n{src}"
    );
    Ok(())
}

#[test]
fn unit_value_and_type_render() -> DResult<()> {
    let mut i = Interner::new();
    let main_mod = i.intern("Main")?;
    let nop = i.intern("nop")?;

    // nop() -> () = ()
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![Func {
                id: FuncId::from_raw(0),
                name: nop,
                home: ModPath(vec![]),
                type_params: vec![],
                row_params: vec![],
                params: vec![],
                ret: IrType::Unit,
                body: Expr::Unit,
            }],
            entry: None,
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
    let src = emit(&i, &prog)?;

    // A zero-parameter binding is a CAF (constant applicative form): its body is
    // evaluated once behind a share-once cell, so the unit value `()` is produced
    // inside `get_or_init`. Both the unit value and the unit return type still
    // render as `()`.
    assert!(
        src.contains("pub fn main_nop() -> () {")
            && src.contains("static CELL: std::sync::OnceLock<()> = std::sync::OnceLock::new();")
            && src.contains("CELL.get_or_init(|| ()).clone()"),
        "unit value and unit return type must both render as `()`, shared once; got:\n{src}"
    );
    Ok(())
}

/// Full spine: build the `Wrap` IR, emit, vendor the runtime, `cargo build`,
/// run, and assert `3` — the expected value for `fstOf (MkWrap (3, 4))`. The
/// soundness-floor regression for a value laundered through a tuple-carrying
/// payload destructured by a tuple pattern. Gated on `IPE_E2E=1`.
#[test]
fn end_to_end_ctor_tuple_field_prints_three() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = wrap_program(&mut interner)?;
    build_and_assert(&interner, &prog, "ipe_backend_tuple_wrap_e2e", "3\n")
}

/// Emit `prog`, vendor the runtime into a temp dir named `slot`, `cargo build`,
/// run the binary, and assert its stdout equals `expected`. Gated on `IPE_E2E=1`
/// so the default `cargo test` stays fast and offline.
fn build_and_assert(
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

    let target_dir = seal_e2e::emitted_run_target_dir(&out);
    let status = std::process::Command::new("cargo")
        .arg("build")
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status();
    assert!(
        matches!(&status, Ok(s) if s.success()),
        "emitted tuple-pattern project must build: {status:?}"
    );

    let bin = target_dir.join("debug").join("ipe-app");
    let output = std::process::Command::new(&bin)
        .output()
        .map_err(|e| seal_e2e::io_bug(&bin, &e))?;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected,
        "tuple-pattern program output must match golden"
    );
    assert!(output.status.success(), "exit 0");
    if target_dir == out.join("target") {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
    Ok(())
}
