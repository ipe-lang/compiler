//! Record-pattern and nested-pattern tests for the Rust backend.
//!
//! These exercise the IR addition the backend learned to render — the RECORD
//! pattern [`Pat::Record`] — plus the renderer's now-fully-recursive coverage of
//! every nesting position:
//!
//! * an irrefutable record destructure `{ x, y } = r` (the lowerer surfaces the
//!   COMPLETE field set, an unbound field as a [`Pat::Wildcard`]) emits the Rust
//!   struct pattern `RecXY { x, y: _, .. }` — a field punned to its own name uses
//!   Rust shorthand, an ignored field renders `field: _`,
//! * a TUPLE nested inside a record field (`{ point = (a, b), tag }`) emits
//!   `RecPointTag { point: (a, b), tag, .. }` — the renderer recurses through the
//!   record field into the tuple sub-pattern,
//! * a record pattern whose field set was never surfaced in a signature fails
//!   fast as a [`Diagnostic::CompilerBug`] (the same upstream contract record
//!   LITERALS are held to), never a silent mis-emit.
//!
//! Behavioural-parity oracle: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the
//! shape-equivalent programs
//!
//! ```text
//! -- record destructure:
//! getX r = let { x, y } = r in x
//! main = Io.println (String.fromInt (getX { x = 7, y = 2 }))           -- prints 7
//!
//! -- nested tuple in a record field:
//! sx r = let { point, tag } = r ; (a, b) = point in a + b + tag
//! main = Io.println (String.fromInt (sx { point = (3, 4), tag = 5 }))  -- prints 12
//! ```
//!
//! to stdout `7\n` / `12\n`, exit 0 (hand-verified). The `end_to_end_*` test
//! (gated on `IPE_E2E=1`) drives the same
//! hand-built IR through the Rust backend, builds the emitted crate, runs it, and
//! asserts the identical `7` — the soundness-floor regression for a value
//! laundered through a record destructured by a record pattern.

mod seal_e2e;

use std::collections::BTreeMap;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind, Pat,
    Program,
};

/// A single-module program with the given funcs and optional entry.
fn program(name: Symbol, funcs: Vec<Func>, entry: Option<FuncId>) -> Program {
    Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![name]),
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
        }],
    }
}

fn emit(interner: &Interner, prog: &Program) -> DResult<String> {
    let emitted = RustBackend::new(interner).emit(prog)?;
    emitted
        .files
        .get("src/main.rs")
        .cloned()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "record_patterns test",
            detail: "no src/main.rs".to_owned(),
        })
}

/// A `{ x : Int, y : Int }` record type.
fn xy_record(x: Symbol, y: Symbol) -> IrType {
    let mut fields = BTreeMap::new();
    fields.insert(x, IrType::Int);
    fields.insert(y, IrType::Int);
    IrType::Record(fields)
}

/// The `getX` program: a record-typed param destructured by a record pattern
/// `{ x, y = _ }` (complete field set; `y` ignored), returning `x`, and a `main`
/// that prints `getX { x = 7, y = 2 }`.
fn getx_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let x = interner.intern("x")?;
    let y = interner.intern("y")?;
    let par = interner.intern("p")?;
    let getx = interner.intern("getX")?;
    let main = interner.intern("main")?;

    let rec = xy_record(x, y);

    // getX p = let { x = x, y = _ } = p in x
    //   (complete field set; `x` punned to its own name, `y` wildcard-ignored)
    let getx_fn = Func {
        id: FuncId::from_raw(0),
        name: getx,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(par, rec)],
        ret: IrType::Int,
        body: Expr::Destructure {
            binder: Pat::Record(vec![(x, Pat::Var(x)), (y, Pat::Wildcard)]),
            value: Box::new(Expr::Var(par)),
            body: Box::new(Expr::Var(x)),
        },
    };
    // main = Io.println (String.fromInt (getX { x = 7, y = 2 }))
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
                    args: vec![Expr::Record {
                        fields: vec![(x, Expr::Int(7)), (y, Expr::Int(2))],
                        ty: None,
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

    Ok(program(
        main_mod,
        vec![getx_fn, main_fn],
        Some(FuncId::from_raw(1)),
    ))
}

#[test]
fn record_pattern_emits_struct_pattern_with_shorthand_and_wildcard() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = getx_program(&mut interner)?;
    let out = emit(&interner, &prog)?;

    // The record destructure renders as a Rust struct pattern: `x` punned to its
    // own name (shorthand), `y` wildcard-ignored, trailing `..`.
    assert!(
        out.contains("let RecXY { x, y: _, .. } ="),
        "record pattern not emitted as struct pattern:\n{out}"
    );
    // No lint-flagged redundant `x: x` shorthand violation.
    assert!(
        !out.contains("x: x"),
        "punned field must use shorthand, not `x: x`:\n{out}"
    );
    Ok(())
}

#[test]
fn nested_tuple_in_record_field_renders_recursively() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let point = interner.intern("point")?;
    let tag = interner.intern("tag")?;
    let a = interner.intern("a")?;
    let b = interner.intern("b")?;
    let par = interner.intern("r")?;
    let sx = interner.intern("sx")?;

    // type alias P = { point : (Int, Int), tag : Int }
    let mut fields = BTreeMap::new();
    fields.insert(point, IrType::Tuple(vec![IrType::Int, IrType::Int]));
    fields.insert(tag, IrType::Int);
    let p_rec = IrType::Record(fields);

    // sx r = let { point = (a, b), tag = tag } = r in <unused body>
    //   (the point of the test is the rendered binder, not the arithmetic)
    let sx_fn = Func {
        id: FuncId::from_raw(0),
        name: sx,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(par, p_rec)],
        ret: IrType::Int,
        body: Expr::Destructure {
            binder: Pat::Record(vec![
                (point, Pat::Tuple(vec![Pat::Var(a), Pat::Var(b)])),
                (tag, Pat::Var(tag)),
            ]),
            value: Box::new(Expr::Var(par)),
            body: Box::new(Expr::Var(a)),
        },
    };
    let prog = program(main_mod, vec![sx_fn], None);
    let out = emit(&interner, &prog)?;

    // The renderer recurses through the record field into the tuple sub-pattern;
    // `tag` is punned to shorthand. Rustfmt may split the struct pattern across
    // lines, so assert the key field-binding fragments individually.
    assert!(
        out.contains("let RecPointTag {"),
        "record destructure binder missing:\n{out}"
    );
    assert!(
        out.contains("point: (a, b),"),
        "nested tuple sub-pattern not rendered recursively:\n{out}"
    );
    assert!(
        out.contains("tag,") && out.contains(".."),
        "tag pun or wildcard missing:\n{out}"
    );
    Ok(())
}

#[test]
fn record_pattern_with_unknown_shape_fails_fast() -> DResult<()> {
    // A record pattern whose field set never appears in a signature: the lowerer
    // is contracted to surface every record type it destructures (the COMPLETE
    // field set), so this is an internal invariant violation — a `CompilerBug`,
    // not a silent mis-emit.
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let x = interner.intern("x")?;
    let func = interner.intern("f")?;
    let par = interner.intern("p")?;

    // f p = let { x = x } = p in x  — but f's signature is Int -> Int, so the
    // `{ x }` shape is never surfaced and cannot resolve to a struct.
    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: func,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(par, IrType::Int)],
        ret: IrType::Int,
        body: Expr::Destructure {
            binder: Pat::Record(vec![(x, Pat::Var(x))]),
            value: Box::new(Expr::Var(par)),
            body: Box::new(Expr::Var(x)),
        },
    };
    let prog = program(main_mod, vec![f_fn], None);
    let res = emit(&interner, &prog);
    assert!(
        matches!(res, Err(Diagnostic::CompilerBug { .. })),
        "unsurfaced record-pattern shape must be a CompilerBug, got {res:?}"
    );
    Ok(())
}

/// Full spine: build the `getX` record-destructure IR, emit the Cargo project,
/// vendor the runtime, `cargo build`, run, and assert the program prints `7` —
/// the value the backend produces for the field-set-equivalent program. Gated
/// on `IPE_E2E=1` so the default `cargo test` stays fast and offline.
#[test]
fn end_to_end_builds_and_prints_seven() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let mut interner = Interner::new();
    let prog = getx_program(&mut interner)?;
    let emitted = RustBackend::new(&interner).emit(&prog)?;

    let out = ipe_test_temp::temp_root().join("ipe_backend_record_patterns_e2e");
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
        "emitted record-pattern project must build: {status:?}"
    );

    let bin = target_dir.join("debug").join("ipe-app");
    let output = std::process::Command::new(&bin)
        .output()
        .map_err(|e| seal_e2e::io_bug(&bin, &e))?;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "7\n",
        "record-pattern program prints 7"
    );
    assert!(output.status.success(), "exit 0");
    if target_dir == out.join("target") {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
    Ok(())
}
