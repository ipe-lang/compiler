//! The hot-appearance baked datum never reaches emitted Rust with a raw bidi
//! or control character.
//!
//! `rust_str_lit` wraps the baked `init`/`update`/`Sub` JSON datum, which
//! `write_json_string` leaves raw for every codepoint `>= 0x20`, as a Rust
//! string literal through Rust's `Debug` grammar. A raw U+202E (RIGHT-TO-LEFT
//! OVERRIDE) in that literal would trip rustc's deny-by-default
//! `text_direction_codepoint_in_literal` lint after `ipe` accepted the program.
//!
//! Two sites build this literal, `emit_init_datum` (a data-describable `init`)
//! and `emit_transition_arm` (a data-describable `update` arm); both are
//! exercised here through the public [`RustBackend`] emit path.

mod seal_e2e;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    Arm, CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, Match, ModPath, Module, OnFormKind,
    Pat, Program,
};
use std::collections::BTreeMap;

/// The hazardous record-field value: an ASCII letter, a RIGHT-TO-LEFT OVERRIDE,
/// then another ASCII letter.
const BIDI_VALUE: &str = "a\u{202E}b";

/// The same character alone, for a raw-byte presence check.
const BIDI_CHAR: char = '\u{202E}';

/// A single-module, hot-appearance-shaped program with the given funcs and
/// entry. `uses_tea` (the `IpeCmd<M>`/`IpeSub<M>` type aliases) and `uses_web`
/// (the Live web-app runtime, which owns `apply_init_hot`/`apply_transition_hot`)
/// are on — the flags a real `Web.tea` program sets.
fn tea_program(name: Symbol, funcs: Vec<Func>, entry: Option<FuncId>) -> Program {
    Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![name]),
            types: vec![],
            funcs,
            entry,
            records: vec![],
            uses_tea: true,
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
            uses_web: true,
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

/// `Cmd.none` — the nullary `CmdNone` kernel call.
const fn cmd_none() -> Expr {
    Expr::Call {
        callee: Callee::Kernel(KernelFn::CmdNone),
        args: vec![],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    }
}

/// Emit `prog` under the hot-appearance flag and return its `src/main.rs` text.
fn emit_hot(interner: &Interner, prog: &Program) -> DResult<String> {
    let emitted = RustBackend::new(interner)
        .with_hot_appearance(true)
        .emit(prog)?;
    emitted
        .files
        .get("src/main.rs")
        .cloned()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "hot_literal_bidi test",
            detail: "no src/main.rs".to_owned(),
        })
}

/// A one-field `{ name : String }` record type.
fn name_record(name_sym: Symbol) -> IrType {
    let mut fields = BTreeMap::new();
    fields.insert(name_sym, IrType::Str);
    IrType::Record(fields)
}

/// A data-describable `init`-shaped function: `() -> ({ name = "a\u{202E}b" },
/// Cmd.none)`. `func_returns_cmd_tuple` arms `emit_init_datum` on any function
/// of this return shape, not only one literally named `init`.
fn init_hot_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let name_sym = interner.intern("name")?;
    let init_name = interner.intern("mkInit")?;
    let rec = name_record(name_sym);

    let init_fn = Func {
        id: FuncId::from_raw(0),
        name: init_name,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Tuple(vec![rec.clone(), IrType::Cmd(Box::new(IrType::Int))]),
        body: Expr::Tuple(vec![
            Expr::Record {
                fields: vec![(name_sym, Expr::Str(BIDI_VALUE.to_owned()))],
                ty: Some(rec),
            },
            cmd_none(),
        ]),
    };

    Ok(tea_program(main_mod, vec![init_fn], None))
}

#[test]
fn init_datum_escapes_bidi_override() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = init_hot_program(&mut interner)?;
    let out = emit_hot(&interner, &prog)?;

    assert!(
        out.contains("ipe_runtime::web::apply_init_hot("),
        "the data-describable init must reduce to apply_init_hot, got:\n{out}"
    );
    assert!(
        out.contains("\\u{202e}"),
        "the baked datum literal must carry the bidi override as a \\u{{..}} \
         escape, got:\n{out}"
    );
    assert!(
        !out.contains(BIDI_CHAR),
        "the emitted source must never carry the raw bidi override byte \
         (an ipe-accepts-then-cargo-fails SEAL break via rustc's \
         text_direction_codepoint_in_literal lint), got:\n{out}"
    );
    Ok(())
}

/// A data-describable `update`-shaped function: `Model -> (Model, Cmd.none)`
/// whose one arm (a flat wildcard match standing in for a `Msg` case) sets
/// `name` to `"a\u{202E}b"`. `tea_update_model_param` arms `emit_transition_arm`
/// on any function of this return shape, keyed off the last parameter.
fn update_hot_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let name_sym = interner.intern("name")?;
    let model_sym = interner.intern("model")?;
    let update_name = interner.intern("upd")?;
    let rec = name_record(name_sym);

    let arm_body = Expr::Tuple(vec![
        Expr::Update {
            record: Box::new(Expr::Var(model_sym)),
            fields: vec![(name_sym, Expr::Str(BIDI_VALUE.to_owned()))],
        },
        cmd_none(),
    ]);
    // A flat, exhaustive match (bare wildcard arm) stands in for the `Msg` case
    // the real lowerer produces — `transition_of_arm` only looks at the arm
    // BODY, never the scrutinee or pattern shape.
    let case = Match::new_flat(Expr::Bool(true), vec![Arm::new(Pat::Wildcard, arm_body)])?;

    let update_fn = Func {
        id: FuncId::from_raw(0),
        name: update_name,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![ipe_ir::Param::owned(model_sym, rec.clone())],
        ret: IrType::Tuple(vec![rec, IrType::Cmd(Box::new(IrType::Int))]),
        body: Expr::Match(case),
    };

    Ok(tea_program(main_mod, vec![update_fn], None))
}

#[test]
fn transition_arm_escapes_bidi_override() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = update_hot_program(&mut interner)?;
    let out = emit_hot(&interner, &prog)?;

    assert!(
        out.contains("ipe_runtime::web::apply_transition_hot("),
        "the data-describable update arm must reduce to apply_transition_hot, \
         got:\n{out}"
    );
    assert!(
        out.contains("\\u{202e}"),
        "the baked transition literal must carry the bidi override as a \
         \\u{{..}} escape, got:\n{out}"
    );
    assert!(
        !out.contains(BIDI_CHAR),
        "the emitted source must never carry the raw bidi override byte, got:\n{out}"
    );
    Ok(())
}

/// Full spine: build the init-hot program, emit it, vendor the runtime, `cargo
/// build`, run it, and assert the program's own stdout carries the DECODED
/// string (the raw bidi override between its two ASCII letters) — proving
/// `apply_init_hot` round-trips the baked datum and the emitted crate builds
/// despite the hazardous codepoint. Gated on `IPE_E2E=1` so the default `cargo
/// test` stays fast and offline.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one straight-line fixture: build the IR, emit, vendor the runtime, cargo build, \
              run, assert — splitting would thread the same locals through helpers with no \
              clarity gain"
)]
fn end_to_end_hot_init_renders_bidi_string() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let name_sym = interner.intern("name")?;
    let model_sym = interner.intern("model")?;
    let main_name = interner.intern("main")?;
    let init_name = interner.intern("mkInit")?;
    let rec = name_record(name_sym);

    let init_fn = Func {
        id: FuncId::from_raw(0),
        name: init_name,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Tuple(vec![rec.clone(), IrType::Cmd(Box::new(IrType::Int))]),
        body: Expr::Tuple(vec![
            Expr::Record {
                fields: vec![(name_sym, Expr::Str(BIDI_VALUE.to_owned()))],
                ty: Some(rec),
            },
            cmd_none(),
        ]),
    };

    // `main = let (model, _) = mkInit () in Io.println model.name` — prints
    // the DECODED field, proving `apply_init_hot` round-tripped the baked datum
    // through the hazardous codepoint.
    let main_fn = Func {
        id: FuncId::from_raw(1),
        name: main_name,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: Expr::Destructure {
            binder: Pat::Tuple(vec![Pat::Var(model_sym), Pat::Wildcard]),
            value: Box::new(Expr::Call {
                callee: Callee::Func(FuncId::from_raw(0)),
                args: vec![],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            }),
            body: Box::new(Expr::Call {
                callee: Callee::Kernel(KernelFn::IoPrintln),
                args: vec![Expr::Access {
                    record: Box::new(Expr::Var(model_sym)),
                    field: name_sym,
                    field_ty: IrType::Str,
                }],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            }),
        },
    };

    let prog = tea_program(main_mod, vec![init_fn, main_fn], Some(FuncId::from_raw(1)));
    let emitted = RustBackend::new(&interner)
        .with_hot_appearance(true)
        .emit(&prog)?;

    let run =
        seal_e2e::build_and_run_emitted(&emitted, &runtime, "ipe_backend_hot_literal_bidi_e2e")?
            .map_err(seal_e2e::build_bug)?;
    assert_eq!(run.exit_code, Some(0), "exit 0");
    assert_eq!(
        run.stdout,
        format!("{BIDI_VALUE}\n"),
        "the hot-reduced init must decode and print the exact source string, \
         bidi override included"
    );
    Ok(())
}
