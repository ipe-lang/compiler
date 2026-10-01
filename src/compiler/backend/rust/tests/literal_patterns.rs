//! Literal-, alias- and wildcard-pattern rendering tests for the Rust
//! backend.
//!
//! These exercise the [`Pat`] additions the backend learned to render as flat
//! Rust match arms:
//!
//! * the LITERAL leaves [`Pat::Int`] / [`Pat::Bool`] / [`Pat::Char`] —
//!   rendered as the in-pattern Rust literals `0` / `true` / `'a'`, and
//!   [`Pat::Str`] — rendered NOT in-pattern (Rust cannot match an
//!   owned `String` against a `"..."` literal) but as a fresh binder plus an
//!   `if __sgN.as_str() == "lit"` match guard,
//! * the ALIAS / `as` binder [`Pat::Alias`] — rendered as the Rust binding-with-
//!   subpattern form `name @ <inner>`.
//!
//! The literal cases appear here as constructor-payload SUB-patterns so they
//! flow through `render_pat` (same-top-constructor literal discrimination —
//! `Wrap 0` vs `Wrap n` — is now lowered one arm per source arm; its end-to-end
//! regression lives in the `golden_m3b4_two_same_ctor` test).
//! They are render-only assertions: a single literal sub-pattern is not an
//! exhaustive cover of its scrutinee axis in Rust, so these programs are not
//! built — the literal's flat-arm SPELLING is what CORE pins. Exhaustiveness +
//! E2E for literals are covered by the lowering / types tests.
//!
//! The alias case IS exhaustive (a binder matches anything), so its emitted
//! crate builds and runs: `end_to_end_alias_binds_whole_value` (gated on
//! `IPE_E2E=1`) drives the hand-built IR through the Rust backend and asserts
//! `7`, matching the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` on the shape-equivalent
//!
//! ```text
//! type Wrap = MkWrap Int
//! f w = case w of MkWrap (x as y) -> y
//! main = Io.println (String.fromInt (f (MkWrap 7)))      -- prints 7
//! ```
//!
//! (hand-verified in a temp dir → stdout `7\n`, exit 0).

mod seal_e2e;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol};
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
            where_: "literal_patterns test",
            detail: "no src/main.rs".to_owned(),
        })
}

/// Build a one-function program whose single case arm matches `payload` as the
/// sole sub-pattern of an `A`-variant constructor (`type Tag = A Int | B`), so
/// the sub-pattern flows through `render_pat`. The `B` arm completes the
/// constructor cover. Returns `(program, the A variant symbol)`.
#[allow(clippy::too_many_lines)] // thorough constructor-cover fixture builder
fn tag_program(interner: &mut Interner, payload: Pat) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let tag = interner.intern("Tag")?;
    let a = interner.intern("A")?;
    let b = interner.intern("B")?;
    let f = interner.intern("f")?;
    let w = interner.intern("w")?;
    let zero = interner.intern("zero")?;

    let def = EnumDef {
        name: tag,
        type_params: vec![],
        variants: vec![
            Variant {
                name: a,
                fields: vec![IrType::Int],
            },
            Variant {
                name: b,
                fields: vec![],
            },
        ],
        home: ModPath(vec![]),
    };

    let arms = vec![
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: tag,
                variant: a,
                args: vec![payload],
            },
            body: Expr::Int(1),
            guard: None,
        },
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: tag,
                variant: b,
                args: vec![],
            },
            body: Expr::Int(0),
            guard: None,
        },
    ];
    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(
            w,
            IrType::Enum {
                home: ModPath(vec![]),
                name: tag,
                args: vec![],
            },
        )],
        ret: IrType::Int,
        body: Expr::Match(ipe_ir::Match::new(Expr::Var(w), arms, &[a, b])?),
    };

    // A trivial entry so the program is well-formed; `zero` keeps it minimal.
    let main_fn = Func {
        id: FuncId::from_raw(1),
        name: zero,
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
                        ty: tag,
                        variant: a,
                        args: vec![Expr::Int(0)],
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
            funcs: vec![f_fn, main_fn],
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
fn int_literal_subpattern_renders() -> DResult<()> {
    let mut i = Interner::new();
    let prog = tag_program(&mut i, Pat::Int(0))?;
    let src = emit(&i, &prog)?;
    assert!(
        src.contains("MainTag::A(0) =>"),
        "int literal sub-pattern must render as `0`; got:\n{src}"
    );
    Ok(())
}

#[test]
fn bool_literal_subpattern_renders() -> DResult<()> {
    let mut i = Interner::new();
    let prog = tag_program(&mut i, Pat::Bool(true))?;
    let src = emit(&i, &prog)?;
    assert!(
        src.contains("MainTag::A(true) =>"),
        "bool literal sub-pattern must render as `true`; got:\n{src}"
    );
    Ok(())
}

#[test]
fn char_literal_subpattern_renders() -> DResult<()> {
    let mut i = Interner::new();
    let prog = tag_program(&mut i, Pat::Char("a".to_owned()))?;
    let src = emit(&i, &prog)?;
    assert!(
        src.contains("MainTag::A('a') =>"),
        "char literal sub-pattern must render as `'a'`; got:\n{src}"
    );
    Ok(())
}

#[test]
fn char_literal_quote_escapes() -> DResult<()> {
    let mut i = Interner::new();
    let prog = tag_program(&mut i, Pat::Char("'".to_owned()))?;
    let src = emit(&i, &prog)?;
    assert!(
        src.contains(r"MainTag::A('\'') =>"),
        "single-quote char must escape to a valid Rust char literal; got:\n{src}"
    );
    Ok(())
}

#[test]
fn str_literal_subpattern_renders_and_escapes() -> DResult<()> {
    let mut i = Interner::new();
    let prog = tag_program(&mut i, Pat::Str("hi\"\n".to_owned()))?;
    let src = emit(&i, &prog)?;
    // A `Pat::Str` leaf does NOT render as an in-pattern string
    // literal (`MainTag::A("hi") =>`) — Rust cannot pattern-match an owned
    // `String` payload against a `"..."` literal. It renders as a fresh binder
    // plus an `if __sgN.as_str() == "lit"` match guard, which IS valid Rust and
    // preserves the same discrimination. The escaped literal must still appear
    // verbatim on the guard's right-hand side.
    assert!(
        src.contains(r#".as_str() == "hi\"\n""#),
        "string literal sub-pattern must render as an escaped `as_str() == \"lit\"` \
         match guard (#182); got:\n{src}"
    );
    Ok(())
}

/// The `Wrap` alias program: `f w = case w of MkWrap (x as y) -> y`. The `x as y`
/// alias renders `y @ x` and the whole match stays exhaustive (a binder matches
/// anything), so the emitted crate builds and runs.
#[allow(clippy::too_many_lines)] // fixture builder — length is the enumerated IR it constructs
fn alias_program(interner: &mut Interner) -> DResult<(Program, Symbol, Symbol)> {
    let main_mod = interner.intern("Main")?;
    let wrap = interner.intern("Wrap")?;
    let mk_wrap = interner.intern("MkWrap")?;
    let f = interner.intern("f")?;
    let main = interner.intern("main")?;
    let w = interner.intern("w")?;
    let x = interner.intern("x")?;
    let y = interner.intern("y")?;

    let def = EnumDef {
        name: wrap,
        type_params: vec![],
        variants: vec![Variant {
            name: mk_wrap,
            fields: vec![IrType::Int],
        }],
        home: ModPath(vec![]),
    };

    // f w = case w of MkWrap (x as y) -> y
    let arms = vec![Arm {
        pat: Pat::Ctor {
            home: ModPath(vec![]),
            ty: wrap,
            variant: mk_wrap,
            args: vec![Pat::Alias(Box::new(Pat::Var(x)), y)],
        },
        body: Expr::Var(y),
        guard: None,
    }];
    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f,
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

    // main = Io.println (String.fromInt (f (MkWrap 7)))
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
                        args: vec![Expr::Int(7)],
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

    Ok((
        Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(def)],
                funcs: vec![f_fn, main_fn],
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
        },
        x,
        y,
    ))
}

#[test]
fn alias_subpattern_renders_binding_with_subpattern() -> DResult<()> {
    let mut i = Interner::new();
    let (prog, _x, _y) = alias_program(&mut i)?;
    let src = emit(&i, &prog)?;
    // in a by-VALUE ctor-payload position the alias does NOT render
    // as `y @ x` (that spelling double-moves a non-`Copy` payload — sound
    // only under a by-ref binding mode). It binds a fresh temp and
    // re-derives both binders in the arm prelude via the clone-rebuild
    // strategy: `MkWrap(__ipe_arm_alias_0) => { let y = __ipe_arm_alias_0;
    // let x = y.clone(); … }`.
    assert!(
        src.contains("MainWrap::MkWrap(__ipe_arm_alias_0) =>"),
        "alias pattern must bind a temp in a by-value ctor payload; got:\n{src}"
    );
    assert!(
        src.contains("let y = __ipe_arm_alias_0;"),
        "alias binder must re-derive from the temp; got:\n{src}"
    );
    assert!(
        src.contains("let x = y.clone();"),
        "inner binder must re-derive from a clone of the alias binder; got:\n{src}"
    );
    Ok(())
}

/// Full spine: build the alias `Wrap` IR, emit, vendor the runtime, `cargo
/// build`, run, and assert `7` — the expected value for `f (MkWrap 7)` where
/// the `as` binder rebinds the whole matched payload. Gated on `IPE_E2E=1`.
#[test]
fn end_to_end_alias_binds_whole_value() -> DResult<()> {
    let mut interner = Interner::new();
    let (prog, _x, _y) = alias_program(&mut interner)?;
    build_and_assert(&interner, &prog, "ipe_backend_alias_wrap_e2e", "7\n")
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
        "emitted alias-pattern project must build: {status:?}"
    );

    let bin = target_dir.join("debug").join("ipe-app");
    let output = std::process::Command::new(&bin)
        .output()
        .map_err(|e| seal_e2e::io_bug(&bin, &e))?;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected,
        "alias-pattern program output must match golden"
    );
    assert!(output.status.success(), "exit 0");
    if target_dir == out.join("target") {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
    Ok(())
}
