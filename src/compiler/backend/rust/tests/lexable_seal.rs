//! An Ipê text carrying characters the Rust lexer refuses raw never reaches
//! emitted Rust raw.
//!
//! The hazard value holds a RIGHT-TO-LEFT OVERRIDE (U+202E), a bare carriage
//! return and a LEFT-TO-RIGHT ISOLATE (U+2066): rustc refuses the two bidi
//! controls raw in a literal (deny-by-default
//! `text_direction_codepoint_in_literal`) and a bare CR raw anywhere. One
//! program carries the value in every user-reachable literal position the
//! backend renders: an `Expr::Str`, an `Expr::Char`, a whole-scrutinee
//! `Pat::Str`, a `Pat::Char`, and the synthesized string guard of a by-value
//! `Pat::Str` constructor payload. Every emitted `.rs` file must hold no lexer
//! hazard (`ipe_intern::find_lexer_hazard`), and under `IPE_E2E=1` the emitted
//! crate builds and prints the exact value. The hot-appearance `init`/`update`
//! datum literals are pinned in `hot_literal_bidi.rs`.

mod seal_e2e;

use std::collections::BTreeMap;

use ipe_backend::{Backend, EmittedProject};
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol, find_lexer_hazard};
use ipe_ir::{
    Arm, CallPin, Callee, EnumDef, Expr, Func, FuncId, IrType, KernelFn, Match, ModPath, Module,
    OnFormKind, Pat, Program, TypeDef, Variant,
};

/// The hazard value: two bidi controls and a bare CR between ASCII letters.
const HAZARD_VALUE: &str = "a\u{202E}\r\u{2066}b";

/// The hazard character an `Expr::Char` and a `Pat::Char` carry.
const HAZARD_CHAR: &str = "\u{202E}";

/// A call of `callee` on `args`.
const fn call(callee: Callee, args: Vec<Expr>) -> Expr {
    Expr::Call {
        callee,
        args,
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    }
}

/// A function with no type or row parameters.
const fn func(
    id: u32,
    name: Symbol,
    params: Vec<(Symbol, IrType)>,
    ret: IrType,
    body: Expr,
) -> Func {
    Func {
        id: FuncId::from_raw(id),
        name,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params,
        ret,
        body,
    }
}

/// The one-module program carrying [`HAZARD_VALUE`] in every literal position.
///
/// ```text
/// type Tag = A String | B
/// pick w = case w of A "<hazard>" -> "<hazard>" ; A _ -> "other" ; B -> "none"
/// same s = case s of "<hazard>" -> True ; _ -> False
/// isOverride c = case c of '\u{202E}' -> True ; _ -> False
/// overrideChar = '\u{202E}'
/// main = Io.println (pick (A "<hazard>"))
/// ```
#[allow(clippy::too_many_lines)] // one straight-line IR fixture
fn hazard_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let tag = interner.intern("Tag")?;
    let ctor_a = interner.intern("A")?;
    let ctor_b = interner.intern("B")?;
    let pick = interner.intern("pick")?;
    let same = interner.intern("same")?;
    let is_override = interner.intern("isOverride")?;
    let override_name = interner.intern("overrideChar")?;
    let main_name = interner.intern("main")?;
    let tagged = interner.intern("w")?;
    let text = interner.intern("s")?;
    let ch = interner.intern("c")?;

    let tag_ty = IrType::Enum {
        home: ModPath(vec![]),
        name: tag,
        args: vec![],
    };
    let def = EnumDef {
        name: tag,
        type_params: vec![],
        variants: vec![
            Variant {
                name: ctor_a,
                fields: vec![IrType::Str],
            },
            Variant {
                name: ctor_b,
                fields: vec![],
            },
        ],
        home: ModPath(vec![]),
    };
    let ctor_pat = |variant: Symbol, args: Vec<Pat>| Pat::Ctor {
        home: ModPath(vec![]),
        ty: tag,
        variant,
        args,
    };

    // `A "<hazard>"` renders as a fresh binder plus the `__sgN.as_str() == ..`
    // guard; the arm body is an `Expr::Str`.
    let pick_fn = func(
        0,
        pick,
        vec![(tagged, tag_ty)],
        IrType::Str,
        Expr::Match(Match::new(
            Expr::Var(tagged),
            vec![
                Arm::new(
                    ctor_pat(ctor_a, vec![Pat::Str(HAZARD_VALUE.to_owned())]),
                    Expr::Str(HAZARD_VALUE.to_owned()),
                ),
                Arm::new(
                    ctor_pat(ctor_a, vec![Pat::Wildcard]),
                    Expr::Str("other".to_owned()),
                ),
                Arm::new(ctor_pat(ctor_b, vec![]), Expr::Str("none".to_owned())),
            ],
            &[ctor_a, ctor_b],
        )?),
    );
    let same_fn = func(
        1,
        same,
        vec![(text, IrType::Str)],
        IrType::Bool,
        Expr::Match(Match::new_flat(
            Expr::Var(text),
            vec![
                Arm::new(Pat::Str(HAZARD_VALUE.to_owned()), Expr::Bool(true)),
                Arm::new(Pat::Wildcard, Expr::Bool(false)),
            ],
        )?),
    );
    let is_override_fn = func(
        2,
        is_override,
        vec![(ch, IrType::Char)],
        IrType::Bool,
        Expr::Match(Match::new_flat(
            Expr::Var(ch),
            vec![
                Arm::new(Pat::Char(HAZARD_CHAR.to_owned()), Expr::Bool(true)),
                Arm::new(Pat::Wildcard, Expr::Bool(false)),
            ],
        )?),
    );
    let override_fn = func(
        3,
        override_name,
        vec![],
        IrType::Char,
        Expr::Char(HAZARD_CHAR.to_owned()),
    );
    let main_fn = func(
        4,
        main_name,
        vec![],
        IrType::Task(Box::new(IrType::Unit)),
        call(
            Callee::Kernel(KernelFn::IoPrintln),
            vec![call(
                Callee::Func(FuncId::from_raw(0)),
                vec![Expr::Ctor {
                    home: ModPath(vec![]),
                    ty: tag,
                    variant: ctor_a,
                    args: vec![Expr::Str(HAZARD_VALUE.to_owned())],
                }],
            )],
        ),
    );

    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![TypeDef::Enum(def)],
            funcs: vec![pick_fn, same_fn, is_override_fn, override_fn, main_fn],
            entry: Some(FuncId::from_raw(4)),
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

/// Emit [`hazard_program`].
fn emit_hazard_program() -> DResult<(EmittedProject, String)> {
    let mut interner = Interner::new();
    let prog = hazard_program(&mut interner)?;
    let emitted = RustBackend::new(&interner).emit(&prog)?;
    let main =
        emitted
            .files
            .get("src/main.rs")
            .cloned()
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "lexable_seal test",
                detail: "no src/main.rs".to_owned(),
            })?;
    Ok((emitted, main))
}

/// Every emitted `.rs` file holds no lexer hazard, and each literal position
/// carries the hazard as an escape.
#[test]
fn every_literal_position_escapes_lexer_hazards() -> DResult<()> {
    let (emitted, main) = emit_hazard_program()?;
    for (path, text) in &emitted.files {
        if std::path::Path::new(path.as_str())
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
        {
            let hazard = find_lexer_hazard(text);
            assert!(hazard.is_none(), "{}: {hazard:?}", path.as_str());
        }
    }
    let escaped = r#""a\u{202e}\r\u{2066}b""#;
    assert!(
        main.contains(&format!("{escaped}.to_string()")),
        "the Expr::Str literal must carry the escaped value, got:\n{main}"
    );
    assert!(
        main.contains(&format!(".as_str() == {escaped}")),
        "the by-value Pat::Str guard must compare against the escaped value, got:\n{main}"
    );
    // Two `Expr::Str` sites (the `pick` arm body and the `A` ctor argument),
    // the guard and the whole-scrutinee `Pat::Str`.
    assert!(
        main.matches(escaped).count() >= 4,
        "every string position must render the escaped value, got:\n{main}"
    );
    assert!(
        main.contains(r"'\u{202e}'"),
        "the Expr::Char and Pat::Char literals must carry the escaped char, got:\n{main}"
    );
    Ok(())
}

/// Full spine: emit, vendor the runtime, `cargo build`, run, and assert the
/// program prints the exact hazard value. Gated on `IPE_E2E=1`.
#[test]
fn end_to_end_hazard_value_builds_and_prints() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let runtime = e2e_support::require_runtime().into_path_buf();
    let (emitted, _) = emit_hazard_program()?;

    let out = ipe_test_temp::temp_root().join("ipe_backend_lexable_seal_e2e");
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
        "the emitted project must build with the hazard value in every literal \
         position: {status:?}"
    );

    let bin = target_dir.join("debug").join("ipe-app");
    let output = std::process::Command::new(&bin)
        .output()
        .map_err(|e| seal_e2e::io_bug(&bin, &e))?;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{HAZARD_VALUE}\n"),
        "the program must print the exact hazard value"
    );
    assert!(output.status.success(), "exit 0");
    if target_dir == out.join("target") {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
    Ok(())
}

/// The split emit (`assemble_split_manifest`, the `ipe_db::emit_manifest` path
/// for a 2+-module program) refuses a raw lexer hazard in a per-module text
/// and in the spine text, past every renderer: both emit paths end at the one
/// lexability check, never only the single-file `emit_program`.
#[test]
fn split_emit_refuses_a_raw_lexer_hazard() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = hazard_program(&mut interner)?;
    let main_mod = interner.intern("Main")?;
    let clean_spine = "fn spine() {}\n";
    let clean_module = "pub fn f() {}\n".to_owned();
    let raw_module = format!("pub fn f() {{ let _ = \"{HAZARD_VALUE}\"; }}\n");
    let raw_spine = "// a\rb\nfn spine() {}\n";
    for (spine, module, shown) in [
        (clean_spine, raw_module, "U+202E"),
        (raw_spine, clean_module.clone(), "U+000D"),
    ] {
        let texts = BTreeMap::from([(ModPath(vec![main_mod]), module)]);
        let refused = RustBackend::new(&interner).assemble_split_manifest(&prog, spine, &texts);
        assert!(
            matches!(
                &refused,
                Err(Diagnostic::CompilerBug { where_, detail })
                    if *where_ == ipe_intern::EMIT_LEXABLE
                        && detail.contains(shown)
                        && find_lexer_hazard(detail).is_none()
            ),
            "a raw {shown} passed the split emit: {refused:?}"
        );
    }
    let texts = BTreeMap::from([(ModPath(vec![main_mod]), clean_module)]);
    let accepted = RustBackend::new(&interner).assemble_split_manifest(&prog, clean_spine, &texts);
    assert!(
        accepted.is_ok(),
        "a lexable split emit was refused: {accepted:?}"
    );
    Ok(())
}
