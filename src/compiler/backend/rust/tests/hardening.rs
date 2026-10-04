//! Hardening regression tests for the Rust backend.
//!
//! These exercise the failure-fast and identifier-safety guards that sit
//! *around* the byte-identical golden emission:
//!
//! * reserved-Rust-name mangling at variant / param emit sites,
//! * the bounded emit-depth guard (IPE-L0200) instead of a native stack
//!   overflow on a deeply nested expression,
//! * the checked ident resolver (IPE-I0201) refusing to emit an empty Rust
//!   identifier,
//! * the cross-module type-name collision guard (IPE-N0012, formerly IPE-I0202).
//!
//! The golden byte-equality contract itself lives in `golden.rs`.

use std::collections::BTreeMap;

use ipe_backend::Backend;
use ipe_backend_rust::{FfiEmit, FfiWrapperGlue, RustBackend};
use ipe_diagnostics::{DResult, Diagnostic, IPE_I0201, IPE_L0200, IPE_N0012};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    Arm, BinOp, CallPin, Callee, EnumDef, Expr, Func, FuncId, IrType, Match, ModPath, Module,
    OnFormKind, Pat, Program, SliceOwnership, TypeDef, Variant,
};

/// A single-module program with the given types and funcs (no entry needed:
/// emission does not require one).
fn program(name: Symbol, types: Vec<TypeDef>, funcs: Vec<Func>) -> Program {
    Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![name]),
            types,
            funcs,
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
    }
}

fn emit(interner: &Interner, program: &Program) -> DResult<String> {
    let emitted = RustBackend::new(interner).emit(program)?;
    emitted
        .files
        .get("src/main.rs")
        .cloned()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "hardening test",
            detail: "no src/main.rs".to_owned(),
        })
}

/// A reserved Rust keyword used as a variant name and a param name must be
/// mangled (`type` → `type_`) so the emitted Rust compiles — while the enum's
/// `ipe_show` keeps the original Ipê spelling.
#[test]
fn reserved_names_are_mangled_in_emitted_output() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let kw_ty = interner.intern("Kw")?;
    // Lowercase Rust keywords used as a variant and a parameter name.
    let variant = interner.intern("type")?;
    let param = interner.intern("match")?;
    let func = interner.intern("render")?;

    let en = EnumDef {
        name: kw_ty,
        type_params: vec![],
        variants: vec![Variant {
            name: variant,
            fields: vec![],
        }],
        home: ModPath(vec![]),
    };
    let render_fn = Func {
        id: FuncId::from_raw(0),
        name: func,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(param, IrType::Int)],
        ret: IrType::Int,
        body: Expr::Var(param),
    };

    let prog = program(main_mod, vec![TypeDef::Enum(en)], vec![render_fn]);
    let out = emit(&interner, &prog)?;

    // Variant declared and matched under its mangled Rust name…
    assert!(out.contains("    type_,\n"), "variant not mangled:\n{out}");
    assert!(
        out.contains("MainKw::type_ => \"type\".to_string(),"),
        "ipe_show must mangle the ident but keep the Ipe display name:\n{out}"
    );
    // …and the keyword parameter is mangled too, with a valid body reference.
    assert!(
        out.contains("pub fn main_render(match_: i64) -> i64 {"),
        "param not mangled:\n{out}"
    );
    assert!(out.contains("    match_\n}"), "var ref not mangled:\n{out}");
    Ok(())
}

/// A deeply nested `BinOp` spine must fail fast with IPE-L0200, not overflow the
/// native stack. The chain is built well past the backend's emit-depth bound.
#[test]
fn deeply_nested_expr_fails_fast_not_stack_overflow() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("deep")?;

    // 4096 left-nested additions: (((… + 1) + 1) + 1). The leaf sits far below
    // the backend's MAX_EMIT_DEPTH (~96), so the guard trips long before.
    let mut body = Expr::Int(0);
    for _ in 0..4096 {
        body = Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(body),
            rhs: Box::new(Expr::Int(1)),
        };
    }
    let deep_fn = Func {
        id: FuncId::from_raw(0),
        name: func,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Int,
        body,
    };

    let prog = program(main_mod, vec![], vec![deep_fn]);
    let res = emit(&interner, &prog);
    assert!(res.is_err(), "deep nesting must error, got {res:?}");
    if let Err(err) = res {
        assert_eq!(err.code(), IPE_L0200, "wrong code for over-deep nesting");
        assert!(
            matches!(err, Diagnostic::Lower { .. }),
            "expected a Lower diagnostic, got {err:?}"
        );
    }
    Ok(())
}

/// An expression at the depth bound still emits successfully — the guard is a
/// ceiling, not an off-by-one rejection of legitimate programs.
#[test]
fn nesting_at_the_bound_still_emits() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("ok")?;

    // 64 levels: comfortably under the emit-depth ceiling.
    let mut body = Expr::Int(0);
    for _ in 0..64 {
        body = Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(body),
            rhs: Box::new(Expr::Int(1)),
        };
    }
    let ok_fn = Func {
        id: FuncId::from_raw(0),
        name: func,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Int,
        body,
    };
    let prog = program(main_mod, vec![], vec![ok_fn]);
    assert!(emit(&interner, &prog).is_ok(), "in-bound nesting must emit");
    Ok(())
}

/// A param symbol that resolves to the empty string is a dangling-symbol
/// invariant violation: emit must fail with IPE-I0201, never produce an empty
/// Rust identifier.
#[test]
fn empty_intended_symbol_is_rejected() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("f")?;
    // An interned *empty* identifier — a dangling/empty-intended symbol the
    // lowerer must never produce.
    let empty = interner.intern("")?;

    let f = Func {
        id: FuncId::from_raw(0),
        name: func,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(empty, IrType::Int)],
        ret: IrType::Int,
        body: Expr::Int(0),
    };
    let prog = program(main_mod, vec![], vec![f]);
    let res = emit(&interner, &prog);
    assert!(res.is_err(), "empty ident must error, got {res:?}");
    if let Err(err) = res {
        assert_eq!(err.code(), IPE_I0201, "wrong code for dangling symbol");
    }
    Ok(())
}

/// Two modules declaring a same-named type intern to the same `Symbol`; the
/// backend cannot tell them apart from the bare key, so it must fail fast with
/// IPE-I0202 rather than silently overwrite one mapping.
#[test]
#[allow(clippy::too_many_lines)] // two full body-free Module literals inline
fn cross_module_type_name_collision_is_rejected() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let other_mod = interner.intern("Other")?;
    // Same Ipê type name in both modules → the *same* interned Symbol.
    let msg = interner.intern("Msg")?;
    let inc = interner.intern("Increment")?;

    let make_enum = || {
        TypeDef::Enum(EnumDef {
            name: msg,
            type_params: vec![],
            variants: vec![Variant {
                name: inc,
                fields: vec![],
            }],
            home: ModPath(vec![]),
        })
    };
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![
            Module {
                name: ModPath(vec![main_mod]),
                types: vec![make_enum()],
                funcs: vec![],
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
            },
            Module {
                name: ModPath(vec![other_mod]),
                types: vec![make_enum()],
                funcs: vec![],
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
            },
        ],
    };

    let res = RustBackend::new(&interner).emit(&prog);
    assert!(res.is_err(), "type-name collision must error, got {res:?}");
    if let Err(err) = res {
        // Pre-Defect-2-fix: IPE-I0202 (CompilerBug). Post-fix: clean IPE-N0012
        // (NameError::DuplicateType) so the user sees a structured error not an ICE.
        assert_eq!(err.code(), IPE_N0012, "wrong code for type-name collision");
    }
    Ok(())
}

/// `Expr::Let`, `Expr::If`, and the extended `BinOp` set emit total,
/// well-formed Rust even though the frontend does not yet produce them. The
/// `let`/`if` forms render as self-contained parenthesised expressions so they
/// compose anywhere an expression is expected, and `/=` maps to Rust `!=`.
#[test]
fn let_if_and_extended_binops_emit_total_rust() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let f = interner.intern("f")?;
    let n = interner.intern("n")?;
    let x = interner.intern("x")?;

    // f(n : Int) -> Int =
    //   let x = n * 2 in
    //     if (x >= 10) && (x /= 0) then x / 2 else x + 1
    let body = Expr::Let {
        name: x,
        value: Box::new(Expr::BinOp {
            op: BinOp::IntMul,
            lhs: Box::new(Expr::Var(n)),
            rhs: Box::new(Expr::Int(2)),
        }),
        body: Box::new(Expr::If {
            cond: Box::new(Expr::BinOp {
                op: BinOp::And,
                lhs: Box::new(Expr::BinOp {
                    op: BinOp::Ge,
                    lhs: Box::new(Expr::Var(x)),
                    rhs: Box::new(Expr::Int(10)),
                }),
                rhs: Box::new(Expr::BinOp {
                    op: BinOp::Neq,
                    lhs: Box::new(Expr::Var(x)),
                    rhs: Box::new(Expr::Int(0)),
                }),
            }),
            then_: Box::new(Expr::BinOp {
                op: BinOp::Div,
                lhs: Box::new(Expr::Var(x)),
                rhs: Box::new(Expr::Int(2)),
            }),
            else_: Box::new(Expr::BinOp {
                op: BinOp::IntAdd,
                lhs: Box::new(Expr::Var(x)),
                rhs: Box::new(Expr::Int(1)),
            }),
        }),
    };
    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(n, IrType::Int)],
        ret: IrType::Int,
        body,
    };

    let out = emit(&interner, &program(main_mod, vec![], vec![f_fn]))?;
    // Rustfmt reformats the emitted let/if block onto multiple lines; assert the
    // key semantic fragments rather than a single-line snapshot.
    // Int `*` emits via the wrapping helper; Float `/` stays infix.
    assert!(
        out.contains("let x = ipe_runtime::math::ipe_int_mul(n, 2i64);"),
        "let binding not emitted:\n{out}"
    );
    assert!(
        out.contains("(if ((x >= 10i64) && (x != 0i64))"),
        "if condition not emitted:\n{out}"
    );
    assert!(
        out.contains("(x / 2i64)") && out.contains("ipe_runtime::math::ipe_int_add(x, 1i64)"),
        "if branches not emitted:\n{out}"
    );
    Ok(())
}

/// A tuple type in a return position and a tuple constructor in the body emit
/// as genuine Rust tuples: `(i64, i64)` and `(x, 1)`.
#[test]
fn tuple_type_and_expr_emit_as_rust_tuples() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let f = interner.intern("pair")?;
    let n = interner.intern("n")?;

    // pair(n : Int) -> (Int, Int) = (n, 1)
    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(n, IrType::Int)],
        ret: IrType::Tuple(vec![IrType::Int, IrType::Int]),
        body: Expr::Tuple(vec![Expr::Var(n), Expr::Int(1)]),
    };

    let out = emit(&interner, &program(main_mod, vec![], vec![f_fn]))?;
    assert!(
        out.contains("-> (i64, i64)"),
        "tuple return type did not emit:\n{out}"
    );
    assert!(out.contains("(n, 1i64)"), "tuple expr did not emit:\n{out}");
    Ok(())
}

/// CO-BACKEND-005: `Expr::Char` carrying anything but exactly one character
/// is an internal invariant violation (the lexer's char-literal invariant
/// broke somewhere upstream) — it must fail closed as a `CompilerBug`, never
/// silently emit a Rust STRING literal in `char` position (invalid Rust,
/// `cargo`-fails E0308 — the exit-0-then-cargo-fail shape THE SEAL forbids).
#[test]
fn malformed_char_literal_fails_closed_not_invalid_rust() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let f = interner.intern("bad")?;

    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Char,
        // A malformed char literal — two characters, never producible by the
        // real lexer, built directly to reach the emitter's fallback arm.
        body: Expr::Char("ab".to_owned()),
    };

    let res = emit(&interner, &program(main_mod, vec![], vec![f_fn]));
    assert!(
        res.is_err(),
        "a malformed char literal must fail closed, got {res:?}"
    );
    if let Err(err) = res {
        assert!(
            matches!(err, Diagnostic::CompilerBug { .. }),
            "expected a CompilerBug, got {err:?}"
        );
    }
    Ok(())
}

/// `Pat::Char` carrying anything but exactly one character fails closed as
/// a `CompilerBug` — the same policy `Expr::Char` applies. A string literal
/// in char-pattern position is invalid Rust (E0308, cargo-fails), the exact
/// exit-0-then-cargo-fail shape THE SEAL forbids.
#[test]
fn malformed_char_pattern_fails_closed_not_invalid_rust() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let tag_sym = interner.intern("Tag")?;
    let a_sym = interner.intern("A")?;
    let b_sym = interner.intern("B")?;
    let f_sym = interner.intern("f")?;
    let w_sym = interner.intern("w")?;

    let def = EnumDef {
        name: tag_sym,
        type_params: vec![],
        variants: vec![
            Variant {
                name: a_sym,
                fields: vec![IrType::Char],
            },
            Variant {
                name: b_sym,
                fields: vec![],
            },
        ],
        home: ModPath(vec![]),
    };
    let arms = vec![
        Arm {
            // A malformed char pattern — two characters, built directly to
            // reach the pattern emitter's guard.
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: tag_sym,
                variant: a_sym,
                args: vec![Pat::Char("xy".to_owned())],
            },
            body: Expr::Int(1),
            guard: None,
        },
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: tag_sym,
                variant: b_sym,
                args: vec![],
            },
            body: Expr::Int(0),
            guard: None,
        },
    ];
    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f_sym,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(
            w_sym,
            IrType::Enum {
                home: ModPath(vec![]),
                name: tag_sym,
                args: vec![],
            },
        )],
        ret: IrType::Int,
        body: Expr::Match(Match::new(Expr::Var(w_sym), arms, &[a_sym, b_sym])?),
    };

    let res = emit(
        &interner,
        &program(main_mod, vec![TypeDef::Enum(def)], vec![f_fn]),
    );
    assert!(
        res.is_err(),
        "a malformed char pattern must fail closed, got {res:?}"
    );
    if let Err(err) = res {
        assert!(
            matches!(err, Diagnostic::CompilerBug { .. }),
            "expected a CompilerBug, got {err:?}"
        );
    }
    Ok(())
}

/// A valid single-char `Pat::Char` renders as the Rust char literal — the
/// positive counterpart to `malformed_char_pattern_fails_closed_not_invalid_rust`.
#[test]
fn valid_char_pattern_emits_char_literal() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let tag_sym = interner.intern("Tag")?;
    let a_sym = interner.intern("A")?;
    let b_sym = interner.intern("B")?;
    let f_sym = interner.intern("f")?;
    let w_sym = interner.intern("w")?;

    let def = EnumDef {
        name: tag_sym,
        type_params: vec![],
        variants: vec![
            Variant {
                name: a_sym,
                fields: vec![IrType::Char],
            },
            Variant {
                name: b_sym,
                fields: vec![],
            },
        ],
        home: ModPath(vec![]),
    };
    let arms = vec![
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: tag_sym,
                variant: a_sym,
                args: vec![Pat::Char("z".to_owned())],
            },
            body: Expr::Int(1),
            guard: None,
        },
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: tag_sym,
                variant: b_sym,
                args: vec![],
            },
            body: Expr::Int(0),
            guard: None,
        },
    ];
    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f_sym,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(
            w_sym,
            IrType::Enum {
                home: ModPath(vec![]),
                name: tag_sym,
                args: vec![],
            },
        )],
        ret: IrType::Int,
        body: Expr::Match(Match::new(Expr::Var(w_sym), arms, &[a_sym, b_sym])?),
    };

    let src = emit(
        &interner,
        &program(main_mod, vec![TypeDef::Enum(def)], vec![f_fn]),
    )?;
    assert!(
        src.contains("'z'"),
        "single-char pattern must render as a Rust char literal; got:\n{src}"
    );
    Ok(())
}

/// An FFI callee ident that is not a legal Rust identifier fails closed as a
/// `CompilerBug` — it must never splice an unchecked string into `crate::ffi::<ident>`.
#[test]
fn ffi_callee_illegal_ident_fails_closed() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let f_sym = interner.intern("f")?;
    // A shell-injection-shaped string that is not a valid Rust identifier.
    let bad_ident = interner.intern("; std::process::exit(1)")?;

    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f_sym,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Int,
        body: Expr::Call {
            callee: Callee::Ffi {
                ident: bad_ident,
                asserted: false,
            },
            args: vec![],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    };

    let res = emit(&interner, &program(main_mod, vec![], vec![f_fn]));
    assert!(
        res.is_err(),
        "an illegal FFI callee ident must fail closed, got {res:?}"
    );
    if let Err(err) = res {
        assert!(
            matches!(err, Diagnostic::CompilerBug { .. }),
            "expected a CompilerBug, got {err:?}"
        );
    }
    Ok(())
}

/// A valid FFI callee ident emits `crate::ffi::<ident>` — the positive
/// counterpart to `ffi_callee_illegal_ident_fails_closed`.
#[test]
fn ffi_callee_valid_ident_emits_crate_ffi_path() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let f_sym = interner.intern("f")?;
    let good_ident = interner.intern("semver_parse")?;

    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: f_sym,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Int,
        body: Expr::Call {
            callee: Callee::Ffi {
                ident: good_ident,
                asserted: false,
            },
            args: vec![],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    };

    let src = emit(&interner, &program(main_mod, vec![], vec![f_fn]))?;
    assert!(
        src.contains("crate::ffi::semver_parse"),
        "valid FFI callee must emit `crate::ffi::semver_parse`; got:\n{src}"
    );
    Ok(())
}

/// CO-BACKEND-004: a glued FFI wrapper whose interned ident string is not a
/// legal Rust identifier must fail closed as a `CompilerBug` — never silently
/// splice the raw string into `crate::ffi::{name}` and produce emitted Rust
/// that fails to compile (the SEAL-violating exit-0-then-cargo-fail class).
///
/// This exercises the `emit_ffi_glued_call` path specifically: the
/// `wrapper_glue` map contains the illegal ident, so `ffi_call_has_glue`
/// returns `true` and the glued code path fires.  The shared `ffi_path`
/// helper must intercept the bad name and surface `Diagnostic::CompilerBug`
/// rather than forwarding it to Rustc.
#[test]
fn glued_ffi_wrapper_with_illegal_ident_fails_closed() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func_name = interner.intern("call_bad_ffi")?;
    // An ident that starts with a digit is never a legal Rust identifier.
    let bad_ident_str = "2bad";
    let bad_ident = interner.intern(bad_ident_str)?;

    // Wire glue for the illegal ident so `ffi_call_has_glue` returns `true`
    // and `emit_ffi_glued_call` is reached.  The simplest glue: no argument
    // conversions, no result conversion (infallible, opaque pass-through
    // shape) — just enough to trigger the glued code path.
    let mut wrapper_glue = BTreeMap::new();
    wrapper_glue.insert(
        bad_ident_str.to_owned(),
        FfiWrapperGlue {
            params: vec![],
            result: None,
        },
    );
    let ffi = FfiEmit {
        wrapper_glue,
        ..FfiEmit::default()
    };

    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: func_name,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Int,
        body: Expr::Call {
            callee: Callee::Ffi {
                ident: bad_ident,
                asserted: false,
            },
            args: vec![],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    };

    let prog = program(main_mod, vec![], vec![f_fn]);
    let res = RustBackend::new(&interner).with_ffi(Some(ffi)).emit(&prog);

    assert!(
        res.is_err(),
        "a glued FFI wrapper with an illegal ident must fail closed, got {res:?}"
    );
    if let Err(err) = res {
        assert!(
            matches!(err, Diagnostic::CompilerBug { .. }),
            "expected a CompilerBug, got {err:?}"
        );
    }
    Ok(())
}

/// CO-BACKEND-005: a tuple-scrutinee `match` whose arm patterns disagree on
/// arity (an internal invariant violation the frontend's Maranget check
/// would never let through — built directly here) must fail closed as a
/// `CompilerBug` when a later arm's pattern reaches past the column table
/// sized from an earlier, narrower arm — never silently default the missing
/// column to `str_mode: false, list: ListView::Off`, which can emit a binder of
/// the wrong type (an exit-0-then-cargo-fail THE SEAL forbids).
#[test]
fn tuple_arm_wider_than_column_table_fails_closed() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("bad")?;
    let narrow0 = interner.intern("narrow0")?;
    let narrow1 = interner.intern("narrow1")?;
    let wide0 = interner.intern("wide0")?;
    let wide1 = interner.intern("wide1")?;
    let wide2 = interner.intern("wide2")?;

    // A 2-element scrutinee tuple; the first arm's arity (2) sizes the
    // column table, but the second arm's pattern is a 3-element tuple.
    let arms = vec![
        Arm::new(
            Pat::Tuple(vec![Pat::Var(narrow0), Pat::Var(narrow1)]),
            Expr::Var(narrow0),
        ),
        Arm::new(
            Pat::Tuple(vec![Pat::Var(wide0), Pat::Var(wide1), Pat::Var(wide2)]),
            Expr::Var(wide0),
        ),
    ];
    let scrutinee = Expr::Tuple(vec![Expr::Int(1), Expr::Int(2)]);
    let f_fn = Func {
        id: FuncId::from_raw(0),
        name: func,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Int,
        body: Expr::Match(Match::new_flat(scrutinee, arms)?),
    };

    let res = emit(&interner, &program(main_mod, vec![], vec![f_fn]));
    assert!(
        res.is_err(),
        "a wider-than-scrutinee arm must fail closed, got {res:?}"
    );
    if let Err(err) = res {
        assert!(
            matches!(err, Diagnostic::CompilerBug { .. }),
            "expected a CompilerBug, got {err:?}"
        );
    }
    Ok(())
}

/// Two distinct Ipê values whose snake-case fold collides
/// (`firstName` and `first_name` in one module both mangle to
/// `main_first_name`) are a LEGAL program: the non-injective fold must
/// disambiguate the loser to a distinct Rust name so both functions emit,
/// rather than reject the program.
#[test]
fn colliding_value_fold_disambiguates_and_emits() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let camel = interner.intern("firstName")?;
    let snake = interner.intern("first_name")?;

    let mk = |id: u32, name: Symbol| Func {
        id: FuncId::from_raw(id),
        name,
        home: ModPath(vec![main_mod]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Int,
        body: Expr::Int(0),
    };
    let prog = program(main_mod, vec![], vec![mk(0, camel), mk(1, snake)]);
    let src = emit(&interner, &prog)?;
    // Both functions are present under distinct names: the base name and its
    // deterministic `_2` disambiguation.
    assert!(
        src.contains("fn main_first_name(") && src.contains("fn main_first_name_2("),
        "both colliding values must emit under distinct names, got:\n{src}"
    );
    Ok(())
}

/// Two distinct Ipê types in different modules whose camel-case fold collides
/// (module `Std.Palette` type `Color` and module `Std` type `PaletteColor`
/// both mangle to `StdPaletteColor`) are a LEGAL program: the non-injective
/// fold must disambiguate the loser so both enums emit, rather than reject the
/// program. Emitting them from distinct modules (empty `home`, so each folds
/// from its own module name) mirrors the real cross-module collision.
#[test]
#[allow(clippy::too_many_lines)] // two full body-free Module literals inline
fn colliding_type_fold_disambiguates_and_emits() -> DResult<()> {
    let mut interner = Interner::new();
    let std_palette = interner.intern("StdPalette")?;
    let std_mod = interner.intern("Std")?;
    let color = interner.intern("Color")?;
    let palette_color = interner.intern("PaletteColor")?;
    let unit = interner.intern("Unit")?;

    let mk_enum = |name: Symbol| {
        TypeDef::Enum(EnumDef {
            name,
            type_params: vec![],
            variants: vec![Variant {
                name: unit,
                fields: vec![],
            }],
            home: ModPath(vec![]),
        })
    };
    let module = |name: Symbol, ty: Symbol| Module {
        name: ModPath(vec![name]),
        types: vec![mk_enum(ty)],
        funcs: vec![],
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
    };
    // `Std.Palette` / `Color` -> `StdPaletteColor`; `Std` / `PaletteColor` ->
    // `StdPaletteColor`. Both fold to the same Rust enum name.
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![module(std_palette, color), module(std_mod, palette_color)],
    };
    // Previously rejected with IPE-N0048; the injective fold now emits both.
    let emitted = RustBackend::new(&interner).emit(&prog)?;
    let all: String = emitted.files.values().cloned().collect();
    assert!(
        all.contains("enum StdPaletteColor ") && all.contains("enum StdPaletteColor2 "),
        "both colliding types must emit under distinct names, got:\n{all}"
    );
    Ok(())
}

/// A one-parameter function `f(xs: List <elem>) -> Int` whose body is a flat
/// list `case` on `xs` with the given arms.
fn list_case_fn(name: Symbol, xs: Symbol, elem: IrType, arms: Vec<Arm>) -> DResult<Func> {
    Ok(Func {
        id: FuncId::from_raw(0),
        name,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(xs, IrType::List(Box::new(elem)))],
        ret: IrType::Int,
        body: Expr::Match(Match::new_flat(Expr::Var(xs), arms)?),
    })
}

/// A slice pattern with the given prefix, rest and ownership.
fn slice(prefix: Vec<Pat>, rest: Option<Pat>, own: SliceOwnership) -> Pat {
    Pat::Slice {
        prefix,
        rest: rest.map(Box::new),
        own,
    }
}

/// The emitted text of the function whose `match` holds `marker`.
fn fn_text<'s>(src: &'s str, marker: &str) -> &'s str {
    let at = src.find(marker).unwrap_or(0);
    let start = src.get(..at).and_then(|s| s.rfind("pub fn ")).unwrap_or(0);
    let end = src
        .get(at..)
        .and_then(|s| s.find("\n}\n"))
        .map_or(src.len(), |e| at + e);
    src.get(start..end).unwrap_or(src)
}

/// An owned-move list `case` over a non-`Clone` element moves every binder out
/// of the owned view: it emits no `.clone()`, `.to_vec()` or `.as_slice()`.
#[test]
fn owned_move_list_case_copies_no_binder() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("shape")?;
    let xs = interner.intern("xs")?;
    let x = interner.intern("x")?;
    let y = interner.intern("y")?;
    let rest = interner.intern("rest")?;
    let other = interner.intern("other")?;
    let own = SliceOwnership::OwnedMove;
    let arms = vec![
        Arm::new(slice(vec![], None, own), Expr::Int(0)),
        Arm::new(slice(vec![Pat::Var(x)], None, own), Expr::Int(1)),
        Arm::new(
            slice(vec![Pat::Var(x), Pat::Var(y)], Some(Pat::Var(rest)), own),
            Expr::Int(2),
        ),
        Arm::new(Pat::Var(other), Expr::Int(3)),
    ];
    let task = IrType::Task(Box::new(IrType::Int));
    let f = list_case_fn(func, xs, task, arms)?;
    let src = emit(&interner, &program(main_mod, vec![], vec![f]))?;
    assert!(
        src.contains("ipe_runtime::list::ipe_list_view_owned::<_, 3>("),
        "an owned list case matches through the owned view, got:\n{src}"
    );
    let body = fn_text(&src, "ipe_list_view_owned");
    for copy in [".clone()", ".to_vec()", ".as_slice()"] {
        assert!(
            !body.contains(copy),
            "an owned list case must not copy a binder ({copy}), got:\n{body}"
        );
    }
    assert!(
        body.contains("ipe_runtime::list::ipe_list_view_rest("),
        "the rest and whole-list binders rebuild from the view, got:\n{body}"
    );
    Ok(())
}

/// Slice arms of one list column that disagree on their ownership are an
/// internal error, never emitted text.
#[test]
fn mixed_slice_ownership_fails_closed() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("mixed")?;
    let xs = interner.intern("xs")?;
    let x = interner.intern("x")?;
    let arms = vec![
        Arm::new(slice(vec![], None, SliceOwnership::OwnedMove), Expr::Int(0)),
        Arm::new(
            slice(vec![Pat::Var(x)], None, SliceOwnership::BorrowClone),
            Expr::Int(1),
        ),
        Arm::new(Pat::Wildcard, Expr::Int(2)),
    ];
    let f = list_case_fn(func, xs, IrType::Task(Box::new(IrType::Int)), arms)?;
    let res = emit(&interner, &program(main_mod, vec![], vec![f]));
    assert!(
        matches!(res, Err(Diagnostic::CompilerBug { .. })),
        "mixed slice ownership must fail closed, got {res:?}"
    );
    Ok(())
}

/// An owned view consumes its variable scrutinee, so an arm that still reads
/// the scrutinee is an internal error, never a use after move.
#[test]
fn owned_view_scrutinee_reuse_fails_closed() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("reuse")?;
    let xs = interner.intern("xs")?;
    let x = interner.intern("x")?;
    let arms = vec![
        Arm::new(
            slice(
                vec![Pat::Var(x)],
                Some(Pat::Wildcard),
                SliceOwnership::OwnedMove,
            ),
            Expr::Var(xs),
        ),
        Arm::new(Pat::Wildcard, Expr::Int(0)),
    ];
    let f = list_case_fn(func, xs, IrType::Task(Box::new(IrType::Int)), arms)?;
    let res = emit(&interner, &program(main_mod, vec![], vec![f]));
    assert!(
        matches!(res, Err(Diagnostic::CompilerBug { .. })),
        "an owned view whose scrutinee an arm rereads must fail closed, got {res:?}"
    );
    Ok(())
}

/// A list `case` whose heads bind nothing borrows its scrutinee even over a
/// non-`Clone` element: it moves no part, so the consume counter still calls
/// the list live after it, and an owned view would move it.
#[test]
fn binder_free_owned_list_case_borrows_the_scrutinee() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("probe")?;
    let xs = interner.intern("xs")?;
    let own = SliceOwnership::OwnedMove;
    let arms = vec![
        Arm::new(slice(vec![], None, own), Expr::Int(0)),
        Arm::new(slice(vec![Pat::Wildcard], None, own), Expr::Int(1)),
        Arm::new(Pat::Wildcard, Expr::Int(2)),
    ];
    let f = list_case_fn(func, xs, IrType::Task(Box::new(IrType::Int)), arms)?;
    let src = emit(&interner, &program(main_mod, vec![], vec![f]))?;
    assert!(
        src.contains("match (xs).as_slice() {"),
        "a binder-free list case matches the borrowed slice, got:\n{src}"
    );
    assert!(
        !src.contains("ipe_list_view_owned"),
        "a binder-free list case takes no owned view, got:\n{src}"
    );
    assert!(
        !src.contains(".clone()") && !src.contains(".to_vec()"),
        "a binder-free list case copies nothing out, got:\n{src}"
    );
    Ok(())
}

/// A borrow-clone list `case` keeps its borrowed-slice emission: the slice
/// scrutinee and the copy-out rebinds of each binder.
#[test]
fn borrow_clone_list_case_keeps_slice_emission() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let func = interner.intern("heads")?;
    let xs = interner.intern("xs")?;
    let x = interner.intern("x")?;
    let rest = interner.intern("rest")?;
    let own = SliceOwnership::BorrowClone;
    let arms = vec![
        Arm::new(slice(vec![], None, own), Expr::Int(0)),
        Arm::new(
            slice(vec![Pat::Var(x)], Some(Pat::Var(rest)), own),
            Expr::Int(1),
        ),
    ];
    let f = list_case_fn(func, xs, IrType::Str, arms)?;
    let src = emit(&interner, &program(main_mod, vec![], vec![f]))?;
    let body = fn_text(&src, "match (xs).as_slice()");
    assert!(
        body.contains("match (xs).as_slice() {"),
        "a borrow-clone list case matches the borrowed slice, got:\n{src}"
    );
    assert!(
        body.contains("[] => 0i64,") && body.contains("[x, rest @ ..] => {"),
        "a borrow-clone list case renders native slice patterns, got:\n{body}"
    );
    assert!(
        body.contains("let x = x.clone();") && body.contains("let rest = rest.to_vec();"),
        "a borrow-clone list case copies each binder out, got:\n{body}"
    );
    assert!(
        !body.contains("ipe_list_view"),
        "a borrow-clone list case takes no owned view, got:\n{body}"
    );
    Ok(())
}
