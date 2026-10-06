//! seal regression: a user record / enum that stores a first-class function
//! or an opaque wrapper (`Decoder` / `Cmd` / …) must NOT reach the unconditional
//! `#[derive(Clone, Debug, PartialEq)]`.
//!
//! Before the seal, `emit_types` stamped that derive on every generated struct /
//! enum, so a well-typed record like `{ dec : Decoder Int }` made `ipe` exit 0
//! and then `cargo build` fail (E0277 `Clone` / E0369 `==` / E0599
//! `IpeStringify`) — the highest-bar exit-0-then-cargo-fail breach. The gate is
//! now a function of a computed derivability flag ([`ipe_ir::ir_type_is_derivable`]
//! together with the backend fixpoint), so the derive can never appear on a
//! non-derivable type by construction.
//!
//! These tests assert the emitted *text*. A non-derivable type carries no
//! `#[derive(` attribute; its `IpeStringify` renders a function field as the
//! `<function>` marker and every other field through its own impl. A normal
//! all-primitive record still carries the full derive.

use std::collections::BTreeMap;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    CallPin, Callee, EnumDef, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind,
    Program, TypeDef, UiCtor, Variant,
};

fn program(name: Symbol, types: Vec<TypeDef>, funcs: Vec<Func>) -> Program {
    program_with_web(name, types, funcs, false)
}

/// Like [`program`] but lets the test set `uses_web`, so the emitter takes the
/// Ipe.Web serde-derive path (SEAL gate exercise).
fn program_with_web(
    name: Symbol,
    types: Vec<TypeDef>,
    funcs: Vec<Func>,
    uses_web: bool,
) -> Program {
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
            uses_ui: uses_web,
            uses_web,
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
            // A web/server shape reaches the reactor, so the emitted crate keeps
            // the tokio spine the `server_cargo_toml` surgery anchors on.
            uses_async_runtime: uses_web,
        }],
    }
}

/// Classify the derive line that immediately precedes the monomorphic
/// `pub struct <name> {` declaration. Returns `(has_cdpeq_only, has_serde)`:
/// a serde-forced struct matches the second form (which is a superset of the
/// first as text), so `has_serde` is checked against the exact serde line.
fn derive_flavours(src: &str, name: &str) -> (bool, bool) {
    let decl = format!("\npub struct {name} {{");
    let cdpeq_only = format!("#[derive(Clone, Debug, PartialEq)]{decl}");
    let with_serde =
        format!("#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]{decl}");
    (src.contains(&cdpeq_only), src.contains(&with_serde))
}

fn emit(interner: &Interner, prog: &Program) -> DResult<String> {
    RustBackend::new(interner)
        .emit(prog)?
        .files
        .get("src/main.rs")
        .cloned()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "seal_derivability test",
            detail: "no src/main.rs".to_owned(),
        })
}

/// The emitter only ever writes the full `#[derive(Clone, Debug, PartialEq)]`
/// (optionally `+ serde`) directly above a declaration, or nothing at all. So a
/// non-derivable type is proven by the *absence* of that full-derive line
/// immediately above its `pub struct` / `pub enum`.
fn assert_no_full_derive(src: &str, kind: &str, name: &str) {
    let with_derive = format!("#[derive(Clone, Debug, PartialEq)]\npub {kind} {name}");
    let with_serde = "#[derive(Clone, Debug, PartialEq, serde";
    assert!(
        !src.contains(&with_derive),
        "non-derivable `{name}` must carry NO Clone/Debug/PartialEq derive:\n{src}"
    );
    assert!(
        !(src.contains(with_serde) && src.contains(&format!("pub {kind} {name}"))),
        "non-derivable `{name}` must not gain a serde derive:\n{src}"
    );
}

/// The Rust struct name synthesised for the program's single record shape (the
/// `Rec…` struct), if present.
fn rec_struct_name(src: &str) -> Option<String> {
    src.lines()
        .find(|l| l.trim_start().starts_with("pub struct Rec"))
        .and_then(|l| l.split_whitespace().nth(2))
        .map(|s| s.trim_end_matches('{').trim().to_owned())
}

/// A record `{ dec : Decoder Int, n : Int }` in a signature: non-derivable
/// (Decoder is `Box<dyn Fn>`-backed) → no derive; both fields still render
/// through their `IpeStringify` impls (a `Decoder` has a show row), so
/// derivability no longer decides rendering.
#[test]
fn decoder_field_record_has_no_derive() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let dec = interner.intern("dec")?;
    let n = interner.intern("n")?;
    let par = interner.intern("r")?;
    let f = interner.intern("getN")?;

    let mut fields = BTreeMap::new();
    fields.insert(dec, IrType::Decoder(Box::new(IrType::Int)));
    fields.insert(n, IrType::Int);
    let rec = IrType::Record(fields);

    let func = Func {
        id: FuncId::from_raw(0),
        name: f,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(par, rec)],
        ret: IrType::Int,
        body: Expr::Access {
            record: Box::new(Expr::Var(par)),
            field: n,
            field_ty: IrType::Int,
        },
    };
    let src = emit(&interner, &program(main_mod, vec![], vec![func]))?;

    assert!(
        src.contains("dec: Decoder<i64>"),
        "decoder field rendered:\n{src}"
    );
    let name = rec_struct_name(&src).unwrap_or_default();
    assert!(!name.is_empty(), "a Rec struct must be synthesised:\n{src}");
    assert_no_full_derive(&src, "struct", &name);
    assert!(
        src.contains("IpeStringify::ipe_show(&self.dec)"),
        "a non-derivable field with a show row renders through its impl:\n{src}"
    );
    assert!(
        src.contains("IpeStringify::ipe_show(&self.n)"),
        "the derivable sibling field renders through its impl:\n{src}"
    );
    assert!(
        !src.contains("\"<function>\""),
        "no field of this record is a function:\n{src}"
    );
    Ok(())
}

/// A normal all-primitive record keeps the full unconditional derive and
/// renders every field through its impl.
#[test]
fn normal_record_keeps_full_derive() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let x = interner.intern("x")?;
    let y = interner.intern("y")?;
    let par = interner.intern("p")?;
    let f = interner.intern("getX")?;

    let mut fields = BTreeMap::new();
    fields.insert(x, IrType::Int);
    fields.insert(y, IrType::Int);
    let rec = IrType::Record(fields);

    let func = Func {
        id: FuncId::from_raw(0),
        name: f,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(par, rec)],
        ret: IrType::Int,
        body: Expr::Access {
            record: Box::new(Expr::Var(par)),
            field: x,
            field_ty: IrType::Int,
        },
    };
    let src = emit(&interner, &program(main_mod, vec![], vec![func]))?;
    let name = rec_struct_name(&src).unwrap_or_default();
    assert!(!name.is_empty(), "a Rec struct must be synthesised:\n{src}");
    assert!(
        src.contains(&format!(
            "#[derive(Clone, Debug, PartialEq)]\npub struct {name}"
        )),
        "normal `{name}` must keep the full derive:\n{src}"
    );
    assert!(
        !src.contains("\"<function>\""),
        "a normal record must not emit any `<function>` marker:\n{src}"
    );
    Ok(())
}

/// An enum with a variant carrying a function payload → non-derivable → no
/// derive, `<function>` marker + `_` binder for the function field.
#[test]
fn enum_with_function_payload_has_no_derive() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let holder = interner.intern("Holder")?;
    let wrap = interner.intern("Wrap")?;
    let empty = interner.intern("Empty")?;

    let def = EnumDef {
        name: holder,
        type_params: vec![],
        variants: vec![
            Variant {
                name: wrap,
                fields: vec![IrType::Fun(vec![IrType::Int], Box::new(IrType::Int))],
            },
            Variant {
                name: empty,
                fields: vec![],
            },
        ],
        home: ModPath(vec![]),
    };
    let src = emit(
        &interner,
        &program(main_mod, vec![TypeDef::Enum(def)], vec![]),
    )?;

    assert!(src.contains("pub enum MainHolder"), "enum emitted:\n{src}");
    assert_no_full_derive(&src, "enum", "MainHolder");
    assert!(
        src.contains("\"<function>\""),
        "function payload renders the `<function>` marker:\n{src}"
    );
    assert!(
        src.contains("MainHolder::Wrap(_)"),
        "function payload binds `_` in the IpeStringify arm:\n{src}"
    );
    Ok(())
}

/// A record `{ b : Bytes, f : Int -> Int, u : Url }`: each field with a show
/// row renders through its own `IpeStringify` impl, the function field renders
/// as the `<function>` marker, and no rendering falls back to `Debug`.
#[test]
fn record_fields_render_through_their_show_rows() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let b = interner.intern("b")?;
    let f = interner.intern("f")?;
    let u = interner.intern("u")?;
    let par = interner.intern("r")?;
    let get = interner.intern("getB")?;

    let mut fields = BTreeMap::new();
    fields.insert(b, IrType::Bytes);
    fields.insert(f, IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)));
    fields.insert(u, IrType::Url);
    let rec = IrType::Record(fields);

    let func = Func {
        id: FuncId::from_raw(0),
        name: get,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(par, rec)],
        ret: IrType::Bytes,
        body: Expr::Access {
            record: Box::new(Expr::Var(par)),
            field: b,
            field_ty: IrType::Bytes,
        },
    };
    let src = emit(&interner, &program(main_mod, vec![], vec![func]))?;

    for field in ["b", "u"] {
        assert!(
            src.contains(&format!("IpeStringify::ipe_show(&self.{field})")),
            "field `{field}` renders through its show row:\n{src}"
        );
    }
    assert!(
        src.contains("\"<function>\""),
        "the function field renders the `<function>` marker:\n{src}"
    );
    assert!(
        !src.contains("stringify::Wrap") && !src.contains("IpeStringify + std::fmt::Debug"),
        "no rendering falls back to `Debug`:\n{src}"
    );
    Ok(())
}

/// seal: in a `Ipe.Web` program, a NON-Model view-helper record that holds
/// an `Html` field is `CDPeq`-supporting (`Html<M>` derives `Clone, Debug,
/// PartialEq`) but NOT serde-supporting (`Html<M>` is not `Serialize`). Gating
/// the serde derive on the `CDPeq` flag (`is_derivable`) would force
/// `#[derive(..., serde::Serialize, serde::Deserialize)]` onto such a record →
/// `ipe` exit 0 then `cargo` E0277. The gate instead reads the per-record
/// serde flag (`is_serde`): the helper keeps its `CDPeq` derive WITHOUT serde,
/// while a sibling all-primitive record still gets the serde derive.
///
/// This is the emit-text half of the seal (fast, no cargo). The cargo-buildable
/// half is proven end-to-end by `ipe`'s `web_e2e::web_html_helper_record_build_only`.
#[test]
fn web_html_helper_record_gets_cdpeq_without_serde() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    // Field symbols. The synthesised struct name is field-name-sorted PascalCase,
    // so `{ body, title }` → `RecBodyTitle` and `{ count }` → `RecCount`.
    let body = interner.intern("body")?;
    let title = interner.intern("title")?;
    let count = interner.intern("count")?;
    let p = interner.intern("p")?;
    let helper_fn = interner.intern("renderSection")?;
    let model_fn = interner.intern("useModel")?;

    // A view-helper record `{ body : Html Int, title : String }` — Html carrier
    // makes it `CDPeq`-but-not-serde. `Html<Int>` (msg = Int) is enough; the serde
    // predicate rejects every `IrType::Ui` carrier regardless of the msg type.
    let mut helper_fields = BTreeMap::new();
    helper_fields.insert(
        body,
        IrType::Ui {
            ctor: UiCtor::Html,
            msg: Box::new(IrType::Int),
        },
    );
    helper_fields.insert(title, IrType::Str);
    let helper_rec = IrType::Record(helper_fields);

    // A plain-data Model record `{ count : Int }` — fully serde.
    let mut model_fields = BTreeMap::new();
    model_fields.insert(count, IrType::Int);
    let model_rec = IrType::Record(model_fields);

    // Two functions, each taking one record shape, so both shapes are synthesised.
    let helper_func = Func {
        id: FuncId::from_raw(0),
        name: helper_fn,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(p, helper_rec)],
        ret: IrType::Str,
        body: Expr::Access {
            record: Box::new(Expr::Var(p)),
            field: title,
            field_ty: IrType::Str,
        },
    };
    let model_func = Func {
        id: FuncId::from_raw(1),
        name: model_fn,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(p, model_rec)],
        ret: IrType::Int,
        body: Expr::Access {
            record: Box::new(Expr::Var(p)),
            field: count,
            field_ty: IrType::Int,
        },
    };

    let prog = program_with_web(main_mod, vec![], vec![helper_func, model_func], true);
    let src = emit(&interner, &prog)?;

    // The helper renders its Html field type — sanity that the shape survived.
    assert!(
        src.contains("body: ipe_runtime::html::Html<i64>"),
        "helper record's Html field rendered:\n{src}"
    );

    // core: the Html-holding helper carries `CDPeq` WITHOUT serde.
    let (helper_cdpeq, helper_serde) = derive_flavours(&src, "RecBodyTitle");
    assert!(
        helper_cdpeq,
        "view-helper record must keep `#[derive(Clone, Debug, PartialEq)]`:\n{src}"
    );
    assert!(
        !helper_serde,
        "view-helper record holding `Html` must NOT be forced to serde (E0277):\n{src}"
    );

    // Regression: a sibling all-primitive record in the same Web program still
    // gets the serde derive (the fix only demotes non-serde records).
    let (_model_cdpeq, model_serde) = derive_flavours(&src, "RecCount");
    assert!(
        model_serde,
        "plain-data record in a Web program must still get serde:\n{src}"
    );
    Ok(())
}

// ── SEAL regression: capture-clone peel for key/file/bool callbacks ───────────
//
// When a Lambda passed to `Ui.onKeyDown` / `Ui.onKeyUp` / `Ui.onFile` /
// `Event.onBool` is preceded by a capture-clone `Let` (the lowerer hoists
// `let sym = sym.clone()` before the lambda when `sym` is also used by a
// sibling attribute on the same element), the emit must PEEL that let OUTSIDE
// the synthesised `Arc::new(move |_x| …)`.
//
// Without the peel (the pre-fix code path), the outer `move` closure
// move-captures the free binding and a sibling use of it hits E0382 at
// `cargo build` — ipe exit-0 then cargo-fail, the cardinal SEAL breach.
//
// The fix routes these arms through `emit_arc_callback_field`, identical to
// the already-correct `Ui.onInput` / `Ui.onChange` arms. The emitted text
// must contain the peel `let pfx` BEFORE the `Arc::new(` that follows it,
// proving the let was hoisted outside the closure boundary.

/// Build:
///   ```
///   view pfx =
///     let pfx = pfx.clone() in   -- lowerer's capture-clone alias
///     Ui.onKeyDown (\k -> pfx ++ k)
///   ```
///
/// This is the minimal IR the lowerer emits when `pfx` is used both by the
/// `onKeyDown` handler AND by a sibling element attribute (the sibling forces
/// the clone before the lambda so the outer `pfx` survives for the sibling).
fn build_capture_clone_on_key_down(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let view = interner.intern("view")?;
    let pfx = interner.intern("pfx")?;
    let k = interner.intern("k")?;

    // `Let { name: pfx, value: CloneVar(pfx), body: Call(UiOnKeyDown, [Lambda]) }`
    // — the lowerer's canonical capture-clone shape.
    let body = Expr::Let {
        name: pfx,
        value: Box::new(Expr::CloneVar(pfx)),
        body: Box::new(Expr::Call {
            callee: Callee::Kernel(KernelFn::UiOnKeyDown),
            args: vec![Expr::Lambda {
                params: vec![(k, IrType::Str)],
                ret: IrType::Str,
                body: Box::new(Expr::BinOp {
                    op: ipe_ir::BinOp::Append,
                    lhs: Box::new(Expr::CloneVar(pfx)),
                    rhs: Box::new(Expr::Var(k)),
                }),
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }),
    };

    let func = Func {
        id: FuncId::from_raw(0),
        name: view,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(pfx, IrType::Str)],
        ret: IrType::Str,
        body,
    };

    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![func],
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
            uses_ui: true,
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

/// `Ui.onKeyDown` with a capture-clone-wrapped lambda: the peel let must appear
/// OUTSIDE the Arc closure in the emitted text.
///
/// Without the fix, this program emits Rust that `ipe` accepts (exit 0) but
/// `cargo build` rejects with E0382 because the outer `move` closure
/// move-captures `pfx` and a sibling use of `pfx` triggers "use of moved value".
#[test]
fn on_key_down_capture_clone_peeled_outside_arc() -> DResult<()> {
    let mut interner = Interner::new();
    let src = {
        let prog = build_capture_clone_on_key_down(&mut interner)?;
        emit(&interner, &prog)?
    };

    // The peel produces `{ let pfx = pfx.clone(); <Arc expr> }` — the `let`
    // must precede `Arc::new(` in the emitted text (not sit inside it).
    let let_pos = src.find("let pfx = pfx.clone()");
    let arc_pos = src.find("::std::sync::Arc::new(");
    assert!(
        let_pos.is_some(),
        "capture-clone peel `let pfx = pfx.clone()` must appear in emitted text:\n{src}"
    );
    assert!(
        arc_pos.is_some(),
        "`Arc::new(` must appear in emitted text:\n{src}"
    );
    assert!(
        let_pos.unwrap() < arc_pos.unwrap(),
        "peel `let` must appear BEFORE `Arc::new(` (hoisted outside the closure):\n{src}"
    );
    Ok(())
}

/// Same shape, `Ui.onKeyUp`.
#[test]
fn on_key_up_capture_clone_peeled_outside_arc() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let view = interner.intern("view")?;
    let pfx = interner.intern("pfx")?;
    let k = interner.intern("k")?;

    let body = Expr::Let {
        name: pfx,
        value: Box::new(Expr::CloneVar(pfx)),
        body: Box::new(Expr::Call {
            callee: Callee::Kernel(KernelFn::UiOnKeyUp),
            args: vec![Expr::Lambda {
                params: vec![(k, IrType::Str)],
                ret: IrType::Str,
                body: Box::new(Expr::Var(k)),
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }),
    };
    let func = Func {
        id: FuncId::from_raw(0),
        name: view,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(pfx, IrType::Str)],
        ret: IrType::Str,
        body,
    };
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![func],
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
            uses_ui: true,
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
    let src = emit(&interner, &prog)?;

    let let_pos = src.find("let pfx = pfx.clone()");
    let arc_pos = src.find("::std::sync::Arc::new(");
    assert!(let_pos.is_some(), "peel let must appear:\n{src}");
    assert!(arc_pos.is_some(), "Arc::new must appear:\n{src}");
    assert!(
        let_pos.unwrap() < arc_pos.unwrap(),
        "peel let must be BEFORE Arc::new:\n{src}"
    );
    Ok(())
}

/// Same shape, `Ui.onFile`.
#[test]
fn on_file_capture_clone_peeled_outside_arc() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let view = interner.intern("view")?;
    let pfx = interner.intern("pfx")?;
    let k = interner.intern("k")?;

    let body = Expr::Let {
        name: pfx,
        value: Box::new(Expr::CloneVar(pfx)),
        body: Box::new(Expr::Call {
            callee: Callee::Kernel(KernelFn::UiOnFile),
            args: vec![Expr::Lambda {
                params: vec![(k, IrType::Str)],
                ret: IrType::Str,
                body: Box::new(Expr::Var(k)),
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }),
    };
    let func = Func {
        id: FuncId::from_raw(0),
        name: view,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(pfx, IrType::Str)],
        ret: IrType::Str,
        body,
    };
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![func],
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
            uses_ui: true,
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
    let src = emit(&interner, &prog)?;

    let let_pos = src.find("let pfx = pfx.clone()");
    let arc_pos = src.find("::std::sync::Arc::new(");
    assert!(let_pos.is_some(), "peel let must appear:\n{src}");
    assert!(arc_pos.is_some(), "Arc::new must appear:\n{src}");
    assert!(
        let_pos.unwrap() < arc_pos.unwrap(),
        "peel let must be BEFORE Arc::new:\n{src}"
    );
    Ok(())
}

/// Same shape, `Event.onBool`.
#[test]
fn on_bool_capture_clone_peeled_outside_arc() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let view = interner.intern("view")?;
    let pfx = interner.intern("pfx")?;
    let b = interner.intern("b")?;

    let body = Expr::Let {
        name: pfx,
        value: Box::new(Expr::CloneVar(pfx)),
        body: Box::new(Expr::Call {
            callee: Callee::Kernel(KernelFn::UiOnBool),
            args: vec![Expr::Lambda {
                params: vec![(b, IrType::Bool)],
                ret: IrType::Bool,
                body: Box::new(Expr::Var(b)),
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }),
    };
    let func = Func {
        id: FuncId::from_raw(0),
        name: view,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(pfx, IrType::Str)],
        ret: IrType::Bool,
        body,
    };
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![func],
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
            uses_ui: true,
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
    let src = emit(&interner, &prog)?;

    let let_pos = src.find("let pfx = pfx.clone()");
    let arc_pos = src.find("::std::sync::Arc::new(");
    assert!(let_pos.is_some(), "peel let must appear:\n{src}");
    assert!(arc_pos.is_some(), "Arc::new must appear:\n{src}");
    assert!(
        let_pos.unwrap() < arc_pos.unwrap(),
        "peel let must be BEFORE Arc::new:\n{src}"
    );
    Ok(())
}

// ── capture-clone peel on the event-callback emit arms ───────────────────────
//
// The sibling class of the onKeyDown/onKeyUp/onFile/onBool peel above. When a
// synthesised callback arm emits its handler inside a `move |…| …` closure and
// the handler is preceded by a lowerer-hoisted capture-clone `Let`
// (`let pfx = pfx.clone() in Lambda …`), the peel MUST hoist that `let` OUTSIDE
// the `move` closure. Otherwise the closure move-captures the free `pfx` while
// the `.clone()` also reads it, and a sibling field/arg reading `pfx` hits
// E0382 at `cargo build` — ipe exit-0 then cargo-fail, the cardinal SEAL breach.
//
// These build the capture-clone `Let` NESTED DIRECTLY IN THE CALLBACK ARG (not
// at the function-body top — a top-level `Let` emits its `let` at function
// scope regardless of whether the ARM peels, so it cannot detect an arm-local
// regression). A single-arm revert (dropping that arm's peel) leaves the
// `let pfx = pfx.clone()` INSIDE the arm's `move |` closure, and the assertion
// below — the peel `let` must precede the arm's `move |` — fails exactly there.

/// A single-`view`-func UI program whose body is `call_body`. `view` takes a
/// `String` param `pfx` so a nested `CloneVar(pfx)` resolves.
fn ui_view_program(interner: &mut Interner, ret: IrType, call_body: Expr) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let view = interner.intern("view")?;
    let pfx = interner.intern("pfx")?;
    let func = Func {
        id: FuncId::from_raw(0),
        name: view,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(pfx, IrType::Str)],
        ret,
        body: call_body,
    };
    let mut prog = program(main_mod, vec![], vec![func]);
    if let Some(module) = prog.modules.first_mut() {
        module.uses_ui = true;
    }
    Ok(prog)
}

/// Build `Call(kernel, [ Let{pfx = pfx.clone(); Lambda(param -> body)} ] ++ tail)`
/// — the capture-clone `Let` sits DIRECTLY in the first (callback) arg, so
/// peeling it is the ARM's responsibility, not the outer let-lowering's.
#[allow(clippy::too_many_arguments)] // one call-shape builder threading the IR pieces
fn capture_clone_callback_call(
    interner: &mut Interner,
    kernel: KernelFn,
    param: Symbol,
    param_ty: IrType,
    lambda_ret: IrType,
    lambda_body: Expr,
    on_form: OnFormKind,
    tail_args: Vec<Expr>,
) -> DResult<Expr> {
    let pfx = interner.intern("pfx")?;
    let callback = Expr::Let {
        name: pfx,
        value: Box::new(Expr::CloneVar(pfx)),
        body: Box::new(Expr::Lambda {
            params: vec![(param, param_ty)],
            ret: lambda_ret,
            body: Box::new(lambda_body),
        }),
    };
    let mut args = vec![callback];
    args.extend(tail_args);
    Ok(Expr::Call {
        callee: Callee::Kernel(kernel),
        args,
        pin: CallPin::None,
        on_form,
    })
}

/// Assert the capture-clone peel `let pfx = pfx.clone();` appears in `src`
/// BEFORE the FIRST `move |` that follows `runtime_path` — i.e. the peel was
/// hoisted OUTSIDE the arm's `move` closure. On a single-arm revert the `let`
/// lands INSIDE that `move` (after `move |`), so this fails exactly there.
fn assert_peeled_before_move(src: &str, runtime_path: &str) {
    // Split the emit at the arm's runtime path. `after` starts just past the
    // path, so the arm's `move |` is the first `move |` in `after`; the peeled
    // clone-let (if hoisted OUTSIDE the closure) lands in `before` or in the
    // call head between the path and `move |`, never in the closure-body tail.
    // All lookups are `Option`-driven — no unwrap/indexing.
    assert!(
        src.contains(runtime_path),
        "runtime path {runtime_path:?} must appear in emitted text:\n{src}"
    );
    let (before, after) = src.split_once(runtime_path).unwrap_or(("", ""));
    assert!(
        after.contains("move |"),
        "a `move |` closure must follow {runtime_path:?}:\n{src}"
    );
    let (call_head, move_tail) = after.split_once("move |").unwrap_or(("", ""));
    // The clone-let must sit BEFORE the arm's `move |` — either in `before` (the
    // common hoist point) or in the call head between the path and `move |`
    // (e.g. `{ let pfx = pfx.clone(); path(Arc::new(move |…`). It must NEVER sit
    // in `move_tail` (the closure body), which is where a reverted arm nests it.
    let peeled_outside =
        before.contains("let pfx = pfx.clone()") || call_head.contains("let pfx = pfx.clone()");
    assert!(
        peeled_outside,
        "capture-clone peel `let pfx = pfx.clone()` must appear BEFORE the \
         `move |` of {runtime_path:?} (hoisted OUTSIDE the closure):\n{src}"
    );
    assert!(
        !move_tail.contains("let pfx = pfx.clone()"),
        "no capture-clone `let` may appear INSIDE the arm's `move` closure \
         (a reverted arm nests it there — E0382):\n{src}"
    );
}

/// `Ui.onSubmit` (bare, non-Arc `ui_on_submit_(move |_x| …)`).
#[test]
fn on_submit_capture_clone_peeled_outside_closure() -> DResult<()> {
    let mut interner = Interner::new();
    let x = interner.intern("x")?;
    let pfx = interner.intern("pfx")?;
    let body = capture_clone_callback_call(
        &mut interner,
        KernelFn::UiOnSubmit,
        x,
        IrType::Str,
        IrType::Str,
        Expr::BinOp {
            op: ipe_ir::BinOp::Append,
            lhs: Box::new(Expr::CloneVar(pfx)),
            rhs: Box::new(Expr::Var(x)),
        },
        OnFormKind::Decoder,
        vec![],
    )?;
    let prog = ui_view_program(&mut interner, IrType::Str, body)?;
    let src = emit(&interner, &prog)?;
    assert_peeled_before_move(&src, "ipe_runtime::ui::helpers::ui_on_submit_(");
    Ok(())
}

/// `Event.onKeyDown` / String shape
/// (`html_on_string_(…, Arc::new(move |_x| …))`).
#[test]
fn html_on_string_capture_clone_peeled_outside_closure() -> DResult<()> {
    let mut interner = Interner::new();
    let x = interner.intern("x")?;
    let pfx = interner.intern("pfx")?;
    let body = capture_clone_callback_call(
        &mut interner,
        KernelFn::HtmlOnKeyDown,
        x,
        IrType::Str,
        IrType::Str,
        Expr::BinOp {
            op: ipe_ir::BinOp::Append,
            lhs: Box::new(Expr::CloneVar(pfx)),
            rhs: Box::new(Expr::Var(x)),
        },
        OnFormKind::NotForm,
        vec![],
    )?;
    let prog = ui_view_program(&mut interner, IrType::Str, body)?;
    let src = emit(&interner, &prog)?;
    assert_peeled_before_move(&src, "ipe_runtime::html::html_on_string_(");
    Ok(())
}

/// `Event.onBool` / Bool shape
/// (`html_on_bool_(…, Arc::new(move |_x| …))`).
#[test]
fn html_on_bool_capture_clone_peeled_outside_closure() -> DResult<()> {
    let mut interner = Interner::new();
    let b = interner.intern("b")?;
    let pfx = interner.intern("pfx")?;
    // `\b -> (pfx, b)` — reads the captured `pfx` in the Bool handler.
    let body = capture_clone_callback_call(
        &mut interner,
        KernelFn::HtmlOnBool,
        b,
        IrType::Bool,
        IrType::Tuple(vec![IrType::Str, IrType::Bool]),
        Expr::Tuple(vec![Expr::CloneVar(pfx), Expr::Var(b)]),
        OnFormKind::NotForm,
        vec![],
    )?;
    let prog = ui_view_program(
        &mut interner,
        IrType::Tuple(vec![IrType::Str, IrType::Bool]),
        body,
    )?;
    let src = emit(&interner, &prog)?;
    assert_peeled_before_move(&src, "ipe_runtime::html::html_on_bool_(");
    Ok(())
}

/// `Event.onSubmit` / Raw decoder shape
/// (bare, non-Arc `html_on_raw_(…, move |_x| …)`).
#[test]
fn html_on_raw_capture_clone_peeled_outside_closure() -> DResult<()> {
    let mut interner = Interner::new();
    let x = interner.intern("x")?;
    let pfx = interner.intern("pfx")?;
    let body = capture_clone_callback_call(
        &mut interner,
        KernelFn::HtmlOnSubmit,
        x,
        IrType::Str,
        IrType::Str,
        Expr::BinOp {
            op: ipe_ir::BinOp::Append,
            lhs: Box::new(Expr::CloneVar(pfx)),
            rhs: Box::new(Expr::Var(x)),
        },
        OnFormKind::Decoder,
        vec![],
    )?;
    let prog = ui_view_program(&mut interner, IrType::Str, body)?;
    let src = emit(&interner, &prog)?;
    assert_peeled_before_move(&src, "ipe_runtime::html::html_on_raw_(");
    Ok(())
}

/// `Lazy.lazy` (bare, non-Arc, MULTI-ARG `lazy_lazy_(move |_a| …, key)`). The
/// captured `pfx` is shared with the POSITIONAL key arg — the peel must hoist
/// the clone-let OUTSIDE the thunk `move` closure while leaving the key arg
/// (which reads `pfx`) intact.
#[test]
fn lazy_capture_clone_peeled_outside_closure() -> DResult<()> {
    let mut interner = Interner::new();
    let a = interner.intern("a")?;
    let pfx = interner.intern("pfx")?;
    // f = \a -> pfx ++ a ; key arg = pfx (positional sibling reading pfx).
    let body = capture_clone_callback_call(
        &mut interner,
        KernelFn::LazyLazy,
        a,
        IrType::Str,
        IrType::Str,
        Expr::BinOp {
            op: ipe_ir::BinOp::Append,
            lhs: Box::new(Expr::CloneVar(pfx)),
            rhs: Box::new(Expr::Var(a)),
        },
        OnFormKind::NotForm,
        vec![Expr::Var(pfx)],
    )?;
    let prog = ui_view_program(&mut interner, IrType::Str, body)?;
    let src = emit(&interner, &prog)?;
    assert_peeled_before_move(&src, "ipe_runtime::ui::lazy::lazy_lazy_(");
    Ok(())
}
