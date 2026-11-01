//! Payload-carrying / generic / recursive ADT tests for the Rust backend.
//!
//! These exercise the enum pipeline beyond nullary variants:
//!
//! * a GENERIC ADT (`type Maybe a = Just a | Nothing`) emits a generic Rust enum
//!   (`pub enum MainMaybe<T1> { Just(T1), Nothing }`) + a bounded `IpeStringify`
//!   impl; a use-site `Maybe Int` renders `MainMaybe<i64>`,
//! * a CONCRETE payload ADT (`type Shape = Circle Float | Rect Float Float`)
//!   emits tuple variants and a `%v`-faithful stringify,
//! * construction (`Just 5`) emits `MainMaybe::Just(5)`,
//! * a constructor PATTERN binding payloads to variables / wildcards emits
//!   `MainMaybe::Just(x) => x`,
//! * a directly self-recursive ADT (`type Tree = Leaf | Node Tree Int Tree`)
//!   boxes its self-edge fields so the Rust enum stays finite-sized, and balances
//!   that with `Box::new` at construction and a deref at pattern binding.
//!
//! Behavioural-parity oracle: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the
//! shape-equivalent programs
//!
//! ```text
//! -- Maybe:
//! unwrap m = case m of Just x -> x ; Nothing -> 0
//! main = Io.println (String.fromInt (unwrap (Just 5)))            -- prints 5
//!
//! -- Tree:
//! sumTree t = case t of Leaf -> 0 ; Node l n r -> sumTree l + n + sumTree r
//! main = Io.println (String.fromInt (sumTree (Node (Node Leaf 3 Leaf) 4 (Node Leaf 5 Leaf))))  -- prints 12
//! ```
//!
//! to stdout `5\n` / `12\n`, exit 0. The two `end_to_end_*` tests (gated on
//! `IPE_E2E=1`) drive the same hand-built IR through the Rust backend, build the
//! emitted crate, and assert the identical output — the soundness-floor
//! regression for a value laundered through a generic / boxed-recursive payload.

mod seal_e2e;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    Arm, BinOp, CallPin, Callee, EnumDef, Expr, Func, FuncId, IrType, KernelFn, Match, ModPath,
    Module, OnFormKind, Pat, Program, TypeDef, Variant,
};

fn emit(interner: &Interner, prog: &Program) -> DResult<String> {
    let emitted = RustBackend::new(interner).emit(prog)?;
    emitted
        .files
        .get("src/main.rs")
        .cloned()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "adts test",
            detail: "no src/main.rs".to_owned(),
        })
}

/// `type Maybe a = Just a | Nothing`.
fn maybe_def(i: &mut Interner) -> DResult<(EnumDef, Symbol, Symbol, Symbol, Symbol)> {
    let a = i.intern("a")?;
    let maybe = i.intern("Maybe")?;
    let just = i.intern("Just")?;
    let nothing = i.intern("Nothing")?;
    let def = EnumDef {
        name: maybe,
        type_params: vec![a],
        variants: vec![
            Variant {
                name: just,
                fields: vec![IrType::Generic(a)],
            },
            Variant {
                name: nothing,
                fields: vec![],
            },
        ],
        home: ModPath(vec![]),
    };
    Ok((def, maybe, just, nothing, a))
}

/// The `Maybe Int` program: `unwrap (Just 5)` → 5.
#[allow(clippy::too_many_lines)] // exhaustive `Module { … }` test literal
fn maybe_program(i: &mut Interner) -> DResult<Program> {
    let main_mod = i.intern("Main")?;
    let (def, maybe, just, nothing, _a) = maybe_def(i)?;
    let unwrap = i.intern("unwrap")?;
    let main = i.intern("main")?;
    let m = i.intern("m")?;
    let x = i.intern("x")?;

    // unwrap m = case m of Just x -> x ; Nothing -> 0
    let arms = vec![
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: maybe,
                variant: just,
                args: vec![Pat::Var(x)],
            },
            body: Expr::Var(x),
            guard: None,
        },
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: maybe,
                variant: nothing,
                args: vec![],
            },
            body: Expr::Int(0),
            guard: None,
        },
    ];
    let unwrap_fn = Func {
        id: FuncId::from_raw(0),
        name: unwrap,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![ipe_ir::Param::owned(
            m,
            IrType::Enum {
                home: ModPath(vec![]),
                name: maybe,
                args: vec![IrType::Int],
            },
        )],
        ret: IrType::Int,
        body: Expr::Match(Match::new(Expr::Var(m), arms, &[just, nothing])?),
    };
    // main = Io.println (String.fromInt (unwrap (Just 5)))
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
                        ty: maybe,
                        variant: just,
                        args: vec![Expr::Int(5)],
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
            funcs: vec![unwrap_fn, main_fn],
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

/// The interned symbols of the `Tree` ADT: type name, the two constructors, and
/// the `Tree` use-site type (no type arguments).
struct TreeSyms {
    tree: Symbol,
    leaf: Symbol,
    node: Symbol,
    self_ty: IrType,
}

/// Build the `Tree` ADT definition and its constructor symbols.
fn tree_def(interner: &mut Interner) -> DResult<(EnumDef, TreeSyms)> {
    let tree = interner.intern("Tree")?;
    let leaf = interner.intern("Leaf")?;
    let node = interner.intern("Node")?;
    let self_ty = IrType::Enum {
        home: ModPath(vec![]),
        name: tree,
        args: vec![],
    };
    let def = EnumDef {
        name: tree,
        type_params: vec![],
        variants: vec![
            Variant {
                name: leaf,
                fields: vec![],
            },
            Variant {
                name: node,
                fields: vec![self_ty.clone(), IrType::Int, self_ty.clone()],
            },
        ],
        home: ModPath(vec![]),
    };
    Ok((
        def,
        TreeSyms {
            tree,
            leaf,
            node,
            self_ty,
        },
    ))
}

/// `sumTree t = case t of Leaf -> 0 ; Node l n r -> (sumTree l + n) + sumTree r`
/// at `FuncId(0)`.
fn tree_sum_fn(interner: &mut Interner, syms: &TreeSyms) -> DResult<Func> {
    let sum_tree = interner.intern("sumTree")?;
    let scrut = interner.intern("t")?;
    let left = interner.intern("l")?;
    let val = interner.intern("n")?;
    let right = interner.intern("r")?;

    let call_sum = |arg: Symbol| Expr::Call {
        callee: Callee::Func(FuncId::from_raw(0)),
        args: vec![Expr::Var(arg)],
        pin: CallPin::None,
        on_form: OnFormKind::NotForm,
    };
    let arms = vec![
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: syms.tree,
                variant: syms.leaf,
                args: vec![],
            },
            body: Expr::Int(0),
            guard: None,
        },
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: syms.tree,
                variant: syms.node,
                args: vec![Pat::Var(left), Pat::Var(val), Pat::Var(right)],
            },
            body: Expr::BinOp {
                op: BinOp::IntAdd,
                lhs: Box::new(Expr::BinOp {
                    op: BinOp::IntAdd,
                    lhs: Box::new(call_sum(left)),
                    rhs: Box::new(Expr::Var(val)),
                }),
                rhs: Box::new(call_sum(right)),
            },
            guard: None,
        },
    ];
    Ok(Func {
        id: FuncId::from_raw(0),
        name: sum_tree,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![ipe_ir::Param::owned(scrut, syms.self_ty.clone())],
        ret: IrType::Int,
        body: Expr::Match(Match::new(Expr::Var(scrut), arms, &[syms.leaf, syms.node])?),
    })
}

/// `main = Io.println (String.fromInt (sumTree (Node (Node Leaf 3 Leaf) 4
/// (Node Leaf 5 Leaf))))` at `FuncId(1)`.
fn tree_main_fn(interner: &mut Interner, syms: &TreeSyms) -> DResult<Func> {
    let main = interner.intern("main")?;
    let leaf_lit = || Expr::Ctor {
        home: ModPath(vec![]),
        ty: syms.tree,
        variant: syms.leaf,
        args: vec![],
    };
    let node_lit = |left: Expr, value: i64, right: Expr| Expr::Ctor {
        home: ModPath(vec![]),
        ty: syms.tree,
        variant: syms.node,
        args: vec![left, Expr::Int(value), right],
    };
    // Node (Node Leaf 3 Leaf) 4 (Node Leaf 5 Leaf)  → 3 + 4 + 5 = 12
    let the_tree = node_lit(
        node_lit(leaf_lit(), 3, leaf_lit()),
        4,
        node_lit(leaf_lit(), 5, leaf_lit()),
    );
    Ok(Func {
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
                    args: vec![the_tree],
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

/// `type Tree = Leaf | Node Tree Int Tree` + `sumTree` over a small tree → 12.
fn tree_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let (def, syms) = tree_def(interner)?;
    let sum_fn = tree_sum_fn(interner, &syms)?;
    let main_fn = tree_main_fn(interner, &syms)?;
    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![TypeDef::Enum(def)],
            funcs: vec![sum_fn, main_fn],
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
fn generic_enum_def_construction_and_pattern_emit() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = maybe_program(&mut interner)?;
    let out = emit(&interner, &prog)?;

    // Generic enum definition, derived, with a payload tuple variant and a
    // nullary variant.
    assert!(
        out.contains("pub enum MainMaybe<T1> {\n    Just(T1),\n    Nothing,\n}"),
        "generic enum definition missing or wrong:\n{out}"
    );
    // Bounded generic IpeStringify impl with a payload-binding arm.
    assert!(
        out.contains("impl<T1: IpeStringify> IpeStringify for MainMaybe<T1> {"),
        "generic IpeStringify impl clause missing:\n{out}"
    );
    // The single-field format! arm fits on one line.
    assert!(
        out.contains("MainMaybe::Just(p0) => format!(\"Just {}\", IpeStringify::ipe_show(p0)),"),
        "payload stringify arm missing or wrong:\n{out}"
    );
    assert!(
        out.contains("MainMaybe::Nothing => \"Nothing\".to_string(),"),
        "nullary stringify arm missing:\n{out}"
    );
    // Use-site `Maybe Int` renders the instantiated Rust type.
    assert!(
        out.contains("pub fn main_unwrap(m: MainMaybe<i64>) -> i64 {"),
        "use-site Maybe Int not rendered as MainMaybe<i64>:\n{out}"
    );
    // Construction `Just 5`.
    assert!(
        out.contains("MainMaybe::Just(5i64)"),
        "construction not emitted:\n{out}"
    );
    // Pattern binding the payload to a variable.
    assert!(
        out.contains("MainMaybe::Just(x) => x,"),
        "payload var pattern not emitted:\n{out}"
    );
    assert!(
        out.contains("MainMaybe::Nothing => 0i64,"),
        "nullary pattern arm not emitted:\n{out}"
    );
    Ok(())
}

/// An enum whose parameter only passes back to itself (`Just (Maybe a)`)
/// declares a parameter rustc refuses (E0392): the emitter refuses it first.
#[test]
fn an_enum_parameter_no_field_uses_is_refused() -> DResult<()> {
    let mut interner = Interner::new();
    let mut prog = maybe_program(&mut interner)?;
    let module = prog.modules.first_mut();
    let def = module.and_then(|m| m.types.first_mut());
    let Some(TypeDef::Enum(def)) = def else {
        return Err(Diagnostic::CompilerBug {
            where_: "adts test",
            detail: "the Maybe program declares no enum".to_owned(),
        });
    };
    let (home, name) = (def.home.clone(), def.name);
    let param = def.type_params.first().copied();
    let just = def.variants.first_mut().map(|v| &mut v.fields);
    let (Some(fields), Some(param)) = (just, param) else {
        return Err(Diagnostic::CompilerBug {
            where_: "adts test",
            detail: "Maybe declares no parameter or no Just".to_owned(),
        });
    };
    *fields = vec![IrType::Enum {
        home,
        name,
        args: vec![IrType::Generic(param)],
    }];
    let emitted = emit(&interner, &prog);
    assert!(
        matches!(
            emitted,
            Err(Diagnostic::CompilerBug {
                where_: "ipe_ir::EnumParamUse::refuse_unused",
                ..
            })
        ),
        "expected the unused-parameter refusal, got {emitted:?}"
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn concrete_multi_field_enum_emits() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let shape = interner.intern("Shape")?;
    let circle = interner.intern("Circle")?;
    let rect = interner.intern("Rect")?;
    let area = interner.intern("area")?;
    let s = interner.intern("s")?;
    let radius = interner.intern("r")?;
    let w = interner.intern("w")?;
    let h = interner.intern("h")?;

    // type Shape = Circle Float | Rect Float Float
    let def = EnumDef {
        name: shape,
        type_params: vec![],
        variants: vec![
            Variant {
                name: circle,
                fields: vec![IrType::Float],
            },
            Variant {
                name: rect,
                fields: vec![IrType::Float, IrType::Float],
            },
        ],
        home: ModPath(vec![]),
    };
    // area s = case s of Circle r -> r ; Rect w h -> w
    let arms = vec![
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: shape,
                variant: circle,
                args: vec![Pat::Var(radius)],
            },
            body: Expr::Var(radius),
            guard: None,
        },
        Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty: shape,
                variant: rect,
                args: vec![Pat::Var(w), Pat::Wildcard],
            },
            body: Expr::Var(w),
            guard: None,
        },
    ];
    let _ = h; // `h` intentionally elided by the wildcard sub-pattern.
    let area_fn = Func {
        id: FuncId::from_raw(0),
        name: area,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![ipe_ir::Param::owned(
            s,
            IrType::Enum {
                home: ModPath(vec![]),
                name: shape,
                args: vec![],
            },
        )],
        ret: IrType::Float,
        body: Expr::Match(Match::new(Expr::Var(s), arms, &[circle, rect])?),
    };
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![TypeDef::Enum(def)],
            funcs: vec![area_fn],
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
    let out = emit(&interner, &prog)?;

    // Tuple variants with concrete field types; non-generic → no generic clause.
    assert!(
        out.contains("pub enum MainShape {\n    Circle(f64),\n    Rect(f64, f64),\n}"),
        "concrete payload enum definition missing or wrong:\n{out}"
    );
    assert!(
        out.contains("impl IpeStringify for MainShape {"),
        "non-generic enum must have an unparameterised impl:\n{out}"
    );
    // Two-field stringify arm: `Rect <f0> <f1>`; rustfmt wraps the format! args.
    assert!(
        out.contains(
            "MainShape::Rect(p0, p1) => format!(\n                \"Rect {} {}\",\n                \
             IpeStringify::ipe_show(p0),\n                \
             IpeStringify::ipe_show(p1)\n            )"
        ),
        "multi-field stringify arm missing or wrong:\n{out}"
    );
    // Wildcard payload sub-pattern emits `_`.
    assert!(
        out.contains("MainShape::Rect(w, _) => w,"),
        "wildcard payload pattern not emitted:\n{out}"
    );
    Ok(())
}

#[test]
fn recursive_enum_boxes_self_edges() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = tree_program(&mut interner)?;
    let out = emit(&interner, &prog)?;

    // The self-recursive payload fields are boxed; the Int field is not.
    assert!(
        out.contains(
            "pub enum MainTree {\n    Leaf,\n    Node(Box<MainTree>, i64, Box<MainTree>),\n}"
        ),
        "recursive enum must box its direct self-edges:\n{out}"
    );
    // Construction wraps the self-edge arguments in Box::new; rustfmt splits long arg lists.
    assert!(
        out.contains(
            "MainTree::Node(\n        Box::new(MainTree::Node(\n            Box::new(MainTree::Leaf),\n            3i64,\n            Box::new(MainTree::Leaf),\n        ))"
        ),
        "construction must box self-edge args:\n{out}"
    );
    // Pattern unboxes the self-edge binders; rustfmt puts each unbox on its own line.
    assert!(
        out.contains(
            "MainTree::Node(l, n, r) => {\n            let l = *l;\n            let r = *r;"
        ),
        "pattern must unbox self-edge binders:\n{out}"
    );
    Ok(())
}

/// Full spine: build the `Maybe Int` IR, emit, vendor the runtime, `cargo build`,
/// run, and assert `5` — the expected value for `unwrap (Just 5)`. The
/// soundness-floor regression for a value laundered through a generic payload.
#[test]
fn end_to_end_generic_maybe_prints_five() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = maybe_program(&mut interner)?;
    build_and_assert(&interner, &prog, "ipe_backend_adts_maybe_e2e", "5\n")
}

/// Full spine for the recursive `Tree`: `sumTree (Node (Node Leaf 3 Leaf) 4
/// (Node Leaf 5 Leaf))` → `12`. The soundness-floor regression for values
/// laundered through a boxed self-recursive payload.
#[test]
fn end_to_end_recursive_tree_prints_twelve() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = tree_program(&mut interner)?;
    build_and_assert(&interner, &prog, "ipe_backend_adts_tree_e2e", "12\n")
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

    let run =
        seal_e2e::build_and_run_emitted(&emitted, &runtime, slot)?.map_err(seal_e2e::build_bug)?;
    assert_eq!(run.exit_code, Some(0), "exit 0");
    assert_eq!(run.stdout, expected, "ADT program output must match golden");
    Ok(())
}

/// The `for` type of every emitted `trait_name` impl, impl headers joined onto one line.
fn impl_targets(out: &str, trait_name: &str) -> Vec<String> {
    let joined = out.replace("\n    for ", " for ");
    let needle = format!(" {trait_name} for ");
    joined
        .lines()
        .filter(|line| line.starts_with("impl"))
        .filter_map(|line| line.split_once(&needle))
        .map(|(_, ty)| ty.trim_end_matches(" {").trim().to_owned())
        .collect()
}

/// Every emitted `IpeStringify` impl has its `RetainedBytes` twin.
///
/// A variant or record holding a non-serde field measures `None`. CI job:
/// `test`.
#[test]
fn every_stringify_impl_has_its_retained_twin() -> DResult<()> {
    let mut interner = Interner::new();
    let mut prog = maybe_program(&mut interner)?;
    let handler = interner.intern("Handler")?;
    let handle = interner.intern("Handle")?;
    let named = interner.intern("Named")?;
    let label = interner.intern("label")?;
    let run = interner.intern("run")?;
    let x = interner.intern("x")?;
    let y = interner.intern("y")?;
    let int_to_int = IrType::Fun(vec![IrType::Int], Box::new(IrType::Int));
    let module = prog
        .modules
        .first_mut()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "adts test",
            detail: "no module".to_owned(),
        })?;
    // type Handler = Handle (Int -> Int) | Named String Int
    module.types.push(TypeDef::Enum(EnumDef {
        name: handler,
        type_params: vec![],
        variants: vec![
            Variant {
                name: handle,
                fields: vec![int_to_int.clone()],
            },
            Variant {
                name: named,
                fields: vec![IrType::Str, IrType::Int],
            },
        ],
        home: ModPath(vec![]),
    }));
    module.records.push(IrType::Record(
        [(x, IrType::Int), (y, IrType::Str)].into_iter().collect(),
    ));
    module.records.push(IrType::Record(
        [(label, IrType::Str), (run, int_to_int)]
            .into_iter()
            .collect(),
    ));
    let mut tree_interner = Interner::new();
    let tree = tree_program(&mut tree_interner)?;
    let out = emit(&interner, &prog)?;
    let tree_out = emit(&tree_interner, &tree)?;

    for emitted in [&out, &tree_out] {
        let shown = impl_targets(emitted, "IpeStringify");
        let measured = impl_targets(emitted, "RetainedBytes");
        assert!(
            !shown.is_empty(),
            "no IpeStringify impl emitted:\n{emitted}"
        );
        assert_eq!(
            shown, measured,
            "a shown type lacks its measure:\n{emitted}"
        );
    }
    assert!(
        out.contains("impl<T1: RetainedBytes> RetainedBytes for MainMaybe<T1> {"),
        "a generic enum's measure must bound its parameters:\n{out}"
    );
    assert!(
        out.contains("MainHandler::Handle(..) => None,"),
        "a function-holding variant must measure None:\n{out}"
    );
    assert!(
        out.contains("MainHandler::Named(p0, p1) => Bytes::inline::<Self>()?.plus(p0)?.plus(p1),"),
        "a serde variant must measure every field:\n{out}"
    );
    assert!(
        out.contains("fn retained_bytes(&self) -> Option<Bytes> {\n        None\n    }"),
        "a function-holding record must measure None:\n{out}"
    );
    assert!(
        tree_out.contains("MainTree::Node(p0, p1, p2) => Bytes::inline::<Self>()?"),
        "a boxed self-edge must measure through its box:\n{tree_out}"
    );
    Ok(())
}

/// A tuple wider than the runtime's widest `RetainedBytes` tuple impl is serde
/// but unmeasured: a field holding one, bare or inside a carrier, measures
/// `None` rather than naming an impl that does not exist. CI job: `test`.
#[test]
fn a_wide_tuple_field_measures_none() -> DResult<()> {
    let mut interner = Interner::new();
    let mut prog = maybe_program(&mut interner)?;
    let wide_name = interner.intern("wide")?;
    let boxed_name = interner.intern("boxed")?;
    let keep_name = interner.intern("keep")?;
    let wide = IrType::Tuple(vec![IrType::Int; ipe_ir::MAX_SHOWN_TUPLE_ARITY + 1]);
    let widest = IrType::Tuple(vec![IrType::Int; ipe_ir::MAX_SHOWN_TUPLE_ARITY]);
    let module = prog
        .modules
        .first_mut()
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "adts test",
            detail: "no module".to_owned(),
        })?;
    module.records.push(IrType::Record(
        std::iter::once((wide_name, wide.clone())).collect(),
    ));
    module.records.push(IrType::Record(
        std::iter::once((boxed_name, IrType::List(Box::new(wide)))).collect(),
    ));
    module.records.push(IrType::Record(
        std::iter::once((keep_name, widest)).collect(),
    ));
    let out = emit(&interner, &prog)?;
    assert_eq!(
        impl_targets(&out, "IpeStringify"),
        impl_targets(&out, "RetainedBytes"),
        "a shown type lacks its measure:\n{out}"
    );
    for field in ["wide", "boxed"] {
        assert!(
            !out.contains(&format!(".plus(&self.{field})")),
            "a wide-tuple field must not be measured:\n{out}"
        );
    }
    assert!(
        out.contains(".plus(&self.keep)"),
        "a tuple at the widest impl arity is measured:\n{out}"
    );
    Ok(())
}
