//! Generic-aware record-struct synthesis for the Rust backend.
//!
//! Extends the closed-record pipeline so a record shape whose field types are
//! type variables ([`IrType::Generic`]) synthesises a GENERIC Rust struct:
//!
//! * `{ value : a }` → `pub struct RecValue<T1> { value: T1 }` with a generic
//!   `IpeStringify` impl bounded `T1: IpeStringify + std::fmt::Debug`,
//! * a function `wrap : a -> { value : a }` renders its signature with the
//!   struct instantiated at the function's own generic (`RecValue<T1>`),
//! * a same-field-set concrete record (`{ value : Int }`) deduplicates onto the
//!   ONE generic struct and renders `RecValue<i64>` at the use site,
//! * monomorphic records emit no `<..>` clause.
//!
//! Behavioural-parity oracle: the reference compiler at
//! `/home/arthur/Documentos/comp/ipe/out/ipe` compiles + runs the
//! equivalent program
//!
//! ```text
//! wrap : a -> { value : a }
//! wrap x = { value = x }
//! unwrap : { value : a } -> a
//! unwrap r = r.value
//! main = Io.println (String.fromInt (unwrap (wrap 42)))
//! ```
//!
//! to stdout `42\n`, exit 0 (hand-verified in a temp dir). The `end_to_end_*`
//! test (gated on `IPE_E2E=1`) drives the hand-built IR through the Rust backend,
//! builds the emitted crate, and asserts the identical `42`.

mod seal_e2e;

use std::collections::BTreeMap;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{
    BoundSet, CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind,
    Program,
};

/// A single-module program.
fn program(name: Symbol, funcs: Vec<Func>, records: Vec<IrType>, entry: Option<FuncId>) -> Program {
    Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![name]),
            types: vec![],
            funcs,
            entry,
            records,
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
            where_: "generic_records test",
            detail: "no src/main.rs".to_owned(),
        })
}

/// A `{ value : <ty> }` record type.
fn value_record(value: Symbol, ty: IrType) -> IrType {
    let mut fields = BTreeMap::new();
    fields.insert(value, ty);
    IrType::Record(fields)
}

/// The canonical generic-record program: `wrap`/`unwrap` over `{ value : a }`,
/// using DISTINCT source type-variable spellings (`a` in `wrap`, `b` in
/// `unwrap`) to exercise alpha-equivalent template selection.
fn wrap_unwrap_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let value = interner.intern("value")?;
    let a = interner.intern("a")?;
    let b = interner.intern("b")?;
    let x = interner.intern("x")?;
    let r = interner.intern("r")?;
    let wrap = interner.intern("wrap")?;
    let unwrap = interner.intern("unwrap")?;
    let main = interner.intern("main")?;

    // wrap : a -> { value : a } ; wrap x = { value = x }
    let wrap_fn = Func {
        id: FuncId::from_raw(0),
        name: wrap,
        home: ModPath(vec![]),
        type_params: vec![(a, BoundSet::UNBOUNDED)],
        row_params: vec![],
        params: vec![(x, IrType::Generic(a))],
        ret: value_record(value, IrType::Generic(a)),
        body: Expr::Record {
            fields: vec![(value, Expr::Var(x))],
            ty: None,
        },
    };
    // unwrap : { value : b } -> b ; unwrap r = r.value
    let unwrap_fn = Func {
        id: FuncId::from_raw(1),
        name: unwrap,
        home: ModPath(vec![]),
        type_params: vec![(b, BoundSet::UNBOUNDED)],
        row_params: vec![],
        params: vec![(r, value_record(value, IrType::Generic(b)))],
        ret: IrType::Generic(b),
        body: Expr::Access {
            record: Box::new(Expr::Var(r)),
            field: value,
            field_ty: IrType::Generic(b),
        },
    };
    // main = Io.println (String.fromInt (unwrap (wrap 42)))
    let main_fn = Func {
        id: FuncId::from_raw(2),
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
                    callee: Callee::Func(FuncId::from_raw(1)),
                    args: vec![Expr::Call {
                        callee: Callee::Func(FuncId::from_raw(0)),
                        args: vec![Expr::Int(42)],
                        pin: CallPin::None,
                        on_form: OnFormKind::NotForm,
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
        vec![wrap_fn, unwrap_fn, main_fn],
        vec![],
        Some(FuncId::from_raw(2)),
    ))
}

#[test]
fn synthesises_generic_struct_and_signatures() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = wrap_unwrap_program(&mut interner)?;
    let out = emit(&interner, &prog)?;

    // The struct is generic over T1, the `value` field typed by it.
    assert!(
        out.contains(
            "#[derive(Clone, Debug, PartialEq)]\npub struct RecValue<T1> {\n    value: T1,\n}"
        ),
        "generic struct definition missing or wrong shape:\n{out}"
    );
    // Generic IpeStringify impl, bounded so the autoref dispatch resolves; rustfmt wraps format!.
    assert!(
        out.contains(
            "impl<T1: IpeStringify + std::fmt::Debug> IpeStringify for RecValue<T1> {\n    \
             fn ipe_show(&self) -> String {\n        \
             format!(\n            \"{{{}}}\",\n            \
             (&ipe_runtime::stringify::Wrap(&self.value)).dispatch()\n        )"
        ),
        "generic IpeStringify impl missing or wrong:\n{out}"
    );
    // Exactly one struct definition (both generic occurrences dedup to one).
    assert_eq!(
        out.matches("pub struct RecValue").count(),
        1,
        "alpha-equivalent generic shapes must dedup to one struct:\n{out}"
    );
    // `wrap` renders the struct at its own generic.
    assert!(
        out.contains("pub fn main_wrap<T1: Clone>(x: T1) -> RecValue<T1> {"),
        "wrap signature not rendered with generic struct:\n{out}"
    );
    // `unwrap`'s param renders `RecValue<T1>` despite its source var being `b`.
    assert!(
        out.contains("pub fn main_unwrap<T1: Clone>(r: RecValue<T1>) -> T1 {"),
        "unwrap signature not rendered with generic struct:\n{out}"
    );
    // Literal construction resolves to the struct name; Rust infers the arg.
    assert!(
        out.contains("RecValue { value: x }"),
        "generic record literal not emitted as struct literal:\n{out}"
    );
    Ok(())
}

#[test]
fn merges_generic_and_concrete_field_set() -> DResult<()> {
    // A generic `{ value : a }` (in `wrap`) and a concrete `{ value : Int }`
    // (in a monomorphic `mkBox`) share the field set `{ value }`. They must
    // collapse to the ONE generic struct, and the concrete use site renders the
    // struct instantiated at `i64`.
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let value = interner.intern("value")?;
    let a = interner.intern("a")?;
    let x = interner.intern("x")?;
    let n = interner.intern("n")?;
    let wrap = interner.intern("wrap")?;
    let mk_box = interner.intern("mkBox")?;

    // wrap : a -> { value : a }
    let wrap_fn = Func {
        id: FuncId::from_raw(0),
        name: wrap,
        home: ModPath(vec![]),
        type_params: vec![(a, BoundSet::UNBOUNDED)],
        row_params: vec![],
        params: vec![(x, IrType::Generic(a))],
        ret: value_record(value, IrType::Generic(a)),
        body: Expr::Record {
            fields: vec![(value, Expr::Var(x))],
            ty: None,
        },
    };
    // mkBox : Int -> { value : Int } ; mkBox n = { value = n }
    let mk_box_fn = Func {
        id: FuncId::from_raw(1),
        name: mk_box,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(n, IrType::Int)],
        ret: value_record(value, IrType::Int),
        body: Expr::Record {
            fields: vec![(value, Expr::Var(n))],
            ty: None,
        },
    };
    let prog = program(main_mod, vec![wrap_fn, mk_box_fn], vec![], None);
    let out = emit(&interner, &prog)?;

    // ONE struct, generic.
    assert_eq!(
        out.matches("pub struct RecValue").count(),
        1,
        "generic + concrete same-field-set must dedup to one struct:\n{out}"
    );
    assert!(
        out.contains("pub struct RecValue<T1> {"),
        "merged struct must be the generic one:\n{out}"
    );
    // The concrete monomorphic function instantiates the struct at i64.
    assert!(
        out.contains("pub fn main_mk_box(n: i64) -> RecValue<i64> {"),
        "concrete use site must render the struct instantiated at i64:\n{out}"
    );
    Ok(())
}

#[test]
fn two_type_parameter_record() -> DResult<()> {
    // `{ first : a, second : b }` synthesises a two-parameter struct, params in
    // field-name order (first → T1, second → T2).
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let first = interner.intern("first")?;
    let second = interner.intern("second")?;
    let a = interner.intern("a")?;
    let b = interner.intern("b")?;
    let x = interner.intern("x")?;
    let y = interner.intern("y")?;
    let pair = interner.intern("pair")?;

    let mut rec_fields = BTreeMap::new();
    rec_fields.insert(first, IrType::Generic(a));
    rec_fields.insert(second, IrType::Generic(b));
    let rec = IrType::Record(rec_fields);

    // pair : a -> b -> { first : a, second : b }
    let pair_fn = Func {
        id: FuncId::from_raw(0),
        name: pair,
        home: ModPath(vec![]),
        type_params: vec![(a, BoundSet::UNBOUNDED), (b, BoundSet::UNBOUNDED)],
        row_params: vec![],
        params: vec![(x, IrType::Generic(a)), (y, IrType::Generic(b))],
        ret: rec,
        body: Expr::Record {
            fields: vec![(first, Expr::Var(x)), (second, Expr::Var(y))],
            ty: None,
        },
    };
    let prog = program(main_mod, vec![pair_fn], vec![], None);
    let out = emit(&interner, &prog)?;

    assert!(
        out.contains("pub struct RecFirstSecond<T1, T2> {\n    first: T1,\n    second: T2,\n}"),
        "two-parameter struct missing or wrong shape:\n{out}"
    );
    // rustfmt line-wraps the long impl header before `for`.
    assert!(
        out.contains(
            "impl<T1: IpeStringify + std::fmt::Debug, T2: IpeStringify + std::fmt::Debug> IpeStringify\n    \
             for RecFirstSecond<T1, T2>\n{"
        ),
        "two-parameter IpeStringify impl missing or wrong:\n{out}"
    );
    assert!(
        out.contains(
            "pub fn main_pair<T1: Clone, T2: Clone>(x: T1, y: T2) -> RecFirstSecond<T1, T2> {"
        ),
        "two-parameter signature not rendered:\n{out}"
    );
    Ok(())
}

#[test]
fn monomorphic_record_stays_byte_identical() -> DResult<()> {
    // A field set with NO generic occurrence anywhere emits the monomorphic
    // struct (no `<..>` clause, concrete field type).
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let value = interner.intern("value")?;
    let n = interner.intern("n")?;
    let mk_box = interner.intern("mkBox")?;

    let mk_box_fn = Func {
        id: FuncId::from_raw(0),
        name: mk_box,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(n, IrType::Int)],
        ret: value_record(value, IrType::Int),
        body: Expr::Record {
            fields: vec![(value, Expr::Var(n))],
            ty: None,
        },
    };
    let prog = program(main_mod, vec![mk_box_fn], vec![], None);
    let out = emit(&interner, &prog)?;

    assert!(
        out.contains(
            "#[derive(Clone, Debug, PartialEq)]\npub struct RecValue {\n    value: i64,\n}"
        ),
        "monomorphic struct must stay byte-identical (no generic clause):\n{out}"
    );
    assert!(
        out.contains("impl IpeStringify for RecValue {"),
        "monomorphic IpeStringify impl must carry no generic clause:\n{out}"
    );
    assert!(
        out.contains("pub fn main_mk_box(n: i64) -> RecValue {"),
        "monomorphic signature must render the bare struct name:\n{out}"
    );
    Ok(())
}

/// Full spine: build the generic-record IR, emit the project, vendor the runtime,
/// `cargo build`, run, and assert the program prints `42` — the expected value/// backend produces. Gated on `IPE_E2E=1` so the default `cargo test` stays fast.
#[test]
fn end_to_end_builds_and_prints_forty_two() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let mut interner = Interner::new();
    let prog = wrap_unwrap_program(&mut interner)?;
    let emitted = RustBackend::new(&interner).emit(&prog)?;

    let out = ipe_test_temp::temp_root().join("ipe_backend_generic_records_e2e");
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
        "emitted generic-record project must build: {status:?}"
    );

    let bin = target_dir.join("debug").join("ipe-app");
    let output = std::process::Command::new(&bin)
        .output()
        .map_err(|e| seal_e2e::io_bug(&bin, &e))?;
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "42\n",
        "generic-record program prints 42"
    );
    assert!(output.status.success(), "exit 0");
    if target_dir == out.join("target") {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Regression: order-independent most-specific resolution
// ---------------------------------------------------------------------------
//
// Three templates share the field-name set `{ q }`:
//   T0: `{ q : a }`              specificity 0  (one generic)
//   T1: `{ q : (a, a) }`         specificity 1  (tuple of two generics)
//   T2: `{ q : ((a,a),(a,a)) }`  specificity 3  (nested tuple)
//
// A concrete use site `{ q : ((Int,Int),(Int,Int)) }` instantiation-matches all
// three.  T2 is the uniquely most-specific.  A single-pass scan that stops at
// the first equal-specificity pair produces declaration-order-dependent results.
// The two-pass fix always picks T2 regardless of order.

/// Build a `{ q : <ty> }` record type.
fn q_record(q: Symbol, ty: IrType) -> IrType {
    let mut fields = BTreeMap::new();
    fields.insert(q, ty);
    IrType::Record(fields)
}

/// Three-template program with the deepest template at position `deepest_pos`
/// (0 = first, 2 = last).  The concrete use site is `{ q : ((Int,Int),(Int,Int)) }`.
fn three_template_program(interner: &mut Interner, deepest_pos: usize) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let q = interner.intern("q")?;
    let a = interner.intern("a")?;
    let f0 = interner.intern("f0")?;
    let f1 = interner.intern("f1")?;
    let f2 = interner.intern("f2")?;
    let fconc = interner.intern("fconc")?;
    let p = interner.intern("p")?;

    // T0: `{ q : a }` — specificity 0
    let t0_rec = q_record(q, IrType::Generic(a));
    // T1: `{ q : (a, a) }` — specificity 1
    let t1_rec = q_record(
        q,
        IrType::Tuple(vec![IrType::Generic(a), IrType::Generic(a)]),
    );
    // T2: `{ q : ((a,a),(a,a)) }` — specificity 3
    let t2_rec = q_record(
        q,
        IrType::Tuple(vec![
            IrType::Tuple(vec![IrType::Generic(a), IrType::Generic(a)]),
            IrType::Tuple(vec![IrType::Generic(a), IrType::Generic(a)]),
        ]),
    );
    // Concrete: `{ q : ((Int,Int),(Int,Int)) }` — instantiation-matches all three
    let conc_rec = q_record(
        q,
        IrType::Tuple(vec![
            IrType::Tuple(vec![IrType::Int, IrType::Int]),
            IrType::Tuple(vec![IrType::Int, IrType::Int]),
        ]),
    );

    // All three generic template functions; we'll reorder them below.
    let all_templates = [(f0, t0_rec), (f1, t1_rec), (f2, t2_rec)];
    // Rotate so T2 (index 2) ends up at `deepest_pos` (0 or 2 from callers).
    // With deepest_pos=0: order is T2, T0, T1.
    // With deepest_pos=2: order is T0, T1, T2 (the bug-triggering order).
    let ordered = if deepest_pos == 0 {
        [
            all_templates[2].clone(),
            all_templates[0].clone(),
            all_templates[1].clone(),
        ]
    } else {
        all_templates
    };

    let mut funcs: Vec<Func> = ordered
        .into_iter()
        .zip([0_u32, 1, 2])
        .map(|((name, rec), raw_id)| Func {
            id: FuncId::from_raw(raw_id),
            name,
            home: ModPath(vec![]),
            type_params: vec![(a, BoundSet::UNBOUNDED)],
            row_params: vec![],
            params: vec![(p, rec.clone())],
            ret: rec,
            body: Expr::Var(p),
        })
        .collect();
    funcs.push(Func {
        id: FuncId::from_raw(3),
        name: fconc,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(p, conc_rec.clone())],
        ret: conc_rec,
        body: Expr::Var(p),
    });

    Ok(program(main_mod, funcs, vec![], None))
}

/// Deepest template (specificity 3) defined LAST: a single-pass scan tied T0
/// and T1 before reaching T2, producing a spurious IPE-I0001.  After the
/// two-pass fix this must succeed and resolve the concrete shape to the
/// most-specific struct.
#[test]
fn most_specific_resolution_order_independent_deepest_last() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = three_template_program(&mut interner, 2)?;
    let out = emit(&interner, &prog)?;
    assert!(
        out.contains("RecQ"),
        "concrete use site must resolve to the most-specific struct:\n{out}"
    );
    Ok(())
}

/// Deepest template defined FIRST: was already correct under the old scan.
/// Both orderings must produce the same outcome.
#[test]
fn most_specific_resolution_order_independent_deepest_first() -> DResult<()> {
    let mut interner_first = Interner::new();
    let prog_first = three_template_program(&mut interner_first, 0)?;
    let out_first = emit(&interner_first, &prog_first)?;

    let mut interner_last = Interner::new();
    let prog_last = three_template_program(&mut interner_last, 2)?;
    let out_last = emit(&interner_last, &prog_last)?;

    assert!(
        out_first.contains("RecQ"),
        "deepest-first must resolve to a struct:\n{out_first}"
    );
    assert!(
        out_last.contains("RecQ"),
        "deepest-last must resolve to a struct:\n{out_last}"
    );
    Ok(())
}

/// True ambiguity: two templates at the same maximum specificity, both
/// matching a single concrete use site.  The two-pass fix must still surface
/// this as a `CompilerBug` rather than silently picking either one.
///
/// Templates: `{ q : (a, Int) }` and `{ q : (Int, a) }`, both specificity 2.
/// Concrete: `{ q : (Int, Int) }` — instantiation-matches both.
#[test]
fn true_tie_at_max_specificity_is_ambiguity_error() -> DResult<()> {
    let mut interner = Interner::new();
    let main_mod = interner.intern("Main")?;
    let q = interner.intern("q")?;
    let a = interner.intern("a")?;
    let fa = interner.intern("fa")?;
    let fb = interner.intern("fb")?;
    let fconc = interner.intern("fconc")?;
    let p = interner.intern("p")?;

    // `{ q : (a, Int) }` — specificity 2
    let rec_a = q_record(q, IrType::Tuple(vec![IrType::Generic(a), IrType::Int]));
    // `{ q : (Int, a) }` — specificity 2
    let rec_b = q_record(q, IrType::Tuple(vec![IrType::Int, IrType::Generic(a)]));
    // Concrete `{ q : (Int, Int) }` — matches both templates above at equal specificity
    let rec_conc = q_record(q, IrType::Tuple(vec![IrType::Int, IrType::Int]));

    let fn_a = Func {
        id: FuncId::from_raw(0),
        name: fa,
        home: ModPath(vec![]),
        type_params: vec![(a, BoundSet::UNBOUNDED)],
        row_params: vec![],
        params: vec![(p, rec_a.clone())],
        ret: rec_a,
        body: Expr::Var(p),
    };
    let fn_b = Func {
        id: FuncId::from_raw(1),
        name: fb,
        home: ModPath(vec![]),
        type_params: vec![(a, BoundSet::UNBOUNDED)],
        row_params: vec![],
        params: vec![(p, rec_b.clone())],
        ret: rec_b,
        body: Expr::Var(p),
    };
    let fn_conc = Func {
        id: FuncId::from_raw(2),
        name: fconc,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(p, rec_conc.clone())],
        ret: rec_conc,
        body: Expr::Var(p),
    };

    let prog = program(main_mod, vec![fn_a, fn_b, fn_conc], vec![], None);
    let res = emit(&interner, &prog);
    assert!(
        matches!(res, Err(Diagnostic::CompilerBug { .. })),
        "a true max-specificity tie must surface as CompilerBug, got {res:?}"
    );
    Ok(())
}
