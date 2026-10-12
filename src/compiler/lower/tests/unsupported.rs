//! Each unsupported feature must lower to a `Diagnostic::Lower` carrying the
//! offending node's span and the right `IPE-L01##` code — never a `CompilerBug`.
//!
//! These build the canonical AST + solved types directly (rather than through
//! the parser/checker) so each lowering arm is exercised in isolation: the
//! upstream stages reject most of these shapes earlier, so a source-level test
//! could never reach the lowerer's arm at all.

use std::collections::BTreeMap;

use ipe_canon::ast as canon;
use ipe_diagnostics::{
    Code, DResult, Diagnostic, Feature, IPE_L0101, IPE_L0102, IPE_L0107, IPE_L0108, IPE_L0119,
    IPE_L0154, Located, LowerError, Span,
};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{BoundSet, Callee, Expr, FuncId, IrType, KernelFn};
use ipe_lower::lower;
use ipe_types::{SolvedTypes, Ty};

/// Extract the single lowered function from a one-binding program, or `None` if
/// the shape is unexpected (the caller asserts on the `Option`).
fn single_func(res: &DResult<ipe_ir::Program>) -> Option<&ipe_ir::Func> {
    res.as_ref().ok()?.modules.first()?.funcs.first()
}

/// Lower a hand-built module + binding environment, with no per-region types.
/// Suffices for the arms that never consult `regions` (most unsupported gates).
fn run(
    unions: Vec<canon::Union>,
    defs: Vec<canon::Def>,
    env: BTreeMap<(Vec<Symbol>, Symbol), Ty>,
    interner: &mut Interner,
) -> DResult<ipe_ir::Program> {
    run_with_regions(unions, defs, env, BTreeMap::new(), interner)
}

/// Lower a hand-built module with an explicit per-region (`span` → solved `Ty`)
/// map — needed by the arms that reify a value's solved type (a first-class
/// function reference, a function-typed lambda parameter).
///
/// Test modules have an empty name (`m.name = Vec::new()`), so every span
/// belongs to the empty home.  The helper converts the convenient
/// `BTreeMap<Span, Ty>` the test callers build into the real
/// `BTreeMap<(Vec<Symbol>, Span), Ty>` that `SolvedTypes` expects, using
/// `vec![]` as the home for every entry.
fn run_with_regions(
    unions: Vec<canon::Union>,
    defs: Vec<canon::Def>,
    env: BTreeMap<(Vec<Symbol>, Symbol), Ty>,
    regions: BTreeMap<Span, Ty>,
    interner: &mut Interner,
) -> DResult<ipe_ir::Program> {
    let m = canon::Module {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        name: Vec::new(),
        unions,
        defs,
    };
    let types = SolvedTypes {
        env,
        regions: regions
            .into_iter()
            .map(|(span, ty)| ((vec![], span), ty))
            .collect(),
        expected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        warnings: Vec::new(),
        poly_var_map: BTreeMap::new(),
        untyped_type_params: BTreeMap::new(),
        msg_defaulted_vars: BTreeMap::new(),
        signature_wildcards: BTreeMap::new(),
    };
    // `lower` pairs its diagnostic with the owning def's `home`;
    // these single-module gap tests assert only on the diagnostic, so drop it.
    lower(&m, &types, interner, "", "").map_err(|(d, _home)| d)
}

/// Assert the lowering failed with exactly the expected unsupported feature,
/// code, and primary span — and that it is a `Lower`, never a `CompilerBug`.
#[allow(clippy::expect_used)] // a failed precondition is the test failure
fn assert_unsupported(res: DResult<ipe_ir::Program>, feature: Feature, code: Code, span: Span) {
    assert!(
        res.is_err(),
        "expected an unsupported-feature diagnostic for {feature:?}, got a successful lowering"
    );
    let d = res.expect_err("`res` must be rejected");
    assert_eq!(d.code(), code, "code mismatch ({feature:?}): {d:?}");
    assert_eq!(d.primary_span(), span, "span mismatch ({feature:?}): {d:?}");
    assert_ne!(
        d.primary_span(),
        Span::DUMMY,
        "must carry a real span: {d:?}"
    );
    assert!(
        matches!(
            d,
            Diagnostic::Lower {
                msg: LowerError::Unsupported(f),
                ..
            } if f == feature
        ),
        "expected Lower/Unsupported({feature:?}), got {d:?}"
    );
}

/// A trivial integer-literal expression at `span`.
const fn int(span: Span, n: i64) -> canon::Expr {
    Located::new(span, canon::Expr_::Int(n))
}

/// A built-in nullary type constructor `Int` (so a binding's signature lowers
/// without itself tripping an unsupported arm).
fn con_int(interner: &mut Interner) -> DResult<canon::Type> {
    Ok(canon::Type::Con {
        home: Vec::new(),
        name: interner.intern("Int")?,
        args: Vec::new(),
    })
}

/// The solved `Ty` for `Int` — a nullary type constructor — used to seed the
/// per-region map the eta-expansion arm consults.
fn ty_int(interner: &mut Interner) -> DResult<Ty> {
    Ok(Ty::Con {
        module: Vec::new(),
        name: interner.intern("Int")?,
        args: Vec::new(),
    })
}

/// A minimal, resolvable top-level callee binding so a `VarTopLevel` reference
/// to `name` finds an entry in `func_ids` (which drives `lower_callee`'s
/// top-level resolution). Its own signature is monomorphic (`Int -> Int`) and
/// its body a trivial literal, so it lowers cleanly; the generic scheme the
/// call-boundary gate reads for `name` is supplied separately through the
/// `env`, exactly as the real solver populates it. The `patterns`/spans use a
/// far-away byte range that never overlaps a caller's spans.
fn resolvable_callee_def(interner: &mut Interner, name: Symbol) -> DResult<canon::Def> {
    let p = interner.intern("cx")?;
    Ok(canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(1000, 1001), name),
        free_vars: Vec::new(),
        patterns: vec![Located::new(
            Span::new(1002, 1003),
            canon::Pattern_::PVar(p),
        )],
        body: int(Span::new(1004, 1005), 0),
        ty: canon::Type::Lambda(Box::new(con_int(interner)?), Box::new(con_int(interner)?)),
    })
}

/// Find the lowered function named `name` in a one-module program.
fn func_named<'a>(
    res: &'a DResult<ipe_ir::Program>,
    interner: &Interner,
    name: &str,
) -> Option<&'a ipe_ir::Func> {
    res.as_ref()
        .ok()?
        .modules
        .first()?
        .funcs
        .iter()
        .find(|f| interner.resolve(f.name) == Some(name))
}

/// An unannotated function whose solved type is polymorphic (`f : T0 -> T0`)
/// cannot be lowered without a source-level name for the generic: the backend
/// surfaces `Feature::Polymorphism` (IPE-L0102) rather than emitting unsound
/// `any`-shaped parameters.
#[test]
fn unannotated_fn_with_polymorphic_solved_type_fails_with_polymorphism() -> DResult<()> {
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let x = i.intern("x")?;
    let name = Located::new(Span::new(10, 11), f);
    let patterns = vec![Located::new(Span::new(12, 13), canon::Pattern_::PVar(x))];
    let def = canon::Def::Untyped {
        home: vec![],
        name,
        patterns,
        body: int(Span::new(14, 15), 0),
    };
    // Supply a polymorphic solved type `T0 -> T0` in the env.  The lowerer
    // must peel the Fun, hit `Ty::Var(0)`, and surface Polymorphism rather
    // than emitting an unsound `any` parameter.
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], f),
        Ty::Fun(Box::new(Ty::Var(0)), Box::new(Ty::Var(0))),
    );
    assert_unsupported(
        run(Vec::new(), vec![def], env, &mut i),
        Feature::Polymorphism,
        IPE_L0102,
        Span::new(10, 11),
    );
    Ok(())
}

/// An unannotated function with a fully-concrete solved type (`f x = 0`,
/// solved as `Int -> Int`) lowers cleanly without a type annotation — the
/// IPE-L0106 gate does not apply to monomorphic bindings.
#[test]
fn unannotated_fn_with_concrete_solved_type_lowers_cleanly() -> DResult<()> {
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let x = i.intern("x")?;
    let int_sym = i.intern("Int")?;
    let ty_int = Ty::Con {
        module: vec![],
        name: int_sym,
        args: vec![],
    };
    let name = Located::new(Span::new(10, 11), f);
    let patterns = vec![Located::new(Span::new(12, 13), canon::Pattern_::PVar(x))];
    let def = canon::Def::Untyped {
        home: vec![],
        name,
        patterns,
        body: int(Span::new(14, 15), 0),
    };
    // Solved type `Int -> Int` in the env.
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], f),
        Ty::Fun(Box::new(ty_int.clone()), Box::new(ty_int)),
    );
    let res = run(Vec::new(), vec![def], env, &mut i);
    let func = single_func(&res)
        .expect("unannotated monomorphic fn must lower cleanly without a type annotation");
    assert_eq!(func.params.len(), 1, "one typed param expected: {res:?}");
    let param_ty = func.params.first().map(|(_, t)| t);
    assert_eq!(
        param_ty,
        Some(&IrType::Int),
        "param type must be Int (from solved env)"
    );
    assert_eq!(func.ret, IrType::Int, "return type must be Int");
    assert!(
        func.type_params.is_empty(),
        "monomorphic function must have no type_params"
    );
    Ok(())
}

#[test]
fn wildcard_parameter_lowers_to_a_fresh_binder() -> DResult<()> {
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let ty = canon::Type::Lambda(Box::new(con_int(&mut i)?), Box::new(con_int(&mut i)?));
    // `f _ = 0` — a wildcard parameter is now a valid IRREFUTABLE binding
    // position (IPE-L0105 retired for param patterns; a refutable param is the
    // separate IPE-T0015 gate). It lowers to a fresh unused parameter carrying
    // the annotated type, with no destructure prologue.
    let patterns = vec![Located::new(Span::new(20, 21), canon::Pattern_::PAnything)];
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(18, 19), f),
        free_vars: Vec::new(),
        patterns,
        body: int(Span::new(22, 23), 0),
        ty,
    };
    let res = run(Vec::new(), vec![def], BTreeMap::new(), &mut i);
    let func = single_func(&res).expect("wildcard-param function must lower cleanly");
    assert_eq!(
        func.params.len(),
        1,
        "one synthetic param expected: {res:?}"
    );
    let param_ty = func.params.first().map(|(_, t)| t);
    assert_eq!(param_ty, Some(&IrType::Int), "param type is the annotation");
    assert_eq!(func.ret, IrType::Int, "return type is the annotation tail");
    Ok(())
}

#[test]
fn function_type_in_annotation_argument_lowers_to_fun() -> DResult<()> {
    // `f : (Int -> Int) -> Int` — a higher-order argument lowers to a boxed
    // `Fn` parameter type `Fun([Int], Int)` (first-class functions), not an
    // unsupported-feature diagnostic.
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let x = i.intern("x")?;
    let arg = canon::Type::Lambda(Box::new(con_int(&mut i)?), Box::new(con_int(&mut i)?));
    let ty = canon::Type::Lambda(Box::new(arg), Box::new(con_int(&mut i)?));
    let patterns = vec![Located::new(Span::new(30, 31), canon::Pattern_::PVar(x))];
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(28, 29), f),
        free_vars: Vec::new(),
        patterns,
        body: int(Span::new(32, 33), 0),
        ty,
    };
    let res = run(Vec::new(), vec![def], BTreeMap::new(), &mut i);
    let func = single_func(&res);
    let param_ty = func.and_then(|fc| fc.params.first()).map(|(_, t)| t);
    assert_eq!(
        param_ty,
        Some(&IrType::Fun(vec![IrType::Int], Box::new(IrType::Int))),
        "higher-order param must lower to Fun([Int], Int): {res:?}"
    );
    Ok(())
}

/// a fully-parametric annotation lowers to a *generic* function — the
/// binding's free type variables become `type_params`, and each annotation
/// `Type::Var` becomes an `IrType::Generic`. `identity : a -> a ; identity x = x`
/// emits `type_params = [a]`, param `(x, Generic(a))`, return `Generic(a)`. This
/// is the positive counterpart of the old "polymorphism rejected" gate, now
/// closed for structural pass-through variables.
#[test]
fn parametric_annotation_lowers_to_generic_func() -> DResult<()> {
    let mut i = Interner::new();
    let identity = i.intern("identity")?;
    let a = i.intern("a")?;
    let x = i.intern("x")?;
    // identity : a -> a ; identity x = x
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(40, 48), identity),
        free_vars: vec![a],
        patterns: vec![Located::new(Span::new(49, 50), canon::Pattern_::PVar(x))],
        body: Located::new(Span::new(53, 54), canon::Expr_::VarLocal(x)),
        ty: canon::Type::Lambda(Box::new(canon::Type::Var(a)), Box::new(canon::Type::Var(a))),
    };
    let res = run(Vec::new(), vec![def], BTreeMap::new(), &mut i);
    let func = single_func(&res);
    assert_eq!(
        func.map(|f| f.type_params.clone()),
        Some(vec![(a, BoundSet::UNBOUNDED)]),
        "identity quantifies exactly [a], unbounded: {res:?}"
    );
    assert_eq!(
        func.and_then(|f| f.params.first()).map(|(_, t)| t),
        Some(&IrType::Generic(a)),
        "the parameter type lowers to Generic(a): {res:?}"
    );
    assert_eq!(
        func.map(|f| f.ret.clone()),
        Some(IrType::Generic(a)),
        "the return type lowers to Generic(a): {res:?}"
    );
    Ok(())
}

/// A wildcard `any` nested in the RETURN type that no parameter carries and the
/// body does not pin is not determinable — the emitted function would carry a
/// type parameter appearing only in its result, which no caller can fix (a
/// downstream inference failure). It is rejected fail-closed with `IPE-L0142`,
/// carrying the signature span, never a `CompilerBug`. `foo : Int -> List any`
/// with body `[]` is the canonical case: the return `any` is neither shared with
/// the `Int` parameter nor pinned to a concrete element type by the body.
#[test]
fn return_only_wildcard_any_is_rejected() -> DResult<()> {
    let mut i = Interner::new();
    let foo = i.intern("foo")?;
    let list = i.intern("List")?;
    let sig_span = Span::new(10, 13);
    // foo : Int -> List any ; foo _ = []
    let list_any = canon::Type::Con {
        home: vec![],
        name: list,
        args: vec![canon::Type::Wildcard],
    };
    let ty = canon::Type::Lambda(Box::new(con_int(&mut i)?), Box::new(list_any));
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(sig_span, foo),
        free_vars: Vec::new(),
        patterns: vec![Located::new(Span::new(14, 15), canon::Pattern_::PAnything)],
        body: Located::new(Span::new(20, 22), canon::Expr_::List(Vec::new())),
        ty,
    };
    let res = run(Vec::new(), vec![def], BTreeMap::new(), &mut i);
    assert!(
        res.is_err(),
        "return-only `List any` must be rejected, got a successful lowering: {res:?}"
    );
    let d = res.expect_err("`res` must be rejected");
    assert!(
        matches!(
            d,
            Diagnostic::Lower {
                msg: LowerError::UndeterminableReturnAny,
                ..
            }
        ),
        "expected Lower/UndeterminableReturnAny, got {d:?}"
    );
    assert_eq!(d.primary_span(), sig_span, "blame the signature: {d:?}");
    Ok(())
}

/// A NAMED type variable in a `List`-nested return position (`mk : a -> List a`)
/// is genuine rank-1 polymorphism, not a wildcard `any` — every caller
/// instantiates it independently, and it is carried by a parameter. It must
/// lower cleanly to a generic function quantifying `[a]`, never tripping the
/// return-`any` gate (which fires only on the wildcard, never a named
/// variable).
#[test]
fn named_type_var_in_nested_return_lowers_cleanly() -> DResult<()> {
    let mut i = Interner::new();
    let mk = i.intern("mk")?;
    let a = i.intern("a")?;
    let x = i.intern("x")?;
    let list = i.intern("List")?;
    // mk : a -> List a ; mk x = [x]
    let list_a = canon::Type::Con {
        home: vec![],
        name: list,
        args: vec![canon::Type::Var(a)],
    };
    let ty = canon::Type::Lambda(Box::new(canon::Type::Var(a)), Box::new(list_a));
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(40, 42), mk),
        free_vars: vec![a],
        patterns: vec![Located::new(Span::new(43, 44), canon::Pattern_::PVar(x))],
        body: Located::new(
            Span::new(48, 51),
            canon::Expr_::List(vec![Located::new(
                Span::new(49, 50),
                canon::Expr_::VarLocal(x),
            )]),
        ),
        ty,
    };
    // The list-element region is needed to lower `[x]` fully; supply it so the
    // binding reaches a complete, generic-quantifying lowering.
    let mut regions = BTreeMap::new();
    regions.insert(
        Span::new(48, 51),
        Ty::Con {
            module: vec![],
            name: list,
            args: vec![Ty::Var(0)],
        },
    );
    regions.insert(Span::new(49, 50), Ty::Var(0));
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    // The named-var return must NOT trip the wildcard-`any` gate — that gate keys
    // on the wildcard, which a named variable is not.
    assert!(
        !matches!(
            res,
            Err(Diagnostic::Lower {
                msg: LowerError::UndeterminableReturnAny,
                ..
            })
        ),
        "a named type variable in return position must never trip the return-`any` gate: {res:?}"
    );
    let func = single_func(&res).expect("`mk : a -> List a` must lower cleanly");
    assert_eq!(
        func.ret,
        IrType::List(Box::new(IrType::Generic(a))),
        "return type lowers to List(Generic(a)): {res:?}"
    );
    assert_eq!(
        func.type_params,
        vec![(a, BoundSet::UNBOUNDED)],
        "quantifies exactly the named var [a]: {res:?}"
    );
    Ok(())
}

/// A wildcard `any` PARAMETER the body threads into an `any` return
/// (`thread : any -> any; thread x = x`) must concretize the parameter to the
/// return's solved type, not emit a generic beside a concrete return. The two
/// independent `any` occurrences unify through the body, so the parameter's
/// solved region is the single call-site-pinned concrete type (`String` here).
/// Emitting the parameter as a generic `T{n}` while the return is `String` makes
/// the body return `x: T{n}` where `String` is expected — E0308, an
/// accept-then-`cargo`-fail (THE SEAL). The parameter must lower to `Str`, the
/// return to `Str`, and the function must quantify NO type parameters.
#[test]
fn threaded_param_wildcard_any_concretizes_from_region() -> DResult<()> {
    let mut i = Interner::new();
    let thread = i.intern("thread")?;
    let x = i.intern("x")?;
    let string = i.intern("String")?;
    let sig_span = Span::new(10, 16);
    let param_span = Span::new(20, 21);
    let body_span = Span::new(24, 25);
    // thread : any -> any ; thread x = x
    let ty = canon::Type::Lambda(
        Box::new(canon::Type::Wildcard),
        Box::new(canon::Type::Wildcard),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(sig_span, thread),
        free_vars: Vec::new(),
        patterns: vec![Located::new(param_span, canon::Pattern_::PVar(x))],
        body: Located::new(body_span, canon::Expr_::VarLocal(x)),
        ty,
    };
    // The call site `thread "hi"` pins both the parameter and the body-threaded
    // return `any` to `String`; the solver records that on the param and body
    // regions.
    let string_ty = Ty::Con {
        module: vec![],
        name: string,
        args: vec![],
    };
    let mut regions = BTreeMap::new();
    regions.insert(param_span, string_ty.clone());
    regions.insert(body_span, string_ty);
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    let func = single_func(&res).expect("`thread : any -> any` must lower cleanly");
    assert_eq!(
        func.params,
        vec![(x, IrType::Str)],
        "the threaded parameter concretizes to the return's type (`String`): {res:?}"
    );
    assert_eq!(
        func.ret,
        IrType::Str,
        "the return concretizes to the body's solved type (`String`): {res:?}"
    );
    assert!(
        func.type_params.is_empty(),
        "a concretized threaded `any` quantifies NO type parameter — no generic \
         beside a concrete return: {res:?}"
    );
    Ok(())
}

/// A wildcard `any` PARAMETER the body does NOT thread into the return
/// (`constFn : any -> any; constFn x = "hi"`) leaves the parameter's region a
/// bare solver var. It must stay a generic — sound, because the parameter never
/// flows into the concrete return. This pins that the fix distinguishes
/// threading from non-threading, never blanket-concretizing every parameter.
#[test]
fn unthreaded_param_wildcard_any_stays_generic() -> DResult<()> {
    let mut i = Interner::new();
    let const_fn = i.intern("constFn")?;
    let x = i.intern("x")?;
    let sig_span = Span::new(10, 17);
    let param_span = Span::new(20, 21);
    let body_span = Span::new(24, 28);
    // constFn : any -> any ; constFn x = "hi"
    let ty = canon::Type::Lambda(
        Box::new(canon::Type::Wildcard),
        Box::new(canon::Type::Wildcard),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(sig_span, const_fn),
        free_vars: Vec::new(),
        patterns: vec![Located::new(param_span, canon::Pattern_::PVar(x))],
        body: Located::new(body_span, canon::Expr_::Str("hi".to_string())),
        ty,
    };
    // The parameter is unused by the body: its region stays a bare solver var
    // (nothing pinned it). The body region is the concrete `String` literal.
    let mut regions = BTreeMap::new();
    regions.insert(param_span, Ty::Var(0));
    regions.insert(
        body_span,
        Ty::Con {
            module: vec![],
            name: i.intern("String")?,
            args: vec![],
        },
    );
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    let func = single_func(&res).expect("`constFn : any -> any` must lower cleanly");
    // The parameter stays a generic (its own minted `any` symbol); the return is
    // the concrete body type.
    let (_, param_ty) = func.params.first().expect("one parameter");
    assert!(
        matches!(param_ty, IrType::Generic(_)),
        "an unthreaded parameter `any` stays generic: {res:?}"
    );
    assert_eq!(
        func.ret,
        IrType::Str,
        "the return concretizes to the body's `String` literal: {res:?}"
    );
    assert_eq!(
        func.type_params.len(),
        1,
        "the surviving generic parameter is quantified exactly once: {res:?}"
    );
    Ok(())
}

/// A type variable left unresolved in *value* position (the solver never pinned
/// it to a concrete instance — e.g. an under-determined polymorphic value) is an
/// polymorphism feature gap, not an invariant violation: it surfaces as `IPE-L0102`
/// (`Feature::Polymorphism`) carrying the binding span, never a `CompilerBug`.
#[test]
fn unresolved_type_variable_in_value_position() -> DResult<()> {
    let mut i = Interner::new();
    let g = i.intern("g")?;
    // An untyped nullary binding whose inferred type is a bare variable.
    let def = canon::Def::Untyped {
        home: vec![],
        name: Located::new(Span::new(40, 41), g),
        patterns: Vec::new(),
        body: int(Span::new(44, 45), 0),
    };
    let mut env = BTreeMap::new();
    env.insert((vec![], g), Ty::Var(0));
    // No parameters → the binding's name span is blamed.
    assert_unsupported(
        run(Vec::new(), vec![def], env, &mut i),
        Feature::Polymorphism,
        IPE_L0102,
        Span::new(40, 41),
    );
    Ok(())
}

#[test]
fn task_with_non_unit_result() -> DResult<()> {
    // There is no IPE-L0104 gate: `Task Int` (and all `Task a`) lower
    // successfully to `IrType::Task(IrType::Int)`. This test checks the
    // positive path — the lowering must succeed and the function's return type
    // must be the parametric Task IR type.
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let task = i.intern("Task")?;
    let int_name = i.intern("Int")?;
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], f),
        Ty::Con {
            module: Vec::new(),
            name: task,
            args: vec![Ty::Con {
                module: Vec::new(),
                name: int_name,
                args: Vec::new(),
            }],
        },
    );
    let def = canon::Def::Untyped {
        home: vec![],
        name: Located::new(Span::new(50, 51), f),
        patterns: Vec::new(),
        body: int(Span::new(52, 53), 0),
    };
    let res = run(Vec::new(), vec![def], env, &mut i);
    // Must succeed now that the TaskResults gate is lifted.
    assert!(
        res.is_ok(),
        "Task Int should lower successfully in M5a, got {res:?}"
    );
    let func = single_func(&res).expect("no function in the lowered program");
    assert_eq!(
        func.ret,
        ipe_ir::IrType::Task(Box::new(ipe_ir::IrType::Int)),
        "Task Int must lower to IrType::Task(IrType::Int)"
    );
    Ok(())
}

#[test]
fn inferred_function_type_in_value_position_lowers_to_fun() -> DResult<()> {
    // An inferred function type `Int -> Int` in value position lowers to the
    // boxed `Fn` return type `Fun([Int], Int)` (first-class functions).
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let int_name = i.intern("Int")?;
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], f),
        Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name))),
    );
    let def = canon::Def::Untyped {
        home: vec![],
        name: Located::new(Span::new(60, 61), f),
        patterns: Vec::new(),
        body: int(Span::new(62, 63), 0),
    };
    let res = run(Vec::new(), vec![def], env, &mut i);
    assert_eq!(
        single_func(&res).map(|fc| &fc.ret),
        Some(&IrType::Fun(vec![IrType::Int], Box::new(IrType::Int))),
        "function-typed binding must lower its return to Fun([Int], Int): {res:?}"
    );
    Ok(())
}

#[test]
fn bare_function_reference_lowers_to_func_value() -> DResult<()> {
    // A kernel named as a bare *value* (not called) reifies into a first-class
    // `Expr::FuncValue` carrying its callee and boxed function type — the M1
    // first-class-function value path, not an unsupported-feature diagnostic.
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let module = i.intern("String")?;
    let fname = i.intern("fromInt")?;
    let int_name = i.intern("Int")?;
    let string_name = i.intern("String")?;
    // `f` is annotated with the function type `Int -> String` so the reified
    // kernel value's shape is consistent end-to-end.
    let ty = canon::Type::Lambda(Box::new(con_int(&mut i)?), {
        Box::new(canon::Type::Con {
            home: Vec::new(),
            name: string_name,
            args: Vec::new(),
        })
    });
    let body_span = Span::new(72, 79);
    // body is a bare kernel reference, not a call.
    let body = Located::new(
        body_span,
        canon::Expr_::VarKernel {
            id: None,
            module,
            name: fname,
        },
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(70, 71), f),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    // The solver records the kernel reference's region type `Int -> String`.
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    let mut regions = BTreeMap::new();
    regions.insert(
        body_span,
        Ty::Fun(Box::new(con(int_name)), Box::new(con(string_name))),
    );

    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    let body = single_func(&res).map(|fc| &fc.body);
    assert_eq!(
        body,
        Some(&Expr::FuncValue {
            callee: Callee::Kernel(KernelFn::StringFromInt),
            ty: IrType::Fun(vec![IrType::Int], Box::new(IrType::Str)),
        }),
        "a bare kernel reference must lower to FuncValue: {res:?}"
    );
    Ok(())
}

#[test]
fn function_value_in_record_field_is_accepted() -> DResult<()> {
    // Carrier normalization (Phase 1): a function value stored DIRECTLY in a
    // record field is carried on the `Arc<dyn Fn>` carrier
    // ([`IrType::SharedFun`]), so the synthesised struct gets a hand-written
    // `Clone` and the field is storable — the literal lowers cleanly where it
    // once tripped IPE-L0107.
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let field = i.intern("step")?;
    let int_name = i.intern("Int")?;
    let ty = con_int(&mut i)?;
    // body: `{ step = inc }` where `inc` is a kernel named as a value. The field
    // value's region type is the function type, which trips the gate.
    let field_span = Span::new(82, 85);
    let module = i.intern("String")?;
    let fname = i.intern("fromInt")?;
    let field_value = Located::new(
        field_span,
        canon::Expr_::VarKernel {
            id: None,
            module,
            name: fname,
        },
    );
    let body = Located::new(
        Span::new(80, 90),
        canon::Expr_::Record(vec![(field, field_value)]),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(70, 71), f),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    let mut regions = BTreeMap::new();
    regions.insert(
        field_span,
        Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name))),
    );
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    assert!(
        res.is_ok(),
        "a function value directly in a record field must lower cleanly (Arc \
         carrier), not trip the record-field function gate: {:?}",
        res.err()
    );
    Ok(())
}

#[test]
fn function_in_record_field_via_type_variable_is_accepted() -> DResult<()> {
    // Carrier normalization (Phase 1), indirect: a function value reaching a
    // record field THROUGH a type variable. A generic `wrap : a -> { value : a }`
    // applied as `wrap (\n -> n + 1)` produces a value whose SOLVED region type is
    // `{ value : Int -> Int }`. The record's `Ty::Fun` field is the `Arc<dyn Fn>`
    // carrier at every occurrence, so the value lowers cleanly where it once
    // tripped IPE-L0107.
    let mut i = Interner::new();
    let boxed = i.intern("boxed")?;
    let value = i.intern("value")?;
    let r = i.intern("r")?;
    let int_name = i.intern("Int")?;
    let ty = con_int(&mut i)?;
    // body: a plain local reference whose region type is `{ value : Int -> Int }`.
    let body_span = Span::new(40, 41);
    let body = Located::new(body_span, canon::Expr_::VarLocal(r));
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(36, 37), boxed),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    let mut record_fields = BTreeMap::new();
    record_fields.insert(
        value,
        Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name))),
    );
    let mut regions = BTreeMap::new();
    regions.insert(
        body_span,
        Ty::Record(record_fields, ipe_types::RowTail::Closed),
    );
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    assert!(
        res.is_ok(),
        "a function reaching a record field through a type variable must lower \
         cleanly (Arc carrier), not trip the record-field function gate: {:?}",
        res.err()
    );
    Ok(())
}

#[test]
fn function_inside_opaque_boxed_wrapper_is_accepted() -> DResult<()> {
    // The dual of `function_in_record_field_via_type_variable_is_unsupported`:
    // a function reaching the type argument of a built-in OPAQUE boxed wrapper
    // (`Decoder`/`Task`/`Cmd`/`Sub`) is legitimate, not a non-derivable carrier.
    // `JsonDec.succeed makeLabel : Decoder (String -> Int -> String -> String)`
    // is the canonical decoder-pipeline shape; the runtime `Decoder<E, T>` boxes
    // its payload behind a `Box<dyn Fn>` and derives nothing over `T`, so a
    // function `T` compiles and runs (`decode_succeed(curryN(f))`). The
    // region-based gate MUST NOT reject it the way it rejects a user-enum payload
    // (`Opt (Int -> Int)`, IPE-L0114) or a record field (`{ v : Int -> Int }`,
    // IPE-L0107). Regression for the json_dec_pipeline CtorPayloadFunction
    // false positive.
    let mut i = Interner::new();
    let boxed = i.intern("boxed")?;
    let r = i.intern("r")?;
    let int_name = i.intern("Int")?;
    let decoder_name = i.intern("Decoder")?;
    let ty = con_int(&mut i)?;
    let body_span = Span::new(40, 41);
    // A plain local reference (the gate runs before var resolution, and lowering
    // does not validate the binding — so a clean lowering proves the gate let it
    // through rather than that the reference resolved).
    let body = Located::new(body_span, canon::Expr_::VarLocal(r));
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(36, 37), boxed),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    // region type: `Decoder (Int -> Int)` — a function inside the opaque wrapper.
    let mut regions = BTreeMap::new();
    regions.insert(
        body_span,
        Ty::Con {
            module: Vec::new(),
            name: decoder_name,
            args: vec![Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name)))],
        },
    );
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    assert!(
        res.is_ok(),
        "a function inside an opaque boxed wrapper (Decoder) must lower cleanly, \
         not trip the ctor-payload/record-field function gate: {:?}",
        res.err()
    );
    Ok(())
}

#[test]
fn fn_instantiating_a_generic_record_slot_is_rejected() -> DResult<()> {
    // `wrap : a -> { value : a }` applied as `wrap (\n -> n + 1)` emits a
    // GENERIC `fn wrap<T1: Clone>(x: T1) -> RecValue<T1>` and a generic struct
    // `RecValue<T1>` deriving `Clone`. Instantiating `T1 = Box<dyn Fn>` cannot
    // satisfy the `Clone` bound (E0277). The region gate sees only the
    // monomorphized `{ value : Int -> Int }` (indistinguishable from a directly
    // declared `Ty::Fun` field, which the carrier flip made legal), so the
    // call-boundary gate must recover the declared template `a -> { value : a }`,
    // match the lambda argument's `Int -> Int` against `a`, and reject IPE-L0107.
    let mut i = Interner::new();
    let main = i.intern("main")?;
    let wrap = i.intern("wrap")?;
    let value = i.intern("value")?;
    let n = i.intern("n")?;
    let int_name = i.intern("Int")?;
    let ty = con_int(&mut i)?;
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    let arrow_int = || Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name)));

    // body: `wrap (\n -> n)` — the argument's region type is `Int -> Int`.
    let arg_span = Span::new(40, 50);
    let lambda = Located::new(
        arg_span,
        canon::Expr_::Lambda(
            vec![Located::new(Span::new(41, 42), canon::Pattern_::PVar(n))],
            Box::new(Located::new(Span::new(46, 47), canon::Expr_::VarLocal(n))),
        ),
    );
    let callee = Located::new(
        Span::new(35, 39),
        canon::Expr_::VarTopLevel {
            module: vec![],
            name: wrap,
        },
    );
    let call_span = Span::new(35, 51);
    let body = Located::new(
        call_span,
        canon::Expr_::Call(Box::new(callee), vec![lambda]),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(30, 34), main),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    // Declared template `wrap : a -> { value : a }`.
    let mut record_fields = BTreeMap::new();
    record_fields.insert(value, Ty::Var(0));
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], wrap),
        Ty::Fun(
            Box::new(Ty::Var(0)),
            Box::new(Ty::Record(record_fields, ipe_types::RowTail::Closed)),
        ),
    );
    // The argument's solved region type is `Int -> Int`.
    let mut regions = BTreeMap::new();
    regions.insert(arg_span, arrow_int());
    let callee_def = resolvable_callee_def(&mut i, wrap)?;
    let res = run_with_regions(Vec::new(), vec![callee_def, def], env, regions, &mut i);
    assert_unsupported(res, Feature::FirstClassFunctions, IPE_L0107, call_span);
    Ok(())
}

#[test]
fn point_free_fn_instantiating_a_generic_record_slot_is_rejected() -> DResult<()> {
    // The point-free twin of `fn_instantiating_a_generic_record_slot_is_rejected`:
    // `let w = wrap in w (\n -> n)` routes the same generic-slot instantiation
    // through a local alias, so the callee reaches lowering as a `VarLocal(w)`
    // whose declared scheme is not in `env`. Without the alias-resolving gate the
    // generic `fn wrap<T1: Clone>` is emitted and instantiated at `T1 = Box<dyn
    // Fn>`, an `ipe`-exit-0-then-`cargo`-fail E0277 SEAL breach. The gate must
    // resolve `w` back to `wrap`'s top-level key and reject IPE-L0107 identically.
    let mut i = Interner::new();
    let main = i.intern("main")?;
    let wrap = i.intern("wrap")?;
    let w = i.intern("w")?;
    let value = i.intern("value")?;
    let n = i.intern("n")?;
    let int_name = i.intern("Int")?;
    let ty = con_int(&mut i)?;
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    let arrow_int = || Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name)));

    // `let w = wrap in w (\n -> n)` — the alias binds the top-level `wrap`, and
    // the inner call instantiates it at `Int -> Int`.
    let arg_span = Span::new(40, 50);
    let lambda = Located::new(
        arg_span,
        canon::Expr_::Lambda(
            vec![Located::new(Span::new(41, 42), canon::Pattern_::PVar(n))],
            Box::new(Located::new(Span::new(46, 47), canon::Expr_::VarLocal(n))),
        ),
    );
    let call_span = Span::new(35, 51);
    let inner_call = Located::new(
        call_span,
        canon::Expr_::Call(
            Box::new(Located::new(Span::new(35, 36), canon::Expr_::VarLocal(w))),
            vec![lambda],
        ),
    );
    let binding = canon::LetBinding {
        pat: Located::new(Span::new(30, 31), canon::Pattern_::PVar(w)),
        body: Located::new(
            Span::new(34, 38),
            canon::Expr_::VarTopLevel {
                module: vec![],
                name: wrap,
            },
        ),
    };
    let body = Located::new(
        Span::new(28, 52),
        canon::Expr_::Let(vec![binding], Box::new(inner_call)),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(20, 24), main),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    // Declared template `wrap : a -> { value : a }`.
    let mut record_fields = BTreeMap::new();
    record_fields.insert(value, Ty::Var(0));
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], wrap),
        Ty::Fun(
            Box::new(Ty::Var(0)),
            Box::new(Ty::Record(record_fields, ipe_types::RowTail::Closed)),
        ),
    );
    // The argument's solved region type is `Int -> Int`.
    let mut regions = BTreeMap::new();
    regions.insert(arg_span, arrow_int());
    let callee_def = resolvable_callee_def(&mut i, wrap)?;
    let res = run_with_regions(Vec::new(), vec![callee_def, def], env, regions, &mut i);
    assert_unsupported(res, Feature::FirstClassFunctions, IPE_L0107, call_span);
    Ok(())
}

#[test]
fn same_let_sibling_alias_instantiating_a_generic_record_slot_is_rejected() -> DResult<()> {
    // The sibling-alias twin of `point_free_fn_instantiating_a_generic_record_slot_is_rejected`:
    // `let w = wrap; v = w in v (\n -> n)` is ONE multi-binding `let`, and canon
    // `let` is sequential (`let*`), so `v = w` resolves `w` to the local alias
    // installed by the earlier sibling. The alias registration therefore must run
    // in source order over the live map — a later sibling has to see its
    // predecessors — otherwise `v` resolves to no alias, the callee `VarLocal(v)`
    // escapes the gate, and the generic `fn wrap<T1: Clone>` is emitted and
    // instantiated at `T1 = Box<dyn Fn>`: an `ipe`-exit-0-then-`cargo`-fail E0277
    // SEAL breach. The gate must resolve `v` through `w` back to `wrap` and reject
    // IPE-L0107 identically.
    let mut i = Interner::new();
    let main = i.intern("main")?;
    let wrap = i.intern("wrap")?;
    let w = i.intern("w")?;
    let v = i.intern("v")?;
    let value = i.intern("value")?;
    let n = i.intern("n")?;
    let int_name = i.intern("Int")?;
    let ty = con_int(&mut i)?;
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    let arrow_int = || Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name)));

    // `let w = wrap; v = w in v (\n -> n)` — two siblings in one `let`. The
    // inner call instantiates the aliased `wrap` at `Int -> Int`.
    let arg_span = Span::new(48, 58);
    let lambda = Located::new(
        arg_span,
        canon::Expr_::Lambda(
            vec![Located::new(Span::new(49, 50), canon::Pattern_::PVar(n))],
            Box::new(Located::new(Span::new(54, 55), canon::Expr_::VarLocal(n))),
        ),
    );
    let call_span = Span::new(43, 59);
    let inner_call = Located::new(
        call_span,
        canon::Expr_::Call(
            Box::new(Located::new(Span::new(43, 44), canon::Expr_::VarLocal(v))),
            vec![lambda],
        ),
    );
    // First sibling: `w = wrap`.
    let binding_w = canon::LetBinding {
        pat: Located::new(Span::new(30, 31), canon::Pattern_::PVar(w)),
        body: Located::new(
            Span::new(34, 38),
            canon::Expr_::VarTopLevel {
                module: vec![],
                name: wrap,
            },
        ),
    };
    // Second sibling: `v = w` — a `VarLocal` referring to the earlier sibling.
    let binding_v = canon::LetBinding {
        pat: Located::new(Span::new(39, 40), canon::Pattern_::PVar(v)),
        body: Located::new(Span::new(43, 44), canon::Expr_::VarLocal(w)),
    };
    let body = Located::new(
        Span::new(28, 60),
        canon::Expr_::Let(vec![binding_w, binding_v], Box::new(inner_call)),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(20, 24), main),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    // Declared template `wrap : a -> { value : a }`.
    let mut record_fields = BTreeMap::new();
    record_fields.insert(value, Ty::Var(0));
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], wrap),
        Ty::Fun(
            Box::new(Ty::Var(0)),
            Box::new(Ty::Record(record_fields, ipe_types::RowTail::Closed)),
        ),
    );
    // The argument's solved region type is `Int -> Int`.
    let mut regions = BTreeMap::new();
    regions.insert(arg_span, arrow_int());
    let callee_def = resolvable_callee_def(&mut i, wrap)?;
    let res = run_with_regions(Vec::new(), vec![callee_def, def], env, regions, &mut i);
    assert_unsupported(res, Feature::FirstClassFunctions, IPE_L0107, call_span);
    Ok(())
}

#[test]
fn point_free_alias_instantiating_a_clone_slot_lowers_cleanly() -> DResult<()> {
    // The gate is narrow: a point-free alias applied to a NON-function argument
    // (`let w = wrap in w 0`) instantiates the generic slot at `Int` — a `Clone`
    // type whose bound is satisfiable — so it must lower cleanly, never a false
    // IPE-L0107. Only a fn-embedding binding is a real E0277.
    let mut i = Interner::new();
    // A non-`main` def name: this exercises point-free-alias clone-slot lowering,
    // not the program-entry admissibility gate (which fires only for `main`).
    let probe = i.intern("probe")?;
    let wrap = i.intern("wrap")?;
    let w = i.intern("w")?;
    let value = i.intern("value")?;
    let int_name = i.intern("Int")?;
    let ty = con_int(&mut i)?;

    // `let w = wrap in w 0` — the argument's region type is `Int`.
    let arg_span = Span::new(40, 41);
    let arg = int(arg_span, 0);
    let call_span = Span::new(35, 42);
    let inner_call = Located::new(
        call_span,
        canon::Expr_::Call(
            Box::new(Located::new(Span::new(35, 36), canon::Expr_::VarLocal(w))),
            vec![arg],
        ),
    );
    let binding = canon::LetBinding {
        pat: Located::new(Span::new(30, 31), canon::Pattern_::PVar(w)),
        body: Located::new(
            Span::new(34, 38),
            canon::Expr_::VarTopLevel {
                module: vec![],
                name: wrap,
            },
        ),
    };
    let body = Located::new(
        Span::new(28, 43),
        canon::Expr_::Let(vec![binding], Box::new(inner_call)),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(20, 24), probe),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let mut record_fields = BTreeMap::new();
    record_fields.insert(value, Ty::Var(0));
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], wrap),
        Ty::Fun(
            Box::new(Ty::Var(0)),
            Box::new(Ty::Record(record_fields, ipe_types::RowTail::Closed)),
        ),
    );
    // The value path reifies the callee's solved type: `w` monomorphized to
    // `Int -> { value : Int }`. Seed that region (and the alias body's) so the
    // clean lowering does not surface a spurious "no inferred type" bug.
    let int_con = Ty::Con {
        module: vec![],
        name: int_name,
        args: vec![],
    };
    let mut mono_fields = BTreeMap::new();
    mono_fields.insert(value, int_con.clone());
    let mono_wrap = || {
        Ty::Fun(
            Box::new(int_con.clone()),
            Box::new(Ty::Record(mono_fields.clone(), ipe_types::RowTail::Closed)),
        )
    };
    let mut regions = BTreeMap::new();
    regions.insert(arg_span, ty_int(&mut i)?);
    regions.insert(Span::new(35, 36), mono_wrap());
    regions.insert(Span::new(34, 38), mono_wrap());
    let callee_def = resolvable_callee_def(&mut i, wrap)?;
    let res = run_with_regions(Vec::new(), vec![callee_def, def], env, regions, &mut i);
    assert!(
        res.is_ok(),
        "a point-free alias instantiating a Clone (Int) slot must lower cleanly, \
         not trip the generic-slot gate: {:?}",
        res.err()
    );
    Ok(())
}

#[test]
fn fn_instantiating_a_bare_generic_slot_is_rejected() -> DResult<()> {
    // The record is incidental: the same E0277 hits any bare-variable slot.
    // `always : a -> b -> a` applied to a lambda for `a` instantiates the
    // `Clone`-bounded `T1` to `Box<dyn Fn>` just the same. Partial application
    // (one argument to a two-arrow callee) must gate identically — the boundary
    // gate runs before the arity reshape.
    let mut i = Interner::new();
    let main = i.intern("main")?;
    let always = i.intern("always")?;
    let n = i.intern("n")?;
    let int_name = i.intern("Int")?;
    let ty = con_int(&mut i)?;
    let arrow_int = Ty::Fun(
        Box::new(Ty::Con {
            module: vec![],
            name: int_name,
            args: vec![],
        }),
        Box::new(Ty::Con {
            module: vec![],
            name: int_name,
            args: vec![],
        }),
    );
    let arg_span = Span::new(40, 50);
    let lambda = Located::new(
        arg_span,
        canon::Expr_::Lambda(
            vec![Located::new(Span::new(41, 42), canon::Pattern_::PVar(n))],
            Box::new(Located::new(Span::new(46, 47), canon::Expr_::VarLocal(n))),
        ),
    );
    let callee = Located::new(
        Span::new(33, 39),
        canon::Expr_::VarTopLevel {
            module: vec![],
            name: always,
        },
    );
    let call_span = Span::new(33, 51);
    let body = Located::new(
        call_span,
        canon::Expr_::Call(Box::new(callee), vec![lambda]),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(30, 34), main),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    // `always : a -> b -> a`.
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], always),
        Ty::Fun(
            Box::new(Ty::Var(0)),
            Box::new(Ty::Fun(Box::new(Ty::Var(1)), Box::new(Ty::Var(0)))),
        ),
    );
    let mut regions = BTreeMap::new();
    regions.insert(arg_span, arrow_int);
    let callee_def = resolvable_callee_def(&mut i, always)?;
    let res = run_with_regions(Vec::new(), vec![callee_def, def], env, regions, &mut i);
    assert_unsupported(res, Feature::FirstClassFunctions, IPE_L0107, call_span);
    Ok(())
}

#[test]
fn hof_argument_matching_a_declared_arrow_stays_accepted() -> DResult<()> {
    // The over-rejection tripwire: a genuine higher-order function
    // `apply : (a -> b) -> a -> b` applied to a lambda must STAY ACCEPTED. The
    // function argument matches the callee's declared ARROW `(a -> b)`, binding
    // `a := Int`, `b := Int` — no type variable binds to a function, so the gate
    // stays silent and the already-supported `Box<dyn Fn>` parameter emits. The
    // gate rejects ONLY a variable bound to a function, never a declared arrow.
    let mut i = Interner::new();
    // A non-`main` def name: this exercises higher-order-argument lowering, not
    // the program-entry admissibility gate (which fires only for `main`).
    let probe = i.intern("probe")?;
    let apply = i.intern("apply")?;
    let n = i.intern("n")?;
    let int_name = i.intern("Int")?;
    let ty = con_int(&mut i)?;
    let con_int_ty = || Ty::Con {
        module: vec![],
        name: int_name,
        args: vec![],
    };
    let arrow_int = || Ty::Fun(Box::new(con_int_ty()), Box::new(con_int_ty()));
    let arg_span = Span::new(40, 50);
    let lambda = Located::new(
        arg_span,
        canon::Expr_::Lambda(
            vec![Located::new(Span::new(41, 42), canon::Pattern_::PVar(n))],
            Box::new(Located::new(Span::new(46, 47), canon::Expr_::VarLocal(n))),
        ),
    );
    let callee = Located::new(
        Span::new(33, 38),
        canon::Expr_::VarTopLevel {
            module: vec![],
            name: apply,
        },
    );
    let call_span = Span::new(33, 51);
    // `apply f` — one argument to the two-arrow callee (partial application).
    let body = Located::new(
        call_span,
        canon::Expr_::Call(Box::new(callee), vec![lambda]),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(30, 34), probe),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    // `apply : (a -> b) -> a -> b`.
    let mut env = BTreeMap::new();
    env.insert(
        (vec![], apply),
        Ty::Fun(
            Box::new(Ty::Fun(Box::new(Ty::Var(0)), Box::new(Ty::Var(1)))),
            Box::new(Ty::Fun(Box::new(Ty::Var(0)), Box::new(Ty::Var(1)))),
        ),
    );
    let mut regions = BTreeMap::new();
    regions.insert(arg_span, arrow_int());
    let callee_def = resolvable_callee_def(&mut i, apply)?;
    let res = run_with_regions(Vec::new(), vec![callee_def, def], env, regions, &mut i);
    assert!(
        res.is_ok(),
        "a higher-order argument matching a declared arrow must stay accepted \
         (no variable binds to a function): {:?}",
        res.err()
    );
    Ok(())
}

#[test]
fn function_inside_maybe_via_type_variable_is_accepted() -> DResult<()> {
    // #90 (IPE-L0114 narrowing, T1): a function reaching the type argument of
    // the built-in ENUM-LIKE `Maybe` is sound — `Just`/`Ok` construct the
    // RUNTIME `IpeMaybe`/`IpeResult` enums, whose derives are generic-bounded,
    // so the type compiles regardless of the payload; use (`==`/stringify/
    // serde) is independently gated elsewhere. Same shape as
    // `function_inside_opaque_boxed_wrapper_is_accepted`, but for an
    // enum-like (not opaque) head — the region gate must now let it through
    // too, distinct from a COLLECTION head (see the `List` sibling test).
    let mut i = Interner::new();
    let boxed = i.intern("boxed")?;
    let r = i.intern("r")?;
    let int_name = i.intern("Int")?;
    let maybe_name = i.intern("Maybe")?;
    let ty = con_int(&mut i)?;
    let body_span = Span::new(40, 41);
    let body = Located::new(body_span, canon::Expr_::VarLocal(r));
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(36, 37), boxed),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    // region type: `Maybe (Int -> Int)` — a function inside the enum-like
    // built-in `Maybe`.
    let mut regions = BTreeMap::new();
    regions.insert(
        body_span,
        Ty::Con {
            module: Vec::new(),
            name: maybe_name,
            args: vec![Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name)))],
        },
    );
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    assert!(
        res.is_ok(),
        "a function inside `Maybe` must lower cleanly (#90) — the runtime \
         IpeMaybe's derives are generic-bounded: {:?}",
        res.err()
    );
    Ok(())
}

#[test]
fn function_inside_list_via_type_variable_lowers() -> DResult<()> {
    // A `List (a -> b)` stores its function element on the `Clone` `Arc<dyn Fn>`
    // carrier (`Vec<Arc<dyn Fn>>` is `Clone`), so a function element is a storable
    // value, not a non-derivable carrier — it lowers cleanly. An equality/ordering
    // kernel over such a list is separately rejected (the element-capability gate,
    // IPE-L0134); the bare storage lowering here must succeed.
    let mut i = Interner::new();
    let boxed = i.intern("boxed")?;
    let r = i.intern("r")?;
    let int_name = i.intern("Int")?;
    let list_name = i.intern("List")?;
    let ty = con_int(&mut i)?;
    let body_span = Span::new(40, 41);
    let body = Located::new(body_span, canon::Expr_::VarLocal(r));
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(36, 37), boxed),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let con = |name| Ty::Con {
        module: Vec::new(),
        name,
        args: Vec::new(),
    };
    // region type: `List (Int -> Int)` — a function element of the COLLECTION
    // built-in `List`, carried on the `Arc<dyn Fn>` `SharedFun` carrier.
    let mut regions = BTreeMap::new();
    regions.insert(
        body_span,
        Ty::Con {
            module: Vec::new(),
            name: list_name,
            args: vec![Ty::Fun(Box::new(con(int_name)), Box::new(con(int_name)))],
        },
    );
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, &mut i);
    assert!(
        res.is_ok(),
        "a function element of a `List` is storable on the `Arc` carrier and must \
         lower cleanly: {:?}",
        res.err()
    );
    Ok(())
}

#[test]
fn value_callee_lowers_to_apply() -> DResult<()> {
    // A call whose callee is not a kernel/top-level name (here a local that
    // would hold a function value) lowers to `Expr::Apply`, the first-class
    // application path — distinct from the direct `Expr::Call` callee path.
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let g = i.intern("g")?;
    let ty = con_int(&mut i)?;
    let callee_ref = Box::new(Located::new(Span::new(82, 83), canon::Expr_::VarLocal(g)));
    let arg = int(Span::new(84, 85), 5);
    let body = Located::new(Span::new(82, 90), canon::Expr_::Call(callee_ref, vec![arg]));
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(80, 81), f),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let res = run(Vec::new(), vec![def], BTreeMap::new(), &mut i);
    let body = single_func(&res).map(|fc| &fc.body);
    assert!(
        matches!(
            body,
            Some(Expr::Apply { func, args })
                if matches!(func.as_ref(), Expr::Var(s) if *s == g) && args.len() == 1
        ),
        "a value callee must lower to Apply over the local, got {body:?}"
    );
    Ok(())
}

#[test]
fn unknown_kernel_call() -> DResult<()> {
    // M5a wired `Time.now` and many other kernels. Use a genuinely-unwired
    // module name (`UnknownMod`) so the catch-all arm still fires IPE-L0108.
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let module = i.intern("UnknownMod")?;
    let fname = i.intern("unknownFn")?;
    let ty = con_int(&mut i)?;
    let callee_ref = Box::new(Located::new(
        Span::new(92, 100),
        canon::Expr_::VarKernel {
            id: None,
            module,
            name: fname,
        },
    ));
    let body = Located::new(
        Span::new(92, 102),
        canon::Expr_::Call(callee_ref, Vec::new()),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(90, 91), f),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    assert_unsupported(
        run(Vec::new(), vec![def], BTreeMap::new(), &mut i),
        Feature::Kernels,
        IPE_L0108,
        Span::new(92, 100),
    );
    Ok(())
}

#[test]
fn unsupported_binary_operator() -> DResult<()> {
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let op = i.intern("::")?;
    let home = i.intern("Basics")?;
    let func = i.intern("cons")?;
    let ty = con_int(&mut i)?;
    // 1 :: 2 — the list cons operator (`::` → cons) awaits the list type; the
    // M1-core arithmetic/comparison/boolean set plus string append (`++` →
    // append) are supported, so cons is the remaining gated binop.
    let body = Located::new(
        Span::new(112, 117),
        canon::Expr_::Binop {
            op,
            op_span: Span::new(113, 115),
            home,
            func,
            lhs: Box::new(int(Span::new(112, 113), 1)),
            rhs: Box::new(int(Span::new(116, 117), 2)),
        },
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(110, 111), f),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    // The whole binop expression span is blamed.
    assert_unsupported(
        run(Vec::new(), vec![def], BTreeMap::new(), &mut i),
        Feature::BinOps,
        IPE_L0101,
        Span::new(112, 117),
    );
    Ok(())
}

/// a single wildcard `case` arm is now a supported FLAT match (a trailing
/// catch-all is structurally exhaustive), no longer the IPE-L0100 gap. The
/// lowering succeeds and yields a `Match` body.
#[test]
fn wildcard_only_case_lowers_to_flat_match() -> DResult<()> {
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let x = i.intern("x")?;
    let ty = con_int(&mut i)?;
    // case x of _ -> 0
    let scrut = Box::new(Located::new(Span::new(122, 123), canon::Expr_::VarLocal(x)));
    let branch = canon::CaseBranch {
        pat: Located::new(Span::new(126, 127), canon::Pattern_::PAnything),
        body: int(Span::new(130, 131), 0),
    };
    let body = Located::new(Span::new(120, 132), canon::Expr_::Case(scrut, vec![branch]));
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(118, 119), f),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let res = run(Vec::new(), vec![def], BTreeMap::new(), &mut i);
    let body = single_func(&res).map(|fc| &fc.body);
    assert!(
        matches!(body, Some(Expr::Match(_))),
        "wildcard-only case must lower to a flat Match, got {body:?}"
    );
    Ok(())
}

/// a constructor arm followed by a variable catch-all is now a supported
/// FLAT match (the trailing variable is an irrefutable catch-all), no longer the
/// IPE-L0100 gap.
#[test]
fn ctor_then_variable_catch_all_lowers_to_flat_match() -> DResult<()> {
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let x = i.intern("x")?;
    let msg = i.intern("Msg")?;
    let inc = i.intern("Increment")?;
    let dec = i.intern("Decrement")?;
    let ty = con_int(&mut i)?;
    let union = canon::Union {
        home: Vec::new(),
        name: msg,
        name_span: Span::DUMMY,
        vars: Vec::new(),
        ctors: vec![
            canon::Ctor {
                name: inc,
                index: 0,
                arity: 0,
                args: Vec::new(),
                span: Span::new(0, 0),
            },
            canon::Ctor {
                name: dec,
                index: 1,
                arity: 0,
                args: Vec::new(),
                span: Span::new(0, 0),
            },
        ],
    };
    let scrut = Box::new(Located::new(Span::new(142, 143), canon::Expr_::VarLocal(x)));
    let arm0 = canon::CaseBranch {
        pat: Located::new(
            Span::new(146, 155),
            canon::Pattern_::PCtor {
                home: Vec::new(),
                type_name: msg,
                name: inc,
                index: 0,
                args: Vec::new(),
            },
        ),
        body: int(Span::new(159, 160), 0),
    };
    // The second arm is a variable catch-all — supported in M3b-3.
    let arm1 = canon::CaseBranch {
        pat: Located::new(Span::new(163, 164), canon::Pattern_::PVar(x)),
        body: int(Span::new(168, 169), 1),
    };
    let body = Located::new(
        Span::new(140, 170),
        canon::Expr_::Case(scrut, vec![arm0, arm1]),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(138, 139), f),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty,
    };
    let res = run(vec![union], vec![def], BTreeMap::new(), &mut i);
    let body = single_func(&res).map(|fc| &fc.body);
    assert!(
        matches!(body, Some(Expr::Match(_))),
        "ctor + variable catch-all must lower to a flat Match, got {body:?}"
    );
    Ok(())
}

#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn partial_application_eta_expands_to_a_closure() -> DResult<()> {
    // `add` declares two parameters; `add 2` passes one. Partial application now
    // eta-expands into a boxed closure `\eta_0 -> add(2, eta_0)` — a first-class
    // function value — rather than failing closed with IPE-L0110. (M1 b4 closed
    // the partial/over-application gate for named callees.)
    let mut i = Interner::new();
    let add = i.intern("add")?;
    let caller = i.intern("caller")?;
    let a = i.intern("a")?;
    let b = i.intern("b")?;
    // add : Int -> Int -> Int   (two parameters)
    let add_ty = canon::Type::Lambda(
        Box::new(con_int(&mut i)?),
        Box::new(canon::Type::Lambda(
            Box::new(con_int(&mut i)?),
            Box::new(con_int(&mut i)?),
        )),
    );
    let add_def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(10, 13), add),
        free_vars: Vec::new(),
        patterns: vec![
            Located::new(Span::new(14, 15), canon::Pattern_::PVar(a)),
            Located::new(Span::new(16, 17), canon::Pattern_::PVar(b)),
        ],
        body: int(Span::new(20, 21), 0),
        ty: add_ty,
    };
    // caller : Int -> Int   — its body `add 2` is a one-argument call.
    let callee_span = Span::new(40, 43);
    let call_span = Span::new(40, 45);
    let callee_ref = Box::new(Located::new(
        callee_span,
        canon::Expr_::VarTopLevel {
            module: Vec::new(),
            name: add,
        },
    ));
    let body = Located::new(
        call_span,
        canon::Expr_::Call(callee_ref, vec![int(Span::new(44, 45), 2)]),
    );
    let caller_ty = canon::Type::Lambda(Box::new(con_int(&mut i)?), Box::new(con_int(&mut i)?));
    let caller_def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(30, 36), caller),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty: caller_ty,
    };
    // The eta-expansion reads the callee's solved arrow type from its region.
    let mut regions = BTreeMap::new();
    regions.insert(
        callee_span,
        Ty::Fun(
            Box::new(ty_int(&mut i)?),
            Box::new(Ty::Fun(
                Box::new(ty_int(&mut i)?),
                Box::new(ty_int(&mut i)?),
            )),
        ),
    );

    let res = run_with_regions(
        Vec::new(),
        vec![add_def, caller_def],
        BTreeMap::new(),
        regions,
        &mut i,
    );
    assert!(res.is_ok(), "partial application must lower, got {res:?}");

    let caller_fn = func_named(&res, &i, "caller");
    let Some(caller_fn) = caller_fn else {
        panic!("caller must lower")
    };
    // The body is the eta-lambda `\eta_0: Int -> add(2, eta_0)` : Int -> Int.
    let Expr::Lambda { params, ret, body } = &caller_fn.body else {
        panic!("partial lowers to a Lambda, got {:?}", caller_fn.body)
    };
    assert_eq!(params.len(), 1, "one missing parameter");
    let Some((eta_sym, eta_ty)) = params.first() else {
        panic!("one missing parameter");
    };
    assert_eq!(*eta_ty, IrType::Int, "missing param keeps its solved type");
    assert_eq!(
        i.resolve(*eta_sym),
        Some("eta_0"),
        "fresh, collision-free eta param name"
    );
    assert_eq!(*ret, IrType::Int, "residual return type");
    // body: add(2, eta_0) — a saturated direct Call to add (FuncId 0).
    let Expr::Call { callee, args, .. } = body.as_ref() else {
        panic!("eta body is a saturated Call, got {body:?}")
    };
    assert_eq!(*callee, Callee::Func(FuncId::from_raw(0)));
    assert_eq!(args.len(), 2, "supplied arg + synthesised param");
    assert!(matches!(args.first(), Some(Expr::Int(2))), "captured arg 2");
    assert!(
        matches!(args.get(1), Some(Expr::Var(s)) if s == eta_sym),
        "trailing arg is the eta param"
    );
    Ok(())
}

#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn over_application_saturates_via_apply() -> DResult<()> {
    // `f` declares one parameter; `f 1 2` passes two — over-application across
    // the arity boundary. The first arg saturates the direct `Call(f, [1])`
    // (which returns a function value); the surplus `2` applies to that result
    // through an `Apply`, rather than failing closed with IPE-L0110.
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let caller = i.intern("caller")?;
    let x = i.intern("x")?;
    // f : Int -> Int   (one parameter)
    let f_ty = canon::Type::Lambda(Box::new(con_int(&mut i)?), Box::new(con_int(&mut i)?));
    let f_def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(10, 11), f),
        free_vars: Vec::new(),
        patterns: vec![Located::new(Span::new(12, 13), canon::Pattern_::PVar(x))],
        body: int(Span::new(16, 17), 0),
        ty: f_ty,
    };
    // caller : Int   — its body `f 1 2` is a two-argument call of a unary `f`.
    let call_span = Span::new(40, 47);
    let callee_ref = Box::new(Located::new(
        Span::new(40, 41),
        canon::Expr_::VarTopLevel {
            module: Vec::new(),
            name: f,
        },
    ));
    let body = Located::new(
        call_span,
        canon::Expr_::Call(
            callee_ref,
            vec![int(Span::new(44, 45), 1), int(Span::new(46, 47), 2)],
        ),
    );
    let caller_def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(30, 36), caller),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty: con_int(&mut i)?,
    };

    let res = run(Vec::new(), vec![f_def, caller_def], BTreeMap::new(), &mut i);
    assert!(res.is_ok(), "over-application must lower, got {res:?}");

    let Some(caller_fn) = func_named(&res, &i, "caller") else {
        panic!("caller must lower")
    };
    // body: (f(1))(2) — Apply over a saturated direct Call.
    let Expr::Apply { func, args } = &caller_fn.body else {
        panic!("over lowers to an Apply, got {:?}", caller_fn.body)
    };
    let Expr::Call {
        callee, args: head, ..
    } = func.as_ref()
    else {
        panic!("Apply func is a direct Call, got {func:?}")
    };
    assert_eq!(*callee, Callee::Func(FuncId::from_raw(0)));
    assert_eq!(head.len(), 1, "first arity args saturate the Call");
    assert!(
        matches!(head.first(), Some(Expr::Int(1))),
        "saturating arg 1"
    );
    assert_eq!(args.len(), 1, "surplus arg applied to the result");
    assert!(matches!(args.first(), Some(Expr::Int(2))), "surplus arg 2");
    Ok(())
}

#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn nested_lambda_body_flattens_into_one_closure() -> DResult<()> {
    // `f a = \b -> \c -> 0` declared `Int -> Int -> Int -> Int`. The body is a
    // curried lambda chain; the lowerer must flatten it into ONE
    // multi-parameter closure so the emitted `Box<dyn Fn(i64, i64) -> i64>` body
    // matches the flattened return type `split_typed_sig` produces. (Without the
    // flatten the body would be a curried `Fn(i64) -> Fn(i64) -> i64`, which
    // cargo rejects with no Ipê diagnostic.) The innermost body is `0` — the
    // flatten depends only on the lambda chain + arrow type, not on the body.
    let mut i = Interner::new();
    let f_sym = i.intern("f")?;
    let a_sym = i.intern("a")?;
    let b_sym = i.intern("b")?;
    let c_sym = i.intern("c")?;
    // f : Int -> Int -> Int -> Int
    let f_ty = canon::Type::Lambda(
        Box::new(con_int(&mut i)?),
        Box::new(canon::Type::Lambda(
            Box::new(con_int(&mut i)?),
            Box::new(canon::Type::Lambda(
                Box::new(con_int(&mut i)?),
                Box::new(con_int(&mut i)?),
            )),
        )),
    );
    // body: \b -> \c -> 0   (two nested lambdas at distinct spans).
    let inner_span = Span::new(30, 40);
    let outer_span = Span::new(20, 40);
    let inner = Located::new(
        inner_span,
        canon::Expr_::Lambda(
            vec![Located::new(
                Span::new(31, 32),
                canon::Pattern_::PVar(c_sym),
            )],
            Box::new(int(Span::new(35, 36), 0)),
        ),
    );
    let outer = Located::new(
        outer_span,
        canon::Expr_::Lambda(
            vec![Located::new(
                Span::new(21, 22),
                canon::Pattern_::PVar(b_sym),
            )],
            Box::new(inner),
        ),
    );
    let f_def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(10, 11), f_sym),
        free_vars: Vec::new(),
        patterns: vec![Located::new(
            Span::new(12, 13),
            canon::Pattern_::PVar(a_sym),
        )],
        body: outer,
        ty: f_ty,
    };
    // Region types: outer lambda is `Int -> Int -> Int`, inner is `Int -> Int`.
    let mut regions = BTreeMap::new();
    regions.insert(
        outer_span,
        Ty::Fun(
            Box::new(ty_int(&mut i)?),
            Box::new(Ty::Fun(
                Box::new(ty_int(&mut i)?),
                Box::new(ty_int(&mut i)?),
            )),
        ),
    );
    regions.insert(
        inner_span,
        Ty::Fun(Box::new(ty_int(&mut i)?), Box::new(ty_int(&mut i)?)),
    );

    let res = run_with_regions(Vec::new(), vec![f_def], BTreeMap::new(), regions, &mut i);
    assert!(res.is_ok(), "nested-lambda binding must lower, got {res:?}");

    let Some(f_fn) = func_named(&res, &i, "f") else {
        panic!("f must lower")
    };
    // f keeps its one declared parameter; its return type is the FLATTENED
    // two-argument closure, never a curried one.
    assert_eq!(f_fn.params.len(), 1, "one declared parameter `a`");
    assert_eq!(
        f_fn.ret,
        IrType::Fun(vec![IrType::Int, IrType::Int], Box::new(IrType::Int)),
        "return type is the flattened Fn(Int, Int) -> Int"
    );
    // The body is ONE Lambda taking BOTH `b` and `c`, returning Int — the nested
    // chain collapsed into a single multi-parameter closure.
    let Expr::Lambda { params, ret, body } = &f_fn.body else {
        panic!(
            "body lowers to a single flattened Lambda, got {:?}",
            f_fn.body
        )
    };
    assert_eq!(params.len(), 2, "both `b` and `c` in one closure");
    let names: Vec<Option<&str>> = params.iter().map(|(s, _)| i.resolve(*s)).collect();
    assert_eq!(
        names,
        vec![Some("b"), Some("c")],
        "flattened params are `b` then `c`, in order"
    );
    assert!(
        params.iter().all(|(_, t)| *t == IrType::Int),
        "both params keep their solved Int type"
    );
    assert_eq!(*ret, IrType::Int, "the flattened closure returns Int");
    assert!(
        matches!(body.as_ref(), Expr::Int(0)),
        "innermost body is the literal 0, got {body:?}"
    );
    Ok(())
}

#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn partial_application_of_a_first_class_value_eta_expands() -> DResult<()> {
    // Partial application of a first-class *value* (here a lambda) — `(\b -> \c
    // -> 0) 2` passes one argument to a two-arity closure. The named-callee path
    // eta-expands an arity mismatch; the value path now does too, capturing the
    // value and the supplied arg into a residual closure `\eta_0 -> (value)(2,
    // eta_0)` : Int -> Int (matching the reference's curried-closure model),
    // rather than failing closed with IPE-L0110.
    let mut i = Interner::new();
    let caller = i.intern("caller")?;
    let b = i.intern("b")?;
    let c = i.intern("c")?;
    // The callee value: \b -> \c -> 0  (solved type Int -> Int -> Int, arity 2).
    let callee_span = Span::new(40, 50);
    let inner = Located::new(
        Span::new(42, 50),
        canon::Expr_::Lambda(
            vec![Located::new(Span::new(43, 44), canon::Pattern_::PVar(c))],
            Box::new(int(Span::new(47, 48), 0)),
        ),
    );
    let callee_lambda = Box::new(Located::new(
        callee_span,
        canon::Expr_::Lambda(
            vec![Located::new(Span::new(41, 42), canon::Pattern_::PVar(b))],
            Box::new(inner),
        ),
    ));
    // caller : Int   — body `(\b -> \c -> 0) 2` applies the value with one arg.
    let call_span = Span::new(40, 53);
    let body = Located::new(
        call_span,
        canon::Expr_::Call(callee_lambda, vec![int(Span::new(52, 53), 2)]),
    );
    let caller_def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(30, 36), caller),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty: con_int(&mut i)?,
    };
    // The value-application gate reads the callee value's solved arrow arity.
    let mut regions = BTreeMap::new();
    regions.insert(
        callee_span,
        Ty::Fun(
            Box::new(ty_int(&mut i)?),
            Box::new(Ty::Fun(
                Box::new(ty_int(&mut i)?),
                Box::new(ty_int(&mut i)?),
            )),
        ),
    );

    let res = run_with_regions(
        Vec::new(),
        vec![caller_def],
        BTreeMap::new(),
        regions,
        &mut i,
    );
    assert!(
        res.is_ok(),
        "value partial application must eta-expand, got {res:?}"
    );
    let caller_fn = func_named(&res, &i, "caller");
    let Some(caller_fn) = caller_fn else {
        panic!("caller must lower")
    };
    // The body is the residual eta-lambda `\eta_0: Int -> (value)(2, eta_0)`.
    let Expr::Lambda { params, ret, body } = &caller_fn.body else {
        panic!("value partial lowers to a Lambda, got {:?}", caller_fn.body)
    };
    assert_eq!(params.len(), 1, "one missing parameter");
    let Some((_, eta_ty)) = params.first() else {
        panic!("one missing parameter");
    };
    assert_eq!(*eta_ty, IrType::Int, "missing param keeps its solved type");
    assert_eq!(*ret, IrType::Int, "residual return type");
    // body: Apply { func: <value>, args: [2, eta_0] } — every arg at once.
    let Expr::Apply { args, .. } = body.as_ref() else {
        panic!("eta body is an Apply of the value, got {body:?}")
    };
    assert_eq!(args.len(), 2, "supplied arg + synthesised residual param");
    assert!(
        matches!(args.first(), Some(Expr::Int(2))),
        "captured supplied arg 2"
    );
    let _ = call_span;
    Ok(())
}

#[test]
// Thorough IR-fixture probe: builds a 4-arrow callee, over-applies it short of
// saturation, and asserts the full residual eta-lambda shape. Naturally long;
// matches the ipe_backend_rust fixture-test convention.
#[allow(clippy::too_many_lines)]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn over_application_with_partial_surplus_eta_expands() -> DResult<()> {
    // `f` declares ONE parameter but a four-arrow type `Int -> Int -> Int -> Int
    // -> Int`, so `f 1` returns a flattened THREE-argument closure. `f 1 2`
    // over-applies (two args > one declared param) but the single surplus arg
    // does NOT saturate that three-argument closure — the result is itself a
    // partial application of the returned first-class value. The over path now
    // eta-expands it (matching the reference's `IpeCall(f(1), 2)` residual):
    // `\eta_0 \eta_1 -> (f(1))(2, eta_0, eta_1)` — capturing the direct call and
    // the surplus arg, taking the two still-missing params, rather than failing
    // closed with IPE-L0110. (`f 1 2 3 4` — surplus 3 == returned arity 3 —
    // still saturates exactly and lowers to a single `Apply`; this test pins the
    // short-surplus case.)
    let mut i = Interner::new();
    let f = i.intern("f")?;
    let caller = i.intern("caller")?;
    let x = i.intern("x")?;
    // f : Int -> Int -> Int -> Int -> Int   (one declared parameter)
    let f_ty = canon::Type::Lambda(
        Box::new(con_int(&mut i)?),
        Box::new(canon::Type::Lambda(
            Box::new(con_int(&mut i)?),
            Box::new(canon::Type::Lambda(
                Box::new(con_int(&mut i)?),
                Box::new(canon::Type::Lambda(
                    Box::new(con_int(&mut i)?),
                    Box::new(con_int(&mut i)?),
                )),
            )),
        )),
    );
    let f_def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(10, 11), f),
        free_vars: Vec::new(),
        patterns: vec![Located::new(Span::new(12, 13), canon::Pattern_::PVar(x))],
        body: int(Span::new(16, 17), 0),
        ty: f_ty,
    };
    // caller : Int   — body `f 1 2`: two args against a one-parameter callee.
    let callee_span = Span::new(40, 41);
    let call_span = Span::new(40, 45);
    let callee_ref = Box::new(Located::new(
        callee_span,
        canon::Expr_::VarTopLevel {
            module: Vec::new(),
            name: f,
        },
    ));
    let body = Located::new(
        call_span,
        canon::Expr_::Call(
            callee_ref,
            vec![int(Span::new(42, 43), 1), int(Span::new(44, 45), 2)],
        ),
    );
    let caller_def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(30, 36), caller),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty: con_int(&mut i)?,
    };
    // The over-application gate reads the callee's full arrow arity (4) and
    // subtracts the one consumed parameter — the returned closure needs 3 args.
    let mut regions = BTreeMap::new();
    regions.insert(
        callee_span,
        Ty::Fun(
            Box::new(ty_int(&mut i)?),
            Box::new(Ty::Fun(
                Box::new(ty_int(&mut i)?),
                Box::new(Ty::Fun(
                    Box::new(ty_int(&mut i)?),
                    Box::new(Ty::Fun(
                        Box::new(ty_int(&mut i)?),
                        Box::new(ty_int(&mut i)?),
                    )),
                )),
            )),
        ),
    );

    let res = run_with_regions(
        Vec::new(),
        vec![f_def, caller_def],
        BTreeMap::new(),
        regions,
        &mut i,
    );
    assert!(
        res.is_ok(),
        "under-saturating over-application must eta-expand, got {res:?}"
    );
    let Some(caller_fn) = func_named(&res, &i, "caller") else {
        panic!("caller must lower")
    };
    // Residual eta-lambda `\eta_0 \eta_1 -> (Call(f, [1]))(2, eta_0, eta_1)`.
    let Expr::Lambda { params, body, .. } = &caller_fn.body else {
        panic!("over-partial lowers to a Lambda, got {:?}", caller_fn.body)
    };
    assert_eq!(
        params.len(),
        2,
        "two still-missing params (3 returned − 1 surplus)"
    );
    let Expr::Apply { func, args } = body.as_ref() else {
        panic!("eta body is an Apply, got {body:?}")
    };
    assert!(
        matches!(func.as_ref(), Expr::Call { .. }),
        "applies Call(f, head), got {func:?}"
    );
    assert_eq!(
        args.len(),
        3,
        "surplus arg + two synthesised residual params"
    );
    assert!(
        matches!(args.first(), Some(Expr::Int(2))),
        "captured surplus arg 2"
    );
    let _ = call_span;
    Ok(())
}

#[test]
fn let_bound_live_app_cfg_is_unsupported() -> DResult<()> {
    // `Web.tea cfg` where `cfg` is a plain local var (not a record literal)
    // must lower to IPE-L0119 at the argument span — never an ICE, never the
    // misleading IPE-L0107 first-class-function message.
    let mut i = Interner::new();
    let main = i.intern("main")?;
    let live = i.intern("Web")?;
    let tea = i.intern("tea")?;
    let cfg = i.intern("cfg")?;
    let callee = Located::new(
        Span::new(10, 18),
        canon::Expr_::VarKernel {
            id: None,
            module: live,
            name: tea,
        },
    );
    let arg_span = Span::new(19, 22);
    let arg = Located::new(arg_span, canon::Expr_::VarLocal(cfg));
    let body = Located::new(
        Span::new(10, 22),
        canon::Expr_::Call(Box::new(callee), vec![arg]),
    );
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(0, 4), main),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body,
        ty: con_int(&mut i)?, // body type is irrelevant to the intercept
    };
    assert_unsupported(
        run(Vec::new(), vec![def], BTreeMap::new(), &mut i),
        Feature::LetBoundAppCfg,
        IPE_L0119,
        arg_span,
    );
    Ok(())
}

/// Lower `f = <module>.<name>` as a bare kernel reference solved at `solved`.
///
/// The binding is annotated `Int` so its signature lowers without tripping any
/// gate of its own; only the body's kernel reference is under test. Returns
/// the lowering result and the reference's span.
fn lower_bare_kernel(
    module: &str,
    name: &str,
    solved: Ty,
    i: &mut Interner,
) -> DResult<(DResult<ipe_ir::Program>, Span)> {
    let body_span = Span::new(90, 98);
    let f = i.intern("f")?;
    let module = i.intern(module)?;
    let name = i.intern(name)?;
    let def = canon::Def::Typed {
        home: vec![],
        name: Located::new(Span::new(88, 89), f),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body: Located::new(
            body_span,
            canon::Expr_::VarKernel {
                id: None,
                module,
                name,
            },
        ),
        ty: con_int(i)?,
    };
    let mut regions = BTreeMap::new();
    regions.insert(body_span, solved);
    let res = run_with_regions(Vec::new(), vec![def], BTreeMap::new(), regions, i);
    Ok((res, body_span))
}

/// `a -> b` as a solved arrow.
fn arrow(a: Ty, b: Ty) -> Ty {
    Ty::Fun(Box::new(a), Box::new(b))
}

/// `List elem` as a solved type.
fn ty_list(elem: Ty, i: &mut Interner) -> DResult<Ty> {
    Ok(Ty::Con {
        module: Vec::new(),
        name: i.intern("List")?,
        args: vec![elem],
    })
}

/// Whether `res` is the higher-order callback-result refusal.
const fn is_hof_callback_refusal(res: &DResult<ipe_ir::Program>) -> bool {
    matches!(
        res,
        Err(Diagnostic::Lower {
            msg: LowerError::Unsupported(Feature::HofCallbackFunctionResult),
            ..
        })
    )
}

/// `List.map` solved with a two-argument callback (`List.map add`) fails closed at lowering.
///
/// The callback's final result `b` is `Int -> Int`, which the exact-arity
/// runtime kernel cannot build; the backstop refuses it with IPE-L0154 at the
/// kernel reference, independently of the type checker's obligation.
#[test]
fn list_map_curried_callback_is_refused() -> DResult<()> {
    let mut i = Interner::new();
    let int = ty_int(&mut i)?;
    let int_to_int = arrow(int.clone(), int.clone());
    let callback = arrow(int.clone(), int_to_int.clone());
    let solved = arrow(
        callback,
        arrow(ty_list(int, &mut i)?, ty_list(int_to_int, &mut i)?),
    );
    let (res, span) = lower_bare_kernel("List", "map", solved, &mut i)?;
    assert_unsupported(res, Feature::HofCallbackFunctionResult, IPE_L0154, span);
    Ok(())
}

/// `List.foldl` solved with a function-valued accumulator fails closed at lowering.
#[test]
fn list_foldl_function_accumulator_is_refused() -> DResult<()> {
    let mut i = Interner::new();
    let int = ty_int(&mut i)?;
    let acc = arrow(int.clone(), int.clone());
    let step = arrow(int.clone(), arrow(acc.clone(), acc.clone()));
    let solved = arrow(step, arrow(acc.clone(), arrow(ty_list(int, &mut i)?, acc)));
    let (res, span) = lower_bare_kernel("List", "foldl", solved, &mut i)?;
    assert_unsupported(res, Feature::HofCallbackFunctionResult, IPE_L0154, span);
    Ok(())
}

/// `List.map` solved with a plain-result callback passes the backstop.
#[test]
fn list_map_plain_callback_passes_backstop() -> DResult<()> {
    let mut i = Interner::new();
    let int = ty_int(&mut i)?;
    let list_int = ty_list(int.clone(), &mut i)?;
    let solved = arrow(arrow(int.clone(), int), arrow(list_int.clone(), list_int));
    let (res, _span) = lower_bare_kernel("List", "map", solved, &mut i)?;
    assert!(
        !is_hof_callback_refusal(&res),
        "a plain-result callback must not trip IPE-L0154: {res:?}"
    );
    Ok(())
}

/// `List.map2` solved with a two-argument callback passes the backstop.
///
/// Its callback takes both arguments at once, so the final result is a plain
/// `Int`.
#[test]
fn list_map2_two_argument_callback_passes_backstop() -> DResult<()> {
    let mut i = Interner::new();
    let int = ty_int(&mut i)?;
    let list_int = ty_list(int.clone(), &mut i)?;
    let callback = arrow(int.clone(), arrow(int.clone(), int));
    let solved = arrow(
        callback,
        arrow(list_int.clone(), arrow(list_int.clone(), list_int)),
    );
    let (res, _span) = lower_bare_kernel("List", "map2", solved, &mut i)?;
    assert!(
        !is_hof_callback_refusal(&res),
        "a full-arity `map2` callback must not trip IPE-L0154: {res:?}"
    );
    Ok(())
}
