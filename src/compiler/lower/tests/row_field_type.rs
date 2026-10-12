//! Caller field-type checks for wildcard-`any` row-generic parameters.
//!
//! A function whose parameter is annotated `any` and whose body reads a record
//! field is lowered to a row-generic: the `any` is erased and the emitted Rust
//! function gains an `IpeHas<Field><Name = T>` bound per field read. A caller
//! passing a record whose matching field has the WRONG type produces Rust that
//! `cargo build` cannot satisfy (E0271), even though the type-checker accepted
//! the call (because `any` severs caller-callee unification). The lowerer
//! catches this at lowering time and emits `IPE-L0143`. A caller passing a
//! non-record concrete type (`Int`, `Bool`, …) is caught by the upstream
//! non-record guard and emits `IPE-L0144`.

#![allow(clippy::unwrap_used)] // `.intern().unwrap()` is acceptable in test helpers

use std::collections::BTreeMap;

use ipe_canon::ast as canon;
use ipe_diagnostics::{DResult, Diagnostic, Feature, LowerError, Span};
use ipe_intern::{Interner, Symbol};
use ipe_lower::lower;
use ipe_types::{RowTail, SolvedTypes, Ty};

fn ty_string(interner: &mut Interner) -> canon::Type {
    canon::Type::Con {
        home: Vec::new(),
        name: interner.intern("String").unwrap(),
        args: Vec::new(),
    }
}

fn solved_string(interner: &mut Interner) -> Ty {
    Ty::Con {
        module: Vec::new(),
        name: interner.intern("String").unwrap(),
        args: Vec::new(),
    }
}

fn solved_int(interner: &mut Interner) -> Ty {
    Ty::Con {
        module: Vec::new(),
        name: interner.intern("Int").unwrap(),
        args: Vec::new(),
    }
}

/// Build the `getName : any -> String; getName p = p.name` canon def.
///
/// Returns the def together with the symbols and spans that callers need to
/// build the companion `caller` def and the solved-type maps.
#[allow(clippy::type_complexity)]
fn make_get_name_def(
    interner: &mut Interner,
) -> (
    canon::Def,
    /* get_name */ Symbol,
    /* p */ Symbol,
    /* name_field */ Symbol,
    /* gn_sig_span */ Span,
    /* gn_param_span */ Span,
    /* gn_access_span */ Span,
) {
    let get_name = interner.intern("getName").unwrap();
    let p = interner.intern("p").unwrap();
    let name_field = interner.intern("name").unwrap();

    let gn_sig_span = Span::new(0, 1);
    let gn_param_span = Span::new(2, 3);
    let gn_access_span = Span::new(4, 5);

    let gn_body = ipe_diagnostics::Located::new(
        gn_access_span,
        canon::Expr_::Access(
            Box::new(ipe_diagnostics::Located::new(
                gn_param_span,
                canon::Expr_::VarLocal(p),
            )),
            name_field,
        ),
    );
    let gn_def = canon::Def::Typed {
        home: vec![],
        name: ipe_diagnostics::Located::new(gn_sig_span, get_name),
        free_vars: Vec::new(),
        patterns: vec![ipe_diagnostics::Located::new(
            gn_param_span,
            canon::Pattern_::PVar(p),
        )],
        body: gn_body,
        ty: canon::Type::Lambda(
            Box::new(canon::Type::Wildcard),
            Box::new(ty_string(interner)),
        ),
    };

    (
        gn_def,
        get_name,
        p,
        name_field,
        gn_sig_span,
        gn_param_span,
        gn_access_span,
    )
}

/// Lower a hand-built two-def program:
///   `getName : any -> String` with body `p.name` (direct field read),
/// and a caller `caller : String; caller = getName { name = <field_value> }`.
///
/// `field_value_expr` is the canon expression node for the record field;
/// `field_solved_ty` is its solved `Ty` (for the region map). The
/// field-type mismatch diagnostic (if any) is attributed to the call span.
fn lower_any_call(
    field_value_expr: canon::Expr_,
    field_solved_ty: Ty,
    interner: &mut Interner,
) -> DResult<ipe_ir::Program> {
    let (gn_def, get_name, _p, name_field, _gn_sig_span, gn_param_span, gn_access_span) =
        make_get_name_def(interner);
    let caller = interner.intern("caller").unwrap();

    let caller_sig_span = Span::new(50, 51);
    let field_val_span = Span::new(60, 62);
    let caller_rec_span = Span::new(60, 70);
    let call_span = Span::new(52, 70);

    // `caller : String; caller = getName { name = <field_value_expr> }`
    let rec_arg = ipe_diagnostics::Located::new(
        caller_rec_span,
        canon::Expr_::Record(vec![(
            name_field,
            ipe_diagnostics::Located::new(field_val_span, field_value_expr),
        )]),
    );
    let callee_ref = ipe_diagnostics::Located::new(
        caller_sig_span,
        canon::Expr_::VarTopLevel {
            module: vec![],
            name: get_name,
        },
    );
    let call_body = ipe_diagnostics::Located::new(
        call_span,
        canon::Expr_::Call(Box::new(callee_ref), vec![rec_arg]),
    );
    let caller_def = canon::Def::Typed {
        home: vec![],
        name: ipe_diagnostics::Located::new(caller_sig_span, caller),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body: call_body,
        ty: ty_string(interner),
    };

    let mut env: BTreeMap<(Vec<Symbol>, Symbol), Ty> = BTreeMap::new();
    env.insert(
        (vec![], get_name),
        Ty::Fun(Box::new(Ty::Wildcard), Box::new(solved_string(interner))),
    );
    env.insert((vec![], caller), solved_string(interner));

    // regions: param p → { name : String } (drives erasure); field-access → String;
    // record arg → { name : T }; call → String.
    let mut regions: BTreeMap<(Vec<Symbol>, Span), Ty> = BTreeMap::new();
    let mut param_rec = BTreeMap::new();
    param_rec.insert(name_field, solved_string(interner));
    regions.insert(
        (vec![], gn_param_span),
        Ty::Record(param_rec, RowTail::Closed),
    );
    regions.insert((vec![], gn_access_span), solved_string(interner));
    let mut rec_fields = BTreeMap::new();
    rec_fields.insert(name_field, field_solved_ty);
    regions.insert(
        (vec![], caller_rec_span),
        Ty::Record(rec_fields, RowTail::Closed),
    );
    regions.insert((vec![], call_span), solved_string(interner));

    let m = canon::Module {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        name: Vec::new(),
        unions: Vec::new(),
        defs: vec![gn_def, caller_def],
    };
    let types = SolvedTypes {
        env,
        regions,
        expected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        warnings: Vec::new(),
        poly_var_map: BTreeMap::new(),
        untyped_type_params: BTreeMap::new(),
        msg_defaulted_vars: BTreeMap::new(),
        signature_wildcards: BTreeMap::new(),
    };
    lower(&m, &types, interner, "", "").map_err(|(d, _home)| d)
}

/// `getName : any -> String; getName p = p.name` called with `{ name = 1 }`
/// (an `Int` field) — the field type `Int` does not match the callee-required
/// `String`. The lowerer must reject this with `IPE-L0143` rather than
/// emitting Rust that `cargo` cannot build (E0271).
#[test]
fn wrong_field_type_at_any_call_site_is_rejected() {
    let mut i = Interner::new();
    let int_val = solved_int(&mut i);
    let res = lower_any_call(canon::Expr_::Int(1), int_val, &mut i);
    assert!(
        matches!(
            res,
            Err(Diagnostic::Lower {
                msg: LowerError::WildcardAnyFieldTypeMismatch { .. },
                ..
            })
        ),
        "wrong field type at an `any` call site must be IPE-L0143, got {res:?}"
    );
}

/// Same callee called with `{ name = "Ada" }` — the field type `String`
/// matches the callee-required `String`. The call must lower cleanly.
#[test]
fn correct_field_type_at_any_call_site_is_accepted() {
    let mut i = Interner::new();
    let str_val = solved_string(&mut i);
    let res = lower_any_call(canon::Expr_::Str("Ada".into()), str_val, &mut i);
    assert!(
        res.is_ok(),
        "matching field type must lower without a diagnostic, got {res:?}"
    );
}

/// Same callee, caller record `{ name = "Ada", age = 1 }` — an extra `age`
/// field beyond the one the callee reads. Row-openness must be preserved: only
/// the fields the callee's body actually reads are checked; extra fields are
/// allowed.
#[test]
fn extra_field_beyond_required_is_accepted() {
    let mut i = Interner::new();
    let (gn_def, get_name, _p, name_field, _gn_sig, gn_param_span, gn_access_span) =
        make_get_name_def(&mut i);
    let caller_sym = i.intern("caller").unwrap();
    let age_field = i.intern("age").unwrap();

    let caller_sig_span = Span::new(50, 51);
    let caller_rec_span = Span::new(60, 70);
    let call_span = Span::new(52, 70);

    let rec_arg = ipe_diagnostics::Located::new(
        caller_rec_span,
        canon::Expr_::Record(vec![
            (
                name_field,
                ipe_diagnostics::Located::new(caller_rec_span, canon::Expr_::Str("Ada".into())),
            ),
            (
                age_field,
                ipe_diagnostics::Located::new(caller_rec_span, canon::Expr_::Int(1)),
            ),
        ]),
    );
    let callee_ref = ipe_diagnostics::Located::new(
        caller_sig_span,
        canon::Expr_::VarTopLevel {
            module: vec![],
            name: get_name,
        },
    );
    let call_body = ipe_diagnostics::Located::new(
        call_span,
        canon::Expr_::Call(Box::new(callee_ref), vec![rec_arg]),
    );
    let caller_def = canon::Def::Typed {
        home: vec![],
        name: ipe_diagnostics::Located::new(caller_sig_span, caller_sym),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body: call_body,
        ty: ty_string(&mut i),
    };

    let mut env: BTreeMap<(Vec<Symbol>, Symbol), Ty> = BTreeMap::new();
    env.insert(
        (vec![], get_name),
        Ty::Fun(Box::new(Ty::Wildcard), Box::new(solved_string(&mut i))),
    );
    env.insert((vec![], caller_sym), solved_string(&mut i));

    let mut regions: BTreeMap<(Vec<Symbol>, Span), Ty> = BTreeMap::new();
    let mut param_rec = BTreeMap::new();
    param_rec.insert(name_field, solved_string(&mut i));
    regions.insert(
        (vec![], gn_param_span),
        Ty::Record(param_rec, RowTail::Closed),
    );
    regions.insert((vec![], gn_access_span), solved_string(&mut i));
    let mut rec_fields = BTreeMap::new();
    rec_fields.insert(name_field, solved_string(&mut i));
    rec_fields.insert(age_field, solved_int(&mut i));
    regions.insert(
        (vec![], caller_rec_span),
        Ty::Record(rec_fields, RowTail::Closed),
    );
    regions.insert((vec![], call_span), solved_string(&mut i));

    let m = canon::Module {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        name: Vec::new(),
        unions: Vec::new(),
        defs: vec![gn_def, caller_def],
    };
    let types = SolvedTypes {
        env,
        regions,
        expected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        warnings: Vec::new(),
        poly_var_map: BTreeMap::new(),
        untyped_type_params: BTreeMap::new(),
        msg_defaulted_vars: BTreeMap::new(),
        signature_wildcards: BTreeMap::new(),
    };
    let res = lower(&m, &types, &mut i, "", "").map_err(|(d, _home)| d);
    assert!(
        res.is_ok(),
        "extra fields beyond those the callee reads must not be rejected — row-openness, got {res:?}"
    );
}

/// A call site where the argument's region type is a bare `Ty::Var` — the relay
/// shape `relay x = getName x` where `x` is itself a wildcard-`any` parameter
/// of the enclosing function.  The emitted Rust for `relay` gives `x` only
/// `T1: Clone`, not the `IpeHasName<Name = String>` the callee requires; the
/// emitted Rust would fail cargo E0277.
///
/// The call-site gate (`check_row_param_caller_fields`) consults
/// `ty_can_satisfy_row_witness`, the single authority on whether a solved `Ty`
/// can carry the bound.  A `Ty::Var` returns `false` there, so the gate must
/// reject the call with `IPE-L0131` rather than emit unsatisfiable Rust.
#[test]
fn relayed_any_param_at_row_callee_is_rejected() {
    let mut i = Interner::new();
    let (gn_def, get_name, _p, name_field, _gn_sig, gn_param_span, gn_access_span) =
        make_get_name_def(&mut i);

    // `relay : any -> String; relay x = getName x`
    // The relay function itself has `any` in param position — its argument `x`
    // gets region type `Ty::Var(relay_any_sym)`, a bare solver variable.
    let relay_sym = i.intern("relay").unwrap();
    let x_sym = i.intern("x").unwrap();
    let relay_any_sym = i.intern("any2").unwrap();

    let relay_sig_span = Span::new(100, 101);
    let relay_param_span = Span::new(102, 103);
    let relay_call_span = Span::new(104, 115);

    // Body: `getName x`
    let x_ref = ipe_diagnostics::Located::new(relay_param_span, canon::Expr_::VarLocal(x_sym));
    let callee_ref = ipe_diagnostics::Located::new(
        relay_sig_span,
        canon::Expr_::VarTopLevel {
            module: vec![],
            name: get_name,
        },
    );
    let relay_body = ipe_diagnostics::Located::new(
        relay_call_span,
        canon::Expr_::Call(Box::new(callee_ref), vec![x_ref]),
    );
    let relay_def = canon::Def::Typed {
        home: vec![],
        name: ipe_diagnostics::Located::new(relay_sig_span, relay_sym),
        free_vars: vec![relay_any_sym],
        patterns: vec![ipe_diagnostics::Located::new(
            relay_param_span,
            canon::Pattern_::PVar(x_sym),
        )],
        body: relay_body,
        ty: canon::Type::Lambda(
            Box::new(canon::Type::Var(relay_any_sym)),
            Box::new(ty_string(&mut i)),
        ),
    };

    let mut env: BTreeMap<(Vec<Symbol>, Symbol), Ty> = BTreeMap::new();
    env.insert(
        (vec![], get_name),
        Ty::Fun(Box::new(Ty::Wildcard), Box::new(solved_string(&mut i))),
    );
    env.insert(
        (vec![], relay_sym),
        Ty::Fun(
            Box::new(Ty::Var(relay_any_sym.as_raw())),
            Box::new(solved_string(&mut i)),
        ),
    );

    let mut regions: BTreeMap<(Vec<Symbol>, Span), Ty> = BTreeMap::new();
    // `getName`'s param `p` region: the concrete `{ name : String }` record that
    // drives the row erasure so `fn_row_params` is populated.
    let mut param_rec = BTreeMap::new();
    param_rec.insert(name_field, solved_string(&mut i));
    regions.insert(
        (vec![], gn_param_span),
        Ty::Record(param_rec, RowTail::Closed),
    );
    regions.insert((vec![], gn_access_span), solved_string(&mut i));

    // `relay`'s argument `x` to `getName`: the region is a bare `Ty::Var` —
    // the solver left `x` free (it is the relay function's own `any` param).
    regions.insert((vec![], relay_param_span), Ty::Var(relay_any_sym.as_raw()));
    regions.insert((vec![], relay_call_span), solved_string(&mut i));

    let m = canon::Module {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        name: Vec::new(),
        unions: Vec::new(),
        defs: vec![gn_def, relay_def],
    };
    let types = SolvedTypes {
        env,
        regions,
        expected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        warnings: Vec::new(),
        poly_var_map: BTreeMap::new(),
        untyped_type_params: BTreeMap::new(),
        msg_defaulted_vars: BTreeMap::new(),
        signature_wildcards: BTreeMap::new(),
    };
    let res = lower(&m, &types, &mut i, "", "").map_err(|(d, _home)| d);
    assert!(
        matches!(
            res,
            Err(Diagnostic::Lower {
                msg: LowerError::Unsupported(Feature::RowPolyRecordAnnotation),
                ..
            })
        ),
        "relaying a bare any-param to a row-generic callee must be IPE-L0131, got {res:?}"
    );
}

/// Lower `getName : any -> String; getName p = p.name` called with a bare
/// non-record argument whose region type is the given concrete `Ty`. The
/// call-site guard must reject fail-closed with `IPE-L0144` before the field
/// check ever runs.
fn lower_any_call_bare_arg(
    arg_expr: canon::Expr_,
    arg_solved_ty: Ty,
    interner: &mut Interner,
) -> DResult<ipe_ir::Program> {
    let (gn_def, get_name, _p, name_field, _gn_sig_span, gn_param_span, gn_access_span) =
        make_get_name_def(interner);
    let caller = interner.intern("caller").unwrap();

    let caller_sig_span = Span::new(50, 51);
    let arg_span = Span::new(60, 62);
    let call_span = Span::new(52, 70);

    let arg_node = ipe_diagnostics::Located::new(arg_span, arg_expr);
    let callee_ref = ipe_diagnostics::Located::new(
        caller_sig_span,
        canon::Expr_::VarTopLevel {
            module: vec![],
            name: get_name,
        },
    );
    let call_body = ipe_diagnostics::Located::new(
        call_span,
        canon::Expr_::Call(Box::new(callee_ref), vec![arg_node]),
    );
    let caller_def = canon::Def::Typed {
        home: vec![],
        name: ipe_diagnostics::Located::new(caller_sig_span, caller),
        free_vars: Vec::new(),
        patterns: Vec::new(),
        body: call_body,
        ty: ty_string(interner),
    };

    let mut env: BTreeMap<(Vec<Symbol>, Symbol), Ty> = BTreeMap::new();
    env.insert(
        (vec![], get_name),
        Ty::Fun(Box::new(Ty::Wildcard), Box::new(solved_string(interner))),
    );
    env.insert((vec![], caller), solved_string(interner));

    let mut regions: BTreeMap<(Vec<Symbol>, Span), Ty> = BTreeMap::new();
    let mut param_rec = BTreeMap::new();
    param_rec.insert(name_field, solved_string(interner));
    regions.insert(
        (vec![], gn_param_span),
        Ty::Record(param_rec, RowTail::Closed),
    );
    regions.insert((vec![], gn_access_span), solved_string(interner));
    // The bare arg has the given concrete (non-record) type.
    regions.insert((vec![], arg_span), arg_solved_ty);
    regions.insert((vec![], call_span), solved_string(interner));

    let m = canon::Module {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        name: Vec::new(),
        unions: Vec::new(),
        defs: vec![gn_def, caller_def],
    };
    let types = SolvedTypes {
        env,
        regions,
        expected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        warnings: Vec::new(),
        poly_var_map: BTreeMap::new(),
        untyped_type_params: BTreeMap::new(),
        msg_defaulted_vars: BTreeMap::new(),
        signature_wildcards: BTreeMap::new(),
    };
    lower(&m, &types, interner, "", "").map_err(|(d, _home)| d)
}

/// `getName : any -> String; getName p = p.name` called with the integer
/// literal `5`. The region type of the argument is `Ty::Con { name: "Int" }` —
/// a concrete non-record type. The lowerer must reject this fail-closed with
/// `IPE-L0144` (`WildcardAnyArgNotRecord`) rather than accepting (exit 0) and
/// emitting Rust that `cargo` cannot build (`error[E0277]`).
#[test]
fn non_record_int_arg_at_row_param_is_rejected() {
    let mut i = Interner::new();
    let int_ty = solved_int(&mut i);
    let res = lower_any_call_bare_arg(canon::Expr_::Int(5), int_ty, &mut i);
    assert!(
        matches!(
            res,
            Err(Diagnostic::Lower {
                msg: LowerError::WildcardAnyArgNotRecord { .. },
                ..
            })
        ),
        "an Int argument at a row-param position must be IPE-L0144, got {res:?}"
    );
}

/// Same callee, argument whose solved region type is a `Ty::Con { name:
/// "Bool" }` — another concrete non-record. The expression itself is `()` (the
/// canonicaliser guards Bool as a constructor; for this test only the region
/// type drives the gate). Rejected fail-closed with `IPE-L0144`.
#[test]
fn non_record_con_arg_at_row_param_is_rejected() {
    let mut i = Interner::new();
    let bool_sym = i.intern("Bool").unwrap();
    let bool_ty = Ty::Con {
        module: vec![],
        name: bool_sym,
        args: vec![],
    };
    // The expression value does not matter here — the gate fires on the solved
    // region type alone, before any expression-level check.
    let res = lower_any_call_bare_arg(canon::Expr_::Unit, bool_ty, &mut i);
    assert!(
        matches!(
            res,
            Err(Diagnostic::Lower {
                msg: LowerError::WildcardAnyArgNotRecord { .. },
                ..
            })
        ),
        "a Bool-typed argument at a row-param position must be IPE-L0144, got {res:?}"
    );
}

/// A `Ty::Record` argument whose region type was produced by fully expanding a
/// type alias (post-solve, `Ty` has no `Alias` variant — the solver stores the
/// fully-expanded record directly). This test verifies that a `Ty::Record`
/// region type still passes the non-record guard and proceeds to the field
/// check: alias-to-record arguments are not over-rejected.
#[test]
fn alias_expanded_to_record_arg_is_accepted() {
    let mut i = Interner::new();
    // The argument's region type is a fully-expanded `Ty::Record` — the form
    // the solver stores after expanding any type alias. The guard must accept
    // it (it IS a record) and let the field check proceed.
    let str_val = solved_string(&mut i);
    let res = lower_any_call(canon::Expr_::Str("Ada".into()), str_val, &mut i);
    assert!(
        res.is_ok(),
        "a record argument (alias-expanded to Ty::Record) must lower without a diagnostic, got {res:?}"
    );
}
