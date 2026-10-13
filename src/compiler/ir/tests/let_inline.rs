//! Pins which `Expr` forms the move-only `let`-value predicate reports.
//!
//! Only a value-building literal holding a task answers `true`.

use ipe_diagnostics::DResult;
use ipe_intern::{Interner, Symbol};
use ipe_ir::let_inline::expr_value_is_non_clone;
use ipe_ir::once_closure::MovedCapture;
use ipe_ir::{
    Arm, BinOp, CallPin, Callee, EnumPayloadTable, Expr, FuncId, IrType, Match, ModPath,
    OnFormKind, Pat,
};

fn task_list() -> Expr {
    Expr::List {
        elem: IrType::Task(Box::new(IrType::Int)),
        items: Vec::new(),
    }
}

fn int_list() -> Expr {
    Expr::List {
        elem: IrType::Int,
        items: vec![Expr::Int(1)],
    }
}

fn boxed(expr: Expr) -> Box<Expr> {
    Box::new(expr)
}

#[test]
fn a_list_of_tasks_is_non_clone() {
    let payloads = EnumPayloadTable::new();
    assert!(expr_value_is_non_clone(&task_list(), &payloads));
    assert!(!expr_value_is_non_clone(&int_list(), &payloads));
}

#[test]
fn a_tuple_or_record_holding_a_task_list_is_non_clone() -> DResult<()> {
    let mut interner = Interner::new();
    let field = interner.intern("tasks")?;
    let payloads = EnumPayloadTable::new();
    let tuple = Expr::Tuple(vec![task_list(), Expr::Int(0)]);
    let record = Expr::Record {
        fields: vec![(field, task_list())],
        ty: None,
    };
    assert!(expr_value_is_non_clone(&tuple, &payloads));
    assert!(expr_value_is_non_clone(&record, &payloads));
    let ints = Expr::Tuple(vec![Expr::Int(1), Expr::Int(2)]);
    let int_record = Expr::Record {
        fields: vec![(field, Expr::Int(3))],
        ty: None,
    };
    assert!(!expr_value_is_non_clone(&ints, &payloads));
    assert!(!expr_value_is_non_clone(&int_record, &payloads));
    Ok(())
}

/// One representative of every `Expr` form that does not build a value
/// literal, each wrapping a task list where it has a child slot.
#[allow(clippy::too_many_lines)] // One literal per `Expr` variant.
fn non_value_building_forms(name: Symbol) -> DResult<Vec<Expr>> {
    let params = vec![(name, IrType::Int)];
    let flat_match = Match::new_flat(
        task_list(),
        vec![Arm {
            pat: Pat::Wildcard,
            body: task_list(),
            guard: None,
        }],
    )?;
    Ok(vec![
        Expr::Int(1),
        Expr::Bool(true),
        Expr::Float(1.5),
        Expr::Str("s".to_owned()),
        Expr::CustomElementRef {
            tag: "x-el".to_owned(),
            js_path: "./el.js".to_owned(),
        },
        Expr::Char("c".to_owned()),
        Expr::Unit,
        Expr::Var(name),
        Expr::CloneVar(name),
        Expr::Ctor {
            home: ModPath(Vec::new()),
            ty: name,
            variant: name,
            args: vec![task_list()],
        },
        Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: boxed(Expr::Int(1)),
            rhs: boxed(Expr::Int(2)),
        },
        Expr::Let {
            name,
            value: boxed(task_list()),
            body: boxed(task_list()),
        },
        Expr::Destructure {
            binder: Pat::Var(name),
            value: boxed(task_list()),
            body: boxed(task_list()),
        },
        Expr::If {
            cond: boxed(Expr::Bool(true)),
            then_: boxed(task_list()),
            else_: boxed(task_list()),
        },
        Expr::Match(flat_match),
        Expr::Call {
            callee: Callee::Func(FuncId::from_raw(0)),
            args: vec![task_list()],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
        Expr::Cons {
            head: boxed(Expr::Int(1)),
            tail: boxed(task_list()),
        },
        Expr::ListIndexClone {
            list: boxed(task_list()),
            index: 0,
            elem: IrType::Task(Box::new(IrType::Int)),
        },
        Expr::ListLenCheck {
            list: boxed(task_list()),
            len: 0,
            exact: true,
        },
        Expr::Access {
            record: boxed(Expr::Var(name)),
            field: name,
            field_ty: IrType::Int,
        },
        Expr::Update {
            record: boxed(Expr::Var(name)),
            fields: vec![(name, task_list())],
        },
        Expr::Lambda {
            params: params.clone(),
            ret: IrType::Int,
            body: boxed(task_list()),
        },
        Expr::SharedLambda {
            params: params.clone(),
            ret: IrType::Int,
            body: boxed(task_list()),
        },
        Expr::OnceLambda {
            params: params.clone(),
            ret: IrType::Int,
            body: boxed(task_list()),
            capture: MovedCapture { name, lo: 0, hi: 1 },
        },
        Expr::Apply {
            func: boxed(Expr::Var(name)),
            args: vec![task_list()],
        },
        Expr::FuncValue {
            callee: Callee::Func(FuncId::from_raw(0)),
            ty: IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)),
        },
        Expr::TaskSeq {
            effect: boxed(task_list()),
            rest: boxed(task_list()),
        },
        Expr::TailLoop {
            params,
            body: boxed(task_list()),
        },
        Expr::TailRecur {
            args: vec![task_list()],
        },
    ])
}

#[test]
fn no_non_value_building_form_reports_inlinable() -> DResult<()> {
    let mut interner = Interner::new();
    let name = interner.intern("x")?;
    let payloads = EnumPayloadTable::new();
    let forms = non_value_building_forms(name)?;
    for form in &forms {
        assert!(
            !expr_value_is_non_clone(form, &payloads),
            "{form:?} must not report a move-only inlinable value"
        );
    }
    Ok(())
}

#[test]
fn a_constructor_carrying_a_task_list_stays_bound() -> DResult<()> {
    let mut interner = Interner::new();
    let name = interner.intern("Wrap")?;
    let payloads = EnumPayloadTable::new();
    let ctor = Expr::Ctor {
        home: ModPath(Vec::new()),
        ty: name,
        variant: name,
        args: vec![task_list()],
    };
    assert!(!expr_value_is_non_clone(&ctor, &payloads));
    Ok(())
}
