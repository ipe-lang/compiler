//! Bounds a function's signature shape alone obliges on its generics.
//!
//! These rules read only the lowered parameter and return types, never the
//! body, and run before the cross-call fixpoint (`propagate_call_site_bounds`)
//! so a caller forwarding its generic into such a slot inherits the bound. The
//! backend renders the finalized [`BoundSet`] verbatim and derives none.

use ipe_intern::Symbol;
use ipe_ir::{BoundSet, IrType, RowParam};

/// Fold every signature-shape obligation into `type_params` and `row_params`.
///
/// - `Clone` on every generic and row variable: Ipê has value semantics, so a
///   field read or a reused binder emits `.clone()`.
/// - `Send + 'static` on every type variable of a `Task`-returning function
///   (the future captures it) and on a type variable named inside a function-
///   typed parameter (the boxed `dyn Fn .. + Send + Sync + 'static` carrier).
/// - `'static` on a type variable that is the message of a UI carrier in the
///   return type (a leaf renderer boxed by its caller).
/// - `Send + 'static` on every row variable of a `Task`-returning function
///   (the boxed `task_and_then` continuation moves it).
pub(super) fn apply_signature_shape_bounds(
    type_params: &mut [(Symbol, BoundSet)],
    row_params: &mut [RowParam],
    params: &[(Symbol, IrType)],
    ret: &IrType,
) {
    let ret_is_task = matches!(ret, IrType::Task(_));
    for (sym, bounds) in type_params.iter_mut() {
        let mut next = bounds.with_clone();
        if ret_is_task || type_var_in_fn_param(params, *sym) {
            next = next.with_send();
        }
        if type_var_in_ui_carrier(ret, *sym) {
            next = next.with_static();
        }
        *bounds = next;
    }
    for row in row_params.iter_mut() {
        let mut next = row.bounds.with_clone();
        if ret_is_task {
            next = next.with_send();
        }
        row.bounds = next;
    }
}

/// `true` if the type variable `sym` appears inside a function-typed
/// (`Fun` / `SharedFun` / `FnOnceChain`) parameter.
///
/// Such a parameter is a boxed trait object carrying `+ 'static`, so every
/// type variable it mentions must itself be `'static`; a pure generic taking no
/// callback keeps a bare `Clone`.
fn type_var_in_fn_param(params: &[(Symbol, IrType)], sym: Symbol) -> bool {
    params
        .iter()
        .any(|(_, ty)| ty_mentions_var_under_fn(ty, sym, false))
}

/// `true` if the type variable `sym` is the message parameter of a UI carrier
/// (`Element msg`, `Attribute msg`, `Html msg`, …) anywhere in `ret`.
///
/// A carrier over `msg` holds event handlers as `Arc<dyn Fn(..) -> msg + Send +
/// Sync + 'static>`, so a `msg`-generic function returning one is boxable into
/// a `Box<dyn Fn(..) -> Element<msg> + 'static>` slot (how `List.map
/// renderCell cells` forwards a leaf renderer); without `msg: 'static` that box
/// is an E0310.
fn type_var_in_ui_carrier(ret: &IrType, sym: Symbol) -> bool {
    match ret {
        IrType::Ui { msg, .. } => ty_mentions_var(msg, sym),
        IrType::Task(inner)
        | IrType::Maybe(inner)
        | IrType::List(inner)
        | IrType::Set(inner)
        | IrType::Decoder(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::WebRoute(inner) => type_var_in_ui_carrier(inner, sym),
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            type_var_in_ui_carrier(a, sym) || type_var_in_ui_carrier(b, sym)
        }
        IrType::Tuple(items) => items.iter().any(|t| type_var_in_ui_carrier(t, sym)),
        IrType::Enum { args, .. } => args.iter().any(|t| type_var_in_ui_carrier(t, sym)),
        IrType::Record(fields) => fields.values().any(|t| type_var_in_ui_carrier(t, sym)),
        _ => false,
    }
}

/// `true` if `IrType::Generic(sym)` occurs anywhere in `ty`.
///
/// The carrier's message argument may itself be a nested structure
/// (`List msg`, `(msg, a)`), so the whole sub-tree is scanned.
fn ty_mentions_var(ty: &IrType, sym: Symbol) -> bool {
    match ty {
        IrType::Generic(s) => *s == sym,
        IrType::Ui { msg, .. } => ty_mentions_var(msg, sym),
        IrType::Task(inner)
        | IrType::Maybe(inner)
        | IrType::List(inner)
        | IrType::Set(inner)
        | IrType::Decoder(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::WebRoute(inner) => ty_mentions_var(inner, sym),
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            params.iter().any(|p| ty_mentions_var(p, sym)) || ty_mentions_var(ret, sym)
        }
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            ty_mentions_var(a, sym) || ty_mentions_var(b, sym)
        }
        IrType::Tuple(items) => items.iter().any(|t| ty_mentions_var(t, sym)),
        IrType::Enum { args, .. } => args.iter().any(|t| ty_mentions_var(t, sym)),
        IrType::Record(fields) => fields.values().any(|t| ty_mentions_var(t, sym)),
        _ => false,
    }
}

/// `true` if `IrType::Generic(sym)` occurs while `under_fn` is set.
///
/// Once a function-typed node (`Fun` / `SharedFun` / `FnOnceChain`) is
/// entered, `under_fn` stays set for the whole sub-tree: the entire boxed trait
/// object is `'static`, so every variable it names needs the bound.
fn ty_mentions_var_under_fn(ty: &IrType, sym: Symbol, under_fn: bool) -> bool {
    match ty {
        IrType::Generic(s) => under_fn && *s == sym,
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            params
                .iter()
                .any(|p| ty_mentions_var_under_fn(p, sym, true))
                || ty_mentions_var_under_fn(ret, sym, true)
        }
        IrType::Task(inner)
        | IrType::Maybe(inner)
        | IrType::List(inner)
        | IrType::Set(inner)
        | IrType::Decoder(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::WebRoute(inner) => ty_mentions_var_under_fn(inner, sym, under_fn),
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            ty_mentions_var_under_fn(a, sym, under_fn) || ty_mentions_var_under_fn(b, sym, under_fn)
        }
        IrType::Tuple(items) => items
            .iter()
            .any(|t| ty_mentions_var_under_fn(t, sym, under_fn)),
        IrType::Enum { args, .. } => args
            .iter()
            .any(|t| ty_mentions_var_under_fn(t, sym, under_fn)),
        IrType::Record(fields) => fields
            .values()
            .any(|t| ty_mentions_var_under_fn(t, sym, under_fn)),
        _ => false,
    }
}
