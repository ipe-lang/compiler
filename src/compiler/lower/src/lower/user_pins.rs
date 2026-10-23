//! Settle every user-generic call pin against its callee's final signature.
//!
//! A pin is built at the call site, before the callee's emitted bounds are
//! final ([`super::propagate_call_site_bounds`] runs after every body is
//! lowered). This pass keeps exactly the pin entries the backend renders
//! ([`UserPin::renders`]), so an unrendered pin feeds no type-mention walker.
//! A rendered [`UserPin::Open`] becomes `()` when the callee's emitted return
//! does not name the parameter either, and its held refusal when it does. A
//! rendered `()` or `JsonVal` reading becomes the lowering's refusal when the
//! callee's bounds on that parameter are ones the pinned type does not meet
//! ([`BoundSet::met_by_unit`], [`BoundSet::met_by_json`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ipe_diagnostics::{Diagnostic, Feature, Span};
use ipe_intern::Symbol;
use ipe_ir::{BoundSet, CallPin, Callee, Expr, Func, FuncId, IrType, UserPin};

use super::ir_type_mentions::ir_type_mentions;

/// One callee's view for pin settling: its type parameters' emitted bounds,
/// the ones some parameter type names, and the ones its return type names.
struct PinLayout {
    bounds: BTreeMap<Symbol, BoundSet>,
    named: BTreeSet<Symbol>,
    in_ret: BTreeSet<Symbol>,
}

/// Settle every [`CallPin::User`] in `funcs` (see the module doc). A refused
/// pin anchors on its caller's definition span `def_span` (the lowered IR
/// carries no spans).
pub(super) fn settle_user_pins(funcs: &mut [Func], def_span: impl Fn(FuncId) -> Option<Span>) {
    let layouts: HashMap<FuncId, PinLayout> = funcs
        .iter()
        .map(|f| {
            let layout = PinLayout {
                bounds: f.type_params.iter().copied().collect(),
                named: f.generics_named_by_params(),
                in_ret: f.generics_named_by_ret(),
            };
            (f.id, layout)
        })
        .collect();
    for func in funcs.iter_mut() {
        let refusal = def_span(func.id).map_or_else(
            || {
                super::bug(
                    "ipe_lower::settle_user_pins",
                    "a lowered function without a definition span",
                )
            },
            |span| super::unsupported(span, Feature::Polymorphism),
        );
        let settle = Settle {
            layouts: &layouts,
            refusal: &refusal,
        };
        let body = std::mem::replace(&mut func.body, Expr::Unit);
        func.body = settle.expr(body);
    }
}

/// Whether `ty` names `JsonVal` anywhere.
fn mentions_json_value(ty: &IrType) -> bool {
    ir_type_mentions(ty, &|t| matches!(t, IrType::Json))
}

struct Settle<'a> {
    layouts: &'a HashMap<FuncId, PinLayout>,
    refusal: &'a Diagnostic,
}

impl Settle<'_> {
    /// The pin `callee`'s call renders, settled against `callee`'s layout. A
    /// callee with no layout has no generics to render, so its pin is empty.
    fn pin(&self, callee: &Callee, pin: CallPin) -> CallPin {
        let (id, pins) = match (callee, pin) {
            (Callee::Func(id), CallPin::User(pins)) => (id, pins),
            (_, other) => return other,
        };
        let Some(layout) = self.layouts.get(id) else {
            return CallPin::None;
        };
        let settled: BTreeMap<Symbol, UserPin> = pins
            .into_iter()
            .filter_map(|(sym, pin)| {
                let bounds = layout.bounds.get(&sym)?;
                if !pin.renders(layout.named.contains(&sym)) {
                    return None;
                }
                let pin = match pin {
                    UserPin::Open(refusal) if layout.in_ret.contains(&sym) => {
                        UserPin::Unlowered(refusal)
                    }
                    UserPin::Open(_) | UserPin::Unit if !bounds.met_by_unit() => {
                        UserPin::Unlowered(Box::new(self.refusal.clone()))
                    }
                    UserPin::Open(_) => UserPin::Unit,
                    UserPin::Instance(ty) if !bounds.met_by_json() && mentions_json_value(&ty) => {
                        UserPin::Unlowered(Box::new(self.refusal.clone()))
                    }
                    other @ (UserPin::Unit | UserPin::Instance(_) | UserPin::Unlowered(_)) => other,
                };
                Some((sym, pin))
            })
            .collect();
        if settled.is_empty() {
            CallPin::None
        } else {
            CallPin::User(settled)
        }
    }

    fn boxed(&self, mut expr: Box<Expr>) -> Box<Expr> {
        let inner = std::mem::replace(&mut *expr, Expr::Unit);
        *expr = self.expr(inner);
        expr
    }

    fn all(&self, exprs: Vec<Expr>) -> Vec<Expr> {
        exprs.into_iter().map(|e| self.expr(e)).collect()
    }

    /// Total over every [`Expr`] arm (no wildcard), so a new variant that can
    /// hold a call is a compile error here, not an unsettled pin.
    #[allow(clippy::too_many_lines)] // one arm per Expr variant; exhaustive by design
    fn expr(&self, expr: Expr) -> Expr {
        match expr {
            Expr::Call {
                callee,
                args,
                pin,
                on_form,
            } => {
                let pin = self.pin(&callee, pin);
                Expr::Call {
                    callee,
                    args: self.all(args),
                    pin,
                    on_form,
                }
            }
            Expr::Let { name, value, body } => Expr::Let {
                name,
                value: self.boxed(value),
                body: self.boxed(body),
            },
            Expr::Destructure {
                binder,
                value,
                body,
            } => Expr::Destructure {
                binder,
                value: self.boxed(value),
                body: self.boxed(body),
            },
            Expr::If { cond, then_, else_ } => Expr::If {
                cond: self.boxed(cond),
                then_: self.boxed(then_),
                else_: self.boxed(else_),
            },
            Expr::Match(m) => Expr::Match(m.map_bodies(
                |e| self.expr(e),
                |_, body, guard| (self.expr(body), guard.map(|g| self.expr(g))),
            )),
            Expr::Ctor {
                home,
                ty,
                variant,
                args,
            } => Expr::Ctor {
                home,
                ty,
                variant,
                args: self.all(args),
            },
            Expr::TailRecur { args } => Expr::TailRecur {
                args: self.all(args),
            },
            Expr::Apply { func, args } => Expr::Apply {
                func: self.boxed(func),
                args: self.all(args),
            },
            Expr::Lambda { params, ret, body } => Expr::Lambda {
                params,
                ret,
                body: self.boxed(body),
            },
            Expr::SharedLambda { params, ret, body } => Expr::SharedLambda {
                params,
                ret,
                body: self.boxed(body),
            },
            Expr::OnceLambda {
                params,
                ret,
                body,
                capture,
            } => Expr::OnceLambda {
                params,
                ret,
                body: self.boxed(body),
                capture,
            },
            Expr::TailLoop { params, body } => Expr::TailLoop {
                params,
                body: self.boxed(body),
            },
            Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
                op,
                lhs: self.boxed(lhs),
                rhs: self.boxed(rhs),
            },
            Expr::Cons { head, tail } => Expr::Cons {
                head: self.boxed(head),
                tail: self.boxed(tail),
            },
            Expr::Tuple(items) => Expr::Tuple(self.all(items)),
            Expr::List { elem, items } => Expr::List {
                elem,
                items: self.all(items),
            },
            Expr::Record { fields, ty } => Expr::Record {
                fields: fields.into_iter().map(|(k, v)| (k, self.expr(v))).collect(),
                ty,
            },
            Expr::Access {
                record,
                field,
                field_ty,
            } => Expr::Access {
                record: self.boxed(record),
                field,
                field_ty,
            },
            Expr::Update { record, fields } => Expr::Update {
                record: self.boxed(record),
                fields: fields.into_iter().map(|(k, v)| (k, self.expr(v))).collect(),
            },
            Expr::TaskSeq { effect, rest } => Expr::TaskSeq {
                effect: self.boxed(effect),
                rest: self.boxed(rest),
            },
            Expr::ListIndexClone { list, index, elem } => Expr::ListIndexClone {
                list: self.boxed(list),
                index,
                elem,
            },
            Expr::ListLenCheck { list, len, exact } => Expr::ListLenCheck {
                list: self.boxed(list),
                len,
                exact,
            },
            leaf @ (Expr::Int(_)
            | Expr::Bool(_)
            | Expr::Float(_)
            | Expr::Str(_)
            | Expr::CustomElementRef { .. }
            | Expr::Char(_)
            | Expr::Unit
            | Expr::Var(_)
            | Expr::CloneVar(_)
            | Expr::FuncValue { .. }) => leaf,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(raw: u32) -> Symbol {
        Symbol::from_raw(raw)
    }

    fn func(
        id: u32,
        type_params: Vec<(Symbol, BoundSet)>,
        params: Vec<IrType>,
        body: Expr,
    ) -> Func {
        func_returning(id, type_params, params, IrType::Unit, body)
    }

    fn func_returning(
        id: u32,
        type_params: Vec<(Symbol, BoundSet)>,
        params: Vec<IrType>,
        ret: IrType,
        body: Expr,
    ) -> Func {
        Func {
            id: FuncId::from_raw(id),
            name: sym(900 + id),
            home: ipe_ir::ModPath(vec![]),
            type_params,
            row_params: vec![],
            params: params
                .into_iter()
                .enumerate()
                .map(|(i, ty)| ipe_ir::Param::owned(sym(800 + u32::try_from(i).unwrap_or(0)), ty))
                .collect(),
            ret,
            body,
        }
    }

    /// The refusal an [`UserPin::Open`] holds in these tests, told apart from
    /// the settle pass's own by its span.
    fn open_refusal() -> Box<Diagnostic> {
        Box::new(super::super::unsupported(
            Span::new(7, 9),
            Feature::Polymorphism,
        ))
    }

    /// Whether `pin` holds, for `a`, a refusal anchored at `span`.
    fn refused_at(pin: Option<&CallPin>, a: Symbol, span: Span) -> bool {
        matches!(
            pin,
            Some(CallPin::User(pins))
                if matches!(pins.get(&a), Some(UserPin::Unlowered(d)) if d.primary_span() == span)
        )
    }

    #[test]
    fn an_open_pin_no_emitted_position_names_becomes_unit() {
        let a = sym(1);
        let mut funcs = vec![
            func(
                0,
                vec![(a, BoundSet::UNBOUNDED.with_clone())],
                vec![IrType::Int],
                Expr::Unit,
            ),
            func(
                1,
                vec![],
                vec![],
                call(0, vec![(a, UserPin::Open(open_refusal()))]),
            ),
        ];
        let pin = settled_pin(&mut funcs).cloned();
        assert_eq!(
            pin,
            Some(CallPin::User(std::iter::once((a, UserPin::Unit)).collect()))
        );
    }

    #[test]
    fn an_open_pin_the_emitted_return_names_becomes_its_refusal() {
        let a = sym(1);
        let mut funcs = vec![
            func_returning(
                0,
                vec![(a, BoundSet::UNBOUNDED)],
                vec![IrType::Int],
                IrType::List(Box::new(IrType::Generic(a))),
                Expr::Unit,
            ),
            func(
                1,
                vec![],
                vec![],
                call(0, vec![(a, UserPin::Open(open_refusal()))]),
            ),
        ];
        let pin = settled_pin(&mut funcs);
        assert!(refused_at(pin, a, Span::new(7, 9)), "{pin:?}");
    }

    #[test]
    fn an_open_pin_a_parameter_names_is_dropped() {
        let a = sym(1);
        let mut funcs = vec![
            func(
                0,
                vec![(a, BoundSet::UNBOUNDED)],
                vec![IrType::Generic(a)],
                Expr::Unit,
            ),
            func(
                1,
                vec![],
                vec![],
                call(0, vec![(a, UserPin::Open(open_refusal()))]),
            ),
        ];
        let pin = settled_pin(&mut funcs).cloned();
        assert_eq!(pin, Some(CallPin::None));
    }

    #[test]
    fn a_unit_reading_under_a_wrapping_add_bound_becomes_the_refusal() {
        let a = sym(1);
        let add = BoundSet::UNBOUNDED.with_add().with_copy();
        let mut funcs = vec![
            func(0, vec![(a, add)], vec![IrType::Int], Expr::Unit),
            func(
                1,
                vec![],
                vec![],
                call(0, vec![(a, UserPin::Open(open_refusal()))]),
            ),
        ];
        let pin = settled_pin(&mut funcs);
        assert!(refused_at(pin, a, Span::new(0, 1)), "{pin:?}");
        let mut unbounded = vec![
            func(
                0,
                vec![(a, BoundSet::UNBOUNDED.with_copy())],
                vec![IrType::Int],
                Expr::Unit,
            ),
            func(
                1,
                vec![],
                vec![],
                call(0, vec![(a, UserPin::Open(open_refusal()))]),
            ),
        ];
        let control = settled_pin(&mut unbounded).cloned();
        assert_eq!(
            control,
            Some(CallPin::User(std::iter::once((a, UserPin::Unit)).collect()))
        );
    }

    #[test]
    fn unit_meets_exactly_its_derived_traits() {
        let met = BoundSet::UNBOUNDED
            .with_clone()
            .with_copy()
            .with_eq()
            .with_ord()
            .with_ord_total()
            .with_hash()
            .with_show()
            .with_static()
            .with_send()
            .with_sync();
        assert!(met.met_by_unit());
        let unmet: [fn(BoundSet) -> BoundSet; 6] = [
            BoundSet::with_add,
            BoundSet::with_sub,
            BoundSet::with_mul,
            BoundSet::with_interpolable,
            BoundSet::with_sql_param,
            BoundSet::with_ipe_row,
        ];
        for add in unmet {
            assert!(!add(met).met_by_unit(), "{:?}", add(BoundSet::UNBOUNDED));
        }
    }

    fn call(callee: u32, pins: Vec<(Symbol, UserPin)>) -> Expr {
        Expr::Call {
            callee: Callee::Func(FuncId::from_raw(callee)),
            args: vec![],
            pin: CallPin::User(pins.into_iter().collect()),
            on_form: ipe_ir::OnFormKind::NotForm,
        }
    }

    fn settled_pin(funcs: &mut [Func]) -> Option<&CallPin> {
        settle_user_pins(funcs, |_| Some(Span::new(0, 1)));
        match funcs.get(1).map(|f| &f.body) {
            Some(Expr::Call { pin, .. }) => Some(pin),
            _ => None,
        }
    }

    #[test]
    fn a_json_reading_on_an_ordered_parameter_becomes_the_refusal() {
        let a = sym(1);
        let ord = BoundSet::UNBOUNDED.with_ord_total().with_clone();
        let mut funcs = vec![
            func(0, vec![(a, ord)], vec![IrType::Int], Expr::Unit),
            func(
                1,
                vec![],
                vec![],
                call(0, vec![(a, UserPin::Instance(IrType::Json))]),
            ),
        ];
        let pin = settled_pin(&mut funcs);
        assert!(
            matches!(pin, Some(CallPin::User(pins)) if matches!(pins.get(&a), Some(UserPin::Unlowered(_)))),
            "{pin:?}"
        );
    }

    #[test]
    fn a_json_reading_on_an_unbounded_parameter_still_renders() {
        let a = sym(1);
        let mut funcs = vec![
            func(
                0,
                vec![(a, BoundSet::UNBOUNDED.with_clone())],
                vec![IrType::Int],
                Expr::Unit,
            ),
            func(
                1,
                vec![],
                vec![],
                call(0, vec![(a, UserPin::Instance(IrType::Json))]),
            ),
        ];
        let pin = settled_pin(&mut funcs).cloned();
        assert_eq!(
            pin,
            Some(CallPin::User(
                std::iter::once((a, UserPin::Instance(IrType::Json))).collect()
            ))
        );
    }

    #[test]
    fn a_pin_a_parameter_names_is_dropped_and_feeds_no_mention_walk() {
        let a = sym(1);
        let mut funcs = vec![
            func(
                0,
                vec![(a, BoundSet::UNBOUNDED)],
                vec![IrType::Generic(a)],
                Expr::Unit,
            ),
            func(
                1,
                vec![],
                vec![],
                call(0, vec![(a, UserPin::Instance(IrType::Json))]),
            ),
        ];
        let pin = settled_pin(&mut funcs).cloned();
        assert_eq!(pin, Some(CallPin::None));
    }

    #[test]
    fn a_unit_pin_renders_even_where_a_parameter_names_it() {
        let a = sym(1);
        let mut funcs = vec![
            func(
                0,
                vec![(a, BoundSet::UNBOUNDED)],
                vec![IrType::Generic(a)],
                Expr::Unit,
            ),
            func(1, vec![], vec![], call(0, vec![(a, UserPin::Unit)])),
        ];
        let pin = settled_pin(&mut funcs).cloned();
        assert_eq!(
            pin,
            Some(CallPin::User(std::iter::once((a, UserPin::Unit)).collect()))
        );
    }

    #[test]
    fn a_pin_on_no_type_parameter_of_the_callee_is_dropped() {
        let a = sym(1);
        let mut funcs = vec![
            func(0, vec![], vec![], Expr::Unit),
            func(1, vec![], vec![], call(0, vec![(a, UserPin::Unit)])),
        ];
        let pin = settled_pin(&mut funcs).cloned();
        assert_eq!(pin, Some(CallPin::None));
    }

    #[test]
    fn json_meets_exactly_its_derived_traits() {
        let met = BoundSet::UNBOUNDED
            .with_clone()
            .with_eq()
            .with_hash()
            .with_static()
            .with_send()
            .with_sync();
        assert!(met.met_by_json());
        let unmet: [fn(BoundSet) -> BoundSet; 10] = [
            BoundSet::with_ord,
            BoundSet::with_ord_total,
            BoundSet::with_copy,
            BoundSet::with_add,
            BoundSet::with_sub,
            BoundSet::with_mul,
            BoundSet::with_show,
            BoundSet::with_interpolable,
            BoundSet::with_sql_param,
            BoundSet::with_ipe_row,
        ];
        for add in unmet {
            assert!(!add(met).met_by_json(), "{:?}", add(BoundSet::UNBOUNDED));
        }
    }
}
