//! Alpha-equivalence of record field templates.
//!
//! Two record field lists denote one synthesised struct exactly when one is a
//! consistent renaming of the other's type variables. The predicate walks both
//! lists side by side, pairs compound children through [`paired_children`] (the
//! head-identity SSOT, exhaustive over every [`IrType`] variant), and compares
//! leaves by equality, so no node is ever identified by a text rendering.

use std::collections::BTreeMap;

use ipe_intern::Symbol;

use crate::{IrType, paired_children};

/// A one-to-one renaming of type variables built up during one comparison.
#[derive(Default)]
struct Renaming {
    forward: BTreeMap<Symbol, Symbol>,
    backward: BTreeMap<Symbol, Symbol>,
}

impl Renaming {
    /// Whether `left` may stand for `right`, recording the pair when both are new.
    ///
    /// The pair is admitted only when neither side is already bound to a
    /// different variable, so the renaming stays a bijection.
    fn admit(&mut self, left: Symbol, right: Symbol) -> bool {
        let forward = *self.forward.entry(left).or_insert(right);
        let backward = *self.backward.entry(right).or_insert(left);
        forward == right && backward == left
    }
}

/// The renamings of one comparison: plain generics and row generics apart.
#[derive(Default)]
struct Renamings {
    generic: Renaming,
    row: Renaming,
}

impl Renamings {
    /// Whether `left` and `right` are one type up to the renamings so far.
    fn equivalent(&mut self, left: &IrType, right: &IrType) -> bool {
        match (left, right) {
            (IrType::Generic(l), IrType::Generic(r)) => self.generic.admit(*l, *r),
            (IrType::RowGeneric(l), IrType::RowGeneric(r)) => self.row.admit(*l, *r),
            (IrType::Generic(_) | IrType::RowGeneric(_), _)
            | (_, IrType::Generic(_) | IrType::RowGeneric(_)) => false,
            (IrType::Record(l), IrType::Record(r)) => {
                l.len() == r.len()
                    && l.iter()
                        .zip(r)
                        .all(|((lk, lt), (rk, rt))| lk == rk && self.equivalent(lt, rt))
            }
            _ => paired_children(left, right).map_or_else(
                || left == right,
                |mut children| children.all(|(l, r)| self.equivalent(l, r)),
            ),
        }
    }
}

/// Whether two record field lists are one template up to renaming type variables.
///
/// Field names must agree position by position (callers pass both lists in
/// their canonical name order). One bijection between the type variables of
/// `left` and those of `right` spans every field, so `{ x : a, y : a }` and
/// `{ x : a, y : b }` are distinct while `{ x : a, y : b }` and
/// `{ x : b, y : a }` are one. A compound node descends through
/// [`paired_children`]; a node it does not pair (a leaf, or two different
/// heads) must be equal.
#[must_use]
pub fn alpha_equivalent_fields<N: PartialEq>(left: &[(N, IrType)], right: &[(N, IrType)]) -> bool {
    let mut renamings = Renamings::default();
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|((ln, lt), (rn, rt))| ln == rn && renamings.equivalent(lt, rt))
}

#[cfg(test)]
mod tests {
    use super::alpha_equivalent_fields;
    use crate::{IrType, UiCtor};
    use ipe_intern::{Interner, Symbol};

    /// Interned type-variable symbols `a`, `b` and `c`.
    fn vars() -> (Symbol, Symbol, Symbol) {
        let mut interner = Interner::new();
        #[allow(clippy::expect_used)] // a fresh interner accepts these names
        let mut sym = |s: &str| interner.intern(s).expect("intern");
        (sym("a"), sym("b"), sym("c"))
    }

    fn generic(s: Symbol) -> IrType {
        IrType::Generic(s)
    }

    fn boxed(t: IrType) -> Box<IrType> {
        Box::new(t)
    }

    /// One field `items` of type `ty`.
    fn items(ty: IrType) -> Vec<(&'static str, IrType)> {
        vec![("items", ty)]
    }

    /// Fields `x` and `y` of the given types.
    fn xy(x: IrType, y: IrType) -> Vec<(&'static str, IrType)> {
        vec![("x", x), ("y", y)]
    }

    /// A variable nested in a `List` is renamed like a bare one.
    #[test]
    fn list_of_renamed_variable_is_equivalent() {
        let (a, b, _) = vars();
        assert!(alpha_equivalent_fields(
            &items(IrType::List(boxed(generic(a)))),
            &items(IrType::List(boxed(generic(b))))
        ));
    }

    /// Two different heads over one variable are not one template.
    #[test]
    fn list_and_maybe_are_distinct() {
        let (a, _, _) = vars();
        assert!(!alpha_equivalent_fields(
            &items(IrType::List(boxed(generic(a)))),
            &items(IrType::Maybe(boxed(generic(a))))
        ));
    }

    /// A variable inside a compound node shares the bijection with its siblings.
    #[test]
    fn nested_variable_counts_toward_the_bijection() {
        let (a, b, _) = vars();
        assert!(!alpha_equivalent_fields(
            &xy(IrType::List(boxed(generic(a))), generic(a)),
            &xy(IrType::List(boxed(generic(a))), generic(b))
        ));
        assert!(alpha_equivalent_fields(
            &xy(IrType::List(boxed(generic(a))), generic(a)),
            &xy(IrType::List(boxed(generic(b))), generic(b))
        ));
    }

    /// The renaming is checked in both directions.
    #[test]
    fn renaming_is_a_bijection() {
        let (a, b, _) = vars();
        assert!(alpha_equivalent_fields(
            &xy(generic(a), generic(b)),
            &xy(generic(b), generic(a))
        ));
        assert!(!alpha_equivalent_fields(
            &xy(generic(a), generic(a)),
            &xy(generic(a), generic(b))
        ));
        assert!(!alpha_equivalent_fields(
            &xy(generic(a), generic(b)),
            &xy(generic(a), generic(a))
        ));
    }

    /// Every compound head descends to its children, so its inner variables are renamed.
    #[test]
    fn every_compound_head_renames_inner_variables() {
        let (a, b, c) = vars();
        let heads: [fn(IrType, IrType) -> IrType; 7] = [
            |x, _| IrType::Maybe(Box::new(x)),
            |x, y| IrType::Result(Box::new(x), Box::new(y)),
            |x, _| IrType::Task(Box::new(x)),
            |x, _| IrType::Decoder(Box::new(x)),
            |x, _| IrType::Ui {
                ctor: UiCtor::Html,
                msg: Box::new(x),
            },
            |x, y| IrType::SharedFun(vec![x], Box::new(y)),
            |x, y| IrType::FnOnceChain(vec![x], Box::new(y)),
        ];
        for head in heads {
            assert!(
                alpha_equivalent_fields(
                    &items(head(generic(a), generic(b))),
                    &items(head(generic(b), generic(c)))
                ),
                "renamed inner variables are one template: {:?}",
                head(generic(a), generic(b))
            );
            assert!(
                !alpha_equivalent_fields(
                    &xy(head(generic(a), generic(a)), generic(a)),
                    &xy(head(generic(a), generic(a)), generic(b))
                ),
                "an inner variable binds its sibling: {:?}",
                head(generic(a), generic(a))
            );
        }
    }

    /// Leaves compare by equality; a variable never matches a leaf.
    #[test]
    fn leaves_compare_by_equality() {
        let (a, _, _) = vars();
        assert!(alpha_equivalent_fields(
            &items(IrType::Int),
            &items(IrType::Int)
        ));
        assert!(!alpha_equivalent_fields(
            &items(IrType::Int),
            &items(IrType::Str)
        ));
        assert!(!alpha_equivalent_fields(
            &items(generic(a)),
            &items(IrType::Int)
        ));
        assert!(!alpha_equivalent_fields(
            &items(IrType::Int),
            &items(generic(a))
        ));
    }

    /// Field names and counts must agree.
    #[test]
    fn field_names_and_counts_must_agree() {
        let (a, _, _) = vars();
        assert!(!alpha_equivalent_fields(
            &items(generic(a)),
            &[("other", generic(a))]
        ));
        assert!(!alpha_equivalent_fields(
            &items(generic(a)),
            &xy(generic(a), generic(a))
        ));
    }

    /// A row generic renames only to a row generic, under its own bijection.
    #[test]
    fn row_generics_rename_apart_from_generics() {
        let (a, b, _) = vars();
        assert!(alpha_equivalent_fields(
            &xy(IrType::RowGeneric(a), generic(a)),
            &xy(IrType::RowGeneric(b), generic(b))
        ));
        assert!(!alpha_equivalent_fields(
            &items(IrType::RowGeneric(a)),
            &items(generic(a))
        ));
        assert!(!alpha_equivalent_fields(
            &xy(IrType::RowGeneric(a), IrType::RowGeneric(a)),
            &xy(IrType::RowGeneric(a), IrType::RowGeneric(b))
        ));
    }
}
