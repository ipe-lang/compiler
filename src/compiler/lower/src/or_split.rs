//! The or-pattern normal form, established on the canonical module before lowering.
//!
//! After [`normalize`], an or-pattern exists only as a whole case-arm head whose
//! alternatives are each a constructor with every argument `_`, or an
//! `Int` / `Char` / `Bool` literal (the shape [`ipe_ir::SharedAlts`] admits).
//! Every other case arm holding an or-pattern anywhere is split into
//! consecutive arms, one per alternative of the distributed pattern, each
//! carrying a copy of the arm body. Ipê or-patterns match first-alternative-wins
//! left to right, and consecutive arms in alternative order match identically.
//! Exhaustiveness and redundancy already ran in the type phase over the source
//! arms, and every span is preserved, so each copy reads the same solved types.
//!
//! A `let`, lambda or definition parameter head has no sibling arm to split
//! into: a non-native or-pattern there is refused with IPE-L0116.
//!
//! The pass runs before the fresh-symbol pools are sized, so the pool counters
//! see every body copy.
//!
//! Splitting multiplies code, and the multiplication nests. Two ceilings bound
//! it, both charged with checked arithmetic, an overflow refusing like an
//! overrun: [`OR_SPLIT_ARM_CEILING`] alternatives per arm, and
//! [`OR_SPLIT_NODE_CEILING`] expression nodes added per top-level definition.
//!
//! # `or_split`: body-duplication audit
//!
//! A split arm's body is lowered once per copy with identical spans. Every
//! `Lowerer` field is one of:
//!
//! | Field | Kind under a repeated body |
//! |---|---|
//! | `m`, `types`, `interner`, `builtins`, `func_ids`, `enum_variants`, `ctor_arity`, `transparent_ffi_unions`, `enum_payloads`, `transparent_ffi_ctors`, `wildcard_marker`, `source_path` | read-only |
//! | `eta_params`, `cap_params`, `param_binders`, `any_param_binders`, `projection_decode_binders`, `destructure_thunk_binders`, `nested_cons_binders`, `nested_strlit_binders`, `tuple_elem_binders` | read-only pools, sized over the split module |
//! | `recorded_bounds` | (a) idempotent: a bound is OR-ed into the same type-variable slot |
//! | `callee_instances` | (a) idempotent: the repeated entry is the same instance, and `propagate_call_site_bounds` folds bounds as a set union to a fixpoint |
//! | `deferred_fun_captures` | (a) idempotent: the same symbol at the same span, removed at its binder in each copy |
//! | `fn_row_params` | (a) idempotent: written once per definition, after its body |
//! | `promotable_fn_binders`, `local_string_literals`, `toplevel_fn_aliases`, `shared_fn_reads`, `current_poly_tvars`, `fn_is_async` | (b) saved and restored around the scope that sets them |
//! | `current_home` | (b) set per definition |
//! | `eta_base`, `param_cursor`, `any_param_cursor`, `projection_decode_cursor`, `destructure_thunk_cursor`, `nested_cons_cursor`, `nested_strlit_cursor`, `tuple_elem_cursor` | (c) per-definition monotonic cursors: each copy draws a disjoint block |
//! | `carrier_walks` | (c) a monotonic budget: each copy is charged, an overrun fails closed |
//!
//! Lowering raises no warning: every warning is the type phase's, rendered once
//! from the source arms, so a copy cannot repeat one.

use std::borrow::Cow;

use ipe_canon::ast as canon;
use ipe_diagnostics::{Diagnostic, Feature, Located, Span};
use ipe_intern::Symbol;

use crate::lower::unsupported;

/// The most alternatives one case arm may split into.
pub const OR_SPLIT_ARM_CEILING: usize = 64;

/// The most expression nodes splitting may add to one top-level definition.
pub const OR_SPLIT_NODE_CEILING: usize = 1 << 16;

/// Establish the or-pattern normal form over `m`.
///
/// `Cow::Borrowed` when no case arm splits.
///
/// # Errors
/// IPE-L0116, homed at the definition, for a non-native or-pattern in a
/// `let`, lambda or definition parameter head, or a split over either ceiling.
pub fn normalize(m: &canon::Module) -> Result<Cow<'_, canon::Module>, (Diagnostic, Vec<Symbol>)> {
    let mut split = Vec::new();
    for (i, def) in m.defs.iter().enumerate() {
        if scan_def(def).map_err(|d| (d, def.home().to_vec()))? {
            split.push(i);
        }
    }
    if split.is_empty() {
        return Ok(Cow::Borrowed(m));
    }
    let mut out = m.clone();
    for i in split {
        if let Some(def) = out.defs.get_mut(i) {
            let home = def.home().to_vec();
            let body = match def {
                canon::Def::Untyped { body, .. } | canon::Def::Typed { body, .. } => body,
            };
            let mut added = 0;
            rewrite(body, &mut added).map_err(|d| (d, home))?;
        }
    }
    Ok(Cow::Owned(out))
}

/// The heads a case-arm pattern discriminates on.
///
/// A [`canon::Pattern_::POr`]'s alternatives, or the pattern itself otherwise,
/// so a head-keyed decision reads through the or-pattern.
#[must_use]
pub fn head_alternatives(pat: &canon::Pattern) -> &[canon::Pattern] {
    match &pat.value {
        canon::Pattern_::POr(alts) => alts.as_slice(),
        canon::Pattern_::PAnything
        | canon::Pattern_::PDebugAnything
        | canon::Pattern_::PUnit
        | canon::Pattern_::PVar(_)
        | canon::Pattern_::PCtor { .. }
        | canon::Pattern_::PTuple(_)
        | canon::Pattern_::PRecord(_)
        | canon::Pattern_::PInt(_)
        | canon::Pattern_::PBool(_)
        | canon::Pattern_::PChar(_)
        | canon::Pattern_::PStr(_)
        | canon::Pattern_::PAlias(..)
        | canon::Pattern_::PList(_)
        | canon::Pattern_::PCons(..) => std::slice::from_ref(pat),
    }
}

/// Whether `pat` is an or-pattern head lowering keeps native.
///
/// Every alternative is a constructor whose arguments are all `_`, or an
/// `Int` / `Char` / `Bool` literal.
fn kept_native(pat: &canon::Pattern) -> bool {
    match &pat.value {
        canon::Pattern_::POr(alts) => alts.iter().all(|a| match &a.value {
            canon::Pattern_::PCtor { args, .. } => args.iter().all(|p| {
                matches!(
                    p.value,
                    canon::Pattern_::PAnything | canon::Pattern_::PDebugAnything
                )
            }),
            canon::Pattern_::PInt(_) | canon::Pattern_::PChar(_) | canon::Pattern_::PBool(_) => {
                true
            }
            canon::Pattern_::PAnything
            | canon::Pattern_::PDebugAnything
            | canon::Pattern_::PUnit
            | canon::Pattern_::PVar(_)
            | canon::Pattern_::PTuple(_)
            | canon::Pattern_::PRecord(_)
            | canon::Pattern_::PStr(_)
            | canon::Pattern_::PAlias(..)
            | canon::Pattern_::PList(_)
            | canon::Pattern_::PCons(..)
            | canon::Pattern_::POr(_) => false,
        }),
        canon::Pattern_::PAnything
        | canon::Pattern_::PDebugAnything
        | canon::Pattern_::PUnit
        | canon::Pattern_::PVar(_)
        | canon::Pattern_::PCtor { .. }
        | canon::Pattern_::PTuple(_)
        | canon::Pattern_::PRecord(_)
        | canon::Pattern_::PInt(_)
        | canon::Pattern_::PBool(_)
        | canon::Pattern_::PChar(_)
        | canon::Pattern_::PStr(_)
        | canon::Pattern_::PAlias(..)
        | canon::Pattern_::PList(_)
        | canon::Pattern_::PCons(..) => false,
    }
}

/// The span of the first alternative of the first or-pattern in `pat`, in source order.
fn first_or_alternative(pat: &canon::Pattern) -> Option<Span> {
    match &pat.value {
        canon::Pattern_::POr(alts) => alts.first().map(|a| a.span),
        canon::Pattern_::PCtor { args: ps, .. }
        | canon::Pattern_::PTuple(ps)
        | canon::Pattern_::PList(ps) => ps.iter().find_map(first_or_alternative),
        canon::Pattern_::PCons(h, t) => first_or_alternative(h).or_else(|| first_or_alternative(t)),
        canon::Pattern_::PAlias(inner, _) => first_or_alternative(inner),
        canon::Pattern_::PAnything
        | canon::Pattern_::PDebugAnything
        | canon::Pattern_::PUnit
        | canon::Pattern_::PVar(_)
        | canon::Pattern_::PRecord(_)
        | canon::Pattern_::PInt(_)
        | canon::Pattern_::PBool(_)
        | canon::Pattern_::PChar(_)
        | canon::Pattern_::PStr(_) => None,
    }
}

/// Whether the case arm headed by `pat` splits.
fn splits(pat: &canon::Pattern) -> bool {
    !kept_native(pat) && first_or_alternative(pat).is_some()
}

/// Refuse a non-native or-pattern in a head with no sibling arm.
fn refuse_unsplittable(pat: &canon::Pattern) -> Result<(), Diagnostic> {
    if kept_native(pat) {
        return Ok(());
    }
    first_or_alternative(pat).map_or(Ok(()), |span| {
        Err(unsupported(span, Feature::NestedCtorDiscrimination))
    })
}

/// The direct sub-expressions of `e`, in source order.
fn children(e: &canon::Expr) -> Vec<&canon::Expr> {
    match &e.value {
        canon::Expr_::VarLocal(_)
        | canon::Expr_::VarTopLevel { .. }
        | canon::Expr_::VarKernel { .. }
        | canon::Expr_::VarCtor { .. }
        | canon::Expr_::Int(_)
        | canon::Expr_::Float(_)
        | canon::Expr_::Str(_)
        | canon::Expr_::Char(_)
        | canon::Expr_::CustomElementCtor(_)
        | canon::Expr_::Unit => Vec::new(),
        canon::Expr_::Call(f, args) => std::iter::once(f.as_ref()).chain(args).collect(),
        canon::Expr_::ForeignCall { args, .. }
        | canon::Expr_::Tuple(args)
        | canon::Expr_::List(args) => args.iter().collect(),
        canon::Expr_::Case(scrut, branches) => std::iter::once(scrut.as_ref())
            .chain(branches.iter().map(|b| &b.body))
            .collect(),
        canon::Expr_::Lambda(_, body) | canon::Expr_::Access(body, _) => vec![body.as_ref()],
        canon::Expr_::Binop { lhs, rhs, .. } | canon::Expr_::Cons(lhs, rhs) => {
            vec![lhs.as_ref(), rhs.as_ref()]
        }
        canon::Expr_::Let(bindings, body) => bindings
            .iter()
            .map(|b| &b.body)
            .chain(std::iter::once(body.as_ref()))
            .collect(),
        canon::Expr_::If(pairs, els) => pairs
            .iter()
            .flat_map(|(c, t)| [c, t])
            .chain(std::iter::once(els.as_ref()))
            .collect(),
        canon::Expr_::Record(fields) => fields.iter().map(|(_, v)| v).collect(),
        canon::Expr_::Update(base, fields) => std::iter::once(base.as_ref())
            .chain(fields.iter().map(|(_, v)| v))
            .collect(),
    }
}

/// Refuse every unsplittable head in `def` and report whether any case arm splits.
fn scan_def(def: &canon::Def) -> Result<bool, Diagnostic> {
    let (patterns, body) = match def {
        canon::Def::Untyped { patterns, body, .. } | canon::Def::Typed { patterns, body, .. } => {
            (patterns, body)
        }
    };
    for p in patterns {
        refuse_unsplittable(p)?;
    }
    let mut any_split = false;
    let mut pending = vec![body];
    while let Some(e) = pending.pop() {
        match &e.value {
            canon::Expr_::Case(_, branches) => {
                any_split = any_split || branches.iter().any(|b| splits(&b.pat));
            }
            canon::Expr_::Lambda(params, _) => {
                for p in params {
                    refuse_unsplittable(p)?;
                }
            }
            canon::Expr_::Let(bindings, _) => {
                for b in bindings {
                    refuse_unsplittable(&b.pat)?;
                }
            }
            canon::Expr_::VarLocal(_)
            | canon::Expr_::VarTopLevel { .. }
            | canon::Expr_::VarKernel { .. }
            | canon::Expr_::VarCtor { .. }
            | canon::Expr_::Int(_)
            | canon::Expr_::Float(_)
            | canon::Expr_::Str(_)
            | canon::Expr_::Char(_)
            | canon::Expr_::CustomElementCtor(_)
            | canon::Expr_::Unit
            | canon::Expr_::Call(..)
            | canon::Expr_::ForeignCall { .. }
            | canon::Expr_::Binop { .. }
            | canon::Expr_::If(..)
            | canon::Expr_::Tuple(_)
            | canon::Expr_::List(_)
            | canon::Expr_::Cons(..)
            | canon::Expr_::Record(_)
            | canon::Expr_::Access(..)
            | canon::Expr_::Update(..) => {}
        }
        pending.extend(children(e));
    }
    Ok(any_split)
}

/// The number of expression nodes in `e`; `None` on overflow.
fn node_count(e: &canon::Expr) -> Option<usize> {
    let mut total: usize = 0;
    let mut pending = vec![e];
    while let Some(e) = pending.pop() {
        total = total.checked_add(1)?;
        pending.extend(children(e));
    }
    Some(total)
}

/// Charge `k - 1` added copies of a `nodes`-node body against `total`.
///
/// # Errors
/// IPE-L0116 at `span` when the sum passes [`OR_SPLIT_NODE_CEILING`] or overflows.
fn charge(total: usize, k: usize, nodes: usize, span: Span) -> Result<usize, Diagnostic> {
    k.checked_sub(1)
        .and_then(|copies| copies.checked_mul(nodes))
        .and_then(|added| added.checked_add(total))
        .filter(|sum| *sum <= OR_SPLIT_NODE_CEILING)
        .ok_or_else(|| unsupported(span, Feature::NestedCtorDiscrimination))
}

/// The number of alternatives `pat` distributes into; `None` on overflow.
fn alternative_count(pat: &canon::Pattern) -> Option<usize> {
    let product = |ps: &[canon::Pattern]| {
        ps.iter()
            .try_fold(1_usize, |acc, p| acc.checked_mul(alternative_count(p)?))
    };
    match &pat.value {
        canon::Pattern_::POr(alts) => alts
            .iter()
            .try_fold(0_usize, |acc, a| acc.checked_add(alternative_count(a)?)),
        canon::Pattern_::PCtor { args: ps, .. }
        | canon::Pattern_::PTuple(ps)
        | canon::Pattern_::PList(ps) => product(ps),
        canon::Pattern_::PCons(h, t) => alternative_count(h)?.checked_mul(alternative_count(t)?),
        canon::Pattern_::PAlias(inner, _) => alternative_count(inner),
        canon::Pattern_::PAnything
        | canon::Pattern_::PDebugAnything
        | canon::Pattern_::PUnit
        | canon::Pattern_::PVar(_)
        | canon::Pattern_::PRecord(_)
        | canon::Pattern_::PInt(_)
        | canon::Pattern_::PBool(_)
        | canon::Pattern_::PChar(_)
        | canon::Pattern_::PStr(_) => Some(1),
    }
}

/// The or-free alternatives of `pat`, every or-pattern lifted to the top.
///
/// A product (constructor arguments, tuple or list elements, cons head and
/// tail) varies its leftmost child slowest. Spans are preserved.
fn distribute(pat: &canon::Pattern) -> Vec<canon::Pattern> {
    let at = |value: canon::Pattern_| Located::new(pat.span, value);
    match &pat.value {
        canon::Pattern_::POr(alts) => alts.iter().flat_map(distribute).collect(),
        canon::Pattern_::PCtor {
            home,
            type_name,
            name,
            index,
            args,
        } => product(args)
            .into_iter()
            .map(|args| {
                at(canon::Pattern_::PCtor {
                    home: home.clone(),
                    type_name: *type_name,
                    name: *name,
                    index: *index,
                    args,
                })
            })
            .collect(),
        canon::Pattern_::PTuple(elems) => product(elems)
            .into_iter()
            .map(|elems| at(canon::Pattern_::PTuple(elems)))
            .collect(),
        canon::Pattern_::PList(elems) => product(elems)
            .into_iter()
            .map(|elems| at(canon::Pattern_::PList(elems)))
            .collect(),
        canon::Pattern_::PCons(h, t) => {
            let tails = distribute(t);
            distribute(h)
                .into_iter()
                .flat_map(|h| {
                    tails.iter().map(move |t| {
                        at(canon::Pattern_::PCons(
                            Box::new(h.clone()),
                            Box::new(t.clone()),
                        ))
                    })
                })
                .collect()
        }
        canon::Pattern_::PAlias(inner, name) => distribute(inner)
            .into_iter()
            .map(|p| at(canon::Pattern_::PAlias(Box::new(p), *name)))
            .collect(),
        canon::Pattern_::PAnything
        | canon::Pattern_::PDebugAnything
        | canon::Pattern_::PUnit
        | canon::Pattern_::PVar(_)
        | canon::Pattern_::PRecord(_)
        | canon::Pattern_::PInt(_)
        | canon::Pattern_::PBool(_)
        | canon::Pattern_::PChar(_)
        | canon::Pattern_::PStr(_) => vec![pat.clone()],
    }
}

/// The cartesian product of each child's alternatives, leftmost slowest.
fn product(children: &[canon::Pattern]) -> Vec<Vec<canon::Pattern>> {
    let mut rows = vec![Vec::with_capacity(children.len())];
    for child in children {
        let alts = distribute(child);
        rows = rows
            .into_iter()
            .flat_map(|row| {
                alts.iter().map(move |a| {
                    let mut next = row.clone();
                    next.push(a.clone());
                    next
                })
            })
            .collect();
    }
    rows
}

/// The alternatives a splitting arm headed by `pat` becomes.
///
/// # Errors
/// IPE-L0116 at the arm pattern when they pass [`OR_SPLIT_ARM_CEILING`].
fn split_alternatives(pat: &canon::Pattern) -> Result<Vec<canon::Pattern>, Diagnostic> {
    match alternative_count(pat) {
        Some(k) if k <= OR_SPLIT_ARM_CEILING => Ok(distribute(pat)),
        Some(_) | None => Err(unsupported(pat.span, Feature::NestedCtorDiscrimination)),
    }
}

/// Split every splitting case arm in `e`, bottom-up, charging `added`.
fn rewrite(e: &mut canon::Expr, added: &mut usize) -> Result<(), Diagnostic> {
    match &mut e.value {
        canon::Expr_::VarLocal(_)
        | canon::Expr_::VarTopLevel { .. }
        | canon::Expr_::VarKernel { .. }
        | canon::Expr_::VarCtor { .. }
        | canon::Expr_::Int(_)
        | canon::Expr_::Float(_)
        | canon::Expr_::Str(_)
        | canon::Expr_::Char(_)
        | canon::Expr_::CustomElementCtor(_)
        | canon::Expr_::Unit => Ok(()),
        canon::Expr_::Call(f, args) => {
            rewrite(f, added)?;
            args.iter_mut().try_for_each(|a| rewrite(a, added))
        }
        canon::Expr_::ForeignCall { args, .. }
        | canon::Expr_::Tuple(args)
        | canon::Expr_::List(args) => args.iter_mut().try_for_each(|a| rewrite(a, added)),
        canon::Expr_::Case(scrut, branches) => {
            rewrite(scrut, added)?;
            let source = std::mem::take(branches);
            let mut out = Vec::with_capacity(source.len());
            for mut branch in source {
                rewrite(&mut branch.body, added)?;
                if !splits(&branch.pat) {
                    out.push(branch);
                    continue;
                }
                let alts = split_alternatives(&branch.pat)?;
                let nodes = node_count(&branch.body).ok_or_else(|| {
                    unsupported(branch.pat.span, Feature::NestedCtorDiscrimination)
                })?;
                *added = charge(*added, alts.len(), nodes, branch.pat.span)?;
                let body = branch.body;
                let mut alts = alts.into_iter();
                let last = alts.next_back();
                for pat in alts {
                    out.push(canon::CaseBranch {
                        pat,
                        body: body.clone(),
                    });
                }
                if let Some(pat) = last {
                    out.push(canon::CaseBranch { pat, body });
                }
            }
            *branches = out;
            Ok(())
        }
        canon::Expr_::Lambda(_, body) | canon::Expr_::Access(body, _) => rewrite(body, added),
        canon::Expr_::Binop { lhs, rhs, .. } | canon::Expr_::Cons(lhs, rhs) => {
            rewrite(lhs, added)?;
            rewrite(rhs, added)
        }
        canon::Expr_::Let(bindings, body) => {
            bindings
                .iter_mut()
                .try_for_each(|b| rewrite(&mut b.body, added))?;
            rewrite(body, added)
        }
        canon::Expr_::If(pairs, els) => {
            pairs.iter_mut().try_for_each(|(c, t)| {
                rewrite(c, added)?;
                rewrite(t, added)
            })?;
            rewrite(els, added)
        }
        canon::Expr_::Record(fields) => fields.iter_mut().try_for_each(|(_, v)| rewrite(v, added)),
        canon::Expr_::Update(base, fields) => {
            rewrite(base, added)?;
            fields.iter_mut().try_for_each(|(_, v)| rewrite(v, added))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at<T>(value: T) -> Located<T> {
        Located::new(Span::new(0, 0), value)
    }

    fn sym(n: u32) -> Symbol {
        Symbol::from_raw(n)
    }

    fn ctor(name: u32, index: usize) -> canon::Pattern {
        at(canon::Pattern_::PCtor {
            home: vec![],
            type_name: sym(1),
            name: sym(name),
            index,
            args: vec![],
        })
    }

    fn module(body: canon::Expr) -> canon::Module {
        canon::Module {
            name: vec![sym(9)],
            unions: vec![],
            defs: vec![canon::Def::Untyped {
                home: vec![sym(9)],
                name: at(sym(8)),
                patterns: vec![],
                body,
            }],
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
        }
    }

    fn case(branches: Vec<canon::CaseBranch>) -> canon::Expr {
        at(canon::Expr_::Case(
            Box::new(at(canon::Expr_::VarLocal(sym(7)))),
            branches,
        ))
    }

    fn arm(pat: canon::Pattern, n: i64) -> canon::CaseBranch {
        canon::CaseBranch {
            pat,
            body: at(canon::Expr_::Int(n)),
        }
    }

    #[test]
    fn or_split_borrowed_when_no_or() {
        let m = module(case(vec![arm(ctor(2, 0), 0), arm(ctor(3, 1), 1)]));
        assert!(matches!(normalize(&m), Ok(Cow::Borrowed(_))));
        let native = at(canon::Pattern_::POr(vec![ctor(2, 0), ctor(3, 1)]));
        let m = module(case(vec![arm(native, 0)]));
        assert!(matches!(normalize(&m), Ok(Cow::Borrowed(_))));
    }

    #[test]
    fn or_split_product_order() {
        let or = |a, b| at(canon::Pattern_::POr(vec![ctor(a, 0), ctor(b, 1)]));
        let pat = at(canon::Pattern_::PTuple(vec![or(2, 3), or(4, 5)]));
        let names: Vec<Vec<Symbol>> = distribute(&pat)
            .iter()
            .map(|p| match &p.value {
                canon::Pattern_::PTuple(elems) => elems
                    .iter()
                    .filter_map(|e| match &e.value {
                        canon::Pattern_::PCtor { name, .. } => Some(*name),
                        canon::Pattern_::PAnything
                        | canon::Pattern_::PDebugAnything
                        | canon::Pattern_::PUnit
                        | canon::Pattern_::PVar(_)
                        | canon::Pattern_::PTuple(_)
                        | canon::Pattern_::PRecord(_)
                        | canon::Pattern_::PInt(_)
                        | canon::Pattern_::PBool(_)
                        | canon::Pattern_::PChar(_)
                        | canon::Pattern_::PStr(_)
                        | canon::Pattern_::PAlias(..)
                        | canon::Pattern_::PList(_)
                        | canon::Pattern_::PCons(..)
                        | canon::Pattern_::POr(_) => None,
                    })
                    .collect(),
                canon::Pattern_::PAnything
                | canon::Pattern_::PDebugAnything
                | canon::Pattern_::PUnit
                | canon::Pattern_::PVar(_)
                | canon::Pattern_::PCtor { .. }
                | canon::Pattern_::PRecord(_)
                | canon::Pattern_::PInt(_)
                | canon::Pattern_::PBool(_)
                | canon::Pattern_::PChar(_)
                | canon::Pattern_::PStr(_)
                | canon::Pattern_::PAlias(..)
                | canon::Pattern_::PList(_)
                | canon::Pattern_::PCons(..)
                | canon::Pattern_::POr(_) => Vec::new(),
            })
            .collect();
        assert_eq!(
            names,
            vec![
                vec![sym(2), sym(4)],
                vec![sym(2), sym(5)],
                vec![sym(3), sym(4)],
                vec![sym(3), sym(5)],
            ]
        );
        let m = module(case(vec![arm(pat, 1)]));
        let split = normalize(&m);
        let arms = match &split {
            Ok(Cow::Owned(out)) => match out.defs.first() {
                Some(canon::Def::Untyped { body, .. }) => {
                    if let canon::Expr_::Case(_, branches) = &body.value {
                        branches.len()
                    } else {
                        0
                    }
                }
                Some(canon::Def::Typed { .. }) | None => 0,
            },
            Ok(Cow::Borrowed(_)) | Err(_) => 0,
        };
        assert_eq!(arms, 4);
    }

    #[test]
    fn or_split_overflow_fails_closed() {
        let span = Span::new(3, 9);
        let refused = Err(unsupported(span, Feature::NestedCtorDiscrimination));
        assert_eq!(charge(usize::MAX, 2, 1, span), refused);
        assert_eq!(charge(0, usize::MAX, 2, span), refused);
        assert_eq!(charge(0, 0, 1, span), refused);
        assert_eq!(
            charge(0, 2, OR_SPLIT_NODE_CEILING, span),
            Ok(OR_SPLIT_NODE_CEILING)
        );
        assert_eq!(charge(1, 2, OR_SPLIT_NODE_CEILING, span), refused);
        let wide = at(canon::Pattern_::PTuple(
            (0..7)
                .map(|_| at(canon::Pattern_::POr(vec![ctor(2, 0), ctor(3, 1)])))
                .collect(),
        ));
        assert!(split_alternatives(&wide).is_err());
    }
}
