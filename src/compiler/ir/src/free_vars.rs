//! Binder-aware free-variable analysis over the typed IR, shared by the backend
//! and the lowerer.
//!
//! The emitter decides which captures to clone from these sets, and the
//! lowerer's `IPE-L0135` gate must mirror that decision, so both read this one
//! implementation.

use std::collections::BTreeSet;

use ipe_intern::Symbol;

use crate::{Expr, Pat};

/// Collect every symbol a pattern binds (recursively) into `out`.
///
/// Same traversal shape as [`crate::let_inline::pat_binds_target`], gathering
/// the full bound set in one pass rather than testing one target.
pub fn pat_bound_symbols(pat: &Pat, out: &mut BTreeSet<Symbol>) {
    match pat {
        Pat::Var(s) => {
            out.insert(*s);
        }
        Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) | Pat::Str(_) => {}
        Pat::Alias(inner, s) => {
            out.insert(*s);
            pat_bound_symbols(inner, out);
        }
        Pat::Ctor { args, .. } => {
            for p in args {
                pat_bound_symbols(p, out);
            }
        }
        Pat::Tuple(elems) => {
            for p in elems {
                pat_bound_symbols(p, out);
            }
        }
        Pat::Record(fields) => {
            for (_, p) in fields {
                pat_bound_symbols(p, out);
            }
        }
        Pat::Slice { prefix, rest } => {
            for p in prefix {
                pat_bound_symbols(p, out);
            }
            if let Some(p) = rest {
                pat_bound_symbols(p, out);
            }
        }
        // Every alternative of an or-pattern binds the same names, so the first
        // alternative's binders are the whole set.
        Pat::Or(alts) => {
            if let Some(first) = alts.first() {
                pat_bound_symbols(first, out);
            }
        }
    }
}

/// Does the by-value arm pattern `pat` carry a string-literal leaf bound to a hidden guard slot?
///
/// Rust cannot match an owned `String` part against a `&str` literal pattern,
/// so the emitter binds a string literal in a by-value position (a tuple
/// element, a constructor payload, a record field, an alias inner, or `pat`
/// itself when the caller renders it by value) to a fresh by-value slot and
/// checks it in a match guard. That slot MOVES the part it binds. A slice
/// prefix/rest is matched by reference (list mode) and is not recursed.
#[must_use]
pub fn pat_has_str_guard_slot(pat: &Pat) -> bool {
    match pat {
        Pat::Str(_) => true,
        Pat::Alias(inner, _) => pat_has_str_guard_slot(inner),
        Pat::Tuple(elems) => elems.iter().any(pat_has_str_guard_slot),
        Pat::Ctor { args, .. } => args.iter().any(pat_has_str_guard_slot),
        Pat::Record(fields) => fields.iter().any(|(_, p)| pat_has_str_guard_slot(p)),
        Pat::Or(alts) => alts.iter().any(pat_has_str_guard_slot),
        Pat::Var(_)
        | Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Slice { .. } => false,
    }
}

/// Does `pat`, in a nested by-value position, move the part it matches?
///
/// Every by-value slot the emitter creates moves its part: a named binder
/// ([`pat_bound_symbols`]) and a hidden string-literal guard slot
/// ([`pat_has_str_guard_slot`]).
#[must_use]
pub fn pat_moves_nested_part(pat: &Pat) -> bool {
    let mut bound = BTreeSet::new();
    pat_bound_symbols(pat, &mut bound);
    !bound.is_empty() || pat_has_str_guard_slot(pat)
}

/// Does matching a by-value scrutinee against the pattern `pat` move any part of it?
///
/// A top-level string literal matches a borrowed `.as_str()` scrutinee and
/// moves nothing; every other shape moves exactly when
/// [`pat_moves_nested_part`] finds a by-value slot.
#[must_use]
pub fn pat_moves_scrutinee(pat: &Pat) -> bool {
    !matches!(pat, Pat::Str(_)) && pat_moves_nested_part(pat)
}

/// The set of symbols that occur free in `expr`.
///
/// Every binder (`Let`/`Destructure`/`Lambda`/`TailLoop`/`Match` arm
/// patterns) removes its bound name(s) from the free set of the scope it
/// introduces. A `Match` arm guard counts as part of its arm. Both `Var` and
/// `CloneVar` occurrences are free uses. String literals and record field
/// names are opaque leaves, never mistaken for a variable occurrence.
#[must_use]
pub fn free_vars(expr: &Expr) -> BTreeSet<Symbol> {
    let mut out = BTreeSet::new();
    collect_free_vars(expr, &mut out);
    out
}

/// Add the free symbols of `expr` to `out` (see [`free_vars`]).
#[allow(clippy::too_many_lines)] // A recursive tree-walk over a large enum — necessarily long.
pub fn collect_free_vars(expr: &Expr, out: &mut BTreeSet<Symbol>) {
    match expr {
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::PathLit(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => {}
        Expr::Var(s) | Expr::CloneVar(s) => {
            out.insert(*s);
        }
        Expr::Ctor { args, .. } | Expr::Call { args, .. } | Expr::TailRecur { args } => {
            for a in args {
                collect_free_vars(a, out);
            }
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_free_vars(lhs, out);
            collect_free_vars(rhs, out);
        }
        Expr::Let { name, value, body } => {
            collect_free_vars(value, out);
            let mut body_free = BTreeSet::new();
            collect_free_vars(body, &mut body_free);
            body_free.remove(name);
            out.extend(body_free);
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            collect_free_vars(value, out);
            let mut bound = BTreeSet::new();
            pat_bound_symbols(binder, &mut bound);
            let mut body_free = BTreeSet::new();
            collect_free_vars(body, &mut body_free);
            for b in &bound {
                body_free.remove(b);
            }
            out.extend(body_free);
        }
        Expr::If { cond, then_, else_ } => {
            collect_free_vars(cond, out);
            collect_free_vars(then_, out);
            collect_free_vars(else_, out);
        }
        Expr::Match(m) => {
            collect_free_vars(m.scrutinee(), out);
            for arm in m.arms() {
                let mut bound = BTreeSet::new();
                pat_bound_symbols(&arm.pat, &mut bound);
                let mut body_free = BTreeSet::new();
                collect_free_vars(&arm.body, &mut body_free);
                if let Some(guard) = &arm.guard {
                    collect_free_vars(guard, &mut body_free);
                }
                for b in &bound {
                    body_free.remove(b);
                }
                out.extend(body_free);
            }
        }
        Expr::Tuple(items) | Expr::List { items, .. } => {
            for e in items {
                collect_free_vars(e, out);
            }
        }
        Expr::Cons { head, tail } => {
            collect_free_vars(head, out);
            collect_free_vars(tail, out);
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            collect_free_vars(list, out);
        }
        Expr::Record { fields, .. } => {
            for (_, e) in fields {
                collect_free_vars(e, out);
            }
        }
        Expr::Access { record, .. } => collect_free_vars(record, out),
        Expr::Update { record, fields } => {
            collect_free_vars(record, out);
            for (_, e) in fields {
                collect_free_vars(e, out);
            }
        }
        Expr::Lambda { params, body, .. }
        | Expr::SharedLambda { params, body, .. }
        | Expr::TailLoop { params, body } => {
            let mut body_free = BTreeSet::new();
            collect_free_vars(body, &mut body_free);
            for (s, _) in params {
                body_free.remove(s);
            }
            out.extend(body_free);
        }
        Expr::Apply { func, args } => {
            collect_free_vars(func, out);
            for a in args {
                collect_free_vars(a, out);
            }
        }
        Expr::TaskSeq { effect, rest } => {
            collect_free_vars(effect, out);
            collect_free_vars(rest, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use ipe_intern::{Interner, Symbol};

    use super::{pat_has_str_guard_slot, pat_moves_nested_part, pat_moves_scrutinee};
    use crate::{ModPath, Pat};

    fn symbols() -> (Symbol, Symbol, Symbol) {
        let mut interner = Interner::new();
        let ty = interner.intern("Cmd").expect("intern");
        let variant = interner.intern("Say").expect("intern");
        let field = interner.intern("name").expect("intern");
        (ty, variant, field)
    }

    fn lit() -> Pat {
        Pat::Str("go".to_owned())
    }

    #[test]
    fn top_level_string_literal_borrows_the_scrutinee() {
        assert!(pat_has_str_guard_slot(&lit()));
        assert!(pat_moves_nested_part(&lit()));
        assert!(!pat_moves_scrutinee(&lit()));
        assert!(!pat_moves_scrutinee(&Pat::Wildcard));
        assert!(!pat_moves_scrutinee(&Pat::Int(1)));
    }

    #[test]
    fn nested_string_literal_moves_its_part() {
        let (ty, variant, field) = symbols();
        let tuple = Pat::Tuple(vec![lit(), Pat::Wildcard]);
        let ctor = Pat::Ctor {
            home: ModPath(vec![ty]),
            ty,
            variant,
            args: vec![lit()],
        };
        let record = Pat::Record(vec![(field, lit())]);
        let alias_inner = Pat::Tuple(vec![Pat::Wildcard, Pat::Alias(Box::new(lit()), field)]);
        for pat in [&tuple, &ctor, &record, &alias_inner] {
            assert!(pat_has_str_guard_slot(pat));
            assert!(pat_moves_scrutinee(pat));
        }
    }

    #[test]
    fn literal_free_shapes_move_only_through_binders() {
        let (ty, _, field) = symbols();
        let wild_tuple = Pat::Tuple(vec![Pat::Int(1), Pat::Wildcard]);
        assert!(!pat_moves_scrutinee(&wild_tuple));
        let bound_tuple = Pat::Tuple(vec![Pat::Int(1), Pat::Var(field)]);
        assert!(!pat_has_str_guard_slot(&bound_tuple));
        assert!(pat_moves_scrutinee(&bound_tuple));
        let slice = Pat::Slice {
            prefix: vec![lit()],
            rest: None,
        };
        assert!(!pat_has_str_guard_slot(&slice));
        assert!(!pat_moves_scrutinee(&slice));
        assert!(pat_moves_scrutinee(&Pat::Var(ty)));
    }
}
