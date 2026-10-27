//! Binder-aware free-variable analysis over the typed IR, shared by the backend
//! and the lowerer.
//!
//! The emitter decides which captures to clone from these sets, and the
//! lowerer's `IPE-L0135` gate must mirror that decision, so both read this one
//! implementation.

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use ipe_intern::Symbol;

use crate::let_inline::pat_binds_target;
use crate::{Expr, IrType, Pat};

/// Collect every symbol a pattern binds (recursively) into `out`.
///
/// Same traversal shape as [`crate::let_inline::pat_binds_target`], gathering
/// the full bound set in one pass rather than testing one target.
pub fn pat_bound_symbols(pat: &Pat, out: &mut BTreeSet<Symbol>) {
    match pat {
        Pat::Var(s) => {
            out.insert(*s);
        }
        // A `SharedAlts` alternative is binder-free.
        Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) | Pat::Str(_) | Pat::Or(_) => {}
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
        Pat::Slice { prefix, rest, .. } => {
            for p in prefix {
                pat_bound_symbols(p, out);
            }
            if let Some(p) = rest {
                pat_bound_symbols(p, out);
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
        // A `SharedAlts` alternative is a constructor or an Int/Char/Bool literal,
        // never a string leaf.
        Pat::Or(_)
        | Pat::Var(_)
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
pub fn collect_free_vars(expr: &Expr, out: &mut BTreeSet<Symbol>) {
    let _ = walk_free(expr, &Scope::Top, &mut Sink::Collect(out));
}

/// Does `sym` occur free in `expr`?
///
/// The same walk as [`free_vars`], stopped at the first free occurrence, so
/// `mentions_free(s, e) == free_vars(e).contains(&s)` for every `s` and `e`.
/// A `move` closure captures by value every free local its body mentions,
/// whatever the emitted form at the mention (a borrow, a `.clone()`, a record
/// update base), so this is the capture predicate of a closure body.
#[must_use]
pub fn mentions_free(sym: Symbol, expr: &Expr) -> bool {
    walk_free(expr, &Scope::Top, &mut Sink::Find(sym)).is_break()
}

/// The binders in scope at a point of a [`walk_free`] walk, innermost first.
///
/// A stack-linked chain, so entering a binder allocates nothing.
#[derive(Clone, Copy)]
enum Scope<'a> {
    /// No binder of the walked expression is in scope.
    Top,
    /// A `let` name.
    Name(Symbol, &'a Self),
    /// The names a capture-clone node rebinds.
    Names(&'a [Symbol], &'a Self),
    /// Lambda or loop parameters.
    Params(&'a [(Symbol, IrType)], &'a Self),
    /// The names a destructure or arm pattern binds.
    Pattern(&'a Pat, &'a Self),
}

impl Scope<'_> {
    /// Is `sym` bound by some binder of this chain?
    fn binds(&self, sym: Symbol) -> bool {
        let mut cur = self;
        loop {
            match cur {
                Self::Top => return false,
                Self::Name(name, up) => {
                    if *name == sym {
                        return true;
                    }
                    cur = up;
                }
                Self::Names(names, up) => {
                    if names.contains(&sym) {
                        return true;
                    }
                    cur = up;
                }
                Self::Params(params, up) => {
                    if params.iter().any(|(s, _)| *s == sym) {
                        return true;
                    }
                    cur = up;
                }
                Self::Pattern(pat, up) => {
                    if pat_binds_target(pat, sym) {
                        return true;
                    }
                    cur = up;
                }
            }
        }
    }
}

/// What a [`walk_free`] walk does with each variable occurrence it meets.
enum Sink<'o> {
    /// Gather every free symbol.
    Collect(&'o mut BTreeSet<Symbol>),
    /// Stop at the first free occurrence of this symbol.
    Find(Symbol),
}

impl Sink<'_> {
    /// Record the occurrence of `sym` under `scope`; `Break` ends the walk.
    fn occur(&mut self, sym: Symbol, scope: &Scope<'_>) -> ControlFlow<()> {
        match self {
            Self::Collect(out) => {
                if !out.contains(&sym) && !scope.binds(sym) {
                    out.insert(sym);
                }
                ControlFlow::Continue(())
            }
            Self::Find(wanted) => {
                if *wanted == sym && !scope.binds(sym) {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            }
        }
    }
}

/// The one free-variable walk behind [`collect_free_vars`] and [`mentions_free`].
///
/// Every sub-expression is visited, the `Update` base included; a binder
/// extends `scope` only over the sub-expressions it scopes. The match is
/// exhaustive, so a new `Expr` variant is a build error here, never a silent
/// skip one walker makes and another does not.
fn walk_free(expr: &Expr, scope: &Scope<'_>, sink: &mut Sink<'_>) -> ControlFlow<()> {
    match expr {
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. } => ControlFlow::Continue(()),
        Expr::Var(s) | Expr::CloneVar(s) => sink.occur(*s, scope),
        Expr::Ctor { args, .. } | Expr::Call { args, .. } | Expr::TailRecur { args } => {
            walk_all(args, scope, sink)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            walk_free(lhs, scope, sink)?;
            walk_free(rhs, scope, sink)
        }
        Expr::Let { name, value, body } => {
            walk_free(value, scope, sink)?;
            walk_free(body, &Scope::Name(*name, scope), sink)
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            walk_free(value, scope, sink)?;
            walk_free(body, &Scope::Pattern(binder, scope), sink)
        }
        Expr::If { cond, then_, else_ } => {
            walk_free(cond, scope, sink)?;
            walk_free(then_, scope, sink)?;
            walk_free(else_, scope, sink)
        }
        Expr::Match(m) => {
            walk_free(m.scrutinee(), scope, sink)?;
            for arm in m.arms() {
                let arm_scope = Scope::Pattern(&arm.pat, scope);
                walk_free(&arm.body, &arm_scope, sink)?;
                if let Some(guard) = &arm.guard {
                    walk_free(guard, &arm_scope, sink)?;
                }
            }
            ControlFlow::Continue(())
        }
        Expr::Tuple(items) | Expr::List { items, .. } => walk_all(items, scope, sink),
        Expr::Cons { head, tail } => {
            walk_free(head, scope, sink)?;
            walk_free(tail, scope, sink)
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            walk_free(list, scope, sink)
        }
        Expr::Record { fields, .. } => walk_fields(fields, scope, sink),
        Expr::Access { record, .. } => walk_free(record, scope, sink),
        Expr::Update { record, fields } => {
            walk_free(record, scope, sink)?;
            walk_fields(fields, scope, sink)
        }
        Expr::Lambda { params, body, .. }
        | Expr::SharedLambda { params, body, .. }
        | Expr::OnceLambda { params, body, .. }
        | Expr::TailLoop { params, body } => walk_free(body, &Scope::Params(params, scope), sink),
        Expr::Apply { func, args } => {
            walk_free(func, scope, sink)?;
            walk_all(args, scope, sink)
        }
        Expr::TaskSeq { effect, rest } => {
            walk_free(effect, scope, sink)?;
            walk_free(rest, scope, sink)
        }
        Expr::CaptureClones { syms, body } => {
            for s in syms {
                sink.occur(*s, scope)?;
            }
            walk_free(body, &Scope::Names(syms, scope), sink)
        }
    }
}

/// [`walk_free`] over each expression of `exprs`, in order.
fn walk_all(exprs: &[Expr], scope: &Scope<'_>, sink: &mut Sink<'_>) -> ControlFlow<()> {
    for e in exprs {
        walk_free(e, scope, sink)?;
    }
    ControlFlow::Continue(())
}

/// [`walk_free`] over each field value of `fields`; field names are not variables.
fn walk_fields(
    fields: &[(Symbol, Expr)],
    scope: &Scope<'_>,
    sink: &mut Sink<'_>,
) -> ControlFlow<()> {
    for (_, e) in fields {
        walk_free(e, scope, sink)?;
    }
    ControlFlow::Continue(())
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
            own: crate::SliceOwnership::BorrowClone,
            elem: crate::IrType::Int,
        };
        assert!(!pat_has_str_guard_slot(&slice));
        assert!(!pat_moves_scrutinee(&slice));
        assert!(pat_moves_scrutinee(&Pat::Var(ty)));
    }
}
