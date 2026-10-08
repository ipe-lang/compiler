//! Owned, interner-free type rendering: build a [`TyDoc`] at the failure point.
//!
//! Parse-don't-validate: a [`TypeError`](ipe_diagnostics::TypeError) payload
//! carries an **already-resolved** [`TyDoc`], so the reporter never touches the
//! interner or the union-find arena. The producers in [`crate::unify`] /
//! [`crate::constrain`] call into here at the exact site a type fails to unify,
//! resolving every [`Symbol`] into an owned `Box<str>`.

use std::collections::BTreeMap;

use ipe_canon::ast as canon;
use ipe_diagnostics::{DResult, Diagnostic, TyDoc};
use ipe_intern::{Interner, Symbol};

use crate::ty::Ty;

/// Deterministic naming for flexible type variables that survived solving.
///
/// A solved [`Ty::Var`] carries an opaque arena id, not a source name; rendering
/// it verbatim would leak an unstable integer. Instead each distinct id is
/// assigned a stable letter (`a`, `b`, …, `z`, `a1`, `b1`, …) in **first-seen
/// order**, shared across the expected/found pair of a single diagnostic so the
/// same variable reads identically on both sides.
#[derive(Default)]
pub struct VarNamer {
    map: BTreeMap<u32, Box<str>>,
    next: u32,
}

impl VarNamer {
    /// A fresh namer with no assignments.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            next: 0,
        }
    }

    /// The stable letter name for arena id `id`, minting one on first sight.
    fn name(&mut self, id: u32) -> Box<str> {
        if let Some(existing) = self.map.get(&id) {
            return existing.clone();
        }
        let name = letters(self.next);
        self.next = self.next.saturating_add(1);
        self.map.insert(id, name.clone());
        name
    }
}

/// `0 → a`, `25 → z`, `26 → a1`, `27 → b1`, … — a spreadsheet-column-style name.
#[must_use]
pub fn letters(k: u32) -> Box<str> {
    let letter = char::from(b'a'.wrapping_add(u8::try_from(k % 26).unwrap_or(0)));
    let suffix = k / 26;
    if suffix == 0 {
        letter.to_string().into_boxed_str()
    } else {
        format!("{letter}{suffix}").into_boxed_str()
    }
}

/// Resolve a single [`Symbol`] into an owned name, or a `CompilerBug` if the
/// interner has no backing string (a forged symbol — see IPE-I0010).
fn resolve(interner: &Interner, sym: Symbol) -> DResult<Box<str>> {
    interner
        .resolve(sym)
        .map(Box::from)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "intern.resolve",
            detail: format!("no backing string for symbol {}", sym.as_raw()),
        })
}

/// Join dotted module segments into an owned `Module.Path` string (empty for the
/// built-in home).
fn resolve_module(interner: &Interner, module: &[Symbol]) -> DResult<Box<str>> {
    let mut parts = Vec::with_capacity(module.len());
    for seg in module {
        parts.push(resolve(interner, *seg)?);
    }
    Ok(parts.join(".").into_boxed_str())
}

/// Render a resolved [`Ty`] (post-solve, read back by `zonk`) into an owned
/// [`TyDoc`].
///
/// The `Ty` is already bounded by `zonk`'s per-call node cap, so this
/// recursion is bounded well under the native-stack ceiling.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if a symbol cannot be resolved.
pub fn ty_to_doc(ty: &Ty, interner: &Interner, namer: &mut VarNamer) -> DResult<TyDoc> {
    match ty {
        Ty::Unit => Ok(TyDoc::Unit),
        Ty::Var(id) => Ok(TyDoc::Var(namer.name(*id))),
        Ty::Wildcard => Ok(TyDoc::Var(canon::WILDCARD_SPELLING.into())),
        Ty::Fun(a, b) => {
            let a = ty_to_doc(a, interner, namer)?;
            let b = ty_to_doc(b, interner, namer)?;
            Ok(TyDoc::Fun(Box::new(a), Box::new(b)))
        }
        Ty::Con { module, name, args } => {
            let module = resolve_module(interner, module)?;
            let name = resolve(interner, *name)?;
            let mut doc_args = Vec::with_capacity(args.len());
            for a in args {
                doc_args.push(ty_to_doc(a, interner, namer)?);
            }
            Ok(TyDoc::Con {
                module,
                name,
                args: doc_args.into_boxed_slice(),
            })
        }
        Ty::Tuple(elems) => {
            let mut doc_elems = Vec::with_capacity(elems.len());
            for e in elems {
                doc_elems.push(ty_to_doc(e, interner, namer)?);
            }
            Ok(TyDoc::Tuple(doc_elems.into_boxed_slice()))
        }
        Ty::Record(fields, _tail) => {
            // Render in field-name order. The map is keyed by `Symbol`, so resolve
            // each name and sort the resulting pairs for a deterministic form.
            // `_tail` is intentionally not rendered here — open records read back
            // as closed in the resolved `Ty` form (the tail is a solver artefact
            // consumed by unify.rs, not by diagnostics).
            let mut entries: Vec<(Box<str>, TyDoc)> = Vec::with_capacity(fields.len());
            for (name, field_ty) in fields {
                entries.push((
                    resolve(interner, *name)?,
                    ty_to_doc(field_ty, interner, namer)?,
                ));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(TyDoc::Record(entries.into_boxed_slice()))
        }
    }
}

/// Render a written annotation type ([`canon::Type`]) into an owned [`TyDoc`].
///
/// Used by the `TooManyParameters` (IPE-T0004) producer to show the signature as
/// the user wrote it. A type variable keeps its **source** name (not a letter),
/// so the rendered annotation matches the program text. The canonical type is
/// bounded by the parser's nesting cap, so the recursion is bounded.
///
/// # Errors
/// [`Diagnostic::CompilerBug`] if a symbol cannot be resolved.
pub fn canon_type_to_doc(t: &canon::Type, interner: &Interner) -> DResult<TyDoc> {
    match t {
        canon::Type::Lambda(a, b) => {
            let a = canon_type_to_doc(a, interner)?;
            let b = canon_type_to_doc(b, interner)?;
            Ok(TyDoc::Fun(Box::new(a), Box::new(b)))
        }
        canon::Type::Var(s) => Ok(TyDoc::Var(resolve(interner, *s)?)),
        canon::Type::Wildcard => Ok(TyDoc::Var(canon::WILDCARD_SPELLING.into())),
        canon::Type::Con { home, name, args } => {
            let module = resolve_module(interner, home)?;
            let name = resolve(interner, *name)?;
            let mut doc_args = Vec::with_capacity(args.len());
            for a in args {
                doc_args.push(canon_type_to_doc(a, interner)?);
            }
            Ok(TyDoc::Con {
                module,
                name,
                args: doc_args.into_boxed_slice(),
            })
        }
        canon::Type::Unit => Ok(TyDoc::Unit),
        canon::Type::Tuple(elems) => {
            let mut doc_elems = Vec::with_capacity(elems.len());
            for e in elems {
                doc_elems.push(canon_type_to_doc(e, interner)?);
            }
            Ok(TyDoc::Tuple(doc_elems.into_boxed_slice()))
        }
        // Both the closed and the row-polymorphic record render as the same
        // field-name-ordered `TyDoc::Record`; the open tail carries no named
        // field, so — like the solved-type renderer above, which discards its
        // tail marker — it is not shown.
        canon::Type::Record(fields) | canon::Type::RecordOpen(_, fields) => {
            // Render in field-name order for a deterministic form, mirroring the
            // solved-type renderer above.
            let mut entries: Vec<(Box<str>, TyDoc)> = Vec::with_capacity(fields.len());
            for (name, field_ty) in fields {
                entries.push((
                    resolve(interner, *name)?,
                    canon_type_to_doc(field_ty, interner)?,
                ));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(TyDoc::Record(entries.into_boxed_slice()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_cycle_through_the_alphabet() {
        assert_eq!(&*letters(0), "a");
        assert_eq!(&*letters(25), "z");
        assert_eq!(&*letters(26), "a1");
        assert_eq!(&*letters(27), "b1");
    }

    #[test]
    fn namer_is_stable_per_id() {
        let mut n = VarNamer::new();
        let first = n.name(42);
        let second = n.name(7);
        let again = n.name(42);
        assert_eq!(&*first, "a");
        assert_eq!(&*second, "b");
        assert_eq!(first, again, "same id must reuse its name");
    }

    #[test]
    fn ty_to_doc_resolves_con_and_module() {
        let mut i = Interner::new();
        let (Ok(list), Ok(int)) = (i.intern("List"), i.intern("Int")) else {
            return;
        };
        let ty = Ty::Con {
            module: Vec::new(),
            name: list,
            args: vec![Ty::Con {
                module: Vec::new(),
                name: int,
                args: Vec::new(),
            }],
        };
        let mut namer = VarNamer::new();
        let Ok(doc) = ty_to_doc(&ty, &i, &mut namer) else {
            return;
        };
        assert_eq!(
            doc,
            TyDoc::Con {
                module: "".into(),
                name: "List".into(),
                args: Box::new([TyDoc::Con {
                    module: "".into(),
                    name: "Int".into(),
                    args: Box::new([]),
                }]),
            }
        );
    }
}
