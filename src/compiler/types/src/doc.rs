//! Owned, interner-free type rendering: build a [`TyDoc`] at the failure point.
//!
//! Parse-don't-validate: a [`TypeError`](ipe_diagnostics::TypeError) payload
//! carries an **already-resolved** [`TyDoc`], so the reporter never touches the
//! interner or the union-find arena. The producers in [`crate::unify`] /
//! [`crate::constrain`] call into here at the exact site a type fails to unify,
//! resolving every [`Symbol`] into an owned `Box<str>`.

use std::collections::{BTreeMap, BTreeSet};

use ipe_canon::ast as canon;
use ipe_diagnostics::{DResult, Diagnostic, TyDoc, TypeClass};
use ipe_intern::{Interner, Symbol};

use crate::ty::Ty;

/// What a rendering knows about a solver variable beyond its arena id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VarLabel {
    /// The variable still owes a named class and reads by the class stem.
    Class(TypeClass),
    /// The variable is the skolem of an annotation variable and reads by the
    /// spelling the user wrote.
    Annotation(Symbol),
}

/// A [`VarLabel`] with its annotation spelling already resolved.
enum ResolvedLabel {
    Class(TypeClass),
    Annotation(Box<str>),
}

/// Deterministic naming for type variables that survived solving.
///
/// A solved [`Ty::Var`] carries an opaque arena id, not a source name; rendering
/// it verbatim would leak an unstable integer. Instead each distinct id is
/// assigned a stable name in **first-seen order**, shared across the
/// expected/found pair of a single diagnostic so the same variable reads
/// identically on both sides. A variable standing for an annotation variable
/// reads by the user's spelling (`x`, then `x1` for a second distinct `x`); a
/// variable owing a [`TypeClass`] is named by the class stem (`number`,
/// `number1`, `comparable`, …); every other variable gets a letter (`a`, `b`,
/// …, `z`, `a1`, `b1`, …). No two ids share a name, and no minted name equals
/// an annotation spelling the same rendering prints.
#[derive(Default)]
pub struct VarNamer {
    map: BTreeMap<u32, Box<str>>,
    next: u32,
    labels: BTreeMap<u32, ResolvedLabel>,
    stem_next: BTreeMap<TypeClass, u32>,
    reserved: BTreeSet<Box<str>>,
    issued: BTreeSet<Box<str>>,
}

impl VarNamer {
    /// A fresh namer with no assignments.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
            next: 0,
            labels: BTreeMap::new(),
            stem_next: BTreeMap::new(),
            reserved: BTreeSet::new(),
            issued: BTreeSet::new(),
        }
    }

    /// A fresh namer that names each id in `labels` by its label.
    ///
    /// # Errors
    /// [`Diagnostic::CompilerBug`] if an annotation symbol cannot be resolved.
    pub fn with_labels(labels: BTreeMap<u32, VarLabel>, interner: &Interner) -> DResult<Self> {
        let mut namer = Self::new();
        for (id, label) in labels {
            let resolved = match label {
                VarLabel::Class(class) => ResolvedLabel::Class(class),
                VarLabel::Annotation(sym) => {
                    let spelling = resolve(interner, sym)?;
                    namer.reserved.insert(spelling.clone());
                    ResolvedLabel::Annotation(spelling)
                }
            };
            namer.labels.insert(id, resolved);
        }
        Ok(namer)
    }

    /// The stable name for arena id `id`, minting one on first sight.
    fn name(&mut self, id: u32) -> Box<str> {
        if let Some(existing) = self.map.get(&id) {
            return existing.clone();
        }
        let name = match self.labels.get(&id) {
            Some(ResolvedLabel::Annotation(spelling)) => {
                let spelling = spelling.clone();
                self.first_free(0, |k| suffixed(&spelling, k), |k| k == 0).1
            }
            Some(ResolvedLabel::Class(class)) => {
                let class = *class;
                let start = self.stem_next.get(&class).copied().unwrap_or(0);
                let (k, name) = self.first_free(start, |k| stem_name(class, k), |_| false);
                self.stem_next.insert(class, k.saturating_add(1));
                name
            }
            None => {
                let (k, name) = self.first_free(self.next, letters, |_| false);
                self.next = k.saturating_add(1);
                name
            }
        };
        self.issued.insert(name.clone());
        self.map.insert(id, name.clone());
        name
    }

    /// The first `candidate(k)`, `k >= start`, no other id holds.
    ///
    /// A candidate equal to an annotation spelling is taken unless
    /// `may_take_reserved(k)` (only an annotation variable's own bare spelling
    /// may). `candidate` is injective, so at most `issued + reserved` candidates
    /// are taken and the bounded walk always ends on a free one.
    fn first_free(
        &self,
        start: u32,
        candidate: impl Fn(u32) -> Box<str>,
        may_take_reserved: impl Fn(u32) -> bool,
    ) -> (u32, Box<str>) {
        let bound = self.issued.len().saturating_add(self.reserved.len());
        let mut k = start;
        let mut name = candidate(k);
        for _ in 0..bound {
            let taken = self.issued.contains(&name)
                || (!may_take_reserved(k) && self.reserved.contains(&name));
            if !taken {
                break;
            }
            k = k.saturating_add(1);
            name = candidate(k);
        }
        (k, name)
    }
}

/// `(x, 0) → x`, `(x, 1) → x1`, … — the `k`-th distinct variable spelled `x`.
fn suffixed(spelling: &str, k: u32) -> Box<str> {
    if k == 0 {
        spelling.into()
    } else {
        format!("{spelling}{k}").into_boxed_str()
    }
}

/// `(Number, 0) → number`, `(Number, 1) → number1`, … — the `k`-th distinct
/// variable owing `class`.
fn stem_name(class: TypeClass, k: u32) -> Box<str> {
    if k == 0 {
        class.stem().into()
    } else {
        format!("{}{k}", class.stem()).into_boxed_str()
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
    fn namer_names_a_class_owing_id_by_its_stem() {
        let labels = BTreeMap::from([
            (1, VarLabel::Class(TypeClass::Number)),
            (2, VarLabel::Class(TypeClass::Number)),
            (3, VarLabel::Class(TypeClass::Comparable)),
        ]);
        let Ok(mut n) = VarNamer::with_labels(labels, &Interner::new()) else {
            return;
        };
        assert_eq!(&*n.name(9), "a");
        assert_eq!(&*n.name(1), "number");
        assert_eq!(&*n.name(2), "number1");
        assert_eq!(&*n.name(3), "comparable");
        assert_eq!(&*n.name(1), "number", "same id must reuse its stem name");
        assert_eq!(&*n.name(8), "b", "a stem name must not consume a letter");
    }

    #[test]
    fn namer_names_an_annotation_id_by_its_spelling() {
        let mut i = Interner::new();
        let Ok(x) = i.intern("x") else {
            return;
        };
        let labels = BTreeMap::from([(5, VarLabel::Annotation(x))]);
        let Ok(mut n) = VarNamer::with_labels(labels, &i) else {
            return;
        };
        assert_eq!(&*n.name(5), "x");
        assert_eq!(&*n.name(5), "x", "same id must reuse its spelling");
    }

    #[test]
    fn two_annotation_ids_with_one_spelling_read_x_and_x1() {
        let mut i = Interner::new();
        let Ok(x) = i.intern("x") else {
            return;
        };
        let labels = BTreeMap::from([(5, VarLabel::Annotation(x)), (6, VarLabel::Annotation(x))]);
        let Ok(mut n) = VarNamer::with_labels(labels, &i) else {
            return;
        };
        assert_eq!(&*n.name(5), "x");
        assert_eq!(
            &*n.name(6),
            "x1",
            "a second distinct `x` must not print as `x`"
        );
    }

    #[test]
    fn a_suffixed_spelling_skips_another_annotation_spelling() {
        let mut i = Interner::new();
        let (Ok(x), Ok(x1)) = (i.intern("x"), i.intern("x1")) else {
            return;
        };
        let labels = BTreeMap::from([
            (5, VarLabel::Annotation(x)),
            (6, VarLabel::Annotation(x)),
            (7, VarLabel::Annotation(x1)),
        ]);
        let Ok(mut n) = VarNamer::with_labels(labels, &i) else {
            return;
        };
        assert_eq!(&*n.name(5), "x");
        assert_eq!(&*n.name(6), "x2", "`x1` is the user's own spelling");
        assert_eq!(&*n.name(7), "x1");
    }

    #[test]
    fn a_minted_letter_never_equals_an_annotation_spelling() {
        let mut i = Interner::new();
        let (Ok(a), Ok(c)) = (i.intern("a"), i.intern("c")) else {
            return;
        };
        let labels = BTreeMap::from([(1, VarLabel::Annotation(a)), (2, VarLabel::Annotation(c))]);
        let Ok(mut n) = VarNamer::with_labels(labels, &i) else {
            return;
        };
        assert_eq!(&*n.name(9), "b", "letter `a` is the user's spelling");
        assert_eq!(&*n.name(8), "d", "letter `c` is the user's spelling");
        assert_eq!(&*n.name(1), "a");
        assert_eq!(&*n.name(2), "c");
    }

    #[test]
    fn a_minted_stem_never_equals_an_annotation_spelling() {
        let mut i = Interner::new();
        let Ok(number) = i.intern("number") else {
            return;
        };
        let labels = BTreeMap::from([
            (1, VarLabel::Annotation(number)),
            (2, VarLabel::Class(TypeClass::Number)),
        ]);
        let Ok(mut n) = VarNamer::with_labels(labels, &i) else {
            return;
        };
        assert_eq!(&*n.name(2), "number1", "`number` is the user's spelling");
        assert_eq!(&*n.name(1), "number");
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
