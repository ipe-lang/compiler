//! Head-identity pairing of two constructor applications' children.
//!
//! Every structural walk that runs two type trees side by side pairs a
//! constructor's arguments through [`HeadIdentity::paired_args`] (any two
//! representations) or [`paired_ty_children`] (two [`Ty`]s), so no walk can
//! pair two distinct constructors that merely share an arity.

use core::array;
use core::iter::Zip;
use core::slice;

use ipe_intern::{Interner, Symbol};

use crate::ty::Ty;
use crate::unify::con_heads_compatible;

/// The lowering's verdict on whether one constructor under two homes emits one type.
///
/// The lowering is the only definition of emitted-type identity: a reserved
/// builtin lowers to one runtime type whatever home spells it, while a program
/// union lowers to an enum keyed by its exact home. Asking the lowering, rather
/// than re-deriving its dispatch, keeps coverage and emission from drifting.
pub trait EmittedHeads {
    /// Whether `name` over `args` lowers to one emitted type under `a_home` and under `b_home`.
    ///
    /// A side the lowering refuses answers `false`, so an unknown shape fails
    /// closed as "distinct".
    fn same_emitted_type(
        &self,
        a_home: &[Symbol],
        b_home: &[Symbol],
        name: Symbol,
        args: &[Ty],
    ) -> bool;
}

/// The rule that decides whether two constructor heads name one type constructor.
#[derive(Clone, Copy)]
pub enum HeadIdentity<'i> {
    /// The rule unification applies ([`con_heads_compatible`]).
    ///
    /// Names agree and homes agree, or one side is a builtin's empty home and
    /// the other its stdlib or reserved spelling. A walk over two types that
    /// inference unified uses this rule.
    Unified(&'i Interner),
    /// Names agree and both heads lower to one emitted type.
    ///
    /// A walk that predicts what the backend will match (a struct template
    /// against a use site) uses this rule. One home is one emitted type, since
    /// lowering is a function of home, name, and arguments; distinct homes
    /// defer to the lowering's own verdict ([`EmittedHeads`]).
    Emitted(&'i dyn EmittedHeads),
}

impl core::fmt::Debug for HeadIdentity<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unified(_) => "Unified",
            Self::Emitted(_) => "Emitted",
        })
    }
}

/// A constructor head and its argument list, in any type representation.
#[derive(Debug)]
pub struct ConHead<'a, T> {
    /// The defining module path; empty for a builtin.
    pub home: &'a [Symbol],
    /// The type constructor's name.
    pub name: Symbol,
    /// The applied arguments.
    pub args: &'a [T],
}

// Every field is a borrow or a `Symbol`, so a head copies whatever `T` is; a
// derive would demand `T: Copy`.
impl<T> Clone for ConHead<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for ConHead<'_, T> {}

/// The pairwise arguments of two constructor applications of one head.
pub type ArgPairs<'x, 'y, X, Y> = Zip<slice::Iter<'x, X>, slice::Iter<'y, Y>>;

impl HeadIdentity<'_> {
    /// Whether head `a_home.a_name` and head `b_home.b_name` over `b_args` name one constructor.
    #[must_use]
    pub fn same_head(
        self,
        a_home: &[Symbol],
        a_name: Symbol,
        b_home: &[Symbol],
        b_name: Symbol,
        b_args: &[Ty],
    ) -> bool {
        match self {
            Self::Unified(interner) => {
                con_heads_compatible(a_home, a_name, b_home, b_name, interner)
            }
            Self::Emitted(lowering) => {
                a_name == b_name
                    && (a_home == b_home
                        || lowering.same_emitted_type(a_home, b_home, b_name, b_args))
            }
        }
    }

    /// The argument pairs of `a` and `b` when they are one constructor at one arity, else `None`.
    ///
    /// `b` is the [`Ty`] side: under [`Self::Emitted`] both heads are lowered
    /// over its arguments.
    #[must_use]
    pub fn paired_args<'x, 'y, X>(
        self,
        a: ConHead<'x, X>,
        b: ConHead<'y, Ty>,
    ) -> Option<ArgPairs<'x, 'y, X, Ty>> {
        (a.args.len() == b.args.len() && self.same_head(a.home, a.name, b.home, b.name, b.args))
            .then(|| a.args.iter().zip(b.args))
    }
}

/// One pair of mirrored [`Ty`] children.
type TyPair<'a> = (&'a Ty, &'a Ty);

/// The positional child pairs of two same-headed [`Ty`] nodes.
///
/// Yields tuple elements or constructor arguments pairwise, or an arrow's
/// argument then result.
#[derive(Clone, Debug)]
pub struct TyPairs<'a> {
    seq: ArgPairs<'a, 'a, Ty, Ty>,
    slots: array::IntoIter<Option<TyPair<'a>>, 2>,
}

impl<'a> Iterator for TyPairs<'a> {
    type Item = TyPair<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.seq
            .next()
            .or_else(|| self.slots.by_ref().flatten().next())
    }
}

/// The child pairs of `a` and `b` when both nodes have one head under `heads`, else `None`.
///
/// An arrow pairs with an arrow, a tuple with a tuple of the same length, a
/// constructor with a constructor [`HeadIdentity::paired_args`] accepts. A
/// record (keyed by field, not position), a variable, unit, and every
/// mismatched pair yield `None`, so a caller that treats `None` as "no shared
/// shape" fails closed.
#[must_use]
pub fn paired_ty_children<'a>(
    a: &'a Ty,
    b: &'a Ty,
    heads: HeadIdentity<'_>,
) -> Option<TyPairs<'a>> {
    let empty: &[Ty] = &[];
    let seq_only = |seq| TyPairs {
        seq,
        slots: [None, None].into_iter(),
    };
    match a {
        Ty::Fun(xa, xr) => match b {
            Ty::Fun(ya, yr) => Some(TyPairs {
                seq: empty.iter().zip(empty),
                slots: [Some((&**xa, &**ya)), Some((&**xr, &**yr))].into_iter(),
            }),
            _ => None,
        },
        Ty::Tuple(xs) => match b {
            Ty::Tuple(ys) => (xs.len() == ys.len()).then(|| seq_only(xs.iter().zip(ys))),
            _ => None,
        },
        Ty::Con {
            module: xm,
            name: xn,
            args: xs,
        } => match b {
            Ty::Con {
                module: ym,
                name: yn,
                args: ys,
            } => heads
                .paired_args(
                    ConHead {
                        home: xm,
                        name: *xn,
                        args: xs,
                    },
                    ConHead {
                        home: ym,
                        name: *yn,
                        args: ys,
                    },
                )
                .map(seq_only),
            _ => None,
        },
        Ty::Var(_) | Ty::Wildcard | Ty::Unit | Ty::Record(..) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{ConHead, EmittedHeads, HeadIdentity, paired_ty_children};
    use crate::ty::Ty;
    use ipe_intern::{Interner, Symbol};

    struct Names {
        interner: Interner,
        ipe: Symbol,
        main: Symbol,
        lib: Symbol,
        list: Symbol,
        set: Symbol,
        web_route: Symbol,
        t: Symbol,
    }

    impl Names {
        fn new() -> Self {
            let mut interner = Interner::new();
            #[allow(clippy::expect_used)] // a fresh interner accepts these names
            let mut sym = |s: &str| interner.intern(s).expect("intern");
            let (ipe, main, lib, list, set, web_route, t) = (
                sym("Ipe"),
                sym("Main"),
                sym("Lib"),
                sym("List"),
                sym("Set"),
                sym("WebRoute"),
                sym("T"),
            );
            Self {
                interner,
                ipe,
                main,
                lib,
                list,
                set,
                web_route,
                t,
            }
        }
    }

    fn con(module: Vec<Symbol>, name: Symbol, args: Vec<Ty>) -> Ty {
        Ty::Con { module, name, args }
    }

    fn paired(a: &Ty, b: &Ty, heads: HeadIdentity<'_>) -> Option<usize> {
        paired_ty_children(a, b, heads).map(Iterator::count)
    }

    /// Same-named constructors of distinct user homes never pair, under either rule.
    #[test]
    fn distinct_user_homes_refuse() {
        let n = Names::new();
        let main_t = con(vec![n.main], n.t, vec![Ty::Unit]);
        let lib_t = con(vec![n.lib], n.t, vec![Ty::Unit]);
        assert_eq!(
            paired(&main_t, &lib_t, HeadIdentity::Emitted(&DistinctHomes)),
            None
        );
        assert_eq!(
            paired(&main_t, &lib_t, HeadIdentity::Unified(&n.interner)),
            None
        );
        assert_eq!(
            paired(&main_t, &main_t, HeadIdentity::Emitted(&DistinctHomes)),
            Some(1)
        );
    }

    /// A user-homed `Main.WebRoute` is not the empty-home builtin `WebRoute`; an `Ipe`-rooted spelling is.
    ///
    /// `WebRoute` is a builtin name user code may declare, so a same-named
    /// user type is a distinct constructor. A reserved name such as `List`
    /// never carries a user home: canon refuses its declaration.
    #[test]
    fn user_home_never_matches_empty_builtin_home() {
        let n = Names::new();
        let unified = HeadIdentity::Unified(&n.interner);
        let builtin = con(vec![], n.web_route, vec![Ty::Unit]);
        let user = con(vec![n.main], n.web_route, vec![Ty::Unit]);
        let stdlib = con(vec![n.ipe, n.web_route], n.web_route, vec![Ty::Unit]);
        assert_eq!(paired(&builtin, &user, unified), None);
        assert_eq!(paired(&user, &builtin, unified), None);
        assert_eq!(paired(&builtin, &stdlib, unified), Some(1));
        assert_eq!(
            paired(&builtin, &stdlib, HeadIdentity::Emitted(&DistinctHomes)),
            None
        );
    }

    /// Distinct names or arities never pair; tuples pair only at one length.
    #[test]
    fn distinct_names_arities_and_lengths_refuse() {
        let n = Names::new();
        let unified = HeadIdentity::Unified(&n.interner);
        let list = con(vec![], n.list, vec![Ty::Unit]);
        assert_eq!(
            paired(&list, &con(vec![], n.set, vec![Ty::Unit]), unified),
            None
        );
        assert_eq!(
            paired(
                &list,
                &con(vec![], n.list, vec![Ty::Unit, Ty::Unit]),
                unified
            ),
            None
        );
        let pair = Ty::Tuple(vec![Ty::Unit, Ty::Unit]);
        let triple = Ty::Tuple(vec![Ty::Unit, Ty::Unit, Ty::Unit]);
        assert_eq!(paired(&pair, &triple, unified), None);
        assert_eq!(paired(&pair, &pair, unified), Some(2));
        let args: [Ty; 1] = [Ty::Unit];
        let head = |args| ConHead {
            home: &[],
            name: n.list,
            args,
        };
        let arity_one: &[Ty] = &args;
        assert!(
            HeadIdentity::Emitted(&DistinctHomes)
                .paired_args(head(arity_one), head(arity_one))
                .is_some()
        );
        assert!(
            HeadIdentity::Emitted(&DistinctHomes)
                .paired_args(head(arity_one), head(&[]))
                .is_none()
        );
        assert!(
            HeadIdentity::Emitted(&HomeBlind(n.list))
                .paired_args(head(arity_one), head(&[]))
                .is_none(),
            "a home-blind lowering never pairs two arities"
        );
    }

    /// Distinct homes pair under the emitted rule exactly when the lowering emits one type for both.
    #[test]
    fn emitted_rule_defers_distinct_homes_to_the_lowering() {
        let n = Names::new();
        let builtin = con(vec![], n.web_route, vec![Ty::Unit]);
        let stdlib = con(vec![n.ipe, n.web_route], n.web_route, vec![Ty::Unit]);
        let blind = HomeBlind(n.web_route);
        assert_eq!(
            paired(&stdlib, &builtin, HeadIdentity::Emitted(&blind)),
            Some(1)
        );
        let main_t = con(vec![n.main], n.t, vec![Ty::Unit]);
        let lib_t = con(vec![n.lib], n.t, vec![Ty::Unit]);
        assert_eq!(
            paired(&main_t, &lib_t, HeadIdentity::Emitted(&blind)),
            None,
            "a name the lowering keys by home stays distinct across homes"
        );
        assert_eq!(
            paired(
                &stdlib,
                &con(vec![], n.list, vec![Ty::Unit]),
                HeadIdentity::Emitted(&blind)
            ),
            None,
            "distinct names never pair, whatever the lowering says of one"
        );
    }

    /// A lowering that emits a distinct type for every distinct home.
    struct DistinctHomes;

    impl EmittedHeads for DistinctHomes {
        fn same_emitted_type(&self, _: &[Symbol], _: &[Symbol], _: Symbol, _: &[Ty]) -> bool {
            false
        }
    }

    /// A lowering that emits one type for the named constructor whatever its home.
    struct HomeBlind(Symbol);

    impl EmittedHeads for HomeBlind {
        fn same_emitted_type(&self, _: &[Symbol], _: &[Symbol], name: Symbol, _: &[Ty]) -> bool {
            name == self.0
        }
    }
}
