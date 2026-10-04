//! The binding ladder every bare module-level name goes through.
//!
//! A bare value, constructor, type or alias name is written only through
//! [`Scope::bind`] and read only through [`Scope::resolve`]. Both work over one
//! precedence ladder, [`Tier`]: local > explicit > open > ambient. An origin is
//! keyed by its DEFINING identity, never by the path that imported it, so one
//! definition reached through two imports is one origin.
//!
//! - The local and explicit tiers are eager: each holds at most one origin, so a
//!   second identity there has no representation and `bind` refuses it.
//! - The open tier is deferred: it holds every identity, and two or more are
//!   ambiguous only at a bare use no higher tier answers.
//! - The ambient tier answers only when the three tiers above it are empty; an
//!   ambiguous open tier never falls through to it.

use std::collections::{BTreeMap, BTreeSet};

use ipe_diagnostics::Span;
use ipe_intern::Symbol;
use ipe_syntax as src;

use crate::env::{CtorHome, CtorIdentity, VarHome};

/// A binding's precedence; the derived `Ord` is the ladder (a smaller tier wins).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tier {
    /// Declared in the module being canonicalised.
    Local,
    /// Named in an explicit `exposing (..)` list item.
    Explicit,
    /// Brought in by an open `exposing (..)` import.
    Open,
    /// A built-in in scope without any import (`Just`, `Ok`, `True`, …).
    Ambient,
}

/// The defining identity of a value: where it is declared, never who imported it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ValueIdentity {
    /// A top-level binding: its defining module and its name.
    TopLevel(Vec<Symbol>, Symbol),
    /// A registry-backed kernel, by its registry position.
    ///
    /// Two spellings of one kernel lower identically: the kernel's type comes
    /// from its scheme by id, never from the module that aliased it.
    Kernel(usize),
    /// A reachable stdlib member with no backing kernel: its module and name.
    ReservedKernel(Symbol, Symbol),
}

impl ValueIdentity {
    /// The defining identity of `name` bound at `home`.
    ///
    /// `None` for a lexical binder ([`VarHome::Local`]): a lexical binder lives
    /// in the per-scope table and never enters the module-level ladder.
    #[must_use]
    pub fn of(home: &VarHome, name: Symbol) -> Option<Self> {
        match home {
            VarHome::Local => None,
            VarHome::TopLevel(module) => Some(Self::TopLevel(module.clone(), name)),
            VarHome::Kernel(kernel, _, _) => Some(Self::Kernel(*kernel as usize)),
            VarHome::ReservedKernel { module, name } => Some(Self::ReservedKernel(*module, *name)),
        }
    }
}

/// The defining identity of a bare name, in one identity space per namespace.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Identity {
    /// A module-level value (a top-level binding, a kernel, a reserved member).
    Value(ValueIdentity),
    /// A constructor: its type's home and name.
    Ctor(CtorIdentity),
    /// The defining home of a union or an alias.
    Type(Vec<Symbol>),
}

/// One binding of a bare name.
#[derive(Clone, Debug)]
pub struct Origin<T> {
    /// What the name resolves to.
    pub target: T,
    /// The definition the binding reaches.
    pub identity: Identity,
    /// The importing module paths that brought it in; empty for local and
    /// ambient bindings. Read only to name modules in a diagnostic.
    pub importers: BTreeSet<Vec<Symbol>>,
    /// The span of the binding that introduced it (a declaration or an import).
    pub span: Span,
}

/// The bindings of one bare name, one slot per tier.
#[derive(Clone, Debug)]
struct Ladder<T> {
    local: Option<Origin<T>>,
    explicit: Option<Origin<T>>,
    open: BTreeMap<Identity, Origin<T>>,
    ambient: Option<Origin<T>>,
}

impl<T> Default for Ladder<T> {
    fn default() -> Self {
        Self {
            local: None,
            explicit: None,
            open: BTreeMap::new(),
            ambient: None,
        }
    }
}

/// The answer to a bare-name read, total by construction.
#[derive(Debug)]
pub enum Resolved<'a, T> {
    /// Exactly one binding answers, from the given tier.
    Found(&'a Origin<T>, Tier),
    /// Two or more open-import identities answer and no higher tier shadows them.
    Ambiguous {
        /// Every importing module path that brought one of the identities in.
        importers: BTreeSet<Vec<Symbol>>,
    },
    /// No tier binds the name.
    Missing,
}

/// Why [`Scope::bind`] refused a binding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Clash {
    /// A second identity in an eager tier, or a second ambient install.
    SameTier {
        /// The span of the binding already in that tier.
        first: Span,
    },
    /// A local declaration and an explicit import spell the same name.
    LocalOverExplicit {
        /// The span of the local declaration.
        local: Span,
        /// The span of the explicit import item.
        import: Span,
    },
}

/// The bare names of one namespace, each with its ladder.
#[derive(Clone, Debug)]
pub struct Scope<T> {
    by_name: BTreeMap<Symbol, Ladder<T>>,
}

impl<T> Default for Scope<T> {
    fn default() -> Self {
        Self {
            by_name: BTreeMap::new(),
        }
    }
}

impl<T> Scope<T> {
    /// Bind `name` at `tier`, refusing a second identity in an eager tier.
    ///
    /// - The same identity bound again in the explicit or open tier is one
    ///   origin: the importer is added.
    /// - A local declaration and an explicit import of the same spelling are
    ///   refused in either order, whatever their identities.
    /// - The open tier never refuses.
    ///
    /// # Errors
    /// [`Clash::SameTier`] for a second binding in the local or ambient tier or a
    /// second identity in the explicit tier; [`Clash::LocalOverExplicit`] for a
    /// local declaration against an explicit import.
    pub fn bind(&mut self, name: Symbol, tier: Tier, origin: Origin<T>) -> Result<(), Clash> {
        let ladder = self.by_name.entry(name).or_default();
        match tier {
            Tier::Local => {
                if let Some(first) = &ladder.local {
                    return Err(Clash::SameTier { first: first.span });
                }
                if let Some(import) = &ladder.explicit {
                    return Err(Clash::LocalOverExplicit {
                        local: origin.span,
                        import: import.span,
                    });
                }
                ladder.local = Some(origin);
            }
            Tier::Explicit => {
                if let Some(local) = &ladder.local {
                    return Err(Clash::LocalOverExplicit {
                        local: local.span,
                        import: origin.span,
                    });
                }
                match &mut ladder.explicit {
                    Some(prior) if prior.identity == origin.identity => {
                        prior.importers.extend(origin.importers);
                    }
                    Some(prior) => return Err(Clash::SameTier { first: prior.span }),
                    None => ladder.explicit = Some(origin),
                }
            }
            Tier::Open => match ladder.open.get_mut(&origin.identity) {
                Some(prior) => prior.importers.extend(origin.importers),
                None => {
                    ladder.open.insert(origin.identity.clone(), origin);
                }
            },
            Tier::Ambient => {
                if let Some(first) = &ladder.ambient {
                    return Err(Clash::SameTier { first: first.span });
                }
                ladder.ambient = Some(origin);
            }
        }
        Ok(())
    }

    /// Read `name` from the first non-empty tier of its ladder.
    #[must_use]
    pub fn resolve(&self, name: Symbol) -> Resolved<'_, T> {
        let Some(ladder) = self.by_name.get(&name) else {
            return Resolved::Missing;
        };
        if let Some(origin) = &ladder.local {
            return Resolved::Found(origin, Tier::Local);
        }
        if let Some(origin) = &ladder.explicit {
            return Resolved::Found(origin, Tier::Explicit);
        }
        let mut open = ladder.open.values();
        match (open.next(), open.next()) {
            (Some(only), None) => return Resolved::Found(only, Tier::Open),
            (Some(_), Some(_)) => {
                return Resolved::Ambiguous {
                    importers: ladder
                        .open
                        .values()
                        .flat_map(|origin| origin.importers.iter().cloned())
                        .collect(),
                };
            }
            (None, _) => {}
        }
        ladder.ambient.as_ref().map_or(Resolved::Missing, |origin| {
            Resolved::Found(origin, Tier::Ambient)
        })
    }

    /// Whether `name` is bound in the local or explicit tier.
    #[must_use]
    pub fn eager_bound(&self, name: Symbol) -> bool {
        self.by_name
            .get(&name)
            .is_some_and(|ladder| ladder.local.is_some() || ladder.explicit.is_some())
    }

    /// Every bound name whose bindings satisfy `keep`, in symbol order.
    ///
    /// The suggestion pools of the not-found diagnostics read it.
    pub fn names_where<'a>(
        &'a self,
        mut keep: impl FnMut(&T) -> bool + 'a,
    ) -> impl Iterator<Item = Symbol> + 'a {
        self.by_name.iter().filter_map(move |(&name, ladder)| {
            let any = ladder
                .local
                .iter()
                .chain(&ladder.explicit)
                .chain(ladder.open.values())
                .chain(&ladder.ambient)
                .any(|origin| keep(&origin.target));
            any.then_some(name)
        })
    }

    /// Every bound name, in symbol order.
    pub fn names(&self) -> impl Iterator<Item = Symbol> + '_ {
        self.by_name.keys().copied()
    }

    /// Every local-tier binding, in symbol order.
    pub fn locals(&self) -> impl Iterator<Item = (Symbol, &Origin<T>)> + '_ {
        self.by_name
            .iter()
            .filter_map(|(&name, ladder)| ladder.local.as_ref().map(|origin| (name, origin)))
    }
}

/// What a bare name in expression or pattern position resolves to.
///
/// A constructor and an uppercase value (a record alias's auto-constructor)
/// share expression position, so they share one ladder.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExprTarget {
    /// A union constructor.
    Ctor(CtorHome),
    /// A module-level value.
    Value(VarHome),
}

/// A `type alias` in scope, awaiting expansion at its use sites.
///
/// A local alias keeps its source body and expands in this module's own scope;
/// an imported alias arrives already resolved in its defining module's scope, so
/// no importer ever re-resolves another module's alias source text.
#[derive(Clone, Debug)]
pub enum AliasBody {
    /// Declared in the module being canonicalised: its type parameters in source
    /// order and its source body.
    Local {
        params: Vec<Symbol>,
        body: src::TypeAnnotation,
    },
    /// Exported by a dependency, its body canonical in the dependency's scope.
    Imported(crate::ExportedAlias),
}

/// What a bare name in type position resolves to.
#[derive(Clone, Debug)]
pub enum TypeTarget {
    /// A union (or a carrier type) declared at the given home.
    Union(Vec<Symbol>),
    /// A type alias.
    Alias(AliasBody),
}

/// The two module-level bare-name namespaces of the module being canonicalised.
#[derive(Clone, Debug, Default)]
pub struct ModuleScope {
    /// Values and constructors.
    pub expr: Scope<ExprTarget>,
    /// Unions and aliases.
    pub ty: Scope<TypeTarget>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ipe_diagnostics::Span;
    use ipe_intern::{Interner, Symbol};

    use super::{Clash, Identity, Origin, Resolved, Scope, Tier, ValueIdentity};

    /// Interned `(name, module A, module B)` symbols.
    #[allow(clippy::expect_used)] // interning a short literal never fails
    fn symbols() -> (Symbol, Symbol, Symbol) {
        let mut interner = Interner::new();
        let name = interner.intern("x").expect("interns");
        let a = interner.intern("A").expect("interns");
        let b = interner.intern("B").expect("interns");
        (name, a, b)
    }

    /// A binding of `x` defined in `home`, imported through `importer`, at
    /// byte `at`.
    fn origin(name: Symbol, home: Symbol, importer: Option<Symbol>, at: u32) -> Origin<u8> {
        Origin {
            target: 0,
            identity: Identity::Value(ValueIdentity::TopLevel(vec![home], name)),
            importers: importer.map(|i| vec![i]).into_iter().collect(),
            span: Span { lo: at, hi: at + 1 },
        }
    }

    #[test]
    fn two_explicit_identities_are_a_same_tier_clash() {
        let (x, a, b) = symbols();
        let mut scope = Scope::default();
        assert_eq!(
            scope.bind(x, Tier::Explicit, origin(x, a, Some(a), 1)),
            Ok(())
        );
        assert_eq!(
            scope.bind(x, Tier::Explicit, origin(x, b, Some(b), 2)),
            Err(Clash::SameTier {
                first: Span { lo: 1, hi: 2 }
            })
        );
    }

    #[test]
    fn one_explicit_identity_twice_is_one_origin() {
        let (x, a, b) = symbols();
        let mut scope = Scope::default();
        assert_eq!(
            scope.bind(x, Tier::Explicit, origin(x, a, Some(a), 1)),
            Ok(())
        );
        assert_eq!(
            scope.bind(x, Tier::Explicit, origin(x, a, Some(b), 2)),
            Ok(())
        );
        let importers = match scope.resolve(x) {
            Resolved::Found(found, Tier::Explicit) => Some(found.importers.clone()),
            Resolved::Found(..) | Resolved::Ambiguous { .. } | Resolved::Missing => None,
        };
        assert_eq!(importers, Some(BTreeSet::from([vec![a], vec![b]])));
    }

    #[test]
    fn a_local_and_an_explicit_binding_clash_in_either_order() {
        let (x, a, b) = symbols();
        let mut scope = Scope::default();
        assert_eq!(
            scope.bind(x, Tier::Explicit, origin(x, a, Some(a), 1)),
            Ok(())
        );
        assert_eq!(
            scope.bind(x, Tier::Local, origin(x, b, None, 5)),
            Err(Clash::LocalOverExplicit {
                local: Span { lo: 5, hi: 6 },
                import: Span { lo: 1, hi: 2 },
            })
        );

        let mut scope = Scope::default();
        assert_eq!(scope.bind(x, Tier::Local, origin(x, b, None, 5)), Ok(()));
        assert_eq!(
            scope.bind(x, Tier::Explicit, origin(x, a, Some(a), 1)),
            Err(Clash::LocalOverExplicit {
                local: Span { lo: 5, hi: 6 },
                import: Span { lo: 1, hi: 2 },
            })
        );
    }

    #[test]
    fn two_open_identities_never_refuse_and_are_ambiguous_at_a_read() {
        let (x, a, b) = symbols();
        let mut scope = Scope::default();
        assert_eq!(scope.bind(x, Tier::Open, origin(x, a, Some(a), 1)), Ok(()));
        assert_eq!(scope.bind(x, Tier::Open, origin(x, b, Some(b), 2)), Ok(()));
        assert_eq!(scope.bind(x, Tier::Ambient, origin(x, b, None, 0)), Ok(()));
        let importers = match scope.resolve(x) {
            Resolved::Ambiguous { importers } => Some(importers),
            Resolved::Found(..) | Resolved::Missing => None,
        };
        assert_eq!(importers, Some(BTreeSet::from([vec![a], vec![b]])));
    }

    #[test]
    fn a_second_ambient_install_is_a_same_tier_clash() {
        let (x, a, b) = symbols();
        let mut scope = Scope::default();
        assert_eq!(scope.bind(x, Tier::Ambient, origin(x, a, None, 1)), Ok(()));
        assert_eq!(
            scope.bind(x, Tier::Ambient, origin(x, b, None, 2)),
            Err(Clash::SameTier {
                first: Span { lo: 1, hi: 2 }
            })
        );
    }

    #[test]
    fn a_higher_tier_shadows_every_lower_one() {
        let (x, a, b) = symbols();
        let mut scope = Scope::default();
        assert_eq!(scope.bind(x, Tier::Ambient, origin(x, a, None, 0)), Ok(()));
        assert_eq!(scope.bind(x, Tier::Open, origin(x, a, Some(a), 1)), Ok(()));
        assert_eq!(scope.bind(x, Tier::Open, origin(x, b, Some(b), 2)), Ok(()));
        assert_eq!(
            scope.bind(x, Tier::Explicit, origin(x, b, Some(b), 3)),
            Ok(())
        );
        assert!(matches!(
            scope.resolve(x),
            Resolved::Found(found, Tier::Explicit) if found.span.lo == 3
        ));
    }
}
