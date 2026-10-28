//! The entry closure: the top-level defs of a linked program its entry can
//! reach, the set the emitted crate is cut down to.
//!
//! Lowering keeps only the functions reachable from the entry `main` plus the
//! functions the backend invokes with no call edge naming them
//! (`ipe_lower`'s dead-function elimination). The wasm gates judge exactly this
//! closure, computed here once over the canonical AST, so a server-only kernel
//! that sits in an imported module but is never reached is neither refused nor
//! emitted, and one that is reached is refused at `ipe` time.
//!
//! The closure is a superset of the lowered survivors by construction: the
//! seeds are the lowerer's seeds (its backend roots unconditionally), and every
//! lowered call edge comes from a canonical `VarTopLevel` reference. A program
//! whose entry is missing, or is not the linked module's own `main`, keeps every
//! def — the same fail-closed fallback the lowerer takes, where nothing is
//! pruned. The build re-judges the lowered survivors after lowering
//! (`target_gate::check_emitted_for_target`), so an edge the lowerer adds that
//! this closure does not model is still refused.

use std::collections::{HashMap, VecDeque};

use ipe_intern::{Interner, Symbol};

use crate::ast::{CaseBranch, Def, Expr, Expr_, LetBinding, Module};

/// The name of the program entry every reachability consumer seeds from.
pub const ENTRY_NAME: &str = "main";

/// The wasm-hydration island projection, called only by generated `hydrate`
/// glue. The lowerer's copy is asserted equal at build time.
pub const HYDRATION_PROJECTION_NAME: &str = "fromHydrationState";

/// The home of the compiled-source `Duration` accessor the `Http.withTimeout`
/// kernel's emitted code calls.
pub const DURATION_TO_MILLIS_HOME: [&str; 2] = ["Ipe", "Duration"];

/// The name of the compiled-source `Duration` accessor the `Http.withTimeout`
/// kernel's emitted code calls.
pub const DURATION_TO_MILLIS_NAME: &str = "toMillis";

/// The defs of a linked [`Module`] reachable from its entry, indexed by their
/// position in `Module::defs`, with the breadth-first parent of each so a
/// diagnostic can name the shortest chain that reaches it.
#[derive(Debug, Clone)]
pub struct EntryClosure {
    order: Vec<usize>,
    parent: Vec<Option<usize>>,
    reached: Vec<bool>,
}

impl EntryClosure {
    /// The entry closure of `linked`.
    ///
    /// Seeds: the last def named [`ENTRY_NAME`] when its home is
    /// `linked.name`, plus every hydration projection and the `Duration`
    /// accessor; otherwise every def. Edges: each `VarTopLevel` reference,
    /// visited in (module, name) order so the breadth-first parents, and the
    /// chains built from them, do not depend on hash order.
    #[must_use]
    pub fn of(linked: &Module, interner: &Interner) -> Self {
        let count = linked.defs.len();
        let mut closure = Self {
            order: Vec::with_capacity(count),
            parent: vec![None; count],
            reached: vec![false; count],
        };
        let mut queue: VecDeque<usize> = VecDeque::new();

        let entry = linked
            .defs
            .iter()
            .rposition(|def| interner.resolve(def.name().value) == Some(ENTRY_NAME));
        let entry_is_demanded = entry
            .and_then(|i| linked.defs.get(i))
            .is_some_and(|def| def.home() == linked.name.as_slice());
        match entry {
            Some(i) if entry_is_demanded => {
                closure.admit(i, None, &mut queue);
                for (j, def) in linked.defs.iter().enumerate() {
                    if is_backend_root(def, interner) {
                        closure.admit(j, None, &mut queue);
                    }
                }
            }
            Some(_) | None => {
                for j in 0..count {
                    closure.admit(j, None, &mut queue);
                }
            }
        }

        let mut by_name: HashMap<Symbol, Vec<usize>> = HashMap::new();
        for (i, def) in linked.defs.iter().enumerate() {
            by_name.entry(def.name().value).or_default().push(i);
        }

        while let Some(i) = queue.pop_front() {
            let Some(def) = linked.defs.get(i) else {
                continue;
            };
            let mut callees: Vec<usize> = Vec::new();
            walk_expr(def_body(def), &mut |e| {
                if let Expr_::VarTopLevel { module, name } = &e.value
                    && let Some(candidates) = by_name.get(name)
                {
                    callees.extend(candidates.iter().copied().filter(|&j| {
                        linked
                            .defs
                            .get(j)
                            .is_some_and(|callee| callee.home() == module.as_slice())
                    }));
                }
            });
            callees.sort_unstable();
            callees.dedup();
            callees.sort_by_cached_key(|&j| {
                linked.defs.get(j).map(|callee| {
                    (
                        module_display_name(callee.home(), interner),
                        interner.resolve(callee.name().value).unwrap_or("?"),
                    )
                })
            });
            for j in callees {
                closure.admit(j, Some(i), &mut queue);
            }
        }
        closure
    }

    /// Mark def `i` reached from `from` and queue it, once.
    fn admit(&mut self, i: usize, from: Option<usize>, queue: &mut VecDeque<usize>) {
        let Some(reached) = self.reached.get_mut(i) else {
            return;
        };
        if *reached {
            return;
        }
        *reached = true;
        if let Some(parent) = self.parent.get_mut(i) {
            *parent = from;
        }
        self.order.push(i);
        queue.push_back(i);
    }

    /// Whether def `i` of the linked module is in the closure.
    #[must_use]
    pub fn contains(&self, i: usize) -> bool {
        self.reached.get(i) == Some(&true)
    }

    /// The reached defs of `linked`, in `linked.defs` order.
    pub fn defs<'m>(&'m self, linked: &'m Module) -> impl Iterator<Item = &'m Def> + 'm {
        linked
            .defs
            .iter()
            .enumerate()
            .filter(|(i, _)| self.contains(*i))
            .map(|(_, def)| def)
    }

    /// The reached def indices in breadth-first order (seeds first).
    pub fn breadth_first(&self) -> impl Iterator<Item = usize> + '_ {
        self.order.iter().copied()
    }

    /// The def indices from a seed to `i`, seed first, along breadth-first
    /// parents: a shortest chain that reaches `i`.
    #[must_use]
    pub fn chain_to(&self, i: usize) -> Vec<usize> {
        let mut chain = Vec::new();
        let mut current = Some(i);
        // A parent chain visits each def at most once, so it is never longer
        // than the def count.
        for _ in 0..=self.parent.len() {
            let Some(at) = current else {
                break;
            };
            chain.push(at);
            current = self.parent.get(at).copied().flatten();
        }
        chain.reverse();
        chain
    }
}

/// Whether `def` is a function the backend invokes with no call edge naming it.
fn is_backend_root(def: &Def, interner: &Interner) -> bool {
    let name = interner.resolve(def.name().value);
    if name == Some(HYDRATION_PROJECTION_NAME) {
        return true;
    }
    let [want0, want1] = DURATION_TO_MILLIS_HOME;
    name == Some(DURATION_TO_MILLIS_NAME)
        && matches!(
            def.home(),
            [seg0, seg1] if interner.resolve(*seg0) == Some(want0)
                && interner.resolve(*seg1) == Some(want1)
        )
}

/// The body of `def`, regardless of typed/untyped shape.
pub(crate) const fn def_body(def: &Def) -> &Expr {
    match def {
        Def::Untyped { body, .. } | Def::Typed { body, .. } => body,
    }
}

/// A module path as its dotted source spelling.
pub(crate) fn module_display_name(path: &[Symbol], interner: &Interner) -> String {
    path.iter()
        .map(|s| interner.resolve(*s).unwrap_or("?"))
        .collect::<Vec<_>>()
        .join(".")
}

/// An iterative (heap-stack) traversal calling `visit` on every node of `root`,
/// so native call depth stays O(1) however deep the expression nests.
pub(crate) fn walk_expr<'e>(root: &'e Expr, visit: &mut impl FnMut(&'e Expr)) {
    let mut stack: Vec<&'e Expr> = vec![root];
    while let Some(e) = stack.pop() {
        visit(e);
        match &e.value {
            Expr_::VarLocal(_)
            | Expr_::VarTopLevel { .. }
            | Expr_::VarKernel { .. }
            | Expr_::VarCtor { .. }
            | Expr_::Int(_)
            | Expr_::Float(_)
            | Expr_::Str(_)
            | Expr_::CustomElementCtor(_)
            | Expr_::Char(_)
            | Expr_::Unit => {}
            Expr_::Call(f, args) => {
                stack.push(f);
                stack.extend(args.iter());
            }
            Expr_::ForeignCall { args, .. } => stack.extend(args.iter()),
            Expr_::Case(scrut, branches) => {
                stack.push(scrut);
                for CaseBranch { body, .. } in branches {
                    stack.push(body);
                }
            }
            Expr_::Lambda(_, body) => stack.push(body),
            Expr_::Binop { lhs, rhs, .. } => {
                stack.push(lhs);
                stack.push(rhs);
            }
            Expr_::Let(bindings, body) => {
                for LetBinding { body: b, .. } in bindings {
                    stack.push(b);
                }
                stack.push(body);
            }
            Expr_::If(arms, els) => {
                for (c, b) in arms {
                    stack.push(c);
                    stack.push(b);
                }
                stack.push(els);
            }
            Expr_::Tuple(items) | Expr_::List(items) => stack.extend(items.iter()),
            Expr_::Cons(h, t) => {
                stack.push(h);
                stack.push(t);
            }
            Expr_::Record(fields) => stack.extend(fields.iter().map(|(_, v)| v)),
            Expr_::Access(base, _) => stack.push(base),
            Expr_::Update(base, fields) => {
                stack.push(base);
                stack.extend(fields.iter().map(|(_, v)| v));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::{Located, Span};

    use super::*;

    #[allow(clippy::expect_used)] // test helper: an intern failure IS the failure
    fn sym(interner: &mut Interner, s: &str) -> Symbol {
        interner.intern(s).expect("intern must succeed in a test")
    }

    fn def(home: Vec<Symbol>, name: Symbol, body: Expr_) -> Def {
        Def::Untyped {
            home,
            name: Located::new(Span::DUMMY, name),
            patterns: Vec::new(),
            body: Located::new(Span::DUMMY, body),
        }
    }

    fn module(name: Vec<Symbol>, defs: Vec<Def>) -> Module {
        Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name,
            unions: Vec::new(),
            defs,
        }
    }

    fn call(module: Vec<Symbol>, name: Symbol) -> Expr_ {
        Expr_::Call(
            Box::new(Located::new(
                Span::DUMMY,
                Expr_::VarTopLevel { module, name },
            )),
            Vec::new(),
        )
    }

    /// `main -> helper` is reached; `unused` is not; the hydration projection
    /// and `Ipe.Duration.toMillis` are seeds though nothing calls them.
    #[test]
    fn closure_is_entry_reach_plus_backend_roots() {
        let mut interner = Interner::new();
        let main_mod = vec![sym(&mut interner, "Main")];
        let duration = vec![sym(&mut interner, "Ipe"), sym(&mut interner, "Duration")];
        let main_fn = sym(&mut interner, ENTRY_NAME);
        let helper = sym(&mut interner, "helper");
        let unused = sym(&mut interner, "unused");
        let hydrate = sym(&mut interner, HYDRATION_PROJECTION_NAME);
        let to_millis = sym(&mut interner, DURATION_TO_MILLIS_NAME);
        let linked = module(
            main_mod.clone(),
            vec![
                def(main_mod.clone(), unused, Expr_::Unit),
                def(main_mod.clone(), helper, Expr_::Unit),
                def(main_mod.clone(), main_fn, call(main_mod.clone(), helper)),
                def(main_mod, hydrate, Expr_::Unit),
                def(duration, to_millis, Expr_::Unit),
            ],
        );
        let closure = EntryClosure::of(&linked, &interner);
        assert!(
            !closure.contains(0),
            "an uncalled def is outside the closure"
        );
        assert!(closure.contains(1), "a def main calls is reached");
        assert!(closure.contains(2), "main is the seed");
        assert!(closure.contains(3), "the hydration projection is a seed");
        assert!(closure.contains(4), "Ipe.Duration.toMillis is a seed");
        assert_eq!(closure.chain_to(1), vec![2, 1]);
        assert!(
            !closure.contains(5),
            "an index past the defs is never reached"
        );
    }

    /// A same-named def in another module is not an edge target: edges match
    /// the referenced module too.
    #[test]
    fn edge_matches_home_not_just_name() {
        let mut interner = Interner::new();
        let main_mod = vec![sym(&mut interner, "Main")];
        let lib = vec![sym(&mut interner, "Lib")];
        let main_fn = sym(&mut interner, ENTRY_NAME);
        let helper = sym(&mut interner, "helper");
        let linked = module(
            main_mod.clone(),
            vec![
                def(lib, helper, Expr_::Unit),
                def(main_mod.clone(), helper, Expr_::Unit),
                def(main_mod.clone(), main_fn, call(main_mod, helper)),
            ],
        );
        let closure = EntryClosure::of(&linked, &interner);
        assert!(!closure.contains(0), "Lib.helper is never referenced");
        assert!(closure.contains(1), "Main.helper is referenced");
    }

    /// No `main`, or a `main` whose home is not the linked module, keeps every
    /// def: the lowerer prunes nothing in either case.
    #[test]
    fn missing_or_foreign_entry_keeps_every_def() {
        let mut interner = Interner::new();
        let main_mod = vec![sym(&mut interner, "Main")];
        let lib = vec![sym(&mut interner, "Lib")];
        let main_fn = sym(&mut interner, ENTRY_NAME);
        let helper = sym(&mut interner, "helper");

        let no_main = module(
            main_mod.clone(),
            vec![def(main_mod.clone(), helper, Expr_::Unit)],
        );
        assert!(EntryClosure::of(&no_main, &interner).contains(0));

        let foreign_main = module(
            main_mod.clone(),
            vec![
                def(main_mod, helper, Expr_::Unit),
                def(lib, main_fn, Expr_::Unit),
            ],
        );
        let closure = EntryClosure::of(&foreign_main, &interner);
        assert!(closure.contains(0), "a foreign main prunes nothing");
        assert!(closure.contains(1));
    }

    /// Mutual recursion terminates and each def is admitted once.
    #[test]
    fn cycle_is_admitted_once() {
        let mut interner = Interner::new();
        let main_mod = vec![sym(&mut interner, "Main")];
        let main_fn = sym(&mut interner, ENTRY_NAME);
        let ping = sym(&mut interner, "ping");
        let pong = sym(&mut interner, "pong");
        let linked = module(
            main_mod.clone(),
            vec![
                def(main_mod.clone(), ping, call(main_mod.clone(), pong)),
                def(main_mod.clone(), pong, call(main_mod.clone(), ping)),
                def(main_mod.clone(), main_fn, call(main_mod, ping)),
            ],
        );
        let closure = EntryClosure::of(&linked, &interner);
        assert_eq!(closure.breadth_first().collect::<Vec<_>>(), vec![2, 0, 1]);
        assert_eq!(closure.chain_to(1), vec![2, 0, 1]);
    }
}
