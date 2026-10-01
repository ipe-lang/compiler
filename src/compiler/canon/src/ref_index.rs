//! Resolver-accurate reference index: for each defined symbol `(module, name)`,
//! the list of every use site with its source span and containing module.
//!
//! # Resolver accuracy
//!
//! The index is built from the canonical AST produced by the resolver —
//! specifically from [`ast::Expr_::VarTopLevel`] and [`ast::Pattern_::PCtor`]
//! nodes, which carry fully-resolved `(module, name)` pairs. Because the
//! resolver already distinguished local bindings (shadowing) from top-level
//! imports and same-named symbols in different modules before producing those
//! nodes, the index inherits that accuracy for free:
//!
//! * A local binding that **shadows** an import does NOT produce a
//!   [`ast::Expr_::VarTopLevel`] node — the resolver emits
//!   [`ast::Expr_::VarLocal`] instead. Shadowed names are invisible to this
//!   index without any extra filtering.
//! * A same-named symbol from a **different module** has a different `module`
//!   vector in its [`ast::Expr_::VarTopLevel`] node, so it is stored under a
//!   different [`SymbolKey`] and never conflated.
//!
//! # What counts as a use site
//!
//! * **Qualified references** (`M.name`, alias-resolved by the canonicaliser to
//!   `VarTopLevel { module: actual_module, name }`) — captured.
//! * **Unqualified in-scope references** (a name exposed without qualification,
//!   also resolved to `VarTopLevel`) — captured.
//! * **Constructor patterns** (`PCtor { home, name, … }`) — captured via the
//!   pattern walker.
//! * **Local bindings** — NOT captured; they are `VarLocal` after resolution.
//! * **Record-field labels** — NOT captured; field names are labels, not
//!   resolvable symbol references.
//!
//! # Building the index
//!
//! Call [`ReferenceIndex::build`] with a slice of `(&Module, containing_module_path)`
//! pairs — one entry per module in the program's resolved module graph. The
//! `containing_module_path` is the path under which the referencing module's
//! definitions are stored (usually `module.name`; callers that rename or merge
//! modules may pass a different path).
//!
//! # Querying
//!
//! Call [`ReferenceIndex::references_of`] with the defining module's path and
//! the symbol name; it returns the (possibly empty) slice of [`Reference`]
//! values.

use std::collections::BTreeMap;

use ipe_diagnostics::Span;
use ipe_intern::Symbol;

use crate::ast::{CaseBranch, Def, Expr, Expr_, LetBinding, Module, Pattern, Pattern_};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A use site: a span in source and the module the reference lives in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reference {
    /// Byte-range of the reference token in the containing module's source.
    pub span: Span,
    /// Module path of the definition that CONTAINS this reference
    /// (i.e. the referencing module, not the defining module).
    pub in_module: Vec<Symbol>,
}

/// Key that identifies a defined symbol: its owning module path and its name.
///
/// `module` is the dotted segment vector of the module that DEFINES the symbol
/// (e.g. `[Lib, Utils]` for `Lib.Utils.helper`). `name` is the symbol's
/// unqualified identifier.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SymbolKey {
    /// Module path of the defining module, in segment order.
    pub module: Vec<Symbol>,
    /// The unqualified symbol name within that module.
    pub name: Symbol,
}

/// Resolver-accurate reference index.
///
/// Maps every `(defining_module, name)` pair to its use sites across all
/// modules in the resolved program graph.
#[derive(Clone, Debug, Default)]
pub struct ReferenceIndex {
    map: BTreeMap<SymbolKey, Vec<Reference>>,
}

impl ReferenceIndex {
    /// Build the index from a resolved module graph.
    ///
    /// `modules` is a slice of `(module, containing_path)` pairs. For a
    /// single-compilation unit the `containing_path` is usually `module.name`;
    /// after `link::link` merges modules the caller may supply the merged
    /// module's path instead. The index stores the supplied path in each
    /// [`Reference::in_module`] field so callers can round-trip to the source
    /// file.
    #[must_use]
    pub fn build(modules: &[(&Module, &[Symbol])]) -> Self {
        let mut map: BTreeMap<SymbolKey, Vec<Reference>> = BTreeMap::new();
        for (module, containing_path) in modules {
            collect_module(&mut map, module, containing_path);
        }
        Self { map }
    }

    /// All use sites of the symbol `(module_path, name)` across the index.
    ///
    /// Returns an empty slice when the symbol has no recorded references
    /// (defined but never used, or not present in the indexed modules).
    #[must_use]
    pub fn references_of(&self, module: &[Symbol], name: Symbol) -> &[Reference] {
        let key = SymbolKey {
            module: module.to_owned(),
            name,
        };
        self.map.get(&key).map_or(&[], Vec::as_slice)
    }
}

// ---------------------------------------------------------------------------
// Module collector
// ---------------------------------------------------------------------------

fn collect_module(
    map: &mut BTreeMap<SymbolKey, Vec<Reference>>,
    module: &Module,
    containing_path: &[Symbol],
) {
    for def in &module.defs {
        let body = match def {
            Def::Untyped { body, .. } | Def::Typed { body, .. } => body,
        };
        collect_expr(map, body, containing_path);
    }
}

// ---------------------------------------------------------------------------
// Expression walker
// ---------------------------------------------------------------------------

fn collect_expr(map: &mut BTreeMap<SymbolKey, Vec<Reference>>, expr: &Expr, containing: &[Symbol]) {
    match &expr.value {
        // Cross-module top-level reference — this is the primary hit kind.
        Expr_::VarTopLevel { module, name } => {
            push_ref(map, module, *name, expr.span, containing);
        }

        // Constructor used as a value (e.g. `Just 1`, `Ok x`).
        Expr_::VarCtor { home, name, .. } => {
            push_ref(map, home, *name, expr.span, containing);
        }

        // Locals (shadowed imports resolve here), kernels, and literals
        // carry no cross-module references.
        Expr_::VarLocal(_)
        | Expr_::VarKernel { .. }
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::Char(_)
        | Expr_::CustomElementCtor(_)
        | Expr_::Unit => {}

        Expr_::Call(f, args) => {
            collect_expr(map, f, containing);
            for a in args {
                collect_expr(map, a, containing);
            }
        }

        Expr_::ForeignCall { args, .. } => {
            for a in args {
                collect_expr(map, a, containing);
            }
        }

        Expr_::Case(scrutinee, branches) => {
            collect_expr(map, scrutinee, containing);
            for CaseBranch { pat, body } in branches {
                collect_pattern(map, pat, containing);
                collect_expr(map, body, containing);
            }
        }

        Expr_::Lambda(params, body) => {
            for p in params {
                collect_pattern(map, p, containing);
            }
            collect_expr(map, body, containing);
        }

        Expr_::Binop { lhs, rhs, .. } => {
            collect_expr(map, lhs, containing);
            collect_expr(map, rhs, containing);
        }

        Expr_::Let(bindings, body) => {
            for LetBinding { pat, body: bval } in bindings {
                collect_pattern(map, pat, containing);
                collect_expr(map, bval, containing);
            }
            collect_expr(map, body, containing);
        }

        Expr_::If(branches, else_) => {
            for (cond, then_) in branches {
                collect_expr(map, cond, containing);
                collect_expr(map, then_, containing);
            }
            collect_expr(map, else_, containing);
        }

        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for e in elems {
                collect_expr(map, e, containing);
            }
        }

        Expr_::Cons(h, t) => {
            collect_expr(map, h, containing);
            collect_expr(map, t, containing);
        }

        Expr_::Record(fields) => {
            for (_, v) in fields {
                collect_expr(map, v, containing);
            }
        }

        // Field label (`.field`) is NOT a resolved symbol reference.
        Expr_::Access(rec, _field) => {
            collect_expr(map, rec, containing);
        }

        Expr_::Update(base, fields) => {
            // The base record expression is walked: while a record update
            // syntactically requires an in-scope variable, the canonicalised
            // base is a full `Expr` that may resolve to `VarTopLevel` when the
            // record comes from an imported module.
            collect_expr(map, base, containing);
            for (_, v) in fields {
                collect_expr(map, v, containing);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pattern walker
// ---------------------------------------------------------------------------

fn collect_pattern(
    map: &mut BTreeMap<SymbolKey, Vec<Reference>>,
    pat: &Pattern,
    containing: &[Symbol],
) {
    match &pat.value {
        Pattern_::PCtor {
            home, name, args, ..
        } => {
            push_ref(map, home, *name, pat.span, containing);
            for a in args {
                collect_pattern(map, a, containing);
            }
        }
        Pattern_::PTuple(elems) | Pattern_::PList(elems) => {
            for e in elems {
                collect_pattern(map, e, containing);
            }
        }
        Pattern_::PAlias(inner, _) => {
            collect_pattern(map, inner, containing);
        }
        Pattern_::PCons(h, t) => {
            collect_pattern(map, h, containing);
            collect_pattern(map, t, containing);
        }
        Pattern_::POr(alts) => {
            for a in alts {
                collect_pattern(map, a, containing);
            }
        }
        // PVar, PAnything, PDebugAnything, PUnit, PRecord, PInt, PBool, PChar,
        // PStr — no cross-module refs.
        Pattern_::PVar(_)
        | Pattern_::PAnything
        | Pattern_::PDebugAnything
        | Pattern_::PUnit
        | Pattern_::PRecord(_)
        | Pattern_::PInt(_)
        | Pattern_::PBool(_)
        | Pattern_::PChar(_)
        | Pattern_::PStr(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn push_ref(
    map: &mut BTreeMap<SymbolKey, Vec<Reference>>,
    module: &[Symbol],
    name: Symbol,
    span: Span,
    containing: &[Symbol],
) {
    let key = SymbolKey {
        module: module.to_owned(),
        name,
    };
    map.entry(key).or_default().push(Reference {
        span,
        in_module: containing.to_owned(),
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Resolver-accuracy tests for [`ReferenceIndex`].
    //!
    //! The fixture is built directly from canonical AST nodes (no parse
    //! round-trip needed) so the tests are fast and deterministic.
    //!
    //! Scenario: three modules `Lib`, `Shadow`, `Other`.
    //!
    //! * `Lib` defines `helper`.
    //! * `Main` references `Lib.helper` three ways:
    //!     1. qualified (`VarTopLevel { module: [Lib], name: helper }`)
    //!     2. alias-resolved (also `VarTopLevel { module: [Lib], name: helper }`)
    //!     3. unqualified in-scope (also `VarTopLevel`)
    //! * `Shadow` defines a LOCAL `helper` that SHADOWS the import from `Lib`.
    //!   Inside `Shadow`, `helper` resolves as `VarLocal` — no hit expected.
    //! * `Other` defines its OWN `helper` (`VarTopLevel { module: [Other], name: helper }`).
    //!   That must NOT be conflated with `Lib.helper`.

    use std::collections::BTreeSet;

    use ipe_diagnostics::{Located, Span};
    use ipe_intern::{Interner, Symbol};

    use crate::ast::{CaseBranch, Def, Expr, Expr_, Module, Pattern, Pattern_};

    use super::ReferenceIndex;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn sym(interner: &mut Interner, s: &str) -> Symbol {
        interner
            .intern(s)
            .expect("intern should not exhaust in test")
    }

    fn loc_sym(interner: &mut Interner, s: &str) -> Located<Symbol> {
        Located::new(Span::new(0, 0), sym(interner, s))
    }

    fn span(lo: u32, hi: u32) -> Span {
        Span::new(lo, hi)
    }

    fn expr(span_: Span, value: Expr_) -> Expr {
        Located::new(span_, value)
    }

    fn pat(span_: Span, value: Pattern_) -> Pattern {
        Located::new(span_, value)
    }

    /// Build a minimal `Module` with no unions and the given defs.
    fn module(name: Vec<Symbol>, defs: Vec<Def>) -> Module {
        Module {
            name,
            unions: vec![],
            defs,
            imports_unsafe_submodule: false,
            imported_web_capabilities: BTreeSet::new(),
        }
    }

    /// Build an `Untyped` def with the given body and no patterns.
    fn untyped_def(name: Located<Symbol>, home: Vec<Symbol>, body: Expr) -> Def {
        Def::Untyped {
            home,
            name,
            patterns: vec![],
            body,
        }
    }

    // ------------------------------------------------------------------
    // Fixture construction
    // ------------------------------------------------------------------

    /// Fixture:
    ///
    /// * `lib_mod`   — `Lib` module; defines `helper` (no body refs to others).
    /// * `main_mod` — `Main` module; three defs each referencing `Lib.helper`
    ///   via resolved `VarTopLevel`.
    /// * `shadow_mod` — `Shadow` module; one def where `helper` is a `VarLocal`
    ///   (shadowed — must NOT appear in index for `Lib.helper`).
    /// * `other_mod` — `Other` module; one def referencing `Other.helper`
    ///   (different module — must NOT be conflated with `Lib`).
    #[allow(clippy::too_many_lines)]
    fn build_fixture(interner: &mut Interner) -> (Module, Module, Module, Module, Symbol) {
        let lib_sym = sym(interner, "Lib");
        let main_sym = sym(interner, "Main");
        let shadow_sym = sym(interner, "Shadow");
        let other_sym = sym(interner, "Other");
        let helper_sym = sym(interner, "helper");
        let f_sym = sym(interner, "f");
        let g_sym = sym(interner, "g");
        let h_sym = sym(interner, "h");
        let local_sym = sym(interner, "local_helper");

        // ---- Lib: defines `helper`, body is just Unit (no outgoing refs).
        let lib_mod = module(
            vec![lib_sym],
            vec![untyped_def(
                loc_sym(interner, "helper"),
                vec![lib_sym],
                expr(span(10, 16), Expr_::Unit),
            )],
        );

        // ---- Main: three defs each referencing Lib.helper at distinct spans.
        //
        // def f = Lib.helper          (qualified, span 100-110)
        // def g = Lib.helper          (alias-resolved, same resolved node, span 200-210)
        // def h = Lib.helper          (unqualified in-scope, same resolved node, span 300-310)
        //
        // All three produce `VarTopLevel { module: [Lib], name: helper }` because
        // the resolver already resolved the qualifier / alias / unqualified name.
        let ref1 = expr(
            span(100, 110),
            Expr_::VarTopLevel {
                module: vec![lib_sym],
                name: helper_sym,
            },
        );
        let ref2 = expr(
            span(200, 210),
            Expr_::VarTopLevel {
                module: vec![lib_sym],
                name: helper_sym,
            },
        );
        let ref3 = expr(
            span(300, 310),
            Expr_::VarTopLevel {
                module: vec![lib_sym],
                name: helper_sym,
            },
        );

        let main_mod = module(
            vec![main_sym],
            vec![
                untyped_def(Located::new(span(90, 91), f_sym), vec![main_sym], ref1),
                untyped_def(Located::new(span(190, 191), g_sym), vec![main_sym], ref2),
                untyped_def(Located::new(span(290, 291), h_sym), vec![main_sym], ref3),
            ],
        );

        // ---- Shadow: local `helper` binding SHADOWS the Lib import.
        //
        // Inside the resolver, `helper` resolves as VarLocal(helper_sym) — NOT
        // VarTopLevel. The index must NOT record this as a hit for Lib.helper.
        let shadow_mod = module(
            vec![shadow_sym],
            vec![untyped_def(
                Located::new(span(400, 401), local_sym),
                vec![shadow_sym],
                expr(span(410, 416), Expr_::VarLocal(helper_sym)),
            )],
        );

        // ---- Other: its own `helper` symbol (different module).
        //
        // VarTopLevel { module: [Other], name: helper } — a different SymbolKey.
        let other_ref = expr(
            span(500, 510),
            Expr_::VarTopLevel {
                module: vec![other_sym],
                name: helper_sym,
            },
        );
        let other_mod = module(
            vec![other_sym],
            vec![untyped_def(
                loc_sym(interner, "use_other_helper"),
                vec![other_sym],
                other_ref,
            )],
        );

        (lib_mod, main_mod, shadow_mod, other_mod, helper_sym)
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    #[test]
    fn lib_helper_has_exactly_three_refs_in_main() {
        let mut interner = Interner::new();
        let (lib_mod, main_mod, shadow_mod, other_mod, helper_sym) = build_fixture(&mut interner);

        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();
        let shadow_path = shadow_mod.name.clone();
        let other_path = other_mod.name.clone();

        let index = ReferenceIndex::build(&[
            (&lib_mod, &lib_path),
            (&main_mod, &main_path),
            (&shadow_mod, &shadow_path),
            (&other_mod, &other_path),
        ]);

        let main_sym = sym(&mut interner, "Main");
        let refs = index.references_of(&lib_path, helper_sym);
        assert_eq!(
            refs.len(),
            3,
            "expected exactly 3 refs to Lib.helper, got {}",
            refs.len()
        );

        // All refs live in Main.
        for r in refs {
            assert_eq!(
                r.in_module,
                vec![main_sym],
                "ref at {:?} expected in_module=[Main]",
                r.span
            );
        }

        // Spans are the three we placed.
        let mut spans: Vec<(u32, u32)> = refs.iter().map(|r| (r.span.lo, r.span.hi)).collect();
        spans.sort_unstable();
        assert_eq!(spans, vec![(100, 110), (200, 210), (300, 310)]);
    }

    #[test]
    fn shadowed_local_is_excluded() {
        let mut interner = Interner::new();
        let (lib_mod, main_mod, shadow_mod, other_mod, helper_sym) = build_fixture(&mut interner);

        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();
        let shadow_path = shadow_mod.name.clone();
        let other_path = other_mod.name.clone();

        let index = ReferenceIndex::build(&[
            (&lib_mod, &lib_path),
            (&main_mod, &main_path),
            (&shadow_mod, &shadow_path),
            (&other_mod, &other_path),
        ]);

        // Shadow module's VarLocal(helper) must not inflate the Lib.helper count.
        let shadow_sym = sym(&mut interner, "Shadow");
        let refs = index.references_of(&lib_path, helper_sym);
        assert!(
            refs.iter().all(|r| r.in_module != vec![shadow_sym]),
            "shadowed local must not appear as a hit for Lib.helper"
        );
    }

    #[test]
    fn other_module_helper_not_conflated_with_lib_helper() {
        let mut interner = Interner::new();
        let (lib_mod, main_mod, shadow_mod, other_mod, helper_sym) = build_fixture(&mut interner);

        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();
        let shadow_path = shadow_mod.name.clone();
        let other_path = other_mod.name.clone();

        let index = ReferenceIndex::build(&[
            (&lib_mod, &lib_path),
            (&main_mod, &main_path),
            (&shadow_mod, &shadow_path),
            (&other_mod, &other_path),
        ]);

        // Other.helper references must appear only under Other's key, not Lib's.
        let other_sym = sym(&mut interner, "Other");
        let lib_refs = index.references_of(&lib_path, helper_sym);
        assert!(
            lib_refs.iter().all(|r| r.in_module != vec![other_sym]),
            "Other.helper refs must not appear under the Lib.helper key"
        );

        // And Other's own key has exactly one ref (the self-ref in other_mod).
        let other_refs = index.references_of(&other_path, helper_sym);
        assert_eq!(
            other_refs.len(),
            1,
            "Other.helper should have exactly 1 ref"
        );
        let r0 = other_refs.first().expect("Other.helper must have a ref");
        assert_eq!(r0.in_module, vec![other_sym]);
        assert_eq!((r0.span.lo, r0.span.hi), (500, 510));
    }

    #[test]
    fn undefined_symbol_returns_empty() {
        let mut interner = Interner::new();
        let (lib_mod, main_mod, shadow_mod, other_mod, _helper_sym) = build_fixture(&mut interner);

        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();
        let shadow_path = shadow_mod.name.clone();
        let other_path = other_mod.name.clone();

        let index = ReferenceIndex::build(&[
            (&lib_mod, &lib_path),
            (&main_mod, &main_path),
            (&shadow_mod, &shadow_path),
            (&other_mod, &other_path),
        ]);

        let never_sym = sym(&mut interner, "neverDefined");
        let refs = index.references_of(&lib_path, never_sym);
        assert!(refs.is_empty(), "absent symbol must return empty slice");
    }

    #[test]
    fn constructor_pattern_ref_captured() {
        // Verify that constructor uses in patterns (PCtor) are also indexed.
        let mut interner = Interner::new();

        let lib_sym = sym(&mut interner, "Lib");
        let main_sym = sym(&mut interner, "Main");
        let ok_sym = sym(&mut interner, "Ok");
        let val_sym = sym(&mut interner, "val");
        let use_ok_sym = sym(&mut interner, "use_ok");

        // Main.use_ok: case expr of Ok val -> val
        // The Ok PCtor has home=[Lib], name=Ok.
        let ctor_pat = pat(
            span(600, 602),
            Pattern_::PCtor {
                home: vec![lib_sym],
                type_name: ok_sym,
                name: ok_sym,
                index: 0,
                args: vec![pat(span(603, 606), Pattern_::PVar(val_sym))],
            },
        );
        let body_expr = expr(
            span(610, 615),
            Expr_::Case(
                Box::new(expr(span(605, 609), Expr_::VarLocal(val_sym))),
                vec![CaseBranch {
                    pat: ctor_pat,
                    body: expr(span(616, 619), Expr_::VarLocal(val_sym)),
                }],
            ),
        );

        let main_mod = module(
            vec![main_sym],
            vec![untyped_def(
                Located::new(span(590, 596), use_ok_sym),
                vec![main_sym],
                body_expr,
            )],
        );
        let lib_mod = module(vec![lib_sym], vec![]);
        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();

        let index = ReferenceIndex::build(&[(&lib_mod, &lib_path), (&main_mod, &main_path)]);

        let refs = index.references_of(&[lib_sym], ok_sym);
        assert_eq!(refs.len(), 1, "PCtor ref to Lib.Ok must be captured");
        let r0 = refs.first().expect("just asserted len==1");
        assert_eq!((r0.span.lo, r0.span.hi), (600, 602));
    }
}
