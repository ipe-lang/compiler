#![forbid(unsafe_code)]
//! `ipe_canon` — name resolution / canonicalisation for the supported subset
//! of Ipê.
//!
//! Entry point: [`canonicalise`]. It consumes a [`ipe_syntax::Module`] (the raw
//! parse tree) plus a mutable [`Interner`] and produces a name-resolved
//! [`ast::Module`], or a typed [`ipe_diagnostics::Diagnostic`]. Every variable
//! reference is classified — local binding, top-level binding, stdlib kernel,
//! or data constructor.

pub mod asserted;
pub mod ast;
pub mod builtins;
pub mod custom_element_gate;
pub mod decoder_pipeline_gate;
mod env;
pub mod link;
pub mod module_classify;
pub mod ref_index;
pub mod rename;
mod resolve;
mod scope;
pub mod shape_runtime;
pub mod shape_source;
pub mod sig_delta;
pub mod target_gate;

use std::collections::{BTreeMap, BTreeSet};

use ipe_diagnostics::DResult;
use ipe_intern::{Interner, Symbol};

pub use env::{
    CtorHome, Env, ModuleCatalog, STDLIB_MODULE_QUALIFIERS, VarHome, bare_import_binds,
    kernel_import_binds_last_segment, stdlib_canonical_qualifier,
};
pub use resolve::{
    ModuleOrigin, QualifierForm, builtin_empty_home_arity, import_qualifier_forms,
    import_qualifiers, is_reserved_builtin_type_name, is_user_type_declaration_forbidden,
    to_snake_case,
};

/// A type alias exported by a module, resolved in the defining module's scope.
///
/// The body is canonicalised once, where the alias is declared, against that
/// module's own imports; an importer substitutes its type arguments for
/// `param_slots` and never re-resolves alias source text, so an alias's private
/// imports never leak into (or get captured by) an importer's scope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportedAlias {
    /// The path of the module that declares the alias. Two imports bringing the
    /// same bare alias name from different homes are ambiguous at a bare use.
    pub home: Vec<Symbol>,
    /// The variable standing for each declared parameter in `body`, in source
    /// order. Each slot is a symbol no source type variable can spell, so a
    /// substitution never captures a variable the body leaves free.
    pub param_slots: Vec<Symbol>,
    /// The fully expanded right-hand side of the `type alias` declaration.
    pub body: ast::Type,
    /// Type variables the body leaves free; a use site's binding quantifies them.
    pub free_vars: BTreeSet<Symbol>,
    /// Whether the declared right-hand side is a `{ … }` record literal.
    pub literal_record: bool,
}

/// The public exports of a canonicalised module: the names and resolved
/// locations of every value, type, constructor, and alias the module exposes
/// via its `exposing` list.
///
/// Used by [`canonicalise_module`] as the `deps` map entries so importing
/// modules can inject the right resolved names into their environments.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ModuleExports {
    /// The module's own path, e.g. `[Lib, Utils]`.
    pub path: Vec<Symbol>,
    /// Exported value names (without their resolved `VarHome`; the home is
    /// always `TopLevel(path)`, reconstructed at injection time).
    pub values: BTreeSet<Symbol>,
    /// Exported type names mapped to their home module path. For a type
    /// `Widget` declared in `Lib.Utils`, this entry is `Widget → [Lib, Utils]`.
    pub types: BTreeMap<Symbol, Vec<Symbol>>,
    /// Exported constructors by name.
    pub ctors: BTreeMap<Symbol, CtorHome>,
    /// Exported type aliases by name.
    pub aliases: BTreeMap<Symbol, ExportedAlias>,
    /// Exported Stage-4 kernel aliases: value names whose binding is
    /// `f = Kernel.kernel "Module_function"`, mapped to the resolved kernel target
    /// `(StdlibKernel, module, function)`.
    ///
    /// A name here is ALSO present in `values` (it is an exported value), but an
    /// importer must register it as a [`VarHome::Kernel`] — routing every
    /// `Alias.f` reference straight to the kernel — rather than the default
    /// `TopLevel(path)`, because the alias emits no top-level body. The
    /// disjointness with a normal value is by construction: `detect_kernel_alias`
    /// classifies each binding exactly once.
    pub kernel_aliases: BTreeMap<Symbol, ExportedKernelAlias>,
}

/// The resolved target of an exported Stage-4 kernel alias — the `(StdlibKernel,
/// module, function)` an `Kernel.kernel "Module_function"` binding routes to. See
/// [`ModuleExports::kernel_aliases`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExportedKernelAlias {
    /// The registered kernel this alias routes to.
    pub id: ipe_kernels::StdlibKernel,
    /// Canonical kernel-module symbol (the `Module` half of the split string).
    pub module: Symbol,
    /// Canonical kernel-function symbol (the `function` half of the split).
    pub function: Symbol,
}

/// Canonicalise a parsed module into its name-resolved canonical AST.
///
/// # Errors
/// Returns a [`ipe_diagnostics::Diagnostic`] for any name that resolves to
/// neither a constructor, a bound variable, a top-level binding, nor a kernel
/// function (an [`ipe_diagnostics::NameError`] payload variant carrying a
/// deterministic did-you-mean), or for a duplicated value/constructor/type
/// name.
pub fn canonicalise(m: &ipe_syntax::Module, interner: &mut Interner) -> DResult<ast::Module> {
    resolve::canonicalise(m, interner)
}

/// Canonicalise a module in a multi-module project context.
///
/// Unlike [`canonicalise`], this function:
/// * validates `m`'s declared module name against `expected_path` — emits
///   [`ipe_diagnostics::NameError::ModulePathMismatch`] when they disagree
/// * rejects `Ipê` / `Std` as the first path segment — emits
///   [`ipe_diagnostics::NameError::ReservedNamespace`]
/// * resolves each local `import` against `deps`, injecting exports into the
///   name-resolution environment — emits
///   [`ipe_diagnostics::NameError::ModuleNotFound`] /
///   [`ipe_diagnostics::NameError::NameNotExposed`] /
///   [`ipe_diagnostics::NameError::AmbiguousImport`] on violations
/// * returns the resolved [`ast::Module`] plus a [`ModuleExports`] summary
///   derived from the module's own `exposing` list
///
/// # Errors
/// Any of the above [`ipe_diagnostics::NameError`] variants, or any error that
/// [`canonicalise`] can return.
pub fn canonicalise_module(
    m: &ipe_syntax::Module,
    expected_path: &[Symbol],
    deps: &BTreeMap<Vec<Symbol>, ModuleExports>,
    interner: &mut Interner,
) -> DResult<(ast::Module, ModuleExports)> {
    resolve::canonicalise_module(m, expected_path, deps, interner)
}

/// Canonicalise a module carrying an explicit trust [`ModuleOrigin`].
///
/// Like [`canonicalise_module`] but lets the build driver vouch that a module's
/// source came from the compiler's own embedded stdlib table
/// ([`ModuleOrigin::EmbeddedStdlib`]) — the ONLY way to legitimately declare a
/// `module Ipe.…` / `module Ipe.…` home without tripping IPE-N0025. The trust tag
/// is unforgeable from module text: a user file named `Ipe.Foo` reaches this
/// function as [`ModuleOrigin::User`] and stays rejected.
///
/// # Errors
/// Any error [`canonicalise_module`] can return, plus a fail-closed
/// [`ipe_diagnostics::Diagnostic::CompilerBug`] when an `EmbeddedStdlib` module
/// carries an un-annotated top-level binding.
pub fn canonicalise_module_with_origin(
    m: &ipe_syntax::Module,
    expected_path: &[Symbol],
    deps: &BTreeMap<Vec<Symbol>, ModuleExports>,
    origin: ModuleOrigin,
    interner: &mut Interner,
) -> DResult<(ast::Module, ModuleExports)> {
    resolve::canonicalise_module_with_origin(m, expected_path, deps, origin, interner)
}

/// Canonicalise a module for the incremental (salsa) build driver.
///
/// Like [`canonicalise_module_with_origin`] but takes the dep interfaces by
/// reference (the `module_interface` query memos — no per-importer deep clone)
/// and the importable-module `catalog`, read only on diagnostic paths: the
/// IPE-N0020 did-you-mean list and the IPE-N0034 verdict for an unbound
/// qualifier. `deps` must contain exactly this module's resolved imports; the
/// catalog should list every project module and compiled-source stdlib module.
///
/// # Errors
/// Same set as [`canonicalise_module_with_origin`].
pub fn canonicalise_module_in_project(
    m: &ipe_syntax::Module,
    expected_path: &[Symbol],
    deps: &BTreeMap<Vec<Symbol>, &ModuleExports>,
    catalog: &ModuleCatalog,
    origin: ModuleOrigin,
    interner: &mut Interner,
) -> DResult<(ast::Module, ModuleExports)> {
    resolve::canonicalise_module_in_project(m, expected_path, deps, catalog, origin, interner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast::{Def, Expr, Expr_, Pattern_};
    use ipe_diagnostics::{Diagnostic, NameError, StdlibReach};
    use ipe_intern::Symbol;

    const GOLDEN: &str = include_str!("../../../../tests/golden/basics/Main.ipe");

    /// Parse + canonicalise the golden module. Returns `None` (failing the
    /// caller's assertions) rather than panicking, per the no-panic gate.
    fn canon_golden(i: &mut Interner) -> Option<ast::Module> {
        let src = ipe_parse::parse_module(GOLDEN, i).ok()?;
        canonicalise(&src, i).ok()
    }

    fn find_def<'a>(m: &'a ast::Module, i: &Interner, name: &str) -> Option<&'a Def> {
        m.defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some(name))
    }

    /// Drill into a [`Call`] node, returning callee + args.
    fn as_call(e: &Expr) -> Option<(&Expr_, &[Expr])> {
        match &e.value {
            Expr_::Call(callee, args) => Some((&callee.value, args)),
            _ => None,
        }
    }

    /// Parse + canonicalise inline source, returning the module + interner.
    fn canon_src(src: &str) -> Option<(ast::Module, Interner)> {
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i).ok()?;
        let m = canonicalise(&parsed, &mut i).ok()?;
        Some((m, i))
    }

    #[test]
    fn lambda_binds_params_locally_and_captures_outer_names() {
        // `f = \x -> x + n` (with top-level `n`): inside the lambda body `x`
        // resolves to a local (the parameter) and `n` to the captured top-level
        // binding.
        let src = "module Main exposing (f)\n\
                   n : Int\n\
                   n = 10\n\
                   f =\n    \\x -> x + n\n";
        let opt = canon_src(src);
        assert!(opt.is_some(), "must parse + canonicalise");
        let Some((m, i)) = opt else { return };
        let def = find_def(&m, &i, "f");
        assert!(matches!(def, Some(Def::Untyped { .. })), "f is untyped");
        let Some(Def::Untyped { body, .. }) = def else {
            return;
        };
        assert!(
            matches!(&body.value, Expr_::Lambda(..)),
            "f body is a lambda"
        );
        let Expr_::Lambda(params, lam_body) = &body.value else {
            return;
        };
        assert_eq!(params.len(), 1, "one parameter");
        assert!(
            matches!(params.first().map(|p| &p.value), Some(Pattern_::PVar(s)) if i.resolve(*s) == Some("x"))
        );
        // The body `x + n`: x is a local, n is the captured top-level binding.
        assert!(
            matches!(&lam_body.value, Expr_::Binop { .. }),
            "body is x + n"
        );
        let Expr_::Binop { lhs, rhs, .. } = &lam_body.value else {
            return;
        };
        assert!(matches!(lhs.value, Expr_::VarLocal(s) if i.resolve(s) == Some("x")));
        assert!(
            matches!(&rhs.value, Expr_::VarTopLevel { name, .. } if i.resolve(*name) == Some("n"))
        );
    }

    #[test]
    fn module_name_and_union_resolve() {
        let mut i = Interner::new();
        let m = canon_golden(&mut i);
        assert!(m.is_some(), "golden must parse + canonicalise");
        let Some(m) = m else { return };

        assert_eq!(m.name.len(), 1);
        assert_eq!(m.name.first().and_then(|&s| i.resolve(s)), Some("Main"));

        // The `Msg` union with two nullary constructors.
        assert_eq!(m.unions.len(), 1);
        let Some(union) = m.unions.first() else {
            return;
        };
        assert_eq!(i.resolve(union.name), Some("Msg"));
        let names: Vec<(&str, usize)> = union
            .ctors
            .iter()
            .filter_map(|c| i.resolve(c.name).map(|n| (n, c.index)))
            .collect();
        assert_eq!(names, vec![("Increment", 0), ("Decrement", 1)]);
    }

    #[test]
    fn update_body_resolves_locals_and_ctor_patterns() {
        let mut i = Interner::new();
        let m = canon_golden(&mut i);
        assert!(m.is_some(), "golden");
        let Some(m) = m else { return };

        let def = find_def(&m, &i, "update");
        assert!(
            matches!(def, Some(Def::Typed { .. })),
            "update is a typed def"
        );
        let Some(Def::Typed { patterns, body, .. }) = def else {
            return;
        };
        assert_eq!(patterns.len(), 2);

        // case msg of ...
        assert!(
            matches!(&body.value, Expr_::Case(..)),
            "update body is a case"
        );
        let Expr_::Case(scrut, branches) = &body.value else {
            return;
        };
        assert!(matches!(scrut.value, Expr_::VarLocal(s) if i.resolve(s) == Some("msg")));
        assert_eq!(branches.len(), 2);

        // First arm: `Increment -> count + 1`.
        let Some(inc) = branches.first() else { return };
        assert!(
            matches!(&inc.pat.value, Pattern_::PCtor { .. }),
            "arm pattern is a ctor"
        );
        let Pattern_::PCtor {
            type_name,
            name,
            index,
            ..
        } = &inc.pat.value
        else {
            return;
        };
        assert_eq!(i.resolve(*type_name), Some("Msg"));
        assert_eq!(i.resolve(*name), Some("Increment"));
        assert_eq!(*index, 0);

        // Body `count + 1` → Binop resolving to Basics.add over a local lhs.
        assert!(
            matches!(&inc.body.value, Expr_::Binop { .. }),
            "arm body is a binop"
        );
        let Expr_::Binop {
            home, func, lhs, ..
        } = &inc.body.value
        else {
            return;
        };
        assert_eq!(i.resolve(*home), Some("Basics"));
        assert_eq!(i.resolve(*func), Some("add"));
        assert!(matches!(lhs.value, Expr_::VarLocal(s) if i.resolve(s) == Some("count")));

        // Second arm resolves `-` to Basics.sub.
        let Some(dec) = branches.get(1) else { return };
        assert!(
            matches!(&dec.body.value, Expr_::Binop { .. }),
            "arm body is a binop"
        );
        let Expr_::Binop { func, .. } = &dec.body.value else {
            return;
        };
        assert_eq!(i.resolve(*func), Some("sub"));
    }

    #[test]
    fn main_body_resolves_kernel_toplevel_and_ctor() {
        let mut i = Interner::new();
        let m = canon_golden(&mut i);
        assert!(m.is_some(), "golden");
        let Some(m) = m else { return };

        // ── main body: System.setenv "HOME" "x" ─────────────────────────────
        let def = find_def(&m, &i, "main");
        assert!(
            matches!(def, Some(Def::Untyped { .. })),
            "main is an untyped def"
        );
        let Some(Def::Untyped { body, .. }) = def else {
            return;
        };

        // main body is: System.setenv "HOME" "x"
        // The parser emits Call(VarKernel{setenv}, ["HOME", "x"]) directly.
        let outer = as_call(body);
        assert!(outer.is_some(), "main body is a call");
        let Some((_, outer_args)) = outer else {
            return;
        };
        assert!(!outer_args.is_empty(), "setenv call has arguments");

        // The first arg is the string literal "HOME".
        let Some(arg0) = outer_args.first() else {
            return;
        };
        assert!(
            matches!(&arg0.value, Expr_::Str(_)),
            "setenv first arg is a string literal"
        );

        // ── update body: case with PCtor patterns ───────────────────────────
        let upd_def = find_def(&m, &i, "update");
        let Some(Def::Typed { body: upd_body, .. }) = upd_def else {
            return;
        };
        let Expr_::Case(_, branches) = &upd_body.value else {
            assert!(false_marker(), "update body is a case");
            return;
        };

        // First arm pattern is `Increment` — PCtor of Main.Msg.
        let Some(first_branch) = branches.first() else {
            return;
        };
        let Pattern_::PCtor {
            type_name,
            name,
            index,
            home,
            ..
        } = &first_branch.pat.value
        else {
            assert!(false_marker(), "first arm pattern is PCtor");
            return;
        };
        assert_eq!(i.resolve(*type_name), Some("Msg"));
        assert_eq!(i.resolve(*name), Some("Increment"));
        assert_eq!(*index, 0);
        assert_eq!(home.first().and_then(|&s| i.resolve(s)), Some("Main"));
    }

    #[test]
    fn typed_def_carries_arrow_annotation() {
        let mut i = Interner::new();
        let m = canon_golden(&mut i);
        assert!(m.is_some(), "golden");
        let Some(m) = m else { return };

        let def = find_def(&m, &i, "update");
        assert!(matches!(def, Some(Def::Typed { .. })), "update is typed");
        let Some(Def::Typed { ty, free_vars, .. }) = def else {
            return;
        };
        // No type variables in `Msg -> Int -> Int`.
        assert!(free_vars.is_empty());
        // Outer arrow: Msg -> (Int -> Int).
        assert!(
            matches!(ty, ast::Type::Lambda(_, _)),
            "annotation is an arrow"
        );
        let ast::Type::Lambda(arg, rest) = ty else {
            return;
        };
        assert!(
            matches!(arg.as_ref(), ast::Type::Con { .. }),
            "first arg is a constructor type"
        );
        let ast::Type::Con { name, home, .. } = arg.as_ref() else {
            return;
        };
        assert_eq!(i.resolve(*name), Some("Msg"));
        // `Msg` is a local union → home is this module.
        assert_eq!(home.first().and_then(|&s| i.resolve(s)), Some("Main"));
        // Tail is Int -> Int.
        assert!(matches!(rest.as_ref(), ast::Type::Lambda(_, _)));
    }

    /// Parse `src_text` and canonicalise it, returning the diagnostic (if any).
    /// Returns `None` from the parse step rather than panicking.
    fn canon_err(src_text: &str) -> Option<Diagnostic> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(src_text, &mut i).ok()?;
        canonicalise(&src, &mut i).err()
    }

    /// Parse `src_text` and canonicalise it through the multi-module project
    /// entry with an empty dep universe, returning the diagnostic (if any).
    /// Exercises the import-existence gate that classifies `Ipe.*` imports
    /// against the kernel table + `deps` — the path the real build driver uses.
    fn canon_module_err(src_text: &str) -> Option<Diagnostic> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(src_text, &mut i).ok()?;
        let deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let expected = src.name.value.clone();
        canonicalise_module(&src, &expected, &deps, &mut i).err()
    }

    /// Parse + canonicalise `src_text` in ONE interner, returning the canonical
    /// annotation type of each named typed binding in `wants` (same order).
    /// Symbol ids are per-interner, so bindings compared for equality MUST be
    /// canonicalised together here. `None` if parse/canon fails.
    fn canon_binding_tys(src_text: &str, wants: &[&str]) -> Option<Vec<ast::Type>> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(src_text, &mut i).ok()?;
        let module = canonicalise(&src, &mut i).ok()?;
        wants
            .iter()
            .map(|w| {
                let want_sym = i.lookup(w)?;
                module.defs.iter().find_map(|d| match d {
                    ast::Def::Typed { name, ty, .. } if name.value == want_sym => Some(ty.clone()),
                    _ => None,
                })
            })
            .collect()
    }

    #[test]
    fn view_web_is_the_dom_element_type() {
        // `View Web msg` and `Element msg` are the SAME canonical type: `View`
        // is the real engine-tagged carrier `Con(View, [Web, msg])`, and
        // `Element` is its per-engine alias canonicalising to the identical con.
        // This is what lets `Ipe.Tea.app`'s `view : model -> View e msg` field
        // accept the existing DOM view combinators (which yield `View Web msg`)
        // with no parallel surface.
        let tys = canon_binding_tys(
            "module Main exposing (v, w)\n\n\
             v : View Web msg\nv = v\n\n\
             w : Element msg\nw = w\n",
            &["v", "w"],
        );
        assert!(
            tys.is_some(),
            "`View Web msg` and `Element msg` must both canonicalise"
        );
        let tys = tys.unwrap();
        assert_eq!(
            tys.first(),
            tys.get(1),
            "`View Web msg` must canonicalise to the identical type as `Element msg`"
        );
    }

    #[test]
    fn view_tui_and_view_cli_are_the_screen_and_lines_types() {
        // The `View` carrier is genuinely engine-parametric over the CLOSED set:
        // `View Tui msg` IS `Screen msg`, `View Cli msg` IS `Lines msg` (each an
        // alias of the same `Con(View, [engine, msg])`). Because the engine tag
        // is a distinct nullary con, the three carriers resolve to three
        // distinct types, so a cross-engine node (`View Tui msg` where a `View
        // Web msg` is wanted) fails unification — the
        // make-invalid-states-unrepresentable guarantee, proven structurally.
        let tys = canon_binding_tys(
            "module Main exposing (tui, screen, cli, lines, web)\n\n\
             tui : View Tui msg\ntui = tui\n\n\
             screen : Screen msg\nscreen = screen\n\n\
             cli : View Cli msg\ncli = cli\n\n\
             lines : Lines msg\nlines = lines\n\n\
             web : View Web msg\nweb = web\n",
            &["tui", "screen", "cli", "lines", "web"],
        )
        .expect("all view annotations must canonicalise");
        let tui = tys.first().expect("tui view annotation");
        let screen = tys.get(1).expect("screen annotation");
        let cli = tys.get(2).expect("cli view annotation");
        let lines = tys.get(3).expect("lines annotation");
        let web = tys.get(4).expect("web view annotation");
        assert_eq!(tui, screen, "`View Tui msg` must be `Screen msg`");
        assert_eq!(cli, lines, "`View Cli msg` must be `Lines msg`");
        assert_ne!(tui, cli, "distinct engines must give distinct view types");
        assert_ne!(
            web, tui,
            "`View Web msg` (Element) and `View Tui msg` (Screen) must differ, \
             so a cross-engine view node fails unification"
        );
    }

    #[test]
    fn view_over_a_non_engine_tag_is_rejected() {
        // Fail closed: the engine tag is drawn from the CLOSED `{Web, Tui, Cli}`
        // set. `View Foo msg` names no view engine and has no rendering
        // denotation, so it is rejected at canon rather than silently accepted.
        let err = canon_err("module Main exposing (v)\n\nv : View Foo msg\nv = v\n");
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::TypeNotFound { ref name, .. },
                    ..
                }) if name.as_ref() == "Foo"
            ),
            "`View Foo msg` must be rejected fail-closed as an unknown view \
             engine, got {err:?}"
        );
    }

    #[test]
    fn unknown_name_is_a_value_not_found() {
        let err = canon_err("module Main exposing (main)\n\nmain = nope\n");
        assert!(matches!(
            err,
            Some(Diagnostic::Name {
                msg: NameError::ValueNotFound { .. },
                ..
            })
        ));
    }

    /// The prelude has no generic stringifier: a bare `toString` is unbound.
    /// Its typed replacement `String.fromBool` lives in the compiled-source
    /// `Ipe.String`, which canon alone cannot see; `type_check::string_from_bool_type_checks`
    /// pins that it resolves through the real stdlib.
    #[test]
    fn bare_to_string_is_not_in_the_prelude() {
        let err = canon_err("module Main exposing (main)\n\nmain = toString 42\n");
        assert!(
            matches!(
                &err,
                Some(Diagnostic::Name {
                    msg: NameError::ValueNotFound { name, .. },
                    ..
                }) if &**name == "toString"
            ),
            "`toString` must be unbound, got {err:?}"
        );
    }

    /// The interpolation renderer is internal: its kernel name has no surface
    /// binding, so `{{…}}` is the only way to reach it.
    #[test]
    fn interpolate_kernel_has_no_surface_binding() {
        let err = canon_err("module Main exposing (main)\n\nmain = interpolate 42\n");
        assert!(
            matches!(
                &err,
                Some(Diagnostic::Name {
                    msg: NameError::ValueNotFound { .. },
                    ..
                })
            ),
            "`interpolate` must be unbound, got {err:?}"
        );
    }

    #[test]
    fn unknown_value_suggests_close_name() {
        // `getcw` is one edit from the `Ipe.System` member `getcwd`.
        let err = canon_err(
            "module Main exposing (main)\nimport Ipe.System as System\n\nmain = System.getcw\n",
        );
        assert!(
            matches!(
                &err,
                Some(Diagnostic::Name {
                    msg: NameError::NoSuchMember { .. },
                    ..
                })
            ),
            "expected NoSuchMember, got {err:?}"
        );
        let Some(Diagnostic::Name {
            msg:
                NameError::NoSuchMember {
                    member,
                    suggestions,
                    ..
                },
            ..
        }) = err
        else {
            return;
        };
        assert_eq!(&*member, "getcw");
        assert!(
            suggestions.names.iter().any(|s| &**s == "getcwd"),
            "suggestions should include `getcwd`, got {suggestions:?}"
        );
    }

    #[test]
    fn unknown_value_far_from_everything_has_no_suggestions() {
        // `zzzzzzzz` is > 2 edits from every in-scope name → silence.
        let err = canon_err("module Main exposing (main)\n\nmain = zzzzzzzz\n");
        let Some(Diagnostic::Name {
            msg: NameError::ValueNotFound { suggestions, .. },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected ValueNotFound");
            return;
        };
        assert!(
            suggestions.names.is_empty(),
            "no suggestion within edit-distance 2, got {suggestions:?}"
        );
    }

    #[test]
    fn suggestions_sorted_by_distance_then_name() {
        // Several `Crypto` members sit at equal edit distance from `sha`; assert
        // the rendered list is `(distance, name)`-sorted. A security module stays
        // kernel-qualifier; a compiled-source module would not resolve here.
        let err =
            canon_err("module Main exposing (main)\nimport Ipe.Crypto\n\nmain = Crypto.sha\n");
        let Some(Diagnostic::Name {
            msg: NameError::NoSuchMember { suggestions, .. },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected NoSuchMember");
            return;
        };
        let keys: Vec<(usize, String)> = suggestions
            .names
            .iter()
            .map(|s| (test_levenshtein("sha", s), s.to_string()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "suggestions must be (distance, name)-sorted");
    }

    #[test]
    fn unknown_qualifier_is_unknown_module() {
        // `Crpyto` is one transposition from the imported `Crypto` qualifier.
        let err =
            canon_err("module Main exposing (main)\nimport Ipe.Crypto\n\nmain = Crpyto.sha256\n");
        let Some(Diagnostic::Name {
            msg:
                NameError::UnknownModule {
                    qualifier,
                    suggestions,
                },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected UnknownModule");
            return;
        };
        assert_eq!(&*qualifier, "Crpyto");
        assert!(
            suggestions.names.iter().any(|s| &**s == "Crypto"),
            "should suggest `Crypto`, got {suggestions:?}"
        );
    }

    #[test]
    fn dotted_user_module_type_in_annotation_resolves() {
        // Regression pin: a bare `import Rls.Owner` (no `as`) registers the
        // module under BOTH its leaf (`Owner`) and its full dotted path
        // (`Rls.Owner`), so a fully-qualified TYPE reference `Rls.Owner.Doc`
        // resolves the same as its expression use — neither is turned away as an
        // unknown module. The type is a record alias, exercising the qualified
        // alias-key expansion under the dotted qualifier.
        let err = canon_main_with_dep(
            "module Rls.Owner exposing (Doc, word)\n\
             type alias Doc =\n    { body : String }\n\n\
             word : String\n\
             word =\n    \"w\"\n",
            "module Main exposing (main)\n\
             import Rls.Owner\n\n\
             thing : Rls.Owner.Doc\n\
             thing =\n    { body = \"x\" }\n\n\
             main =\n    thing.body\n",
        );
        assert!(
            err.is_none(),
            "a dotted user module referenced by fully-qualified TYPE \
             (`Rls.Owner.Doc`) must resolve, got {err:?}"
        );
    }

    #[test]
    fn dotted_user_module_value_in_expression_resolves() {
        // Non-regression companion: the SAME dotted module referenced by
        // fully-qualified VALUE (`Rls.Owner.word`) still resolves — the leaf and
        // dotted qualifiers back the identical member table.
        let err = canon_main_with_dep(
            "module Rls.Owner exposing (Doc, word)\n\
             type alias Doc =\n    { body : String }\n\n\
             word : String\n\
             word =\n    \"w\"\n",
            "module Main exposing (main)\n\
             import Rls.Owner\n\n\
             main =\n    Rls.Owner.word\n",
        );
        assert!(
            err.is_none(),
            "a dotted user module referenced by fully-qualified VALUE \
             (`Rls.Owner.word`) must resolve, got {err:?}"
        );
    }

    #[test]
    fn unknown_dotted_qualifier_in_type_is_unknown_module() {
        // Prove the refusal survives: opening the resolver to a dotted user
        // module must NOT make a genuinely-unknown dotted qualifier silently
        // resolve. `Rls.Ownr` (a typo of the imported `Rls.Owner`) names no
        // registered qualifier, so a TYPE annotation over it is IPE-N0004
        // UnknownModule — never a silent success.
        let err = canon_main_with_dep(
            "module Rls.Owner exposing (Doc, word)\n\
             type alias Doc =\n    { body : String }\n\n\
             word : String\n\
             word =\n    \"w\"\n",
            "module Main exposing (main)\n\
             import Rls.Owner\n\n\
             thing : Rls.Ownr.Doc\n\
             thing =\n    { body = \"x\" }\n\n\
             main =\n    thing.body\n",
        );
        let Some(Diagnostic::Name {
            msg: NameError::UnknownModule { qualifier, .. },
            ..
        }) = err
        else {
            assert!(
                false_marker(),
                "an unknown dotted qualifier in TYPE position must be \
                 UnknownModule (IPE-N0004), got {err:?}"
            );
            return;
        };
        assert_eq!(&*qualifier, "Rls.Ownr");
    }

    #[test]
    fn known_qualifier_missing_member_is_no_such_member() {
        // `sha25` is one deletion from the `Crypto` member `sha256`.
        let err =
            canon_err("module Main exposing (main)\nimport Ipe.Crypto\n\nmain = Crypto.sha25\n");
        let Some(Diagnostic::Name {
            msg:
                NameError::NoSuchMember {
                    module,
                    member,
                    suggestions,
                },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected NoSuchMember");
            return;
        };
        assert_eq!(&*module, "Crypto");
        assert_eq!(&*member, "sha25");
        assert!(
            suggestions.names.iter().any(|s| &**s == "sha256"),
            "should suggest `sha256`, got {suggestions:?}"
        );
    }

    /// A bare `import Ipe.Crpyto` names no stdlib module. It must be rejected AT
    /// the import with IPE-N0020 (`ModuleNotFound`) and a did-you-mean to
    /// `Ipe.Crypto`, never silently dropped — even though the typo'd name is
    /// otherwise unused. Reverting the import-existence gate makes this program
    /// canonicalise clean, so the test fails on mutation.
    #[test]
    fn unknown_ipe_stdlib_import_is_module_not_found() {
        // The body is a plain literal so the ONLY possible diagnostic is the
        // bogus import — with the gate reverted the program canonicalises clean.
        let err = canon_module_err("module Main exposing (main)\nimport Ipe.Crpyto\n\nmain = 0\n");
        let Some(Diagnostic::Name {
            msg: NameError::ModuleNotFound { name, suggestions },
            ..
        }) = err
        else {
            assert!(
                false_marker(),
                "expected ModuleNotFound (IPE-N0020), got {err:?}"
            );
            return;
        };
        assert_eq!(&*name, "Ipe.Crpyto");
        assert!(
            suggestions.names.iter().any(|s| &**s == "Ipe.Crypto"),
            "should suggest `Ipe.Crypto`, got {suggestions:?}"
        );
    }

    /// The `exposing`-list form of a typo'd stdlib import must fail the SAME way
    /// — at the import with IPE-N0020 — and NOT defer to a use-site IPE-N0001 for
    /// the exposed name. Reverting the fix leaves this accepted (the exposed name
    /// is unused), so the test fails on mutation.
    #[test]
    fn unknown_ipe_stdlib_exposing_import_is_module_not_found() {
        let err = canon_module_err(
            "module Main exposing (main)\nimport Ipe.Crpyto exposing (sha256)\n\nmain = 0\n",
        );
        let Some(Diagnostic::Name {
            msg: NameError::ModuleNotFound { name, suggestions },
            ..
        }) = err
        else {
            assert!(
                false_marker(),
                "expected ModuleNotFound (IPE-N0020) at the import, got {err:?}"
            );
            return;
        };
        assert_eq!(&*name, "Ipe.Crpyto");
        assert!(
            suggestions.names.iter().any(|s| &**s == "Ipe.Crypto"),
            "should suggest `Ipe.Crypto`, got {suggestions:?}"
        );
    }

    /// ADR 0001 Tier A (`Ipe.Basics`) and Tier B (core type vocabulary) are
    /// ambient: a module reaches for `identity` / `always` / `not`, the type
    /// names `Maybe` / `Result` / `List`, and the constructors `Just` /
    /// `Nothing` / `Ok` / `Err` / `True` / `False` with NO import line. This is
    /// what makes the removed `Ipe.Prelude` value-flood redundant — Tiers A and B
    /// are ambient, so no open prelude import is needed.
    #[test]
    fn tier_a_and_b_resolve_ambiently_without_import() {
        let src = "module Main exposing (main)\n\
                   \n\
                   wrap : Int -> Maybe (Result String (List Int))\n\
                   wrap n =\n\
                   \x20   if not (always False n) then\n\
                   \x20       Just (Ok [ identity n ])\n\
                   \x20   else\n\
                   \x20       Nothing\n\
                   \n\
                   main =\n\
                   \x20   case wrap 1 of\n\
                   \x20       Just _ -> LT\n\
                   \x20       Nothing -> GT\n";
        let opt = canon_src(src);
        assert!(
            opt.is_some(),
            "Tier-A/B names must canonicalise with no import line"
        );
    }

    /// ADR 0001 Tier B allows a local definition to shadow a core-vocabulary
    /// name without a diagnostic — a user `map` binds locally.
    #[test]
    fn tier_b_name_may_be_shadowed_locally() {
        let src = "module Main exposing (map)\n\
                   \n\
                   map : Int -> Int\n\
                   map n = n\n";
        let opt = canon_src(src);
        assert!(
            opt.is_some(),
            "a local `map` must shadow the ambient vocabulary without a diagnostic"
        );
    }

    /// ADR 0001 Tier C: a qualified reference to a module the compiler does not
    /// place in ambient scope fails to resolve (IPE-N0004) at its use site,
    /// never a silent success — the import list stays a complete inventory of a
    /// file's capabilities.
    #[test]
    fn tier_c_unimported_qualifier_is_unknown_module() {
        let err = canon_err("module Main exposing (main)\n\nmain = Widgets.render 0\n");
        let Some(Diagnostic::Name {
            msg: NameError::UnknownModule { qualifier, .. },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected UnknownModule (IPE-N0004)");
            return;
        };
        assert_eq!(&*qualifier, "Widgets");
    }

    /// ADR 0001 Tier C: a KNOWN stdlib qualifier (`Crypto`) used with no
    /// `import Ipe.Crypto` fires the teachable must-import diagnostic (IPE-N0034)
    /// naming the exact module to add — NOT a silent resolve against the
    /// pre-installed catalog, and NOT the generic unknown-module error.
    #[test]
    fn tier_c_known_unimported_qualifier_demands_its_import() {
        let err = canon_err("module Main exposing (main)\n\nmain = Crypto.sha256 \"x\"\n");
        let Some(Diagnostic::Name {
            msg:
                NameError::ImportRequired {
                    reached: StdlibReach::Qualifier(qualifier),
                    candidates,
                    imported_as: None,
                },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected ImportRequired (IPE-N0034)");
            return;
        };
        assert_eq!(&*qualifier, "Crypto");
        assert_eq!(&*candidates, &[Box::<str>::from("Ipe.Crypto")]);
    }

    /// The counterpart to the gate: WITH `import Ipe.Crypto`, the same qualified
    /// use resolves — so the diagnostic fires strictly on the missing import,
    /// never on a real, imported stdlib module.
    #[test]
    fn tier_c_qualifier_resolves_once_its_module_is_imported() {
        let opt = canon_src(
            "module Main exposing (main)\nimport Ipe.Crypto\n\nmain = Crypto.sha256 \"x\"\n",
        );
        assert!(
            opt.is_some(),
            "a Tier-C qualifier must resolve once its module is imported"
        );
    }

    #[test]
    fn unknown_constructor_pattern_is_constructor_not_found() {
        let src = "module Main exposing (main)\n\n\
                   type Msg = Increment | Decrement\n\n\
                   f x =\n    case x of\n        Incremen -> 0\n\n\
                   main = f Increment\n";
        let err = canon_err(src);
        let Some(Diagnostic::Name {
            msg: NameError::ConstructorNotFound { name, suggestions },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected ConstructorNotFound, got {err:?}");
            return;
        };
        assert_eq!(&*name, "Incremen");
        assert!(
            suggestions.names.iter().any(|s| &**s == "Increment"),
            "should suggest `Increment`, got {suggestions:?}"
        );
    }

    #[test]
    fn duplicate_value_points_at_both_spans() {
        let src = "module Main exposing (main)\n\nmain = 1\n\nmain = 2\n";
        let err = canon_err(src);
        let Some(Diagnostic::Name {
            span,
            msg: NameError::DuplicateValue { name, first },
        }) = err
        else {
            assert!(false_marker(), "expected DuplicateValue, got {err:?}");
            return;
        };
        assert_eq!(&*name, "main");
        // The second definition (primary) is strictly after the first.
        assert!(
            first.lo < span.lo,
            "first span {first:?} must precede the duplicate {span:?}"
        );
    }

    #[test]
    fn duplicate_type_points_at_both_spans() {
        let src = "module Main exposing (main)\n\n\
                   type Msg = A\n\ntype Msg = B\n\nmain = 0\n";
        let err = canon_err(src);
        let Some(Diagnostic::Name {
            span,
            msg: NameError::DuplicateType { name, first },
        }) = err
        else {
            assert!(false_marker(), "expected DuplicateType, got {err:?}");
            return;
        };
        assert_eq!(&*name, "Msg");
        assert!(first.lo < span.lo, "first span precedes duplicate");
    }

    #[test]
    fn user_type_shadowing_builtin_rejected() {
        // `Length` is a reserved built-in (`Ipe.Ui` nullary type) that the
        // lowerer matches ahead of the user-enum lookup; a user `type Length`
        // would be silently overridden, so canon must reject it (IPE-N0026).
        let src = "module Main exposing (main)\n\n\
                   type Length = Red | Green\n\nmain = 0\n";
        let err = canon_err(src);
        let Some(Diagnostic::Name {
            msg: NameError::ReservedBuiltinType { name },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected ReservedBuiltinType, got {err:?}");
            return;
        };
        assert_eq!(&*name, "Length");
    }

    #[test]
    fn non_reserved_user_type_still_compiles() {
        // A same-shaped ADT under a NON-reserved name must canonicalise cleanly —
        // the gate is scoped to reserved built-in names only.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\n\
             type Swatch = Red | Green\n\nmain = 0\n",
        );
        assert!(m.is_some(), "non-reserved `type Swatch` must canonicalise");
    }

    #[test]
    fn type_alias_shadowing_builtin_rejected() {
        // Aliases are gated identically — `type alias Html = String` shadows the
        // built-in `Ipe.Html.Html`, which the lowerer maps to `IrType::Ui`.
        let src = "module Main exposing (main)\n\n\
                   type alias Html = String\n\nmain = 0\n";
        let err = canon_err(src);
        let Some(Diagnostic::Name {
            msg: NameError::ReservedBuiltinType { name },
            ..
        }) = err
        else {
            assert!(
                false_marker(),
                "expected ReservedBuiltinType for the alias, got {err:?}"
            );
            return;
        };
        assert_eq!(&*name, "Html");
    }

    /// Kernel-implicit names (`Handler`, `Store`, …) are user-shadowable: their
    /// lowerer arms sit below the `enum_variants` guard so the user ADT wins.
    /// Both the resolve gate (`is_user_type_declaration_forbidden`) and the FFI
    /// shadow gate call the same predicate — they must agree.
    #[test]
    fn kernel_implicit_type_names_are_user_shadowable_at_resolve_gate() {
        let mut i = Interner::new();

        // `type Store = Store` — a user ADT whose name is a kernel-implicit
        // built-in; the lowerer arm for `Store` sits below `enum_variants`,
        // so the user ADT wins by its real home (safe).
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\ntype Store = Store\n\nmain = 0\n",
        );
        assert!(
            m.is_some(),
            "user `type Store` must canonicalise (kernel-implicit, user-shadowable)"
        );

        let mut i2 = Interner::new();
        // `type Handler a` — parametric user ADT; same reasoning.
        let m2 = canon_ok(
            &mut i2,
            "module Main exposing (main)\n\ntype Handler a = Wrap a\n\nmain = 0\n",
        );
        assert!(
            m2.is_some(),
            "user `type Handler a` must canonicalise (kernel-implicit, user-shadowable)"
        );
    }

    /// A genuinely reserved name (`HttpMethod`, `Connection`) is rejected at
    /// the resolve gate — its lowerer arm sits above `enum_variants`.
    #[test]
    fn genuinely_reserved_names_rejected_at_both_gates() {
        // `HttpMethod` — closed ADT with a fixed `IrType::HttpMethod` mapping.
        let err = canon_err("module Main exposing (main)\n\ntype HttpMethod = Get\n\nmain = 0\n");
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::ReservedBuiltinType { .. },
                    ..
                })
            ),
            "`type HttpMethod` must be rejected (IPE-N0026), got: {err:?}"
        );

        // `Connection` — reserved because the read-only-by-type security property
        // depends on canon rejecting user shadows.
        let err2 =
            canon_err("module Main exposing (main)\n\ntype Connection a = Conn a\n\nmain = 0\n");
        assert!(
            matches!(
                err2,
                Some(Diagnostic::Name {
                    msg: NameError::ReservedBuiltinType { .. },
                    ..
                })
            ),
            "`type Connection` must be rejected (IPE-N0026), got: {err2:?}"
        );
    }

    /// `is_user_type_declaration_forbidden` and `is_reserved_builtin_type_name`
    /// agree on RESERVED names (both true) and differ on kernel-implicit
    /// user-shadowable names (forbidden=false, reserved=true) — verifying the
    /// SSOT split.
    #[test]
    fn ssot_predicates_agree_on_reserved_differ_on_kernel_implicit() {
        // Reserved names: both predicates return true.
        for name in &["HttpMethod", "Connection", "Int", "Bool", "SqlValue"] {
            assert!(
                is_user_type_declaration_forbidden(name),
                "`{name}` must be user-declaration-forbidden"
            );
            assert!(
                is_reserved_builtin_type_name(name),
                "`{name}` must be a known builtin"
            );
        }

        // Kernel-implicit user-shadowable names: forbidden=false, builtin=true.
        for name in &["Handler", "Store", "Middleware", "Session", "VNode"] {
            assert!(
                !is_user_type_declaration_forbidden(name),
                "`{name}` must NOT be user-declaration-forbidden (user-shadowable)"
            );
            assert!(
                is_reserved_builtin_type_name(name),
                "`{name}` must still be a known builtin name"
            );
        }

        // Names both reserved and lowered by a fixed arm: forbidden and builtin.
        for name in &[
            "Html",
            "CustomElement",
            "Description",
            "HAlign",
            "LayoutContext",
            "Length",
            "Location",
            "PseudoClass",
            "VAlign",
            "WebReq",
        ] {
            assert!(
                is_user_type_declaration_forbidden(name),
                "`{name}` must be user-declaration-forbidden"
            );
            assert!(
                is_reserved_builtin_type_name(name),
                "`{name}` must be a known builtin"
            );
        }

        // Below-guard and kernel-implicit names: builtin, user-shadowable.
        for name in &["Order", "Color", "Decimal", "Value"] {
            assert!(
                !is_user_type_declaration_forbidden(name),
                "`{name}` must NOT be user-declaration-forbidden (user-shadowable)"
            );
            assert!(
                is_reserved_builtin_type_name(name),
                "`{name}` must still be a known builtin name"
            );
        }

        // Heads that live only at a module home are never bare builtins.
        for name in &["Claims", "Draft", "Cond", "RadioOption"] {
            assert!(
                !is_reserved_builtin_type_name(name),
                "`{name}` lives only at a module home"
            );
            assert!(
                !is_user_type_declaration_forbidden(name),
                "`{name}` lives only at a module home"
            );
        }
    }

    #[test]
    fn duplicate_constructor_across_unions_points_at_both_spans() {
        // Same constructor name `A` in two distinct unions.
        let src = "module Main exposing (main)\n\n\
                   type Foo = A\n\ntype Bar = A\n\nmain = 0\n";
        let err = canon_err(src);
        let Some(Diagnostic::Name {
            span,
            msg: NameError::DuplicateConstructor { name, first },
        }) = err
        else {
            assert!(false_marker(), "expected DuplicateConstructor, got {err:?}");
            return;
        };
        assert_eq!(&*name, "A");
        assert!(first.lo < span.lo, "first span precedes duplicate");
    }

    #[test]
    fn free_type_vars_ordered_by_name_not_symbol_id() {
        // Source order of the tyvars is `z`, `a`; an id-ordered result would be
        // `[z, a]`, but the name order is `[a, z]`.
        let src = "module Main exposing (main)\n\n\
                   f : z -> a -> z\nf x y = x\n\nmain = 0\n";
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i);
        assert!(parsed.is_ok(), "source parses");
        let Ok(srcm) = parsed else { return };
        let m = canonicalise(&srcm, &mut i);
        assert!(m.is_ok(), "canonicalises: {m:?}");
        let Ok(m) = m else { return };
        let def = m
            .defs
            .iter()
            .find(|d| i.resolve(d.name().value) == Some("f"));
        let Some(Def::Typed { free_vars, .. }) = def else {
            assert!(false_marker(), "f is a typed def");
            return;
        };
        let names: Vec<&str> = free_vars.iter().filter_map(|&v| i.resolve(v)).collect();
        assert_eq!(names, vec!["a", "z"], "free vars sorted by name");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stdlib import-alias registration.
    // ─────────────────────────────────────────────────────────────────────────

    /// Parse + canonicalise a single module through the MULTI-module entry
    /// (`canonicalise_module`) with no deps — the path the build driver uses for
    /// a project with a `package.ipe`, and the one that processes `import`
    /// declarations. Returns the canonical module + interner.
    fn canon_module_src(src: &str) -> Option<(ast::Module, Interner)> {
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i).ok()?;
        let expected: Vec<Symbol> = parsed.name.value.clone();
        let deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let (m, _exports) = canonicalise_module(&parsed, &expected, &deps, &mut i).ok()?;
        Some((m, i))
    }

    /// Assert the body of `main` is a bare `Qualifier.member` reference resolving
    /// to a kernel with the given canonical module + name.
    fn assert_main_is_kernel(m: &ast::Module, i: &Interner, module: &str, name: &str) {
        let Some(Def::Untyped { body, .. }) = find_def(m, i, "main") else {
            assert!(false_marker(), "main should be an untyped def");
            return;
        };
        let Expr_::VarKernel {
            module: mo,
            name: na,
            ..
        } = &body.value
        else {
            assert!(
                false_marker(),
                "main body should be a kernel reference, got {:?}",
                body.value
            );
            return;
        };
        assert_eq!(i.resolve(*mo), Some(module), "kernel module");
        assert_eq!(i.resolve(*na), Some(name), "kernel name");
    }

    #[test]
    fn stdlib_alias_registers_multisegment_json_encode() {
        // A multi-segment aliased import (`import Ipe.Json.Encode as Encode`)
        // registers the alias against the canonical `JsonEnc`, so `Encode.string`
        // resolves rather than erroring IPE-N0004 (unknown module `Encode`).
        let src = "module Main exposing (main)\n\
                   import Ipe.Json.Encode as Encode\n\n\
                   main = Encode.string\n";
        let Some((m, i)) = canon_module_src(src) else {
            assert!(false_marker(), "aliased stdlib import must canonicalise");
            return;
        };
        assert_main_is_kernel(&m, &i, "JsonEnc", "string");
    }

    #[test]
    fn stdlib_alias_registers_multisegment_json_decode_pipeline() {
        // Deepest path (5 segments) → canonical `JsonDecP`.
        let src = "module Main exposing (main)\n\
                   import Ipe.Json.Decode.Pipeline as P\n\n\
                   main = P.required\n";
        let Some((m, i)) = canon_module_src(src) else {
            assert!(false_marker(), "aliased pipeline import must canonicalise");
            return;
        };
        assert_main_is_kernel(&m, &i, "JsonDecP", "required");
    }

    #[test]
    fn stdlib_alias_registers_std_module() {
        // Completeness: a kernel-qualifier `Ipe.*` module aliased to a name
        // differing from both the last segment and the canonical qualifier.
        let src = "module Main exposing (main)\n\
                   import Ipe.System as S\n\n\
                   main = S.getenv\n";
        let Some((m, i)) = canon_module_src(src) else {
            assert!(
                false_marker(),
                "aliased Ipe.System import must canonicalise"
            );
            return;
        };
        assert_main_is_kernel(&m, &i, "System", "getenv");
    }

    #[test]
    fn stdlib_import_no_as_uses_last_segment() {
        // No `as`: Elm exposes the module under its LAST path segment. Here the
        // last segment (`Encode`) differs from the canonical qualifier
        // (`JsonEnc`), so the fix must register `Encode`, not only `JsonEnc`.
        let src = "module Main exposing (main)\n\
                   import Ipe.Json.Encode\n\n\
                   main = Encode.string\n";
        let Some((m, i)) = canon_module_src(src) else {
            assert!(false_marker(), "no-as stdlib import must canonicalise");
            return;
        };
        assert_main_is_kernel(&m, &i, "JsonEnc", "string");
    }

    #[test]
    fn stdlib_alias_works_on_single_module_path() {
        // The single-module `canonicalise` entry also registers stdlib aliases
        // (it previously ignored imports entirely).
        let src = "module Main exposing (main)\n\
                   import Ipe.Json.Encode as Encode\n\n\
                   main = Encode.int\n";
        let mut i = Interner::new();
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            assert!(false_marker(), "parse");
            return;
        };
        let Ok(m) = canonicalise(&parsed, &mut i) else {
            assert!(false_marker(), "single-module canonicalise must succeed");
            return;
        };
        assert_main_is_kernel(&m, &i, "JsonEnc", "int");
    }

    #[test]
    fn random_is_not_a_kernel_qualifier() {
        // `Ipe.Random` is COMPILED-SOURCE (`ipe::stdlib::COMPILED_STD_MODULES`),
        // so it must NOT appear in the kernel-qualifier catalog — the disjointness
        // invariant. Its whole surface (`int`/`float`/`range`/`choice`/`shuffle`/
        // `weighted`/the seeded helpers/the `Seed` ADT) resolves from
        // `Ipe/Random.ipe`, exercised end-to-end by the `random_members` golden.
        assert!(
            !crate::env::STDLIB_MODULE_QUALIFIERS
                .iter()
                .any(|(path, canonical)| *path == ["Ipe", "Random"] || *canonical == "Random"),
            "Ipe.Random must not be a kernel qualifier — it is compiled-source",
        );
    }

    #[test]
    fn unknown_stdlib_alias_stays_fail_closed() {
        // A `Ipê.*` path that names no kernel module and no dep is rejected AT
        // the import with ModuleNotFound (IPE-N0020) — the fail-closed boundary,
        // never a silently-dropped import deferred to a use-site error.
        let src = "module Main exposing (main)\n\
                   import Ipe.Nonexistent as N\n\n\
                   main = N.foo\n";
        let mut i = Interner::new();
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            assert!(false_marker(), "parse");
            return;
        };
        let deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let expected = parsed.name.value.clone();
        let err = canonicalise_module(&parsed, &expected, &deps, &mut i).err();
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::ModuleNotFound { .. },
                    ..
                })
            ),
            "unknown stdlib import must fail closed with ModuleNotFound, got {err:?}"
        );
    }

    #[test]
    fn prelude_module_alias_is_removed() {
        // ADR 0001: `Ipe.Prelude` is REMOVED — not a retained alias for
        // `Ipe.Basics`. It names no kernel qualifier and no embedded source, so
        // the import itself fails closed with ModuleNotFound (IPE-N0020), exactly
        // like any other nonexistent `Ipe.*` module. This proves the old
        // value-flood alias no longer resolves.
        let src = "module Main exposing (main)\n\
                   import Ipe.Prelude as P\n\n\
                   main = P.identity\n";
        let mut i = Interner::new();
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            assert!(false_marker(), "parse");
            return;
        };
        let deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let expected = parsed.name.value.clone();
        let err = canonicalise_module(&parsed, &expected, &deps, &mut i).err();
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::ModuleNotFound { .. },
                    ..
                })
            ),
            "removed `Ipe.Prelude` must fail closed with ModuleNotFound, got {err:?}"
        );
    }

    #[test]
    fn stdlib_module_paths_target_a_known_qualifier() {
        // Anti-drift (no dangling target): every canonical named in the path
        // table is a real registered qualifier, and every path is `Ipê.*`/`Ipe.*`.
        let mut i = Interner::new();
        let home = vec![i.intern("Main").expect("intern Main")];
        let env = Env::initial(home, &mut i).expect("build env");
        for (path, canonical) in crate::env::STDLIB_MODULE_QUALIFIERS {
            assert!(
                matches!(path.first(), Some(&"Ipe")),
                "path {path:?} must start with Ipe or Std"
            );
            let sym = i.intern(canonical).expect("intern canonical");
            assert!(
                env.kernel_module_of(sym).is_some(),
                "canonical `{canonical}` for path {path:?} is not a registered kernel module"
            );
        }
    }

    #[test]
    fn every_canonical_qualifier_has_an_import_path() {
        // Anti-drift (total coverage): every PRIMARY qualifier the registry
        // defines is reachable via at least one import path, so a new kernel
        // module cannot ship without an `import … as Alias` route.
        //
        // Primary qualifiers are the bare short-names (no `.`) plus the sole
        // dotted canonical `Db.Decode`; the other dotted kernel-pool keys are the
        // inline-qualifier convenience aliases (`Ipe.Html`, …), not import targets.
        //
        // The canonical `Cmd` / `Sub` kernel qualifiers are internal-only: they
        // back the shape-scoped re-export modules (`Ipe.Tea.Web.Cmd`, …) but are
        // themselves not user-importable, so they deliberately carry no import
        // path. Users reach `Cmd` / `Sub` through a shape, which does have one.
        const INTERNAL_ONLY_QUALIFIERS: &[&str] = &["Cmd", "Sub"];
        let mut i = Interner::new();
        let home = vec![i.intern("Main").expect("intern Main")];
        let env = Env::initial(home, &mut i).expect("build env");
        let targets: BTreeSet<&str> = crate::env::STDLIB_MODULE_QUALIFIERS
            .iter()
            .map(|(_, c)| *c)
            .collect();
        for key in env.kernel_members.keys().map(|module| module.symbol()) {
            let Some(name) = i.resolve(key) else { continue };
            if INTERNAL_ONLY_QUALIFIERS.contains(&name) {
                continue;
            }
            let is_primary = !name.contains('.') || name == "Db.Decode";
            if is_primary {
                assert!(
                    targets.contains(name),
                    "canonical qualifier `{name}` has no STDLIB_MODULE_QUALIFIERS \
                     import path — add one so `import …Path… as Alias` can register it"
                );
            }
        }
    }

    /// A runtime `false` the optimiser cannot fold, so `assert!(false_marker())`
    /// fails the test (the desired "wrong variant" signal) without tripping
    /// `clippy::assertions_on_constants`, which fires on a literal `false`.
    fn false_marker() -> bool {
        std::hint::black_box(false)
    }

    /// Stand-alone Levenshtein for the ordering assertion, kept separate from
    /// the production helper (which is private to `resolve`).
    fn test_levenshtein(a: &str, b: &str) -> usize {
        let bc: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=bc.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut curr = vec![i + 1];
            let mut diag = i;
            for (cb, &up) in bc.iter().zip(prev.iter().skip(1)) {
                let cost = usize::from(ca != *cb);
                let left = curr.last().copied().unwrap_or(i + 1);
                curr.push((up + 1).min(left + 1).min(diag + cost));
                diag = up;
            }
            prev = curr;
        }
        prev.last().copied().unwrap_or(0)
    }

    /// Parse + canonicalise a free-standing module body, returning the resolved
    /// body expression of the binding named `which`.
    fn canon_body(i: &mut Interner, source: &str, which: &str) -> Option<Expr_> {
        let src = ipe_parse::parse_module(source, i).ok()?;
        let m = canonicalise(&src, i).ok()?;
        let def = find_def(&m, i, which)?;
        match def {
            Def::Typed { body, .. } | Def::Untyped { body, .. } => Some(body.value.clone()),
        }
    }

    /// Destructure a resolved binop into `(func-name, lhs, rhs)`.
    fn as_binop<'a>(i: &Interner, e: &'a Expr_) -> Option<(String, &'a Expr, &'a Expr)> {
        match e {
            Expr_::Binop { func, lhs, rhs, .. } => Some((i.resolve(*func)?.to_owned(), lhs, rhs)),
            _ => None,
        }
    }

    #[test]
    fn mul_binds_tighter_than_add() {
        // `2 + 3 * 4` must associate as `add(2, mul(3, 4))`, never `mul(add(2,3), 4)`.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (v)\nv : Int\nv =\n    2 + 3 * 4\n",
            "v",
        );
        assert!(body.is_some(), "v must canonicalise");
        let Some(body) = body else { return };
        let top = as_binop(&i, &body);
        assert!(top.is_some(), "top is a binop");
        let Some((top, lhs, rhs)) = top else { return };
        assert_eq!(top, "add", "outer op is +");
        assert!(matches!(lhs.value, Expr_::Int(2)), "lhs is literal 2");
        let inner = as_binop(&i, &rhs.value);
        assert!(inner.is_some(), "rhs is the * subtree");
        let Some((inner, il, ir)) = inner else { return };
        assert_eq!(inner, "mul", "inner op is *");
        assert!(matches!(il.value, Expr_::Int(3)));
        assert!(matches!(ir.value, Expr_::Int(4)));
    }

    #[test]
    fn left_associative_subtraction_chains_left() {
        // `10 - 3 - 2` is `sub(sub(10, 3), 2)` (left-assoc), not `sub(10, sub(3, 2))`.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (v)\nv : Int\nv =\n    10 - 3 - 2\n",
            "v",
        );
        assert!(body.is_some(), "v must canonicalise");
        let Some(body) = body else { return };
        let top = as_binop(&i, &body);
        assert!(top.is_some(), "top is a binop");
        let Some((top, lhs, rhs)) = top else { return };
        assert_eq!(top, "sub");
        assert!(
            matches!(rhs.value, Expr_::Int(2)),
            "rhs is the last operand"
        );
        assert_eq!(
            as_binop(&i, &lhs.value).map(|t| t.0),
            Some("sub".to_owned())
        );
    }

    #[test]
    fn comparison_below_arithmetic_and_above_boolean() {
        // `n > 10 && n < 100` ⇒ `and(gt(n, 10), lt(n, 100))`: `&&` is the root,
        // each comparison its own subtree (comparison binds tighter than `&&`).
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (f)\nf : Int -> Bool\nf n =\n    n > 10 && n < 100\n",
            "f",
        );
        assert!(body.is_some(), "f must canonicalise");
        let Some(body) = body else { return };
        let top = as_binop(&i, &body);
        assert!(top.is_some(), "top is a binop");
        let Some((top, lhs, rhs)) = top else { return };
        assert_eq!(top, "and", "root is &&");
        assert_eq!(as_binop(&i, &lhs.value).map(|t| t.0), Some("gt".to_owned()));
        assert_eq!(as_binop(&i, &rhs.value).map(|t| t.0), Some("lt".to_owned()));
    }

    #[test]
    fn parenthesised_group_is_not_reassociated() {
        // `(2 + 3) * 4` ⇒ `mul(add(2, 3), 4)`. Parens override precedence.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (v)\nv : Int\nv =\n    (2 + 3) * 4\n",
            "v",
        );
        assert!(body.is_some(), "v must canonicalise");
        let Some(body) = body else { return };
        let top = as_binop(&i, &body);
        assert!(top.is_some(), "top is a binop");
        let Some((top, lhs, rhs)) = top else { return };
        assert_eq!(top, "mul", "root is *");
        assert!(matches!(rhs.value, Expr_::Int(4)));
        assert_eq!(
            as_binop(&i, &lhs.value).map(|t| t.0),
            Some("add".to_owned())
        );
    }

    #[test]
    fn or_is_right_associative() {
        // `a || b || c` ⇒ `or(a, or(b, c))` (right-assoc, prec 2).
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (f)\nf : Bool -> Bool -> Bool -> Bool\nf a b c =\n    a || b || c\n",
            "f",
        );
        assert!(body.is_some(), "f must canonicalise");
        let Some(body) = body else { return };
        let top = as_binop(&i, &body);
        assert!(top.is_some(), "top is a binop");
        let Some((top, lhs, rhs)) = top else { return };
        assert_eq!(top, "or");
        assert!(
            matches!(lhs.value, Expr_::VarLocal(_)),
            "lhs is the lone `a`"
        );
        assert_eq!(as_binop(&i, &rhs.value).map(|t| t.0), Some("or".to_owned()));
    }

    #[test]
    fn append_is_right_associative_and_maps_to_append_kernel() {
        // `a ++ b ++ c` ⇒ `append(a, append(b, c))` (right-assoc, prec 5), and
        // the `++` operator resolves to the `append` kernel.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (f)\nf : String -> String -> String -> String\nf a b c =\n    a ++ b ++ c\n",
            "f",
        );
        assert!(body.is_some(), "f must canonicalise");
        let Some(body) = body else { return };
        let top = as_binop(&i, &body);
        assert!(top.is_some(), "top is a binop");
        let Some((top, lhs, rhs)) = top else { return };
        assert_eq!(top, "append", "`++` resolves to the append kernel");
        assert!(
            matches!(lhs.value, Expr_::VarLocal(_)),
            "lhs is the lone `a` (right-assoc keeps the tail nested)"
        );
        assert_eq!(
            as_binop(&i, &rhs.value).map(|t| t.0),
            Some("append".to_owned()),
            "the right operand is itself an append"
        );
    }

    #[test]
    fn let_binds_names_as_locals() {
        // `let x = 2 in x + x` → a `Let` whose in-body is a Binop over the
        // let-bound local `x`.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (v)\nv : Int\nv =\n    let x = 2 in x + x\n",
            "v",
        );
        assert!(body.is_some(), "v must canonicalise");
        let Some(Expr_::Let(bindings, in_body)) = body else {
            assert!(false_marker(), "v body is a Let");
            return;
        };
        assert_eq!(bindings.len(), 1, "one binding");
        assert!(
            bindings.first().is_some_and(|b| matches!(
                &b.pat.value,
                Pattern_::PVar(s) if i.resolve(*s) == Some("x")
            )),
            "binding name is x"
        );
        let Some((func, lhs, rhs)) = as_binop(&i, &in_body.value) else {
            assert!(false_marker(), "in-body is a binop");
            return;
        };
        assert_eq!(func, "add");
        assert!(matches!(lhs.value, Expr_::VarLocal(s) if i.resolve(s) == Some("x")));
        assert!(matches!(rhs.value, Expr_::VarLocal(s) if i.resolve(s) == Some("x")));
    }

    #[test]
    fn let_later_binding_sees_earlier() {
        // Sequential (`let*`) scoping: `b = a` resolves `a` to the earlier
        // let-bound local, not to an error.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (v)\nv : Int\nv =\n    let\n        a = 1\n        b = a\n    in\n    b\n",
            "v",
        );
        assert!(body.is_some(), "v must canonicalise");
        let Some(Expr_::Let(bindings, _)) = body else {
            assert!(false_marker(), "v body is a Let");
            return;
        };
        let second = bindings.get(1);
        assert!(
            second.is_some_and(
                |b| matches!(b.body.value, Expr_::VarLocal(s) if i.resolve(s) == Some("a"))
            ),
            "the second binding's value resolves `a` to a local"
        );
    }

    #[test]
    fn if_resolves_conditions_and_branches() {
        // `if x > 0 then x else 0` over a parameter `x`: the condition and both
        // branches resolve against the same scope (the parameter is in scope in
        // each). `if` introduces no bindings.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (f)\nf : Int -> Int\nf x =\n    if x > 0 then x else 0\n",
            "f",
        );
        assert!(body.is_some(), "f must canonicalise");
        let Some(Expr_::If(branches, els)) = body else {
            assert!(false_marker(), "f body is an If");
            return;
        };
        assert_eq!(branches.len(), 1, "one `(cond, branch)` pair");
        let Some((cond, branch)) = branches.first() else {
            assert!(false_marker(), "the pair is present");
            return;
        };
        // The condition is `x > 0` — a binop reading the local `x`.
        let Some((func, lhs, _)) = as_binop(&i, &cond.value) else {
            assert!(false_marker(), "cond is a binop");
            return;
        };
        assert_eq!(func, "gt", "condition op is >");
        assert!(matches!(lhs.value, Expr_::VarLocal(s) if i.resolve(s) == Some("x")));
        // The `then` branch reads the same local; the `else` is the literal 0.
        assert!(matches!(branch.value, Expr_::VarLocal(s) if i.resolve(s) == Some("x")));
        assert!(matches!(els.value, Expr_::Int(0)));
    }

    #[test]
    fn let_forward_reference_rejects_cleanly() {
        // `y = x` before `x = 2`: with sequential scoping `x` is not yet bound
        // and there is no outer `x`, so it resolves to nothing — a clean
        // ValueNotFound, never a miscompile.
        let err = canon_err(
            "module Main exposing (v)\nv : Int\nv =\n    let\n        y = x\n        x = 2\n    in\n    y\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::ValueNotFound { .. },
                    ..
                })
            ),
            "forward reference must reject as ValueNotFound, got {err:?}"
        );
    }

    #[test]
    fn tuple_canonicalises_element_wise() {
        // `(1, x)` resolves each element against the enclosing scope; the second
        // element is the parameter `x`, bound to a local.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (v)\nv : Int -> Int\nv x =\n    (1, x)\n",
            "v",
        );
        assert!(body.is_some(), "v must canonicalise");
        let Some(body) = body else { return };
        assert!(
            matches!(&body, Expr_::Tuple(es)
                if es.len() == 2
                    && matches!(es.first().map(|e| &e.value), Some(Expr_::Int(1)))
                    && matches!(es.get(1).map(|e| &e.value), Some(Expr_::VarLocal(_)))),
            "(1, x) resolves to a 2-tuple of Int and a local, got {body:?}"
        );
    }

    #[test]
    fn record_literal_canonicalises_field_wise() {
        // `{ x = 1, y = a }` resolves each field value against scope; the second
        // is the parameter `a`, a local. Field labels are carried unresolved.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (v)\nv : Int -> Int\nv a =\n    { x = 1, y = a }\n",
            "v",
        );
        assert!(body.is_some(), "v must canonicalise");
        let Some(body) = body else { return };
        assert!(
            matches!(&body, Expr_::Record(fields)
                if fields.len() == 2
                    && matches!(fields.first().map(|(_, e)| &e.value), Some(Expr_::Int(1)))
                    && matches!(fields.get(1).map(|(_, e)| &e.value), Some(Expr_::VarLocal(_)))),
            "`{{ x = 1, y = a }}` resolves to a 2-field Record, got {body:?}"
        );
    }

    #[test]
    fn field_access_canonicalises_over_its_record() {
        // `p.x` resolves the record sub-expression (the local `p`); the field is
        // a label carried unresolved.
        let mut i = Interner::new();
        let body = canon_body(&mut i, "module Main exposing (v)\nv p =\n    p.x\n", "v");
        assert!(body.is_some(), "v must canonicalise");
        let Some(body) = body else { return };
        assert!(
            matches!(&body, Expr_::Access(rec, field)
                if matches!(rec.value, Expr_::VarLocal(_)) && i.resolve(*field) == Some("x")),
            "`p.x` resolves to an Access over a local, got {body:?}"
        );
    }

    #[test]
    fn record_update_canonicalises_base_and_fields() {
        // `{ p | x = 41 }` resolves the base `p` (the parameter, a local) and the
        // updated field value; the field name is a label carried unresolved.
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (v)\nv p =\n    { p | x = 41 }\n",
            "v",
        );
        assert!(body.is_some(), "v must canonicalise");
        let Some(body) = body else { return };
        assert!(
            matches!(&body, Expr_::Update(base, fields)
                if matches!(base.value, Expr_::VarLocal(_))
                    && fields.len() == 1
                    && matches!(fields.first().map(|(_, e)| &e.value), Some(Expr_::Int(41)))),
            "`{{ p | x = 41 }}` resolves to an Update over a local, got {body:?}"
        );
    }

    #[test]
    fn duplicate_record_update_field_is_rejected() {
        // `{ p | x = 1, x = 2 }` updates `x` twice — rejected (IPE-N0010), as on
        // a record literal.
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(
            "module Main exposing (v)\nv p =\n    { p | x = 1, x = 2 }\n",
            &mut i,
        );
        assert!(src.is_ok(), "must parse");
        let Ok(src) = src else { return };
        let r = canonicalise(&src, &mut i);
        assert!(
            matches!(
                r,
                Err(ipe_diagnostics::Diagnostic::Name {
                    msg: ipe_diagnostics::NameError::DuplicateValue { .. },
                    ..
                })
            ),
            "duplicate update field must be a DuplicateValue, got {r:?}"
        );
    }

    #[test]
    fn duplicate_record_field_is_rejected() {
        // `{ x = 1, x = 2 }` defines `x` twice — rejected (IPE-N0010) rather than
        // silently collapsing to one field.
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(
            "module Main exposing (v)\nv =\n    { x = 1, x = 2 }\n",
            &mut i,
        );
        assert!(src.is_ok(), "must parse");
        let Ok(src) = src else { return };
        let r = canonicalise(&src, &mut i);
        assert!(
            matches!(
                r,
                Err(ipe_diagnostics::Diagnostic::Name {
                    msg: ipe_diagnostics::NameError::DuplicateValue { .. },
                    ..
                })
            ),
            "duplicate record field must be a DuplicateValue, got {r:?}"
        );
    }

    #[test]
    fn env_var_homes_compare() {
        // Exercise the VarHome surface for PartialEq coverage.
        assert_eq!(VarHome::Local, VarHome::Local);
        let m: Vec<Symbol> = vec![Symbol::from_raw(1)];
        assert_ne!(VarHome::TopLevel(m.clone()), VarHome::Local);
        assert_eq!(VarHome::TopLevel(m.clone()), VarHome::TopLevel(m));
    }

    // ---- type aliases (B2) ------------------------------------------------

    /// Parse `source` and canonicalise it, returning the module on success.
    fn canon_ok(i: &mut Interner, source: &str) -> Option<ast::Module> {
        let src = ipe_parse::parse_module(source, i).ok()?;
        canonicalise(&src, i).ok()
    }

    /// The annotation type of a named typed def, cloned for inspection.
    fn typed_ann(m: &ast::Module, i: &Interner, name: &str) -> Option<ast::Type> {
        match find_def(m, i, name)? {
            Def::Typed { ty, .. } => Some(ty.clone()),
            Def::Untyped { .. } => None,
        }
    }

    #[test]
    fn non_parametric_alias_expands_to_its_body() {
        // `type alias Count = Int` then `inc : Count -> Count` must canonicalise
        // exactly as if written `inc : Int -> Int` — the alias is gone.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (inc)\n\
             type alias Count = Int\n\n\
             inc : Count -> Count\n\
             inc n =\n    n\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        let ty = typed_ann(&m, &i, "inc");
        let Some(ast::Type::Lambda(arg, rest)) = ty else {
            assert!(false_marker(), "inc annotation is an arrow");
            return;
        };
        // Both sides are `Int` (a built-in con, empty home) — no `Count` survives.
        for side in [arg.as_ref(), rest.as_ref()] {
            let ast::Type::Con { name, home, args } = side else {
                assert!(false_marker(), "alias expanded to a constructor type");
                return;
            };
            assert_eq!(i.resolve(*name), Some("Int"));
            assert!(home.is_empty(), "Int is a built-in: empty home");
            assert!(args.is_empty());
        }
    }

    #[test]
    fn chained_alias_expands_through() {
        // `B = A`, `A = Int`: a reference to `B` expands through `A` to `Int`.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (v)\n\
             type alias A = Int\n\
             type alias B = A\n\n\
             v : B\n\
             v =\n    0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        let ty = typed_ann(&m, &i, "v");
        let Some(ast::Type::Con { name, home, .. }) = ty else {
            assert!(false_marker(), "v annotation is a constructor type");
            return;
        };
        assert_eq!(i.resolve(name), Some("Int"));
        assert!(home.is_empty());
    }

    #[test]
    fn alias_to_local_union_preserves_home() {
        // An alias whose body names a local union keeps that union's home, so the
        // expansion is identical to naming the union directly.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (v)\n\
             type Color = Red | Green\n\
             type alias C = Color\n\n\
             v : C -> Int\n\
             v c =\n    0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        let ty = typed_ann(&m, &i, "v");
        let Some(ast::Type::Lambda(arg, _)) = ty else {
            assert!(false_marker(), "v annotation is an arrow");
            return;
        };
        let ast::Type::Con { name, home, .. } = arg.as_ref() else {
            assert!(false_marker(), "arg is a constructor type");
            return;
        };
        assert_eq!(i.resolve(*name), Some("Color"));
        assert_eq!(home.first().and_then(|&s| i.resolve(s)), Some("Main"));
    }

    #[test]
    fn parametric_alias_substitutes_and_expands() {
        // `type alias Pair a = (a, a)` applied as `Pair Int` must expand, with
        // the parameter `a` substituted by `Int`, to the tuple `(Int, Int)` —
        // exactly as if the annotation read `(Int, Int) -> Int`. No `Pair` and no
        // free `a` survive.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (addPair)\n\
             type alias Pair a = (a, a)\n\n\
             addPair : Pair Int -> Int\n\
             addPair p =\n    0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        // The binding generalises over nothing — `a` was bound to `Int`.
        let Some(Def::Typed { free_vars, .. }) = find_def(&m, &i, "addPair") else {
            assert!(false_marker(), "addPair is a typed def");
            return;
        };
        assert!(free_vars.is_empty(), "no free type variable survives");
        let Some(ast::Type::Lambda(arg, _)) = typed_ann(&m, &i, "addPair") else {
            assert!(false_marker(), "addPair annotation is an arrow");
            return;
        };
        let ast::Type::Tuple(elems) = arg.as_ref() else {
            assert!(false_marker(), "argument expanded to a tuple");
            return;
        };
        assert_eq!(elems.len(), 2, "Pair expands to a 2-tuple");
        for e in elems {
            let ast::Type::Con { name, home, args } = e else {
                assert!(false_marker(), "each tuple member is `Int`");
                return;
            };
            assert_eq!(i.resolve(*name), Some("Int"));
            assert!(
                home.is_empty() && args.is_empty(),
                "Int is a nullary builtin"
            );
        }
    }

    #[test]
    fn parametric_alias_keeps_a_free_argument_variable() {
        // `Pair a` applied to a *variable* argument (`Pair b`) leaves `b` free, so
        // the binding generalises over it: `f : Pair b -> b` is `(b, b) -> b`.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (f)\n\
             type alias Pair a = (a, a)\n\n\
             f : Pair b -> b\n\
             f p =\n    p\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        let Some(Def::Typed { free_vars, .. }) = find_def(&m, &i, "f") else {
            assert!(false_marker(), "f is a typed def");
            return;
        };
        let names: Vec<_> = free_vars.iter().filter_map(|s| i.resolve(*s)).collect();
        assert_eq!(names, vec!["b"], "the argument variable `b` stays free");
    }

    #[test]
    fn alias_applied_with_too_many_arguments_is_an_arity_error() {
        // `Pair` declares one parameter; `Pair Int Bool` supplies two — a coded
        // IPE-N0013 arity error with a span, never a crash.
        let err = canon_err(
            "module Main exposing (v)\n\
             type alias Pair a = (a, a)\n\n\
             v : Pair Int Bool\n\
             v =\n    0\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::AliasArity {
                        expected: 1,
                        found: 2,
                        ..
                    },
                    ..
                })
            ),
            "expected an AliasArity Name diagnostic (1 expected, 2 found), got {err:?}"
        );
    }

    #[test]
    fn parametric_alias_under_applied_is_an_arity_error() {
        // A bare `Pair` supplies zero arguments to a one-parameter alias — a type
        // alias must be fully applied, so this is an arity error, not an opaque
        // constructor.
        let err = canon_err(
            "module Main exposing (v)\n\
             type alias Pair a = (a, a)\n\n\
             v : Pair\n\
             v =\n    0\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::AliasArity {
                        expected: 1,
                        found: 0,
                        ..
                    },
                    ..
                })
            ),
            "expected an AliasArity Name diagnostic (1 expected, 0 found), got {err:?}"
        );
    }

    #[test]
    fn unparenthesised_nested_container_is_a_builtin_arity_error() {
        // `Maybe List Int` parses as `Maybe` over TWO args (`List`, `Int`) with
        // `List` itself nullary — the exact shape that ICE'd the lowerer
        // (IPE-I0001, empty-home `List`). Arguments canonicalise depth-first, so
        // the bare `List` is caught first: a clean IPE-N0031 pointing straight
        // at the constructor missing its element type. (Were `List` well-formed,
        // the over-applied `Maybe` would then be rejected — either way the ICE
        // is unreachable.)
        let err = canon_err(
            "module Main exposing (v)\n\
             v : Maybe List Int\n\
             v =\n    Nothing\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::BuiltinTypeArity {
                        ref name,
                        expected: 1,
                        found: 0,
                    },
                    ..
                }) if name.as_ref() == "List"
            ),
            "expected a BuiltinTypeArity(List, 1, 0) diagnostic, got {err:?}"
        );
    }

    #[test]
    fn over_applied_maybe_is_a_builtin_arity_error() {
        // Well-formed inner, over-applied outer: `Maybe (List Int) Bool` gives
        // `Maybe` two arguments. The inner `(List Int)` passes, so the outer
        // over-application is the caught error.
        let err = canon_err(
            "module Main exposing (v)\n\
             v : Maybe (List Int) Bool\n\
             v =\n    Nothing\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::BuiltinTypeArity {
                        ref name,
                        expected: 1,
                        found: 2,
                    },
                    ..
                }) if name.as_ref() == "Maybe"
            ),
            "expected a BuiltinTypeArity(Maybe, 1, 2) diagnostic, got {err:?}"
        );
    }

    #[test]
    fn under_applied_dict_is_a_builtin_arity_error() {
        // `Dict` takes two arguments; `Dict String` supplies one.
        let err = canon_err(
            "module Main exposing (v)\n\
             v : Dict String\n\
             v =\n    Nothing\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::BuiltinTypeArity {
                        ref name,
                        expected: 2,
                        found: 1,
                    },
                    ..
                }) if name.as_ref() == "Dict"
            ),
            "expected a BuiltinTypeArity(Dict, 2, 1) diagnostic, got {err:?}"
        );
    }

    #[test]
    fn parenthesised_nested_container_stays_well_formed() {
        // The fix must not reject the correct spelling — `Maybe (List Int)` is
        // `Maybe` over exactly one argument.
        let err = canon_err(
            "module Main exposing (v)\n\
             v : Maybe (List Int)\n\
             v =\n    Nothing\n",
        );
        assert!(
            !matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::BuiltinTypeArity { .. },
                    ..
                })
            ),
            "well-formed `Maybe (List Int)` must not trip IPE-N0031, got {err:?}"
        );
    }

    #[test]
    fn duplicate_alias_name_is_a_duplicate_type() {
        let err = canon_err(
            "module Main exposing (v)\n\
             type alias X = Int\n\
             type alias X = Bool\n\n\
             v : Int\n\
             v =\n    0\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::DuplicateType { .. },
                    ..
                })
            ),
            "expected DuplicateType, got {err:?}"
        );
    }

    #[test]
    fn alias_colliding_with_a_union_is_a_duplicate_type() {
        let err = canon_err(
            "module Main exposing (v)\n\
             type Color = Red\n\
             type alias Color = Int\n\n\
             v : Int\n\
             v =\n    0\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::DuplicateType { .. },
                    ..
                })
            ),
            "expected DuplicateType, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------
    // A LOCAL `type X` / `type alias X` shadowing a dep-imported `X`
    // must be rejected at the declaration with IPE-N0012 (`DuplicateType`),
    // not a downstream IPE-T0001. See `canonicalise_with_env`'s dep-shadow
    // pre-pass and docs/adr/0002-codegen-soundness-and-the-seal.md
    // (item D).
    // ---------------------------------------------------------------------

    /// Canonicalise a `Dep` source (no deps of its own), then canonicalise a
    /// `Main` source with `Dep`'s exports available for import. Returns the
    /// diagnostic (if any) from canonicalising `Main`. Returns `None` from the
    /// parse/Dep-canon steps rather than panicking, per the no-panic gate.
    fn canon_main_with_dep(dep_src: &str, main_src: &str) -> Option<Diagnostic> {
        let mut i = Interner::new();
        let dep_parsed = ipe_parse::parse_module(dep_src, &mut i).ok()?;
        let dep_expected = dep_parsed.name.value.clone();
        let empty: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let (_dep_m, dep_exports) =
            canonicalise_module(&dep_parsed, &dep_expected, &empty, &mut i).ok()?;

        let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        deps.insert(dep_exports.path.clone(), dep_exports);

        let main_parsed = ipe_parse::parse_module(main_src, &mut i).ok()?;
        let main_expected = main_parsed.name.value.clone();
        canonicalise_module(&main_parsed, &main_expected, &deps, &mut i).err()
    }

    #[test]
    fn local_type_shadowing_dep_imported_type_is_duplicate_type() {
        let err = canon_main_with_dep(
            "module Dep exposing (Color(..))\n\
             type Color = Red | Green | Blue\n",
            "module Main exposing (main)\n\
             import Dep exposing (Color(..))\n\n\
             type Color = Warm | Cool\n\n\
             describe : Color -> String\n\
             describe c =\n    case c of\n        Warm -> \"warm\"\n        Cool -> \"cool\"\n\n\
             main =\n    describe Warm\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::DuplicateType { .. },
                    ..
                })
            ),
            "local `type Color` shadowing imported Dep.Color must be a \
             DuplicateType (IPE-N0012) at the declaration, got {err:?}"
        );
    }

    #[test]
    fn local_type_alias_shadowing_dep_imported_type_is_duplicate_type() {
        // Same shape, but the LOCAL declaration is a `type alias`, proving the
        // alias-side gap is ALSO closed.
        let err = canon_main_with_dep(
            "module Dep exposing (Color(..))\n\
             type Color = Red | Green | Blue\n",
            "module Main exposing (main)\n\
             import Dep exposing (Color(..))\n\n\
             type alias Color = Int\n\n\
             main =\n    0\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::DuplicateType { .. },
                    ..
                })
            ),
            "local `type alias Color` shadowing imported Dep.Color must be a \
             DuplicateType (IPE-N0012) at the declaration, got {err:?}"
        );
    }

    #[test]
    fn two_modules_each_declaring_unrelated_same_named_type_without_import_is_fine() {
        // Non-regression control: `Dep` declares `type Color` but `Main` never
        // imports it, so `type_home_map` in `Main`'s resolution never gains a
        // `Dep.Color` entry — the dep-shadow pre-pass sees `None` and nothing
        // rejects. `Main`'s own unrelated `type Color` compiles cleanly.
        let err = canon_main_with_dep(
            "module Dep exposing (Color(..))\n\
             type Color = Red | Green | Blue\n",
            "module Main exposing (main)\n\n\
             type Color = Warm | Cool\n\n\
             describe : Color -> String\n\
             describe c =\n    case c of\n        Warm -> \"warm\"\n        Cool -> \"cool\"\n\n\
             main =\n    describe Warm\n",
        );
        assert!(
            err.is_none(),
            "an unrelated same-named local type with NO import of the dep must \
             compile cleanly, got {err:?}"
        );
    }

    #[test]
    fn same_module_duplicate_type_still_uses_first_declared_span() {
        // The same-module duplicate path (the `seen_types`
        // loop) is separate from the dep-shadow pre-pass: two `type Color`
        // declarations in ONE module still report the FIRST-declared span, not
        // the `Span::DUMMY` the dep-shadow path uses.
        let err = canon_err(
            "module Main exposing (main)\n\
             type Color = Warm\n\
             type Color = Cool\n\n\
             main =\n    Io.println \"hi\"\n",
        );
        let Some(Diagnostic::Name {
            msg: NameError::DuplicateType { first, .. },
            ..
        }) = err
        else {
            assert!(false_marker(), "expected DuplicateType, got {err:?}");
            return;
        };
        assert_ne!(
            first,
            ipe_diagnostics::Span::DUMMY,
            "same-module duplicate must carry the first-declared span, not DUMMY"
        );
    }

    #[test]
    #[allow(clippy::similar_names)] // parallel `mod_a_*`/`mod_b_*` fixtures for the two clashing dep modules
    fn dep_import_clash_duplicate_type_carries_non_dummy_first_span() {
        // Two distinct dep modules both expose a type under the same unqualified
        // name. `DuplicateType::first` must point at the FIRST import's span, not
        // `Span::DUMMY` — the user needs both sites to resolve the clash.
        // Non-vacuous: fails on the pre-fix `Span::DUMMY` path in `inject_dep_type`.
        let mut i = Interner::new();
        let mod_a_src = "module ModA exposing (Color(..))\ntype Color = Warm | Cool\n";
        let mod_b_src = "module ModB exposing (Color(..))\ntype Color = Red | Blue\n";
        let empty: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();

        let mod_a_parsed = ipe_parse::parse_module(mod_a_src, &mut i).expect("ModA parse");
        let mod_a_path = mod_a_parsed.name.value.clone();
        let (_mod_a, mod_a_exports) =
            canonicalise_module(&mod_a_parsed, &mod_a_path, &empty, &mut i).expect("ModA canon");

        let mod_b_parsed = ipe_parse::parse_module(mod_b_src, &mut i).expect("ModB parse");
        let mod_b_path = mod_b_parsed.name.value.clone();
        let (_mod_b, mod_b_exports) =
            canonicalise_module(&mod_b_parsed, &mod_b_path, &empty, &mut i).expect("ModB canon");

        let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        deps.insert(mod_a_exports.path.clone(), mod_a_exports);
        deps.insert(mod_b_exports.path.clone(), mod_b_exports);

        // Main imports both — second `exposing (Color(..))` clashes with first.
        let main_src = "module Main exposing (main)\n\
                        import ModA exposing (Color(..))\n\
                        import ModB exposing (Color(..))\n\n\
                        main =\n    Io.println \"hi\"\n";
        let main_parsed = ipe_parse::parse_module(main_src, &mut i).expect("Main parse");
        let main_path = main_parsed.name.value.clone();
        let err = canonicalise_module(&main_parsed, &main_path, &deps, &mut i).err();

        let Some(Diagnostic::Name {
            msg: NameError::DuplicateType { first, .. },
            ..
        }) = err
        else {
            assert!(
                false_marker(),
                "expected DuplicateType from two-dep type clash, got {err:?}"
            );
            return;
        };
        assert_ne!(
            first,
            ipe_diagnostics::Span::DUMMY,
            "DuplicateType from dep import clash must carry the first import span, not DUMMY"
        );
    }

    /// **Tripwire: registry ↔ canon parity.**
    ///
    /// Forward direction (registry → canon): for every
    /// [`ipe_kernels::StdlibKernel`] variant in `ALL`, if the variant's
    /// declared qualifier IS present in `Env.kernel_members`, then the variant's
    /// declared name must ALSO be present in that qualifier's member map.  A
    /// failure here means `QUALIFIERS` in `env.rs` diverged from
    /// `StdlibKernel::ALL + decl()` — the anti-drift invariant is broken.
    ///
    /// The forward check is intentionally one-directional: names present in
    /// `QUALIFIERS` but absent from the registry (e.g. `Basics.*` helper
    /// aliases) are NOT an error.  Qualifiers absent from the pool entirely
    /// (e.g. `"Log"`, `"PubSub"`) are skipped automatically.
    ///
    /// Reverse direction (canon → registry, "G1"): every
    /// `VarHome::Kernel(sk, ..)` entry is checked for exact kernel propagation
    /// against `stdlib_index`. A separate "is there a kernel at all" subset gate
    /// is no longer needed: "a reachable member with no backing kernel" is not a
    /// representable state — a member is either a backed `Kernel` or an explicit
    /// `VarHome::ReservedKernel`. The reserved set is asserted against a fixed
    /// allowlist so it cannot drift.
    ///
    /// **Scope note (this crate has no dependency on `ipe_types`):** this
    /// test proves `QUALIFIERS` (env.rs) stays consistent with
    /// `StdlibKernel::ALL` — it does NOT re-verify the type-scheme table's
    /// own fail-closed behaviour. That guarantee (`ipe`'s exit-0-then-
    /// cargo-fail class `PRINCIPLES.md` calls out: a kernel the resolver
    /// recognises but the type-scheme table does not cover) is a SEPARATE
    /// invariant owned by
    /// `ipe_types::constrain::kernel_scheme_or_unsupported`'s unconditional
    /// `.ok_or(Err(..))` (no flexible-type-variable fallback exists there).
    /// A future regression in that function would sail through this test
    /// untouched — don't treat `canon_equals_registry` as a substitute
    /// regression test for it.
    #[test]
    #[allow(clippy::too_many_lines)] // declarative tripwire — forward + reverse parity directions plus the reserved-category allowlist; splitting would obscure the invariant
    fn canon_equals_registry() {
        use crate::env::VarHome;
        use ipe_intern::Interner;
        use ipe_kernels::StdlibKernel;

        let mut interner = Interner::new();
        let env = Env::initial(vec![], &mut interner)
            .expect("Env::initial must not fail in the tripwire test");

        // Kernels whose CANONICAL (qualifier, member) key is retained for
        // `Kernel.kernel` alias resolution (via `stdlib_index`) but whose SURFACE
        // relocated OUT of the native qualifier into a compiled-source
        // `Ipe.<M>.Unsafe` escape-hatch submodule. The canonical qualifier stays
        // (so `Kernel.kernel "Db_unsafeExecRaw"` still splits to `("Db", …)` and
        // resolves the same kernel), but the member is intentionally ABSENT from
        // `kernel_members[qualifier]` so it no longer resolves off a plain import of
        // the native module. Verified positively by the `Ipe.Db.Unsafe`
        // disclosure + resolution tests; this set exempts them from the
        // surface-parity tripwire below.
        let relocated_to_unsafe: std::collections::BTreeSet<(&str, &str)> = [
            ("Db", "unsafeExecRaw"),
            ("Db", "unsafeQuery"),
            ("Db", "unsafeGetString"),
            ("Db", "unsafeGetInt"),
            ("Db", "unsafeGetBool"),
            ("Db", "unsafeGetField"),
            // The external-connection raw write hatch: canonical `("Db", …)` key
            // for the `Kernel.kernel` alias, surfaced only through `Ipe.Db.Unsafe`.
            ("Db", "unsafeExecRawOn"),
            // The un-validated anti-`Sql.column`: canonical `("Sql", …)` key for
            // the alias, surfaced only through `Ipe.Db.Unsafe.unsafeFragment`.
            ("Sql", "unsafeFragment"),
            // The blunt secret un-parse: canonical `("Secret", "reveal")` key
            // retained for the `Kernel.kernel "Secret_reveal"` alias, surfaced only
            // through `Ipe.Secret.Unsafe.unsafeReveal`. The scoped `Secret.use`
            // stays on the native `Secret` surface (capability-neutral).
            ("Secret", "reveal"),
            // The policy-checked secured writes: canonical `("Db", …)` keys for
            // the `Kernel.kernel` aliases `Ipe.Db.Store` keeps private to
            // `insertAs` / `updateAs`; no module surfaces them.
            ("Db", "insertFieldsChecked"),
            ("Db", "updateWhereChecked"),
        ]
        .into_iter()
        .collect();

        for sk in StdlibKernel::ALL {
            let decl = sk.decl();

            // Skip internal-only qualifiers (e.g. "_internal_").
            if decl.qualifier.starts_with('_') {
                continue;
            }

            // Skip members relocated to a compiled-source `.Unsafe` submodule:
            // their canonical key stays for alias resolution but the surface
            // deliberately left the native qualifier (see the set above).
            if relocated_to_unsafe.contains(&(decl.qualifier, decl.name)) {
                continue;
            }

            // Intern qualifier + name.  If they were already interned by
            // install_prelude_qualifiers we get the same symbol; if not, the
            // fresh symbol will simply not appear in the pool (correct skip).
            // `Interner::intern` is infallible in practice (OOM only).
            let qual_sym = interner
                .intern(decl.qualifier)
                .expect("tripwire: intern qualifier OOM");
            let name_sym = interner
                .intern(decl.name)
                .expect("tripwire: intern name OOM");

            // If the qualifier is not in the kernel pool at all (e.g. "Log" is
            // only in `vars`; "PubSub" is not yet wired), skip.
            let Some(members) = env.kernel_members.get(&qual_sym) else {
                continue;
            };

            // The qualifier IS registered — so the name must also be present.
            assert!(
                members.contains_key(&name_sym),
                "StdlibKernel::{sk:?} declares ({:?}, {:?}) but {:?} is missing \
                 from env.kernel_members[{:?}]; update QUALIFIERS in env.rs to match \
                 StdlibKernel::decl()",
                decl.qualifier,
                decl.name,
                decl.name,
                decl.qualifier,
            );

            // Also verify the stdlib_index was populated for this entry.
            assert!(
                env.stdlib_index.contains_key(&(qual_sym, name_sym)),
                "StdlibKernel::{sk:?} is in kernel_members but missing from stdlib_index; \
                 the Phase-A registry-population loop in install_prelude_qualifiers \
                 must have skipped it",
            );
        }

        // ── G1 reverse check: canon → registry ───────────────────────────────
        // For every `VarHome::Kernel(actual_sk, m, f)` entry, verify the carried
        // kernel EXACTLY MATCHES `stdlib_index[(m, f)]` — proving
        // install_prelude_qualifiers stored the kernel it read from
        // stdlib_index, not a transposed or stale copy.
        //
        // With the totality fix there is no separate "is there a kernel at all"
        // subset gate to run: a reachable member is either `Kernel(sk, ..)`
        // (backed by construction — this loop checks it points at the RIGHT sk)
        // or `ReservedKernel { .. }` (the explicit reserved category, asserted
        // against a fixed allowlist below). "A reachable member with no backing
        // kernel" is no longer a representable state, so a `Kernel(None, ..)`
        // hole cannot arise for the gate to catch.
        //
        // SCOPE: verifies propagation wiring. It does NOT verify injectivity of
        // decl() (covered by ipe_kernels::tests::no_colliding_qualifier_name_pairs)
        // nor decl-equiv-legacy equivalence (covered by
        // ipe_lower::tests::decl_equiv_legacy_match).
        for (module, members) in env.kernel_members.iter() {
            let qual_str = interner.resolve(module.symbol()).unwrap_or("<unknown>");
            for (name_sym, home) in members {
                if let VarHome::Kernel(actual_sk, m, f) = home {
                    // The carried kernel is verified against stdlib_index using
                    // the CANONICAL (module, name) stored in VarHome, not the
                    // pool KEY.
                    //
                    // For plain entries: m == qual_sym, f == name_sym.
                    // For FUNC_ALIASES: name_sym is the ALIAS (e.g.
                    // "htmlRender") while f is the CANONICAL name (e.g.
                    // "render").  stdlib_index is keyed by
                    // (qual_sym, canonical_name), so using (m, f) is always
                    // correct for both.
                    //
                    // Alias namespaces (`Attr`, `Event`, the `Ipe.*` clones)
                    // carry the canonical kernel + canonical (m, f) symbols, so
                    // the same (m, f) lookup validates them too — no qualifier
                    // needs excluding.
                    let expected = env.stdlib_index.get(&(*m, *f));
                    let name_str = interner.resolve(*name_sym).unwrap_or("<unknown>");
                    let canon_str = interner.resolve(*f).unwrap_or("<unknown>");
                    assert_eq!(
                        Some(actual_sk),
                        expected,
                        "G1 reverse: VarHome::Kernel in kernel_members[{qual_str:?}][{name_str:?}] \
                         (canonical fn={canon_str:?}) carries kernel {actual_sk:?} but \
                         stdlib_index has {expected:?}; \
                         install_prelude_qualifiers propagation is incorrect",
                    );
                }
            }
        }

        // Reserved-category gate: the reachable-but-unbacked members
        // (`VarHome::ReservedKernel`) must be EXACTLY this allowlist. A member
        // dropping off (once it gains a `StdlibKernel`) or a new one appearing
        // both fail here, so the reserved set cannot silently drift — the same
        // anti-drift protection the old subset gate gave, now over the explicit
        // reserved variant instead of a `None` inside `Kernel`.
        //
        // The allowlist is intentionally empty: `("String", "toChar")` which was
        // previously the sole entry is no longer registered in the pool because
        // `Ipe.String` is now a compiled-source module (not a kernel qualifier).
        // Any future reserved entry must be added here with a comment explaining
        // why it deliberately lacks a `StdlibKernel` variant.
        let reserved_allowlist: std::collections::BTreeSet<(&str, &str)> =
            std::collections::BTreeSet::new();
        let reserved_actual = reserved_kernel_members(&env.kernel_members, &interner);
        assert_eq!(
            reserved_actual, reserved_allowlist,
            "reserved-category gate: VarHome::ReservedKernel members must be \
             exactly the documented allowlist. A member here that gained a \
             StdlibKernel must move from ReservedKernel to Kernel (remove it \
             from the allowlist); a genuinely new unbacked member must gain a \
             StdlibKernel variant + scheme, or be added to the allowlist with a \
             comment explaining why it is deliberately unbacked.\n\
             actual={reserved_actual:?}\nexpected={reserved_allowlist:?}",
        );
    }

    /// Collect the `(qualifier, name)` pairs of every reachable-but-unbacked
    /// member — the [`crate::env::VarHome::ReservedKernel`] entries — in
    /// a qualifier-keyed member table. `canon_equals_registry` asserts the
    /// result equals the fixed reserved allowlist, so the reserved set cannot
    /// drift.
    fn reserved_kernel_members<'a, K>(
        qual_vars: &std::collections::BTreeMap<
            K,
            std::collections::BTreeMap<ipe_intern::Symbol, crate::env::VarHome>,
        >,
        interner: &'a ipe_intern::Interner,
    ) -> std::collections::BTreeSet<(&'a str, &'a str)> {
        use crate::env::VarHome;

        let mut reserved = std::collections::BTreeSet::new();
        for members in qual_vars.values() {
            for home in members.values() {
                if let VarHome::ReservedKernel { module, name } = home {
                    let m_str = interner.resolve(*module).unwrap_or("<unknown>");
                    let n_str = interner.resolve(*name).unwrap_or("<unknown>");
                    reserved.insert((m_str, n_str));
                }
            }
        }
        reserved
    }

    /// **Regression proof**: the reserved-category gate
    /// (`reserved_kernel_members`, exercised for real by
    /// `canon_equals_registry`) actually SEES a reachable-but-unbacked member,
    /// rather than being a check that just happens to stay silent. A synthetic
    /// `qual_vars`-shaped fixture — bypassing `Env::initial` entirely — holds
    /// one `VarHome::ReservedKernel` member, and the collector must report
    /// exactly that pair (and nothing when the member is a backed `Kernel`).
    #[test]
    fn reserved_kernel_members_collects_unbacked() {
        use crate::env::VarHome;
        use ipe_intern::Interner;
        use ipe_kernels::StdlibKernel;

        let mut interner = Interner::new();
        let qual_sym = interner.intern("Totally.Fake").expect("intern OOM");
        let name_sym = interner.intern("madeUpKernel").expect("intern OOM");

        // A reachable member with no backing kernel — the reserved category.
        let mut members = std::collections::BTreeMap::new();
        members.insert(
            name_sym,
            VarHome::ReservedKernel {
                module: qual_sym,
                name: name_sym,
            },
        );
        let mut qual_vars = std::collections::BTreeMap::new();
        qual_vars.insert(qual_sym, members);

        let reserved = reserved_kernel_members(&qual_vars, &interner);
        assert_eq!(
            reserved,
            std::iter::once(("Totally.Fake", "madeUpKernel")).collect(),
            "collector must report exactly the synthetic reserved member",
        );

        // A backed `Kernel` member is NOT reserved — the collector skips it.
        let mut backed = std::collections::BTreeMap::new();
        backed.insert(
            name_sym,
            VarHome::Kernel(StdlibKernel::BasicsIdentity, qual_sym, name_sym),
        );
        let mut backed_vars = std::collections::BTreeMap::new();
        backed_vars.insert(qual_sym, backed);
        assert!(
            reserved_kernel_members(&backed_vars, &interner).is_empty(),
            "a backed Kernel member must not be reported as reserved",
        );
    }

    /// `Ipe.PubSub` (the top-level, Task-shaped publish surface) is a
    /// COMPILED-SOURCE stdlib module (`src/stdlib/Ipe/PubSub.ipe`), so the bare
    /// `"PubSub"` KERNEL qualifier must NOT be registered in `env.kernel_members`
    /// (kernel qualifier OR compiled-source — never both). `Ipe.PubSub.publish`
    /// resolves through the compiled module's `Kernel.kernel "PubSub_publish"` alias,
    /// whose fast-path mints a `VarKernel` with a concrete kernel id — so the
    /// `stdlib_scheme` totality flip stays sound without a kernel-pool entry.
    #[test]
    fn pubsub_kernel_qualifier_absent_compiled_source() {
        use ipe_intern::Interner;

        let mut interner = Interner::new();
        let pubsub = interner
            .intern("PubSub")
            .expect("tripwire: intern PubSub OOM");
        let env = Env::initial(vec![], &mut interner)
            .expect("Env::initial must not fail in the tripwire test");

        assert!(
            env.kernel_module_of(pubsub).is_none(),
            "The `PubSub` kernel qualifier must stay OUT of env.kernel_members — \
             `Ipe.PubSub` is a compiled-source module resolved via the \
             `Kernel.kernel \"PubSub_publish\"` alias, not a kernel qualifier.",
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Record type-alias auto-constructor (IPE-N0001).
    // ─────────────────────────────────────────────────────────────────────────

    /// Flatten an arrow type into `(arg types…, final result type)`.
    fn arrow_spine(ty: &ast::Type) -> (Vec<&ast::Type>, &ast::Type) {
        let mut args = Vec::new();
        let mut cur = ty;
        while let ast::Type::Lambda(a, b) = cur {
            args.push(a.as_ref());
            cur = b.as_ref();
        }
        (args, cur)
    }

    #[test]
    fn record_alias_synthesizes_typed_ctor() {
        // `type alias Profile = { name : String, age : Int }` introduces a value
        // `Profile : String -> Int -> { name:String, age:Int }`.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias Profile =\n    { name : String, age : Int }\n\n\
             main = 0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        let Some(Def::Typed {
            patterns,
            body,
            ty,
            free_vars,
            ..
        }) = find_def(&m, &i, "Profile")
        else {
            assert!(false_marker(), "Profile is a synthesized typed def");
            return;
        };
        assert!(free_vars.is_empty(), "monomorphic record: no free vars");
        // Two params, in declared order.
        let pnames: Vec<&str> = patterns
            .iter()
            .filter_map(|p| match &p.value {
                Pattern_::PVar(s) => i.resolve(*s),
                _ => None,
            })
            .collect();
        assert_eq!(pnames, vec!["name", "age"], "params in declared order");
        // Body is a record literal of VarLocal refs in declared order.
        let Expr_::Record(fields) = &body.value else {
            assert!(false_marker(), "body is a record literal");
            return;
        };
        let bnames: Vec<&str> = fields.iter().filter_map(|(f, _)| i.resolve(*f)).collect();
        assert_eq!(bnames, vec!["name", "age"]);
        for (f, e) in fields {
            assert!(
                matches!(&e.value, Expr_::VarLocal(s) if s == f),
                "each field value is the eponymous local"
            );
        }
        // Arrow: String -> Int -> { name, age }.
        let (arg_tys, result) = arrow_spine(ty);
        assert_eq!(arg_tys.len(), 2, "two arrow arguments");
        assert!(
            matches!(arg_tys.first(), Some(ast::Type::Con { name, .. }) if i.resolve(*name) == Some("String"))
        );
        assert!(
            matches!(arg_tys.get(1), Some(ast::Type::Con { name, .. }) if i.resolve(*name) == Some("Int"))
        );
        let ast::Type::Record(rfields) = result else {
            assert!(false_marker(), "result is a closed record type");
            return;
        };
        let rnames: Vec<&str> = rfields.iter().filter_map(|(f, _)| i.resolve(*f)).collect();
        assert_eq!(
            rnames,
            vec!["name", "age"],
            "record fields in declared order"
        );
    }

    #[test]
    fn record_alias_ctor_field_order_is_declared_not_alphabetical() {
        // Non-alphabetical declared order `{ zebra, apple }` must produce the
        // ctor `zebra -> apple`, NOT alphabetised — the field-order guarantee.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias Row =\n    { zebra : Int, apple : String }\n\n\
             main = 0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        let Some(Def::Typed { patterns, ty, .. }) = find_def(&m, &i, "Row") else {
            assert!(false_marker(), "Row is a synthesized typed def");
            return;
        };
        let pnames: Vec<&str> = patterns
            .iter()
            .filter_map(|p| match &p.value {
                Pattern_::PVar(s) => i.resolve(*s),
                _ => None,
            })
            .collect();
        assert_eq!(pnames, vec!["zebra", "apple"], "declared, not alphabetical");
        let (arg_tys, _) = arrow_spine(ty);
        // First arg `zebra : Int`, second `apple : String` — positional binding.
        assert!(
            matches!(arg_tys.first(), Some(ast::Type::Con { name, .. }) if i.resolve(*name) == Some("Int")),
            "first arg type is Int (zebra), got {:?}",
            arg_tys.first()
        );
        assert!(
            matches!(arg_tys.get(1), Some(ast::Type::Con { name, .. }) if i.resolve(*name) == Some("String")),
            "second arg type is String (apple), got {:?}",
            arg_tys.get(1)
        );
    }

    #[test]
    fn record_alias_ctor_resolves_as_a_value() {
        // Bare use of the alias name as a value resolves to a top-level binding,
        // not a name error — the IPE-N0001 fix.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias P =\n    { a : Int }\n\n\
             mk = P\n\
             main = 0\n",
        );
        assert!(m.is_some(), "bare `P` used as a value must resolve");
        let Some(m) = m else { return };
        let body = match find_def(&m, &i, "mk") {
            Some(Def::Untyped { body, .. } | Def::Typed { body, .. }) => Some(&body.value),
            None => None,
        };
        assert!(
            matches!(body, Some(Expr_::VarTopLevel { name, .. }) if i.resolve(*name) == Some("P")),
            "`mk = P` resolves P to a top-level ctor, got {body:?}"
        );
    }

    #[test]
    fn parametric_record_alias_generalises_over_used_params() {
        // `type alias Box a = { value : a, tag : String }` → the ctor generalises
        // over `a`: `Box : a -> String -> { value:a, tag:String }`. The param
        // canonicalises to `Type::Var`, never an unknown/opaque `Con`.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias Box a =\n    { value : a, tag : String }\n\n\
             main = 0\n",
        );
        assert!(m.is_some(), "parametric record alias must canonicalise");
        let Some(m) = m else { return };
        let Some(Def::Typed { free_vars, ty, .. }) = find_def(&m, &i, "Box") else {
            assert!(false_marker(), "Box is a synthesized typed def");
            return;
        };
        let fv: Vec<&str> = free_vars.iter().filter_map(|s| i.resolve(*s)).collect();
        assert_eq!(fv, vec!["a"], "generalises over the used param `a` only");
        let (arg_tys, _) = arrow_spine(ty);
        assert!(
            matches!(arg_tys.first(), Some(ast::Type::Var(s)) if i.resolve(*s) == Some("a")),
            "first arg is the type variable `a` (not UnknownType/Con), got {:?}",
            arg_tys.first()
        );
    }

    #[test]
    fn phantom_param_drops_out_of_ctor_scheme() {
        // A declared-but-unused param must NOT appear in the ctor's free vars.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias Tagged phantom =\n    { label : String }\n\n\
             main = 0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        let Some(Def::Typed { free_vars, .. }) = find_def(&m, &i, "Tagged") else {
            assert!(false_marker(), "Tagged is a synthesized typed def");
            return;
        };
        assert!(
            free_vars.is_empty(),
            "phantom param must not generalise the ctor, got {:?}",
            free_vars
                .iter()
                .filter_map(|s| i.resolve(*s))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn non_record_alias_has_no_ctor_and_still_errors_as_value() {
        // `type alias Count = Int` gets NO value binding; using it as a value
        // stays an ordinary IPE-N0001 ValueNotFound (Elm parity).
        let mut i = Interner::new();
        let ok = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias Count = Int\n\n\
             main = 0\n",
        );
        assert!(ok.is_some(), "control module canonicalises");
        if let Some(m) = ok {
            assert!(
                find_def(&m, &i, "Count").is_none(),
                "non-record alias must not synthesize a def"
            );
        }
        // Now use it as a value → ValueNotFound.
        let err = canon_err(
            "module Main exposing (main)\n\
             type alias Count = Int\n\n\
             main = Count\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::ValueNotFound { .. },
                    ..
                })
            ),
            "non-record alias used as a value must be ValueNotFound, got {err:?}"
        );
    }

    #[test]
    fn head_alias_to_record_alias_gets_no_ctor() {
        // `type alias U = P` where P is a record alias: U's SOURCE body is a
        // TType, not a literal TRecord, so U gets NO constructor (Elm parity).
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias P =\n    { a : Int }\n\
             type alias U = P\n\n\
             main = 0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        assert!(
            find_def(&m, &i, "P").is_some(),
            "the literal record alias P has a ctor"
        );
        assert!(
            find_def(&m, &i, "U").is_none(),
            "the head alias U must NOT get a ctor"
        );
    }

    #[test]
    fn record_alias_name_coinciding_with_data_ctor_is_allowed() {
        // A record alias whose name also names a data constructor is VALID: the
        // TYPE namespace (`type alias Foo`) and the CONSTRUCTOR namespace
        // (`type Bar = Foo`) are distinct. The upstream the compiler (`registerAliases`)
        // inserts into `_vars` without checking `_ctors`, so both coexist.
        //
        // Previously this wrongly emitted IPE-N0010 (DuplicateValue). The fix
        // changes `synthesize_record_alias_ctors` to `continue` (skip synthesis)
        // when the alias name coincides with a known ADT constructor, instead of
        // erroring — achieving the same "ADT ctor wins in expression position"
        // outcome more cleanly.
        let src = "module Main exposing (main)\n\
                   type alias Foo =\n    { x : Int }\n\
                   type Bar = Foo\n\n\
                   main = 0\n";
        let mut i = Interner::new();
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            assert!(false_marker(), "source must parse");
            return;
        };
        assert!(
            canonicalise(&parsed, &mut i).is_ok(),
            "record alias `Foo` and ADT ctor `Foo` in `type Bar = Foo` must \
             coexist without N0010 — they live in separate namespaces"
        );
    }

    #[test]
    fn explicit_binding_suppresses_record_alias_ctor_synthesis() {
        // A user-written top-level value sharing a record alias's name IS the
        // constructor — the explicit binding provides the implementation and
        // SUPPRESSES synthesis of the auto-ctor (upstream Rust emitter's
        // `existingNames` guard). The two do NOT collide as DuplicateValue; the
        // module canonicalises, and the single `Mk` def is the user's binding.
        //
        // This is the `06-json` pattern: `type alias Profile = { … }` plus an
        // explicit `Profile name age active = { … }` record-constructor helper.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias Mk =\n    { x : Int }\n\n\
             Mk n =\n    { x = n }\n\n\
             main = 0\n",
        );
        assert!(
            m.is_some(),
            "an explicit record-ctor binding sharing the alias name must \
             canonicalise (synthesis suppressed), not fail with DuplicateValue"
        );
        let Some(m) = m else { return };
        // Exactly ONE `Mk` def — the user's binding, not a synthesized ctor
        // duplicated alongside it.
        let mk_defs = m
            .defs
            .iter()
            .filter(|d| i.resolve(d.name().value) == Some("Mk"))
            .count();
        assert_eq!(
            mk_defs, 1,
            "the user's explicit `Mk` binding is the sole def; the auto-ctor \
             must be suppressed, not emitted alongside it"
        );
    }

    #[test]
    fn function_field_record_alias_has_no_ctor() {
        // A config-record alias with an ARROW-headed field must NOT synthesize a
        // constructor — its body would be a record literal with a function field,
        // which the lowerer rejects (IPE-L0107), and there is no DCE to prune an
        // unused one. It stays a type only, with no synthesized constructor.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias Cfg =\n    { run : Int -> Int, label : String }\n\n\
             main = 0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        assert!(
            find_def(&m, &i, "Cfg").is_none(),
            "function-field record alias must not get a constructor"
        );
    }

    #[test]
    fn generic_carrier_field_without_function_still_gets_ctor() {
        // A field carrying a GENERIC (non-function, non-opaque) argument
        // (`List a`) is derivable, so the struct-derivability gate keeps its
        // constructor. This is the control that the recursive
        // `field_type_nonderivable` predicate does NOT over-gate an ordinary
        // parametric container — only an embedded arrow (see
        // `nested_function_in_derive_carrier_has_no_ctor`) or an opaque wrapper
        // (see `opaque_wrapper_field_record_alias_gets_no_ctor`) blocks synthesis.
        let mut i = Interner::new();
        let m = canon_ok(
            &mut i,
            "module Main exposing (main)\n\
             type alias Wrap a =\n    { items : List a, count : Int }\n\n\
             main = 0\n",
        );
        assert!(m.is_some(), "module must canonicalise");
        let Some(m) = m else { return };
        assert!(
            find_def(&m, &i, "Wrap").is_some(),
            "a record alias with only non-function-embedding fields keeps its ctor"
        );
    }

    #[test]
    fn nested_function_in_derive_carrier_has_no_ctor() {
        // SEAL FIX. A field whose function is NESTED inside a derive carrier
        // — `List (Int -> Bool)` (head `Con "List"`, not `Lambda`) — was MISSED by
        // the earlier head-only gate: a ctor was synthesised, the backend emitted a
        // `#[derive(Clone, Debug, PartialEq)]` struct over a `Box<dyn Fn>` field,
        // and ipe exited 0 while cargo failed (the seal violation). The recursive
        // gate now declines synthesis, so merely NAMING the alias builds clean.
        let cases = [
            "type alias T =\n    { xs : List (Int -> Int) }\n",
            "type alias T =\n    { f : Maybe (Int -> Int) }\n",
            "type alias T =\n    { p : (Int -> Int, Bool) }\n",
            "type alias T =\n    { g : Result Error (Int -> Int) }\n",
            "type alias T =\n    { inner : { h : Int -> Int } }\n",
        ];
        for body in cases {
            let mut i = Interner::new();
            let src = format!("module Main exposing (main)\n{body}\nmain = 0\n");
            let m = canon_ok(&mut i, &src);
            assert!(m.is_some(), "module must canonicalise: {body}");
            let Some(m) = m else { continue };
            assert!(
                find_def(&m, &i, "T").is_none(),
                "a record alias embedding a nested function must NOT get a ctor: {body}"
            );
        }
    }

    #[test]
    fn opaque_wrapper_field_record_alias_gets_no_ctor() {
        // ROUND-2 SEAL FIX. An opaque boxed-wrapper in FIELD position
        // (`Decoder` / `Cmd` / `Sub` / `Task`) is ITSELF non-derivable as a
        // struct field — its runtime rep (`Box<dyn Fn>` / boxed-thunk enum /
        // `Pin<Box<dyn Future>>`) impls no Clone/Debug/PartialEq/IpeStringify.
        // Round-1 synthesised a ctor here, so the backend emitted a
        // `#[derive(…)]` struct over the wrapper and ipe-0 then cargo-101 (the
        // seal hole). The struct-derivability gate now DECLINES synthesis, so
        // merely NAMING the alias builds clean and no dangling ctor value exists.
        // Use only builtin type args (`Int`, `Error`) so the test is not
        // sensitive to whether an undefined user ADT (`Msg`) compiles.
        // Unknown unqualified type names fail closed with IPE-N0002;
        // the test's intent (no ctor for opaque-field alias) does not depend on
        // the specific type argument — `Cmd Int` tests the same gate as `Cmd Msg`.
        for (decl, field_ty) in [
            ("Dec", "Decoder Int"),
            ("Ev", "Cmd Int"),
            ("Sb", "Sub Int"),
            ("Tk", "Task Error Int"),
        ] {
            let mut i = Interner::new();
            let src = format!(
                "module Main exposing (main)\n\
                 type alias {decl} =\n    {{ payload : {field_ty} }}\n\n\
                 main = 0\n"
            );
            let m = canon_ok(&mut i, &src);
            assert!(m.is_some(), "module must canonicalise: {field_ty}");
            let Some(m) = m else { continue };
            // NO constructor Def is synthesised for an opaque-wrapper-field alias.
            assert!(
                find_def(&m, &i, decl).is_none(),
                "an opaque-wrapper-field record alias must NOT get a ctor: {field_ty}"
            );
        }
    }

    #[test]
    fn function_field_alias_is_not_exported_as_a_value() {
        // Exports must match synthesis: a gated-out function-field alias exports
        // its TYPE but NOT a (non-existent) constructor value — otherwise an
        // importer would inject a dangling binding.
        let mut i = Interner::new();
        let src = "module Lib exposing (..)\n\
                   type alias Cfg =\n    { run : Int -> Int }\n";
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            assert!(false_marker(), "parse");
            return;
        };
        let expected = parsed.name.value.clone();
        let deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let Ok((_m, exports)) = canonicalise_module(&parsed, &expected, &deps, &mut i) else {
            assert!(false_marker(), "Lib must canonicalise");
            return;
        };
        let cfg = i.intern("Cfg").expect("intern Cfg");
        assert!(
            exports.aliases.contains_key(&cfg),
            "Cfg is still exported as a type alias"
        );
        assert!(
            !exports.values.contains(&cfg),
            "Cfg must NOT be exported as a value (no ctor synthesized)"
        );
    }

    #[test]
    fn exposed_record_alias_exports_its_ctor_value() {
        // `exposing (..)` on a module with a record alias must export the alias
        // name in BOTH the type namespace (aliases) and the value namespace
        // (values), so an importer can use it as a constructor.
        let mut i = Interner::new();
        let src = "module Lib exposing (..)\n\
                   type alias Widget =\n    { w : Int, h : Int }\n";
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            assert!(false_marker(), "parse");
            return;
        };
        let expected = parsed.name.value.clone();
        let deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let Ok((_m, exports)) = canonicalise_module(&parsed, &expected, &deps, &mut i) else {
            assert!(false_marker(), "Lib must canonicalise");
            return;
        };
        let widget = i.intern("Widget").expect("intern Widget");
        assert!(
            exports.aliases.contains_key(&widget),
            "Widget is exported as a type alias"
        );
        assert!(
            exports.values.contains(&widget),
            "Widget's auto-constructor is exported as a value"
        );
    }

    #[test]
    fn exposed_record_alias_via_list_exports_its_ctor_value() {
        // Explicit `exposing (Widget)` (list form) must also export the value.
        let mut i = Interner::new();
        let src = "module Lib exposing (Widget)\n\
                   type alias Widget =\n    { w : Int }\n";
        let Ok(parsed) = ipe_parse::parse_module(src, &mut i) else {
            assert!(false_marker(), "parse");
            return;
        };
        let expected = parsed.name.value.clone();
        let deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        let Ok((_m, exports)) = canonicalise_module(&parsed, &expected, &deps, &mut i) else {
            assert!(false_marker(), "Lib must canonicalise");
            return;
        };
        let widget = i.intern("Widget").expect("intern Widget");
        assert!(
            exports.values.contains(&widget),
            "list-exposed record alias must export its ctor value"
        );
    }

    // ── `import Ipê.*/Ipe.* exposing (member)` brings stdlib VALUE members
    // into UNQUALIFIED scope ─────────────────────────────────────────────────

    #[test]
    fn stdlib_exposing_brings_value_into_unqualified_scope() {
        // `import Ipe.Tea.Web exposing (tea, route)` → bare `tea` resolves to the
        // same `VarKernel { module: Web, name: tea }` a `Web.tea` reference
        // would. Previously this was `IPE-N0001` "tea not found".
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Web exposing (tea, route)\n\n\
                   main = tea\n";
        let Some((m, i)) = canon_src(src) else {
            assert!(false_marker(), "exposing (tea, route) must canonicalise");
            return;
        };
        assert_main_is_kernel(&m, &i, "Web", "tea");
    }

    #[test]
    fn html_kernel_qualifier_absent_compiled_source() {
        use ipe_intern::Interner;

        // `Ipe.Html` is a COMPILED-SOURCE module (`COMPILED_STD_MODULES`), so the
        // `Html` kernel qualifier must be ABSENT from `env.kernel_members`: its element
        // builders and the re-exposed serialiser (`render` / `renderStatic` / …)
        // resolve through the `Kernel.kernel "Html_*"` aliases in `Ipe/Html.ipe`, not
        // a kernel-qualifier prelude (mirrors the `PubSub` precedent).
        let mut interner = Interner::new();
        let html = interner.intern("Html").expect("tripwire: intern Html OOM");
        let env = Env::initial(vec![], &mut interner)
            .expect("Env::initial must not fail in the tripwire test");
        assert!(
            env.kernel_module_of(html).is_none(),
            "The `Html` kernel qualifier must stay OUT of env.kernel_members — \
             `Ipe.Html` is a compiled-source module resolved via the \
             `Kernel.kernel \"Html_*\"` alias, not a kernel qualifier.",
        );
    }

    #[test]
    fn program_importing_ipe_html_is_not_a_tea_app() {
        // ADR 0005: a module is a TEA app iff it imports something under
        // `Ipe.Tea.*`. Importing the shape-neutral `Ipe.Html` (where the static
        // render bridge `renderStatic` lives, next to `render`) must NOT be
        // rejected as a Program-importing-a-shape contradiction (IPE-N0033). The
        // canon-only harness does not inject the compiled-source `Ipe.Html` dep,
        // so a bare `Html.*` member is unresolved here — the point is only that no
        // TEA-gate (IPE-N0033) error fires for the import itself.
        let src = "module Main exposing (main)\n\
                   import Ipe.Html as Html\n\n\
                   main = 0\n";
        assert!(
            !matches!(
                canon_err(src),
                Some(Diagnostic::Name {
                    msg: NameError::ProgramImportsTeaShape { .. },
                    ..
                })
            ),
            "importing the shape-neutral `Ipe.Html` must not trip the IPE-N0033 \
             TEA-import gate"
        );
    }

    #[test]
    fn main_branching_between_shapes_is_rejected_n0035() {
        // A `main` whose head is an `if` choosing between two app entries selects
        // its shape at run time. The second shape import is already refused at
        // the import (IPE-N0035), ahead of the `main` gate.
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Web as Web\n\
                   import Ipe.Tea.Tui as Tui\n\n\
                   flag = True\n\
                   cfg = 0\n\n\
                   main =\n    if flag then\n        Web.tea cfg\n    else\n        Tui.tea cfg\n";
        assert!(
            matches!(
                canon_module_err(src),
                Some(Diagnostic::Name {
                    msg: NameError::TwoShapeImports { .. },
                    ..
                })
            ),
            "a module importing two shapes must be rejected IPE-N0035 at the second import"
        );
    }

    #[test]
    fn main_case_branching_to_a_shape_entry_is_rejected_n0045() {
        // The `case` head is the other run-time shape choice; one branch reaching
        // an app entry is enough to make the shape a value, so it is refused.
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Web as Web\n\n\
                   mode = 0\n\
                   cfg = 0\n\n\
                   main =\n    case mode of\n        first ->\n            Web.tea cfg\n";
        assert!(
            matches!(
                canon_module_err(src),
                Some(Diagnostic::Name {
                    msg: NameError::RuntimeBranchedMain,
                    ..
                })
            ),
            "a `main` that picks its shape from a `case` must be rejected IPE-N0045"
        );
    }

    #[test]
    fn main_nested_if_reaching_a_shape_entry_is_rejected_n0045() {
        // The branch peeler recurses, so an app entry nested in an `else if` is
        // still caught — the shape choice cannot hide one level down.
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Web as Web\n\n\
                   a = True\n\
                   b = True\n\
                   cfg = 0\n\n\
                   main =\n    if a then\n        Web.tea cfg\n    else if b then\n        Web.tea cfg\n    else\n        Web.tea cfg\n";
        assert!(
            matches!(
                canon_module_err(src),
                Some(Diagnostic::Name {
                    msg: NameError::RuntimeBranchedMain,
                    ..
                })
            ),
            "an app entry nested under `else if` must still be rejected IPE-N0045"
        );
    }

    #[test]
    fn tui_app_importing_web_cmd_sub_is_rejected_n0035() {
        // Importing another shape's `Sub` (`Ipe.Tea.Web.Sub`) has no denotation
        // in a terminal app and must fail closed (IPE-N0035).
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Tui as Tui\n\
                   import Ipe.Tea.Web.Sub as Sub\n\n\
                   cfg = 0\n\n\
                   main = Tui.tea cfg\n";
        assert!(
            matches!(
                canon_module_err(src),
                Some(Diagnostic::Name {
                    msg: NameError::WrongShapeCmdSub(_),
                    ..
                })
            ),
            "a `Tui.tea` importing `Ipe.Tea.Web.Sub` must be rejected IPE-N0035"
        );
    }

    #[test]
    fn web_app_importing_tui_cmd_sub_is_rejected_n0035() {
        // The reverse direction: a `Web.tea` importing the terminal
        // `Ipe.Tea.Tui.Sub` must also fail closed.
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Web as Web\n\
                   import Ipe.Tea.Tui.Sub as Sub\n\n\
                   cfg = 0\n\n\
                   main = Web.tea cfg\n";
        assert!(
            matches!(
                canon_module_err(src),
                Some(Diagnostic::Name {
                    msg: NameError::WrongShapeCmdSub(_),
                    ..
                })
            ),
            "a `Web.tea` importing `Ipe.Tea.Tui.Sub` must be rejected IPE-N0035"
        );
    }

    /// Canonicalise a one-import app and report whether IPE-N0035 fired.
    fn wrong_shape_cmd_sub_fires(entry_import: &str, entry: &str, sub_import: &str) -> bool {
        let src = format!(
            "module Main exposing (main)\n\
             import {entry_import}\n\
             import {sub_import} as Sub\n\n\
             cfg = 0\n\n\
             main = {entry} cfg\n"
        );
        matches!(
            canon_module_err(&src),
            Some(Diagnostic::Name {
                msg: NameError::WrongShapeCmdSub(_),
                ..
            })
        )
    }

    #[test]
    fn cli_app_importing_tui_sub_is_rejected_n0035() {
        // `Ipe.Tea.Tui.Sub` owns the key subscription (`onKey`); a `Cli` app has
        // no key stream, so the Tui surface's `Sub` is refused there.
        assert!(
            wrong_shape_cmd_sub_fires("Ipe.Tea.Cli as Cli", "Cli.tea", "Ipe.Tea.Tui.Sub"),
            "a `Cli.tea` importing `Ipe.Tea.Tui.Sub` must be rejected IPE-N0035"
        );
        assert!(
            wrong_shape_cmd_sub_fires("Ipe.Tea.Cli as Cli", "Cli.tea", "Ipe.Tea.Tui.Cmd"),
            "a `Cli.tea` importing `Ipe.Tea.Tui.Cmd` must be rejected IPE-N0035"
        );
    }

    #[test]
    fn tui_app_importing_cli_sub_is_rejected_n0035() {
        // `Ipe.Tea.Cli.Sub` owns the line subscription (`onLine`); a `Tui` app
        // has no line stream, so the Cli surface's `Sub` is refused there.
        assert!(
            wrong_shape_cmd_sub_fires("Ipe.Tea.Tui as Tui", "Tui.tea", "Ipe.Tea.Cli.Sub"),
            "a `Tui.tea` importing `Ipe.Tea.Cli.Sub` must be rejected IPE-N0035"
        );
    }

    #[test]
    fn terminal_apps_admit_their_own_and_the_shared_terminal_sub() {
        for (entry_import, entry, own) in [
            ("Ipe.Tea.Tui as Tui", "Tui.tea", "Ipe.Tea.Tui.Sub"),
            ("Ipe.Tea.Cli as Cli", "Cli.tea", "Ipe.Tea.Cli.Sub"),
        ] {
            assert!(
                !wrong_shape_cmd_sub_fires(entry_import, entry, own),
                "`{entry}` must admit its own `{own}`"
            );
            // The shared terminal-family re-export carries no input subscription.
            assert!(
                !wrong_shape_cmd_sub_fires(entry_import, entry, "Ipe.Tea.Terminal.Sub"),
                "`{entry}` must admit the shared `Ipe.Tea.Terminal.Sub`"
            );
        }
    }

    #[test]
    fn input_subscriptions_resolve_only_under_their_own_shape_sub() {
        // `onKey` is a member of `Ipe.Tea.Tui.Sub` and `onLine` of
        // `Ipe.Tea.Cli.Sub` — and neither leaks into another shape's `Sub`.
        let resolves = |entry_import: &str, entry: &str, sub_import: &str, member: &str| {
            let src = format!(
                "module Main exposing (main)\n\
                 import {entry_import}\n\
                 import {sub_import} as Sub\n\n\
                 subs = Sub.{member}\n\n\
                 cfg = 0\n\n\
                 main = {entry} cfg\n"
            );
            !matches!(
                canon_module_err(&src),
                Some(Diagnostic::Name {
                    msg: NameError::NoSuchMember { .. },
                    ..
                })
            )
        };
        assert!(resolves(
            "Ipe.Tea.Tui as Tui",
            "Tui.tea",
            "Ipe.Tea.Tui.Sub",
            "onKey"
        ));
        assert!(resolves(
            "Ipe.Tea.Cli as Cli",
            "Cli.tea",
            "Ipe.Tea.Cli.Sub",
            "onLine"
        ));
        assert!(!resolves(
            "Ipe.Tea.Tui as Tui",
            "Tui.tea",
            "Ipe.Tea.Tui.Sub",
            "onLine"
        ));
        assert!(!resolves(
            "Ipe.Tea.Cli as Cli",
            "Cli.tea",
            "Ipe.Tea.Cli.Sub",
            "onKey"
        ));
        // The shared terminal `Sub` adds nothing to the shape's own `Sub`: the
        // spelling holds the shape's members and never another shape's.
        assert!(resolves(
            "Ipe.Tea.Tui as Tui",
            "Tui.tea",
            "Ipe.Tea.Terminal.Sub",
            "onKey"
        ));
        assert!(!resolves(
            "Ipe.Tea.Tui as Tui",
            "Tui.tea",
            "Ipe.Tea.Terminal.Sub",
            "onLine"
        ));
        assert!(!resolves(
            "Ipe.Tea.Web as Web",
            "Web.tea",
            "Ipe.Tea.Web.Sub",
            "onKey"
        ));
    }

    /// Canonicalise `src` and return the IPE-N0052 payload, if that is the error.
    fn input_field_error(src: &str) -> Option<(String, String, String)> {
        match canon_module_err(src) {
            Some(Diagnostic::Name {
                msg:
                    NameError::InputFieldIsSubscription {
                        entry,
                        field,
                        sub_module,
                    },
                ..
            }) => Some((entry.into(), field.into(), sub_module.into())),
            _ => None,
        }
    }

    #[test]
    fn tui_cfg_on_key_field_is_rejected_n0052() {
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Tui as Tui\n\n\
                   main = Tui.tea { init = 0, update = 0, view = 0, subscriptions = 0, onKey = 0 }\n";
        assert_eq!(
            input_field_error(src),
            Some(("Tui.tea".into(), "onKey".into(), "Ipe.Tea.Tui.Sub".into())),
            "a `Tui.tea` config still passing `onKey` must be rejected IPE-N0052"
        );
    }

    #[test]
    fn cli_cfg_on_line_field_is_rejected_n0052() {
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Cli as Cli\n\n\
                   main = Cli.tea { init = 0, update = 0, view = 0, subscriptions = 0, onLine = 0 }\n";
        assert_eq!(
            input_field_error(src),
            Some(("Cli.tea".into(), "onLine".into(), "Ipe.Tea.Cli.Sub".into())),
            "a `Cli.tea` config still passing `onLine` must be rejected IPE-N0052"
        );
    }

    #[test]
    fn top_level_cfg_binding_with_input_field_is_rejected_n0052() {
        // The config bound to a sibling top-level name is checked too.
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Cli as Cli\n\n\
                   cfg = { init = 0, update = 0, view = 0, subscriptions = 0, onLine = 0 }\n\n\
                   main = Cli.tea cfg\n";
        assert!(
            input_field_error(src).is_some(),
            "a top-level `Cli.tea` config binding passing `onLine` must be rejected IPE-N0052"
        );
    }

    #[test]
    fn canonical_four_field_cfg_is_not_rejected_n0052() {
        for (import, entry) in [
            ("Ipe.Tea.Tui as Tui", "Tui.tea"),
            ("Ipe.Tea.Cli as Cli", "Cli.tea"),
        ] {
            let src = format!(
                "module Main exposing (main)\n\
                 import {import}\n\n\
                 main = {entry} {{ init = 0, update = 0, view = 0, subscriptions = 0 }}\n"
            );
            assert_eq!(input_field_error(&src), None, "`{entry}` four-field config");
        }
        // The other entry's field name is not this entry's input field: it falls
        // to the closed-row type check, not this gate.
        let src = "module Main exposing (main)\n\
                   import Ipe.Tea.Tui as Tui\n\n\
                   main = Tui.tea { init = 0, update = 0, view = 0, subscriptions = 0, onLine = 0 }\n";
        assert_eq!(input_field_error(src), None);
    }

    #[test]
    fn plain_task_main_branching_on_a_value_is_not_a_shape_choice() {
        // A script's `main` is ONE shape (Script) no matter what its `Task`
        // computes: branching on a value inside a `Task Error ()` `main` selects a
        // value, not a shape, and must NOT trip IPE-N0045.
        let src = "module Main exposing (main)\n\
                   import Ipe.Io as Io\n\n\
                   flag = True\n\n\
                   main =\n    if flag then\n        Io.println \"a\"\n    else\n        Io.println \"b\"\n";
        assert!(
            !matches!(
                canon_module_err(src),
                Some(Diagnostic::Name {
                    msg: NameError::RuntimeBranchedMain,
                    ..
                })
            ),
            "a plain `Task`-valued `main` branching on a value is a script, not a \
             run-time shape choice — it must NOT trip IPE-N0045"
        );
    }

    #[test]
    fn helper_submodule_without_main_importing_tea_shape_is_not_gated_n0033() {
        // The Program/TEA distinction is only about an ENTRY module (one that
        // defines `main`). A helper submodule with no `main` that imports
        // `Ipe.Tea.Web.Cmd` solely to name `Cmd` in an `update` signature and
        // build `Cmd.none` effects is a library module — neither a Program nor
        // an app entry — so it must NOT trip the IPE-N0033 gate.
        let src = "module Update exposing (update)\n\
                   import Ipe.Tea.Web.Cmd as Cmd\n\n\
                   update msg model =\n    ( model, Cmd.none )\n";
        assert!(
            canon_err(src).is_none(),
            "a `main`-less helper submodule importing a TEA shape must not trip \
             the IPE-N0033 gate"
        );
    }

    #[test]
    fn generic_tea_app_surface_is_no_longer_a_known_module() {
        // A Direct program's `main` is a `Task Error ()`; the generic
        // `Ipe.Tea` view-ful entry (surface `Tea.app`) is retired in favour
        // of the per-engine `Web.tea`. So `import Ipe.Tea` no longer names a
        // known module — the shape-scoped `Ipe.Tea.Web` / `.Tui` / `.Cli` /
        // `.Worker` surfaces remain, but the bare generic one is gone.
        let err = canon_module_err("module Main exposing (main)\nimport Ipe.Tea\n\nmain = 0\n");
        let Some(Diagnostic::Name {
            msg: NameError::ModuleNotFound { name, .. },
            ..
        }) = err
        else {
            assert!(
                false_marker(),
                "expected ModuleNotFound for the retired `Ipe.Tea`, got {err:?}"
            );
            return;
        };
        assert_eq!(&*name, "Ipe.Tea");
    }

    #[test]
    fn stdlib_exposing_member_resolves_unqualified() {
        // `import Ipe.System exposing (exit)` → bare `exit` resolves via the
        // exposing path to `VarKernel { module: System, name: exit }`.
        let src = "module Main exposing (main)\n\
                   import Ipe.System exposing (exit)\n\n\
                   main = exit\n";
        let Some((m, i)) = canon_src(src) else {
            assert!(false_marker(), "exposing (exit) must canonicalise");
            return;
        };
        assert_main_is_kernel(&m, &i, "System", "exit");
    }

    #[test]
    fn stdlib_exposing_nonmember_is_name_not_exposed() {
        // Fail-closed: a lowercase name that is NOT a real value member of the
        // module surfaces `NameNotExposed`, never a dangling unqualified binding.
        let err = canon_err(
            "module Main exposing (main)\n\
             import Ipe.Tea.Web exposing (bogusFn)\n\
             main = 0\n",
        );
        let Some(Diagnostic::Name {
            msg: NameError::NameNotExposed { module, name, .. },
            ..
        }) = &err
        else {
            assert!(false_marker(), "expected NameNotExposed, got {err:?}");
            return;
        };
        assert_eq!(&**name, "bogusFn");
        assert_eq!(&**module, "Ipe.Tea.Web");
    }

    #[test]
    fn stdlib_exposed_name_colliding_with_local_is_duplicate_value() {
        // An exposed name folds into `seen_values`, so a user top-level value of
        // the same name is a genuine conflict (`DuplicateValue`), matching Elm's
        // rule that importing a name and defining it locally clash.
        let err = canon_err(
            "module Main exposing (main)\n\
             import Ipe.Tea.Web exposing (tea)\n\
             tea = 1\n\
             main = 0\n",
        );
        assert!(
            matches!(
                &err,
                Some(Diagnostic::Name {
                    msg: NameError::DuplicateValue { .. },
                    ..
                })
            ),
            "expected DuplicateValue, got {err:?}"
        );
    }

    #[test]
    fn stdlib_exposing_type_is_untouched() {
        // Capitalized TYPE exposures (`exposing (Element)`) are kernel-implicit
        // types resolved elsewhere — the value-injection pass must NOT reject
        // them as non-members. This must canonicalise cleanly.
        let ok = canon_src(
            "module Main exposing (main)\n\
             import Ipe.Ui exposing (Element)\n\
             main = 0\n",
        );
        assert!(
            ok.is_some(),
            "type exposure of a stdlib module must not be rejected as a non-member value"
        );
    }

    #[test]
    fn stdlib_exposing_wildcard_allows_local_shadow() {
        // `exposing (..)` on a stdlib module floods the LOW-PRIORITY
        // wildcard tier. A local `withDefault` must NOT collide (no `DuplicateValue`) and
        // a bare `withDefault` use must resolve to the LOCAL binding, silently shadowing
        // the wildcard member (`Ipe.Maybe` exports `withDefault`).
        let src = "module Main exposing (main)\n\
                   import Ipe.Maybe exposing (..)\n\
                   withDefault = 1\n\
                   main = withDefault\n";
        let Some((m, i)) = canon_src(src) else {
            assert!(false_marker(), "local shadow of a wildcard member is legal");
            return;
        };
        let body = match find_def(&m, &i, "main") {
            Some(Def::Untyped { body, .. } | Def::Typed { body, .. }) => Some(&body.value),
            None => None,
        };
        assert!(
            matches!(body, Some(Expr_::VarTopLevel { name, .. }) if i.resolve(*name) == Some("withDefault")),
            "bare `withDefault` must resolve to the LOCAL top-level binding, got {body:?}"
        );
    }

    // ── `import Ipê.*/Ipe.* exposing (..)` floods the low-priority wildcard
    // tier ─────────────────────────────────────────────────────────────────────

    #[test]
    fn stdlib_wildcard_brings_member_into_unqualified_scope() {
        // `import Ipe.Ui.Font exposing (..)` → bare `bold` resolves to the same
        // `VarKernel { module: Font, name: bold }` a `Font.bold` reference would.
        // This is the wildcard-tier flood a kernel-qualifier module gets on an open
        // import (`Ipe.Ui` is compiled-source now, so `Ipe.Ui.Font` is the example).
        let src = "module Main exposing (main)\n\
                   import Ipe.Ui.Font exposing (..)\n\n\
                   main = bold\n";
        let Some((m, i)) = canon_src(src) else {
            assert!(false_marker(), "wildcard `bold` must canonicalise");
            return;
        };
        assert_main_is_kernel(&m, &i, "Font", "bold");
    }

    #[test]
    fn stdlib_wildcard_member_lowers_identically_to_qualified() {
        // A wildcard `bold` and a qualified `Font.bold` must produce the same
        // `VarKernel` (identical module + name), so lowering is unaffected.
        let bare = "module Main exposing (main)\n\
                    import Ipe.Ui.Font exposing (..)\n\n\
                    main = bold\n";
        let qual = "module Main exposing (main)\n\
                    import Ipe.Ui.Font\n\n\
                    main = Font.bold\n";
        let Some((mb, ib)) = canon_src(bare) else {
            assert!(false_marker(), "bare wildcard `bold` must canonicalise");
            return;
        };
        let Some((mq, iq)) = canon_src(qual) else {
            assert!(false_marker(), "qualified `Font.bold` must canonicalise");
            return;
        };
        let kernel_of = |m: &ast::Module, i: &Interner| -> Option<(String, String)> {
            match find_def(m, i, "main") {
                Some(Def::Untyped { body, .. } | Def::Typed { body, .. }) => match &body.value {
                    Expr_::VarKernel { module, name, .. } => Some((
                        i.resolve(*module)?.to_string(),
                        i.resolve(*name)?.to_string(),
                    )),
                    _ => None,
                },
                None => None,
            }
        };
        assert_eq!(
            kernel_of(&mb, &ib),
            Some(("Font".to_string(), "bold".to_string())),
            "bare wildcard `bold` resolves to VarKernel(Font, bold)"
        );
        assert_eq!(
            kernel_of(&mb, &ib),
            kernel_of(&mq, &iq),
            "wildcard and qualified references must lower identically"
        );
    }

    #[test]
    fn two_stdlib_wildcards_same_name_is_ambiguous_at_use() {
        // Both `Ipe.Ui.Background` and `Ipe.Ui.Font` export `color`. Two
        // `exposing (..)` imports are BOTH legal at import time; a bare `color` USE
        // is `AmbiguousImport` (IPE-N0024), never a silent last-wins.
        let err = canon_err(
            "module Main exposing (main)\n\
             import Ipe.Ui.Background exposing (..)\n\
             import Ipe.Ui.Font exposing (..)\n\
             main = color\n",
        );
        let Some(Diagnostic::Name {
            msg: NameError::AmbiguousImport { name, modules },
            ..
        }) = &err
        else {
            assert!(false_marker(), "expected AmbiguousImport, got {err:?}");
            return;
        };
        assert_eq!(&**name, "color");
        // The origins render in canonical string order regardless of import
        // order — `Background` precedes `Font` because the diagnostic newtype
        // sorts the resolved dot-strings, not the interner-allocation sequence.
        let rendered: Vec<&str> = modules.iter().map(AsRef::as_ref).collect();
        assert_eq!(rendered, vec!["Ipe.Ui.Background", "Ipe.Ui.Font"]);
    }

    /// The ambiguous-origin list orders by resolved module dot-string, not by
    /// import order — swapping the two `import` lines yields byte-identical
    /// origins. Two imports whose dot-strings sort OPPOSITE to their source
    /// order would, without the newtype, render in interner-allocation order.
    #[test]
    fn ambiguous_import_origins_are_string_ordered_not_import_ordered() {
        let font_first = canon_err(
            "module Main exposing (main)\n\
             import Ipe.Ui.Font exposing (..)\n\
             import Ipe.Ui.Background exposing (..)\n\
             main = color\n",
        );
        let background_first = canon_err(
            "module Main exposing (main)\n\
             import Ipe.Ui.Background exposing (..)\n\
             import Ipe.Ui.Font exposing (..)\n\
             main = color\n",
        );
        let origins = |err: &Option<Diagnostic>| -> Vec<String> {
            let Some(Diagnostic::Name {
                msg: NameError::AmbiguousImport { modules, .. },
                ..
            }) = err
            else {
                return Vec::new();
            };
            modules.iter().map(|m| (**m).to_owned()).collect()
        };
        let ordered = vec!["Ipe.Ui.Background".to_owned(), "Ipe.Ui.Font".to_owned()];
        assert_eq!(origins(&font_first), ordered);
        assert_eq!(origins(&background_first), ordered);
        assert_eq!(origins(&font_first), origins(&background_first));
    }

    #[test]
    fn two_compiled_stdlib_wildcards_sharing_a_leaf_are_ambiguous_at_use() {
        // Two DISTINCT compiled-source stdlib modules whose paths share a LEAF
        // segment (`Ipe.Foo.Widget` and `Ipe.Bar.Widget`), each open-imported and
        // each exposing the same bare `gadget`, must make a bare use of `gadget`
        // an `AmbiguousImport` (IPE-N0024) — the wildcard-origin map keys on the
        // FULL dotted path, so the shared leaf `Widget` can never collapse the two
        // origins into one and silently mask the ambiguity (last-wins). Keyed on
        // the leaf alone, this test resolves `gadget` to a single surviving origin
        // and no diagnostic is raised.
        let mut i = Interner::new();
        let ipe = i.intern("Ipe").expect("intern Ipe");
        let foo = i.intern("Foo").expect("intern Foo");
        let bar = i.intern("Bar").expect("intern Bar");
        let widget = i.intern("Widget").expect("intern Widget");
        let gadget = i.intern("gadget").expect("intern gadget");

        // Hand-built compiled-source deps: a user module can never DECLARE an
        // `Ipe.*` name (ReservedNamespace), but the build driver injects real
        // compiled-source stdlib modules under `Ipe.*` paths into `deps` exactly
        // like this, so constructing the exports directly is faithful.
        let foo_widget = ModuleExports {
            path: vec![ipe, foo, widget],
            values: BTreeSet::from([gadget]),
            ..ModuleExports::default()
        };
        let bar_widget = ModuleExports {
            path: vec![ipe, bar, widget],
            values: BTreeSet::from([gadget]),
            ..ModuleExports::default()
        };

        let mut deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        deps.insert(foo_widget.path.clone(), foo_widget);
        deps.insert(bar_widget.path.clone(), bar_widget);

        // Distinct `as` aliases keep the auto-qualifiers (both would default to the
        // shared leaf `Widget`) from colliding as a separate `DuplicateQualifier`
        // — the point under test is the bare-VALUE wildcard ambiguity, not the
        // qualifier one.
        let main_src = "module Main exposing (main)\n\
                        import Ipe.Foo.Widget as FW exposing (..)\n\
                        import Ipe.Bar.Widget as BW exposing (..)\n\
                        main = gadget\n";
        let parsed = ipe_parse::parse_module(main_src, &mut i).expect("main parses");
        let expected = parsed.name.value.clone();
        let err = canonicalise_module(&parsed, &expected, &deps, &mut i).err();

        let Some(Diagnostic::Name {
            msg: NameError::AmbiguousImport { name, modules },
            ..
        }) = &err
        else {
            assert!(
                false_marker(),
                "same-leaf compiled-source wildcards must be AmbiguousImport at \
                 the bare use, got {err:?}"
            );
            return;
        };
        assert_eq!(&**name, "gadget");
        assert!(
            modules.iter().any(|m| &**m == "Ipe.Foo.Widget")
                && modules.iter().any(|m| &**m == "Ipe.Bar.Widget"),
            "both same-leaf origins must be named, got {modules:?}"
        );
    }

    #[test]
    fn two_stdlib_wildcards_shared_name_ok_when_unused() {
        // The ambiguity is deferred: two wildcards sharing `color` are legal as
        // long as no bare `color` is used (a non-shared name still resolves).
        let ok = canon_src(
            "module Main exposing (main)\n\
             import Ipe.Ui.Background exposing (..)\n\
             import Ipe.Ui.Font exposing (..)\n\
             main = bold\n",
        );
        assert!(
            ok.is_some(),
            "unused shared wildcard name must not fail at import time"
        );
    }

    #[test]
    fn two_stdlib_wildcards_ambiguity_resolved_by_local() {
        // A local binding silently shadows BOTH wildcard origins — no ambiguity,
        // no `DuplicateValue`.
        let src = "module Main exposing (main)\n\
                   import Ipe.Ui.Background exposing (..)\n\
                   import Ipe.Ui.Font exposing (..)\n\
                   color = 1\n\
                   main = color\n";
        let Some((m, i)) = canon_src(src) else {
            assert!(false_marker(), "local shadow resolves the ambiguity");
            return;
        };
        let body = match find_def(&m, &i, "main") {
            Some(Def::Untyped { body, .. } | Def::Typed { body, .. }) => Some(&body.value),
            None => None,
        };
        assert!(
            matches!(body, Some(Expr_::VarTopLevel { name, .. }) if i.resolve(*name) == Some("color")),
            "local `color` shadows both wildcards, got {body:?}"
        );
    }

    #[test]
    fn a_local_value_shadows_the_prelude_without_a_duplicate() {
        let src = "module Main exposing (main)\n\
                   max : Int -> Int -> Int\n\
                   max a _b = a\n\
                   main = max\n";
        let Some((m, i)) = canon_src(src) else {
            assert!(
                false_marker(),
                "a local `max` is no duplicate of the prelude's"
            );
            return;
        };
        let Some(Def::Untyped { body, .. }) = find_def(&m, &i, "main") else {
            assert!(false_marker(), "main should be an untyped def");
            return;
        };
        assert!(
            matches!(body.value, Expr_::VarTopLevel { name, .. } if i.resolve(name) == Some("max")),
            "a bare `max` names the local definition, got {:?}",
            body.value
        );
    }

    #[test]
    fn stdlib_wildcard_shadowed_by_explicit_exposing() {
        // An explicit `exposing (color)` (the explicit tier) wins over
        // a wildcard `color`; the pair is NOT ambiguous. Resolves to Font.color.
        let src = "module Main exposing (main)\n\
                   import Ipe.Ui.Background exposing (..)\n\
                   import Ipe.Ui.Font exposing (color)\n\
                   main = color\n";
        let Some((m, i)) = canon_src(src) else {
            assert!(false_marker(), "explicit exposure wins over wildcard");
            return;
        };
        assert_main_is_kernel(&m, &i, "Font", "color");
    }

    #[test]
    fn stdlib_wildcard_same_module_twice_not_ambiguous() {
        // Importing the same module under an alias AND a wildcard must not fake a
        // self-ambiguity (dedup by canonical qualifier).
        let src = "module Main exposing (main)\n\
                   import Ipe.Ui.Font exposing (..)\n\
                   import Ipe.Ui.Font as F exposing (..)\n\
                   main = bold\n";
        let Some((m, i)) = canon_src(src) else {
            assert!(false_marker(), "same module twice must not be ambiguous");
            return;
        };
        assert_main_is_kernel(&m, &i, "Font", "bold");
    }

    #[test]
    fn explicit_exposing_still_collides_with_local() {
        // An EXPLICIT `exposing (tea)` hard-collides
        // with a local `tea` (`DuplicateValue`) — unlike a wildcard member.
        let err = canon_err(
            "module Main exposing (main)\n\
             import Ipe.Tea.Web exposing (tea)\n\
             tea = 1\n\
             main = 0\n",
        );
        assert!(
            matches!(
                &err,
                Some(Diagnostic::Name {
                    msg: NameError::DuplicateValue { .. },
                    ..
                })
            ),
            "explicit exposure must still collide, got {err:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ModuleOrigin: unforgeable stdlib trust tag.
    // ─────────────────────────────────────────────────────────────────────────

    /// Canonicalise `src` with an explicit [`ModuleOrigin`], returning the result.
    fn canon_with_origin(src: &str, origin: ModuleOrigin) -> DResult<(ast::Module, ModuleExports)> {
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i).expect("spike source parses");
        let expected: Vec<Symbol> = parsed.name.value.clone();
        let deps: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
        canonicalise_module_with_origin(&parsed, &expected, &deps, origin, &mut i)
    }

    /// The exact spike module, declaring `module Ipe.Palette` and matching its
    /// own ctor.
    const PALETTE_SRC: &str = "module Ipe.Palette exposing (Shade(..), toHex)\n\
         type Shade = Dark | Light\n\
         toHex : Shade -> String\n\
         toHex shade =\n    case shade of\n        Dark -> \"#000\"\n        Light -> \"#fff\"\n";

    #[test]
    fn embedded_stdlib_origin_exempts_reserved_namespace() {
        // The compiled-source path: a driver-vouched `Ipe.Palette` is accepted,
        // reserved-namespace gate exempted — it is the legitimate definer.
        let res = canon_with_origin(PALETTE_SRC, ModuleOrigin::EmbeddedStdlib);
        assert!(
            res.is_ok(),
            "EmbeddedStdlib Ipe.Palette must canonicalise: {:?}",
            res.err()
        );
    }

    #[test]
    fn user_origin_std_module_is_reserved_namespace() {
        // SECURITY: the SAME text, tagged User (a hostile file literally named
        // `Ipe.Palette`), stays N0025-rejected. Trust is the tag, not the name.
        let err = canon_with_origin(PALETTE_SRC, ModuleOrigin::User)
            .expect_err("user Ipe.Palette must be rejected");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::ReservedNamespace { .. },
                    ..
                }
            ),
            "hostile user Ipe.Palette must be IPE-N0025, got {err:?}"
        );
    }

    /// A dotted `Ipe.<M>.Unsafe` submodule — the escape-hatch home the
    /// `unsafe` capability discloses. The reserved-namespace gate keys on the
    /// FIRST segment (`Ipe`) only, so a driver-vouched `EmbeddedStdlib`
    /// submodule with a trailing `Unsafe` segment resolves through the same
    /// exemption as `Ipe.Palette` — no new module-system concept, no
    /// reserved-type-list change.
    const DB_UNSAFE_SRC: &str = "module Ipe.Db.Unsafe exposing (marker)\n\
         marker : String\n\
         marker =\n    \"x\"\n";

    #[test]
    fn embedded_stdlib_origin_hosts_a_dotted_unsafe_submodule() {
        let res = canon_with_origin(DB_UNSAFE_SRC, ModuleOrigin::EmbeddedStdlib);
        assert!(
            res.is_ok(),
            "EmbeddedStdlib `Ipe.Db.Unsafe` must canonicalise via the reserved-namespace exemption: {:?}",
            res.err()
        );
    }

    #[test]
    fn user_origin_ipe_unsafe_submodule_is_reserved_namespace() {
        // SECURITY: a hostile user file literally named `Ipe.Db.Unsafe` cannot
        // squat the escape-hatch home — it reaches canon as `User` origin and
        // stays N0025-rejected. Trust is the driver's tag, never the name, so a
        // program cannot forge the `.Unsafe` home to disclose (or hide) `unsafe`.
        let err = canon_with_origin(DB_UNSAFE_SRC, ModuleOrigin::User)
            .expect_err("user `Ipe.Db.Unsafe` must be rejected");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::ReservedNamespace { .. },
                    ..
                }
            ),
            "hostile user `Ipe.Db.Unsafe` must be IPE-N0025, got {err:?}"
        );
    }

    /// A four-segment `Ipe.Web.Head.Unsafe` submodule — the JSON-LD hatch home —
    /// resolves under the same reserved-namespace exemption when the driver tags
    /// it `EmbeddedStdlib`. The gate keys on the FIRST segment (`Ipe`), so the
    /// extra depth versus `Ipe.Db.Unsafe` changes nothing.
    const WEB_HEAD_UNSAFE_SRC: &str = "module Ipe.Web.Head.Unsafe exposing (marker)\n\
         marker : String\n\
         marker =\n    \"x\"\n";

    #[test]
    fn embedded_stdlib_origin_hosts_a_dotted_web_head_unsafe_submodule() {
        let res = canon_with_origin(WEB_HEAD_UNSAFE_SRC, ModuleOrigin::EmbeddedStdlib);
        assert!(
            res.is_ok(),
            "EmbeddedStdlib `Ipe.Web.Head.Unsafe` must canonicalise via the reserved-namespace exemption: {:?}",
            res.err()
        );
    }

    #[test]
    fn user_origin_ipe_web_head_unsafe_submodule_is_reserved_namespace() {
        // SECURITY: a hostile user file literally named `Ipe.Web.Head.Unsafe`
        // cannot squat the JSON-LD escape-hatch home — it reaches canon as `User`
        // origin and stays N0025-rejected. Trust is the driver's tag, never the
        // name, so a program cannot forge the `.Unsafe` home to disclose (or hide)
        // `unsafe`.
        let err = canon_with_origin(WEB_HEAD_UNSAFE_SRC, ModuleOrigin::User)
            .expect_err("user `Ipe.Web.Head.Unsafe` must be rejected");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::ReservedNamespace { .. },
                    ..
                }
            ),
            "hostile user `Ipe.Web.Head.Unsafe` must be IPE-N0025, got {err:?}"
        );
    }

    /// The `Ipe.Html.Unsafe` submodule — the un-escaped raw-HTML hatch home —
    /// resolves under the reserved-namespace exemption when the driver tags it
    /// `EmbeddedStdlib`, exactly like `Ipe.Db.Unsafe`.
    const HTML_UNSAFE_SRC: &str = "module Ipe.Html.Unsafe exposing (marker)\n\
         marker : String\n\
         marker =\n    \"x\"\n";

    #[test]
    fn embedded_stdlib_origin_hosts_a_dotted_html_unsafe_submodule() {
        let res = canon_with_origin(HTML_UNSAFE_SRC, ModuleOrigin::EmbeddedStdlib);
        assert!(
            res.is_ok(),
            "EmbeddedStdlib `Ipe.Html.Unsafe` must canonicalise via the reserved-namespace exemption: {:?}",
            res.err()
        );
    }

    #[test]
    fn user_origin_ipe_html_unsafe_submodule_is_reserved_namespace() {
        // SECURITY: a hostile user file literally named `Ipe.Html.Unsafe` cannot
        // squat the raw-HTML escape-hatch home — it reaches canon as `User` origin
        // and stays N0025-rejected. Trust is the driver's tag, never the name, so a
        // program cannot forge the `.Unsafe` home to disclose (or hide) `unsafe`.
        let err = canon_with_origin(HTML_UNSAFE_SRC, ModuleOrigin::User)
            .expect_err("user `Ipe.Html.Unsafe` must be rejected");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::ReservedNamespace { .. },
                    ..
                }
            ),
            "hostile user `Ipe.Html.Unsafe` must be IPE-N0025, got {err:?}"
        );
    }

    /// A third-party dependency masquerading as first-party: a package (whatever
    /// its name) that declares `module Ipe.Evil`. A dependency's module reaches
    /// canon as `ModuleOrigin::User` exactly like a local file — only the
    /// driver's stdlib-injection origin is exempt — so it is IPE-N0025-rejected,
    /// squat-proofing the trusted `Ipe.*` namespace at compile time.
    const THIRD_PARTY_IPE_SRC: &str = "module Ipe.Evil exposing (payload)\n\
         payload : String\n\
         payload =\n    \"x\"\n";

    #[test]
    fn third_party_dep_declaring_reserved_ipe_module_is_rejected() {
        let err = canon_with_origin(THIRD_PARTY_IPE_SRC, ModuleOrigin::User)
            .expect_err("a third-party `Ipe.Evil` must be rejected");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::ReservedNamespace { .. },
                    ..
                }
            ),
            "third-party `Ipe.Evil` must be IPE-N0025, got {err:?}"
        );
    }

    /// A user (or dependency) module squatting the `Rust.*` FFI-interface
    /// namespace. Only `ModuleOrigin::FfiInterface` — the driver-generated FFI
    /// interface origin — may define a `Rust.*` home; a `User`-origin one is
    /// refused via the same closed reserved-prefix set.
    const USER_RUST_SRC: &str = "module Rust.Firestore exposing (payload)\n\
         payload : String\n\
         payload =\n    \"x\"\n";

    #[test]
    fn user_origin_rust_module_is_reserved_namespace() {
        let err = canon_with_origin(USER_RUST_SRC, ModuleOrigin::User)
            .expect_err("user `Rust.Firestore` must be rejected");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::ReservedNamespace { .. },
                    ..
                }
            ),
            "user `Rust.Firestore` must be IPE-N0025, got {err:?}"
        );
    }

    #[test]
    fn reserved_prefix_gate_reads_the_kernels_ssot() {
        // The resolver's reserved-prefix identity is the closed kernels-crate
        // list, not a local re-listing: `Ipe`/`Rust` are reserved, an ordinary
        // module home is not.
        assert_eq!(
            ipe_kernels::reserved_prefix_of(&["Ipe", "Palette"]),
            Some("Ipe")
        );
        assert_eq!(
            ipe_kernels::reserved_prefix_of(&["Rust", "Zstd"]),
            Some("Rust")
        );
        assert_eq!(ipe_kernels::reserved_prefix_of(&["App", "View"]), None);
    }

    /// A USER module minting an UNSAFE-tier kernel alias (`Kernel.kernel
    /// "Html_unsafeScript"` — the raw-`<script>` XSS sink). No `.Unsafe` import,
    /// so before the origin gate this canonicalised clean while `capabilities`
    /// reported `pure`: the capability-model bypass the gate closes.
    const USER_MINTS_UNSAFE_KERNEL_SRC: &str = "module Main exposing (main)\n\
         import Ipe.Ffi.Kernel as Kernel\n\
         sneaky : String -> Html msg\n\
         sneaky =\n    Kernel.kernel \"Html_unsafeScript\"\n\
         main =\n    0\n";

    /// A USER module minting an ORDINARY (safe-tier) kernel alias. Rejected too —
    /// the privilege is denied by ORIGIN, not by which kernel is named, so there
    /// is no "safe kernel" loophole for user source to mint through.
    const USER_MINTS_PLAIN_KERNEL_SRC: &str = "module Main exposing (main)\n\
         import Ipe.Ffi.Kernel as Kernel\n\
         shout : String -> String\n\
         shout =\n    Kernel.kernel \"String_toUpper\"\n\
         main =\n    0\n";

    #[test]
    fn user_origin_cannot_mint_an_unsafe_kernel_alias() {
        // SECURITY: user source may not mint a kernel alias — an unsafe kernel
        // must be reached only through its `.Unsafe` module, which discloses
        // `unsafe`. The origin gate makes the bypass unrepresentable.
        let err = canon_with_origin(USER_MINTS_UNSAFE_KERNEL_SRC, ModuleOrigin::User)
            .expect_err("user source minting `Kernel.kernel` must be rejected");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::KernelAliasInUserSource { .. },
                    ..
                }
            ),
            "user-source kernel alias must be IPE-N0042, got {err:?}"
        );
    }

    #[test]
    fn user_origin_cannot_mint_even_a_plain_kernel_alias() {
        // SECURITY: the gate is by ORIGIN, not by kernel tier — a user module
        // cannot mint any kernel alias, safe-tier included.
        let err = canon_with_origin(USER_MINTS_PLAIN_KERNEL_SRC, ModuleOrigin::User)
            .expect_err("user source minting any `Kernel.kernel` must be rejected");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::KernelAliasInUserSource { .. },
                    ..
                }
            ),
            "user-source kernel alias must be IPE-N0042, got {err:?}"
        );
    }

    #[test]
    fn embedded_stdlib_origin_still_mints_the_unsafe_kernel_alias() {
        // NON-REGRESS: the SAME `Kernel.kernel "Html_unsafeScript"` binding, in a
        // driver-vouched EmbeddedStdlib module (this IS the body of the real
        // `Ipe.Html.Unsafe` submodule), must still canonicalise — the legitimate
        // kernel-alias surface is untouched by the origin gate.
        let src = "module Ipe.Html.Unsafe exposing (unsafeScript)\n\
             import Ipe.Ffi.Kernel as Kernel\n\
             unsafeScript : String -> Html msg\n\
             unsafeScript =\n    Kernel.kernel \"Html_unsafeScript\"\n";
        let res = canon_with_origin(src, ModuleOrigin::EmbeddedStdlib);
        assert!(
            res.is_ok(),
            "EmbeddedStdlib kernel alias must still canonicalise: {:?}",
            res.err()
        );
    }

    #[test]
    fn embedded_stdlib_unannotated_binding_fails_closed() {
        // The fail-closed annotation gate: an EmbeddedStdlib module with an
        // un-annotated top-level binding is a compiler-internal error at canon,
        // never an exit-0-then-cargo-fail. `bad` has no signature.
        let src = "module Ipe.Foo exposing (bad)\n\
             good : Int\n\
             good = 1\n\
             bad = good\n";
        let err = canon_with_origin(src, ModuleOrigin::EmbeddedStdlib)
            .expect_err("unannotated stdlib binding must fail closed");
        assert!(
            matches!(
                &err,
                Diagnostic::CompilerBug {
                    where_: "canon.stdlib_unannotated",
                    ..
                }
            ),
            "unannotated EmbeddedStdlib binding must be a fail-closed CompilerBug, got {err:?}"
        );
    }

    #[test]
    fn user_unannotated_binding_is_fine() {
        // The gate can NEVER fire for user code: an un-annotated top-level in a
        // normal user module is business as usual.
        let res = canon_with_origin(
            "module Main exposing (main)\nmain = 0\n",
            ModuleOrigin::User,
        );
        assert!(
            res.is_ok(),
            "user unannotated main is fine: {:?}",
            res.err()
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IPE-N0034 regression: a compiled-source stdlib module that itself imports
    // another stdlib module must not fire IPE-N0034 on its OWN import.
    //
    // Ipe.Money imports `Ipe.String as String` and uses `String.*` in its body.
    // The Tier-C import gate (ADR 0001) must see that import as satisfied —
    // `register_stdlib_import_aliases` installs the qualifier BEFORE any body
    // reference reaches `resolve_qual_var`. If that ordering were broken, every
    // compiled-source stdlib module that imports a kernel module would fail
    // with IPE-N0034 on its own import.
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn embedded_stdlib_own_kernel_import_not_gated_n0034() {
        // A compiled-source module (`Ipe.Money`-like) that imports `Ipe.Crypto`
        // and uses `Crypto.sha256` must NOT fire IPE-N0034 — the module's
        // own `import Ipe.Crypto as Crypto` satisfies the Tier-C gate.
        let src = "module Ipe.Money exposing (show)\n\
             import Ipe.Crypto as Crypto\n\
             show : String -> String\n\
             show s = Crypto.sha256 s\n";
        let res = canon_with_origin(src, ModuleOrigin::EmbeddedStdlib);
        assert!(
            res.is_ok(),
            "EmbeddedStdlib module's own `import Ipe.Crypto` must satisfy the Tier-C gate \
             (no IPE-N0034): {:?}",
            res.err()
        );
    }

    #[test]
    fn user_module_without_import_still_fires_n0034() {
        // Mirror test: a USER module using `Crypto.sha256` without the import
        // must STILL fire N0034 — the EmbeddedStdlib exemption above must not
        // accidentally relax the gate for ordinary user code.
        let err = canon_with_origin(
            "module Main exposing (main)\nmain = Crypto.sha256 \"x\"\n",
            ModuleOrigin::User,
        );
        assert!(
            matches!(
                err.as_ref().err(),
                Some(Diagnostic::Name {
                    msg: NameError::ImportRequired { .. },
                    ..
                })
            ),
            "user module without import must still be IPE-N0034, got {err:?}"
        );
    }

    /// The IPE-N0034 candidate rule (`bare_import_binds`) agrees with what a
    /// bare import of every kernel module actually binds.
    ///
    /// For each kernel path and each spelling a use site may try (canonical,
    /// last segment, dotted path) that the gate refuses with no import, `import
    /// P` then `Q.member` resolves the qualifier exactly when the rule says the
    /// import binds it. A candidate the import would not bind (an applied fix
    /// that still fails), or a binding import left out of the list, goes red
    /// here. A spelling that resolves with no import never raises IPE-N0034, so
    /// no candidate list is built for it.
    #[test]
    fn candidate_rule_matches_kernel_import_binding() {
        let mut checked = 0usize;
        for (path, canonical) in STDLIB_MODULE_QUALIFIERS {
            let module = path.join(".");
            let last = path.last().copied().unwrap_or(&module);
            for qualifier in [*canonical, last, &module] {
                if qualifier_bound("", qualifier).0 != Some(false) {
                    continue;
                }
                checked += 1;
                let (bound, result) = qualifier_bound(&format!("import {module}\n"), qualifier);
                assert_eq!(
                    bound,
                    Some(bare_import_binds(&module, qualifier)),
                    "import {module}; {qualifier}.member: {result:?}"
                );
            }
        }
        assert!(checked > 0, "no gated kernel spelling was exercised");
    }

    /// Whether `qualifier.zzAbsentMember` reaches the qualifier's member table
    /// after `imports`: `Some(true)` resolved (or missed only the member),
    /// `Some(false)` the qualifier is gated or unknown, `None` anything else.
    fn qualifier_bound(
        imports: &str,
        qualifier: &str,
    ) -> (Option<bool>, DResult<(ast::Module, ModuleExports)>) {
        let src =
            format!("module Main exposing (main)\n{imports}main = {qualifier}.zzAbsentMember\n");
        let result = canon_with_origin(&src, ModuleOrigin::User);
        let bound = match &result {
            Ok(_)
            | Err(Diagnostic::Name {
                msg: NameError::NoSuchMember { .. },
                ..
            }) => Some(true),
            Err(Diagnostic::Name {
                msg: NameError::ImportRequired { .. } | NameError::UnknownModule { .. },
                ..
            }) => Some(false),
            Err(_) => None,
        };
        (bound, result)
    }

    #[test]
    fn local_module_shadowing_stdlib_qualifier_not_gated_n0034() {
        // A project-local module whose name collides with a gated stdlib
        // short-name (here `Auth`, colliding with the stdlib `Auth`) shadows the
        // Tier-C import gate: importing it brings its members into scope under
        // that qualifier, so `Auth.member` resolves against the LOCAL module and
        // must NOT raise IPE-N0034 for the un-imported stdlib `Auth`.
        let err = canon_main_with_dep(
            "module Auth exposing (verifyBearer)\n\
             verifyBearer : String -> Bool\n\
             verifyBearer token =\n    token == \"ok\"\n",
            "module Main exposing (main)\n\
             import Auth\n\n\
             main =\n    Auth.verifyBearer \"ok\"\n",
        );
        assert!(
            err.is_none(),
            "a local module shadowing a stdlib qualifier must resolve without \
             IPE-N0034, got {err:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ModuleOrigin-gated reserved-builtin exemption.
    //
    // The unforgeable `ModuleOrigin` and the home-aware lowerer (the nullary
    // Ipe.Ui opaque names sit BELOW the `enum_variants` guard) together mean the
    // canon reservation of those names is not load-bearing
    // for lowering-soundness, and a trusted `EmbeddedStdlib` module — the
    // canonical definer — is exempt for that subset while USER modules stay
    // rejected (keeping the user-facing "cannot shadow Length" guarantee).
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn embedded_stdlib_origin_exempts_reserved_ui_type() {
        // The capability compiled-source `Ipe.Css` needs: DEFINE `type Length`
        // (a reserved built-in name). Exempt ONLY because the driver vouched for
        // the origin (unforgeable). The same text tagged User is N0026-rejected
        // — see `user_type_shadowing_builtin_rejected`.
        let src = "module Ipe.Css exposing (Length(..))\n\
             type Length = Px Int\n";
        let res = canon_with_origin(src, ModuleOrigin::EmbeddedStdlib);
        assert!(
            res.is_ok(),
            "EmbeddedStdlib `type Length` must be exempt from IPE-N0026: {:?}",
            res.err()
        );
    }

    #[test]
    fn user_origin_reserved_ui_type_still_rejected() {
        // The mirror of the exemption: the identical `type Length`, in a
        // non-Std user module (so N0025 does not pre-empt), stays IPE-N0026.
        // A hostile author gets NEITHER the namespace nor the builtin exemption.
        let src = "module Main exposing (main)\n\
             type Length = Px Int\n\
             main = 0\n";
        let err = canon_with_origin(src, ModuleOrigin::User)
            .expect_err("user `type Length` must stay reserved");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::ReservedBuiltinType { .. },
                    ..
                }
            ),
            "user `type Length` must be IPE-N0026, got {err:?}"
        );
    }

    #[test]
    fn embedded_stdlib_origin_still_rejects_load_bearing_builtin() {
        // The carve-out is SCOPED to the below-guard nullary UI set
        // (`STDLIB_DEFINABLE_UI_TYPES`). `Html`'s lowerer arm sits ABOVE the
        // home-aware `enum_variants` guard, so a same-named union would be
        // hijacked to `IrType::Ui` and mis-lower — even trusted stdlib must not
        // redefine it. Stays IPE-N0026 for EVERY origin.
        let src = "module Ipe.Css exposing (Html(..))\n\
             type Html = Blob\n";
        let err = canon_with_origin(src, ModuleOrigin::EmbeddedStdlib)
            .expect_err("EmbeddedStdlib `type Html` must still be reserved");
        assert!(
            matches!(
                &err,
                Diagnostic::Name {
                    msg: NameError::ReservedBuiltinType { .. },
                    ..
                }
            ),
            "load-bearing builtin `Html` must stay IPE-N0026 even for stdlib, got {err:?}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IPE-N0010 regression: type-alias name coinciding with an ADT constructor
    // must NOT produce a DuplicateValue error.  The TYPE namespace (`type alias`)
    // and the CONSTRUCTOR namespace (`type … = Ctor`) are distinct in both
    // Elm and Ipê.  Reproduces the failure seen in
    // examples/25-ipe-console/src/State.ipe where `type Tab = Overview | …`
    // and `type alias Overview = { … }` coexist in the same module.
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn type_alias_name_coinciding_with_adt_ctor_is_not_a_duplicate_value() {
        // `type Tab = Overview | Metrics | Logs` defines ADT constructors.
        // `type alias Overview = { ipeVersion : String }` defines a type alias
        // in a SEPARATE namespace.  Both should coexist without an error.
        //
        // The regression was IPE-N0010 (DuplicateValue) from
        // `synthesize_record_alias_ctors` incorrectly checking `seen_ctors`.
        let src = "module Main exposing (main)\n\n\
                   type Tab = Overview | Metrics | Logs\n\n\
                   type alias Overview =\n    { ipeVersion : String\n    , commit : String\n    }\n\n\
                   main : Int\n\
                   main = 0\n";
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i);
        assert!(parsed.is_ok(), "source must parse");
        let Ok(parsed) = parsed else { return };
        let result = canonicalise(&parsed, &mut i);
        assert!(
            result.is_ok(),
            "type alias `Overview` and ADT ctor `Overview` must coexist without N0010; \
             got {result:?}"
        );
    }

    #[test]
    fn adt_ctor_wins_in_expression_position_over_same_named_alias() {
        // When both an ADT ctor `Overview` (from `type Tab = Overview | …`)
        // and a record alias `type alias Overview = { … }` share a name,
        // a bare `Overview` in expression position MUST resolve to the ADT
        // constructor, not to the alias auto-ctor (which is suppressed).
        // Verifies that `resolve_var` correctly returns `VarCtor`, not
        // `VarTopLevel`.
        let src = "module Main exposing (main)\n\n\
                   type Tab = Overview | Metrics\n\n\
                   type alias Overview =\n    { ipeVersion : String\n    }\n\n\
                   main : Tab\n\
                   main = Overview\n";
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i);
        assert!(parsed.is_ok(), "source must parse");
        let Ok(parsed) = parsed else { return };
        let m = canonicalise(&parsed, &mut i);
        assert!(m.is_ok(), "must canonicalise cleanly; got {m:?}");
        let Ok(m) = m else { return };
        // `main = Overview` → the body should be a VarCtor, not a VarTopLevel.
        let Some(Def::Typed { body, .. }) = find_def(&m, &i, "main") else {
            assert!(false_marker(), "main is a typed def");
            return;
        };
        assert!(
            matches!(body.value, Expr_::VarCtor { .. }),
            "bare `Overview` in expression position must resolve to the ADT ctor, \
             not to the alias auto-ctor; got {:?}",
            body.value
        );
        let Expr_::VarCtor {
            type_name,
            name,
            index,
            ..
        } = body.value
        else {
            return;
        };
        assert_eq!(i.resolve(type_name), Some("Tab"), "ctor belongs to `Tab`");
        assert_eq!(i.resolve(name), Some("Overview"), "ctor name is `Overview`");
        assert_eq!(index, 0, "`Overview` is the first ctor");
    }

    /// A qualified-home built-in union's constructors (`HttpMethod`'s verbs)
    /// are registered qualified-only, so a bare `Post` with NO import of
    /// `Ipe.Http` is unresolved — it must never resolve to the HTTP verb (and
    /// so never shadow a user's own `Post`).
    #[test]
    fn http_verb_unqualified_without_import_is_unresolved() {
        let err = canon_err(
            "module Main exposing (main)\n\
             main = Post\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::ValueNotFound { .. } | NameError::ConstructorNotFound { .. },
                    ..
                })
            ),
            "a bare `Post` with no `Ipe.Http` import must be unresolved; got {err:?}"
        );
    }

    /// A bare nullary constructor inside a triple-quoted interpolation
    /// (`{{Nothing}}`) resolves to its constructor value, exactly as the same
    /// bare name resolves outside an interpolation — never a blind `VarLocal`
    /// that would leak an unbound local past canonicalisation into `constrain`.
    #[test]
    fn interp_bare_ctor_resolves_to_the_constructor_value() {
        let mut i = Interner::new();
        let body = canon_body(
            &mut i,
            "module Main exposing (main)\n\
             main =\n    \"\"\"{{Nothing}}\"\"\"\n",
            "main",
        );
        // A triple-quoted interpolation `{{Nothing}}` desugars to
        // `Interpolate Nothing` (the internal renderer kernel), so the canonical
        // body is a `Call` whose one argument is the resolved reference. The fix
        // must make that argument the `Nothing` `VarCtor` value, never an unbound
        // `VarLocal`.
        let Some(Expr_::Call(_, args)) = body else {
            assert!(
                false_marker(),
                "`{{{{Nothing}}}}` must desugar to an `Interpolate` Call, got {body:?}"
            );
            return;
        };
        let Some(arg) = args.into_iter().next() else {
            assert!(
                false_marker(),
                "the interpolation Call must carry one argument"
            );
            return;
        };
        let Expr_::VarCtor { name, .. } = arg.value else {
            assert!(
                false_marker(),
                "`{{{{Nothing}}}}`'s interpolated ref must be the `Nothing` VarCtor, got {:?}",
                arg.value
            );
            return;
        };
        assert_eq!(
            i.resolve(name),
            Some("Nothing"),
            "resolved constructor is `Nothing`"
        );
    }

    /// An UNKNOWN bare name inside an interpolation (`{{typoo}}`) fails closed
    /// at the resolver with the ordinary IPE-N0001 `ValueNotFound` diagnostic —
    /// NOT a silent `VarLocal` that reaches `constrain` as a violated invariant
    /// (the unbound-local ICE this fix closes).
    #[test]
    fn interp_unknown_bare_name_is_a_typed_name_error_not_an_ice() {
        let err = canon_err(
            "module Main exposing (main)\n\
             main =\n    \"\"\"{{typoo}}\"\"\"\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::ValueNotFound { .. },
                    ..
                })
            ),
            "an unknown interpolation name must be a typed ValueNotFound, got {err:?}"
        );
    }

    /// A bare constructor spelling that names no constructor in scope
    /// (`{{Nope}}`) is likewise turned back with the typed unknown-name
    /// diagnostic rather than resolving or ICE-ing downstream.
    #[test]
    fn interp_unknown_bare_ctor_is_a_typed_name_error() {
        let err = canon_err(
            "module Main exposing (main)\n\
             main =\n    \"\"\"{{Nope}}\"\"\"\n",
        );
        assert!(
            matches!(
                err,
                Some(Diagnostic::Name {
                    msg: NameError::ValueNotFound { .. } | NameError::ConstructorNotFound { .. },
                    ..
                })
            ),
            "an unknown interpolation constructor must be a typed name error, got {err:?}"
        );
    }

    /// An explicit `import Ipe.Http exposing (HttpMethod(..))` brings the
    /// union's constructors into UNQUALIFIED scope: a bare `Post` resolves to
    /// the `HttpMethod` verb `VarCtor`, the whole meaning of open-import.
    #[test]
    fn http_verb_resolves_unqualified_when_type_is_exposed_open() {
        let src = "module Main exposing (main)\n\
                   import Ipe.Http as Http exposing (HttpMethod(..))\n\
                   main = Post\n";
        let mut i = Interner::new();
        let parsed = ipe_parse::parse_module(src, &mut i);
        assert!(parsed.is_ok(), "source must parse");
        let Ok(parsed) = parsed else { return };
        let m = canonicalise(&parsed, &mut i);
        assert!(m.is_ok(), "must canonicalise cleanly; got {m:?}");
        let Ok(m) = m else { return };
        let Some(Def::Untyped { body, .. }) = find_def(&m, &i, "main") else {
            assert!(false_marker(), "main is an untyped def");
            return;
        };
        assert!(
            matches!(body.value, Expr_::VarCtor { .. }),
            "bare `Post` under `exposing (HttpMethod(..))` must resolve to the \
             HttpMethod verb ctor; got {:?}",
            body.value
        );
        let Expr_::VarCtor {
            type_name, name, ..
        } = body.value
        else {
            return;
        };
        assert_eq!(
            i.resolve(type_name),
            Some("HttpMethod"),
            "ctor belongs to `HttpMethod`"
        );
        assert_eq!(i.resolve(name), Some("Post"), "ctor name is `Post`");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ipe.Ui.Lazy: module registration regression
    // ─────────────────────────────────────────────────────────────────────────

    /// `import Ipe.Ui.Lazy as Lazy` followed by a bare `Lazy.lazy` call must
    /// resolve without a name error.  If the qualifier "Lazy" were
    /// absent from `STDLIB_MODULE_QUALIFIERS` / `QUALIFIERS`, any reference
    /// to `Lazy.lazy` would fire `NameError::ValueNotFound`.
    #[test]
    fn lazy_module_lazy_resolves_without_name_error() {
        let err = canon_err(
            "module Main exposing (main)\n\
             import Ipe.Ui.Lazy as Lazy\n\
             main = Lazy.lazy identity 0\n",
        );
        assert!(
            err.is_none(),
            "#146 regression: `Lazy.lazy` must resolve cleanly; got {err:?}"
        );
    }

    /// All five arity variants (`lazy`..`lazy5`) must resolve.
    #[test]
    fn lazy_module_all_arities_resolve() {
        // Use integer literals for extra args — bare names like `x` aren't
        // in scope inside a minimal canon fixture and produce ValueNotFound.
        for (name, extra_args) in [
            ("lazy", " 0"),
            ("lazy2", " 0 1"),
            ("lazy3", " 0 1 2"),
            ("lazy4", " 0 1 2 3"),
            ("lazy5", " 0 1 2 3 4"),
        ] {
            let src = format!(
                "module Main exposing (main)\n\
                 import Ipe.Ui.Lazy as Lazy\n\
                 main = Lazy.{name} identity{extra_args}\n"
            );
            let err = canon_err(&src);
            assert!(
                err.is_none(),
                "#146 regression: `Lazy.{name}` must resolve cleanly; got {err:?}"
            );
        }
    }

    /// `Task.run` and `Task.perform` are removed from the Ipê surface.
    /// Any use of either must produce `IPE-N0036` (`RemovedSurface`), not a
    /// successful resolution.
    #[test]
    fn task_run_and_perform_emit_removed_surface_diagnostic() {
        // `RemovedSurface` fires before the import gate, so the import line is
        // intentionally absent — the diagnostic must fire on the bare qualifier use.
        // The removed name must appear FIRST in the expression so no earlier
        // qualifier use shadows the error.
        for (src, removed_name) in [
            (
                "module Main exposing (main)\n\
                 main = Task.run ()\n",
                "run",
            ),
            (
                "module Main exposing (main)\n\
                 main = Task.perform ()\n",
                "perform",
            ),
        ] {
            let diag = canon_err(src);
            assert!(
                matches!(
                    diag,
                    Some(Diagnostic::Name {
                        msg: NameError::RemovedSurface { ref name, .. },
                        ..
                    }) if name.as_ref() == removed_name
                ),
                "`Task.{removed_name}` must produce IPE-N0036 RemovedSurface; got: {diag:?}"
            );
        }
    }
}
