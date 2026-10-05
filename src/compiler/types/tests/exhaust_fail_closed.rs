//! Case-analysis over a union reached only through another module's interface.
//!
//! A module's scoped solve sees exactly the interfaces it imports. A union its
//! scrutinee carries may be declared further down the dependency graph, so the
//! signature tables must hold the transitive closure, or a catch-all over that
//! union escapes IPE-T0018 (and a missing head would be skipped, not refused).

use std::collections::BTreeMap;
use std::sync::Arc;

use ipe_canon::ModuleExports;
use ipe_diagnostics::{DResult, Diagnostic, TypeError};
use ipe_intern::{Interner, Symbol};
use ipe_types::{InferError, InterfaceStatus, ModuleInference, TypedInterface, infer_module};

/// One module of a fixture: its dotted path, its source, and its direct imports.
type Fixture<'a> = (&'a str, &'a str, &'a [&'a str]);

/// A module's scoped-solve outcome, with its closed interface when it has one.
struct Solved {
    result: Result<(), Diagnostic>,
    closed: bool,
    reachable_union_names: Vec<String>,
}

/// Solve dependency-first modules, each over the interfaces it imports only.
///
/// This is the shape the driver's per-module tier offers: a union declared two
/// imports down reaches a module only through an interface's closure. Returns
/// every module's outcome in order, or `None` when one fails to parse,
/// canonicalise, or name a closed import.
fn solve_direct(modules: &[Fixture<'_>]) -> Option<Vec<Solved>> {
    let mut i = Interner::new();
    let mut exports_by_path: BTreeMap<Vec<Symbol>, ModuleExports> = BTreeMap::new();
    let mut interfaces: BTreeMap<Vec<Symbol>, Arc<TypedInterface>> = BTreeMap::new();
    let mut out = Vec::new();
    for (path_str, src, imports) in modules {
        let mut intern_path = |dotted: &str| {
            dotted
                .split('.')
                .map(|seg| i.intern(seg))
                .collect::<DResult<Vec<Symbol>>>()
                .ok()
        };
        let path = intern_path(path_str)?;
        let mut direct: BTreeMap<Vec<Symbol>, Arc<TypedInterface>> = BTreeMap::new();
        for import in *imports {
            let import_path = intern_path(import)?;
            let iface = interfaces.get(&import_path)?;
            direct.insert(import_path, Arc::clone(iface));
        }
        let parsed = ipe_parse::parse_module(src, &mut i).ok()?;
        let (cm, exports) =
            ipe_canon::canonicalise_module(&parsed, &path, &exports_by_path, &mut i).ok()?;
        let solved = match infer_module(&cm, &exports, &direct, &mut i) {
            Ok(ModuleInference {
                interface: InterfaceStatus::Closed(iface),
                ..
            }) => {
                let reachable_union_names = iface
                    .reachable_unions
                    .iter()
                    .filter_map(|u| i.resolve(u.name).map(str::to_owned))
                    .collect();
                interfaces.insert(path.clone(), Arc::new(iface));
                Solved {
                    result: Ok(()),
                    closed: true,
                    reachable_union_names,
                }
            }
            Ok(_) => Solved {
                result: Ok(()),
                closed: false,
                reachable_union_names: Vec::new(),
            },
            Err(error) => Solved {
                result: Err(InferError::into_diagnostic(error)),
                closed: false,
                reachable_union_names: Vec::new(),
            },
        };
        exports_by_path.insert(path, exports);
        out.push(solved);
    }
    Some(out)
}

/// `C` declares a closed union; `B` hands out a value of it.
const C_SRC: &str = "module C exposing (T(..))\n\ntype T\n    = X\n    | Y\n";
const B_SRC: &str =
    "module B exposing (wrap)\n\nimport C exposing (T(..))\n\nwrap : T\nwrap =\n    X\n";

/// Whether `outcome` is the catch-all-over-a-closed-union refusal.
fn is_t0018(outcome: Option<&Solved>) -> bool {
    matches!(
        outcome.map(|s| &s.result),
        Some(Err(Diagnostic::Type {
            msg: TypeError::WildcardCoversKnownConstructors { .. },
            ..
        }))
    )
}

/// A `_`-only case over a union declared two imports down is IPE-T0018.
///
/// `A` imports only `B`; the scrutinee's type `C.T` reaches `A` through `B`'s
/// interface. Read from direct deps alone, the union is absent and the
/// catch-all escapes the judgement.
#[test]
fn wildcard_only_case_over_transitive_union_is_t0018() {
    let a_src = "module A exposing (main)\n\nimport B\n\nmain =\n    case B.wrap of\n        _ ->\n            0\n";
    let modules: [Fixture<'_>; 3] = [
        ("C", C_SRC, &[]),
        ("B", B_SRC, &["C"]),
        ("A", a_src, &["B"]),
    ];
    let solved = solve_direct(&modules).expect("the three-module fixture must canonicalise");
    assert!(
        is_t0018(solved.get(2)),
        "a `_`-only case over `C.T` reached through `B` must be refused: {:?}",
        solved.get(2).map(|s| &s.result)
    );
}

/// Naming every constructor of the transitively reached union is accepted.
///
/// The control for the refusal above: the same scrutinee, judged against the
/// same union, with `X` and `Y` spelled out.
#[test]
fn explicit_arms_over_transitive_union_are_accepted() {
    let a_src = "module A exposing (main)\n\nimport B\nimport C exposing (T(..))\n\n\
                 main =\n    case B.wrap of\n        X ->\n            0\n\n        Y ->\n            1\n";
    let modules: [Fixture<'_>; 3] = [
        ("C", C_SRC, &[]),
        ("B", B_SRC, &["C"]),
        ("A", a_src, &["B", "C"]),
    ];
    let solved = solve_direct(&modules).expect("the three-module fixture must canonicalise");
    assert!(
        matches!(solved.get(2).map(|s| &s.result), Some(Ok(()))),
        "explicit `X` / `Y` arms over `C.T` must be accepted: {:?}",
        solved.get(2).map(|s| &s.result)
    );
}

/// A diamond reaches one union along two paths and the closure keeps one copy.
///
/// `B` and `D` both import `C`; `E` imports both, so `C.T` arrives through two
/// interfaces. `E`'s closure must hold it once, and `A`, importing only `E`,
/// must still judge a catch-all over it. Interfaces are values built
/// dependency-first, so an import cycle has no representation here: the
/// closure is one pass over the direct deps and cannot loop.
#[test]
fn diamond_closure_terminates_and_holds_each_union_once() {
    let d_src =
        "module D exposing (other)\n\nimport C exposing (T(..))\n\nother : T\nother =\n    Y\n";
    let e_src = "module E exposing (pick)\n\nimport B\nimport D\n\npick =\n    if True then\n        B.wrap\n\n    else\n        D.other\n";
    let a_src = "module A exposing (main)\n\nimport E\n\nmain =\n    case E.pick of\n        _ ->\n            0\n";
    let modules: [Fixture<'_>; 5] = [
        ("C", C_SRC, &[]),
        ("B", B_SRC, &["C"]),
        ("D", d_src, &["C"]),
        ("E", e_src, &["B", "D"]),
        ("A", a_src, &["E"]),
    ];
    let solved = solve_direct(&modules).expect("the five-module fixture must canonicalise");
    let e = solved.get(3);
    assert!(e.is_some_and(|s| s.closed), "`E` must close its interface");
    assert_eq!(
        e.map(|s| s.reachable_union_names.clone()),
        Some(vec!["T".to_owned()]),
        "`E` reaches `C.T` along two paths and must hold it once"
    );
    assert!(
        is_t0018(solved.get(4)),
        "a `_`-only case over `C.T` reached through the diamond must be refused: {:?}",
        solved.get(4).map(|s| &s.result)
    );
}
