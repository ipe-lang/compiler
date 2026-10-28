//! Layer 2 of the wasm security gate (spec Q5): the exact chain from the
//! client entry to a reached server-only def.
//!
//! [`crate::target_gate`] (Layer 1) refuses every server-only kernel or FFI
//! call in the entry closure ([`crate::reach::EntryClosure`]) at the reference
//! itself. This layer runs first over the SAME closure and, when the offending
//! def sits in a module other than the entry, names the route instead: the
//! modules along the shortest def chain from the entry to it, labelled
//! `client`, `shared` and `server: imports <kernel>` — the exact chain, not
//! "not allowed".
//!
//! Judging defs, not whole modules, is what keeps a module usable from the
//! client when only some of its defs are server-only: a def the entry never
//! reaches is not emitted, so it classifies nothing.
//!
//! A def reached only within the entry's own module is Layer 1's direct
//! naming case (IPE-N0029); this layer leaves it there and keeps walking, so
//! the same violation never surfaces under two diagnostics.

use ipe_diagnostics::{DResult, Diagnostic, NameError, Span};
use ipe_intern::{Interner, Symbol};
use ipe_kernels::Target;

use crate::ast::Module;
use crate::reach::{EntryClosure, def_body, module_display_name};
use crate::target_gate::{Denied, first_denied};

/// Reject a wasm client entry whose closure reaches a server-only def in
/// another module.
///
/// `entry` is the client entry module's path (`linked.name` for today's
/// single-entry `ipe dev build --target wasm`). Walks the entry closure of
/// `linked` breadth-first and reports the first reached def that names a kernel
/// with no `WasmClient` denotation (or a foreign FFI call) and whose chain
/// from the entry leaves the entry module.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0030) naming the exact module chain from `entry`
/// to the first such def, in breadth-first (shortest-chain) order.
pub fn check_client_reachability(
    linked: &Module,
    entry: &[Symbol],
    interner: &Interner,
) -> DResult<()> {
    let closure = EntryClosure::of(linked, interner);
    for i in closure.breadth_first() {
        let Some(def) = linked.defs.get(i) else {
            continue;
        };
        let Some(denied) = first_denied(def_body(def), interner, Target::WasmClient) else {
            continue;
        };
        let mut homes: Vec<&[Symbol]> = closure
            .chain_to(i)
            .into_iter()
            .filter_map(|j| linked.defs.get(j).map(crate::ast::Def::home))
            .collect();
        homes.dedup();
        let leaves_entry = homes.first().copied() == Some(entry)
            && homes.last().copied().is_some_and(|home| home != entry);
        if leaves_entry {
            return Err(chain_error(&homes, denied, interner));
        }
    }
    Ok(())
}

fn chain_error(homes: &[&[Symbol]], denied: Denied<'_>, interner: &Interner) -> Diagnostic {
    let cause = format!("{}.{}", denied.qualifier, denied.name);
    let mut segments: Vec<String> = Vec::with_capacity(homes.len());
    for (i, module) in homes.iter().enumerate() {
        let name = module_display_name(module, interner);
        let label = if i + 1 == homes.len() {
            format!("server: imports {cause}")
        } else if i == 0 {
            "client".to_owned()
        } else {
            "shared".to_owned()
        };
        segments.push(format!("{name}({label})"));
    }
    Diagnostic::Name {
        span: Span::DUMMY,
        msg: NameError::ServerModuleReachableFromWasmClient {
            chain: segments.join(" -> ").into_boxed_str(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Def, Expr_};
    use ipe_diagnostics::Located;

    #[allow(clippy::expect_used)] // test helper: an intern failure IS the failure
    fn sym(interner: &mut Interner, s: &str) -> Symbol {
        interner.intern(s).expect("intern must succeed in a test")
    }

    fn path(interner: &mut Interner, s: &str) -> Vec<Symbol> {
        vec![sym(interner, s)]
    }

    fn top_level(home: Vec<Symbol>, name: Symbol, body: Expr_) -> Def {
        Def::Untyped {
            home,
            name: Located::new(Span::DUMMY, name),
            patterns: Vec::new(),
            body: Located::new(Span::DUMMY, body),
        }
    }

    fn var_top(module: Vec<Symbol>, name: Symbol) -> Expr_ {
        Expr_::VarTopLevel { module, name }
    }

    /// `Main(client) -> View(shared) -> Data(server: imports Ipe.Db.query)` —
    /// the exact chain the spec's M5 gate demands, not just "not allowed".
    #[test]
    fn reachability_error_names_the_exact_chain() {
        let mut interner = Interner::new();
        let main = path(&mut interner, "Main");
        let view = path(&mut interner, "View");
        let data = path(&mut interner, "Data");
        let ipe_db = sym(&mut interner, "Ipe.Db");
        let query = sym(&mut interner, "query");
        let call_view = sym(&mut interner, "callView");
        let load = sym(&mut interner, "load");
        let entry_fn = sym(&mut interner, "main");

        let defs = vec![
            top_level(
                main.clone(),
                entry_fn,
                Expr_::Call(
                    Box::new(Located::new(Span::DUMMY, var_top(view.clone(), call_view))),
                    vec![],
                ),
            ),
            top_level(
                view,
                call_view,
                Expr_::Call(
                    Box::new(Located::new(Span::DUMMY, var_top(data.clone(), load))),
                    vec![],
                ),
            ),
            top_level(
                data,
                load,
                Expr_::VarKernel {
                    id: None, // unregistered / DOES-NOT kernel: default-deny
                    module: ipe_db,
                    name: query,
                },
            ),
        ];
        let linked = Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: main.clone(),
            unions: Vec::new(),
            defs,
        };

        let err = check_client_reachability(&linked, &main, &interner)
            .expect_err("Data is server-classified and reachable from Main");
        let chain = match err {
            Diagnostic::Name {
                msg: NameError::ServerModuleReachableFromWasmClient { chain },
                ..
            } => chain,
            other => {
                return assert_eq!(
                    format!("{other:?}"),
                    "ServerModuleReachableFromWasmClient",
                    "expected ServerModuleReachableFromWasmClient"
                );
            }
        };
        assert_eq!(
            chain.as_ref(),
            "Main(client) -> View(shared) -> Data(server: imports Ipe.Db.query)"
        );
    }

    /// One imported module holds a clean def the entry calls and a server-only
    /// def nothing calls (the `Ipe.Task` shape: `map` beside `linearBackoff`).
    /// Only reached defs classify, so neither layer refuses the build.
    #[test]
    fn unreached_server_def_beside_a_reached_clean_def_passes() {
        let mut interner = Interner::new();
        let main = path(&mut interner, "Main");
        let task = path(&mut interner, "Task");
        let entry_fn = sym(&mut interner, "main");
        let map = sym(&mut interner, "map");
        let backoff = sym(&mut interner, "linearBackoff");
        let ipe_task = sym(&mut interner, "Ipe.Task");
        let kernel = sym(&mut interner, "linearBackoffKernel");

        let defs = vec![
            top_level(
                main.clone(),
                entry_fn,
                Expr_::Call(
                    Box::new(Located::new(Span::DUMMY, var_top(task.clone(), map))),
                    vec![],
                ),
            ),
            top_level(task.clone(), map, Expr_::Unit),
            top_level(
                task,
                backoff,
                Expr_::VarKernel {
                    id: None,
                    module: ipe_task,
                    name: kernel,
                },
            ),
        ];
        let linked = Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: main.clone(),
            unions: Vec::new(),
            defs,
        };

        check_client_reachability(&linked, &main, &interner)
            .expect("an unreached server-only def must not classify its module");
        crate::target_gate::check_wasm_client(&linked, &interner)
            .expect("an unreached server-only def must not reach Layer 1");
    }

    /// The same module reached through the server-only def itself is refused
    /// with the chain to it.
    #[test]
    fn reached_server_def_in_imported_module_names_the_chain() {
        let mut interner = Interner::new();
        let main = path(&mut interner, "Main");
        let task = path(&mut interner, "Task");
        let entry_fn = sym(&mut interner, "main");
        let map = sym(&mut interner, "map");
        let backoff = sym(&mut interner, "linearBackoff");
        let ipe_task = sym(&mut interner, "Ipe.Task");
        let kernel = sym(&mut interner, "linearBackoffKernel");

        let defs = vec![
            top_level(
                main.clone(),
                entry_fn,
                Expr_::Call(
                    Box::new(Located::new(Span::DUMMY, var_top(task.clone(), backoff))),
                    vec![],
                ),
            ),
            top_level(task.clone(), map, Expr_::Unit),
            top_level(
                task,
                backoff,
                Expr_::VarKernel {
                    id: None,
                    module: ipe_task,
                    name: kernel,
                },
            ),
        ];
        let linked = Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: main.clone(),
            unions: Vec::new(),
            defs,
        };

        let err = check_client_reachability(&linked, &main, &interner)
            .expect_err("a reached server-only def in an imported module is refused");
        assert!(
            format!("{err:?}")
                .contains("Main(client) -> Task(server: imports Ipe.Task.linearBackoffKernel)"),
            "expected the exact chain, got {err:?}"
        );
    }

    /// A server-only def reached only inside the entry module is Layer 1's
    /// direct-naming case: Layer 2 passes it through, Layer 1 refuses it.
    #[test]
    fn entry_module_server_def_is_left_to_layer_one() {
        let mut interner = Interner::new();
        let main = path(&mut interner, "Main");
        let entry_fn = sym(&mut interner, "main");
        let helper = sym(&mut interner, "helper");
        let ipe_db = sym(&mut interner, "Ipe.Db");
        let query = sym(&mut interner, "query");

        let defs = vec![
            top_level(
                main.clone(),
                entry_fn,
                Expr_::Call(
                    Box::new(Located::new(Span::DUMMY, var_top(main.clone(), helper))),
                    vec![],
                ),
            ),
            top_level(
                main.clone(),
                helper,
                Expr_::VarKernel {
                    id: None,
                    module: ipe_db,
                    name: query,
                },
            ),
        ];
        let linked = Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: main.clone(),
            unions: Vec::new(),
            defs,
        };

        check_client_reachability(&linked, &main, &interner)
            .expect("an entry-module offender is not a transitive chain");
        let err = crate::target_gate::check_wasm_client(&linked, &interner)
            .expect_err("a helper main calls is refused by Layer 1");
        assert!(
            matches!(
                err,
                Diagnostic::Name {
                    msg: NameError::ServerOnlyKernelForWasm { .. },
                    ..
                }
            ),
            "expected IPE-N0029, got {err:?}"
        );
    }

    /// A `server` module the entry never imports (transitively) is not an
    /// error — only the REACHABLE subset matters.
    #[test]
    fn unreachable_server_module_is_not_an_error() {
        let mut interner = Interner::new();
        let main = path(&mut interner, "Main");
        let unrelated = path(&mut interner, "Unrelated");
        let ipe_db = sym(&mut interner, "Ipe.Db");
        let query = sym(&mut interner, "query");
        let entry_fn = sym(&mut interner, "main");
        let load = sym(&mut interner, "load");

        let defs = vec![
            top_level(main.clone(), entry_fn, Expr_::Unit),
            top_level(
                unrelated,
                load,
                Expr_::VarKernel {
                    id: None,
                    module: ipe_db,
                    name: query,
                },
            ),
        ];
        let linked = Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: main.clone(),
            unions: Vec::new(),
            defs,
        };

        check_client_reachability(&linked, &main, &interner)
            .expect("an unreachable server module must not fail the client build");
    }

    /// A pure shared module the entry imports directly, with no server
    /// dependency anywhere in its closure, passes cleanly.
    #[test]
    fn all_shared_closure_passes() {
        let mut interner = Interner::new();
        let main = path(&mut interner, "Main");
        let view = path(&mut interner, "View");
        let call_view = sym(&mut interner, "callView");
        let entry_fn = sym(&mut interner, "main");

        let defs = vec![
            top_level(
                main.clone(),
                entry_fn,
                Expr_::Call(
                    Box::new(Located::new(Span::DUMMY, var_top(view.clone(), call_view))),
                    vec![],
                ),
            ),
            top_level(view, call_view, Expr_::Unit),
        ];
        let linked = Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: main.clone(),
            unions: Vec::new(),
            defs,
        };

        check_client_reachability(&linked, &main, &interner).expect("all-shared closure is fine");
    }

    /// Two shared modules sit at equal BFS depth from the entry, each importing
    /// a distinct server module one hop deeper, so two shortest chains of equal
    /// length exist. The reported chain must be the one through the
    /// lexicographically-FIRST shared module, deterministically — never
    /// whichever `HashSet` iteration happened to dequeue first. The shared
    /// modules are declared in the order OPPOSITE to their dot-string sort, so
    /// a source-order (or hash-order) tie-break would pick the wrong one.
    #[test]
    fn equal_depth_sibling_chain_is_string_deterministic() {
        // Declared order: `Zeta` before `Alpha`; expected chain goes through
        // `Alpha` (lexicographically first). Rebuild and re-walk many times: a
        // per-process `RandomState` would otherwise flip the result run to run.
        for _ in 0..50 {
            let mut interner = Interner::new();
            let main = path(&mut interner, "Main");
            let zeta = path(&mut interner, "Zeta");
            let alpha = path(&mut interner, "Alpha");
            let server_z = path(&mut interner, "ServerZ");
            let server_a = path(&mut interner, "ServerA");
            let ipe_db = sym(&mut interner, "Ipe.Db");
            let query = sym(&mut interner, "query");
            let entry_fn = sym(&mut interner, "main");
            let call_z = sym(&mut interner, "callZ");
            let call_a = sym(&mut interner, "callA");
            let touch_z = sym(&mut interner, "touchZ");
            let touch_a = sym(&mut interner, "touchA");
            let load = sym(&mut interner, "load");

            let defs = vec![
                top_level(
                    main.clone(),
                    entry_fn,
                    Expr_::Tuple(vec![
                        Located::new(Span::DUMMY, var_top(zeta.clone(), call_z)),
                        Located::new(Span::DUMMY, var_top(alpha.clone(), call_a)),
                    ]),
                ),
                top_level(
                    zeta,
                    call_z,
                    Expr_::Call(
                        Box::new(Located::new(
                            Span::DUMMY,
                            var_top(server_z.clone(), touch_z),
                        )),
                        vec![],
                    ),
                ),
                top_level(
                    alpha,
                    call_a,
                    Expr_::Call(
                        Box::new(Located::new(
                            Span::DUMMY,
                            var_top(server_a.clone(), touch_a),
                        )),
                        vec![],
                    ),
                ),
                top_level(
                    server_z,
                    touch_z,
                    Expr_::VarKernel {
                        id: None,
                        module: ipe_db,
                        name: query,
                    },
                ),
                top_level(
                    server_a,
                    touch_a,
                    Expr_::VarKernel {
                        id: None,
                        module: ipe_db,
                        name: load,
                    },
                ),
            ];
            let linked = Module {
                imports_unsafe_submodule: false,
                imported_web_capabilities: std::collections::BTreeSet::new(),
                name: main.clone(),
                unions: Vec::new(),
                defs,
            };

            let err = check_client_reachability(&linked, &main, &interner)
                .expect_err("both siblings reach a server module");
            let chain = match err {
                Diagnostic::Name {
                    msg: NameError::ServerModuleReachableFromWasmClient { chain },
                    ..
                } => chain,
                other => {
                    return assert_eq!(
                        format!("{other:?}"),
                        "ServerModuleReachableFromWasmClient",
                        "expected ServerModuleReachableFromWasmClient"
                    );
                }
            };
            assert_eq!(
                chain.as_ref(),
                "Main(client) -> Alpha(shared) -> ServerA(server: imports Ipe.Db.load)",
                "the shortest chain must go through the lexicographically-first sibling"
            );
        }
    }
}
