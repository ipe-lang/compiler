//! Layer 2 of the wasm security gate (spec Q5): module `server`/`shared`
//! classification + client-entry reachability closure.
//!
//! [`crate::target_gate`] (Layer 1) is naming-based over the WHOLE linked
//! program: a kernel with no `WasmClient` denotation fails wherever it is
//! named, even inside a def the client entry can never reach. This
//! module supplies the promised compositional guarantee: it classifies every
//! module actually linked into the build, then walks ONLY the transitive
//! import closure from the client entry, so a `server` module the entry
//! never reaches is not an error, and one it DOES reach is reported by name
//! — the exact chain, not "not allowed".
//!
//! A module is `server` if ANY of its own defs directly names a kernel with
//! no `WasmClient` denotation (or a foreign FFI call — Q5: FFI is a
//! native-target concept). Every other module defaults to `shared` — the
//! same default the spec assigns pure/UI modules, so a shared `view` module
//! type-checks against both targets without duplication.
//!
//! Dependency edges are read off `Expr_::VarTopLevel { module, .. }` — every
//! cross-module reference in the canonical AST already carries its target
//! module's path (see `link.rs`), so no separate import-graph structure is
//! needed: the defs THEMSELVES are the edge list.

use std::collections::{HashMap, HashSet, VecDeque};

use ipe_diagnostics::{DResult, Diagnostic, NameError, Span};
use ipe_intern::{Interner, Symbol};
use ipe_kernels::Target;

use crate::ast::{CaseBranch, Def, Expr, Expr_, LetBinding, Module};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ModuleClass {
    Shared,
    Server,
}

/// Why a module earned [`ModuleClass::Server`] — the specific kernel/FFI
/// reference, so the chain error can name it (`Data(server: imports
/// Ipe.Db.query)`), never a bare "not allowed".
struct ServerCause {
    qualifier: String,
    name: String,
}

struct ModuleInfo {
    class: ModuleClass,
    cause: Option<ServerCause>,
}

/// Reject a wasm client entry whose reachability closure transitively
/// touches a `server`-classified module.
///
/// `entry` is the client entry module's path (`linked.name` for today's
/// single-entry `ipe build --target wasm`; a distinct `[wasm].entry` module
/// takes the same role once M6 wires it through). Walks the linked program's
/// defs, grouped by their retained `home` (original source module — see
/// `ast::Def::home`), classifying each and building the module dependency
/// graph from `VarTopLevel` references, then BFS-walks from `entry`.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0030) naming the exact chain from `entry` to
/// the first server module reached, in breadth-first (shortest-chain) order.
pub fn check_client_reachability(
    linked: &Module,
    entry: &[Symbol],
    interner: &Interner,
) -> DResult<()> {
    let mut by_home: HashMap<Vec<Symbol>, Vec<&Def>> = HashMap::new();
    for def in &linked.defs {
        by_home.entry(def.home().to_vec()).or_default().push(def);
    }

    let mut infos: HashMap<Vec<Symbol>, ModuleInfo> = HashMap::new();
    let mut edges: HashMap<Vec<Symbol>, Vec<Vec<Symbol>>> = HashMap::new();

    for (home, defs) in &by_home {
        let mut cause: Option<ServerCause> = None;
        let mut deps: HashSet<Vec<Symbol>> = HashSet::new();
        for def in defs {
            let body = match def {
                Def::Untyped { body, .. } | Def::Typed { body, .. } => body,
            };
            walk_expr(body, &mut |e| match &e.value {
                Expr_::VarKernel { id, module, name } => {
                    let allowed = id.is_some_and(|k| k.available_on(Target::WasmClient));
                    if !allowed && cause.is_none() {
                        cause = Some(ServerCause {
                            qualifier: interner.resolve(*module).unwrap_or("?").to_owned(),
                            name: interner.resolve(*name).unwrap_or("?").to_owned(),
                        });
                    }
                }
                Expr_::ForeignCall { .. } => {
                    if cause.is_none() {
                        cause = Some(ServerCause {
                            qualifier: "Ffi".to_owned(),
                            name: "binding".to_owned(),
                        });
                    }
                }
                Expr_::VarTopLevel { module, .. } if module != home => {
                    deps.insert(module.clone());
                }
                _ => {}
            });
        }
        let class = if cause.is_some() {
            ModuleClass::Server
        } else {
            ModuleClass::Shared
        };
        infos.insert(home.clone(), ModuleInfo { class, cause });
        // Order the neighbour list by resolved dot-string so the BFS reaches
        // equal-depth siblings in a fixed order — which sibling wins the
        // shortest-chain tie-break is decided by the module name, not by
        // `HashSet` iteration order.
        let mut deps: Vec<Vec<Symbol>> = deps.into_iter().collect();
        deps.sort_by(|a, b| {
            module_display_name(a, interner).cmp(&module_display_name(b, interner))
        });
        edges.insert(home.clone(), deps);
    }

    // BFS from `entry`, tracking the path so far — gives the SHORTEST chain
    // to the first-reached server module (breadth-first = fewest hops),
    // matching the spec's "exact import path" requirement.
    let mut visited: HashSet<Vec<Symbol>> = HashSet::new();
    let mut queue: VecDeque<Vec<Vec<Symbol>>> = VecDeque::new();
    let entry = entry.to_vec();
    visited.insert(entry.clone());
    queue.push_back(vec![entry]);

    while let Some(path) = queue.pop_front() {
        let Some(current) = path.last() else {
            continue;
        };
        // A length-1 "chain" (the entry module directly names the bad
        // kernel) is Layer 1's job (IPE-N0029) — that is direct naming, not
        // a compositional/transitive reachability violation, and Layer 1
        // already covers it unconditionally. Reporting it here too would
        // make the SAME violation surface under two different diagnostics
        // depending on unrelated ordering; skip and keep walking so a
        // DEEPER transitive violation (the case this layer exists for)
        // still gets its own chain.
        if path.len() > 1
            && let Some(info) = infos.get(current)
            && info.class == ModuleClass::Server
        {
            return Err(chain_error(&path, info, interner));
        }
        if let Some(deps) = edges.get(current) {
            for dep in deps {
                if visited.insert(dep.clone()) {
                    let mut next = path.clone();
                    next.push(dep.clone());
                    queue.push_back(next);
                }
            }
        }
    }
    Ok(())
}

fn module_display_name(path: &[Symbol], interner: &Interner) -> String {
    path.iter()
        .map(|s| interner.resolve(*s).unwrap_or("?"))
        .collect::<Vec<_>>()
        .join(".")
}

fn chain_error(path: &[Vec<Symbol>], offending: &ModuleInfo, interner: &Interner) -> Diagnostic {
    let cause = offending
        .cause
        .as_ref()
        .map_or_else(|| "?".to_owned(), |c| format!("{}.{}", c.qualifier, c.name));
    let mut segments: Vec<String> = Vec::with_capacity(path.len());
    for (i, module) in path.iter().enumerate() {
        let name = module_display_name(module, interner);
        let label = if i == 0 {
            "client".to_owned()
        } else if i + 1 == path.len() {
            format!("server: imports {cause}")
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

/// An iterative (heap-stack) traversal, generalised to a visitor called on
/// every node. Unlike `target_gate::first_denied`, which recurses over the same
/// expression shape, this keeps native call depth O(1).
fn walk_expr<'e>(root: &'e Expr, visit: &mut impl FnMut(&'e Expr)) {
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
    use super::*;
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
