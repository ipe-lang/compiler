//! Layer-1 wasm security gate: server-only kernels have no denotation in a
//! `--target wasm` build.
//!
//! Walks the entry closure of the linked canonical module
//! ([`crate::reach::EntryClosure`], the defs the emitted crate is cut down to)
//! and rejects every kernel reference that is not on the target's allowlist
//! (`ipe_kernels::StdlibKernel::available_on`, default-deny). A kernel outside
//! the allowlist has no runtime symbol in the wasm crate, and letting a reached
//! one through would trade this compile error for a cargo failure (THE SEAL),
//! or, worse, a secret consumer in a public bundle. A def the entry cannot
//! reach is not emitted, so naming a server-only kernel there is not an error.
//!
//! [`check_emitted_for_target`] re-judges the functions lowering actually kept,
//! so the gate never rests on the closure alone matching the lowerer's prune.
//!
//! Foreign-crate FFI calls are equally unrepresentable client-side: the wasm
//! crate's only host surface is the fixed web-sys allowlist.

use std::collections::HashMap;

use ipe_diagnostics::{DResult, Diagnostic, NameError, Span};
use ipe_intern::{Interner, Symbol};
use ipe_kernels::Target;

use crate::ast::{CaseBranch, Def, Expr, Expr_, LetBinding, Module};
use crate::reach::{EntryClosure, def_body, module_display_name};

/// Reject every kernel/FFI reference reachable from the entry of `module` that
/// has no `WasmClient` denotation.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0029) at the first offending reference, in
/// source order within each reached def, defs in linked order.
pub fn check_wasm_client(module: &Module, interner: &Interner) -> DResult<()> {
    check_wasm_target(module, interner, Target::WasmClient)
}

/// Reject every kernel/FFI reference reachable from the entry of `module` that
/// has no denotation on the co-located WASI (`wasm32-wasip1`) target, the
/// sealed-floor gate.
///
/// The SAME default-deny walk as [`check_wasm_client`], keyed to the WASI
/// availability set (`available_on(Target::WasmWasi)`): a kernel outside the
/// sealed floor has no wasip1 runtime symbol, so letting it through would trade
/// this compile error for a `cargo build --target wasm32-wasip1` failure (THE
/// SEAL). It is the build-boundary backstop to the delivery matrix's shape gate
/// — defense in depth: even a kernel reached through a path the shape gate does
/// not model is turned back here.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0029) at the first offending reference, in
/// source order within each reached def, defs in linked order.
pub fn check_wasm_wasi(module: &Module, interner: &Interner) -> DResult<()> {
    check_wasm_target(module, interner, Target::WasmWasi)
}

/// Re-judge, after lowering, every function the emitted crate will contain.
///
/// `emitted` names each surviving lowered function by `(home, name)`; each is
/// judged by the canonical def it was lowered from, with the same default-deny
/// walk as [`check_wasm_client`]. This is the second, independent boundary of
/// the gate: an edge the lowerer adds that [`EntryClosure`] does not model
/// still cannot ship a server-only kernel.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0029) at the first offending reference of the
/// first offending function, in `emitted` order; [`Diagnostic::CompilerBug`]
/// for an emitted function no canonical def accounts for, which the gate
/// cannot judge and so refuses.
pub fn check_emitted_for_target(
    linked: &Module,
    emitted: &[(&[Symbol], Symbol)],
    interner: &Interner,
    target: Target,
) -> DResult<()> {
    let mut by_name: HashMap<Symbol, Vec<&Def>> = HashMap::new();
    for def in &linked.defs {
        by_name.entry(def.name().value).or_default().push(def);
    }
    for &(home, name) in emitted {
        let sources: Vec<&Def> = by_name
            .get(&name)
            .into_iter()
            .flatten()
            .copied()
            .filter(|def| def.home() == home)
            .collect();
        if sources.is_empty() {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_canon::target_gate::check_emitted_for_target",
                detail: format!(
                    "the emitted function `{}.{}` has no canonical definition, so \
                     the wasm gate cannot judge it",
                    module_display_name(home, interner),
                    interner.resolve(name).unwrap_or("?"),
                ),
            });
        }
        for def in sources {
            if let Some(denied) = first_denied(def_body(def), interner, target) {
                return Err(denied.into_diagnostic());
            }
        }
    }
    Ok(())
}

/// The shared default-deny walk over the entry closure of `module`,
/// parameterised by the wasm [`Target`] whose `available_on` set decides
/// admission. One walker, two targets — the SSOT for "a kernel with no
/// denotation on this wasm target is rejected before it can become a cargo
/// failure".
fn check_wasm_target(module: &Module, interner: &Interner, target: Target) -> DResult<()> {
    let closure = EntryClosure::of(module, interner);
    for def in closure.defs(module) {
        if let Some(denied) = first_denied(def_body(def), interner, target) {
            return Err(denied.into_diagnostic());
        }
    }
    Ok(())
}

/// A kernel or FFI reference with no denotation on the judged target.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Denied<'i> {
    pub(crate) span: Span,
    pub(crate) qualifier: &'i str,
    pub(crate) name: &'i str,
}

impl Denied<'_> {
    fn into_diagnostic(self) -> Diagnostic {
        Diagnostic::Name {
            span: self.span,
            msg: NameError::ServerOnlyKernelForWasm {
                qualifier: self.qualifier.into(),
                name: self.name.into(),
            },
        }
    }
}

/// Build a minimal single-def module whose body is `body_expr`.
#[cfg(test)]
fn single_def_module(interner: &mut Interner, body_expr: Expr_) -> Module {
    use ipe_diagnostics::Located;
    let main = vec![interner.intern("Main").expect("intern")];
    let entry = interner.intern("main").expect("intern");
    let def = Def::Untyped {
        home: main.clone(),
        name: Located::new(Span::DUMMY, entry),
        patterns: Vec::new(),
        body: Located::new(Span::DUMMY, body_expr),
    };
    Module {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        name: main,
        unions: Vec::new(),
        defs: vec![def],
    }
}

/// Return the first offending kernel/FFI reference in source order, or `None`
/// if the expression is clean. Children are visited in their textual
/// (left-to-right, outer-before-inner) order, matching the documented
/// contract: callee before arguments, scrutinee before arms, each binding
/// before its continuation, if-condition before body before else, and
/// tuple/list/record/update fields in their declaration order.
pub(crate) fn first_denied<'i>(
    e: &Expr,
    interner: &'i Interner,
    target: Target,
) -> Option<Denied<'i>> {
    match &e.value {
        Expr_::VarKernel { id, module, name } => {
            let allowed = id.is_some_and(|k| k.available_on(target));
            // `id: None` (a kernel resolved only by the string-match
            // fallback) fails closed — an unaudited kernel is denied.
            if allowed {
                None
            } else {
                let q = interner.resolve(*module).unwrap_or("?");
                let n = interner.resolve(*name).unwrap_or("?");
                Some(Denied {
                    span: e.span,
                    qualifier: q,
                    name: n,
                })
            }
        }
        Expr_::ForeignCall { .. } => {
            // FFI bindings are a native-target concept: the client's only
            // host surface is the fixed web-sys allowlist.
            Some(Denied {
                span: e.span,
                qualifier: "Ffi",
                name: "binding",
            })
        }
        Expr_::VarLocal(_)
        | Expr_::VarTopLevel { .. }
        | Expr_::VarCtor { .. }
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::CustomElementCtor(_)
        | Expr_::Char(_)
        | Expr_::Unit => None,
        Expr_::Call(f, args) => first_denied(f, interner, target)
            .or_else(|| args.iter().find_map(|a| first_denied(a, interner, target))),
        Expr_::Case(scrut, branches) => first_denied(scrut, interner, target).or_else(|| {
            branches
                .iter()
                .find_map(|CaseBranch { body, .. }| first_denied(body, interner, target))
        }),
        Expr_::Lambda(_, body) => first_denied(body, interner, target),
        // Binops resolve to `Basics` arithmetic/comparison kernels —
        // pure, always client-representable.
        Expr_::Binop { lhs, rhs, .. } => {
            first_denied(lhs, interner, target).or_else(|| first_denied(rhs, interner, target))
        }
        Expr_::Let(bindings, body) => bindings
            .iter()
            .find_map(|LetBinding { body: b, .. }| first_denied(b, interner, target))
            .or_else(|| first_denied(body, interner, target)),
        Expr_::If(arms, els) => arms
            .iter()
            .find_map(|(c, b)| {
                first_denied(c, interner, target).or_else(|| first_denied(b, interner, target))
            })
            .or_else(|| first_denied(els, interner, target)),
        Expr_::Tuple(items) | Expr_::List(items) => {
            items.iter().find_map(|i| first_denied(i, interner, target))
        }
        Expr_::Cons(h, t) => {
            first_denied(h, interner, target).or_else(|| first_denied(t, interner, target))
        }
        Expr_::Record(fields) => fields
            .iter()
            .find_map(|(_, v)| first_denied(v, interner, target)),
        Expr_::Access(base, _) => first_denied(base, interner, target),
        Expr_::Update(base, fields) => first_denied(base, interner, target).or_else(|| {
            fields
                .iter()
                .find_map(|(_, v)| first_denied(v, interner, target))
        }),
    }
}

/// Layer-1 red-team tests: the default-deny allowlist BLOCKS server-only
/// kernels and FFI under `--target wasm`; wasm-available kernels pass.
#[cfg(test)]
mod tests {
    use ipe_diagnostics::NameError;
    use ipe_kernels::StdlibKernel;

    use super::*;

    fn intern(interner: &mut Interner, s: &str) -> ipe_intern::Symbol {
        #[allow(clippy::expect_used)]
        interner.intern(s).expect("intern must succeed in a test")
    }

    /// A server-only kernel (`Db.query`, `id: None` — unregistered) is denied
    /// under `--target wasm`: it has no `WasmClient` denotation and must never
    /// reach the bundle (it would either fail cargo or leak a server secret).
    #[test]
    fn server_only_kernel_is_denied() {
        let mut interner = Interner::new();
        let ipe_db = intern(&mut interner, "Ipe.Db");
        let query = intern(&mut interner, "query");
        let body = Expr_::VarKernel {
            id: None,
            module: ipe_db,
            name: query,
        };
        let module = single_def_module(&mut interner, body);
        let err = check_wasm_client(&module, &interner)
            .expect_err("Ipe.Db.query must be denied under --target wasm");
        let (qualifier, name) = match err {
            Diagnostic::Name {
                msg: NameError::ServerOnlyKernelForWasm { qualifier, name },
                ..
            } => (qualifier, name),
            other => {
                return assert_eq!(
                    format!("{other:?}"),
                    "ServerOnlyKernelForWasm",
                    "expected ServerOnlyKernelForWasm"
                );
            }
        };
        assert_eq!(qualifier.as_ref(), "Ipe.Db");
        assert_eq!(name.as_ref(), "query");
    }

    /// A wasm-available kernel (`CmdNone`) carries a `WasmClient` denotation
    /// and must pass the Layer-1 check without error.
    #[test]
    fn wasm_available_kernel_passes() {
        let mut interner = Interner::new();
        let ipe_cmd = intern(&mut interner, "Ipe.Cmd");
        let none_sym = intern(&mut interner, "none");
        let body = Expr_::VarKernel {
            id: Some(StdlibKernel::CmdNone),
            module: ipe_cmd,
            name: none_sym,
        };
        let module = single_def_module(&mut interner, body);
        check_wasm_client(&module, &interner)
            .expect("Cmd.none is wasm-available and must pass the Layer-1 gate");
    }

    /// The typed `Ipe.Ffi.Js` port (`Js.send` / `Js.subscribe`) is wasm-available:
    /// its `js_port` wasm arm posts each sealed frame to `window.ipeOnReceive`
    /// and drains inbound frames the page feeds through the same fail-closed seal
    /// decoder, so a client SPA using a port must pass the Layer-1 gate.
    #[test]
    fn js_port_kernels_pass() {
        for (kernel, module, name) in [
            (StdlibKernel::JsSend, "Ipe.Ffi.Js", "send"),
            (StdlibKernel::JsSubscribe, "Ipe.Ffi.Js", "subscribe"),
        ] {
            let mut interner = Interner::new();
            let m = intern(&mut interner, module);
            let n = intern(&mut interner, name);
            let body = Expr_::VarKernel {
                id: Some(kernel),
                module: m,
                name: n,
            };
            let module = single_def_module(&mut interner, body);
            check_wasm_client(&module, &interner)
                .expect("Js.send/Js.subscribe are wasm-available and must pass the Layer-1 gate");
        }
    }

    /// A foreign FFI call is always denied under `--target wasm` — the client's
    /// only host surface is the fixed web-sys allowlist, not arbitrary crates.
    #[test]
    fn ffi_call_is_denied() {
        let mut interner = Interner::new();
        let ident = intern(&mut interner, "native_lib_do_something");
        let body = Expr_::ForeignCall {
            ident,
            args: vec![],
            asserted: false,
        };
        let module = single_def_module(&mut interner, body);
        let err = check_wasm_client(&module, &interner)
            .expect_err("FFI calls must be denied under --target wasm");
        assert!(
            matches!(
                err,
                Diagnostic::Name {
                    msg: NameError::ServerOnlyKernelForWasm { .. },
                    ..
                }
            ),
            "expected ServerOnlyKernelForWasm, got {err:?}"
        );
    }

    /// A program with no kernel calls (pure unit body) passes the gate — the
    /// default-deny allowlist only fires on an EXPLICIT kernel reference.
    #[test]
    fn kernel_free_program_passes() {
        let mut interner = Interner::new();
        let module = single_def_module(&mut interner, Expr_::Unit);
        check_wasm_client(&module, &interner)
            .expect("a kernel-free program must pass the Layer-1 gate unconditionally");
    }

    /// THE SEAL for the collapsed `server` bucket: a `Server.listen` program is
    /// a `Direct` (`script`) shape, so the delivery matrix's shape gate no longer
    /// refuses it on `wasm32-wasip1` — the per-kernel sealed floor MUST. This
    /// pins that floor: `StdlibKernel::ServerListen` carries `KernelClass::Server`
    /// and so is NOT in `available_on(WasmWasi)`, so `check_wasm_wasi` refuses it
    /// at `ipe` time (IPE-N0029). tokio/axum do not build on wasip1, so admitting
    /// it would break the ipe-accepts ⇒ cargo-builds SEAL; this refusal is the
    /// invariant that replaces the dropped shape arm.
    #[test]
    fn server_listen_is_denied_on_wasi_floor() {
        assert!(
            !StdlibKernel::ServerListen.available_on(Target::WasmWasi),
            "Server.listen has no wasip1 denotation — it must stay off the sealed WASI floor"
        );
        let mut interner = Interner::new();
        let module_sym = intern(&mut interner, "Ipe.Http.Server");
        let name = intern(&mut interner, "listen");
        let body = Expr_::VarKernel {
            id: Some(StdlibKernel::ServerListen),
            module: module_sym,
            name,
        };
        let module = single_def_module(&mut interner, body);
        let err = check_wasm_wasi(&module, &interner)
            .expect_err("Server.listen must be refused on the wasm32-wasip1 target");
        assert!(
            matches!(
                err,
                Diagnostic::Name {
                    msg: NameError::ServerOnlyKernelForWasm { .. },
                    ..
                }
            ),
            "expected ServerOnlyKernelForWasm, got {err:?}"
        );
    }

    /// Builds a denied `VarKernel` expression at the given byte-offset span.
    fn denied_kernel_at(interner: &mut Interner, lo: u32) -> Expr {
        use ipe_diagnostics::Located;
        let m = intern(interner, "Ipe.Db");
        let n = intern(interner, "query");
        Located::new(
            Span::new(lo, lo + 1),
            Expr_::VarKernel {
                id: None,
                module: m,
                name: n,
            },
        )
    }

    /// Builds a denied `VarKernel` with a distinct name to identify the offender.
    fn denied_kernel_named(interner: &mut Interner, lo: u32, name: &str) -> Expr {
        use ipe_diagnostics::Located;
        let m = intern(interner, "Ipe.Db");
        let n = intern(interner, name);
        Located::new(
            Span::new(lo, lo + 1),
            Expr_::VarKernel {
                id: None,
                module: m,
                name: n,
            },
        )
    }

    fn unit_at(lo: u32) -> Expr {
        use ipe_diagnostics::Located;
        Located::new(Span::new(lo, lo + 1), Expr_::Unit)
    }

    /// Extract the source span from a `Diagnostic::Name` or fail the test.
    fn name_span(d: &Diagnostic, context: &str) -> Span {
        if let Diagnostic::Name { span, .. } = d {
            *span
        } else {
            assert_eq!(
                format!("{d:?}"),
                "Diagnostic::Name { .. }",
                "{context}: expected Name diagnostic"
            );
            Span::DUMMY
        }
    }

    /// Three distinct denied kernels at ascending spans inside a `Call` argument
    /// list. Source order is arg0, arg1, arg2; a LIFO walk returns arg2 first.
    /// The gate must return the offender at arg0's span.
    #[test]
    fn call_reports_first_arg_offender_not_last() {
        use ipe_diagnostics::Located;
        let mut interner = Interner::new();
        let arg0 = denied_kernel_named(&mut interner, 10, "alpha");
        let arg1 = denied_kernel_named(&mut interner, 20, "beta");
        let arg2 = denied_kernel_named(&mut interner, 30, "gamma");
        let f_sym = intern(&mut interner, "f");
        let callee = Located::new(Span::new(0, 1), Expr_::VarLocal(f_sym));
        let body = Expr_::Call(Box::new(callee), vec![arg0, arg1, arg2]);
        let module = single_def_module(&mut interner, body);
        let err = check_wasm_client(&module, &interner)
            .expect_err("at least one denied kernel must be reported");
        let (name, span) = match err {
            Diagnostic::Name {
                span,
                msg: NameError::ServerOnlyKernelForWasm { name, .. },
            } => (name, span),
            other => {
                return assert_eq!(
                    format!("{other:?}"),
                    "ServerOnlyKernelForWasm",
                    "expected ServerOnlyKernelForWasm"
                );
            }
        };
        assert_eq!(
            name.as_ref(),
            "alpha",
            "first source-order arg (alpha) must be reported, not a later one"
        );
        assert_eq!(span.lo, 10, "span must match arg0");
    }

    /// `If` arms: the first condition's offender is reported before any body.
    #[test]
    fn if_reports_first_condition_offender() {
        let mut interner = Interner::new();
        let c0 = denied_kernel_at(&mut interner, 10);
        let b0 = unit_at(20);
        let c1 = denied_kernel_at(&mut interner, 30);
        let b1 = unit_at(40);
        let els = unit_at(50);
        let body = Expr_::If(vec![(c0, b0), (c1, b1)], Box::new(els));
        let module = single_def_module(&mut interner, body);
        let err =
            check_wasm_client(&module, &interner).expect_err("first condition must be denied");
        let span = name_span(&err, "if_reports_first_condition_offender");
        assert_eq!(
            span.lo, 10,
            "must report the first (lo=10) condition, not lo=30"
        );
    }

    /// `Let` bindings: the first binding body offender is reported before
    /// subsequent bindings and before the let-body.
    #[test]
    fn let_reports_first_binding_offender() {
        use crate::ast::Pattern_;
        use ipe_diagnostics::Located;
        let mut interner = Interner::new();
        let v0 = intern(&mut interner, "x");
        let v1 = intern(&mut interner, "y");
        let bind0 = LetBinding {
            pat: Located::new(Span::DUMMY, Pattern_::PVar(v0)),
            body: denied_kernel_at(&mut interner, 10),
        };
        let bind1 = LetBinding {
            pat: Located::new(Span::DUMMY, Pattern_::PVar(v1)),
            body: denied_kernel_at(&mut interner, 20),
        };
        let let_body = unit_at(30);
        let body = Expr_::Let(vec![bind0, bind1], Box::new(let_body));
        let module = single_def_module(&mut interner, body);
        let err = check_wasm_client(&module, &interner).expect_err("first binding must be denied");
        let span = name_span(&err, "let_reports_first_binding_offender");
        assert_eq!(span.lo, 10, "must report first binding (lo=10), not lo=20");
    }

    /// `Tuple` and `List`: first element in declaration order is reported.
    #[test]
    fn tuple_and_list_report_first_field_offender() {
        let mut interner = Interner::new();

        let t0 = denied_kernel_at(&mut interner, 10);
        let t1 = denied_kernel_at(&mut interner, 20);
        let body = Expr_::Tuple(vec![t0, t1]);
        let module = single_def_module(&mut interner, body);
        let err =
            check_wasm_client(&module, &interner).expect_err("first tuple field must be denied");
        let span = name_span(&err, "tuple");
        assert_eq!(span.lo, 10, "tuple: first field (lo=10) must be reported");

        let l0 = denied_kernel_at(&mut interner, 10);
        let l1 = denied_kernel_at(&mut interner, 20);
        let body2 = Expr_::List(vec![l0, l1]);
        let module2 = single_def_module(&mut interner, body2);
        let err2 =
            check_wasm_client(&module2, &interner).expect_err("first list element must be denied");
        let span2 = name_span(&err2, "list");
        assert_eq!(span2.lo, 10, "list: first element (lo=10) must be reported");
    }

    /// `Record`: first field value offender is reported.
    #[test]
    fn record_reports_first_field_offender() {
        let mut interner = Interner::new();
        let f0 = intern(&mut interner, "foo");
        let f1 = intern(&mut interner, "bar");
        let v0 = denied_kernel_at(&mut interner, 10);
        let v1 = denied_kernel_at(&mut interner, 20);
        let body = Expr_::Record(vec![(f0, v0), (f1, v1)]);
        let module = single_def_module(&mut interner, body);
        let err =
            check_wasm_client(&module, &interner).expect_err("first record field must be denied");
        let span = name_span(&err, "record_reports_first_field_offender");
        assert_eq!(span.lo, 10, "record: first field (lo=10) must be reported");
    }

    /// `Update`: base is checked before update fields.
    #[test]
    fn update_reports_base_before_fields() {
        let mut interner = Interner::new();
        let f0 = intern(&mut interner, "foo");
        let base = denied_kernel_at(&mut interner, 10);
        let fv = denied_kernel_at(&mut interner, 20);
        let body = Expr_::Update(Box::new(base), vec![(f0, fv)]);
        let module = single_def_module(&mut interner, body);
        let err = check_wasm_client(&module, &interner).expect_err("base must be denied first");
        let span = name_span(&err, "update_reports_base_before_fields");
        assert_eq!(
            span.lo, 10,
            "update: base (lo=10) must precede field (lo=20)"
        );
    }

    fn plain_def(home: Vec<ipe_intern::Symbol>, name: ipe_intern::Symbol, body: Expr) -> Def {
        use ipe_diagnostics::Located;
        Def::Untyped {
            home,
            name: Located::new(Span::DUMMY, name),
            patterns: Vec::new(),
            body,
        }
    }

    fn call_top(module: Vec<ipe_intern::Symbol>, name: ipe_intern::Symbol) -> Expr {
        use ipe_diagnostics::Located;
        Located::new(
            Span::DUMMY,
            Expr_::Call(
                Box::new(Located::new(
                    Span::DUMMY,
                    Expr_::VarTopLevel { module, name },
                )),
                Vec::new(),
            ),
        )
    }

    fn linked_module(name: Vec<ipe_intern::Symbol>, defs: Vec<Def>) -> Module {
        Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name,
            unions: Vec::new(),
            defs,
        }
    }

    /// The `Ipe.Task` shape: `Main.main` calls `Ipe.Task.map`, while the
    /// sibling `Ipe.Task.linearBackoff` names the tokio-bound
    /// `Task_linearBackoff` kernel and nothing calls it. The entry closure
    /// excludes it, so the wasm client gate passes.
    #[test]
    fn unreached_server_only_def_in_imported_module_passes() {
        use ipe_diagnostics::Located;
        assert!(
            !StdlibKernel::TaskLinearBackoff.available_on(Target::WasmClient),
            "the premise: Task.linearBackoff has no wasm client denotation"
        );
        let mut interner = Interner::new();
        let main_mod = vec![intern(&mut interner, "Main")];
        let task_mod = vec![intern(&mut interner, "Ipe"), intern(&mut interner, "Task")];
        let main_fn = intern(&mut interner, "main");
        let map = intern(&mut interner, "map");
        let backoff = intern(&mut interner, "linearBackoff");
        let qualifier = intern(&mut interner, "Task");
        let kernel = Located::new(
            Span::new(30, 31),
            Expr_::VarKernel {
                id: Some(StdlibKernel::TaskLinearBackoff),
                module: qualifier,
                name: backoff,
            },
        );
        let linked = linked_module(
            main_mod.clone(),
            vec![
                plain_def(task_mod.clone(), map, unit_at(0)),
                plain_def(task_mod.clone(), backoff, kernel),
                plain_def(main_mod, main_fn, call_top(task_mod, map)),
            ],
        );
        check_wasm_client(&linked, &interner)
            .expect("an unreached server-only stdlib def must not refuse the client build");
        check_wasm_wasi(&linked, &interner)
            .expect("an unreached server-only stdlib def must not refuse the WASI build");
    }

    /// The same program reaching `Ipe.Task.linearBackoff` from `main` is
    /// refused (IPE-N0029) at the kernel inside the imported def.
    #[test]
    fn reached_server_only_def_in_imported_module_is_denied() {
        use ipe_diagnostics::Located;
        let mut interner = Interner::new();
        let main_mod = vec![intern(&mut interner, "Main")];
        let task_mod = vec![intern(&mut interner, "Ipe"), intern(&mut interner, "Task")];
        let main_fn = intern(&mut interner, "main");
        let backoff = intern(&mut interner, "linearBackoff");
        let qualifier = intern(&mut interner, "Task");
        let kernel = Located::new(
            Span::new(30, 31),
            Expr_::VarKernel {
                id: Some(StdlibKernel::TaskLinearBackoff),
                module: qualifier,
                name: backoff,
            },
        );
        let linked = linked_module(
            main_mod.clone(),
            vec![
                plain_def(task_mod.clone(), backoff, kernel),
                plain_def(main_mod, main_fn, call_top(task_mod, backoff)),
            ],
        );
        let err = check_wasm_client(&linked, &interner)
            .expect_err("a reached server-only stdlib def must be refused");
        match err {
            Diagnostic::Name {
                span,
                msg: NameError::ServerOnlyKernelForWasm { qualifier, name },
            } => {
                assert_eq!(qualifier.as_ref(), "Task");
                assert_eq!(name.as_ref(), "linearBackoff");
                assert_eq!(span.lo, 30, "blame the kernel inside the imported def");
            }
            other => assert_eq!(
                format!("{other:?}"),
                "ServerOnlyKernelForWasm",
                "expected ServerOnlyKernelForWasm"
            ),
        }
    }

    /// A same-module helper `main` calls is reached, so its server-only kernel
    /// is refused; the identical helper uncalled is not.
    #[test]
    fn same_module_helper_is_judged_by_reach() {
        let mut interner = Interner::new();
        let main_mod = vec![intern(&mut interner, "Main")];
        let main_fn = intern(&mut interner, "main");
        let helper = intern(&mut interner, "helper");

        let called = linked_module(
            main_mod.clone(),
            vec![
                plain_def(
                    main_mod.clone(),
                    helper,
                    denied_kernel_at(&mut interner, 10),
                ),
                plain_def(
                    main_mod.clone(),
                    main_fn,
                    call_top(main_mod.clone(), helper),
                ),
            ],
        );
        let err = check_wasm_client(&called, &interner)
            .expect_err("a helper main calls is in the bundle and must be refused");
        assert_eq!(name_span(&err, "called helper").lo, 10);

        let uncalled = linked_module(
            main_mod.clone(),
            vec![
                plain_def(
                    main_mod.clone(),
                    helper,
                    denied_kernel_at(&mut interner, 10),
                ),
                plain_def(main_mod, main_fn, unit_at(0)),
            ],
        );
        check_wasm_client(&uncalled, &interner)
            .expect("an uncalled helper is not emitted and must not be refused");
    }

    /// No `main` at all: nothing is pruned, so every def is judged and a
    /// server-only kernel anywhere is refused (fail closed).
    #[test]
    fn missing_entry_judges_every_def() {
        let mut interner = Interner::new();
        let main_mod = vec![intern(&mut interner, "Main")];
        let helper = intern(&mut interner, "helper");
        let linked = linked_module(
            main_mod.clone(),
            vec![plain_def(
                main_mod,
                helper,
                denied_kernel_at(&mut interner, 10),
            )],
        );
        check_wasm_client(&linked, &interner)
            .expect_err("with no entry every def ships, so every def is judged");
    }

    /// The post-lowering backstop judges what lowering kept, whatever the
    /// closure said: an emitted server-only def is refused, an emitted clean
    /// def passes, and an emitted function with no canonical def is a refused
    /// compiler bug, never a pass.
    #[test]
    fn emitted_set_is_rejudged() {
        let mut interner = Interner::new();
        let main_mod = vec![intern(&mut interner, "Main")];
        let main_fn = intern(&mut interner, "main");
        let helper = intern(&mut interner, "helper");
        let ghost = intern(&mut interner, "ghost");
        let linked = linked_module(
            main_mod.clone(),
            vec![
                plain_def(
                    main_mod.clone(),
                    helper,
                    denied_kernel_at(&mut interner, 10),
                ),
                plain_def(main_mod.clone(), main_fn, unit_at(0)),
            ],
        );
        check_wasm_client(&linked, &interner).expect("the helper is outside the closure");

        check_emitted_for_target(
            &linked,
            &[(main_mod.as_slice(), main_fn)],
            &interner,
            Target::WasmClient,
        )
        .expect("only the clean main is emitted");

        let err = check_emitted_for_target(
            &linked,
            &[
                (main_mod.as_slice(), main_fn),
                (main_mod.as_slice(), helper),
            ],
            &interner,
            Target::WasmClient,
        )
        .expect_err("an emitted server-only def is refused after lowering");
        assert_eq!(name_span(&err, "emitted helper").lo, 10);

        let err = check_emitted_for_target(
            &linked,
            &[(main_mod.as_slice(), ghost)],
            &interner,
            Target::WasmClient,
        )
        .expect_err("an emitted function the gate cannot judge is refused");
        assert!(
            matches!(err, Diagnostic::CompilerBug { .. }),
            "expected CompilerBug, got {err:?}"
        );
    }

    /// Nested `Call` inside an `If` arm body: the recursive walk correctly
    /// descends in source order and finds the earliest offender in a mixed tree.
    #[test]
    fn nested_deep_body_still_finds_first() {
        use ipe_diagnostics::Located;
        let mut interner = Interner::new();

        // If [(clean_cond, Call(f, [denied@lo5, denied@lo15]))] Unit
        let clean_cond = unit_at(0);
        let f_sym = intern(&mut interner, "f");
        let callee = Located::new(Span::new(2, 3), Expr_::VarLocal(f_sym));
        let arg0 = denied_kernel_at(&mut interner, 5);
        let arg1 = denied_kernel_at(&mut interner, 15);
        let call_body = Located::new(
            Span::new(2, 16),
            Expr_::Call(Box::new(callee), vec![arg0, arg1]),
        );
        let body = Expr_::If(vec![(clean_cond, call_body)], Box::new(unit_at(50)));
        let module = single_def_module(&mut interner, body);
        let err = check_wasm_client(&module, &interner)
            .expect_err("denied kernel inside nested call must be found");
        let span = name_span(&err, "nested_deep_body_still_finds_first");
        assert_eq!(span.lo, 5, "first offender is the call arg at lo=5");
    }
}
