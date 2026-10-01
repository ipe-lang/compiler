//! Decoder-pipeline direction gate: reject the hand-nested form of the
//! `required` / `optional` / `requiredAt` / `custom` decoder combinators.
//!
//! The `Db.Decode` and `Json.Decode.Pipeline` combinators thread a decoder
//! accumulator as their LAST argument, so the idiomatic spelling is a `|>`
//! pipe:
//!
//! ```ipe
//! Db.Decode.succeed User
//!     |> Db.Decode.required "name" Db.Decode.string
//!     |> Db.Decode.required "email" Db.Decode.string
//! ```
//!
//! Read top-to-bottom, the fields bind to the constructor in source order.
//! Hand-nesting the same calls REVERSES that order — the innermost call binds
//! to the constructor first:
//!
//! ```ipe
//! Db.Decode.required "name" Db.Decode.string
//!     (Db.Decode.required "email" Db.Decode.string
//!         (Db.Decode.succeed User))
//! ```
//!
//! Here `email` reaches the constructor before `name`. When two fields share a
//! type this silently swaps them with NO type error — a `User name email`
//! decodes into `User email name`. The gate makes that footgun a compile error
//! (IPE-N0040) whose message shows the correct `|>` rewrite.
//!
//! ## What is detected
//!
//! A [`Expr_::Call`] is a *fully-applied family call* when its head is a bare
//! [`Expr_::VarKernel`] of one of the six family kernels AND its argument count
//! equals that kernel's declared arity. Its accumulator is the LAST argument.
//! The gate rejects a fully-applied family call whose accumulator RESOLVES to
//! another fully-applied family call — either directly nested, or reached
//! through a `let`-bound or top-level binder (the binder-indirection the
//! idiomatic pipe never produces).
//!
//! ## Why the pipe form is untouched (no false positives)
//!
//! `x |> f` desugars to `Call(f, [x])` (`resolve::resolve_binop`). A pipe
//! stage `acc |> Db.Decode.required "name" da` therefore becomes
//! `Call(Call(VarKernel required, ["name", da]), [acc])`: the OUTER call's head
//! is a `Call`, not a bare `VarKernel`, so it is never a fully-applied family
//! call and never inspected. The inner `Call(VarKernel required, ["name", da])`
//! is under-applied (2 args, arity 3), so it is not one either. Only the
//! literally hand-nested spelling — a bare-kernel head applied to its full
//! arity, threading another such call as its accumulator — matches.

use ipe_diagnostics::{DResult, Diagnostic, NameError, Span};
use ipe_intern::Symbol;
use ipe_kernels::StdlibKernel;

use crate::ast::{CaseBranch, Def, Expr, Expr_, LetBinding, Module};

/// The decoder-pipeline combinator family: the accumulator-threading kernels
/// whose hand-nested form silently reverses field↔constructor binding.
///
/// `Db.Decode` exposes only `required` / `optional`; `Json.Decode.Pipeline`
/// additionally exposes `requiredAt` / `custom`. Every one takes its decoder
/// accumulator as its LAST argument.
const FAMILY: [StdlibKernel; 6] = [
    StdlibKernel::DbDecRequired,
    StdlibKernel::DbDecOptional,
    StdlibKernel::JsonDecPRequired,
    StdlibKernel::JsonDecPOptional,
    StdlibKernel::JsonDecPRequiredAt,
    StdlibKernel::JsonDecPCustom,
];

/// A key identifying a top-level binding by its defining module and name.
///
/// After `link::link` merges modules, a [`Expr_::VarTopLevel`] reference
/// carries the ORIGINAL defining module path, matching the `home` each [`Def`]
/// retains — so a `(home, name)` pair resolves a reference to its body across
/// the linked program.
type TopLevelKey = (Vec<Symbol>, Symbol);

/// If `kernel` is a family combinator, its Ipê-level arity; otherwise `None`.
fn family_arity(kernel: StdlibKernel) -> Option<usize> {
    FAMILY
        .contains(&kernel)
        .then(|| usize::from(kernel.decl().arity))
}

/// The accumulator argument of a fully-applied family call, or `None` when
/// `expr` is not one.
///
/// A fully-applied family call is a [`Expr_::Call`] whose head is a bare
/// [`Expr_::VarKernel`] with a resolved family `id` and whose argument count
/// equals that kernel's arity. The accumulator is the last argument. A
/// `VarKernel` with `id: None` (a kernel reached only through the string-match
/// fallback) is never a family match: the gate keys off the pre-resolved
/// discriminant, never a name.
fn family_call_accumulator(expr: &Expr) -> Option<&Expr> {
    let Expr_::Call(head, args) = &expr.value else {
        return None;
    };
    let Expr_::VarKernel { id: Some(k), .. } = &head.value else {
        return None;
    };
    let arity = family_arity(*k)?;
    if args.len() != arity {
        return None;
    }
    args.last()
}

/// A binder already visited on the current accumulator-resolution chain, used
/// to bound the walk against a (source-unrepresentable) binder cycle.
#[derive(Clone, PartialEq, Eq)]
enum ResolveKey {
    Local(Symbol),
    TopLevel(TopLevelKey),
}

/// Resolve an accumulator expression through `let`-bound and top-level binders
/// to the fully-applied family call it ultimately denotes, if any.
///
/// The direct case is `acc` itself being a family call. The indirected cases:
/// `acc` is a [`Expr_::VarLocal`] bound (by an enclosing `let`) to a family
/// call, or a [`Expr_::VarTopLevel`] whose definition body is one. Only a
/// binder whose bound value is ITSELF a fully-applied family call counts;
/// binder chains resolve transitively, and a cycle (which a well-formed source
/// program cannot express through immutable `let`/top-level bindings) is
/// bounded by `seen` so the walk always terminates.
fn resolve_accumulator_family_call<'e>(
    acc: &'e Expr,
    scope: &Scope<'e>,
    seen: &mut Vec<ResolveKey>,
) -> Option<&'e Expr> {
    // A direct family call is the base case.
    if family_call_accumulator(acc).is_some() {
        return Some(acc);
    }
    // Otherwise follow one binder hop and recurse. Guard against revisiting a
    // binder already on the current resolution chain.
    let (key, bound) = match &acc.value {
        Expr_::VarLocal(sym) => (ResolveKey::Local(*sym), scope.lookup_local(*sym)?),
        Expr_::VarTopLevel { module, name } => {
            let key = (module.clone(), *name);
            (
                ResolveKey::TopLevel(key.clone()),
                scope.lookup_toplevel(&key)?,
            )
        }
        _ => return None,
    };
    if seen.contains(&key) {
        return None;
    }
    seen.push(key);
    resolve_accumulator_family_call(bound, scope, seen)
}

/// The binder environment a family call's accumulator resolves against: the
/// program's top-level bodies (module-wide, immutable) plus the `let`-bound
/// locals in scope at the call site (innermost binding wins).
struct Scope<'e> {
    toplevel: &'e std::collections::BTreeMap<TopLevelKey, &'e Expr>,
    /// `let`-bound locals, outermost-first; a later binding shadows an earlier
    /// same-named one, so the lookup scans from the end.
    locals: Vec<(Symbol, &'e Expr)>,
}

impl<'e> Scope<'e> {
    fn lookup_local(&self, sym: Symbol) -> Option<&'e Expr> {
        self.locals
            .iter()
            .rev()
            .find_map(|(s, body)| (*s == sym).then_some(*body))
    }

    fn lookup_toplevel(&self, key: &TopLevelKey) -> Option<&'e Expr> {
        self.toplevel.get(key).copied()
    }
}

/// Reject every hand-nested decoder-pipeline combinator in `module`.
///
/// The idiomatic `|>` pipe form is unaffected (it never produces a
/// fully-applied family call whose accumulator is another one); only the
/// reverse-associated hand-nested spelling — directly or through a binder — is
/// rejected.
///
/// # Errors
/// [`Diagnostic::Name`] (IPE-N0040) at the OUTER hand-nested call, in source
/// order within each def.
pub fn check_decoder_pipelines(module: &Module) -> DResult<()> {
    // Every top-level body, keyed by its `(home, name)`, so a `VarTopLevel`
    // accumulator resolves to the binding it names across the linked program.
    let mut toplevel: std::collections::BTreeMap<TopLevelKey, &Expr> =
        std::collections::BTreeMap::new();
    for def in &module.defs {
        let (home, name, body) = match def {
            Def::Untyped {
                home, name, body, ..
            }
            | Def::Typed {
                home, name, body, ..
            } => (home.clone(), name.value, body),
        };
        toplevel.insert((home, name), body);
    }

    for def in &module.defs {
        let body = match def {
            Def::Untyped { body, .. } | Def::Typed { body, .. } => body,
        };
        let mut scope = Scope {
            toplevel: &toplevel,
            locals: Vec::new(),
        };
        check_expr(body, &mut scope)?;
    }
    Ok(())
}

/// Walk one expression, rejecting a fully-applied family call whose resolved
/// accumulator is itself a fully-applied family call.
///
/// `let`-bound locals are pushed onto `scope.locals` for the duration of the
/// binding's body and its `in` body, then popped, so a family call resolves its
/// accumulator against exactly the bindings visible at its own site. Native
/// recursion mirrors the tree: canonicalisation already recurses natively over
/// this same tree upstream, so any body deep enough to overflow here overflowed
/// canon first — this gate adds no new stack-depth exposure.
fn check_expr<'e>(expr: &'e Expr, scope: &mut Scope<'e>) -> DResult<()> {
    // A hand-nested family call is the rejection: this expression is a
    // fully-applied family call AND its accumulator resolves to another.
    if let Some(acc) = family_call_accumulator(expr) {
        let mut seen = Vec::new();
        if resolve_accumulator_family_call(acc, scope, &mut seen).is_some() {
            return Err(reject(expr.span));
        }
    }

    match &expr.value {
        Expr_::VarLocal(_)
        | Expr_::VarTopLevel { .. }
        | Expr_::VarKernel { .. }
        | Expr_::VarCtor { .. }
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::Char(_)
        | Expr_::CustomElementCtor(_)
        | Expr_::Unit => Ok(()),
        Expr_::Call(head, args) => {
            check_expr(head, scope)?;
            for a in args {
                check_expr(a, scope)?;
            }
            Ok(())
        }
        Expr_::ForeignCall { args, .. } => {
            for a in args {
                check_expr(a, scope)?;
            }
            Ok(())
        }
        Expr_::Case(scrut, branches) => {
            check_expr(scrut, scope)?;
            for CaseBranch { body, .. } in branches {
                check_expr(body, scope)?;
            }
            Ok(())
        }
        Expr_::Lambda(_, body) => check_expr(body, scope),
        Expr_::Binop { lhs, rhs, .. } => {
            check_expr(lhs, scope)?;
            check_expr(rhs, scope)
        }
        Expr_::Let(bindings, body) => check_let(bindings, body, scope),
        Expr_::If(arms, els) => {
            for (c, b) in arms {
                check_expr(c, scope)?;
                check_expr(b, scope)?;
            }
            check_expr(els, scope)
        }
        Expr_::Tuple(items) | Expr_::List(items) => {
            for e in items {
                check_expr(e, scope)?;
            }
            Ok(())
        }
        Expr_::Cons(h, t) => {
            check_expr(h, scope)?;
            check_expr(t, scope)
        }
        Expr_::Record(fields) => {
            for (_, v) in fields {
                check_expr(v, scope)?;
            }
            Ok(())
        }
        Expr_::Access(base, _) => check_expr(base, scope),
        Expr_::Update(base, fields) => {
            check_expr(base, scope)?;
            for (_, v) in fields {
                check_expr(v, scope)?;
            }
            Ok(())
        }
    }
}

/// Walk a `let`, registering each `PVar` binding as an in-scope local for the
/// checks of the later bindings and the `in` body, then unregistering them.
///
/// Ipê `let` bindings are scoped sequentially (each resolved against the
/// bindings before it), so a binding's own body sees only the earlier ones;
/// this pushes each binding AFTER checking its body. Only a plain `name = …`
/// (`PVar`) binder can be named by a later accumulator reference, so only those
/// are recorded; a destructuring binder introduces no name a `VarLocal`
/// accumulator could denote.
fn check_let<'e>(bindings: &'e [LetBinding], body: &'e Expr, scope: &mut Scope<'e>) -> DResult<()> {
    let depth = scope.locals.len();
    for LetBinding { pat, body: b } in bindings {
        check_expr(b, scope)?;
        if let crate::ast::Pattern_::PVar(sym) = &pat.value {
            scope.locals.push((*sym, b));
        }
    }
    let result = check_expr(body, scope);
    scope.locals.truncate(depth);
    result
}

/// The IPE-N0040 rejection at the outer hand-nested combinator call.
const fn reject(span: Span) -> Diagnostic {
    Diagnostic::Name {
        span,
        msg: NameError::NestedDecoderPipeline,
    }
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::{Located, Span};
    use ipe_intern::Interner;

    use super::*;
    use crate::ast::Pattern_;

    fn intern(interner: &mut Interner, s: &str) -> Symbol {
        #[allow(clippy::expect_used)]
        interner.intern(s).expect("intern must succeed in a test")
    }

    fn sp<T>(v: T) -> Located<T> {
        Located::new(Span::DUMMY, v)
    }

    /// A `Db.Decode.<name>` kernel reference node for the given family variant.
    fn kernel(interner: &mut Interner, k: StdlibKernel, module: &str, name: &str) -> Expr {
        let module = intern(interner, module);
        let name = intern(interner, name);
        sp(Expr_::VarKernel {
            id: Some(k),
            module,
            name,
        })
    }

    /// A fully-applied family `required` call over `field`, decoder `da`, and
    /// accumulator `acc`: `Db.Decode.required "field" da acc` (arity 3).
    fn required_call(interner: &mut Interner, acc: Expr) -> Expr {
        let head = kernel(
            interner,
            StdlibKernel::DbDecRequired,
            "Db.Decode",
            "required",
        );
        sp(Expr_::Call(
            Box::new(head),
            vec![sp(Expr_::Str("field".into())), sp(Expr_::Unit), acc],
        ))
    }

    /// `Db.Decode.succeed Ctor` — a fully-applied `succeed` (NOT a family
    /// combinator, so a valid pipeline base).
    fn succeed_call(interner: &mut Interner) -> Expr {
        let head = kernel(interner, StdlibKernel::DbDecSucceed, "Db.Decode", "succeed");
        sp(Expr_::Call(Box::new(head), vec![sp(Expr_::Unit)]))
    }

    fn module_with_body(interner: &mut Interner, body: Expr) -> Module {
        let main = vec![intern(interner, "Main")];
        let name = intern(interner, "decoder");
        Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: main.clone(),
            unions: Vec::new(),
            defs: vec![Def::Untyped {
                home: main,
                name: sp(name),
                patterns: Vec::new(),
                body,
            }],
        }
    }

    /// The DIRECT hand-nested form — `required "a" da (required "b" db
    /// (succeed Ctor))` — is rejected with IPE-N0040 (the base footgun).
    #[test]
    fn direct_nested_is_rejected() {
        let mut interner = Interner::new();
        let base = succeed_call(&mut interner);
        let inner = required_call(&mut interner, base);
        let outer = required_call(&mut interner, inner);
        let module = module_with_body(&mut interner, outer);
        let err = check_decoder_pipelines(&module)
            .expect_err("the direct hand-nested decoder form must be rejected");
        assert!(
            matches!(
                err,
                Diagnostic::Name {
                    msg: NameError::NestedDecoderPipeline,
                    ..
                }
            ),
            "expected NestedDecoderPipeline, got {err:?}"
        );
    }

    /// The binder-indirected form — `acc = required "b" db (succeed Ctor)`
    /// then `required "a" da acc` — is rejected too: the accumulator resolves
    /// through the `let` binder to a fully-applied family call.
    #[test]
    fn let_binder_indirected_nested_is_rejected() {
        let mut interner = Interner::new();
        let acc_sym = intern(&mut interner, "acc");
        let base = succeed_call(&mut interner);
        let acc_body = required_call(&mut interner, base);
        // `required "a" da acc` — accumulator is a bare VarLocal(acc).
        let outer = required_call(&mut interner, sp(Expr_::VarLocal(acc_sym)));
        let body = sp(Expr_::Let(
            vec![LetBinding {
                pat: sp(Pattern_::PVar(acc_sym)),
                body: acc_body,
            }],
            Box::new(outer),
        ));
        let module = module_with_body(&mut interner, body);
        let err = check_decoder_pipelines(&module)
            .expect_err("the let-binder-indirected hand-nested form must be rejected");
        assert!(matches!(
            err,
            Diagnostic::Name {
                msg: NameError::NestedDecoderPipeline,
                ..
            }
        ));
    }

    /// A top-level binder accumulator — `acc` a sibling def whose body is a
    /// family call, referenced as the accumulator of `required "a" da acc` —
    /// is rejected: `VarTopLevel` resolves across the linked program.
    #[test]
    fn toplevel_binder_indirected_nested_is_rejected() {
        let mut interner = Interner::new();
        let main = vec![intern(&mut interner, "Main")];
        let acc_name = intern(&mut interner, "acc");
        let dec_name = intern(&mut interner, "decoder");
        let base = succeed_call(&mut interner);
        let acc_body = required_call(&mut interner, base);
        let outer = required_call(
            &mut interner,
            sp(Expr_::VarTopLevel {
                module: main.clone(),
                name: acc_name,
            }),
        );
        let module = Module {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            name: main.clone(),
            unions: Vec::new(),
            defs: vec![
                Def::Untyped {
                    home: main.clone(),
                    name: sp(acc_name),
                    patterns: Vec::new(),
                    body: acc_body,
                },
                Def::Untyped {
                    home: main,
                    name: sp(dec_name),
                    patterns: Vec::new(),
                    body: outer,
                },
            ],
        };
        let err = check_decoder_pipelines(&module)
            .expect_err("the top-level-binder-indirected hand-nested form must be rejected");
        assert!(matches!(
            err,
            Diagnostic::Name {
                msg: NameError::NestedDecoderPipeline,
                ..
            }
        ));
    }

    /// The idiomatic pipe form — `Call(Call(required, [..]), [acc])`, the
    /// desugaring of `acc |> required "a" da` — passes: the outer call's head
    /// is a `Call`, not a bare `VarKernel`, so it is never a fully-applied
    /// family call.
    #[test]
    fn idiomatic_pipe_form_passes() {
        let mut interner = Interner::new();
        // Inner (under-applied) head: `required "a" da` — 2 args, arity 3.
        let head = kernel(
            &mut interner,
            StdlibKernel::DbDecRequired,
            "Db.Decode",
            "required",
        );
        let partial = sp(Expr_::Call(
            Box::new(head),
            vec![sp(Expr_::Str("a".into())), sp(Expr_::Unit)],
        ));
        // `acc |> required "a" da` == Call(partial, [acc]).
        let base = succeed_call(&mut interner);
        let piped = sp(Expr_::Call(Box::new(partial), vec![base]));
        let module = module_with_body(&mut interner, piped);
        check_decoder_pipelines(&module)
            .expect("the idiomatic |> pipe form must pass the gate unconditionally");
    }

    /// A single fully-applied family call whose accumulator is a plain
    /// `succeed` (not a family combinator) passes — one combinator is not a
    /// nesting.
    #[test]
    fn single_combinator_over_succeed_passes() {
        let mut interner = Interner::new();
        let base = succeed_call(&mut interner);
        let one = required_call(&mut interner, base);
        let module = module_with_body(&mut interner, one);
        check_decoder_pipelines(&module)
            .expect("a single combinator over `succeed` is a valid one-field decoder");
    }

    /// A binder bound to a NON-family value is not a nesting: `acc = succeed
    /// Ctor` then `required "a" da acc` is the ordinary one-combinator form.
    #[test]
    fn binder_to_non_family_value_passes() {
        let mut interner = Interner::new();
        let acc_sym = intern(&mut interner, "acc");
        let base = succeed_call(&mut interner);
        let outer = required_call(&mut interner, sp(Expr_::VarLocal(acc_sym)));
        let body = sp(Expr_::Let(
            vec![LetBinding {
                pat: sp(Pattern_::PVar(acc_sym)),
                body: base,
            }],
            Box::new(outer),
        ));
        let module = module_with_body(&mut interner, body);
        check_decoder_pipelines(&module)
            .expect("a binder to a plain `succeed` base is a valid one-field decoder");
    }
}
