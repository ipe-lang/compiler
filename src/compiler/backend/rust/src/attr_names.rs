//! Compile-time refusal of literal attribute names the runtime owns.
//!
//! The runtime reserves the `ipe-*` markers but the keyed-list `ipe-key`,
//! `nonce`, and every `data-ipe-*` name
//! (`ipe_runtime_rust::html::is_runtime_owned_attr_name` is the one
//! predicate). A view that spells one as a literal, at the call or through a
//! `let` (a partial application's hoisted argument), is refused here
//! (IPE-L0163). The runtime's program-facing attribute constructors drop a
//! reserved name computed at run time, and the page renderer drops a reserved
//! name again at the sink, so no boundary is the only one.

use ipe_diagnostics::{DResult, Diagnostic, LowerError, Span};
use ipe_ir::KernelFn;
use ipe_runtime_rust::html::is_runtime_owned_attr_name;

use crate::kernel_walk::KernelSite;
use crate::route_grammar::excerpt;

/// Whether kernel `k` takes an attribute name as its first argument.
const fn names_an_attribute(k: KernelFn) -> bool {
    matches!(
        k,
        KernelFn::HtmlAttribute | KernelFn::HtmlBoolAttribute | KernelFn::UiHtmlAttribute
    )
}

/// Refuse a runtime-owned literal attribute name at one kernel site.
///
/// The literal is read where it is written and through a `let` that binds it,
/// so a partially applied `Attr.attribute "data-ipe-path"` is refused like a
/// saturated call. A name computed at run time is dropped by the runtime's
/// program-facing attribute constructors instead.
///
/// # Errors
///
/// IPE-L0163 when the site names a reserved attribute as a literal.
pub fn refuse_reserved_attr_site(site: KernelSite<'_, '_>) -> DResult<()> {
    let (KernelSite::Call { kernel, .. } | KernelSite::Applied { kernel, .. }) = site else {
        return Ok(());
    };
    match site.literal_arg(0) {
        Some(lit) if names_an_attribute(kernel) && is_runtime_owned_attr_name(lit) => {
            let d = kernel.decl();
            Err(Diagnostic::Lower {
                span: Span::DUMMY,
                msg: LowerError::ReservedAttributeName {
                    call: format!("{}.{}", d.qualifier, d.name).into(),
                    name: excerpt(lit),
                },
            })
        }
        Some(_) | None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::{Diagnostic, LowerError};
    use ipe_intern::Symbol;
    use ipe_ir::{CallPin, Callee, Expr, IrType, KernelFn, OnFormKind};

    use super::refuse_reserved_attr_site;
    use crate::kernel_walk::each_kernel_site_in;

    fn call(k: KernelFn, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Callee::Kernel(k),
            args,
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    fn attr(k: KernelFn, name: &str) -> Expr {
        call(k, vec![Expr::Str(name.into()), Expr::Str("/about".into())])
    }

    /// The name the walk refuses inside `expr`, if any.
    fn refused_name(expr: &Expr) -> Option<Box<str>> {
        match each_kernel_site_in(expr, &mut refuse_reserved_attr_site) {
            Err(Diagnostic::Lower {
                msg: LowerError::ReservedAttributeName { name, .. },
                ..
            }) => Some(name),
            _ => None,
        }
    }

    /// Prove the refusal: every attribute-name kernel refuses a literal
    /// `data-ipe-path` in any case spelling, and any other runtime-owned name.
    #[test]
    fn data_ipe_path_literal_is_refused_by_every_attribute_kernel() {
        for k in [
            KernelFn::HtmlAttribute,
            KernelFn::HtmlBoolAttribute,
            KernelFn::UiHtmlAttribute,
        ] {
            for name in [
                "data-ipe-path",
                "DATA-IPE-PATH",
                "Data-Ipe-Path",
                "data-ipe-on",
                "data-ipe-hid",
                "ipe-click",
                "nonce",
            ] {
                assert_eq!(
                    refused_name(&attr(k, name)).as_deref(),
                    Some(name),
                    "{k:?} {name}"
                );
            }
        }
    }

    /// Prove the refusal reaches nested and applied positions: a reserved name
    /// inside a list, and a kernel value applied to it.
    #[test]
    fn nested_and_applied_reserved_names_are_refused() {
        let nested = Expr::List {
            items: vec![
                attr(KernelFn::HtmlAttribute, "data-x"),
                attr(KernelFn::HtmlAttribute, "data-ipe-path"),
            ],
            elem: IrType::Unit,
        };
        assert_eq!(refused_name(&nested).as_deref(), Some("data-ipe-path"));
        let applied = Expr::Apply {
            func: Box::new(Expr::FuncValue {
                callee: Callee::Kernel(KernelFn::UiHtmlAttribute),
                ty: IrType::Unit,
            }),
            args: vec![Expr::Str("data-ipe-path".into())],
        };
        assert_eq!(refused_name(&applied).as_deref(), Some("data-ipe-path"));
    }

    /// The lowered shape of a partially applied `Attr.attribute "<name>"`:
    /// the supplied literal is hoisted into a `let` around the residual
    /// closure, and the kernel call reads it through `cap`.
    fn partial(name: &str, cap: Symbol, eta: Symbol) -> Expr {
        Expr::Let {
            name: cap,
            value: Box::new(Expr::Str(name.into())),
            body: Box::new(Expr::Lambda {
                params: vec![(eta, IrType::Unit)],
                ret: IrType::Unit,
                body: Box::new(call(
                    KernelFn::HtmlAttribute,
                    vec![Expr::CloneVar(cap), Expr::Var(eta)],
                )),
            }),
        }
    }

    /// Prove the refusal: a partially applied attribute kernel (`List.map
    /// (Attr.attribute "data-ipe-path") values`) is refused like a saturated
    /// call, as is a name bound by a plain `let`.
    #[test]
    fn partially_applied_reserved_name_is_refused() {
        let cap = Symbol::from_raw(1);
        let eta = Symbol::from_raw(2);
        assert_eq!(
            refused_name(&partial("data-ipe-path", cap, eta)).as_deref(),
            Some("data-ipe-path")
        );
        assert_eq!(
            refused_name(&partial("Data-Ipe-Mq-Rules", cap, eta)).as_deref(),
            Some("Data-Ipe-Mq-Rules")
        );
        assert_eq!(refused_name(&partial("data-x", cap, eta)), None);
    }

    /// The control: a binder between the `let` and the call that rebinds the
    /// symbol hides the outer literal.
    #[test]
    fn a_shadowed_literal_is_not_read_through() {
        let cap = Symbol::from_raw(1);
        let eta = Symbol::from_raw(2);
        let inner = call(
            KernelFn::HtmlAttribute,
            vec![Expr::Var(cap), Expr::Var(eta)],
        );
        let shadowed = Expr::Let {
            name: cap,
            value: Box::new(Expr::Str("data-ipe-path".into())),
            body: Box::new(Expr::Lambda {
                params: vec![(cap, IrType::Unit), (eta, IrType::Unit)],
                ret: IrType::Unit,
                body: Box::new(inner.clone()),
            }),
        };
        assert_eq!(refused_name(&shadowed), None);
        let rebound = Expr::Let {
            name: cap,
            value: Box::new(Expr::Str("data-ipe-path".into())),
            body: Box::new(Expr::Let {
                name: cap,
                value: Box::new(Expr::Var(eta)),
                body: Box::new(inner),
            }),
        };
        assert_eq!(refused_name(&rebound), None);
    }

    /// The control: names outside the reserved set, the exact `ipe-key`, and a
    /// reserved string in a non-name position all pass.
    #[test]
    fn unreserved_names_pass() {
        for name in ["data-x", "data-section", "ipe-key", "data-ipe", "title"] {
            assert_eq!(
                refused_name(&attr(KernelFn::HtmlAttribute, name)),
                None,
                "{name}"
            );
        }
        let value_only = call(
            KernelFn::HtmlAttribute,
            vec![Expr::Str("title".into()), Expr::Str("data-ipe-path".into())],
        );
        assert_eq!(refused_name(&value_only), None);
    }
}
