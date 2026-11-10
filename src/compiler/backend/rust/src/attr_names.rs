//! Compile-time refusal of literal attribute names the runtime owns.
//!
//! The runtime reserves the `ipe-*` markers, `nonce`, and every `data-ipe-*`
//! name (`ipe_runtime_rust::html::is_runtime_owned_attr_name` is the one
//! predicate). The page renderer drops a hand-built reserved name; a view that
//! spells one as a literal is refused here first (IPE-L0163), so the drop is
//! the second boundary, never the only one.

use ipe_diagnostics::{DResult, Diagnostic, LowerError, Span};
use ipe_ir::{Expr, KernelFn};
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
/// # Errors
///
/// IPE-L0163 when the site names a reserved attribute as a literal.
pub fn refuse_reserved_attr_site(site: KernelSite<'_>) -> DResult<()> {
    let (KernelSite::Call { kernel, args } | KernelSite::Applied { kernel, args }) = site else {
        return Ok(());
    };
    match args.first() {
        Some(Expr::Str(lit))
            if names_an_attribute(kernel) && is_runtime_owned_attr_name(lit.as_str()) =>
        {
            let d = kernel.decl();
            Err(Diagnostic::Lower {
                span: Span::DUMMY,
                msg: LowerError::ReservedAttributeName {
                    call: format!("{}.{}", d.qualifier, d.name).into(),
                    name: excerpt(lit.as_str()),
                },
            })
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::{Diagnostic, LowerError};
    use ipe_ir::{CallPin, Callee, Expr, KernelFn, OnFormKind};

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
            elem: ipe_ir::IrType::Unit,
        };
        assert_eq!(refused_name(&nested).as_deref(), Some("data-ipe-path"));
        let applied = Expr::Apply {
            func: Box::new(Expr::FuncValue {
                callee: Callee::Kernel(KernelFn::UiHtmlAttribute),
                ty: ipe_ir::IrType::Unit,
            }),
            args: vec![Expr::Str("data-ipe-path".into())],
        };
        assert_eq!(refused_name(&applied).as_deref(), Some("data-ipe-path"));
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
