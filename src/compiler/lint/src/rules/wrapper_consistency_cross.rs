//! `wrapper-consistency-cross` — the cross-module counterpart of
//! `wrapper-consistency`.
//!
//! When a parameter name is consistently wrapped as a newtype across MULTIPLE
//! modules' exported APIs, a module that leaves the same-named parameter bare
//! violates the project-wide convention. This rule aggregates the wrapper
//! evidence from ALL modules under lint and flags bare usages against that
//! project-wide convention.
//!
//! The intra-module `wrapper-consistency` rule fires when two sibling
//! functions within one module set the convention. This rule fires when the
//! convention is set by bindings in OTHER modules (at least two distinct
//! modules that each wrap the parameter) and one module leaves it bare.
//!
//! Same conservative guard as the intra-module rule: at least two wrap sites
//! across the project (from at least two distinct modules), a single consensus
//! wrapper name, and at least one bare site.

use std::collections::{BTreeMap, BTreeSet};

use ipe_canon::sig_delta::ShapeDelta;

use crate::cancel::CancelProbe;
use crate::finding::{Finding, SigFix};
use crate::rules::{self, Ctx};

/// A usage record collected across all modules for one parameter name.
#[derive(Default)]
struct CrossUsage<'a> {
    /// `(module, binding_name, span, bare_type, param_index)` — bare sites.
    bare: Vec<(&'a [String], &'a str, ipe_diagnostics::Span, &'a str, usize)>,
    /// Distinct wrapper names seen across all modules.
    wrapped_as: BTreeSet<&'a str>,
    /// Number of distinct modules that wrap this parameter.
    wrap_module_count: usize,
    /// Total wrap sites.
    wrap_sites: usize,
}

fn is_primitive(name: &str) -> bool {
    matches!(name, "Int" | "String" | "Float" | "Bool" | "Char")
}

/// Check `wrapper-consistency-cross` across all modules.
///
/// `probe` is polled before each module's contribution is aggregated, so a
/// superseded run stops within one module of this pass too.
///
/// # Errors
///
/// Returns the probe's `Cancelled` value once it fires; no partial finding set
/// is returned.
pub fn check_cross<'a, P: CancelProbe>(
    ctxs: &[&'a Ctx<'a>],
    probe: &P,
) -> Result<Vec<Finding>, P::Cancelled> {
    // First pass: aggregate per-param-name usage across all modules.
    let mut by_param: BTreeMap<&'a str, CrossUsage<'a>> = BTreeMap::new();

    for ctx in ctxs {
        probe.poll()?;
        // Track which param names this module wraps, to count module-level
        // wrap contributions correctly.
        let mut wrapped_in_this_module: BTreeSet<&str> = BTreeSet::new();

        for (value, ann) in rules::annotated_values(ctx) {
            if !rules::is_exported(ctx, value.value.name.value) {
                continue;
            }
            let binding = ctx.text(value.value.name.value);
            let (params, _ret) = rules::flatten_arrow(&ann.value);
            for (idx, param_ty) in params.iter().enumerate() {
                let Some(param_name) = nth_param_name(ctx, value, idx) else {
                    continue;
                };
                let Some(head) = rules::con_head_name(ctx, param_ty) else {
                    continue;
                };
                let usage = by_param.entry(param_name).or_default();
                if is_primitive(head) {
                    usage.bare.push((ctx.module, binding, ann.span, head, idx));
                } else {
                    usage.wrapped_as.insert(head);
                    usage.wrap_sites += 1;
                    wrapped_in_this_module.insert(param_name);
                }
            }
        }
        // Count this module's contribution toward the module-count threshold.
        for param_name in wrapped_in_this_module {
            by_param.entry(param_name).or_default().wrap_module_count += 1;
        }
    }

    let mut findings = Vec::new();
    for (param_name, usage) in &by_param {
        // Cross-module guard: at least 2 modules set the convention under a
        // single wrapper name, and at least one module leaves the param bare.
        if usage.wrap_module_count < 2 || usage.wrapped_as.len() != 1 || usage.bare.is_empty() {
            continue;
        }
        let wrapper = usage.wrapped_as.iter().next().copied().unwrap_or_default();

        // Emit one finding per bare site, attributed to the module that owns it.
        // We need a `Ctx` to call `ctx.with_sig_fix`; find it by matching module.
        for (module_path, binding_name, span, bare, param_idx) in &usage.bare {
            let Some(ctx) = ctxs.iter().find(|c| c.module == *module_path) else {
                continue;
            };
            let sig_fix = SigFix {
                symbol_module: ctx.module.to_vec(),
                symbol_name: (*binding_name).to_owned(),
                param_index: *param_idx,
                delta: ShapeDelta::WrapPrimitive {
                    arg_index: *param_idx,
                    ctor_name: wrapper.to_owned(),
                },
            };
            findings.push(ctx.with_sig_fix(
                "wrapper-consistency-cross",
                *span,
                format!(
                    "exported `{binding_name}` passes `{param_name}` as a bare `{bare}`, \
                     but {} other module(s) wrap it as `{wrapper}`",
                    usage.wrap_module_count,
                ),
                vec![
                    format!(
                        "the convention is established across {} module(s); \
                         wrap `{param_name}` as `{wrapper}` here too",
                        usage.wrap_module_count,
                    ),
                    format!("`ipe lint --fix` wraps call-site arguments with `{wrapper}`"),
                    "suppress: `-- ipe-lint: allow wrapper-consistency-cross`".to_owned(),
                ],
                sig_fix,
            ));
        }
    }
    Ok(findings)
}

fn nth_param_name<'a>(
    ctx: &'a Ctx,
    value: &ipe_diagnostics::Located<ipe_syntax::Value>,
    idx: usize,
) -> Option<&'a str> {
    use ipe_syntax::Pattern_;
    match value.value.patterns.get(idx).map(|p| &p.value) {
        Some(Pattern_::PVar(sym)) => Some(ctx.text(*sym)),
        _ => None,
    }
}
