//! The layout-budget seam: what the renderer spends laying out each function body.
//!
//! Every function is emitted through [`crate::emit_expr::emit_func`], the call a
//! build makes, while [`crate::emit_expr::record_body_spends`] collects the spend
//! of each body render it does, so the spend reported is the spend a real build
//! pays. A body the build emits without the renderer (a tail loop) reports none.

use ipe_diagnostics::DResult;
use ipe_intern::Interner;

use crate::EmitCtx;
use crate::emit_expr::{emit_func, record_body_spends};

pub use crate::render::LAYOUT_FUEL;

/// What laying out one function body spent of [`LAYOUT_FUEL`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyLayoutBudget {
    /// The Rust name of the function whose body was laid out.
    pub func: String,
    /// The fuel the layout search spent, all of [`LAYOUT_FUEL`] when it ran out.
    pub spent: usize,
    /// Whether the search ran out and the body was written in its plain layout.
    pub exhausted: bool,
}

/// The layout spend of every function-body render in `program`, in module then
/// function then render order.
///
/// # Errors
/// Propagates any [`ipe_diagnostics::Diagnostic`] from [`EmitCtx::build`] or
/// [`emit_func`].
pub fn body_layout_budgets(
    interner: &Interner,
    program: &ipe_ir::Program,
) -> DResult<Vec<BodyLayoutBudget>> {
    let ctx = EmitCtx::build(
        interner,
        program,
        crate::DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        crate::MountBase::root(),
        false,
        None,
        false,
        crate::BuildIntent::Release,
        String::new(),
        false,
        false,
        None,
    )?;
    let mut budgets = Vec::new();
    for module in &program.modules {
        for func in &module.funcs {
            let func_name = ctx.func_name(func.id)?.to_owned();
            let (emitted, spends) = record_body_spends(|| emit_func(&ctx, func));
            emitted?;
            budgets.extend(spends.into_iter().map(|spend| BodyLayoutBudget {
                func: func_name.clone(),
                spent: spend.spent,
                exhausted: spend.exhausted,
            }));
        }
    }
    Ok(budgets)
}
