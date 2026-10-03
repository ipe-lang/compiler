//! Expression and function emission.
//!
//! Ports the relevant arms of `Ipê/Generate/Rust/Builder/ExprEmitter.hs` and
//! the function-item shape from `ModuleEmitter.hs`. The byte target is golden
//! `main.rs` lines 129–137 (`main_update` / `ipe_main`).

pub use crate::doc::Doc;
pub use crate::emit_types::{GenericScope, render_type};
pub use crate::emit_ui_plan::{
    ArgPlan, Guard, LitKind, NativeUiEmit, UiDelegate, UiEmitPlan,
    appearance_literal_record_fields, shape_appearance_literal_args, ui_call_shape,
};
pub use crate::naming::kernel_name;
pub use crate::render::RenderConfig;
pub use ipe_diagnostics::{DResult, Diagnostic, LowerError, Span};
pub use ipe_intern::Symbol;
pub use ipe_ir::{
    Arm, BinOp, BoundSet, Callee, Expr, Func, IrType, KernelClass, KernelFn, MAX_IR_RENDER_DEPTH,
    Match, ModPath, Pat,
};

mod analysis;
mod expr;
mod ffi;
mod func;
mod kernel_calls;
mod numeric;
mod patterns;
mod records;
#[cfg(test)]
mod tests;

pub use analysis::*;
pub use expr::*;
pub use ffi::*;
pub use func::*;
pub use kernel_calls::*;
pub use numeric::*;
pub use patterns::*;
pub use records::*;
