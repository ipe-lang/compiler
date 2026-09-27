#![forbid(unsafe_code)]
//! Backend-agnostic typed intermediate representation for the Ipê compiler.
//! This is the single boundary every backend consumes: the frontend lowers
//! into [`Program`], backends read it and emit code. No frontend type leaks
//! across this line.
//!
//! Illegal states are unrepresentable. In particular, a
//! [`Match`] is exhaustive by construction — the only way to build one is
//! [`Match::new`], which verifies the arm set covers exactly the scrutinee's
//! enum variants and returns [`ipe_diagnostics::Diagnostic::CompilerBug`]
//! otherwise. A backend that receives a [`Program`] never has to re-check
//! exhaustiveness.

pub mod free_vars;
mod ir;
pub mod let_inline;
mod pretty;
pub mod record_shapes;
pub mod seq_clone;

pub use ir::{
    Arm, BinOp, BoundSet, CallPin, Callee, EnumDef, EvalOrder, Expr, Func, FuncId, HtmlEventShape,
    IrType, KernelClass, KernelFn, Match, ModPath, Module, OnFormKind, Pat, Program, RowParam,
    RuntimeFeatureId, RuntimeModule, TypeDef, UiCtor, UiPlain, Variant, carrier_is_clone,
    fun_value_arc_promotable, ir_type_feature_requirement, ir_type_has_effect_carrier,
    ir_type_is_derivable, ir_type_is_serde, is_dispatch_free, is_irrefutable,
};
pub use pretty::{MAX_IR_RENDER_DEPTH, pretty};

/// The compilation target (kernel-availability axis) — re-exported so
/// backend/db consumers reach it through the IR crate like `KernelFn`.
pub use ipe_kernels::Target;

/// The security-capability vocabulary — re-exported so lowering/CLI consumers
/// reach it through the IR crate like `KernelFn`. [`WebCapability`] is the closed
/// per-Web-API sub-axis a [`Capability::JsPort`] discloses.
pub use ipe_kernels::{Capability, WebCapability};

/// The user function name of the wasm-hydration island projection.
///
/// It is invoked only by generated `hydrate` glue, never from user code, so it
/// is an externally-invoked export root the frontend must keep past
/// dead-function elimination and the backend resolves the island type from.
/// Both sites share this one name so they cannot drift.
pub const HYDRATION_PROJECTION_NAME: &str = "fromHydrationState";
