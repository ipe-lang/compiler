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

mod enum_facts;
pub mod free_vars;
mod held;
mod ir;
pub mod let_inline;
pub mod once_closure;
mod pairing;
mod pretty;
pub mod record_shapes;
pub mod seq_clone;
mod show_policy;

pub use enum_facts::{EnumTraits, RuntimeBridgedEnum, payload_leaf_is_clone};
pub use held::{
    EnumPayloadTable, MAX_HELD_WALK_DEPTH, Reach, enum_payload_holds, enum_payload_table,
    ir_type_holds, ir_type_reaches,
};
pub use ir::{
    Arm, BinOp, BoundSet, CallPin, Callee, Carried, CarrierLeaf, EnumDef, EvalOrder, Expr, Func,
    FuncId, HtmlEventShape, IrType, KernelClass, KernelFn, Match, ModPath, Module, OnFormKind, Pat,
    Program, RowParam, RuntimeFeatureId, RuntimeModule, SliceOwnership, TypeDef, UiCtor, UiPlain,
    Variant, carrier_is_clone, carrier_is_clone_bounded, carrier_leaf, fun_value_arc_promotable,
    ir_type_feature_requirement, ir_type_has_effect_carrier, ir_type_is_derivable,
    ir_type_is_serde, is_dispatch_free, is_irrefutable,
};
pub use pairing::{PairedChildren, paired_children};
pub use pretty::{MAX_IR_RENDER_DEPTH, pretty};
pub use show_policy::{
    DEEP_VALUE_MARKER, FUNCTION_MARKER, MAX_SHOWN_TUPLE_ARITY, NamedShow, SHOWN_LEAVES, ShowLeaf,
    ShowPolicy, ShowShape, WIDE_TUPLE_MARKER, ir_type_holds_refused, named_enum_shape,
    refused_marker, show_leaf,
};

/// The compilation target (kernel-availability axis) — re-exported so
/// backend/db consumers reach it through the IR crate like `KernelFn`.
pub use ipe_kernels::Target;

/// The app surface a program's entry pins.
///
/// Re-exported so the lowerer and backend key shape-owned kernels on it through
/// the IR crate.
pub use ipe_kernels::AppSurface;

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
