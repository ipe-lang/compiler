//! Consolidated golden binary for the `tuple` theme.
//! Each `mod` below is one original `golden_*.rs`; test identity is
//! preserved as `<module>::<fn>`. Merged to cut per-file link cost.

mod support;

#[path = "g_tuple/golden_alias_tuple.rs"]
mod golden_alias_tuple;
#[path = "g_tuple/golden_generic_tuple_param_binder.rs"]
mod golden_generic_tuple_param_binder;
#[path = "g_tuple/golden_tuple_annotations.rs"]
mod golden_tuple_annotations;
#[path = "g_tuple/golden_tuple_multiarm_case.rs"]
mod golden_tuple_multiarm_case;
#[path = "g_tuple/golden_tuple_multiarm_var_scrutinee.rs"]
mod golden_tuple_multiarm_var_scrutinee;
#[path = "g_tuple/golden_tuple_nested_coerce_gate.rs"]
mod golden_tuple_nested_coerce_gate;
#[path = "g_tuple/golden_tuple_pattern.rs"]
mod golden_tuple_pattern;
#[path = "g_tuple/golden_tuple_refutable_var_scrutinee.rs"]
mod golden_tuple_refutable_var_scrutinee;
#[path = "g_tuple/golden_tuple_self_edge.rs"]
mod golden_tuple_self_edge;
#[path = "g_tuple/golden_tuple_str_column_var_scrutinee.rs"]
mod golden_tuple_str_column_var_scrutinee;
#[path = "g_tuple/golden_tuples.rs"]
mod golden_tuples;
#[path = "g_tuple/golden_two_same_ctor.rs"]
mod golden_two_same_ctor;
