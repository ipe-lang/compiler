//! Consolidated golden binary for the `record_generic` theme.
//! Each `mod` below is one original `golden_*.rs`; test identity is
//! preserved as `<module>::<fn>`. Merged to cut per-file link cost.

mod support;

#[path = "g_record_generic/golden_body_local_generic_record.rs"]
mod golden_body_local_generic_record;
#[path = "g_record_generic/golden_captured_record_field_access_clone.rs"]
mod golden_captured_record_field_access_clone;
#[path = "g_record_generic/golden_csv_record_nominal_fold_seal.rs"]
mod golden_csv_record_nominal_fold_seal;
#[path = "g_record_generic/golden_dotfield.rs"]
mod golden_dotfield;
#[path = "g_record_generic/golden_fncarrier_record_generic_clone.rs"]
mod golden_fncarrier_record_generic_clone;
#[path = "g_record_generic/golden_generic.rs"]
mod golden_generic;
#[path = "g_record_generic/golden_generic_records.rs"]
mod golden_generic_records;
#[path = "g_record_generic/golden_i1346_generic_record_field_name_collision.rs"]
mod golden_i1346_generic_record_field_name_collision;
#[path = "g_record_generic/golden_i1349_concrete_record_straddles_two_generic_templates.rs"]
mod golden_i1349_concrete_record_straddles_two_generic_templates;
#[path = "g_record_generic/golden_i3658_record_template_lgg.rs"]
mod golden_i3658_record_template_lgg;
#[path = "g_record_generic/golden_param_patterns.rs"]
mod golden_param_patterns;
#[path = "g_record_generic/golden_parametric.rs"]
mod golden_parametric;
#[path = "g_record_generic/golden_record_ctor.rs"]
mod golden_record_ctor;
#[path = "g_record_generic/golden_record_self_edge.rs"]
mod golden_record_self_edge;
#[path = "g_record_generic/golden_record_update.rs"]
mod golden_record_update;
#[path = "g_record_generic/golden_record_update_nonclone_field_reads_base.rs"]
mod golden_record_update_nonclone_field_reads_base;
#[path = "g_record_generic/golden_records.rs"]
mod golden_records;
#[path = "g_record_generic/golden_reused_generic_clone.rs"]
mod golden_reused_generic_clone;
#[path = "g_record_generic/golden_row_poly_records.rs"]
mod golden_row_poly_records;
#[path = "g_record_generic/golden_runtime_shape_fold_seal.rs"]
mod golden_runtime_shape_fold_seal;
