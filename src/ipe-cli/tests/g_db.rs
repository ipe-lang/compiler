//! Consolidated golden binary for the `db` theme.
//! Each `mod` below is one original `golden_*.rs`; test identity is
//! preserved as `<module>::<fn>`. Merged to cut per-file link cost.

mod support;

#[path = "g_db/golden_app_settings_front_door.rs"]
mod golden_app_settings_front_door;
#[path = "g_db/golden_authed_store_query_seal.rs"]
mod golden_authed_store_query_seal;
#[path = "g_db/golden_db_get_alias_row.rs"]
mod golden_db_get_alias_row;
#[path = "g_db/golden_db_get_iperow_bound.rs"]
mod golden_db_get_iperow_bound;
#[path = "g_db/golden_db_store_accessor_leaves.rs"]
mod golden_db_store_accessor_leaves;
#[path = "g_db/golden_db_store_composite_pk.rs"]
mod golden_db_store_composite_pk;
#[path = "g_db/golden_db_store_cond_composed_lowers.rs"]
mod golden_db_store_cond_composed_lowers;
#[path = "g_db/golden_db_store_draft_query_rejected.rs"]
mod golden_db_store_draft_query_rejected;
#[path = "g_db/golden_db_store_immutable_update_seal.rs"]
mod golden_db_store_immutable_update_seal;
#[path = "g_db/golden_db_store_index_seal.rs"]
mod golden_db_store_index_seal;
#[path = "g_db/golden_db_store_insert_if_absent_seal.rs"]
mod golden_db_store_insert_if_absent_seal;
#[path = "g_db/golden_db_store_insert_returning_seal.rs"]
mod golden_db_store_insert_returning_seal;
#[path = "g_db/golden_db_store_join_seal.rs"]
mod golden_db_store_join_seal;
#[path = "g_db/golden_db_store_order_by_seal.rs"]
mod golden_db_store_order_by_seal;
#[path = "g_db/golden_db_store_placeholder_off_intercept.rs"]
mod golden_db_store_placeholder_off_intercept;
#[path = "g_db/golden_db_store_policy_algebra.rs"]
mod golden_db_store_policy_algebra;
#[path = "g_db/golden_db_store_projection_arith_seal.rs"]
mod golden_db_store_projection_arith_seal;
#[path = "g_db/golden_db_store_projection_coalesce_seal.rs"]
mod golden_db_store_projection_coalesce_seal;
#[path = "g_db/golden_db_store_projection_literal_seal.rs"]
mod golden_db_store_projection_literal_seal;
#[path = "g_db/golden_db_store_projection_multicol_seal.rs"]
mod golden_db_store_projection_multicol_seal;
#[path = "g_db/golden_db_store_projection_rejections.rs"]
mod golden_db_store_projection_rejections;
#[path = "g_db/golden_db_store_projection_seal.rs"]
mod golden_db_store_projection_seal;
#[path = "g_db/golden_db_store_projection_upper_lower_seal.rs"]
mod golden_db_store_projection_upper_lower_seal;
#[path = "g_db/golden_db_store_rename_column.rs"]
mod golden_db_store_rename_column;
#[path = "g_db/golden_db_store_rls_composition_builders_seal.rs"]
mod golden_db_store_rls_composition_builders_seal;
#[path = "g_db/golden_db_store_upsert.rs"]
mod golden_db_store_upsert;
#[path = "g_db/golden_db_wrapper_empty_params_165.rs"]
mod golden_db_wrapper_empty_params_165;
#[path = "g_db/golden_i177_db_get_false_positive.rs"]
mod golden_i177_db_get_false_positive;
#[path = "g_db/golden_m5b_db.rs"]
mod golden_m5b_db;
#[path = "g_db/golden_m5b_db_gates.rs"]
mod golden_m5b_db_gates;
#[path = "g_db/golden_m5b_http.rs"]
mod golden_m5b_http;
#[path = "g_db/golden_m5b_uuid_jwt.rs"]
mod golden_m5b_uuid_jwt;
#[path = "g_db/golden_store_ident_parity.rs"]
mod golden_store_ident_parity;
