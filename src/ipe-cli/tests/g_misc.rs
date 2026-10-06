//! Consolidated golden binary for the `misc` theme.
//! Each `mod` below is one original `golden_*.rs`; test identity is
//! preserved as `<module>::<fn>`. Merged to cut per-file link cost.

mod support;

#[path = "g_misc/golden_alias.rs"]
mod golden_alias;
#[path = "g_misc/golden_alias_move_seal.rs"]
mod golden_alias_move_seal;
#[path = "g_misc/golden_aliases.rs"]
mod golden_aliases;
#[path = "g_misc/golden_ambiguous_kernel_turbofish.rs"]
mod golden_ambiguous_kernel_turbofish;
#[path = "g_misc/golden_analytics_consent_gate.rs"]
mod golden_analytics_consent_gate;
#[path = "g_misc/golden_analytics_store_gate.rs"]
mod golden_analytics_store_gate;
#[path = "g_misc/golden_any_ctor_payload.rs"]
mod golden_any_ctor_payload;
#[path = "g_misc/golden_attribute_home_disambiguation_179.rs"]
mod golden_attribute_home_disambiguation_179;
#[path = "g_misc/golden_aud14_duplicate_qualifier.rs"]
mod golden_aud14_duplicate_qualifier;
#[path = "g_misc/golden_bare_ui_arity_fill.rs"]
mod golden_bare_ui_arity_fill;
#[path = "g_misc/golden_basics.rs"]
mod golden_basics;
#[path = "g_misc/golden_cache_handle_seal.rs"]
mod golden_cache_handle_seal;
#[path = "g_misc/golden_cache_handle_task_reuse.rs"]
mod golden_cache_handle_task_reuse;
#[path = "g_misc/golden_cache_int_get.rs"]
mod golden_cache_int_get;
#[path = "g_misc/golden_cache_module_seal.rs"]
mod golden_cache_module_seal;
#[path = "g_misc/golden_cli_program_seal.rs"]
mod golden_cli_program_seal;
#[path = "g_misc/golden_cmd_sub_map.rs"]
mod golden_cmd_sub_map;
#[path = "g_misc/golden_core_stdlib.rs"]
mod golden_core_stdlib;
#[path = "g_misc/golden_cross_module_attr_field_access.rs"]
mod golden_cross_module_attr_field_access;
#[path = "g_misc/golden_cross_module_attr_field_mismatch.rs"]
mod golden_cross_module_attr_field_mismatch;
#[path = "g_misc/golden_cross_module_attr_lowering.rs"]
mod golden_cross_module_attr_lowering;
#[path = "g_misc/golden_cross_module_type_res.rs"]
mod golden_cross_module_type_res;
#[path = "g_misc/golden_custom_maybe_adt.rs"]
mod golden_custom_maybe_adt;
#[path = "g_misc/golden_destructure_move_ownership.rs"]
mod golden_destructure_move_ownership;
#[path = "g_misc/golden_email_send_composed_lowers.rs"]
mod golden_email_send_composed_lowers;
#[path = "g_misc/golden_email_send_nominal_fold_seal.rs"]
mod golden_email_send_nominal_fold_seal;
#[path = "g_misc/golden_enum_fn_payload_reuse_seal.rs"]
mod golden_enum_fn_payload_reuse_seal;
#[path = "g_misc/golden_enum_payload_nonclone_seal.rs"]
mod golden_enum_payload_nonclone_seal;
#[path = "g_misc/golden_ffi_kernel_alias_seal.rs"]
mod golden_ffi_kernel_alias_seal;
#[path = "g_misc/golden_ffi_nonclone_handle_reuse_seal.rs"]
mod golden_ffi_nonclone_handle_reuse_seal;
#[path = "g_misc/golden_harness_coverage.rs"]
mod golden_harness_coverage;
#[path = "g_misc/golden_http_statuscode_imagesrc_seal.rs"]
mod golden_http_statuscode_imagesrc_seal;
#[path = "g_misc/golden_if_expr.rs"]
mod golden_if_expr;
#[path = "g_misc/golden_l0105_refutable_gates.rs"]
mod golden_l0105_refutable_gates;
#[path = "g_misc/golden_lambda_field_access_seal.rs"]
mod golden_lambda_field_access_seal;
#[path = "g_misc/golden_lazy_emit_seal.rs"]
mod golden_lazy_emit_seal;
#[path = "g_misc/golden_local_type_shadows_dep.rs"]
mod golden_local_type_shadows_dep;
#[path = "g_misc/golden_money_parse_currency_maybe.rs"]
mod golden_money_parse_currency_maybe;
#[path = "g_misc/golden_multi_instantiation.rs"]
mod golden_multi_instantiation;
#[path = "g_misc/golden_multi_mod_split_pilot.rs"]
mod golden_multi_mod_split_pilot;
#[path = "g_misc/golden_parametric_aliases.rs"]
mod golden_parametric_aliases;
#[path = "g_misc/golden_parser_gaps.rs"]
mod golden_parser_gaps;
#[path = "g_misc/golden_phantom_binder_reuse.rs"]
mod golden_phantom_binder_reuse;
#[path = "g_misc/golden_region_seal.rs"]
mod golden_region_seal;
#[path = "g_misc/golden_secret.rs"]
mod golden_secret;
#[path = "g_misc/golden_session_replay_seal.rs"]
mod golden_session_replay_seal;
#[path = "g_misc/golden_show_policy.rs"]
mod golden_show_policy;
#[path = "g_misc/golden_static_bound.rs"]
mod golden_static_bound;
#[path = "g_misc/golden_stdlib_module_seal.rs"]
mod golden_stdlib_module_seal;
#[path = "g_misc/golden_test_summary_line_219.rs"]
mod golden_test_summary_line_219;
#[path = "g_misc/golden_time_format_arith.rs"]
mod golden_time_format_arith;
#[path = "g_misc/golden_time_from_to_millis.rs"]
mod golden_time_from_to_millis;
#[path = "g_misc/golden_timestamp_arithmetic.rs"]
mod golden_timestamp_arithmetic;
#[path = "g_misc/golden_timestamp_seal.rs"]
mod golden_timestamp_seal;
#[path = "g_misc/golden_timestamp_type_safety.rs"]
mod golden_timestamp_type_safety;
#[path = "g_misc/golden_tree.rs"]
mod golden_tree;
#[path = "g_misc/golden_typed_primitives_seal.rs"]
mod golden_typed_primitives_seal;
#[path = "g_misc/golden_unit_pattern.rs"]
mod golden_unit_pattern;
#[path = "g_misc/golden_unit_pattern_match.rs"]
mod golden_unit_pattern_match;
#[path = "g_misc/golden_update_base_after_move.rs"]
mod golden_update_base_after_move;
#[path = "g_misc/golden_url_scheme_seal.rs"]
mod golden_url_scheme_seal;
