//! Consolidated golden binary for the `issues` theme.
//! Each `mod` below is one original `golden_*.rs`; test identity is
//! preserved as `<module>::<fn>`. Merged to cut per-file link cost.

mod support;

#[path = "g_issues/golden_cross_module_chained_msg_slot_seal.rs"]
mod golden_cross_module_chained_msg_slot_seal;
#[path = "g_issues/golden_embed_fn_param_capture_seal.rs"]
mod golden_embed_fn_param_capture_seal;
#[path = "g_issues/golden_generic_carrier_send_seal.rs"]
mod golden_generic_carrier_send_seal;
#[path = "g_issues/golden_generic_msg_forward_sync_seal.rs"]
mod golden_generic_msg_forward_sync_seal;
#[path = "g_issues/golden_generic_msg_input_sync_seal.rs"]
mod golden_generic_msg_input_sync_seal;
#[path = "g_issues/golden_generic_return_only_sync_seal.rs"]
mod golden_generic_return_only_sync_seal;
#[path = "g_issues/golden_generic_succeed_tail_sync_seal.rs"]
mod golden_generic_succeed_tail_sync_seal;
#[path = "g_issues/golden_i1005_generic_capture_append_seal.rs"]
mod golden_i1005_generic_capture_append_seal;
#[path = "g_issues/golden_i1005_generic_capture_tuple_cons_seal.rs"]
mod golden_i1005_generic_capture_tuple_cons_seal;
#[path = "g_issues/golden_i1005_store_list_query_seal.rs"]
mod golden_i1005_store_list_query_seal;
#[path = "g_issues/golden_i101_color_seal.rs"]
mod golden_i101_color_seal;
#[path = "g_issues/golden_i104_seal.rs"]
mod golden_i104_seal;
#[path = "g_issues/golden_i1139_fn_field_record_literal.rs"]
mod golden_i1139_fn_field_record_literal;
#[path = "g_issues/golden_i119_list_batch_seal.rs"]
mod golden_i119_list_batch_seal;
#[path = "g_issues/golden_i121_curried_seal.rs"]
mod golden_i121_curried_seal;
#[path = "g_issues/golden_i122_cli_program_separator.rs"]
mod golden_i122_cli_program_separator;
#[path = "g_issues/golden_i1230_store_migrations_producer.rs"]
mod golden_i1230_store_migrations_producer;
#[path = "g_issues/golden_i1255_pointfree_store_kernel_seal.rs"]
mod golden_i1255_pointfree_store_kernel_seal;
#[path = "g_issues/golden_i125_decoder_destructure_thunk.rs"]
mod golden_i125_decoder_destructure_thunk;
#[path = "g_issues/golden_i1309_polymorphic_msg_helper_seal.rs"]
mod golden_i1309_polymorphic_msg_helper_seal;
#[path = "g_issues/golden_i1309_unconstrained_msg_defaulting_seal.rs"]
mod golden_i1309_unconstrained_msg_defaulting_seal;
#[path = "g_issues/golden_i130_seal.rs"]
mod golden_i130_seal;
#[path = "g_issues/golden_i1329_server_view_msg_defaulting_seal.rs"]
mod golden_i1329_server_view_msg_defaulting_seal;
#[path = "g_issues/golden_i1338_cross_module_msg_polymorphic_helper_seal.rs"]
mod golden_i1338_cross_module_msg_polymorphic_helper_seal;
#[path = "g_issues/golden_i1338_unannotated_view_arg_msg_defaulting_seal.rs"]
mod golden_i1338_unannotated_view_arg_msg_defaulting_seal;
#[path = "g_issues/golden_i1347_cross_module_monomorphic_view_msg_defaulting_seal.rs"]
mod golden_i1347_cross_module_monomorphic_view_msg_defaulting_seal;
#[path = "g_issues/golden_i1347_cross_module_unpinned_view_msg_defaulting_seal.rs"]
mod golden_i1347_cross_module_unpinned_view_msg_defaulting_seal;
#[path = "g_issues/golden_i1353_generic_view_helper_body_msg_tvar_seal.rs"]
mod golden_i1353_generic_view_helper_body_msg_tvar_seal;
#[path = "g_issues/golden_i136_alias_truncation.rs"]
mod golden_i136_alias_truncation;
#[path = "g_issues/golden_i138_total_resolution.rs"]
mod golden_i138_total_resolution;
#[path = "g_issues/golden_i1421_backoff_strategy_adt.rs"]
mod golden_i1421_backoff_strategy_adt;
#[path = "g_issues/golden_i142_access_copy_elision.rs"]
mod golden_i142_access_copy_elision;
#[path = "g_issues/golden_i147_ctor_as_fn_seal.rs"]
mod golden_i147_ctor_as_fn_seal;
#[path = "g_issues/golden_i151_nested_let_fn.rs"]
mod golden_i151_nested_let_fn;
#[path = "g_issues/golden_i172_mixed_arc_box_handler.rs"]
mod golden_i172_mixed_arc_box_handler;
#[path = "g_issues/golden_i178_fn_composite_reuse.rs"]
mod golden_i178_fn_composite_reuse;
#[path = "g_issues/golden_i217_stdlib_contract_drift.rs"]
mod golden_i217_stdlib_contract_drift;
#[path = "g_issues/golden_i221_fn_value_carrier.rs"]
mod golden_i221_fn_value_carrier;
#[path = "g_issues/golden_i3320_task_loop.rs"]
mod golden_i3320_task_loop;
#[path = "g_issues/golden_i3332_stored_fn_kernel_args.rs"]
mod golden_i3332_stored_fn_kernel_args;
#[path = "g_issues/golden_i663_codec_combinators.rs"]
mod golden_i663_codec_combinators;
#[path = "g_issues/golden_i665_retry_policy_value_callee.rs"]
mod golden_i665_retry_policy_value_callee;
#[path = "g_issues/golden_i672_random_members.rs"]
mod golden_i672_random_members;
#[path = "g_issues/golden_i789_record_fn_carrier.rs"]
mod golden_i789_record_fn_carrier;
#[path = "g_issues/golden_i793_record_fn_read.rs"]
mod golden_i793_record_fn_read;
#[path = "g_issues/golden_i798_generic_combinator_seal.rs"]
mod golden_i798_generic_combinator_seal;
#[path = "g_issues/golden_i799_gate_relaxation.rs"]
mod golden_i799_gate_relaxation;
#[path = "g_issues/golden_i801_decoder_storage_reuse.rs"]
mod golden_i801_decoder_storage_reuse;
#[path = "g_issues/golden_i802_generic_optional_sync.rs"]
mod golden_i802_generic_optional_sync;
#[path = "g_issues/golden_i807_codec_enum_taggedunion.rs"]
mod golden_i807_codec_enum_taggedunion;
#[path = "g_issues/golden_i825_generic_decoder_send.rs"]
mod golden_i825_generic_decoder_send;
#[path = "g_issues/golden_i858_update_base_nonclone_reuse_seal.rs"]
mod golden_i858_update_base_nonclone_reuse_seal;
#[path = "g_issues/golden_i963_retry_policy_field_access_ice.rs"]
mod golden_i963_retry_policy_field_access_ice;
#[path = "g_issues/golden_i979_retry_policy_exact_shape_user_record.rs"]
mod golden_i979_retry_policy_exact_shape_user_record;
#[path = "g_issues/golden_i981_fn_value_move_then_call.rs"]
mod golden_i981_fn_value_move_then_call;
#[path = "g_issues/golden_i984_cons_fn_value_arc_carrier.rs"]
mod golden_i984_cons_fn_value_arc_carrier;
#[path = "g_issues/golden_i99_alias_match_arm.rs"]
mod golden_i99_alias_match_arm;
#[path = "g_issues/golden_l0135_access_base_move_seal.rs"]
mod golden_l0135_access_base_move_seal;
#[path = "g_issues/golden_l0135_consume_then_borrow_seal.rs"]
mod golden_l0135_consume_then_borrow_seal;
#[path = "g_issues/golden_l0135_effect_field_move_seal.rs"]
mod golden_l0135_effect_field_move_seal;
#[path = "g_issues/golden_l0135_union_task_reuse_seal.rs"]
mod golden_l0135_union_task_reuse_seal;
#[path = "g_issues/golden_shared_msg_class_seal.rs"]
mod golden_shared_msg_class_seal;
#[path = "g_issues/golden_stream_handler_capture_seal.rs"]
mod golden_stream_handler_capture_seal;
#[path = "g_issues/golden_swapped_container_capture_seal.rs"]
mod golden_swapped_container_capture_seal;
#[path = "g_issues/golden_swapped_effect_capture_seal.rs"]
mod golden_swapped_effect_capture_seal;
#[path = "g_issues/golden_unannotated_value_sync_seal.rs"]
mod golden_unannotated_value_sync_seal;
#[path = "g_issues/golden_untyped_app_entry_row_seal.rs"]
mod golden_untyped_app_entry_row_seal;
