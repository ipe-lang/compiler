//! Consolidated golden binary for the `fn_pattern` theme.
//! Each `mod` below is one original `golden_*.rs`; test identity is
//! preserved as `<module>::<fn>`. Merged to cut per-file link cost.

mod support;

#[path = "g_fn_pattern/golden_asymmetric_arms_cloneok.rs"]
mod golden_asymmetric_arms_cloneok;
#[path = "g_fn_pattern/golden_aud04_emit_expr_ir_capture.rs"]
mod golden_aud04_emit_expr_ir_capture;
#[path = "g_fn_pattern/golden_aud08_function_name_collision.rs"]
mod golden_aud08_function_name_collision;
#[path = "g_fn_pattern/golden_boundary_scheme_field_result.rs"]
mod golden_boundary_scheme_field_result;
#[path = "g_fn_pattern/golden_clone_relay_intermediate_eta.rs"]
mod golden_clone_relay_intermediate_eta;
#[path = "g_fn_pattern/golden_config_decoder_combinators.rs"]
mod golden_config_decoder_combinators;
#[path = "g_fn_pattern/golden_cross_module_poly_recursion.rs"]
mod golden_cross_module_poly_recursion;
#[path = "g_fn_pattern/golden_decoder_payload_mapper.rs"]
mod golden_decoder_payload_mapper;
#[path = "g_fn_pattern/golden_depth0_no_overclone.rs"]
mod golden_depth0_no_overclone;
#[path = "g_fn_pattern/golden_error_adt_roundtrip.rs"]
mod golden_error_adt_roundtrip;
#[path = "g_fn_pattern/golden_error_details_roundtrip.rs"]
mod golden_error_details_roundtrip;
#[path = "g_fn_pattern/golden_error_expect_err_288.rs"]
mod golden_error_expect_err_288;
#[path = "g_fn_pattern/golden_error_nominal_payload.rs"]
mod golden_error_nominal_payload;
#[path = "g_fn_pattern/golden_eta_inline_arg_capture.rs"]
mod golden_eta_inline_arg_capture;
#[path = "g_fn_pattern/golden_eta_once_closure.rs"]
mod golden_eta_once_closure;
#[path = "g_fn_pattern/golden_firstclass.rs"]
mod golden_firstclass;
#[path = "g_fn_pattern/golden_fn_capture_boundary.rs"]
mod golden_fn_capture_boundary;
#[path = "g_fn_pattern/golden_fn_enum_payload.rs"]
mod golden_fn_enum_payload;
#[path = "g_fn_pattern/golden_fn_pattern_binder_forward.rs"]
mod golden_fn_pattern_binder_forward;
#[path = "g_fn_pattern/golden_fn_record_field.rs"]
mod golden_fn_record_field;
#[path = "g_fn_pattern/golden_fn_record_nested_transitive.rs"]
mod golden_fn_record_nested_transitive;
#[path = "g_fn_pattern/golden_fn_value_reify_typevar.rs"]
mod golden_fn_value_reify_typevar;
#[path = "g_fn_pattern/golden_fn_value_return_reify_typevar.rs"]
mod golden_fn_value_return_reify_typevar;
#[path = "g_fn_pattern/golden_function_field_gate.rs"]
mod golden_function_field_gate;
#[path = "g_fn_pattern/golden_function_payload_gate.rs"]
mod golden_function_payload_gate;
#[path = "g_fn_pattern/golden_json_decode_nullable.rs"]
mod golden_json_decode_nullable;
#[path = "g_fn_pattern/golden_json_decode_pipeline.rs"]
mod golden_json_decode_pipeline;
#[path = "g_fn_pattern/golden_lambdas.rs"]
mod golden_lambdas;
#[path = "g_fn_pattern/golden_let_destructure.rs"]
mod golden_let_destructure;
#[path = "g_fn_pattern/golden_let_in.rs"]
mod golden_let_in;
#[path = "g_fn_pattern/golden_match_arm_clone_relay.rs"]
mod golden_match_arm_clone_relay;
#[path = "g_fn_pattern/golden_mixed_arm_task_run_elision_seal.rs"]
mod golden_mixed_arm_task_run_elision_seal;
#[path = "g_fn_pattern/golden_mutual_recursion.rs"]
mod golden_mutual_recursion;
#[path = "g_fn_pattern/golden_nested.rs"]
mod golden_nested;
#[path = "g_fn_pattern/golden_nested_capture_outer_arg.rs"]
mod golden_nested_capture_outer_arg;
#[path = "g_fn_pattern/golden_nested_lambda.rs"]
mod golden_nested_lambda;
#[path = "g_fn_pattern/golden_noncl_var_hof.rs"]
mod golden_noncl_var_hof;
#[path = "g_fn_pattern/golden_nonclone_fn_once_per_arm.rs"]
mod golden_nonclone_fn_once_per_arm;
#[path = "g_fn_pattern/golden_oninput_reused_capture.rs"]
mod golden_oninput_reused_capture;
#[path = "g_fn_pattern/golden_partial.rs"]
mod golden_partial;
#[path = "g_fn_pattern/golden_partial_app.rs"]
mod golden_partial_app;
#[path = "g_fn_pattern/golden_poly_task_on_error_nested.rs"]
mod golden_poly_task_on_error_nested;
#[path = "g_fn_pattern/golden_result_bridges.rs"]
mod golden_result_bridges;
#[path = "g_fn_pattern/golden_task_attempt.rs"]
mod golden_task_attempt;
#[path = "g_fn_pattern/golden_taskseq_reuse.rs"]
mod golden_taskseq_reuse;
#[path = "g_fn_pattern/golden_url_parser_combinators.rs"]
mod golden_url_parser_combinators;
#[path = "g_fn_pattern/golden_wildcard_lambda_pany.rs"]
mod golden_wildcard_lambda_pany;
