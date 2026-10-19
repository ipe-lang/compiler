//! Consolidated golden binary for the `http_live` theme.
//! Each `mod` below is one original `golden_*.rs`; test identity is
//! preserved as `<module>::<fn>`. Merged to cut per-file link cost.

mod support;

#[path = "g_http_live/golden_http_builders_redirects.rs"]
mod golden_http_builders_redirects;
#[path = "g_http_live/golden_http_request_name_only_fold_seal.rs"]
mod golden_http_request_name_only_fold_seal;
#[path = "g_http_live/golden_http_stream_id.rs"]
mod golden_http_stream_id;
#[path = "g_http_live/golden_i180_prescriptive_init_livereq.rs"]
mod golden_i180_prescriptive_init_livereq;
#[path = "g_http_live/golden_l0114_ctor_payload_function.rs"]
mod golden_l0114_ctor_payload_function;
#[path = "g_http_live/golden_l0114_server_handler_arc.rs"]
mod golden_l0114_server_handler_arc;
#[path = "g_http_live/golden_live_let_bound_routes.rs"]
mod golden_live_let_bound_routes;
#[path = "g_http_live/golden_live_on_navigate.rs"]
mod golden_live_on_navigate;
#[path = "g_http_live/golden_live_param_routes.rs"]
mod golden_live_param_routes;
#[path = "g_http_live/golden_m6_server.rs"]
mod golden_m6_server;
#[path = "g_http_live/golden_m7_live_lambda_view_routed.rs"]
mod golden_m7_live_lambda_view_routed;
#[path = "g_http_live/golden_m7_live_routed_empty_routes.rs"]
mod golden_m7_live_routed_empty_routes;
#[path = "g_http_live/golden_middleware_csrf.rs"]
mod golden_middleware_csrf;
#[path = "g_http_live/golden_t0020_web_view_html.rs"]
mod golden_t0020_web_view_html;
