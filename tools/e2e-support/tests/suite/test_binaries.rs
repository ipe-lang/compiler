//! The ratchet that bounds the workspace's test binaries.
//!
//! Every test binary statically links its crate's whole dependency graph, so
//! the number of test targets is the number of link outputs a CI job must
//! hold. That number is an exact committed list, [`TEST_BINARIES`], and every
//! entry carries a [`Reason`] this module checks against the tree:
//!
//! - **R1** — the live set of `cargo metadata` test targets equals the list;
//!   each reason holds; each crate's count of [`Reason::Unconsolidated`]
//!   entries equals its row in [`UNCONSOLIDATED_CEILINGS`].
//! - **R2** — every `.rs` file under a crate's `tests/` is reached by exactly
//!   one target's module graph, except files under [`TEST_DATA_DIRS`] and the
//!   [`SHARED_MODULES`], which hold no test of their own.
//! - **R3** — every `--test <name>`, `binary(<name>)` and harness-module
//!   filter in the CI and nextest configuration names a live target or
//!   module; `cargo test` never runs an area harness; no file below a
//!   harness root carries a crate-only inner attribute.
//! - **R4** — every `src/…/tests/….rs` or `tools/…/tests/….rs` path in the
//!   workspace's Rust, Python and shell sources names a file that exists,
//!   except the exact pairs in [`SYNTHETIC_PATHS`].
//! - **R5** — `set_current_dir` occurs only in a target whose reason is
//!   [`Reason::ProcessGlobalState`].
//!
//! Every check is a pure function over a [`Model`] of the tree and the
//! configuration texts, so each refusal is driven by a planted case below and
//! the live tree is checked by the same functions.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::common;

/// Why a test target is its own binary rather than a module of a harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    /// The target is a harness: its root is `tests/<name>/main.rs`, or a
    /// `tests/g_*.rs` golden root.
    AreaHarness,
    /// A CI command or script runs it alone: `--test <name>` or
    /// `binary(<name>)` in a workflow, `check-manifest.yml` or
    /// `tools/scripts`.
    DedicatedJob,
    /// A workflow line runs it with `--target wasm32-…` and `--test <name>`.
    ForeignTarget,
    /// Its module graph calls `set_current_dir`, a process-global mutation
    /// that cannot share a process with unrelated tests under `cargo test`.
    ProcessGlobalState,
    /// Not yet moved into a harness; bounded by its crate's row in
    /// [`UNCONSOLIDATED_CEILINGS`].
    Unconsolidated,
}

/// The identifier R5 confines.
const CWD_IDENT: &str = "set_current_dir";

/// The inner attributes that apply only at a crate root: below a harness
/// root they either fail to compile or silently change the whole harness.
const CRATE_ONLY_ATTRS: &[&str] = &[
    "crate_name",
    "crate_type",
    "feature",
    "no_main",
    "no_std",
    "recursion_limit",
    "test_runner",
    "type_length_limit",
    "windows_subsystem",
];

/// This file, which names the synthetic literals of [`SYNTHETIC_PATHS`] and
/// so is outside R4.
const SELF: &str = "tools/e2e-support/tests/suite/test_binaries.rs";

/// The fixed configuration files R3 reads, besides every workflow and every
/// file under `tools/scripts`.
const FILTER_FILES: &[&str] = &[
    ".config/nextest.toml",
    ".github/ci/check-manifest.yml",
    ".github/ci/e2e_shard.py",
    ".github/ci/e2e-shard-times.txt",
];

/// Directories under a crate's `tests/` whose `.rs` files are data a test
/// reads, never compiled as part of any target.
const TEST_DATA_DIRS: &[&str] = &[
    "src/runtime/rust/tests/data/",
    "src/runtime/rust/tests/fixtures/",
    "tools/e2e-support/tests/fixtures/",
];

/// Support modules reached by more than one target. Each holds no test of
/// its own, so sharing it never runs one test twice.
const SHARED_MODULES: &[&str] = &[
    "src/compiler/backend/rust/tests/seal_e2e/mod.rs",
    "src/compiler/kernels/tests/veneer_helpers.rs",
    "src/ipe-cli/tests/parity_shards/mod.rs",
    "src/ipe-cli/tests/support/mod.rs",
    "src/runtime/rust/tests/support/cfg_scan.rs",
    "src/runtime/rust/tests/support/format_width.rs",
    "src/runtime/rust/tests/support/source_tree.rs",
];

/// `(file, literal)` pairs whose test-file path is invented on purpose: a
/// fixture asserting how a path is classified, never a file to read.
const SYNTHETIC_PATHS: &[(&str, &str)] = &[
    (".github/ci/test_local_gate.py", "src/cli/tests/ssot.rs"),
    (".github/ci/test_local_gate.py", "src/core/tests/paths.rs"),
    (
        ".github/ci/test_trust_roots.py",
        "src/ipe-cli/tests/g_db/x.rs",
    ),
    (
        ".github/ci/test_trust_roots.py",
        "src/ipe-cli/tests/golden_x.rs",
    ),
    (
        "src/ipe-cli/tests/env_read_scan.rs",
        "tools/gated/tests/mod.rs",
    ),
    (
        "src/ipe-cli/tests/home_read_scan.rs",
        "src/compiler/db/tests/planted.rs",
    ),
    (
        "src/ipe-cli/tests/lsp_degraded_scan.rs",
        "src/compiler/db/tests/differential.rs",
    ),
    (
        "src/ipe-cli/tests/lsp_degraded_scan.rs",
        "src/lsp/features/tests/hover.rs",
    ),
    (
        "tools/ipe-index/src/model.rs",
        "src/compiler/parse/tests/lex.rs",
    ),
    ("tools/panic-scan/src/manifest.rs", "src/../tests/main.rs"),
    ("tools/panic-scan/src/test_path.rs", "src/bin/tests/main.rs"),
    (
        "tools/panic-scan/src/test_path.rs",
        "src/driver/tests/mod.rs",
    ),
    (
        "tools/panic-scan/src/test_path.rs",
        "src/driver/tests/nested/deep.rs",
    ),
    (
        "tools/panic-scan/src/test_path.rs",
        "src/ipe-cli/tests/cli.rs",
    ),
];

/// Per crate, how many [`TEST_BINARIES`] entries are
/// [`Reason::Unconsolidated`]. A row may only equal the live count, so moving
/// a target into a harness lowers it and adding one cannot raise it unseen.
const UNCONSOLIDATED_CEILINGS: &[(&str, usize)] = &[
    ("ipe", 140),
    ("ipe-runtime-rust", 44),
    ("ipe_backend_rust", 35),
    ("ipe_bindgen", 1),
    ("ipe_canon", 8),
    ("ipe_db", 15),
    ("ipe_diagnostics", 2),
    ("ipe_docs", 3),
    ("ipe_ffi", 16),
    ("ipe_fmt", 5),
    ("ipe_fs_open", 1),
    ("ipe_ir", 2),
    ("ipe_kernels", 6),
    ("ipe_lower", 4),
    ("ipe_lsp_features", 6),
    ("ipe_lsp_server", 2),
    ("ipe_parse", 1),
    ("ipe_sandbox", 7),
    ("ipe_stdlib", 1),
    ("ipe_types", 2),
    ("ipe_wrapper", 1),
    ("panic-scan", 2),
    ("playground-jail-runner", 1),
];

/// Every test target of the workspace: `(package, target, reason)`.
const TEST_BINARIES: &[(&str, &str, Reason)] = &[
    ("e2e-support", "suite", Reason::AreaHarness),
    ("ipe", "add_resolve", Reason::Unconsolidated),
    (
        "ipe",
        "adversarial_review_parity_probe",
        Reason::Unconsolidated,
    ),
    ("ipe", "adversarial_scan_gap_cycle", Reason::Unconsolidated),
    ("ipe", "analysis_root_forms", Reason::Unconsolidated),
    ("ipe", "argv_decode_scan", Reason::Unconsolidated),
    ("ipe", "argv_non_utf8", Reason::Unconsolidated),
    ("ipe", "audit_native", Reason::DedicatedJob),
    ("ipe", "build_artifact_copy", Reason::Unconsolidated),
    ("ipe", "build_no_arg", Reason::ProcessGlobalState),
    (
        "ipe",
        "build_propagates_cargo_failure",
        Reason::Unconsolidated,
    ),
    ("ipe", "build_registry_unreachable", Reason::Unconsolidated),
    (
        "ipe",
        "build_streams_cargo_progress",
        Reason::Unconsolidated,
    ),
    ("ipe", "capabilities", Reason::Unconsolidated),
    ("ipe", "capability_inference", Reason::Unconsolidated),
    ("ipe", "cargo_step_scan", Reason::Unconsolidated),
    ("ipe", "child_runner_scan", Reason::Unconsolidated),
    ("ipe", "clean_vs_incremental_parity", Reason::Unconsolidated),
    ("ipe", "cli_arg_combinations", Reason::Unconsolidated),
    ("ipe", "cli_output_conformance", Reason::Unconsolidated),
    ("ipe", "cli_output_format", Reason::Unconsolidated),
    ("ipe", "cli_surface_coverage_matrix", Reason::Unconsolidated),
    ("ipe", "cli_transcripts", Reason::Unconsolidated),
    ("ipe", "color_e2e", Reason::Unconsolidated),
    ("ipe", "compiler_coverage_matrix", Reason::Unconsolidated),
    ("ipe", "composed_hof_combinators", Reason::Unconsolidated),
    ("ipe", "db_connection_readonly_seal", Reason::Unconsolidated),
    ("ipe", "db_location_e2e", Reason::Unconsolidated),
    ("ipe", "db_unsafe_exec_raw_marker", Reason::Unconsolidated),
    ("ipe", "db_unsafe_row_read_marker", Reason::Unconsolidated),
    ("ipe", "deep_binop_chain", Reason::Unconsolidated),
    ("ipe", "deep_do_task_bind", Reason::Unconsolidated),
    ("ipe", "dependency_refused", Reason::Unconsolidated),
    ("ipe", "diagnostic_coverage_matrix", Reason::Unconsolidated),
    ("ipe", "diagnostic_json", Reason::Unconsolidated),
    ("ipe", "diff_api_surface", Reason::Unconsolidated),
    ("ipe", "diff_classification", Reason::Unconsolidated),
    ("ipe", "diff_cli", Reason::Unconsolidated),
    ("ipe", "doc_subcommand", Reason::Unconsolidated),
    ("ipe", "e2e_scratch_dir_scan", Reason::Unconsolidated),
    ("ipe", "elm_coverage_additions", Reason::Unconsolidated),
    ("ipe", "emit_settings_paths", Reason::Unconsolidated),
    ("ipe", "emit_settings_scan", Reason::Unconsolidated),
    ("ipe", "emitted_cargo_build_scan", Reason::Unconsolidated),
    ("ipe", "env_read_scan", Reason::Unconsolidated),
    ("ipe", "env_startup_refusal", Reason::Unconsolidated),
    ("ipe", "env_var_coverage_matrix", Reason::Unconsolidated),
    ("ipe", "error_kind_agreement", Reason::Unconsolidated),
    ("ipe", "error_record_literal_gates", Reason::Unconsolidated),
    ("ipe", "explain_examples", Reason::DedicatedJob),
    ("ipe", "ffi_byte_narrow_parity", Reason::Unconsolidated),
    ("ipe", "ffi_cache_path_scan", Reason::Unconsolidated),
    ("ipe", "ffi_seq_narrow_parity", Reason::Unconsolidated),
    ("ipe", "fmt", Reason::Unconsolidated),
    (
        "ipe",
        "foreign_surface_coverage_matrix",
        Reason::Unconsolidated,
    ),
    ("ipe", "format_width_scan", Reason::Unconsolidated),
    ("ipe", "fuzz_templates", Reason::DedicatedJob),
    ("ipe", "g_core_data", Reason::AreaHarness),
    ("ipe", "g_db", Reason::AreaHarness),
    ("ipe", "g_fn_pattern", Reason::AreaHarness),
    ("ipe", "g_http_live", Reason::AreaHarness),
    ("ipe", "g_issues", Reason::AreaHarness),
    ("ipe", "g_m4", Reason::AreaHarness),
    ("ipe", "g_m5", Reason::AreaHarness),
    ("ipe", "g_m_early", Reason::AreaHarness),
    ("ipe", "g_misc", Reason::AreaHarness),
    ("ipe", "g_record_generic", Reason::AreaHarness),
    ("ipe", "g_stdui", Reason::AreaHarness),
    ("ipe", "g_tuple", Reason::AreaHarness),
    (
        "ipe",
        "golden_ffi_asserted_call_seal",
        Reason::Unconsolidated,
    ),
    (
        "ipe",
        "golden_ffi_define_transparency_seal",
        Reason::Unconsolidated,
    ),
    ("ipe", "golden_ffi_rust_fn_seal", Reason::Unconsolidated),
    (
        "ipe",
        "golden_ffi_transparent_import_seal",
        Reason::Unconsolidated,
    ),
    (
        "ipe",
        "golden_ffi_unlexable_name_seal",
        Reason::Unconsolidated,
    ),
    ("ipe", "help_output", Reason::Unconsolidated),
    ("ipe", "home_read_scan", Reason::Unconsolidated),
    ("ipe", "html_entity_owner_scan", Reason::Unconsolidated),
    ("ipe", "http_e2e", Reason::Unconsolidated),
    ("ipe", "init_subcommand", Reason::Unconsolidated),
    ("ipe", "install_messages", Reason::Unconsolidated),
    ("ipe", "install_private_scratch", Reason::Unconsolidated),
    ("ipe", "install_style_drift", Reason::Unconsolidated),
    ("ipe", "interp_indented", Reason::Unconsolidated),
    ("ipe", "interp_literal", Reason::Unconsolidated),
    ("ipe", "interpolation_scalars", Reason::Unconsolidated),
    ("ipe", "lenient_decode_scan", Reason::Unconsolidated),
    ("ipe", "lint", Reason::Unconsolidated),
    ("ipe", "lint_table_coverage", Reason::Unconsolidated),
    ("ipe", "live_e2e", Reason::Unconsolidated),
    ("ipe", "lsp_degraded_scan", Reason::Unconsolidated),
    ("ipe", "lsp_stdio_e2e", Reason::Unconsolidated),
    ("ipe", "manifest_schema", Reason::Unconsolidated),
    ("ipe", "model_admissibility", Reason::Unconsolidated),
    ("ipe", "msg_admissibility", Reason::Unconsolidated),
    ("ipe", "native_emit_corpus_sweep", Reason::Unconsolidated),
    ("ipe", "negative_suite", Reason::Unconsolidated),
    ("ipe", "nextest_bin_canary", Reason::Unconsolidated),
    ("ipe", "out_target_inventory", Reason::Unconsolidated),
    ("ipe", "output_marker_scan", Reason::Unconsolidated),
    ("ipe", "pack_desktop", Reason::Unconsolidated),
    ("ipe", "pack_emit_permissions", Reason::Unconsolidated),
    ("ipe", "package_audit", Reason::Unconsolidated),
    ("ipe", "package_single_read_scan", Reason::Unconsolidated),
    ("ipe", "package_surface_coverage", Reason::Unconsolidated),
    (
        "ipe",
        "param_shared_wildcard_any_seal",
        Reason::Unconsolidated,
    ),
    ("ipe", "per_module_typecheck_parity", Reason::Unconsolidated),
    ("ipe", "permission_changes_filter", Reason::Unconsolidated),
    ("ipe", "pkg_stub", Reason::Unconsolidated),
    (
        "ipe",
        "postgres_driver_reachability",
        Reason::Unconsolidated,
    ),
    (
        "ipe",
        "probe_shared_target_soundness",
        Reason::Unconsolidated,
    ),
    ("ipe", "publish_fork_write_scan", Reason::Unconsolidated),
    ("ipe", "raw_print_ratchet", Reason::Unconsolidated),
    ("ipe", "registry_admission", Reason::DedicatedJob),
    ("ipe", "registry_smoke_probes", Reason::Unconsolidated),
    ("ipe", "release_subcommand", Reason::ProcessGlobalState),
    ("ipe", "render_layout_budget", Reason::Unconsolidated),
    ("ipe", "repo_url_drift", Reason::Unconsolidated),
    ("ipe", "retired_delivery_words_scan", Reason::Unconsolidated),
    ("ipe", "root_fixture_build", Reason::Unconsolidated),
    ("ipe", "run_subcommand", Reason::Unconsolidated),
    ("ipe", "runtime_resolver_scan", Reason::Unconsolidated),
    ("ipe", "rust_group", Reason::Unconsolidated),
    ("ipe", "seal_modset", Reason::DedicatedJob),
    ("ipe", "seal_regression", Reason::Unconsolidated),
    ("ipe", "secret_gates", Reason::Unconsolidated),
    ("ipe", "secured_store_e2e", Reason::Unconsolidated),
    ("ipe", "served_install_icon", Reason::Unconsolidated),
    ("ipe", "server_e2e", Reason::Unconsolidated),
    ("ipe", "server_shutdown_e2e", Reason::Unconsolidated),
    ("ipe", "spike_std_source", Reason::Unconsolidated),
    ("ipe", "static_emit", Reason::DedicatedJob),
    ("ipe", "stdlib_alias_gate", Reason::Unconsolidated),
    ("ipe", "stdlib_coverage_dynamic", Reason::Unconsolidated),
    ("ipe", "stdlib_coverage_matrix", Reason::Unconsolidated),
    ("ipe", "stdlib_export_resolvability", Reason::Unconsolidated),
    ("ipe", "stdlib_parser_composed", Reason::Unconsolidated),
    ("ipe", "target_dir_windows_gnu", Reason::Unconsolidated),
    ("ipe", "tea_tui_cli_surface", Reason::Unconsolidated),
    ("ipe", "test_command", Reason::Unconsolidated),
    ("ipe", "tool_path_scan", Reason::Unconsolidated),
    ("ipe", "tui_e2e", Reason::Unconsolidated),
    ("ipe", "tui_terminal_gate", Reason::Unconsolidated),
    ("ipe", "type_check", Reason::Unconsolidated),
    ("ipe", "type_depth_ceiling", Reason::Unconsolidated),
    ("ipe", "ui_cells_shape_gate", Reason::Unconsolidated),
    ("ipe", "ui_widget_shape_gate", Reason::Unconsolidated),
    (
        "ipe",
        "unsafe_import_acknowledgment",
        Reason::Unconsolidated,
    ),
    ("ipe", "usage_route_scan", Reason::Unconsolidated),
    ("ipe", "verb_prose_ratchet", Reason::Unconsolidated),
    ("ipe", "verify", Reason::Unconsolidated),
    ("ipe", "wasi_run_ceilings", Reason::Unconsolidated),
    ("ipe", "wasi_target_seal", Reason::DedicatedJob),
    ("ipe", "wasm_target_gate", Reason::Unconsolidated),
    ("ipe", "wasm_widget_adapter", Reason::Unconsolidated),
    ("ipe", "watch_bluegreen", Reason::Unconsolidated),
    ("ipe", "watch_cancellation", Reason::Unconsolidated),
    ("ipe", "watch_hot_appearance", Reason::Unconsolidated),
    ("ipe", "watch_integration", Reason::Unconsolidated),
    ("ipe", "watch_sigterm", Reason::Unconsolidated),
    ("ipe", "webview_e2e", Reason::Unconsolidated),
    ("ipe", "widget_e2e", Reason::Unconsolidated),
    ("ipe", "wildcard_spelling_scan", Reason::Unconsolidated),
    (
        "ipe-runtime-rust",
        "calling_convention",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "composite_tostring_floor",
        Reason::Unconsolidated,
    ),
    ("ipe-runtime-rust", "core_soundness", Reason::Unconsolidated),
    ("ipe-runtime-rust", "debug_behavior", Reason::Unconsolidated),
    ("ipe-runtime-rust", "decimal_parity", Reason::Unconsolidated),
    (
        "ipe-runtime-rust",
        "dict_determinism",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "entropy_site_inventory",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "error_bridge_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "event_answer_single_table",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "fetch_error_text_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "ffi_async_bridge",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "ffi_call_task_divergence",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "format_width_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "int_arith_total_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "json_depth_stack_safety",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "kernel_soundness",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "lib_reexport_units",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "like_prefix_single_renderer",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "limit_message_kind",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "listen_site_inventory",
        Reason::Unconsolidated,
    ),
    ("ipe-runtime-rust", "money_parity", Reason::Unconsolidated),
    (
        "ipe-runtime-rust",
        "no_color_env_reader_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "no_panicking_print_macro",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "no_ungated_dial",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "parent_death_spawner",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "per_event_render_budget",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "posture_read_inventory",
        Reason::Unconsolidated,
    ),
    ("ipe-runtime-rust", "proptest", Reason::Unconsolidated),
    ("ipe-runtime-rust", "regex_parity", Reason::Unconsolidated),
    (
        "ipe-runtime-rust",
        "secret_debug_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "serde_error_text_scan",
        Reason::Unconsolidated,
    ),
    ("ipe-runtime-rust", "show_rows", Reason::Unconsolidated),
    ("ipe-runtime-rust", "spawn_fd_floor", Reason::Unconsolidated),
    (
        "ipe-runtime-rust",
        "sql_safe_single_site",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "startup_fact_single_emitter",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "stdin_line_reader",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "store_write_outcome_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "symbol_resolution",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "sync_bound_registry",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "unwind_boundary_scan",
        Reason::Unconsolidated,
    ),
    ("ipe-runtime-rust", "wasm_cell_scan", Reason::Unconsolidated),
    ("ipe-runtime-rust", "wasm_dom_paint", Reason::ForeignTarget),
    (
        "ipe-runtime-rust",
        "wasm_floor_scope",
        Reason::Unconsolidated,
    ),
    (
        "ipe-runtime-rust",
        "wasm_js_port_bridge",
        Reason::ForeignTarget,
    ),
    (
        "ipe-runtime-rust",
        "wasm_websocket_bridge",
        Reason::ForeignTarget,
    ),
    (
        "ipe-runtime-rust",
        "web_base_env_scan",
        Reason::Unconsolidated,
    ),
    ("ipe-runtime-rust", "worker_scan", Reason::Unconsolidated),
    ("ipe_backend_rust", "adts", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "bound_render_only_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "boxed_field_funnel_scan",
        Reason::Unconsolidated,
    ),
    ("ipe_backend_rust", "caf_share_once", Reason::Unconsolidated),
    ("ipe_backend_rust", "cargo_name", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "dep_manifest_selfcontained",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "display_hazard_parity",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "emit_layout_normal_form",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "emitted_closure_inventory_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "generic_records",
        Reason::Unconsolidated,
    ),
    ("ipe_backend_rust", "generics", Reason::Unconsolidated),
    ("ipe_backend_rust", "golden", Reason::Unconsolidated),
    ("ipe_backend_rust", "hardening", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "hot_literal_bidi",
        Reason::Unconsolidated,
    ),
    ("ipe_backend_rust", "int_wrap", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "intercept_placeholder_emit",
        Reason::Unconsolidated,
    ),
    ("ipe_backend_rust", "lexable_seal", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "literal_patterns",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "record_patterns",
        Reason::Unconsolidated,
    ),
    ("ipe_backend_rust", "records", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "runtime_featureset_closure",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "runtime_modset_closure",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "rust_literal_owner_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "seal_derivability",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "seal_run_target_isolation",
        Reason::Unconsolidated,
    ),
    ("ipe_backend_rust", "split_emit", Reason::Unconsolidated),
    ("ipe_backend_rust", "tail_call", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "template_exit_funnel_scan",
        Reason::Unconsolidated,
    ),
    ("ipe_backend_rust", "tuple_patterns", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "user_local_escape_scan",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "vendored_clippy_config",
        Reason::Unconsolidated,
    ),
    ("ipe_backend_rust", "wasm_dep_floor", Reason::Unconsolidated),
    (
        "ipe_backend_rust",
        "wasm_featureset_closure",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "wasm_hydration_gate",
        Reason::Unconsolidated,
    ),
    (
        "ipe_backend_rust",
        "webview_dep_floor",
        Reason::Unconsolidated,
    ),
    ("ipe_bindgen", "inert", Reason::Unconsolidated),
    ("ipe_canon", "alias_defining_scope", Reason::Unconsolidated),
    ("ipe_canon", "alias_row_param", Reason::Unconsolidated),
    ("ipe_canon", "binding_ladder", Reason::Unconsolidated),
    ("ipe_canon", "canonical_import_gate", Reason::Unconsolidated),
    ("ipe_canon", "import_required", Reason::Unconsolidated),
    (
        "ipe_canon",
        "link_asserted_refusals",
        Reason::Unconsolidated,
    ),
    (
        "ipe_canon",
        "task_step_ctor_resolution",
        Reason::Unconsolidated,
    ),
    (
        "ipe_canon",
        "wildcard_type_ctor_tier",
        Reason::Unconsolidated,
    ),
    ("ipe_db", "adversarial_review", Reason::Unconsolidated),
    ("ipe_db", "db_smoke", Reason::Unconsolidated),
    ("ipe_db", "emit_settings_split", Reason::Unconsolidated),
    ("ipe_db", "incrementality", Reason::Unconsolidated),
    ("ipe_db", "inv1_clippy_config", Reason::Unconsolidated),
    (
        "ipe_db",
        "lsp_degraded_differential",
        Reason::Unconsolidated,
    ),
    ("ipe_db", "lsp_seam", Reason::Unconsolidated),
    ("ipe_db", "per_module_typecheck", Reason::Unconsolidated),
    ("ipe_db", "phase2_incrementality", Reason::Unconsolidated),
    ("ipe_db", "phase3_spine", Reason::Unconsolidated),
    ("ipe_db", "phase4_seams", Reason::Unconsolidated),
    ("ipe_db", "phase5_metadata", Reason::Unconsolidated),
    ("ipe_db", "phase6_build_config", Reason::Unconsolidated),
    ("ipe_db", "phase9_emit_rust_file", Reason::Unconsolidated),
    (
        "ipe_db",
        "phase9_incrementality_e2e",
        Reason::Unconsolidated,
    ),
    (
        "ipe_diagnostics",
        "printed_codes_registered",
        Reason::Unconsolidated,
    ),
    ("ipe_diagnostics", "render_goldens", Reason::Unconsolidated),
    ("ipe_docs", "fmt_keeps_docs", Reason::Unconsolidated),
    ("ipe_docs", "html_escape_contract", Reason::Unconsolidated),
    ("ipe_docs", "string_doc_examples", Reason::Unconsolidated),
    ("ipe_ffi", "closure_adapter_seal", Reason::Unconsolidated),
    ("ipe_ffi", "closure_handoff_seal", Reason::Unconsolidated),
    (
        "ipe_ffi",
        "define_async_closure_seal",
        Reason::Unconsolidated,
    ),
    ("ipe_ffi", "define_enum_seal", Reason::Unconsolidated),
    ("ipe_ffi", "define_forwarder_seal", Reason::Unconsolidated),
    (
        "ipe_ffi",
        "define_opaque_field_seal",
        Reason::Unconsolidated,
    ),
    (
        "ipe_ffi",
        "define_opaque_return_seal",
        Reason::Unconsolidated,
    ),
    ("ipe_ffi", "define_recursive_seal", Reason::Unconsolidated),
    ("ipe_ffi", "define_struct_seal", Reason::Unconsolidated),
    ("ipe_ffi", "define_trait_impl_seal", Reason::Unconsolidated),
    (
        "ipe_ffi",
        "define_transparency_fixpoint_seal",
        Reason::Unconsolidated,
    ),
    (
        "ipe_ffi",
        "generic_and_system_over_drop_seal",
        Reason::Unconsolidated,
    ),
    ("ipe_ffi", "multi_result_tuple_seal", Reason::Unconsolidated),
    ("ipe_ffi", "seq_narrow_seal", Reason::Unconsolidated),
    ("ipe_ffi", "wrapper_capability_gate", Reason::Unconsolidated),
    ("ipe_ffi", "wrapper_crate_seal", Reason::Unconsolidated),
    ("ipe_fmt", "comment_positions", Reason::Unconsolidated),
    ("ipe_fmt", "corpus_fixed_point", Reason::Unconsolidated),
    ("ipe_fmt", "layout_goldens", Reason::Unconsolidated),
    ("ipe_fmt", "record_layout", Reason::Unconsolidated),
    ("ipe_fmt", "trailing_comments", Reason::Unconsolidated),
    (
        "ipe_fs_open",
        "regular_file_api_scan",
        Reason::Unconsolidated,
    ),
    ("ipe_ir", "let_inline", Reason::Unconsolidated),
    ("ipe_ir", "tail_nodes", Reason::Unconsolidated),
    ("ipe_kernels", "kernel_row", Reason::Unconsolidated),
    ("ipe_kernels", "list_veneer_ssot", Reason::Unconsolidated),
    ("ipe_kernels", "maybe_veneer_ssot", Reason::Unconsolidated),
    ("ipe_kernels", "result_veneer_ssot", Reason::Unconsolidated),
    ("ipe_kernels", "string_veneer_ssot", Reason::Unconsolidated),
    ("ipe_kernels", "veneer_helpers", Reason::Unconsolidated),
    ("ipe_lower", "opaque_home_guard", Reason::Unconsolidated),
    ("ipe_lower", "row_field_type", Reason::Unconsolidated),
    ("ipe_lower", "tail_analysis", Reason::Unconsolidated),
    ("ipe_lower", "unsupported", Reason::Unconsolidated),
    ("ipe_lsp_features", "collect", Reason::Unconsolidated),
    (
        "ipe_lsp_features",
        "completion_context",
        Reason::Unconsolidated,
    ),
    ("ipe_lsp_features", "definition", Reason::Unconsolidated),
    ("ipe_lsp_features", "degraded", Reason::Unconsolidated),
    ("ipe_lsp_features", "navigation", Reason::Unconsolidated),
    ("ipe_lsp_features", "panic_guard", Reason::Unconsolidated),
    ("ipe_lsp_server", "compile_stack", Reason::Unconsolidated),
    ("ipe_lsp_server", "protocol", Reason::Unconsolidated),
    ("ipe_parse", "front_end_refusals", Reason::Unconsolidated),
    ("ipe_sandbox", "build_jail_e2e", Reason::Unconsolidated),
    (
        "ipe_sandbox",
        "build_jail_freebsd_e2e",
        Reason::Unconsolidated,
    ),
    (
        "ipe_sandbox",
        "build_jail_windows_e2e",
        Reason::Unconsolidated,
    ),
    ("ipe_sandbox", "run_jail_e2e", Reason::Unconsolidated),
    ("ipe_sandbox", "run_jail_macos_e2e", Reason::Unconsolidated),
    (
        "ipe_sandbox",
        "run_jail_windows_e2e",
        Reason::Unconsolidated,
    ),
    (
        "ipe_sandbox",
        "vcs_metadata_handle_scan",
        Reason::Unconsolidated,
    ),
    ("ipe_stdlib", "browser_port_tag", Reason::Unconsolidated),
    ("ipe_types", "exhaust_fail_closed", Reason::Unconsolidated),
    ("ipe_types", "stdlib_builtin_heads", Reason::Unconsolidated),
    ("ipe_wrapper", "bundle_refusals", Reason::Unconsolidated),
    ("panic-scan", "depth_ceiling", Reason::DedicatedJob),
    ("panic-scan", "exit_codes", Reason::Unconsolidated),
    ("panic-scan", "walk", Reason::Unconsolidated),
    (
        "playground-jail-runner",
        "sandbox_security",
        Reason::Unconsolidated,
    ),
];

/// The committed policy every check reads.
struct Policy<'a> {
    binaries: &'a [(&'a str, &'a str, Reason)],
    ceilings: &'a [(&'a str, usize)],
    data_dirs: &'a [&'a str],
    shared: &'a [&'a str],
}

const POLICY: Policy<'static> = Policy {
    binaries: TEST_BINARIES,
    ceilings: UNCONSOLIDATED_CEILINGS,
    data_dirs: TEST_DATA_DIRS,
    shared: SHARED_MODULES,
};

impl Policy<'_> {
    fn reason(&self, package: &str, name: &str) -> Option<Reason> {
        self.binaries
            .iter()
            .find(|(p, n, _)| *p == package && *n == name)
            .map(|(_, _, r)| *r)
    }
}

/// One test target, every path relative to the workspace root with `/`
/// separators.
#[derive(Default)]
struct Target {
    package: String,
    name: String,
    root: String,
    files: BTreeSet<String>,
    /// The modules its root file declares.
    modules: BTreeSet<String>,
}

/// What R2, R3 and R5 read from one source file.
#[derive(Clone, Default)]
struct Facts {
    /// A fn under an attribute whose last path segment is `test`.
    has_test: bool,
    /// Inner attributes named in [`CRATE_ONLY_ATTRS`].
    crate_attrs: Vec<String>,
    /// An identifier token [`CWD_IDENT`], outside string literals and
    /// comments.
    cwd_ident: bool,
}

/// The tree as the checks see it.
#[derive(Default)]
struct Model {
    packages: BTreeSet<String>,
    targets: Vec<Target>,
    facts: BTreeMap<String, Facts>,
    /// Every `.rs` file under some package's `tests/` directory.
    tests_files: BTreeSet<String>,
    /// Each test-target file that does not parse, with the parse error.
    unparsable: Vec<String>,
}

impl Model {
    fn targets_named<'m>(&'m self, name: &'m str) -> impl Iterator<Item = &'m Target> + 'm {
        self.targets.iter().filter(move |t| t.name == name)
    }

    fn has_target(&self, name: &str) -> bool {
        self.targets_named(name).next().is_some()
    }

    fn graph_has<F: Fn(&Facts) -> bool>(&self, target: &Target, pred: F) -> bool {
        target
            .files
            .iter()
            .any(|f| self.facts.get(f).is_some_and(&pred))
    }
}

/// A configuration file R1 and R3 read.
struct Text {
    path: String,
    body: String,
}

impl Text {
    fn new(path: &str, body: &str) -> Self {
        Self {
            path: path.to_owned(),
            body: body.to_owned(),
        }
    }

    fn is_workflow(&self) -> bool {
        self.path.starts_with(".github/workflows/")
    }

    /// A file whose `--test`/`binary(…)` names a job that runs a target alone.
    fn is_job(&self) -> bool {
        self.is_workflow()
            || self.path == ".github/ci/check-manifest.yml"
            || self.path.starts_with("tools/scripts/")
    }
}

// ---------------------------------------------------------------- scanners

const fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// The leading run of `s` that `keep` accepts.
fn leading(s: &str, keep: impl Fn(char) -> bool) -> &str {
    let end = s.find(|c: char| !keep(c)).unwrap_or(s.len());
    s.get(..end).unwrap_or_default()
}

/// Every operand of a `--test` flag on `line` (`--test name` or
/// `--test=name`). An operand that is not a plain name comes back empty, so
/// R3 refuses what it cannot read.
fn test_flags(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("--test") {
        let after = rest.get(at + "--test".len()..).unwrap_or_default();
        let before = rest.get(..at).unwrap_or_default();
        rest = after;
        if before.ends_with(is_name_char) || !after.starts_with([' ', '=']) {
            continue;
        }
        let operand = after.trim_start_matches([' ', '=']);
        out.push(leading(operand, is_name_char));
    }
    out
}

/// Every `binary(…)` operand on `line`, verbatim.
fn binary_args(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("binary(") {
        let before = rest.get(..at).unwrap_or_default();
        let after = rest.get(at + "binary(".len()..).unwrap_or_default();
        rest = after;
        if before.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        out.push(after.split_once(')').map_or(after, |(arg, _)| arg));
    }
    out
}

/// What a `binary(…)` operand names.
#[derive(Debug, PartialEq, Eq)]
enum BinaryArg<'a> {
    /// A target name.
    Name(&'a str),
    /// A `/regex/` of anchors and literal name characters.
    Pattern {
        start: bool,
        literal: &'a str,
        end: bool,
    },
    /// A Python format template (`{b}`) or an ellipsis in a comment; the
    /// group it builds is proved live by R6 on the archive.
    Template,
    /// Anything else, refused.
    Unreadable,
}

fn classify(arg: &str) -> BinaryArg<'_> {
    if arg.contains('{') || arg == "..." {
        return BinaryArg::Template;
    }
    if !arg.is_empty() && arg.chars().all(is_name_char) {
        return BinaryArg::Name(arg);
    }
    let Some(re) = arg.strip_prefix('/').and_then(|a| a.strip_suffix('/')) else {
        return BinaryArg::Unreadable;
    };
    let (start, re) = re.strip_prefix('^').map_or((false, re), |r| (true, r));
    let (end, literal) = re.strip_suffix('$').map_or((false, re), |r| (true, r));
    if literal.is_empty() || !literal.chars().all(is_name_char) {
        return BinaryArg::Unreadable;
    }
    BinaryArg::Pattern {
        start,
        literal,
        end,
    }
}

fn pattern_matches(start: bool, literal: &str, end: bool, name: &str) -> bool {
    match (start, end) {
        (true, true) => name == literal,
        (true, false) => name.starts_with(literal),
        (false, true) => name.ends_with(literal),
        (false, false) => name.contains(literal),
    }
}

/// Every `(binary, module)` pair on `line` where a `test(=M::…)` or
/// `test(/^M::…/)` filter follows a `binary(X)` naming one target.
fn module_filters(line: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for opener in ["test(=", "test(/^"] {
        let mut rest = line;
        let mut offset = 0;
        while let Some(at) = rest.find(opener) {
            let after = rest.get(at + opener.len()..).unwrap_or_default();
            let head = line.get(..offset + at).unwrap_or_default();
            offset += at + opener.len();
            rest = after;
            let module = leading(after, |c| c.is_ascii_alphanumeric() || c == '_');
            let is_path = after
                .get(module.len()..)
                .is_some_and(|tail| tail.starts_with("::"));
            let binary = binary_args(head).last().copied().map(classify);
            if let (true, false, Some(BinaryArg::Name(x))) = (is_path, module.is_empty(), binary) {
                out.push((x, module));
            }
        }
    }
    out
}

/// Every double-quoted string on `line`.
fn quoted(line: &str) -> Vec<&str> {
    line.split('"').skip(1).step_by(2).collect()
}

/// The binaries `e2e_shard.py` names: the heavy set, each `OneTest`
/// binary and each `Binaries` tuple member. An empty read is an error.
fn shard_plan_binaries(body: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    let heavy: Vec<&str> = body
        .split_once("HEAVY_BINARIES = (")
        .and_then(|(_, rest)| rest.split_once("\n)"))
        .map(|(tuple, _)| tuple.lines().flat_map(quoted).collect())
        .unwrap_or_default();
    let mut one_tests = 0_usize;
    let mut tuples = 0_usize;
    for line in body.lines() {
        if line.contains("OneTest(\"") {
            one_tests += 1;
            out.extend(quoted(line).get(1).copied());
        } else if line.contains("Binaries(\"") && line.contains(", (") {
            tuples += 1;
            out.extend(quoted(line).into_iter().skip(1));
        }
    }
    if heavy.is_empty() || one_tests == 0 || tuples == 0 {
        return Err(format!(
            "`e2e_shard.py` no longer reads as this ratchet expects (heavy set {}, \
             `OneTest` rows {one_tests}, `Binaries` tuples {tuples}): update the reader",
            heavy.len()
        ));
    }
    out.extend(heavy);
    Ok(out)
}

/// Every `src/…/tests/….rs` or `tools/…/tests/….rs` path in `text`.
fn path_literals(text: &str) -> Vec<&str> {
    const fn is_path_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-')
    }
    let mut out = Vec::new();
    let mut prev_path = false;
    for (at, c) in text.char_indices() {
        let starts = !prev_path
            && text
                .get(at..)
                .is_some_and(|r| r.starts_with("src/") || r.starts_with("tools/"));
        prev_path = is_path_char(c);
        if starts {
            let run = leading(text.get(at..).unwrap_or_default(), is_path_char);
            if is_test_path(run) {
                out.push(run);
            }
        }
    }
    out
}

/// `src/<dir>/tests/<tail>.rs` or `tools/<dir>/tests/<tail>.rs`, the tail
/// made of name characters and `/`.
fn is_test_path(run: &str) -> bool {
    let body = run
        .strip_prefix("src/")
        .or_else(|| run.strip_prefix("tools/"))
        .unwrap_or_default();
    body.find("/tests/")
        .filter(|at| *at > 0)
        .and_then(|at| body.get(at + "/tests/".len()..))
        .and_then(|tail| tail.strip_suffix(".rs"))
        .is_some_and(|stem| {
            !stem.is_empty()
                && stem
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '/'))
        })
}

/// The facts of one source file, or why it does not parse.
fn facts(text: &str) -> Result<Facts, String> {
    struct TestFns(bool);
    impl<'ast> syn::visit::Visit<'ast> for TestFns {
        fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
            self.0 |= f
                .attrs
                .iter()
                .any(|a| a.path().segments.last().is_some_and(|s| s.ident == "test"));
            syn::visit::visit_item_fn(self, f);
        }
    }
    let file = syn::parse_file(text).map_err(|e| e.to_string())?;
    let mut tests = TestFns(false);
    syn::visit::Visit::visit_file(&mut tests, &file);
    let crate_attrs = file
        .attrs
        .iter()
        .filter(|a| matches!(a.style, syn::AttrStyle::Inner(_)))
        .filter_map(|a| a.path().get_ident().map(ToString::to_string))
        .filter(|name| CRATE_ONLY_ATTRS.contains(&name.as_str()))
        .collect();
    let tokens: proc_macro2::TokenStream = text
        .parse()
        .map_err(|e: proc_macro2::LexError| e.to_string())?;
    Ok(Facts {
        has_test: tests.0,
        crate_attrs,
        cwd_ident: has_ident(tokens, CWD_IDENT),
    })
}

fn has_ident(tokens: proc_macro2::TokenStream, name: &str) -> bool {
    let mut stack = vec![tokens];
    while let Some(stream) = stack.pop() {
        for tree in stream {
            match tree {
                proc_macro2::TokenTree::Ident(i) if i == name => return true,
                proc_macro2::TokenTree::Group(g) => stack.push(g.stream()),
                _ => {}
            }
        }
    }
    false
}

/// The modules a root file declares.
fn root_modules(text: &str) -> BTreeSet<String> {
    syn::parse_file(text)
        .map(|f| {
            f.items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Mod(m) => Some(m.ident.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

// ------------------------------------------------------------------ checks

/// R1: the live target set equals the committed list.
fn check_set(model: &Model, policy: &Policy<'_>) -> Vec<String> {
    let live: BTreeSet<(&str, &str)> = model
        .targets
        .iter()
        .map(|t| (t.package.as_str(), t.name.as_str()))
        .collect();
    let mut listed = BTreeSet::new();
    let mut errors = Vec::new();
    for (package, name, _) in policy.binaries {
        if !listed.insert((*package, *name)) {
            errors.push(format!(
                "`{package}::{name}` is listed twice in `TEST_BINARIES`"
            ));
        }
        if !live.contains(&(*package, *name)) {
            errors.push(format!(
                "`{package}::{name}` is in `TEST_BINARIES` but is no longer a test target: drop the stale entry"
            ));
        }
    }
    for (package, name) in live.difference(&listed) {
        errors.push(format!(
            "`{package}::{name}` is a new test binary: add it as a module of an existing harness \
             (`tests/<area>/main.rs`) instead of a top-level `tests/{name}.rs`"
        ));
    }
    errors
}

/// R1: each listed reason holds.
fn check_reasons(model: &Model, policy: &Policy<'_>, texts: &[Text]) -> Vec<String> {
    let mut errors = Vec::new();
    for target in &model.targets {
        let Some(reason) = policy.reason(&target.package, &target.name) else {
            continue;
        };
        let holds = match reason {
            Reason::AreaHarness => is_harness_root(target),
            Reason::DedicatedJob => names_job(&target.name, texts),
            Reason::ForeignTarget => names_foreign(&target.name, texts),
            Reason::ProcessGlobalState => model.graph_has(target, |f| f.cwd_ident),
            Reason::Unconsolidated => true,
        };
        if !holds {
            errors.push(format!(
                "`{}::{}` is listed as `{reason:?}`, which no longer holds ({})",
                target.package,
                target.name,
                reason_check(reason)
            ));
        }
    }
    errors
}

const fn reason_check(reason: Reason) -> &'static str {
    match reason {
        Reason::AreaHarness => "its root is neither `tests/<name>/main.rs` nor `tests/g_*.rs`",
        Reason::DedicatedJob => {
            "no workflow, `check-manifest.yml` or `tools/scripts` command names `--test <name>` or `binary(<name>)`"
        }
        Reason::ForeignTarget => {
            "no workflow line runs it with `--target wasm32-` and `--test <name>`"
        }
        Reason::ProcessGlobalState => "its module graph no longer calls `set_current_dir`",
        Reason::Unconsolidated => "always holds",
    }
}

fn is_harness_root(target: &Target) -> bool {
    let name = &target.name;
    target.root.ends_with(&format!("/tests/{name}/main.rs"))
        || (name.starts_with("g_") && target.root.ends_with(&format!("/tests/{name}.rs")))
}

fn names_job(name: &str, texts: &[Text]) -> bool {
    texts.iter().filter(|t| t.is_job()).any(|t| {
        t.body
            .lines()
            .any(|line| test_flags(line).contains(&name) || binary_args(line).contains(&name))
    })
}

fn names_foreign(name: &str, texts: &[Text]) -> bool {
    texts.iter().filter(|t| t.is_workflow()).any(|t| {
        t.body
            .lines()
            .any(|line| line.contains("--target wasm32-") && test_flags(line).contains(&name))
    })
}

/// R1: each crate's unconsolidated count equals its ceiling.
fn check_ceilings(policy: &Policy<'_>) -> Vec<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (package, _, reason) in policy.binaries {
        if *reason == Reason::Unconsolidated {
            *counts.entry(package).or_default() += 1;
        }
    }
    let ceilings: BTreeMap<&str, usize> = policy.ceilings.iter().copied().collect();
    let mut errors = Vec::new();
    for package in counts
        .keys()
        .chain(ceilings.keys())
        .collect::<BTreeSet<_>>()
    {
        let live = counts.get(package).copied().unwrap_or_default();
        let ceiling = ceilings.get(package).copied().unwrap_or_default();
        if live != ceiling {
            errors.push(format!(
                "`{package}` has {live} unconsolidated test binaries but its ceiling is {ceiling}: \
                 the ceiling only ever equals the live count (lower it when a target moves into a harness)"
            ));
        }
    }
    errors
}

/// R2: no orphan, no duplicate, no stale data dir or shared module.
fn check_reach(model: &Model, policy: &Policy<'_>) -> Vec<String> {
    let mut reach: BTreeMap<&str, usize> = BTreeMap::new();
    for target in &model.targets {
        for file in &target.files {
            *reach.entry(file.as_str()).or_default() += 1;
        }
    }
    let mut errors = Vec::new();
    for file in &model.tests_files {
        if policy.data_dirs.iter().any(|d| file.starts_with(d)) {
            continue;
        }
        let n = reach.get(file.as_str()).copied().unwrap_or_default();
        if n == 0 {
            errors.push(format!(
                "`{file}` is reached by no test target, so it never compiles: declare it as a module of the harness it belongs to"
            ));
        } else if n > 1 && !policy.shared.contains(&file.as_str()) {
            errors.push(format!(
                "`{file}` is compiled into {n} test targets: declare it in one, or list it in `SHARED_MODULES` if it is support with no test"
            ));
        }
    }
    for shared in policy.shared {
        if reach.get(shared).copied().unwrap_or_default() < 2 {
            errors.push(format!(
                "`SHARED_MODULES` entry `{shared}` is reached by fewer than two targets: drop it"
            ));
        }
        if model.facts.get(*shared).is_some_and(|f| f.has_test) {
            errors.push(format!(
                "shared module `{shared}` holds a `#[test]`, which then runs once per target that reaches it: move the test into one target"
            ));
        }
    }
    for dir in policy.data_dirs {
        if !model.tests_files.iter().any(|f| f.starts_with(dir)) {
            errors.push(format!(
                "`TEST_DATA_DIRS` entry `{dir}` holds no `.rs` file: drop it"
            ));
        }
    }
    errors
}

/// R3: every binary and module filter names something live.
fn check_filters(model: &Model, policy: &Policy<'_>, texts: &[Text]) -> Vec<String> {
    let mut errors = Vec::new();
    for text in texts {
        if text.path.ends_with("e2e_shard.py") {
            errors.extend(check_shard_plan(model, text));
        }
        if text.path.ends_with("e2e-shard-times.txt") {
            errors.extend(check_times(model, text));
        }
        for (n, line) in text.body.lines().enumerate() {
            let at = format!("{}:{}", text.path, n + 1);
            errors.extend(check_line(model, policy, &at, line));
        }
    }
    errors
}

fn check_line(model: &Model, policy: &Policy<'_>, at: &str, line: &str) -> Vec<String> {
    let mut errors = Vec::new();
    for name in test_flags(line) {
        if !model.has_target(name) {
            errors.push(format!("{at}: `--test {name}` names no test target"));
        }
        let harness = model
            .targets_named(name)
            .any(|t| policy.reason(&t.package, &t.name) == Some(Reason::AreaHarness));
        if harness && line.contains("cargo test") {
            errors.push(format!(
                "{at}: `cargo test --test {name}` runs a harness's modules as threads of one process; run it through nextest"
            ));
        }
    }
    for arg in binary_args(line) {
        match classify(arg) {
            BinaryArg::Name(name) if !model.has_target(name) => {
                errors.push(format!("{at}: `binary({name})` names no test target"));
            }
            BinaryArg::Pattern { start, literal, end }
                if !model
                    .targets
                    .iter()
                    .any(|t| pattern_matches(start, literal, end, &t.name)) =>
            {
                errors.push(format!("{at}: `binary({arg})` matches no test target"));
            }
            BinaryArg::Unreadable => errors.push(format!(
                "{at}: `binary({arg})` is not a name or an anchored literal pattern, so its liveness cannot be checked"
            )),
            _ => {}
        }
    }
    for (binary, module) in module_filters(line) {
        if model
            .targets_named(binary)
            .all(|t| !t.modules.contains(module))
        {
            errors.push(format!("{at}: the filter on `binary({binary})` names module `{module}`, which it does not declare"));
        }
    }
    errors
}

fn check_shard_plan(model: &Model, text: &Text) -> Vec<String> {
    match shard_plan_binaries(&text.body) {
        Err(e) => vec![format!("{}: {e}", text.path)],
        Ok(names) => names
            .into_iter()
            .filter(|n| !model.has_target(n))
            .map(|n| {
                format!(
                    "{}: shard group binary `{n}` names no test target",
                    text.path
                )
            })
            .collect(),
    }
}

/// Each row is `<binary-id> [<test>] <seconds>`: the id is a package, a
/// `package::target`, or a `package::bin/<name>`.
fn check_times(model: &Model, text: &Text) -> Vec<String> {
    let mut errors = Vec::new();
    for (n, line) in text.body.lines().enumerate() {
        let at = format!("{}:{}", text.path, n + 1);
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        let (id, test) = match words.as_slice() {
            [id, secs] if secs.parse::<u64>().is_ok() => (*id, None),
            [id, test, secs] if secs.parse::<u64>().is_ok() => (*id, Some(*test)),
            _ => {
                errors.push(format!(
                    "{at}: `{line}` is not `<binary-id> [<test>] <seconds>`"
                ));
                continue;
            }
        };
        let (package, target) = id
            .split_once("::")
            .map_or((id, None), |(p, t)| (p, Some(t)));
        if !model.packages.contains(package) {
            errors.push(format!("{at}: `{package}` is not a workspace package"));
        }
        let Some(target) = target.filter(|t| !t.starts_with("bin/")) else {
            continue;
        };
        let live: Vec<&Target> = model
            .targets
            .iter()
            .filter(|t| t.package == package && t.name == target)
            .collect();
        if live.is_empty() {
            errors.push(format!("{at}: `{id}` names no test target"));
        }
        if let Some((module, _)) = test.and_then(|t| t.split_once("::"))
            && live.iter().all(|t| !t.modules.contains(module))
        {
            errors.push(format!("{at}: `{id}` declares no module `{module}`"));
        }
    }
    errors
}

/// R3: no crate-only inner attribute below a harness root.
fn check_harness_attrs(model: &Model, policy: &Policy<'_>) -> Vec<String> {
    let mut errors = Vec::new();
    for target in &model.targets {
        if policy.reason(&target.package, &target.name) != Some(Reason::AreaHarness) {
            continue;
        }
        for file in target.files.iter().filter(|f| **f != target.root) {
            for attr in model
                .facts
                .get(file)
                .map(|f| f.crate_attrs.as_slice())
                .unwrap_or_default()
            {
                errors.push(format!(
                    "`{file}` carries `#![{attr}]`, which applies only at a crate root: move it to `{}`",
                    target.root
                ));
            }
        }
    }
    errors
}

/// R4: every test-file path literal names a file, except the synthetic pairs.
fn check_literals(
    found: &[(String, String)],
    exists: impl Fn(&str) -> bool,
    synthetic: &[(&str, &str)],
) -> Vec<String> {
    let mut errors = Vec::new();
    for (file, literal) in found {
        let listed = synthetic.contains(&(file.as_str(), literal.as_str()));
        if !listed && !exists(literal) {
            errors.push(format!(
                "`{file}` names `{literal}`, which does not exist: a filter, allowlist or exclusion keyed by it matches nothing"
            ));
        }
        if listed && exists(literal) {
            errors.push(format!("`SYNTHETIC_PATHS` lists `({file}, {literal})`, but `{literal}` exists: drop the entry"));
        }
    }
    for (file, literal) in synthetic {
        if !found.iter().any(|(f, l)| f == file && l == literal) {
            errors.push(format!(
                "`SYNTHETIC_PATHS` entry `({file}, {literal})` no longer occurs: drop it"
            ));
        }
    }
    errors
}

/// R5: `set_current_dir` only in a process-global-state target.
fn check_cwd(model: &Model, policy: &Policy<'_>) -> Vec<String> {
    model
        .targets
        .iter()
        .filter(|t| policy.reason(&t.package, &t.name) != Some(Reason::ProcessGlobalState))
        .filter(|t| model.graph_has(t, |f| f.cwd_ident))
        .map(|t| {
            format!(
                "`{}::{}` calls `set_current_dir`, a process-global mutation: keep it in a `ProcessGlobalState` target",
                t.package, t.name
            )
        })
        .collect()
}

// -------------------------------------------------------------- live model

fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Every file under `dir` whose name `keep` accepts, skipping `skip_dir`
/// directories, relative to `root`.
#[allow(clippy::expect_used)] // an unreadable tree fails the ratchet: the designed outcome
fn walk(
    root: &Path,
    dir: &Path,
    keep: &dyn Fn(&str) -> bool,
    skip_dir: &dyn Fn(&str, &str) -> bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("read a directory entry").path();
            let rel = slash(path.strip_prefix(root).unwrap_or(&path));
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if path.is_dir() {
                if !skip_dir(&rel, &name) {
                    stack.push(path);
                }
            } else if keep(&name) {
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

#[allow(clippy::expect_used)] // an unreadable test source fails the ratchet: the designed outcome
fn live_model() -> (std::path::PathBuf, Model) {
    let (workspace, targets) = common::test_targets();
    let root = workspace.root;
    let mut model = Model {
        packages: workspace.packages.iter().map(|p| p.name.clone()).collect(),
        ..Model::default()
    };
    for package in &workspace.packages {
        let tests = package.manifest_dir.join("tests");
        model
            .tests_files
            .extend(walk(&root, &tests, &|n| n.ends_with(".rs"), &|_, n| {
                n == "target"
            }));
    }
    for target in targets {
        let files: BTreeSet<String> = target.files.iter().map(|f| slash(f)).collect();
        for file in &files {
            let text = std::fs::read_to_string(root.join(file)).expect("read a test-target file");
            match facts(&text) {
                Ok(parsed) => {
                    model.facts.insert(file.clone(), parsed);
                }
                Err(e) => model
                    .unparsable
                    .push(format!("`{file}` does not parse: {e}")),
            }
        }
        let root_text =
            std::fs::read_to_string(root.join(&target.root)).expect("read a test-target root");
        model.targets.push(Target {
            package: target.package,
            name: target.name,
            root: slash(&target.root),
            modules: root_modules(&root_text),
            files,
        });
    }
    (root, model)
}

#[allow(clippy::expect_used)] // a missing configuration file fails the ratchet: the designed outcome
fn live_texts(root: &Path) -> Vec<Text> {
    let mut paths: Vec<String> = FILTER_FILES.iter().map(|p| (*p).to_owned()).collect();
    paths.extend(walk(
        root,
        &root.join(".github/workflows"),
        &|n| n.ends_with(".yml") || n.ends_with(".yaml"),
        &|_, _| false,
    ));
    paths.extend(walk(
        root,
        &root.join("tools/scripts"),
        &|_| true,
        &|_, n| n == "node_modules" || n == "__pycache__",
    ));
    paths
        .into_iter()
        .filter_map(|path| {
            let bytes = std::fs::read(root.join(&path)).expect("read a configuration file");
            String::from_utf8(bytes)
                .ok()
                .map(|body| Text { path, body })
        })
        .collect()
}

/// The directories the root `.gitignore` names by a plain name: a `/name`
/// entry at the root only, a `name` or `**/name` entry at any depth. An entry
/// with a glob or an inner `/` is no plain directory name and is left out;
/// such entries name files the literal walk does not read.
struct IgnoredDirs {
    root: BTreeSet<String>,
    anywhere: BTreeSet<String>,
}

impl IgnoredDirs {
    fn parse(text: &str) -> Self {
        let mut dirs = Self {
            root: BTreeSet::new(),
            anywhere: BTreeSet::new(),
        };
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            let entry = line.trim_end_matches('/');
            let (set, name) = if let Some(name) = entry.strip_prefix("**/") {
                (&mut dirs.anywhere, name)
            } else if let Some(name) = entry.strip_prefix('/') {
                (&mut dirs.root, name)
            } else {
                (&mut dirs.anywhere, entry)
            };
            if !name.is_empty() && !name.contains(['/', '*', '?', '[', '\\']) {
                set.insert(name.to_owned());
            }
        }
        dirs
    }

    /// Whether the directory `rel` (relative to the root), named `name`, is
    /// ignored.
    fn covers(&self, rel: &str, name: &str) -> bool {
        self.anywhere.contains(name) || (rel == name && self.root.contains(name))
    }
}

/// Every test-file path literal in the workspace's `.rs`, `.py` and `.sh`
/// sources, as `(file, literal)`.
#[allow(clippy::expect_used)] // an unreadable source fails the ratchet: the designed outcome
fn live_literals(root: &Path) -> Vec<(String, String)> {
    let ignore =
        std::fs::read_to_string(root.join(".gitignore")).expect("read the root .gitignore");
    let ignored = IgnoredDirs::parse(&ignore);
    let skip_dir = |rel: &str, name: &str| {
        name == ".git"
            || ignored.covers(rel, name)
            || (name.starts_with('.') && rel != ".github" && rel != ".config")
    };
    let keep = |n: &str| n.ends_with(".rs") || n.ends_with(".py") || n.ends_with(".sh");
    walk(root, root, &keep, &skip_dir)
        .into_iter()
        .filter(|file| file != SELF)
        .flat_map(|file| {
            let bytes = std::fs::read(root.join(&file)).expect("read a workspace source");
            let text = String::from_utf8_lossy(&bytes).into_owned();
            path_literals(&text)
                .into_iter()
                .map(|l| (file.clone(), l.to_owned()))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn assert_clean(rule: &str, errors: &[String]) {
    assert!(errors.is_empty(), "{rule} refused:\n{}", errors.join("\n"));
}

// ------------------------------------------------------------- live checks

#[test]
fn r1_the_test_binaries_are_exactly_the_committed_list() {
    let (root, model) = live_model();
    assert_clean("parse", &model.unparsable);
    let texts = live_texts(&root);
    let mut errors = check_set(&model, &POLICY);
    errors.extend(check_reasons(&model, &POLICY, &texts));
    errors.extend(check_ceilings(&POLICY));
    assert_clean("R1", &errors);
}

#[test]
fn r2_every_test_file_is_compiled_by_exactly_one_target() {
    let (_, model) = live_model();
    assert_clean("parse", &model.unparsable);
    assert_clean("R2", &check_reach(&model, &POLICY));
}

#[test]
fn r3_every_binary_and_module_filter_names_something_live() {
    let (root, model) = live_model();
    assert_clean("parse", &model.unparsable);
    let texts = live_texts(&root);
    let mut errors = check_filters(&model, &POLICY, &texts);
    errors.extend(check_harness_attrs(&model, &POLICY));
    assert_clean("R3", &errors);
}

#[test]
fn r4_every_test_file_path_literal_names_a_file() {
    let (root, _) = common::test_target_files();
    let found = live_literals(&root);
    assert!(
        found.len() > SYNTHETIC_PATHS.len(),
        "the literal walk found only {} paths",
        found.len()
    );
    assert_clean(
        "R4",
        &check_literals(&found, |l| root.join(l).is_file(), SYNTHETIC_PATHS),
    );
}

#[test]
fn r5_only_a_process_global_state_target_changes_the_working_directory() {
    let (_, model) = live_model();
    assert_clean("parse", &model.unparsable);
    assert_clean("R5", &check_cwd(&model, &POLICY));
}

// ---------------------------------------------------------- planted cases

const HARNESS_ROOT: &str = "c/tests/harness/main.rs";
const ALPHA: &str = "c/tests/harness/alpha.rs";
const JOB_ROOT: &str = "c/tests/job.rs";
const SUPPORT: &str = "c/tests/support/mod.rs";
const DATA: &str = "c/tests/data/";

const GOOD_BINARIES: &[(&str, &str, Reason)] = &[
    ("p", "harness", Reason::AreaHarness),
    ("p", "job", Reason::DedicatedJob),
];

const fn good_policy() -> Policy<'static> {
    Policy {
        binaries: GOOD_BINARIES,
        ceilings: &[],
        data_dirs: &[DATA],
        shared: &[SUPPORT],
    }
}

fn target(name: &str, root: &str, files: &[&str], modules: &[&str]) -> Target {
    Target {
        package: "p".to_owned(),
        name: name.to_owned(),
        root: root.to_owned(),
        files: files.iter().map(|f| (*f).to_owned()).collect(),
        modules: modules.iter().map(|m| (*m).to_owned()).collect(),
    }
}

fn tested() -> Facts {
    Facts {
        has_test: true,
        ..Facts::default()
    }
}

/// Two targets: a harness with one module and a job, sharing one support
/// module, beside one data file.
fn good_model() -> Model {
    let mut model = Model {
        packages: ["p".to_owned()].into(),
        targets: vec![
            target(
                "harness",
                HARNESS_ROOT,
                &[HARNESS_ROOT, ALPHA, SUPPORT],
                &["alpha"],
            ),
            target("job", JOB_ROOT, &[JOB_ROOT, SUPPORT], &[]),
        ],
        ..Model::default()
    };
    for file in [HARNESS_ROOT, ALPHA, JOB_ROOT, SUPPORT] {
        model.tests_files.insert(file.to_owned());
        model.facts.insert(file.to_owned(), Facts::default());
    }
    model.tests_files.insert(format!("{DATA}fixture.rs"));
    model.facts.insert(ALPHA.to_owned(), tested());
    model.facts.insert(JOB_ROOT.to_owned(), tested());
    model
}

fn good_texts() -> Vec<Text> {
    vec![Text::new(
        ".github/workflows/ci.yml",
        "run: cargo nextest run -p p --test job\n  -E 'binary(harness) & test(/^alpha::/)'\n",
    )]
}

fn all_checks(model: &Model, policy: &Policy<'_>, texts: &[Text]) -> Vec<String> {
    let mut errors = check_set(model, policy);
    errors.extend(check_reasons(model, policy, texts));
    errors.extend(check_ceilings(policy));
    errors.extend(check_reach(model, policy));
    errors.extend(check_filters(model, policy, texts));
    errors.extend(check_harness_attrs(model, policy));
    errors.extend(check_cwd(model, policy));
    errors
}

/// `errors` holds exactly one refusal, and it says `needle`.
fn assert_refused(errors: &[String], needle: &str) {
    assert!(
        errors.len() == 1 && errors.iter().all(|e| e.contains(needle)),
        "expected one refusal naming {needle:?}, got:\n{}",
        errors.join("\n")
    );
}

#[test]
fn the_planted_tree_passes_every_check() {
    assert_clean(
        "planted",
        &all_checks(&good_model(), &good_policy(), &good_texts()),
    );
}

#[test]
fn an_extra_top_level_test_binary_is_refused() {
    let mut model = good_model();
    model.targets.push(target(
        "extra",
        "c/tests/extra.rs",
        &["c/tests/extra.rs"],
        &[],
    ));
    assert_refused(
        &check_set(&model, &good_policy()),
        "add it as a module of an existing harness",
    );
}

#[test]
fn a_stale_allowlist_entry_is_refused() {
    let mut model = good_model();
    model.targets.retain(|t| t.name != "job");
    assert_refused(&check_set(&model, &good_policy()), "drop the stale entry");
}

#[test]
fn a_dedicated_job_no_command_runs_is_refused() {
    let texts = [Text::new(
        ".github/workflows/ci.yml",
        "run: cargo nextest run -p p\n",
    )];
    assert_refused(
        &check_reasons(&good_model(), &good_policy(), &texts),
        "`DedicatedJob`",
    );
}

#[test]
fn a_dedicated_job_named_only_by_nextest_config_is_refused() {
    let texts = [Text::new(
        ".config/nextest.toml",
        "filter = 'binary(job)'\n",
    )];
    assert_refused(
        &check_reasons(&good_model(), &good_policy(), &texts),
        "`DedicatedJob`",
    );
}

#[test]
fn an_area_harness_with_a_flat_root_is_refused() {
    let mut model = good_model();
    if let Some(t) = model.targets.iter_mut().find(|t| t.name == "harness") {
        t.root = "c/tests/harness.rs".to_owned();
    }
    assert_refused(
        &check_reasons(&model, &good_policy(), &good_texts()),
        "`AreaHarness`",
    );
}

#[test]
fn a_foreign_target_without_its_wasm_line_is_refused() {
    const BINARIES: &[(&str, &str, Reason)] = &[
        ("p", "harness", Reason::AreaHarness),
        ("p", "job", Reason::ForeignTarget),
    ];
    let policy = Policy {
        binaries: BINARIES,
        ..good_policy()
    };
    assert_refused(
        &check_reasons(&good_model(), &policy, &good_texts()),
        "`ForeignTarget`",
    );
    let wasm = [Text::new(
        ".github/workflows/ci.yml",
        "run: cargo test --target wasm32-unknown-unknown --test job\n",
    )];
    assert_clean("foreign", &check_reasons(&good_model(), &policy, &wasm));
}

#[test]
fn a_ceiling_off_the_live_count_is_refused() {
    const BINARIES: &[(&str, &str, Reason)] = &[
        ("p", "harness", Reason::AreaHarness),
        ("p", "job", Reason::Unconsolidated),
    ];
    let policy = Policy {
        binaries: BINARIES,
        ceilings: &[("p", 2)],
        ..good_policy()
    };
    assert_refused(&check_ceilings(&policy), "ceiling is 2");
    let missing = Policy {
        binaries: BINARIES,
        ..good_policy()
    };
    assert_refused(&check_ceilings(&missing), "ceiling is 0");
}

#[test]
fn an_orphan_test_file_is_refused() {
    let mut model = good_model();
    model
        .tests_files
        .insert("c/tests/harness/beta.rs".to_owned());
    assert_refused(
        &check_reach(&model, &good_policy()),
        "reached by no test target",
    );
}

#[test]
fn a_file_compiled_by_two_targets_is_refused() {
    let mut model = good_model();
    if let Some(t) = model.targets.iter_mut().find(|t| t.name == "job") {
        t.files.insert(ALPHA.to_owned());
    }
    assert_refused(
        &check_reach(&model, &good_policy()),
        "compiled into 2 test targets",
    );
}

#[test]
fn a_shared_module_holding_a_test_is_refused() {
    let mut model = good_model();
    model.facts.insert(SUPPORT.to_owned(), tested());
    assert_refused(&check_reach(&model, &good_policy()), "holds a `#[test]`");
}

#[test]
fn stale_shared_and_data_entries_are_refused() {
    let mut model = good_model();
    if let Some(t) = model.targets.iter_mut().find(|t| t.name == "job") {
        t.files.remove(SUPPORT);
    }
    assert_refused(
        &check_reach(&model, &good_policy()),
        "fewer than two targets",
    );
    let mut model = good_model();
    model.tests_files.retain(|f| !f.starts_with(DATA));
    assert_refused(&check_reach(&model, &good_policy()), "holds no `.rs` file");
}

#[test]
fn a_binary_filter_naming_no_target_is_refused() {
    let texts = [Text::new(
        ".config/nextest.toml",
        "filter = 'binary(nope)'\n",
    )];
    assert_refused(
        &check_filters(&good_model(), &good_policy(), &texts),
        "`binary(nope)` names no test target",
    );
}

#[test]
fn a_module_filter_naming_a_missing_module_is_refused() {
    for filter in [
        "binary(harness) & test(/^missing::/)",
        "binary(harness) & test(=missing::one)",
    ] {
        let texts = [Text::new(
            ".config/nextest.toml",
            &format!("filter = '{filter}'\n"),
        )];
        assert_refused(
            &check_filters(&good_model(), &good_policy(), &texts),
            "module `missing`",
        );
    }
}

#[test]
fn a_test_flag_naming_no_target_is_refused() {
    let texts = [Text::new(
        "tools/scripts/run.sh",
        "cargo nextest run --test=gone\n",
    )];
    assert_refused(
        &check_filters(&good_model(), &good_policy(), &texts),
        "`--test gone`",
    );
    let unreadable = [Text::new(
        "tools/scripts/run.sh",
        "cargo nextest run --test \"$name\"\n",
    )];
    assert_refused(
        &check_filters(&good_model(), &good_policy(), &unreadable),
        "`--test `",
    );
}

#[test]
fn cargo_test_on_a_harness_is_refused() {
    let texts = [Text::new(
        ".github/workflows/ci.yml",
        "run: cargo test -p p --test harness\n",
    )];
    assert_refused(
        &check_filters(&good_model(), &good_policy(), &texts),
        "runs a harness's modules",
    );
}

#[test]
fn binary_patterns_are_checked_or_refused() {
    let live = [Text::new(
        ".github/workflows/ci.yml",
        "-E 'binary(/^har/) | binary(/ob$/) | binary({b})'\n",
    )];
    assert_clean(
        "pattern",
        &check_filters(&good_model(), &good_policy(), &live),
    );
    let dead = [Text::new(
        ".github/workflows/ci.yml",
        "-E 'binary(/_seal$/)'\n",
    )];
    assert_refused(
        &check_filters(&good_model(), &good_policy(), &dead),
        "matches no test target",
    );
    let opaque = [Text::new(
        ".github/workflows/ci.yml",
        "-E 'binary(/a.*b/)'\n",
    )];
    assert_refused(
        &check_filters(&good_model(), &good_policy(), &opaque),
        "anchored literal pattern",
    );
}

#[test]
fn the_shard_plan_reader_fails_closed() {
    let plan = "HEAVY_BINARIES = (\n    \"job\",\n)\n\
                OneTest(\"one\", \"harness\", \"t\"),\n\
                Binaries(\"pair\", (\"job\", \"gone\"), 2),\n";
    let texts = [Text::new(".github/ci/e2e_shard.py", plan)];
    assert_refused(
        &check_filters(&good_model(), &good_policy(), &texts),
        "`gone` names no test target",
    );
    let reshaped = [Text::new(
        ".github/ci/e2e_shard.py",
        "HEAVY = frozenset()\n",
    )];
    assert_refused(
        &check_filters(&good_model(), &good_policy(), &reshaped),
        "update the reader",
    );
}

#[test]
fn a_times_row_naming_nothing_live_is_refused() {
    let path = ".github/ci/e2e-shard-times.txt";
    let good = "# comment\np 3\np::job 1\np::bin/tool 2\np::harness alpha::t 4\n";
    assert_clean(
        "times",
        &check_filters(&good_model(), &good_policy(), &[Text::new(path, good)]),
    );
    for (row, needle) in [
        ("q 1", "`q` is not a workspace package"),
        ("p::gone 1", "`p::gone` names no test target"),
        ("p::harness missing::t 1", "no module `missing`"),
        ("p::job one", "is not `<binary-id> [<test>] <seconds>`"),
    ] {
        let texts = [Text::new(path, &format!("{row}\n"))];
        assert_refused(
            &check_filters(&good_model(), &good_policy(), &texts),
            needle,
        );
    }
}

#[test]
fn a_crate_only_attribute_below_a_harness_root_is_refused() {
    let mut model = good_model();
    let attrs = facts("#![recursion_limit = \"256\"]\n#![allow(dead_code)]\n").expect("parse");
    assert_eq!(attrs.crate_attrs, vec!["recursion_limit".to_owned()]);
    model.facts.insert(ALPHA.to_owned(), attrs);
    assert_refused(
        &check_harness_attrs(&model, &good_policy()),
        "`#![recursion_limit]`",
    );
}

#[test]
fn a_dead_test_path_literal_is_refused() {
    let found = vec![
        ("a.py".to_owned(), "src/x/tests/live.rs".to_owned()),
        ("a.py".to_owned(), "src/x/tests/x.rs".to_owned()),
    ];
    let exists = |l: &str| l == "src/x/tests/live.rs";
    assert_refused(
        &check_literals(&found, exists, &[]),
        "`src/x/tests/x.rs`, which does not exist",
    );
    assert_clean(
        "synthetic",
        &check_literals(&found, exists, &[("a.py", "src/x/tests/x.rs")]),
    );
}

#[test]
fn a_stale_synthetic_path_is_refused() {
    let found = vec![("a.py".to_owned(), "src/x/tests/live.rs".to_owned())];
    let exists = |l: &str| l == "src/x/tests/live.rs";
    assert_refused(
        &check_literals(&found, exists, &[("a.py", "src/x/tests/gone.rs")]),
        "no longer occurs",
    );
    assert_refused(
        &check_literals(&found, exists, &[("a.py", "src/x/tests/live.rs")]),
        "exists: drop the entry",
    );
}

#[test]
fn path_literals_match_only_test_file_paths() {
    let text = "\"src/x/tests/a.rs\" tools/y/tests/b/c.rs src/tests/top.rs \
                xsrc/z/tests/d.rs src/x/tests/e.txt src/x/tests/a-b.rs";
    assert_eq!(
        path_literals(text),
        vec!["src/x/tests/a.rs", "tools/y/tests/b/c.rs"]
    );
}

#[test]
fn set_current_dir_outside_a_process_global_state_target_is_refused() {
    let mut model = good_model();
    let planted = facts("fn f() { std::env::set_current_dir(\"/\").ok(); }").expect("parse");
    assert!(planted.cwd_ident);
    model.facts.insert(ALPHA.to_owned(), planted);
    assert_refused(
        &check_cwd(&model, &good_policy()),
        "`p::harness` calls `set_current_dir`",
    );
    let named = facts("const S: &str = \"std::env::set_current_dir\"; // set_current_dir\n")
        .expect("parse");
    assert!(!named.cwd_ident);
}

#[test]
fn a_process_global_state_target_that_no_longer_changes_directory_is_refused() {
    const BINARIES: &[(&str, &str, Reason)] = &[
        ("p", "harness", Reason::AreaHarness),
        ("p", "job", Reason::ProcessGlobalState),
    ];
    let policy = Policy {
        binaries: BINARIES,
        ..good_policy()
    };
    assert_refused(
        &check_reasons(&good_model(), &policy, &good_texts()),
        "`ProcessGlobalState`",
    );
}

#[test]
fn a_test_fn_is_seen_under_any_test_attribute_in_a_nested_module() {
    assert!(
        facts("mod m { #[tokio::test] async fn t() {} }")
            .expect("parse")
            .has_test
    );
    assert!(
        !facts("macro_rules! m { () => { #[test] fn t() {} } }")
            .expect("parse")
            .has_test
    );
}

#[test]
fn the_literal_walk_skips_only_the_directories_the_root_gitignore_names() {
    let dirs = IgnoredDirs::parse(
        "# c\n*.db\n**/target\n**/node_modules/\n/notes\ngraft\nplugins/\n!keep\nsrc/x/\n",
    );
    assert!(dirs.covers("notes", "notes"));
    assert!(
        !dirs.covers("tools/notes", "notes"),
        "a root-anchored entry skips the root directory only"
    );
    assert!(dirs.covers("src/ipe-cli/target", "target"));
    assert!(dirs.covers("a/node_modules", "node_modules"));
    assert!(dirs.covers("a/graft", "graft") && dirs.covers("plugins", "plugins"));
    assert!(
        !dirs.covers("src/x", "x"),
        "an entry with an inner `/` names no plain directory"
    );
    assert!(!dirs.covers("tests", "tests") && !dirs.covers("keep", "keep"));
}
