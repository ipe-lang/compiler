#![forbid(unsafe_code)]
//! `ipe` — the command-line driver.
//!
//! Wires the pipeline end to end: read a `.ipe` entry file, run it through
//! [`ipe_parse`] → [`ipe_canon`] → [`ipe_types`] → [`ipe_lower`] → the
//! [`ipe_backend_rust`] emitter, write the emitted Cargo project, and vendor the
//! Ipe runtime module tree into it (a port of the copy step in the Haskell
//! compiler's `Ipe.Generate.Rust.Project`).
//!
//! Generated Rust projects do not depend on the runtime as a Cargo path crate;
//! instead `main.rs` declares `mod ipe_runtime;` and the runtime sources are
//! copied in beside it. The driver therefore must locate
//! `src/runtime/rust/src/` (the in-repo copy) and vendor it under
//! `<out>/src/ipe_runtime/`.
//!
//! Errors are typed ([`CliError`]); no operation panics or unwraps.

pub mod advisory;
pub mod api_surface;
pub mod audit;
pub mod audit_native;
pub mod build_plan;
mod cache;
pub mod clean;
pub mod cli_args;
pub mod cli_docs;
pub mod cli_transcript;
pub mod contained_path;
pub mod control_model_consent;
pub mod coverage;
pub mod delivery;
pub mod delivery_set;
pub mod diff;
pub mod doc;
pub mod doc_bundle;
pub mod doc_type_search;
pub mod ffi;
pub mod fmt;
pub mod health;
pub mod help;
pub mod hot_classify;
pub mod index;
pub mod init;
pub mod io_bounded;
pub mod lint;
pub mod lockfile;
pub mod login;
mod lsp;
pub mod machine_output;
pub mod migrate;
pub mod native_ffi_consent;
pub mod net;
pub mod pack;
pub mod package_manifest;
pub mod package_name;
pub mod pkg;
pub mod progress;
pub mod project;
pub mod publish;
pub mod publisher;
pub mod registry;
pub mod resolve;
pub mod run_sandbox;
pub mod runtime_embed;
pub mod scratch;
pub mod signing;
pub mod style;
pub mod toolchain;
pub mod unsafe_ack;
pub mod version_check;
pub mod wasi_run;
pub mod web_consent;
/// The embedded Ipê standard-library source now lives in the dependency-free
/// [`ipe_stdlib`] leaf crate so the WebAssembly frontend can share one copy.
/// Re-exported here so `crate::stdlib::…` call sites resolve unchanged.
pub use ipe_stdlib as stdlib;
pub mod watch;

pub(crate) use std::collections::{BTreeMap, BTreeSet};
pub(crate) use std::fs;
pub(crate) use std::io::Write;
pub(crate) use std::path::{Path, PathBuf};

pub(crate) use ipe_diagnostics::{
    ALL_CODES, Applicability, Diagnostic, HelpLine, Suggestion, explain_page, render, render_json,
    title,
};
pub(crate) use ipe_intern::Interner;

mod driver;

pub use driver::{
    AdvisoryVulnerablePayload, BuildOptions, CliError, INSTALL_SH_URL, RuntimeContext, apply_fixes,
    bluegreen_enabled, build, build_project, build_project_with_options, build_with_options,
    build_with_sibling_discovery, build_with_sibling_discovery_with_options, code_index,
    compile_prepared, create_source_root, emit_ir_text, explain_lookup, hot_appearance_enabled,
    infer_package_capabilities, resolve_runtime, run_cli, run_upgrade, runtime_dep_from_env,
    select_non_overlapping, verify_capabilities, watch_banner_enabled,
};
// Crate-internal driver items reached as `crate::…` by sibling modules
// (`watch`, `pkg`, …). Kept `pub(crate)` so no originally-private helper widens
// to public API; the block above re-exports the genuine public surface as `pub`.
pub(crate) use driver::{
    build_source_graph, capabilities_including_served_widgets, default_entry,
    find_manifest_for_ipe_file, force_cargo_terminal_ui, io_err, lower_entry_via_graph,
    read_progress_chunk, read_yes_no, read_yes_no_default, resolve_vendored_runtime_dir, run_build,
    run_capabilities, run_debugger, run_eject, run_exec, run_fix, run_installer, run_package,
    run_release, run_run, run_test, run_type_check, run_verify, run_version, run_watch,
    typecheck_entry_via_graph, write_atomic, write_emitted_project,
};
