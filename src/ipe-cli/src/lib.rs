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
mod cargo_step;
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
pub mod env_dir;
pub mod ffi;
pub mod fmt;
pub mod health;
pub mod help;
pub mod help_page;
pub mod hot_classify;
pub mod index;
pub mod init;
pub mod io_bounded;
pub mod lint;
pub mod lockfile;
pub mod login;
pub mod loose_file;
mod lsp;
pub mod machine_output;
pub mod native_ffi_consent;
pub mod net;
pub mod output_dir;
pub mod owner_trust;
pub mod pack;
pub mod package_manifest;
pub mod package_name;
pub mod pkg;
pub mod progress;
pub mod project;
pub mod proven_dir;
pub mod publish;
pub mod published_version;
pub mod publisher;
pub mod registry;
pub mod remote_ingest;
pub mod resolve;
pub mod run_sandbox;
pub mod runtime_embed;
pub mod scratch;
pub mod screen;
pub mod secret_file;
pub mod signing;
pub mod ssh_signing_key;
pub mod style;
#[cfg(unix)]
mod terminate;
pub mod text;
pub mod threads;
pub mod toolchain;
pub mod unsafe_ack;
pub mod verb;
pub mod version_check;
pub mod wasi_run;
pub mod web_consent;
pub mod wrapper_source;
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

// The type checker's interpolable scalar set and the runtime's sealed
// `IpeInterpolate` impl set name the same types in the same order: a drift
// breaks this crate's build instead of reaching an emitted `cargo` E0277.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the interpolable set drifts from the runtime's sealed impl set, the interpolation SEAL [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    names_eq(
        &ipe_diagnostics::INTERPOLABLE_TYPES,
        &ipe_runtime_rust::stringify::INTERPOLABLE_IPE_TYPES,
    ),
    "the interpolable scalar set must match the runtime's IpeInterpolate impls"
);

// The compiler's show-leaf table and the runtime's show-row table name the
// same leaves with the same policies in the same order, and agree on the
// widest rendered tuple: a leaf the compiler shows is a leaf the runtime
// renders, and a drift on either side breaks this crate's build instead of
// reaching an emitted `cargo` E0277.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the show-leaf table drifts from the runtime's show rows, the stringify SEAL [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    shown_eq(
        &ipe_ir::SHOWN_LEAVES,
        &ipe_runtime_rust::stringify::SHOWN_RUNTIME_TYPES,
    ) && ipe_ir::MAX_SHOWN_TUPLE_ARITY == ipe_runtime_rust::stringify::MAX_SHOWN_TUPLE_ARITY
        && ipe_types::MAX_SHOWN_TUPLE_ARITY == ipe_ir::MAX_SHOWN_TUPLE_ARITY,
    "the compiler's show leaves must match the runtime's show rows"
);

/// Ordered element-wise equality of the two show tables, name and policy tag, in one pass.
const fn shown_eq(
    compiler: &[(&str, ipe_ir::ShowPolicy)],
    runtime: &[(&str, ipe_runtime_rust::stringify::ShowPolicy)],
) -> bool {
    let (mut a, mut b) = (compiler, runtime);
    loop {
        match (a, b) {
            ([], []) => return true,
            ([(x, p), a_rest @ ..], [(y, q), b_rest @ ..]) => {
                if !text::bytes_eq(x.as_bytes(), y.as_bytes()) || p.tag() != q.tag() {
                    return false;
                }
                a = a_rest;
                b = b_rest;
            }
            _ => return false,
        }
    }
}

/// Element-wise `&str`-slice equality in a `const` context.
const fn names_eq(a: &[&str], b: &[&str]) -> bool {
    match (a, b) {
        ([], []) => true,
        ([x, a_rest @ ..], [y, b_rest @ ..]) => {
            text::bytes_eq(x.as_bytes(), y.as_bytes()) && names_eq(a_rest, b_rest)
        }
        _ => false,
    }
}

mod driver;

pub use driver::{
    AdvisoryVulnerablePayload, BuildOptions, CliError, INSTALL_SH_URL, PackageSourceSet,
    RuntimeContext, UPGRADE_TAG_FILE_ENV, UPGRADE_WRAPPED_ENV, apply_fixes, bluegreen_enabled,
    build, build_loose_file, build_loose_file_with_options, build_project,
    build_project_with_options, build_with_options, code_index, compile_prepared,
    create_source_root, emit_ir_text, explain_lookup, front_check_entry, hot_appearance_enabled,
    infer_package_capabilities, infer_package_capabilities_in, resolve_runtime, run_cli,
    run_upgrade, runtime_dep_from_env, select_non_overlapping, verify_capabilities,
    watch_banner_enabled,
};
// Crate-internal driver items reached as `crate::…` by sibling modules
// (`watch`, `pkg`, …). Kept `pub(crate)` so no originally-private helper widens
// to public API; the block above re-exports the genuine public surface as `pub`.
pub(crate) use driver::{
    DevMarkedCrate, RewriteKind, build_source_graph, capabilities_including_served_widgets,
    default_entry, find_manifest_for_ipe_file, force_cargo_terminal_ui, io_err,
    lower_entry_via_graph, read_progress_chunk, read_yes_no, read_yes_no_default,
    resolve_vendored_runtime_dir, rewrite_user_file, rewrite_walked_file, run_capabilities,
    run_fix, run_installer, run_package, run_test, run_type_check, run_verify, run_version,
    typecheck_entry_via_graph, write_emitted_project,
};
