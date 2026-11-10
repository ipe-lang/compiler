#![forbid(unsafe_code)]
//! Pins that `CliError::Usage` is built only for command-line misuse.
//!
//! The dispatcher (`with_help_on_misuse`) pairs every `Usage` with the
//! command's help page, so a refusal about the project (its manifest, its
//! source layout, a foreign-declaration file) built as `Usage` tells the user
//! they mistyped an argument. Project refusals use `ProjectRefused`. This scan
//! parses every non-test item of `src/` and counts each expression that builds
//! the `Usage` variant, per file and enclosing function. The argv parser
//! (`cli_args.rs`, `help.rs`) is exempt by exact path; every other site is in
//! [`ADMITTED`] with why it is argument misuse, or in [`UNROUTED`] with why
//! neither `Usage` nor `ProjectRefused` is its route yet, and the count must
//! match exactly in both directions. [`UNROUTED`] only shrinks: a new site
//! lands as argument misuse, as a project refusal, or not at all.
//!
//! The variant is followed through every spelling that reaches it: a path
//! ending `CliError::Usage` (any prefix, `<CliError>::Usage` included),
//! `Self::Usage` inside an `impl` of `CliError`, a `type` alias or `use … as`
//! rename of `CliError` (to a fixpoint, crate-wide), a `use` of the variant
//! itself (renamed or not, re-exports followed), a glob `use CliError::*`, the
//! struct spelling `CliError::Usage { 0: … }`, the variant as a function value
//! (`.map_err(CliError::Usage)`), and every macro body: a body that parses as
//! expressions is visited as such, any other body is scanned token by token.
//! A `use CliError::{self as E}` renames the type; a glob of a module that
//! holds an imported variant binds it bare; an associated `type E = CliError`
//! is an alias; `<X as T>::E::Usage` names the variant through `E`; in a macro
//! body, a metavariable owner (`$t::Usage`) or a metavariable variant
//! (`CliError::$v`) is a site.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Meta, Token};

/// The error type whose variant is judged.
const ERROR_TYPE: &str = "CliError";

/// The judged variant.
const VARIANT: &str = "Usage";

/// The argv parser: every `Usage` it builds is command-line misuse by
/// construction, so these files are exempt by exact path under `src/`.
const ARGV_PARSER: &[&str] = &["cli_args.rs", "help.rs"];

/// Each `Usage` site outside the argv parser that is command-line misuse:
/// (file under `src/`, enclosing function, count, the misuse).
const ADMITTED: &[(&str, &str, usize, &str)] = &[
    (
        "audit.rs",
        "parse_audit_args",
        11,
        "a flag of `ipe package audit` that is unknown, repeated, valueless, or exclusive of another",
    ),
    (
        "audit.rs",
        "locate_manifest",
        1,
        "a path argument that names neither a directory nor a `package.ipe`",
    ),
    (
        "audit.rs",
        "set_format",
        2,
        "a repeated or contradictory output-format flag",
    ),
    (
        "diff.rs",
        "parse_version",
        1,
        "a version argument that does not parse as a version",
    ),
    (
        "diff.rs",
        "run_diff_with",
        1,
        "the wrong number of `ipe diff` arguments",
    ),
    (
        "doc.rs",
        "parse_doc_flags",
        14,
        "a flag of `ipe doc` that is unknown, repeated, valueless, or out of its mode",
    ),
    (
        "doc.rs",
        "parse_doc_with",
        5,
        "a flag or positional of `ipe doc --type` that is unknown or exclusive of another",
    ),
    (
        "doc.rs",
        "parse_port",
        2,
        "a `--port` value that is zero or not a port number",
    ),
    (
        "doc.rs",
        "parse_write_format",
        1,
        "a `--write` format word that names no format",
    ),
    (
        "doc.rs",
        "query_refused",
        1,
        "a query argument that is empty, too long, or carries a control character",
    ),
    (
        "ffi.rs",
        "run_rust",
        1,
        "an `ipe rust` subcommand that names none",
    ),
    (
        "fmt.rs",
        "FmtWalk::root",
        1,
        "a path argument that names nothing on disk",
    ),
    (
        "init.rs",
        "parse_init_args",
        3,
        "a flag or positional of `ipe init` that is valueless or contradicts another",
    ),
    (
        "init.rs",
        "parse_runtime_word",
        1,
        "a runtime word that names no runtime",
    ),
    (
        "init.rs",
        "parse_shape_word",
        1,
        "a shape word that names no shape",
    ),
    (
        "init.rs",
        "project_name_for",
        1,
        "a target path argument with no final name to call the project",
    ),
    (
        "lint.rs",
        "parse_lint_args",
        2,
        "more than one path argument, or `--fix` with a format flag",
    ),
    (
        "pkg.rs",
        "package_arg",
        1,
        "a missing package-name argument",
    ),
    (
        "pkg.rs",
        "parse_add_arg",
        2,
        "a missing or unparsable package-requirement argument",
    ),
    (
        "publish.rs",
        "locate_manifest",
        1,
        "a path argument that names neither a directory nor a `package.ipe`",
    ),
    (
        "publish.rs",
        "parse_args",
        2,
        "an unknown flag or more than one path argument",
    ),
    (
        "publish.rs",
        "take_value",
        1,
        "a flag given without its value",
    ),
    (
        "publisher.rs",
        "AttestedActor::parse",
        1,
        "a `--publisher` value that is not a GitHub login",
    ),
];

/// Each `Usage` site that is neither command-line misuse nor project state, so
/// its route is an open decision: (file under `src/`, enclosing function,
/// count, what it refuses).
const UNROUTED: &[(&str, &str, usize, &str)] = &[
    (
        "cargo_step.rs",
        "target_directory_within",
        3,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "doc.rs",
        "ambiguous_module_error",
        1,
        "a stdlib index, bundle, kernel table, or picker failure: neither an argument nor the project",
    ),
    (
        "doc.rs",
        "build_index",
        3,
        "a stdlib index, bundle, kernel table, or picker failure: neither an argument nor the project",
    ),
    (
        "doc.rs",
        "bundle_build_error",
        3,
        "a stdlib index, bundle, kernel table, or picker failure: neither an argument nor the project",
    ),
    (
        "doc.rs",
        "kernel_doc_error",
        1,
        "a stdlib index, bundle, kernel table, or picker failure: neither an argument nor the project",
    ),
    (
        "doc.rs",
        "open_picked",
        1,
        "a stdlib index, bundle, kernel table, or picker failure: neither an argument nor the project",
    ),
    (
        "doc.rs",
        "run_bundle_lookup",
        2,
        "an unknown kind prefix (argument) or a bundle failure (not an argument) in one site",
    ),
    (
        "doc.rs",
        "run_type_search",
        1,
        "a stdlib index, bundle, kernel table, or picker failure: neither an argument nor the project",
    ),
    (
        "doc_type_search.rs",
        "TypeSearchError::into_cli_error",
        2,
        "an invalid query (argument) or no match (not an argument) in one conversion",
    ),
    (
        "driver/build_pipeline.rs",
        "attribute_canon_errors",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/build_pipeline.rs",
        "build_held_into",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/build_pipeline.rs",
        "compile_prepared",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/build_pipeline.rs",
        "refuse_debugger_without_runtime_dep",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/build_pipeline.rs",
        "refuse_webview_off_web",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/build_pipeline.rs",
        "write_emitted_project",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "TargetRefusal::into_cli",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "admit_dev_build",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "bundle_wasm_pkg_with",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "copy_native_artifact",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "discover_manifest",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "emitted_bin_name",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "exec_program",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "gate_session",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "gate_session_ffi",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "gate_terminal_decision",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "prebuilt_artifact",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "refuse_bundle_target",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "refuse_client_host_run",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "planned_release",
        1,
        "the delivery words argv named have no release route",
    ),
    (
        "driver/commands.rs",
        "release_pipeline",
        4,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "replay_plan",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "resolve_delivery",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "resolve_session_plan",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "run_cli",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "run_explain",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "run_release_run",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "run_run_with_args",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands.rs",
        "wasm_artifact_path",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "BundleAssembler::assemble_desktop",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "BundleAssembler::assemble_mobile",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "BundleAssembler::gate_desktop",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "aggregate_entry_inferences",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "build_under_pinned_manifest",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "build_wasm_for_mobile",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "capabilities_in",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "download_installer",
        3,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "emit_permissions",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "installer_gate",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "pack_desktop",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "parse_audit_entry_args",
        6,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "run_audit_entry",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "run_installer",
        4,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "run_package",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "run_upgrade",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "run_validate_entry",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "validate_desktop_shape",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "validate_mobile_pack",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/commands_pkg.rs",
        "validate_mobile_shape",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/driver_error.rs",
        "CliError::from",
        2,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "driver/driver_error.rs",
        "CliError::manifest_entry_refused",
        1,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "ffi.rs",
        "InspectorFailure::into_cli_error",
        3,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "enforce_wrapper_capabilities",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "inspector_binary",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "install_registry_deps_for_project",
        6,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "install_wrapper",
        5,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "jail_limits",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "jail_path_refused",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "make_scratch_dir",
        2,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "merge_provides",
        3,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "run_add",
        6,
        "argument misuse, a refused manifest, and an aborted install in one command body",
    ),
    (
        "ffi.rs",
        "run_inspector_job",
        2,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "run_inspector_job_unsandboxed",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "run_install",
        10,
        "argument misuse, a refused manifest, and an inspector failure in one command body",
    ),
    (
        "ffi.rs",
        "run_manifest_bwrap_chunked",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "run_phase",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "run_remove",
        2,
        "argument misuse and a cache-delete failure in one command body",
    ),
    (
        "ffi.rs",
        "toolchain_binds_from",
        2,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "write_inspector_manifest",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "ffi.rs",
        "write_inspector_manifest_chunk",
        1,
        "an inspector, jail, toolchain, or scratch-space failure: neither an argument nor the project",
    ),
    (
        "fmt.rs",
        "hold_rewrite",
        1,
        "a formatting-run failure (nothing to format, a held-bytes ceiling, a racing write): neither an argument nor the project",
    ),
    (
        "fmt.rs",
        "run_fmt_inplace",
        1,
        "a formatting-run failure (nothing to format, a held-bytes ceiling, a racing write): neither an argument nor the project",
    ),
    (
        "fmt.rs",
        "write_rewrites",
        1,
        "a formatting-run failure (nothing to format, a held-bytes ceiling, a racing write): neither an argument nor the project",
    ),
    (
        "health.rs",
        "apply_config_edit",
        2,
        "a toolchain or tool-install failure: neither an argument nor the project",
    ),
    (
        "health.rs",
        "cargo_config_path_from",
        1,
        "a toolchain or tool-install failure: neither an argument nor the project",
    ),
    (
        "health.rs",
        "run_install",
        3,
        "a toolchain or tool-install failure: neither an argument nor the project",
    ),
    (
        "index.rs",
        "admission_precheck",
        4,
        "a registry-index entry refusal: neither an argument nor the project",
    ),
    (
        "index.rs",
        "validate_entry_file",
        1,
        "a registry-index entry refusal: neither an argument nor the project",
    ),
    (
        "init.rs",
        "runtime_choice",
        1,
        "an interactive answer that names no choice: neither an argument nor the project",
    ),
    (
        "init.rs",
        "wizard_shape",
        1,
        "an interactive answer that names no choice: neither an argument nor the project",
    ),
    (
        "lsp.rs",
        "run_lsp",
        2,
        "an argument given (argument) or the server failing (not an argument) in one command body",
    ),
    (
        "pack/mobile.rs",
        "materialise",
        1,
        "a bundle held under the build output that changed or cannot be policed: neither an argument nor the project",
    ),
    (
        "publish.rs",
        "build_fresh_entry",
        1,
        "a publish refusal mixing a flag, the git checkout, and registry policy",
    ),
    (
        "publish.rs",
        "compute_entry_draft",
        4,
        "a publish refusal mixing a flag, the git checkout, and registry policy",
    ),
    (
        "publish.rs",
        "fresh_needs_blessing",
        1,
        "a publish refusal mixing a flag, the git checkout, and registry policy",
    ),
    (
        "publish.rs",
        "refuse_rev_other_than_clean_head",
        1,
        "a publish refusal mixing a flag, the git checkout, and registry policy",
    ),
    (
        "publish.rs",
        "run_publish",
        2,
        "a publish refusal mixing a flag, the git checkout, and registry policy",
    ),
    (
        "registry.rs",
        "CliError::from",
        1,
        "an environment override that is not an `https://` base: neither an argument nor the project",
    ),
    (
        "run_sandbox.rs",
        "inject_floor_reference",
        2,
        "a refused sandbox profile or artifact: neither an argument nor the project",
    ),
    (
        "run_sandbox.rs",
        "strip_capfloor_block",
        1,
        "a refused sandbox profile or artifact: neither an argument nor the project",
    ),
    (
        "run_sandbox.rs",
        "verify_artifact_under",
        2,
        "a refused sandbox profile or artifact: neither an argument nor the project",
    ),
    (
        "watch.rs",
        "run_inner",
        4,
        "built in a file another lane owns; its route is decided there",
    ),
    (
        "watch.rs",
        "watch_runtime_dep",
        1,
        "the watch mirror of `refuse_debugger_without_runtime_dep`; it routes with that refusal",
    ),
];

/// One source file under scan: its path relative to `src/` (`/`-separated) and its text.
struct SourceFile {
    rel: String,
    text: String,
}

/// Whether `meta` holds only under `cfg(test)`.
fn test_only(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            let Ok(nested) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            else {
                return false;
            };
            if list.path.is_ident("all") {
                nested.iter().any(test_only)
            } else if list.path.is_ident("any") {
                !nested.is_empty() && nested.iter().all(test_only)
            } else {
                false
            }
        }
        Meta::NameValue(_) => false,
    }
}

/// Whether `attrs` compile the item only under `cfg(test)` (or mark a `#[test]`).
fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .meta
                    .require_list()
                    .ok()
                    .and_then(|list| syn::parse2::<Meta>(list.tokens.clone()).ok())
                    .is_some_and(|meta| test_only(&meta)))
    })
}

/// Every `.rs` file under `dir`, relative to `root`, sorted.
fn walk(root: &Path, dir: &Path, out: &mut Vec<SourceFile>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        paths.push(
            entry
                .map_err(|e| format!("entry of {}: {e}", dir.display()))?
                .path(),
        );
    }
    paths.sort();
    for path in paths {
        if path.is_dir() {
            walk(root, &path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push(SourceFile { rel, text });
        }
    }
    Ok(())
}

/// The directory a file's out-of-line child modules live in, relative to `src/`.
fn child_dir(rel: &str) -> String {
    let (dir, file) = rel.rsplit_once('/').unwrap_or(("", rel));
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    let is_root = matches!(file, "lib.rs" | "main.rs" | "mod.rs") || dir == "bin";
    match (is_root, dir.is_empty()) {
        (true, _) => dir.to_owned(),
        (false, true) => stem.to_owned(),
        (false, false) => format!("{dir}/{stem}"),
    }
}

/// The files of `child` declared in `dir`, as either `child.rs` or `child/mod.rs`.
fn child_files(dir: &str, child: &str) -> [String; 2] {
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    [
        format!("{prefix}{child}.rs"),
        format!("{prefix}{child}/mod.rs"),
    ]
}

/// Record every out-of-line `mod x;` under `items` declared in `dir`: each
/// child file is test-only when its declaration (or an enclosing one) is.
fn mark_children(
    items: &[syn::Item],
    dir: &str,
    test: bool,
    marks: &mut Vec<(String, bool)>,
) -> Result<(), String> {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module.attrs.iter().any(|attr| attr.path().is_ident("path")) {
            return Err(format!(
                "`#[path]` on `mod {}` in `{dir}`: the scan resolves module files by name only",
                module.ident
            ));
        }
        let child_test = test || is_test_only(&module.attrs);
        let name = module.ident.to_string();
        match &module.content {
            Some((_, inner)) => {
                let inner_dir = if dir.is_empty() {
                    name
                } else {
                    format!("{dir}/{name}")
                };
                mark_children(inner, &inner_dir, child_test, marks)?;
            }
            None => {
                for file in child_files(dir, &name) {
                    marks.push((file, child_test));
                }
            }
        }
    }
    Ok(())
}

/// The files compiled only under `cfg(test)`: reached from a crate root only
/// through a test-only `mod` declaration.
fn test_only_files(parsed: &BTreeMap<String, syn::File>) -> Result<BTreeSet<String>, String> {
    let mut test_files = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut queue: Vec<(String, bool)> = parsed
        .keys()
        .filter(|rel| {
            matches!(rel.as_str(), "lib.rs" | "main.rs")
                || rel
                    .strip_prefix("bin/")
                    .is_some_and(|rest| !rest.contains('/'))
        })
        .map(|rel| (rel.clone(), false))
        .collect();
    while let Some((rel, test)) = queue.pop() {
        let Some(file) = parsed.get(&rel) else {
            continue;
        };
        if !seen.insert(rel.clone()) {
            continue;
        }
        if test {
            test_files.insert(rel.clone());
        }
        let mut marks = Vec::new();
        mark_children(&file.items, &child_dir(&rel), test, &mut marks)?;
        queue.extend(marks);
    }
    let unreached: Vec<&String> = parsed.keys().filter(|rel| !seen.contains(*rel)).collect();
    if unreached.is_empty() {
        Ok(test_files)
    } else {
        Err(format!(
            "files no crate root reaches, so their cfg is unknown: {unreached:?}"
        ))
    }
}

/// One leaf of a `use` tree: the path before it, and what it imports.
enum UseLeaf {
    /// `prefix::name as alias` (alias == name when not renamed).
    Name {
        prefix: Vec<String>,
        name: String,
        alias: String,
    },
    /// `prefix::*`.
    Glob { prefix: Vec<String> },
}

/// The path and name one `use` leaf imports: `prefix::{self}` imports the
/// prefix's last segment itself.
fn named(prefix: &[String], ident: &syn::Ident) -> (Vec<String>, String) {
    match prefix.split_last() {
        Some((last, rest)) if ident == "self" => (rest.to_vec(), last.clone()),
        Some(_) | None => (prefix.to_vec(), ident.to_string()),
    }
}

/// Flatten `tree` under `prefix` into its leaves.
fn use_leaves(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<UseLeaf>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            use_leaves(&path.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let (prefix, name) = named(prefix, &name.ident);
            out.push(UseLeaf::Name {
                prefix,
                alias: name.clone(),
                name,
            });
        }
        syn::UseTree::Rename(rename) => {
            let (prefix, name) = named(prefix, &rename.ident);
            out.push(UseLeaf::Name {
                prefix,
                name,
                alias: rename.rename.to_string(),
            });
        }
        syn::UseTree::Glob(_) => out.push(UseLeaf::Glob {
            prefix: prefix.clone(),
        }),
        syn::UseTree::Group(group) => {
            for item in &group.items {
                use_leaves(item, prefix, out);
            }
        }
    }
}

/// Every `use` leaf and `type` alias of a file, macro-free, at any depth.
#[derive(Default)]
struct Imports {
    leaves: Vec<UseLeaf>,
    /// `type Name = Target` with `Target`'s last path segment.
    aliases: Vec<(String, String)>,
}

impl<'ast> Visit<'ast> for Imports {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        use_leaves(&item.tree, &mut Vec::new(), &mut self.leaves);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.alias(&item.ident, &item.ty);
        visit::visit_item_type(self, item);
    }

    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        self.alias(&item.ident, &item.ty);
        visit::visit_impl_item_type(self, item);
    }

    fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
        if let Some((_, ty)) = &item.default {
            self.alias(&item.ident, ty);
        }
        visit::visit_trait_item_type(self, item);
    }
}

impl Imports {
    /// Record `name = ty` when `ty` is a path.
    fn alias(&mut self, name: &syn::Ident, ty: &syn::Type) {
        if let syn::Type::Path(path) = ty
            && let Some(last) = path.path.segments.last()
        {
            self.aliases
                .push((name.to_string(), last.ident.to_string()));
        }
    }
}

/// The names that reach the judged variant.
struct Names {
    /// Names of the error type: itself, every `type` alias and every `use … as` rename.
    types: BTreeSet<String>,
    /// Per file: bare names bound to the variant by a `use`.
    variants: BTreeMap<String, BTreeSet<String>>,
}

/// Resolve every alias of the error type and of its variant, crate-wide, to a fixpoint.
fn names(imports: &BTreeMap<String, Imports>) -> Names {
    let mut types: BTreeSet<String> = BTreeSet::from([ERROR_TYPE.to_owned()]);
    // Names a `use` re-exports the variant under, crate-wide.
    let mut exported: BTreeSet<String> = BTreeSet::new();
    let mut variants: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    loop {
        let before = (types.len(), exported.len());
        for (rel, file) in imports {
            for (alias, target) in &file.aliases {
                if types.contains(target) {
                    types.insert(alias.clone());
                }
            }
            for leaf in &file.leaves {
                match leaf {
                    UseLeaf::Name {
                        prefix,
                        name,
                        alias,
                    } => {
                        if types.contains(name) {
                            types.insert(alias.clone());
                        }
                        let of_type = prefix.last().is_some_and(|last| types.contains(last));
                        if (of_type && name == VARIANT) || exported.contains(name) {
                            exported.insert(alias.clone());
                            variants
                                .entry(rel.clone())
                                .or_default()
                                .insert(alias.clone());
                        }
                    }
                    UseLeaf::Glob { prefix } => {
                        if prefix.last().is_some_and(|last| types.contains(last)) {
                            exported.insert(VARIANT.to_owned());
                            variants
                                .entry(rel.clone())
                                .or_default()
                                .insert(VARIANT.to_owned());
                        } else {
                            // A module glob may carry a name another file bound
                            // to the variant; it binds every such name here.
                            variants
                                .entry(rel.clone())
                                .or_default()
                                .extend(exported.iter().cloned());
                        }
                    }
                }
            }
        }
        if (types.len(), exported.len()) == before {
            return Names { types, variants };
        }
        // `variants` grows only from `types` and `exported`, both bounded by the
        // crate's finite names, so the loop reaches its fixpoint.
    }
}

/// The visitor counting each built variant in one file.
struct Count<'n> {
    names: &'n Names,
    /// The bare names bound to the variant in this file.
    bare: BTreeSet<String>,
    /// Whether each enclosing `impl` is an `impl` of the error type, innermost last.
    impls: Vec<(String, bool)>,
    /// The enclosing function label, outermost first.
    fns: Vec<String>,
    /// Sites counted by enclosing function.
    sites: BTreeMap<String, usize>,
}

impl Count<'_> {
    /// The enclosing function label, or `<item>` outside every function.
    fn site(&self) -> String {
        self.fns
            .first()
            .cloned()
            .unwrap_or_else(|| "<item>".to_owned())
    }

    /// Count one site.
    fn hit(&mut self) {
        *self.sites.entry(self.site()).or_insert(0) += 1;
    }

    /// Whether `Self` names the error type here.
    fn self_is_type(&self) -> bool {
        self.impls.last().is_some_and(|(_, of_type)| *of_type)
    }

    /// Whether `owner` (the segment before the variant) names the error type.
    fn owner_is_type(&self, owner: &str) -> bool {
        self.names.types.contains(owner) || (owner == "Self" && self.self_is_type())
    }

    /// Whether `qself` and `path` spell the judged variant.
    fn names_variant(&self, qself: Option<&syn::QSelf>, path: &syn::Path) -> bool {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        if let Some(qself) = qself {
            if segments.last().is_none_or(|l| l != VARIANT) {
                return false;
            }
            // `<X as T>::E::Usage` names the variant through `E`, the segment
            // before it; `<CliError>::Usage` through the qualified type itself.
            if let Some([.., owner, _]) = segments.get(qself.position..) {
                return self.owner_is_type(owner);
            }
            let syn::Type::Path(ty) = &*qself.ty else {
                return false;
            };
            let owner = ty
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            return self.owner_is_type(&owner);
        }
        match segments.as_slice() {
            [single] => self.bare.contains(single),
            [.., owner, last] => last == VARIANT && self.owner_is_type(owner),
            [] => false,
        }
    }

    /// Count the variant in a macro body read as tokens: `Owner :: Usage`, or a
    /// bare bound name.
    fn tokens(&mut self, tokens: TokenStream) {
        let mut previous: Vec<String> = Vec::new();
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    let qualified = matches!(
                        previous.as_slice(),
                        [.., owner, a, b] if a == ":" && b == ":" && name == VARIANT && self.owner_is_type(owner)
                    );
                    // `$t::Usage`: the owner is a metavariable the scan cannot
                    // resolve, so the variant's name alone makes it a site.
                    let metavariable_owner = matches!(
                        previous.as_slice(),
                        [.., dollar, _, a, b] if dollar == "$" && a == ":" && b == ":" && name == VARIANT
                    );
                    // `CliError::$v`: the variant is a metavariable, so any
                    // variant the type is built with here is a site.
                    let metavariable_variant = matches!(
                        previous.as_slice(),
                        [.., owner, a, b, dollar] if a == ":" && b == ":" && dollar == "$" && self.owner_is_type(owner)
                    );
                    let after_colons =
                        matches!(previous.as_slice(), [.., a, b] if a == ":" && b == ":");
                    if qualified
                        || metavariable_owner
                        || metavariable_variant
                        || (!after_colons && self.bare.contains(&name))
                    {
                        self.hit();
                    }
                    previous.push(name);
                }
                TokenTree::Group(group) => {
                    self.tokens(group.stream());
                    previous.push("<group>".to_owned());
                }
                TokenTree::Punct(punct) => previous.push(punct.as_char().to_string()),
                TokenTree::Literal(_) => previous.push("<lit>".to_owned()),
            }
        }
    }
}

/// `matches!`-shaped arguments: one scrutinee expression, then a pattern the scan skips.
fn scrutinee(input: syn::parse::ParseStream<'_>) -> syn::Result<syn::Expr> {
    let expr: syn::Expr = input.parse()?;
    let _: Token![,] = input.parse()?;
    let _: TokenStream = input.parse()?;
    Ok(expr)
}

impl<'ast> Visit<'ast> for Count<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[Attribute] = match item {
            syn::Item::Fn(item) => &item.attrs,
            syn::Item::Mod(item) => &item.attrs,
            syn::Item::Impl(item) => &item.attrs,
            syn::Item::Const(item) => &item.attrs,
            syn::Item::Static(item) => &item.attrs,
            syn::Item::Macro(item) => &item.attrs,
            syn::Item::Trait(item) => &item.attrs,
            _ => &[],
        };
        if !is_test_only(attrs) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let owner = match &*item.self_ty {
            syn::Type::Path(ty) => ty
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default(),
            _ => String::new(),
        };
        let of_type = self.names.types.contains(&owner);
        self.impls.push((owner, of_type));
        visit::visit_item_impl(self, item);
        self.impls.pop();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.fns.push(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.fns.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if is_test_only(&item.attrs) {
            return;
        }
        let owner = self
            .impls
            .last()
            .map(|(o, _)| o.clone())
            .unwrap_or_default();
        self.fns.push(format!("{owner}::{}", item.sig.ident));
        visit::visit_impl_item_fn(self, item);
        self.fns.pop();
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        if self.names_variant(expr.qself.as_ref(), &expr.path) {
            self.hit();
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
        if self.names_variant(expr.qself.as_ref(), &expr.path) {
            self.hit();
        }
        visit::visit_expr_struct(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let is_matches = mac
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "matches" || s.ident == "assert_matches");
        if is_matches && let Ok(expr) = scrutinee.parse2(mac.tokens.clone()) {
            self.visit_expr(&expr);
            return;
        }
        if let Ok(exprs) =
            Punctuated::<syn::Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone())
        {
            for expr in &exprs {
                self.visit_expr(expr);
            }
            return;
        }
        self.tokens(mac.tokens.clone());
    }
}

/// Every site building the variant outside test code: (file, function) -> count.
fn scan(files: &[SourceFile]) -> Result<BTreeMap<(String, String), usize>, String> {
    let mut parsed = BTreeMap::new();
    for file in files {
        let ast = syn::parse_file(&file.text).map_err(|e| format!("parse {}: {e}", file.rel))?;
        parsed.insert(file.rel.clone(), ast);
    }
    let test_files = test_only_files(&parsed)?;
    let mut imports = BTreeMap::new();
    for (rel, ast) in &parsed {
        let mut found = Imports::default();
        found.visit_file(ast);
        imports.insert(rel.clone(), found);
    }
    let names = names(&imports);
    let mut sites = BTreeMap::new();
    for (rel, ast) in &parsed {
        if test_files.contains(rel) {
            continue;
        }
        let mut count = Count {
            names: &names,
            bare: names.variants.get(rel).cloned().unwrap_or_default(),
            impls: Vec::new(),
            fns: Vec::new(),
            sites: BTreeMap::new(),
        };
        count.visit_file(ast);
        for (function, n) in count.sites {
            sites.insert((rel.clone(), function), n);
        }
    }
    Ok(sites)
}

/// The judged sites of `sites`: every site outside the argv parser.
fn judged(sites: BTreeMap<(String, String), usize>) -> BTreeMap<(String, String), usize> {
    sites
        .into_iter()
        .filter(|((rel, _), _)| !ARGV_PARSER.contains(&rel.as_str()))
        .collect()
}

/// Every `Usage` built outside the argv parser is an [`ADMITTED`] or
/// [`UNROUTED`] site, at its exact count, and every listed site still exists.
#[test]
fn usage_is_built_only_for_argument_misuse() {
    let root = e2e_support::manifest_dir!().join("src");
    let mut files = Vec::new();
    let walked = walk(&root, &root, &mut files);
    assert!(walked.is_ok(), "{walked:?}");
    for exempt in ARGV_PARSER {
        assert!(
            files.iter().any(|f| f.rel == *exempt),
            "the exempt argv parser `{exempt}` no longer exists"
        );
    }
    let sites = scan(&files);
    assert!(sites.is_ok(), "{sites:?}");
    let found = judged(sites.unwrap_or_default());
    let mut admitted: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (rel, function, count, why) in ADMITTED.iter().chain(UNROUTED) {
        assert!(
            !why.is_empty(),
            "{rel} {function}: an admission needs its why"
        );
        let prior = admitted.insert(((*rel).to_owned(), (*function).to_owned()), *count);
        assert!(prior.is_none(), "{rel} {function} is admitted twice");
    }
    let row =
        |((rel, function), n): (&(String, String), &usize)| format!("({rel:?}, {function:?}, {n})");
    let unadmitted: Vec<String> = found
        .iter()
        .filter(|(key, n)| admitted.get(*key) != Some(*n))
        .map(row)
        .collect();
    let stale: Vec<String> = admitted
        .iter()
        .filter(|(key, n)| found.get(*key) != Some(*n))
        .map(row)
        .collect();
    assert!(
        unadmitted.is_empty() && stale.is_empty(),
        "`CliError::Usage` prints the command's help page, so it is only for \
         command-line misuse; a refusal about the project is `ProjectRefused`.\n\
         built but not admitted (or at another count):\n{}\n\
         admitted but not built at that count:\n{}",
        unadmitted.join("\n"),
        stale.join("\n")
    );
}

/// The sites of one planted `src/` tree whose crate root is `lib.rs`.
fn planted(files: &[(&str, &str)]) -> BTreeMap<(String, String), usize> {
    let files: Vec<SourceFile> = files
        .iter()
        .map(|(rel, text)| SourceFile {
            rel: (*rel).to_owned(),
            text: (*text).to_owned(),
        })
        .collect();
    let sites = scan(&files);
    assert!(sites.is_ok(), "{sites:?}");
    sites.unwrap_or_default()
}

/// The count of one planted site.
fn site(sites: &BTreeMap<(String, String), usize>, rel: &str, function: &str) -> usize {
    sites
        .get(&(rel.to_owned(), function.to_owned()))
        .copied()
        .unwrap_or(0)
}

/// A planted `lib.rs` declaring module `a`, beside `a.rs` holding `body`.
fn in_module(body: &str) -> BTreeMap<(String, String), usize> {
    planted(&[("lib.rs", "mod a;\n"), ("a.rs", body)])
}

#[test]
fn a_qualified_construction_is_a_site() {
    let sites = in_module("fn f() -> E { crate::driver::CliError::Usage(m()) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_pattern_is_not_a_site() {
    let sites = in_module(
        "fn f(e: CliError) -> bool { if let CliError::Usage(_) = e { true } else { matches!(e, CliError::Usage(_)) } }",
    );
    assert_eq!(site(&sites, "a.rs", "f"), 0);
}

#[test]
fn self_inside_an_impl_of_the_error_type_is_a_site() {
    let sites = in_module(
        "impl CliError { fn g() -> Self { Self::Usage(m()) } }\nimpl Other { fn g() -> Self { Self::Usage(m()) } }",
    );
    assert_eq!(site(&sites, "a.rs", "CliError::g"), 1);
    assert_eq!(site(&sites, "a.rs", "Other::g"), 0);
}

#[test]
fn self_inside_a_trait_impl_for_the_error_type_is_a_site() {
    let sites =
        in_module("impl From<X> for CliError { fn from(x: X) -> Self { Self::Usage(m(x)) } }");
    assert_eq!(site(&sites, "a.rs", "CliError::from"), 1);
}

#[test]
fn a_qself_spelling_is_a_site() {
    let sites = in_module("fn f() -> E { <CliError>::Usage(m()) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_renamed_type_is_a_site() {
    let sites = in_module("use crate::CliError as E;\nfn f() -> E { E::Usage(m()) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_type_alias_in_another_file_is_a_site() {
    let sites = planted(&[
        ("lib.rs", "mod a;\nmod b;\npub type Failure = CliError;\n"),
        ("a.rs", "fn f() -> Failure { crate::Failure::Usage(m()) }"),
        ("b.rs", "pub type Again = crate::Failure;"),
    ]);
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn an_imported_variant_is_a_site() {
    let sites = in_module("use crate::CliError::Usage;\nfn f() -> E { Usage(m()) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_renamed_variant_is_a_site() {
    let sites = in_module("use crate::CliError::{Usage as Misuse};\nfn f() -> E { Misuse(m()) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_reexported_variant_is_a_site() {
    let sites = planted(&[
        (
            "lib.rs",
            "mod a;\npub use crate::CliError::Usage as Wrong;\n",
        ),
        (
            "a.rs",
            "use crate::Wrong as Again;\nfn f() -> E { Again(m()) }",
        ),
    ]);
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_self_rename_of_the_type_is_a_site() {
    let sites = in_module("use crate::CliError::{self as E};\nfn f() -> E { E::Usage(m()) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_module_glob_carrying_the_variant_is_a_site() {
    let sites = planted(&[
        ("lib.rs", "mod a;\nmod b;\n"),
        ("a.rs", "pub use crate::CliError::Usage;\n"),
        ("b.rs", "use crate::a::*;\nfn f() -> E { Usage(m()) }"),
    ]);
    assert_eq!(site(&sites, "b.rs", "f"), 1);
}

#[test]
fn a_name_reexported_from_a_type_glob_is_a_site() {
    let sites = planted(&[
        ("lib.rs", "mod a;\nmod b;\n"),
        ("a.rs", "pub use crate::CliError::*;\n"),
        ("b.rs", "use crate::a::Usage;\nfn f() -> E { Usage(m()) }"),
    ]);
    assert_eq!(site(&sites, "b.rs", "f"), 1);
}

#[test]
fn an_associated_type_alias_is_a_site() {
    let sites =
        in_module("impl T for X { type E = CliError; }\nfn f() -> R { <X as T>::E::Usage(m()) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_metavariable_owner_in_a_macro_is_a_site() {
    let sites = in_module("macro_rules! refuse { ($t:ident) => { $t::Usage(m()) }; }");
    assert_eq!(site(&sites, "a.rs", "<item>"), 1);
}

#[test]
fn a_metavariable_variant_in_a_macro_is_a_site() {
    let sites = in_module("macro_rules! refuse { ($v:ident) => { CliError::$v(m()) }; }");
    assert_eq!(site(&sites, "a.rs", "<item>"), 1);
}

#[test]
fn a_glob_import_of_the_variants_is_a_site() {
    let sites = in_module("use crate::CliError::*;\nfn f() -> E { Usage(m()) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_bare_name_without_an_import_is_not_a_site() {
    let sites = in_module("fn f() -> Usage { Usage { bytes: 0 } }");
    assert_eq!(site(&sites, "a.rs", "f"), 0);
}

#[test]
fn the_struct_spelling_is_a_site() {
    let sites = in_module("fn f() -> E { CliError::Usage { 0: m() } }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn the_variant_as_a_function_value_is_a_site() {
    let sites = in_module("fn f(r: R) -> Result<(), E> { r.map_err(CliError::Usage) }");
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn a_construction_inside_a_macro_is_a_site() {
    let sites = in_module(
        "fn f() { g(vec![CliError::Usage(m())]); h(format!(\"{}\", CliError::Usage(m()))); k![CliError::Usage(m()); 2]; }",
    );
    assert_eq!(site(&sites, "a.rs", "f"), 3);
}

#[test]
fn a_macro_rules_body_is_a_site() {
    let sites = in_module("macro_rules! refuse { () => { CliError::Usage(m()) }; }");
    assert_eq!(site(&sites, "a.rs", "<item>"), 1);
}

#[test]
fn test_code_is_not_judged() {
    let sites = planted(&[
        ("lib.rs", "mod a;\n#[cfg(test)]\nmod t;\n"),
        (
            "a.rs",
            "#[cfg(test)]\nmod tests { fn f() -> E { CliError::Usage(m()) } }\n#[test]\nfn g() { CliError::Usage(m()); }\nfn h() -> E { CliError::Usage(m()) }",
        ),
        ("t.rs", "fn f() -> E { CliError::Usage(m()) }"),
    ]);
    assert_eq!(site(&sites, "a.rs", "tests"), 0);
    assert_eq!(site(&sites, "a.rs", "g"), 0);
    assert_eq!(site(&sites, "a.rs", "f"), 0);
    assert_eq!(site(&sites, "t.rs", "f"), 0);
    assert_eq!(site(&sites, "a.rs", "h"), 1);
}

#[test]
fn a_feature_gated_module_is_judged() {
    let sites = planted(&[
        ("lib.rs", "#[cfg(any(test, feature = \"x\"))]\nmod a;\n"),
        ("a.rs", "fn f() -> E { CliError::Usage(m()) }"),
    ]);
    assert_eq!(site(&sites, "a.rs", "f"), 1);
}

#[test]
fn an_unreached_file_is_refused() {
    let files = [
        SourceFile {
            rel: "lib.rs".to_owned(),
            text: String::new(),
        },
        SourceFile {
            rel: "stray.rs".to_owned(),
            text: "fn f() -> E { CliError::Usage(m()) }".to_owned(),
        },
    ];
    assert!(scan(&files).is_err());
}

#[test]
fn the_argv_parser_is_exempt_and_nothing_else() {
    let sites = planted(&[
        ("lib.rs", "mod cli_args;\nmod a;\n"),
        ("cli_args.rs", "fn f() -> E { CliError::Usage(m()) }"),
        ("a.rs", "fn f() -> E { CliError::Usage(m()) }"),
    ]);
    let judged = judged(sites);
    assert_eq!(judged.len(), 1, "{judged:?}");
    assert_eq!(site(&judged, "a.rs", "f"), 1);
}
