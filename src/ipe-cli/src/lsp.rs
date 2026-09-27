//! `ipe lsp` — the JSON-RPC-over-stdio language server subcommand.
//!
//! The server loop and every feature handler live in `ipe_lsp_server` /
//! `ipe_lsp_features`; this module supplies the one driver-side ingredient
//! the server cannot own — project resolution. [`DriverLoader`] routes
//! through the SAME manifest/sibling-discovery/stdlib-injection code path
//! `ipe build` and `ipe watch` use, so the module set the editor analyzes
//! can never diverge from the one the batch build compiles.

use std::path::Path;

use ipe_lsp_server::{LoadError, LoadedFile, LoadedProject, ProjectLoader};

use crate::{CliError, project, text, watch};

struct DriverLoader;

impl ProjectLoader for DriverLoader {
    fn load(
        &self,
        workspace_root: Option<&Path>,
        open_file: &Path,
        open_text: Option<&str>,
    ) -> Result<LoadedProject, LoadError> {
        // A workspace folder holding a manifest wins; otherwise resolve from
        // the opened file exactly like `ipe build <file.ipe>` would
        // (manifest walk-up, else sibling discovery). Manifest presence is a
        // `package.ipe` in the workspace root.
        let entry = workspace_root
            .filter(|root| project::manifest_in_dir(root).is_some())
            .map_or_else(|| open_file.to_path_buf(), Path::to_path_buf);
        let overlay = if entry == open_file { open_text } else { None };
        let resolved = watch::resolve_project_sources(&entry, overlay).map_err(|e| LoadError {
            detail: e.to_string(),
        })?;
        let mut sources = resolved.sources;
        let mut discovered = resolved.discovered;
        let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);
        // Load FFI catalog and inject installed-crate interface modules so the
        // LSP sees `Rust.<Crate>` bindings exactly as `ipe build` does
        // (CO-INCR-005). A missing/empty catalog is fine (no crates installed);
        // a tampered cache is surfaced as a `LoadError`.
        let ffi_injected = crate::ffi::prepare_ffi(&mut sources, &resolved.blame_path)
            .map_err(|e| LoadError {
                detail: e.to_string(),
            })
            .map(|p| p.injected)
            .unwrap_or_default();
        let files = sources
            .into_iter()
            .map(|(module, (path, text))| {
                let origin = if injected.contains(&module) {
                    ipe_canon::ModuleOrigin::EmbeddedStdlib
                } else if ffi_injected.contains(&module) {
                    ipe_canon::ModuleOrigin::FfiInterface
                } else {
                    ipe_canon::ModuleOrigin::User
                };
                (module, LoadedFile { path, text, origin })
            })
            .collect();
        Ok(LoadedProject {
            files,
            entry_module: resolved.entry_path,
        })
    }
}

/// `ipe lsp` — serve the Language Server Protocol over stdio until the
/// client disconnects.
///
/// # Errors
/// [`CliError`] on misuse (unexpected arguments) or a protocol-level
/// failure; never for a compile diagnostic (those flow to the editor).
pub fn run_lsp(rest: &[String]) -> Result<(), CliError> {
    if !rest.is_empty() {
        return Err(CliError::Usage(text::lsp_takes_no_arguments()));
    }
    ipe_lsp_server::run_stdio(&DriverLoader).map_err(|e| CliError::UsageOwned(text::lsp_failed(&e)))
}
