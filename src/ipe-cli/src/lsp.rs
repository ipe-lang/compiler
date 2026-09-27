//! `ipe lsp` — the JSON-RPC-over-stdio language server subcommand.
//!
//! The server loop and every feature handler live in `ipe_lsp_server` /
//! `ipe_lsp_features`; this module supplies the one driver-side ingredient
//! the server cannot own — project resolution. [`DriverLoader`] first
//! classifies the opened document as a [`ProjectRoot`]. A package routes
//! through the SAME manifest-discovery/stdlib-injection code path `ipe build`
//! and `ipe watch` use, so the module set the editor analyzes can never
//! diverge from the one the batch build compiles. A loose file (no
//! `package.ipe` above it) loads alone plus the sibling modules its imports
//! name — the directory holding it is never listed, so opening a file in
//! `/tmp` or `$HOME` reads nothing unrelated to it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ipe_intern::{Interner, Symbol};
use ipe_lsp_server::{LoadError, LoadedFile, LoadedProject, ProjectLoader};

use crate::{CliError, io_bounded, project, text, watch};

/// Upper bound on the user modules a loose-file load follows through imports.
const MAX_LOOSE_FILE_MODULES: usize = 256;

/// Where an opened document's project is rooted.
#[derive(Clone, PartialEq, Eq, Debug)]
enum ProjectRoot {
    /// A package directory holding a `package.ipe` manifest.
    Package(PathBuf),
    /// A file under no manifest, analysed alone plus the siblings it imports.
    LooseFile(PathBuf),
}

impl ProjectRoot {
    /// Classify `open_file` by its nearest `package.ipe`.
    ///
    /// A workspace folder holding a manifest wins; otherwise the manifest
    /// walk-up from the file decides (it probes one `package.ipe` path per
    /// ancestor and lists no directory).
    fn of(workspace_root: Option<&Path>, open_file: &Path) -> Self {
        workspace_root
            .filter(|root| project::manifest_in_dir(root).is_some())
            .map(Path::to_path_buf)
            .or_else(|| {
                crate::find_manifest_for_ipe_file(open_file)
                    .and_then(|manifest| manifest.parent().map(Path::to_path_buf))
            })
            .map_or_else(|| Self::LooseFile(open_file.to_path_buf()), Self::Package)
    }
}

/// The user modules one project root resolves to, before stdlib and FFI injection.
struct UserSources {
    sources: BTreeMap<Vec<String>, (PathBuf, String)>,
    discovered: Vec<project::DiscoveredModule>,
    entry_module: Vec<String>,
    blame_path: PathBuf,
}

/// Resolve the user modules of `root`.
///
/// `open_text` shadows the loose file's disk bytes; a package reads disk
/// only (its layout comes from the manifest, not the open buffer).
fn resolve_user_sources(
    root: &ProjectRoot,
    open_text: Option<&str>,
) -> Result<UserSources, CliError> {
    match root {
        ProjectRoot::Package(dir) => {
            let resolved = watch::resolve_project_sources(dir, None)?;
            Ok(UserSources {
                sources: resolved.sources,
                discovered: resolved.discovered,
                entry_module: resolved.entry_path,
                blame_path: resolved.blame_path,
            })
        }
        ProjectRoot::LooseFile(file) => resolve_loose_file(file, open_text, MAX_LOOSE_FILE_MODULES),
    }
}

/// Load a loose file plus the transitive closure of sibling modules it imports.
///
/// An import `A.B` resolves to `<dir>/A/B.ipe`, where `<dir>` is the file's
/// directory; only that one path is probed, and only a regular file that
/// canonicalizes inside `<dir>` is read. An import with no such file (the
/// stdlib, a typo) is left for the analysis to resolve or report. A sibling
/// that fails to parse is still loaded — the analysis reports its errors —
/// but contributes no further imports.
///
/// # Errors
/// [`CliError::Pipeline`] when the entry does not parse; [`CliError::Io`]
/// when a probed module cannot be read; [`CliError::DiscoveryLimitReached`]
/// when the import closure exceeds `module_limit` modules.
fn resolve_loose_file(
    entry: &Path,
    entry_text: Option<&str>,
    module_limit: usize,
) -> Result<UserSources, CliError> {
    let entry_source = match entry_text {
        Some(text) => text.to_owned(),
        None => io_bounded::read_to_string_capped(entry, io_bounded::SOURCE_READ_CAP)?,
    };
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(&entry_source, &mut interner).map_err(|diag| {
        CliError::Pipeline {
            file: entry.to_path_buf(),
            src: entry_source.clone(),
            diag: Box::new(diag),
        }
    })?;
    let entry_module = module_segments(&parsed.name.value, &interner);
    let mut pending = imported_modules(&parsed, &interner);
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(entry_module.clone(), (entry.to_path_buf(), entry_source));

    if let Some(source_dir) = entry.parent().and_then(|dir| fs::canonicalize(dir).ok()) {
        while let Some(module) = pending.pop() {
            if sources.contains_key(&module) {
                continue;
            }
            let Some(path) = sibling_module_file(&source_dir, &module) else {
                continue;
            };
            if sources.len() >= module_limit {
                return Err(CliError::DiscoveryLimitReached {
                    detail: format!(
                        "`{}` imports more than {module_limit} sibling modules",
                        entry.display()
                    ),
                });
            }
            let source = io_bounded::read_to_string_capped(&path, io_bounded::SOURCE_READ_CAP)?;
            if let Ok(parsed) = ipe_parse::parse_module(&source, &mut interner) {
                pending.extend(imported_modules(&parsed, &interner));
            }
            sources.insert(module, (path, source));
        }
    }

    let discovered = sources
        .iter()
        .map(|(module, (path, _))| project::DiscoveredModule {
            path: path.clone(),
            module_path: module.clone(),
        })
        .collect();
    Ok(UserSources {
        sources,
        discovered,
        entry_module,
        blame_path: entry.to_path_buf(),
    })
}

/// The on-disk file for sibling `module` under the canonical `source_dir`.
///
/// `None` unless every segment is a module segment and the path is a regular
/// file (not a symlink) that canonicalizes inside `source_dir`.
fn sibling_module_file(source_dir: &Path, module: &[String]) -> Option<PathBuf> {
    if module.is_empty()
        || !module
            .iter()
            .all(|segment| project::is_module_segment(segment))
    {
        return None;
    }
    let mut path = source_dir.to_path_buf();
    path.extend(module);
    path.set_extension("ipe");
    let is_regular_file = fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_file());
    let is_contained =
        fs::canonicalize(&path).is_ok_and(|canonical| canonical.starts_with(source_dir));
    (is_regular_file && is_contained).then_some(path)
}

/// Every module path `parsed` imports.
fn imported_modules(parsed: &ipe_syntax::Module, interner: &Interner) -> Vec<Vec<String>> {
    parsed
        .imports
        .iter()
        .map(|import| module_segments(&import.name.value, interner))
        .collect()
}

/// Render interned module-name segments as strings.
fn module_segments(symbols: &[Symbol], interner: &Interner) -> Vec<String> {
    symbols
        .iter()
        .map(|symbol| interner.resolve(*symbol).unwrap_or_default().to_owned())
        .collect()
}

/// Render a driver failure as the server's load error.
fn load_error(err: &CliError) -> LoadError {
    LoadError {
        detail: err.to_string(),
    }
}

struct DriverLoader;

impl ProjectLoader for DriverLoader {
    fn load(
        &self,
        workspace_root: Option<&Path>,
        open_file: &Path,
        open_text: Option<&str>,
    ) -> Result<LoadedProject, LoadError> {
        let root = ProjectRoot::of(workspace_root, open_file);
        let UserSources {
            mut sources,
            mut discovered,
            entry_module,
            blame_path,
        } = resolve_user_sources(&root, open_text).map_err(|e| load_error(&e))?;
        let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);
        // Load the FFI catalog and inject installed-crate interface modules so
        // the LSP sees `Rust.<Crate>` bindings exactly as `ipe build` does. A
        // missing/empty catalog is fine (no crates installed); a tampered
        // cache is surfaced as a `LoadError`.
        let ffi_injected = crate::ffi::prepare_ffi(&mut sources, &blame_path)
            .map_err(|e| load_error(&e))?
            .injected;
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
            entry_module,
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{CliError, MAX_LOOSE_FILE_MODULES, ProjectRoot, UserSources, resolve_loose_file};

    /// A fresh, canonical scratch directory unique to `name` and this process.
    #[allow(clippy::expect_used)] // test fixture: an unwritable temp dir IS the failure
    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ipe-lsp-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        fs::canonicalize(&dir).expect("canonical scratch dir")
    }

    #[allow(clippy::expect_used)] // test fixture: an unwritable temp dir IS the failure
    fn write(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dir");
        }
        fs::write(path, text).expect("write fixture file");
    }

    fn user_modules(loaded: &UserSources) -> Vec<Vec<String>> {
        loaded.sources.keys().cloned().collect()
    }

    fn module(segments: &[&str]) -> Vec<String> {
        segments.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn loose_file_beside_unreadable_directories_loads_alone() {
        let dir = scratch_dir("loose-unreadable");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain = Io.println \"hi\"\n",
        );
        // Unrelated neighbours: a sibling module nobody imports and a
        // directory the server may not read (a systemd-private dir in `/tmp`).
        write(
            &dir.join("Other.ipe"),
            "module Other exposing (x)\n\nx = 1\n",
        );
        let locked = dir.join("locked");
        write(
            &locked.join("Hidden.ipe"),
            "module Hidden exposing (y)\n\ny = 2\n",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))
                .expect("lock the unrelated directory");
        }

        let loaded = resolve_loose_file(&entry, None, MAX_LOOSE_FILE_MODULES);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));
        }
        let _ = fs::remove_dir_all(&dir);
        let loaded = loaded.expect("a loose file loads without listing its directory");
        assert_eq!(user_modules(&loaded), vec![module(&["Main"])]);
        assert_eq!(loaded.entry_module, module(&["Main"]));
        assert_eq!(loaded.blame_path, entry);
    }

    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn loose_file_follows_the_sibling_modules_it_imports() {
        let dir = scratch_dir("loose-imports");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Helper\nimport Ipe.Io as Io\n\nmain = Io.println Helper.greeting\n",
        );
        write(
            &dir.join("Helper.ipe"),
            "module Helper exposing (greeting)\n\nimport Lib.Util\n\ngreeting = Lib.Util.word\n",
        );
        write(
            &dir.join("Lib").join("Util.ipe"),
            "module Lib.Util exposing (word)\n\nword = \"hi\"\n",
        );
        write(
            &dir.join("Unused.ipe"),
            "module Unused exposing (z)\n\nz = 3\n",
        );

        let loaded = resolve_loose_file(&entry, None, MAX_LOOSE_FILE_MODULES);
        let _ = fs::remove_dir_all(&dir);
        let loaded = loaded.expect("imported siblings resolve");
        assert_eq!(
            user_modules(&loaded),
            vec![
                module(&["Helper"]),
                module(&["Lib", "Util"]),
                module(&["Main"])
            ]
        );
        assert_eq!(loaded.discovered.len(), 3);
    }

    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn open_buffer_imports_drive_the_loose_file_closure() {
        let dir = scratch_dir("loose-overlay");
        let entry = dir.join("Main.ipe");
        write(&entry, "module Main exposing (main)\n\nmain = 1\n");
        write(
            &dir.join("Helper.ipe"),
            "module Helper exposing (x)\n\nx = 1\n",
        );
        let buffer = "module Main exposing (main)\n\nimport Helper\n\nmain = Helper.x\n";

        let loaded = resolve_loose_file(&entry, Some(buffer), MAX_LOOSE_FILE_MODULES);
        let _ = fs::remove_dir_all(&dir);
        let loaded = loaded.expect("overlay entry loads");
        assert_eq!(
            user_modules(&loaded),
            vec![module(&["Helper"]), module(&["Main"])]
        );
        assert_eq!(
            loaded
                .sources
                .get(&module(&["Main"]))
                .map(|(_, text)| text.as_str()),
            Some(buffer)
        );
    }

    #[test]
    fn loose_file_import_closure_past_the_module_limit_is_refused() {
        let dir = scratch_dir("loose-limit");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport A\n\nmain = A.a\n",
        );
        write(
            &dir.join("A.ipe"),
            "module A exposing (a)\n\nimport B\n\na = B.b\n",
        );
        write(&dir.join("B.ipe"), "module B exposing (b)\n\nb = 1\n");

        let at_limit = resolve_loose_file(&entry, None, 3);
        let past_limit = resolve_loose_file(&entry, None, 2);
        let _ = fs::remove_dir_all(&dir);
        assert!(at_limit.is_ok(), "three modules fit a limit of three");
        assert!(
            matches!(past_limit, Err(CliError::DiscoveryLimitReached { .. })),
            "a closure one module past the limit is refused"
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // a load failure IS the regression under test
    fn loose_file_never_follows_an_import_symlinked_out_of_its_directory() {
        let outside = scratch_dir("loose-symlink-outside");
        write(
            &outside.join("Secret.ipe"),
            "module Secret exposing (s)\n\ns = 1\n",
        );
        let dir = scratch_dir("loose-symlink");
        let entry = dir.join("Main.ipe");
        write(
            &entry,
            "module Main exposing (main)\n\nimport Secret\n\nmain = Secret.s\n",
        );
        std::os::unix::fs::symlink(outside.join("Secret.ipe"), dir.join("Secret.ipe"))
            .expect("plant symlink");

        let loaded = resolve_loose_file(&entry, None, MAX_LOOSE_FILE_MODULES);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
        let loaded = loaded.expect("entry still loads");
        assert_eq!(user_modules(&loaded), vec![module(&["Main"])]);
    }

    #[test]
    fn file_inside_a_package_resolves_to_the_package_root() {
        let dir = scratch_dir("package-root");
        write(
            &dir.join("package.ipe"),
            "module Package exposing (package)\n",
        );
        let entry = dir.join("src").join("Main.ipe");
        write(&entry, "module Main exposing (main)\n\nmain = 1\n");

        let from_walk_up = ProjectRoot::of(None, &entry);
        let from_workspace = ProjectRoot::of(Some(&dir), &entry);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(from_walk_up, ProjectRoot::Package(dir.clone()));
        assert_eq!(from_workspace, ProjectRoot::Package(dir));
    }

    #[test]
    fn file_under_no_manifest_is_a_loose_file() {
        let dir = scratch_dir("loose-root");
        let entry = dir.join("Main.ipe");
        write(&entry, "module Main exposing (main)\n\nmain = 1\n");

        let root = ProjectRoot::of(Some(&dir), &entry);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(root, ProjectRoot::LooseFile(entry));
    }
}
