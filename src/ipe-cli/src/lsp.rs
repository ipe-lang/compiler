//! `ipe lsp` — the JSON-RPC-over-stdio language server subcommand.
//!
//! The server loop and every feature handler live in `ipe_lsp_server` /
//! `ipe_lsp_features`; this module supplies the one driver-side ingredient
//! the server cannot own — project resolution. [`DriverLoader`] first
//! classifies the opened document as a [`ProjectRoot`]. A package routes
//! through the SAME manifest-discovery/stdlib-injection code path `ipe build`
//! and `ipe watch` use, so the module set the editor analyzes can never
//! diverge from the one the batch build compiles. A loose file (no
//! `package.ipe` above it) resolves through [`crate::loose_file`], the same
//! resolver `ipe build` and `ipe watch` use for it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ipe_lsp_server::{LimitSource, LoadError, LoadedFile, LoadedProject, ProjectLoader};

use crate::ffi::FfiPrepError;
use crate::loose_file::{LooseFileLimits, ProjectRoot, resolve_loose_file};
use crate::{CliError, project, text, watch};

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
        ProjectRoot::LooseFile(file) => {
            let loaded = resolve_loose_file(file, open_text, LooseFileLimits::DEFAULT)?;
            Ok(UserSources {
                sources: loaded.sources,
                discovered: loaded.discovered,
                entry_module: loaded.entry_module,
                blame_path: file.clone(),
            })
        }
    }
}

/// What can lift a limit hit while resolving the user modules of `root`.
///
/// A loose file's closure is walked from the open buffer, so an edit that
/// drops an import can bring it back under its limits; a package's layout
/// comes from disk alone, so no edit to the buffer changes it.
const fn user_sources_limit(root: &ProjectRoot) -> LimitSource {
    match root {
        ProjectRoot::Package(_) => LimitSource::Filesystem,
        ProjectRoot::LooseFile(_) => LimitSource::Buffer,
    }
}

/// Type a driver failure as the server's load error, keeping its rendered text.
///
/// The match names every [`CliError`] variant with no fallback arm, so a new
/// variant cannot reach the editor until someone decides whether it degrades
/// the load (single-file fallback, retried per edit) or refuses it. A limit
/// carries `lifted_by`, what the failing step counted.
fn load_error(err: &CliError, lifted_by: LimitSource) -> LoadError {
    use crate::owner_trust::TrustSubject;
    let detail = err.to_string();
    match err {
        CliError::Io { .. }
        | CliError::ScratchUnavailable { .. }
        | CliError::ChildPipeHeld(_)
        | CliError::ThreadRefused { .. }
        | CliError::Interrupted => LoadError::Io(detail),
        CliError::SourceRefused { .. } | CliError::DeviceNamedModule { .. } => {
            LoadError::Refused(detail)
        }
        CliError::FileTooLarge { .. }
        | CliError::DiscoveryLimitReached { .. }
        | CliError::RemoteIngestExceeded(_)
        | CliError::LocalLimitExceeded(_) => LoadError::Limit { lifted_by, detail },
        CliError::TrustRefused(refusal) => match refusal.subject() {
            TrustSubject::Ffi => LoadError::FfiUntrusted(detail),
            TrustSubject::Manifest => LoadError::ManifestUntrusted(detail),
        },
        CliError::FfiPrep(refusal) => ffi_prep_load_error(refusal, detail),
        CliError::Usage(_)
        | CliError::UnknownCommand { .. }
        | CliError::Pipeline { .. }
        | CliError::RuntimeNotFound
        | CliError::RuntimeDirInvalid { .. }
        | CliError::RuntimeHomeUnknown
        | CliError::CacheHomeUnknown
        | CliError::EnvDirNotAbsolute { .. }
        | CliError::RuntimeMaterializeFailed { .. }
        | CliError::RuntimeVersionMismatch { .. }
        | CliError::EmittedBuildFailed { .. }
        | CliError::UnknownCode { .. }
        | CliError::DocNotFound { .. }
        | CliError::StaticRefusal(_)
        | CliError::CapabilityMismatch { .. }
        | CliError::Resolve(_)
        | CliError::LockRefused(_)
        | CliError::HashMismatch { .. }
        | CliError::Diff(_)
        | CliError::SemverRejected { .. }
        | CliError::PackageAudit(_)
        | CliError::Publish(_)
        | CliError::VersionRefused { .. }
        | CliError::DocCoverage(_)
        | CliError::DocExamplesFailed(_)
        | CliError::CommandUsage { .. }
        | CliError::UnknownGroupSub { .. }
        | CliError::VerifyFailed { .. }
        | CliError::TestFailed { .. }
        | CliError::UpgradeNoPrebuilt { .. }
        | CliError::ToolchainMissing(_)
        | CliError::HealthCritical
        | CliError::LintGateFailed
        | CliError::EjectUnsupported { .. }
        | CliError::DiagnosticJsonEmitted
        | CliError::PathEscape { .. }
        | CliError::OutputRefused(_)
        | CliError::UpgradeFeedUnreachable
        | CliError::UpgradeCheckExit { .. }
        | CliError::AdvisoryVulnerable(_)
        | CliError::AdvisoryDbUnreachable { .. }
        | CliError::AdvisoryDbMalformed { .. }
        | CliError::WasiRunFeatureDisabled
        | CliError::WasiRunFailed { .. }
        | CliError::WasiRunExited { .. } => LoadError::Pipeline(detail),
    }
}

/// Classify an FFI prep refusal by whether an edit to the project can fix it.
///
/// A refusal caused by project source (a module path, a `Rust.Ffi.call` site)
/// degrades the load, since an edit can lift it. A conflict inside the
/// installed catalog refuses it: no buffer edit fixes it, and degrading would
/// serve analysis over a program `ipe build` rejects. The match names every
/// variant with no fallback arm, so a new refusal cannot reach the editor
/// until its disposition is decided.
const fn ffi_prep_load_error(refusal: &FfiPrepError, detail: String) -> LoadError {
    match refusal {
        FfiPrepError::ModuleClaimed { .. }
        | FfiPrepError::ReservedModuleExists
        | FfiPrepError::AssertedRefused(_)
        | FfiPrepError::AssertedShimSeal(_) => LoadError::Pipeline(detail),
        FfiPrepError::DefineOpaqueCollision { .. }
        | FfiPrepError::DependencyMerge(_)
        | FfiPrepError::CatalogSeal(_)
        | FfiPrepError::TransparentWithoutShape { .. }
        | FfiPrepError::AssertedWithoutCatalog => LoadError::FfiCatalogRefused(detail),
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
        let root = ProjectRoot::of(workspace_root, open_file)
            .map_err(|e| load_error(&e, LimitSource::Filesystem))?;
        let UserSources {
            mut sources,
            mut discovered,
            entry_module,
            blame_path,
        } = resolve_user_sources(&root, open_text)
            .map_err(|e| load_error(&e, user_sources_limit(&root)))?;
        let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);
        // Load the FFI catalog and inject installed-crate interface modules so
        // the LSP sees `Rust.<Crate>` bindings exactly as `ipe build` does. A
        // missing/empty catalog is fine (no crates installed); a tampered
        // cache is surfaced as a `LoadError`.
        let ffi_injected = crate::ffi::prepare_ffi(&mut sources, &blame_path)
            .map_err(|e| load_error(&e, LimitSource::Filesystem))?
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
            lint_config_dir: ipe_lint::lint_config_dir(&blame_path),
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
        return Err(CliError::Usage(text::msg::lsp_takes_no_arguments()));
    }
    ipe_lsp_server::run_stdio(&DriverLoader).map_err(|e| CliError::Usage(text::msg::lsp_failed(&e)))
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::io_bounded::SourceRefusal;
    use crate::owner_trust::TrustRefusal;

    /// A fresh scratch directory for one test.
    #[allow(clippy::expect_used)] // test fixture: a failed mkdir IS the failure
    fn scratch_dir(tag: &str) -> PathBuf {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe-lsp-load-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// Every trust refusal, one per variant.
    fn every_trust_refusal() -> Vec<TrustRefusal> {
        let path = || PathBuf::from("/p/.ipe/cache/ffi/rust");
        let manifest = || PathBuf::from("/p/package.ipe");
        vec![
            TrustRefusal::ManifestSymlink(manifest()),
            TrustRefusal::ManifestUntrusted(manifest()),
            TrustRefusal::ManifestUnverifiable(manifest()),
            TrustRefusal::FfiCacheUnverifiable(path()),
            TrustRefusal::FfiCacheSymlink(path()),
            TrustRefusal::FfiCacheUntrusted(path()),
            TrustRefusal::FfiCacheNotRegular(path()),
            TrustRefusal::FfiCacheTooManyEntries {
                path: path(),
                cap: 1,
            },
            TrustRefusal::FfiCatalog(Box::new(ipe_ffi::diag::Diagnostic::ArtifactIo {
                path: "/p/x.consumer.json".to_owned(),
                detail: "artifact is missing".to_owned(),
            })),
            TrustRefusal::FfiReservedModule {
                slug: "x".to_owned(),
            },
            TrustRefusal::FfiReservedWrapperPrefix {
                slug: "x".to_owned(),
                ident: "ipe_asserted_x".to_owned(),
            },
        ]
    }

    #[test]
    fn each_failure_class_maps_to_its_named_load_error() {
        let io = CliError::Io {
            path: PathBuf::from("/p/Main.ipe"),
            source: std::io::Error::other("gone"),
        };
        let refused = CliError::SourceRefused {
            path: PathBuf::from("/p/Pipe.ipe"),
            reason: SourceRefusal::NotRegularFile,
        };
        let too_large = CliError::FileTooLarge {
            path: PathBuf::from("/p/Big.ipe"),
            max: 1,
        };
        let too_deep = CliError::DiscoveryLimitReached {
            detail: "64".to_owned(),
        };
        let filesystem = LimitSource::Filesystem;
        assert_eq!(load_error(&io, filesystem), LoadError::Io(io.to_string()));
        assert_eq!(
            load_error(&refused, filesystem),
            LoadError::Refused(refused.to_string())
        );
        for lifted_by in [LimitSource::Buffer, LimitSource::Filesystem] {
            for limit in [&too_large, &too_deep] {
                assert_eq!(
                    load_error(limit, lifted_by),
                    LoadError::Limit {
                        lifted_by,
                        detail: limit.to_string()
                    }
                );
            }
        }
        for pipeline in [
            CliError::Usage(text::msg::lsp_takes_no_arguments()),
            CliError::RuntimeNotFound,
            CliError::HealthCritical,
            CliError::LintGateFailed,
        ] {
            assert_eq!(
                load_error(&pipeline, filesystem),
                LoadError::Pipeline(pipeline.to_string()),
                "{pipeline:?}"
            );
        }
    }

    /// Every FFI prep refusal, one per variant.
    ///
    /// The exhaustive match over a witness value makes a new variant a build
    /// error here until it joins the list.
    fn every_ffi_prep_error() -> [FfiPrepError; 9] {
        let witness = FfiPrepError::ReservedModuleExists;
        match witness {
            FfiPrepError::ModuleClaimed { .. }
            | FfiPrepError::ReservedModuleExists
            | FfiPrepError::AssertedRefused(_)
            | FfiPrepError::AssertedShimSeal(_)
            | FfiPrepError::DefineOpaqueCollision { .. }
            | FfiPrepError::DependencyMerge(_)
            | FfiPrepError::CatalogSeal(_)
            | FfiPrepError::TransparentWithoutShape { .. }
            | FfiPrepError::AssertedWithoutCatalog => {}
        }
        let dropped = || crate::ffi::SealRefusal::DroppedTransitive {
            package: "syn".to_owned(),
            ident: "syn".to_owned(),
            site: "src/ffi.rs".to_owned(),
        };
        [
            FfiPrepError::ModuleClaimed {
                module: "Rust.A".to_owned(),
                slug: "a".to_owned(),
            },
            FfiPrepError::ReservedModuleExists,
            FfiPrepError::AssertedRefused(Box::new(ipe_ffi::diag::Diagnostic::ArtifactIo {
                path: "/p/x.consumer.json".to_owned(),
                detail: "refused".to_owned(),
            })),
            FfiPrepError::AssertedShimSeal(dropped()),
            FfiPrepError::DefineOpaqueCollision {
                slug: "a".to_owned(),
                name: "T".to_owned(),
            },
            FfiPrepError::DependencyMerge(crate::ffi::MergeRefusal::PinConflict {
                name: "serde".to_owned(),
                first: "1.0.1".to_owned(),
                second: "1.0.2".to_owned(),
            }),
            FfiPrepError::CatalogSeal(dropped()),
            FfiPrepError::TransparentWithoutShape {
                slug: "a".to_owned(),
                name: "Shape".to_owned(),
                binding: "make".to_owned(),
            },
            FfiPrepError::AssertedWithoutCatalog,
        ]
    }

    /// Whether an FFI prep refusal comes from project source an edit can fix.
    const fn is_source_side(refusal: &FfiPrepError) -> bool {
        matches!(
            refusal,
            FfiPrepError::ModuleClaimed { .. }
                | FfiPrepError::ReservedModuleExists
                | FfiPrepError::AssertedRefused(_)
                | FfiPrepError::AssertedShimSeal(_)
        )
    }

    #[test]
    fn ffi_prep_each_variant_maps_to_named_load_error() {
        for refusal in every_ffi_prep_error() {
            let source_side = is_source_side(&refusal);
            let err = CliError::FfiPrep(Box::new(refusal));
            let detail = err.to_string();
            let expected = if source_side {
                LoadError::Pipeline(detail)
            } else {
                LoadError::FfiCatalogRefused(detail)
            };
            assert_eq!(
                load_error(&err, LimitSource::Filesystem),
                expected,
                "{err:?}"
            );
        }
    }

    #[test]
    fn ffi_catalog_conflicts_refuse() {
        for refusal in every_ffi_prep_error()
            .into_iter()
            .filter(|r| !is_source_side(r))
        {
            let err = CliError::FfiPrep(Box::new(refusal));
            assert_eq!(
                load_error(&err, LimitSource::Buffer).disposition(),
                ipe_lsp_server::LoadDisposition::Refuse,
                "{err:?}"
            );
        }
        let opaque_collision = CliError::FfiPrep(Box::new(FfiPrepError::DefineOpaqueCollision {
            slug: "a".to_owned(),
            name: "T".to_owned(),
        }));
        let pin_conflict = CliError::FfiPrep(Box::new(FfiPrepError::DependencyMerge(
            crate::ffi::MergeRefusal::PinConflict {
                name: "serde".to_owned(),
                first: "1.0.1".to_owned(),
                second: "1.0.2".to_owned(),
            },
        )));
        for named in [opaque_collision, pin_conflict] {
            assert_eq!(
                load_error(&named, LimitSource::Buffer).disposition(),
                ipe_lsp_server::LoadDisposition::Refuse,
                "{named:?}"
            );
        }
    }

    #[test]
    fn ffi_source_side_refusals_degrade() {
        let source_side: Vec<FfiPrepError> = every_ffi_prep_error()
            .into_iter()
            .filter(is_source_side)
            .collect();
        assert_eq!(source_side.len(), 4, "{source_side:?}");
        for refusal in source_side {
            let err = CliError::FfiPrep(Box::new(refusal));
            assert_eq!(
                load_error(&err, LimitSource::Filesystem).disposition(),
                ipe_lsp_server::LoadDisposition::Degrade,
                "{err:?}"
            );
        }
    }

    #[test]
    fn every_trust_refusal_is_refused_not_degraded() {
        for refusal in every_trust_refusal() {
            let manifest = matches!(
                refusal,
                TrustRefusal::ManifestSymlink(_)
                    | TrustRefusal::ManifestUntrusted(_)
                    | TrustRefusal::ManifestUnverifiable(_)
            );
            let err = CliError::TrustRefused(refusal);
            let detail = err.to_string();
            let expected = if manifest {
                LoadError::ManifestUntrusted(detail)
            } else {
                LoadError::FfiUntrusted(detail)
            };
            let got = load_error(&err, LimitSource::Filesystem);
            assert_eq!(got, expected, "{err:?}");
            assert_eq!(
                got.disposition(),
                ipe_lsp_server::LoadDisposition::Refuse,
                "{err:?}"
            );
        }
    }

    #[test]
    fn every_source_refusal_degrades() {
        for reason in [SourceRefusal::NotRegularFile, SourceRefusal::AccessDenied] {
            let err = CliError::SourceRefused {
                path: PathBuf::from("/p/Pipe.ipe"),
                reason,
            };
            let got = load_error(&err, LimitSource::Filesystem);
            assert!(matches!(got, LoadError::Refused(_)), "{got:?}");
            assert_eq!(got.disposition(), ipe_lsp_server::LoadDisposition::Degrade);
        }
    }

    /// A loose file's limits count its open buffer, so the load degrades and an edit lifts it.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn a_loose_file_closure_limit_degrades_and_an_edit_lifts_it() {
        let dir = scratch_dir("closure-limit");
        let main = dir.join("Main.ipe");
        let small = "module Main exposing (main)\n\nmain = 0\n";
        fs::write(&main, small).expect("write Main.ipe");
        let imports = (0..=crate::loose_file::MAX_LOOSE_FILE_PROBES)
            .map(|index| format!("import M{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let oversized = format!("module Main exposing (main)\n\n{imports}\nmain = 0\n");
        let over = DriverLoader.load(None, &main, Some(&oversized));
        let under = DriverLoader.load(None, &main, Some(small));
        let _ = fs::remove_dir_all(&dir);
        let err = over.err();
        assert!(
            matches!(
                err,
                Some(LoadError::Limit {
                    lifted_by: LimitSource::Buffer,
                    ..
                })
            ),
            "{err:?}"
        );
        assert_eq!(
            err.as_ref().map(LoadError::disposition),
            Some(ipe_lsp_server::LoadDisposition::Degrade)
        );
        assert!(under.is_ok(), "{:?}", under.err());
    }

    /// A package's discovery limit counts the filesystem, so the load refuses and the buffer cannot lift it.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write or mkdir IS the failure
    fn a_package_discovery_limit_refuses_the_load() {
        let dir = scratch_dir("package-limit");
        fs::write(
            dir.join("package.ipe"),
            "module Package exposing (package)\n\npackage =\n    { name = \"deep\" }\n",
        )
        .expect("write package.ipe");
        let src = dir.join("src");
        let main = src.join("Main.ipe");
        let text = "module Main exposing (main)\n\nmain = 0\n";
        let nested = (0..=crate::project::MAX_DISCOVERY_DEPTH)
            .fold(src, |parent, index| parent.join(format!("D{index}")));
        fs::create_dir_all(&nested).expect("create nested source tree");
        fs::write(&main, text).expect("write Main.ipe");
        let loaded = DriverLoader.load(Some(&dir), &main, Some(text));
        let _ = fs::remove_dir_all(&dir);
        let err = loaded.err();
        assert!(
            matches!(
                err,
                Some(LoadError::Limit {
                    lifted_by: LimitSource::Filesystem,
                    ..
                })
            ),
            "{err:?}"
        );
        assert_eq!(
            err.as_ref().map(LoadError::disposition),
            Some(ipe_lsp_server::LoadDisposition::Refuse)
        );
    }

    /// Make every component of `root/rel` a directory only its owner may write.
    #[allow(clippy::expect_used)] // test fixture: a failed mkdir IS the failure
    fn private_chain(root: &Path, rel: &str) -> PathBuf {
        let mut dir = root.to_path_buf();
        for segment in rel.split('/') {
            dir.push(segment);
            fs::create_dir_all(&dir).expect("create cache component");
            #[cfg(unix)]
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        dir
    }

    /// A tampered FFI catalog refuses the load rather than degrading it.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn a_tampered_catalog_refuses_the_load() {
        let dir = scratch_dir("tampered-catalog");
        let main = dir.join("Main.ipe");
        let text = "module Main exposing (main)\n\nmain = 0\n";
        fs::write(&main, text).expect("write Main.ipe");
        let cache = private_chain(&dir, ipe_ffi::driver::FFI_CACHE_REL);
        fs::write(cache.join("x.consumer.json"), "{ not json").expect("write artifact");
        let loaded = DriverLoader.load(None, &main, Some(text));
        let _ = fs::remove_dir_all(&dir);
        assert!(
            matches!(&loaded, Err(LoadError::FfiUntrusted(_))),
            "{:?}",
            loaded.err()
        );
    }

    /// An imported FIFO degrades the load: the user can fix it, so edits retry.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write or `mkfifo` IS the failure
    fn an_imported_fifo_degrades_the_load() {
        let dir = scratch_dir("fifo");
        let main = dir.join("Main.ipe");
        let text = "module Main exposing (main)\n\nimport Pipe\n\nmain = Pipe.x\n";
        fs::write(&main, text).expect("write Main.ipe");
        let made = std::process::Command::new("mkfifo")
            .arg(dir.join("Pipe.ipe"))
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
        let loaded = DriverLoader.load(None, &main, Some(text));
        let _ = fs::remove_dir_all(&dir);
        let err = loaded.err();
        assert!(matches!(err, Some(LoadError::Refused(_))), "{err:?}");
        assert_eq!(
            err.as_ref().map(LoadError::disposition),
            Some(ipe_lsp_server::LoadDisposition::Degrade)
        );
    }
}
