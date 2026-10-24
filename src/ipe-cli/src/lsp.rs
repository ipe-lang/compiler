//! `ipe lsp` — the JSON-RPC-over-stdio language server subcommand.
//!
//! The server loop and every feature handler live in `ipe_lsp_server` /
//! `ipe_lsp_features`; this module supplies the one driver-side ingredient
//! the server cannot own — project resolution. [`DriverLoader`] resolves the
//! workspace folder holding the opened document as a [`ProjectRoot`], the
//! same held root `ipe dev build` and `ipe dev watch` resolve for that
//! directory, and reads the module set, the manifest and the FFI catalog
//! through it. No directory above a workspace folder is ever searched, so
//! the module set the editor analyzes can never diverge from the one the
//! batch build compiles, and no parent directory can supply the scope.

use std::path::{Path, PathBuf};

use ipe_lsp_server::{LimitSource, LoadError, LoadedFile, LoadedProject, ProjectLoader};

use crate::ffi::FfiPrepError;
use crate::package_manifest::PACKAGE_IPE;
use crate::project_root::{ProjectRoot, RootArg, SourceDir};
use crate::source_snapshot::SourceOrigin;
use crate::{CliError, text, watch};

/// The directory `open_file` is resolved in.
///
/// The innermost workspace folder holding the file wins; a file outside every
/// folder is resolved in the first folder, which is the project the editor
/// opened. An editor that sent no folders at all leaves the file's own
/// directory as the only candidate. The candidate is where `package.ipe` must
/// be: nothing above it is searched.
fn root_dir(workspace_roots: &[PathBuf], open_file: &Path) -> Option<PathBuf> {
    workspace_roots
        .iter()
        .filter(|folder| open_file.starts_with(folder))
        .max_by_key(|folder| folder.components().count())
        .or_else(|| workspace_roots.first())
        .cloned()
        .or_else(|| open_file.parent().map(Path::to_path_buf))
}

/// Type a driver failure as the server's load error, keeping its rendered text.
///
/// The match names every [`CliError`] variant with no fallback arm, so a new
/// variant cannot reach the editor until someone decides whether it degrades
/// the load (single-file fallback, retried per edit) or refuses it. Every
/// limit the driver hits counts the filesystem: the layout comes from disk
/// alone, so no edit to the open buffer lifts it.
fn load_error(err: &CliError) -> LoadError {
    use crate::owner_trust::TrustSubject;
    let detail = err.to_string();
    match err {
        CliError::Io { .. }
        | CliError::ScratchUnavailable { .. }
        | CliError::ChildPipeHeld(_)
        | CliError::ThreadRefused { .. }
        | CliError::ChildPipeUnread(..)
        | CliError::Interrupted => LoadError::Io(detail),
        CliError::SourceRefused { .. }
        | CliError::DeviceNamedModule { .. }
        | CliError::SourceTree(_)
        | CliError::SymlinkInSource { .. } => LoadError::Refused(detail),
        CliError::NoManifest { .. }
        | CliError::NoSrcDir { .. }
        | CliError::EntryMissing { .. }
        | CliError::NoDefaultEntry { .. }
        | CliError::EntryEscapes { .. }
        | CliError::ExposedModuleMissing { .. }
        | CliError::FileOutsideRoot { .. }
        | CliError::DirectoryExpected { .. } => LoadError::RootRefused(detail),
        CliError::FileTooLarge { .. }
        | CliError::FmtOutputTooLarge { .. }
        | CliError::DiscoveryLimitReached { .. }
        | CliError::RemoteIngestExceeded(_)
        | CliError::LocalLimitExceeded(_) => LoadError::Limit {
            lifted_by: LimitSource::Filesystem,
            detail,
        },
        CliError::TrustRefused(refusal) => match refusal.subject() {
            TrustSubject::Ffi => LoadError::FfiUntrusted(detail),
            TrustSubject::Manifest => LoadError::RootRefused(detail),
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
        | CliError::CargoBuildTimedOut { .. }
        | CliError::TargetDirUnlinkable { .. }
        | CliError::BundledManifest { .. }
        | CliError::TestTargetBusy { .. }
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
        | CliError::CheckFailed(_)
        | CliError::DocCoverage(_)
        | CliError::DocExamplesFailed(_)
        | CliError::CommandUsage { .. }
        | CliError::UnknownGroupSub { .. }
        | CliError::GroupRequired { .. }
        | CliError::NoRunForm { .. }
        | CliError::WrapperSourceRefused(_)
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
/// serve analysis over a program `ipe dev build` rejects. The match names every
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
        workspace_roots: &[PathBuf],
        open_file: &Path,
        _open_text: Option<&str>,
    ) -> Result<LoadedProject, LoadError> {
        let dir = root_dir(workspace_roots, open_file).ok_or_else(|| {
            load_error(&CliError::NoManifest {
                dir: open_file.to_path_buf(),
            })
        })?;
        let root = ProjectRoot::resolve(RootArg::at(&dir)).map_err(|e| load_error(&e))?;
        let manifest_path = root.path().join(PACKAGE_IPE);
        // The module set is the source snapshot `ipe dev build` reads for this
        // root: held-handle reads, a link anywhere refused, the summed size
        // capped, and the FFI catalog read through the held cache directory.
        let resolved = watch::resolve_project_sources(root).map_err(|e| load_error(&e))?;
        let entry_module = resolved.entry_path;
        let files = resolved
            .snapshot
            .modules()
            .iter()
            .map(|(module, held)| {
                let origin = match held.origin() {
                    SourceOrigin::Own(SourceDir::Src | SourceDir::Tests) => {
                        ipe_canon::ModuleOrigin::User
                    }
                    SourceOrigin::Stdlib => ipe_canon::ModuleOrigin::EmbeddedStdlib,
                    SourceOrigin::FfiInterface => ipe_canon::ModuleOrigin::FfiInterface,
                };
                let file = LoadedFile {
                    path: held.path().to_path_buf(),
                    text: held.text().to_owned(),
                    origin,
                };
                (module.clone(), file)
            })
            .collect();
        Ok(LoadedProject {
            files,
            entry_module,
            lint_config_dir: ipe_lint::lint_config_dir(&manifest_path),
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
    use crate::RootFixture;
    use crate::io_bounded::SourceRefusal;
    use crate::owner_trust::TrustRefusal;
    use crate::project_root::SourceTree;

    const MAIN: &str = "module Main exposing (main)\n\nmain =\n    0\n";

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
            TrustRefusal::FfiCacheEscapes(path()),
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
        assert_eq!(load_error(&io), LoadError::Io(io.to_string()));
        assert_eq!(
            load_error(&refused),
            LoadError::Refused(refused.to_string())
        );
        let root = PathBuf::from("/p");
        for source in [
            CliError::SourceTree(crate::project_root::TreeRefusal::NotModuleSegment {
                module: "main".to_owned(),
                segment: "main".to_owned(),
            }),
            CliError::SymlinkInSource {
                path: root.join("src/Main.ipe"),
            },
        ] {
            assert_eq!(
                load_error(&source),
                LoadError::Refused(source.to_string()),
                "{source:?}"
            );
        }
        for project in [
            CliError::NoManifest { dir: root.clone() },
            CliError::NoSrcDir { root: root.clone() },
            CliError::EntryMissing {
                entry: "Cli/Main.ipe".to_owned(),
            },
            CliError::NoDefaultEntry { root: root.clone() },
            CliError::EntryEscapes {
                entry: "Cli/Main.ipe".to_owned(),
                path: root.join("src/Cli"),
            },
            CliError::ExposedModuleMissing {
                module: "Shapes".to_owned(),
            },
            CliError::FileOutsideRoot {
                arg: root.join("other/Main.ipe"),
                root: root.clone(),
            },
        ] {
            let got = load_error(&project);
            assert_eq!(
                got,
                LoadError::RootRefused(project.to_string()),
                "{project:?}"
            );
            assert_eq!(
                got.disposition(),
                ipe_lsp_server::LoadDisposition::Refuse,
                "{project:?}"
            );
        }
        for limit in [&too_large, &too_deep] {
            assert_eq!(
                load_error(limit),
                LoadError::Limit {
                    lifted_by: LimitSource::Filesystem,
                    detail: limit.to_string()
                }
            );
        }
        for pipeline in [
            CliError::Usage(text::msg::lsp_takes_no_arguments()),
            CliError::RuntimeNotFound,
            CliError::HealthCritical,
            CliError::LintGateFailed,
        ] {
            assert_eq!(
                load_error(&pipeline),
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
            assert_eq!(load_error(&err), expected, "{err:?}");
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
                load_error(&err).disposition(),
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
                load_error(&named).disposition(),
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
                load_error(&err).disposition(),
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
                LoadError::RootRefused(detail)
            } else {
                LoadError::FfiUntrusted(detail)
            };
            let got = load_error(&err);
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
            let got = load_error(&err);
            assert!(matches!(got, LoadError::Refused(_)), "{got:?}");
            assert_eq!(got.disposition(), ipe_lsp_server::LoadDisposition::Degrade);
        }
    }

    /// The innermost workspace folder holding the file is its root; a file
    /// outside every folder resolves in the first folder; no folder at all
    /// leaves the file's own directory.
    #[test]
    fn the_root_is_the_workspace_folder_holding_the_file() {
        let outer = PathBuf::from("/w/outer");
        let inner = PathBuf::from("/w/outer/inner");
        let other = PathBuf::from("/w/other");
        let folders = [other.clone(), outer.clone(), inner.clone()];
        assert_eq!(
            root_dir(&folders, Path::new("/w/outer/inner/src/Main.ipe")),
            Some(inner)
        );
        assert_eq!(
            root_dir(&folders, Path::new("/w/outer/src/Main.ipe")),
            Some(outer)
        );
        assert_eq!(
            root_dir(&folders, Path::new("/elsewhere/Main.ipe")),
            Some(other)
        );
        assert_eq!(
            root_dir(&[], Path::new("/elsewhere/Main.ipe")),
            Some(PathBuf::from("/elsewhere"))
        );
    }

    /// A workspace folder with no `package.ipe` refuses the load with the
    /// compiler's own no-manifest refusal, and nothing above it is searched.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed fixture IS the failure
    fn a_workspace_folder_without_a_manifest_refuses_the_load() {
        let fixture = RootFixture::main(MAIN).expect("fixture");
        let folder = fixture.path().join("src");
        let main = folder.join("Main.ipe");
        let loaded = DriverLoader.load(&[folder.clone()], &main, Some(MAIN));
        let expected = CliError::NoManifest { dir: folder }.to_string();
        let err = loaded.err();
        assert_eq!(err, Some(LoadError::RootRefused(expected)));
        assert_eq!(
            err.as_ref().map(LoadError::disposition),
            Some(ipe_lsp_server::LoadDisposition::Refuse)
        );
    }

    /// A package's discovery limit counts the filesystem, so the load refuses and the buffer cannot lift it.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write or mkdir IS the failure
    fn a_package_discovery_limit_refuses_the_load() {
        let fixture = RootFixture::main(MAIN).expect("fixture");
        let src = fixture.path().join("src");
        let main = src.join("Main.ipe");
        let nested = (0..=crate::project::MAX_DISCOVERY_DEPTH)
            .fold(src, |parent, index| parent.join(format!("D{index}")));
        fs::create_dir_all(&nested).expect("create nested source tree");
        let loaded = DriverLoader.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
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

    /// Make every one of `components` below `root` a directory only its owner may write.
    #[allow(clippy::expect_used)] // test fixture: a failed mkdir IS the failure
    fn private_chain(root: &Path, components: &[&str]) -> PathBuf {
        let mut dir = root.to_path_buf();
        for segment in components {
            dir.push(segment);
            fs::create_dir_all(&dir).expect("create cache component");
            #[cfg(unix)]
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        dir
    }

    /// A tampered FFI catalog under the project root refuses the load rather than degrading it.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn a_tampered_catalog_refuses_the_load() {
        let fixture = RootFixture::main(MAIN).expect("fixture");
        let main = fixture.path().join("src/Main.ipe");
        let cache = private_chain(fixture.path(), &ipe_ffi::driver::FFI_CACHE_COMPONENTS);
        fs::write(cache.join("x.consumer.json"), "{ not json").expect("write artifact");
        let loaded = DriverLoader.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
        assert!(
            matches!(&loaded, Err(LoadError::FfiUntrusted(_))),
            "{:?}",
            loaded.err()
        );
    }

    /// A module file that is a FIFO degrades the load: the user can fix it, so edits retry.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write or `mkfifo` IS the failure
    fn a_fifo_module_degrades_the_load() {
        let fixture = RootFixture::main(MAIN).expect("fixture");
        let main = fixture.path().join("src/Main.ipe");
        let made = std::process::Command::new("mkfifo")
            .arg(fixture.path().join("src/Pipe.ipe"))
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo creates the fixture");
        let loaded = DriverLoader.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
        let err = loaded.err();
        assert!(matches!(err, Some(LoadError::Refused(_))), "{err:?}");
        assert_eq!(
            err.as_ref().map(LoadError::disposition),
            Some(ipe_lsp_server::LoadDisposition::Degrade)
        );
    }

    /// A module that is a link refuses the LSP load and the watch resolution
    /// exactly as it refuses the build: no reader of the project skips it or
    /// follows it out of `src/`.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write or symlink IS the failure
    fn a_symlinked_module_refuses_like_the_build() {
        let fixture = RootFixture::main(MAIN).expect("fixture");
        let outside = fixture.path().join("Outside.ipe");
        fs::write(&outside, "module Helper exposing (h)\n\nh =\n    1\n")
            .expect("write the link target");
        std::os::unix::fs::symlink(&outside, fixture.path().join("src/Helper.ipe"))
            .expect("link a module out of src/");
        let main = fixture.path().join("src/Main.ipe");

        let build_root =
            ProjectRoot::resolve(RootArg::at(fixture.path())).expect("build resolves the root");
        let build = crate::source_snapshot::SourceSnapshot::read(
            &build_root,
            crate::source_snapshot::Limits::DEFAULT,
        );
        assert!(
            matches!(build, Err(CliError::SymlinkInSource { .. })),
            "the build refuses the link"
        );

        let loaded = DriverLoader.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
        let err = loaded.err();
        assert!(matches!(err, Some(LoadError::Refused(_))), "{err:?}");

        let watch_root =
            ProjectRoot::resolve(RootArg::at(fixture.path())).expect("watch resolves the root");
        let watched = watch::resolve_project_sources(watch_root);
        assert!(
            matches!(watched, Err(CliError::SymlinkInSource { .. })),
            "the watch refuses the link"
        );
    }

    /// Build, LSP load and a watch resolution of one project reach the same
    /// root, the same module set and the same FFI cache; a stray
    /// `package.ipe` under `src/` changes none of them and is never read.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn build_lsp_and_watch_resolve_one_root() {
        let fixture = RootFixture::from_tree(
            &SourceTree::main(MAIN).module("Helper", "module Helper exposing (h)\n\nh =\n    1\n"),
        )
        .expect("fixture");
        let stray = fixture.path().join("src").join(PACKAGE_IPE);
        fs::write(
            &stray,
            "module Package exposing (package)\n\npackage =\n    { name = \"stray\" }\n",
        )
        .expect("write stray manifest");
        #[cfg(unix)]
        fs::set_permissions(&stray, fs::Permissions::from_mode(0o000)).expect("chmod 000");
        let cache = private_chain(fixture.path(), &ipe_ffi::driver::FFI_CACHE_COMPONENTS);

        let build_root =
            ProjectRoot::resolve(RootArg::at(fixture.path())).expect("build resolves the root");
        let snapshot = crate::source_snapshot::SourceSnapshot::read(
            &build_root,
            crate::source_snapshot::Limits::DEFAULT,
        )
        .expect("build reads the snapshot");
        let build_modules: Vec<(Vec<String>, PathBuf)> = snapshot
            .modules()
            .iter()
            .filter(|(_, module)| module.path().starts_with(fixture.path()))
            .map(|(module, source)| (module.clone(), source.path().to_path_buf()))
            .collect();

        let main = fixture.path().join("src/Main.ipe");
        let loaded = DriverLoader
            .load(&[fixture.path().to_path_buf()], &main, None)
            .expect("the LSP loads the project");
        let lsp_modules: Vec<(Vec<String>, PathBuf)> = loaded
            .files
            .iter()
            .filter(|(_, file)| file.origin == ipe_canon::ModuleOrigin::User)
            .map(|(module, file)| (module.clone(), file.path.clone()))
            .collect();

        let watch_root =
            ProjectRoot::resolve(RootArg::at(fixture.path())).expect("watch resolves the root");
        let watched = watch::resolve_project_sources(watch_root).expect("watch resolves");
        let watch_modules: Vec<(Vec<String>, PathBuf)> = watched
            .snapshot
            .modules()
            .iter()
            .filter(|(_, held)| held.origin() == SourceOrigin::Own(SourceDir::Src))
            .map(|(module, held)| (module.clone(), held.path().to_path_buf()))
            .collect();

        let expected = vec![
            (
                vec!["Helper".to_owned()],
                fixture.path().join("src/Helper.ipe"),
            ),
            (vec!["Main".to_owned()], main),
        ];
        assert_eq!(build_modules, expected);
        assert_eq!(lsp_modules, expected);
        assert_eq!(watch_modules, expected);
        assert_eq!(loaded.entry_module, watched.entry_path);
        assert_eq!(loaded.lint_config_dir, fixture.path());
        assert_eq!(watched.root.path(), fixture.path());
        assert_eq!(watched.scope.root, fixture.path());
        assert_eq!(watched.root.manifest().name, build_root.manifest().name);
        assert_eq!(
            watched.root.manifest().name,
            crate::project_root::DEFAULT_NAME,
            "the stray manifest under src/ names no project"
        );
        let cache_of = |root: &ProjectRoot| {
            root.cache_dir()
                .expect("the cache opens")
                .map(|cache| cache.path().to_path_buf())
        };
        assert_eq!(cache_of(&build_root), Some(cache.clone()));
        assert_eq!(cache_of(&watched.root), Some(cache));
    }
}
