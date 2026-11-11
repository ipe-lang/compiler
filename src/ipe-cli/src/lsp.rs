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
//! Each embedded stdlib module it reports carries the path of a verified
//! read-only copy in the per-user cache, so a definition inside the stdlib
//! has a file the editor can open.

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
        | CliError::DirectoryExpected { .. }
        | CliError::DependencyNotCompiled { .. } => LoadError::RootRefused(detail),
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
        | CliError::ProjectRefused(_)
        | CliError::UnknownCommand { .. }
        | CliError::Pipeline { .. }
        | CliError::RuntimeDirInvalid { .. }
        | CliError::RuntimeHomeUnknown
        | CliError::CacheHomeUnknown
        | CliError::EnvDirNotAbsolute { .. }
        | CliError::EnvSwitchNotRecognised { .. }
        | CliError::EnvRefused(_)
        | CliError::ServePortTaken { .. }
        | CliError::RuntimeMaterializeFailed { .. }
        | CliError::RuntimeVersionMismatch { .. }
        | CliError::RuntimeTreeRefused { .. }
        | CliError::RuntimeVersionUnknown { .. }
        | CliError::ReleaseRuntimeOverride { .. }
        | CliError::EmittedBuildFailed { .. }
        | CliError::CargoBuildTimedOut { .. }
        | CliError::TargetDirUnlinkable { .. }
        | CliError::BundledManifest { .. }
        | CliError::TestTargetBusy { .. }
        | CliError::TestRunnerStale { .. }
        | CliError::TestRunKeyUnavailable { .. }
        | CliError::UnknownCode { .. }
        | CliError::DocNotFound { .. }
        | CliError::StaticRefusal(_)
        | CliError::CapabilityMismatch { .. }
        | CliError::Resolve(_)
        | CliError::LockRefused(_)
        | CliError::IndexEntryRefused(_)
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
        | CliError::AgentsGuideRefused(_)
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
        | FfiPrepError::AssertedShimSeal(_) => LoadError::Pipeline(detail),
        FfiPrepError::DefineOpaqueCollision { .. }
        | FfiPrepError::DependencyMerge(_)
        | FfiPrepError::CatalogSeal(_)
        | FfiPrepError::TransparentWithoutShape { .. }
        | FfiPrepError::AssertedWithoutCatalog => LoadError::FfiCatalogRefused(detail),
    }
}

/// The read-only per-user copies of the embedded stdlib sources an editor opens.
///
/// A definition inside the stdlib needs a file the editor can open, but the
/// stdlib lives only inside the binary. Each module is written once into
/// `<cache base>/ipe/stdlib/<key>/`, where the key digests the compiler
/// version and the whole embedded table, so one compiler's copies never
/// serve another's sources. The trust boundary is held three ways: the
/// directory is a [`ProvenDir`] (every ancestor proven, the leaf private), a
/// file name exists only for a module of the compile-time stdlib table, and
/// a copy is handed out only after its bytes re-prove equal to the embedded
/// source — a tampered, partial or swapped copy is re-written through a
/// fresh temporary file and an atomic rename, never served.
mod stdlib_cache {
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use ipe_stdlib::{COMPILED_STD_MODULES, CompiledStdModule};
    use sha2::Digest as _;

    use crate::proven_dir::{EntryName, NewFileMode, ProvenDir};

    /// The most bytes every copy and its temporary file may occupy together.
    pub const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;

    /// The bytes the whole table occupies on disk at most: every copy plus one temporary file each.
    const fn table_footprint(mut rest: &[CompiledStdModule]) -> Option<usize> {
        let mut sum: usize = 0;
        while let Some((module, tail)) = rest.split_first() {
            sum = match sum.checked_add(module.source.len()) {
                Some(next) => next,
                None => return None,
            };
            rest = tail;
        }
        sum.checked_mul(2)
    }

    /// Whether `footprint` is a computed size within [`MAX_CACHE_BYTES`].
    pub const fn within_cap(footprint: Option<usize>) -> bool {
        matches!(footprint, Some(bytes) if bytes <= MAX_CACHE_BYTES)
    }

    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the embedded stdlib outgrows the cache's size ceiling [ledger #boundary]
    const _: () = assert!(within_cap(table_footprint(COMPILED_STD_MODULES)));

    /// The directory name under `<cache base>/ipe` the copies live in.
    const STDLIB_DIR: &str = "stdlib";

    /// The domain tag that opens the key digest.
    const KEY_TAG: &[u8] = b"ipe-stdlib-sources\0";

    /// The version key: SHA-256 over the compiler version and every table entry, each length-framed.
    fn cache_key() -> &'static str {
        static KEY: OnceLock<String> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut hasher = sha2::Sha256::new();
            hasher.update(KEY_TAG);
            let mut frame = |bytes: &[u8]| {
                let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                hasher.update(len.to_le_bytes());
                hasher.update(bytes);
            };
            frame(crate::runtime_embed::COMPILER_VERSION.as_bytes());
            for module in COMPILED_STD_MODULES {
                frame(module.dotted.as_bytes());
                frame(module.source.as_bytes());
            }
            hex::encode(hasher.finalize())
        })
    }

    /// The directory the copies of this compiler's stdlib live in, under `cache_base`.
    pub fn dir_under(cache_base: &Path) -> PathBuf {
        cache_base.join("ipe").join(STDLIB_DIR).join(cache_key())
    }

    /// A stdlib module of the compile-time table, with the two entry names its copy uses.
    pub struct StdlibEntry {
        /// The embedded source the copy must hold.
        source: &'static str,
        /// The copy's name, `<dotted>.ipe`.
        copy: EntryName,
        /// The temporary file the copy is written through, `.<dotted>.ipe.tmp`.
        temp: EntryName,
    }

    impl StdlibEntry {
        /// Parse `module` into its table entry; `None` unless the table holds it.
        ///
        /// The names come from the table's own dotted spelling, every segment
        /// a legal module segment, so no name a caller supplies reaches a path.
        pub fn of(module: &[String]) -> Option<Self> {
            let entry = COMPILED_STD_MODULES.iter().find(|entry| {
                entry
                    .dotted
                    .split('.')
                    .eq(module.iter().map(String::as_str))
            })?;
            if !entry
                .dotted
                .split('.')
                .all(crate::project::is_module_segment)
            {
                return None;
            }
            let copy = format!("{}.ipe", entry.dotted);
            let temp = format!(".{copy}.tmp");
            Some(Self {
                source: entry.source,
                copy: EntryName::new(copy.as_ref())?,
                temp: EntryName::new(temp.as_ref())?,
            })
        }
    }

    /// This compiler's stdlib copy directory, held open and proven private.
    pub struct StdlibCache {
        /// The held directory every copy is written and read through.
        dir: ProvenDir,
    }

    impl StdlibCache {
        /// Hold this compiler's copy directory under `cache_base`, creating it.
        ///
        /// `None` when any component fails its ownership proof, or on a host
        /// with no file ownership to prove it by.
        pub fn open(cache_base: &Path) -> Option<Self> {
            ProvenDir::create(&dir_under(cache_base))
                .ok()
                .map(|dir| Self { dir })
        }

        /// The path of `module`'s verified copy, written first when absent or wrong.
        ///
        /// `None` when `module` is not a table module, when `text` is not its
        /// embedded source, or when no verified copy could be put in place.
        pub fn materialise(&self, module: &[String], text: &str) -> Option<PathBuf> {
            let entry = StdlibEntry::of(module)?;
            if entry.source != text {
                return None;
            }
            if !self.holds(&entry) {
                self.write(&entry).ok()?;
                if !self.holds(&entry) {
                    return None;
                }
            }
            Some(self.dir.path_of(&entry.copy))
        }

        /// Whether the copy of `entry` is a read-only regular file holding exactly its source.
        pub fn holds(&self, entry: &StdlibEntry) -> bool {
            self.dir
                .open_file(&entry.copy)
                .is_ok_and(|file| holds_exactly(file, entry.source))
        }

        /// Write `entry`'s copy through its temporary file and rename it into place.
        fn write(&self, entry: &StdlibEntry) -> io::Result<()> {
            let file = match self
                .dir
                .create_file(&entry.temp, NewFileMode::WorldReadable)
            {
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    self.dir.remove_file(&entry.temp)?;
                    self.dir
                        .create_file(&entry.temp, NewFileMode::WorldReadable)?
                }
                created => created?,
            };
            let placed = fill_read_only(file, entry.source)
                .and_then(|()| self.dir.rename(&entry.temp, &entry.copy));
            if placed.is_err() {
                // The rename failed, so the temporary file is the one this
                // call created; the error reported is the write's own.
                let _ = self.dir.remove_file(&entry.temp);
            }
            placed
        }
    }

    /// Write `source` into `file`, flush it to disk, and drop every write permission.
    fn fill_read_only(mut file: File, source: &str) -> io::Result<()> {
        file.write_all(source.as_bytes())?;
        file.sync_all()?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)
    }

    /// Whether the open `file` is read-only and holds exactly `source`, read no further than one byte past it.
    fn holds_exactly(file: File, source: &str) -> bool {
        let read_only = file
            .metadata()
            .is_ok_and(|meta| meta.is_file() && meta.permissions().readonly());
        let Some(cap) = u64::try_from(source.len())
            .ok()
            .and_then(|len| len.checked_add(1))
        else {
            return false;
        };
        let mut bytes = Vec::with_capacity(source.len());
        read_only && file.take(cap).read_to_end(&mut bytes).is_ok() && bytes == source.as_bytes()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_embedded_table_fits_the_cache_ceiling() {
            assert!(within_cap(table_footprint(COMPILED_STD_MODULES)));
        }

        #[test]
        fn a_footprint_past_the_ceiling_or_overflowing_is_refused() {
            assert!(within_cap(Some(MAX_CACHE_BYTES)));
            assert!(!within_cap(Some(MAX_CACHE_BYTES + 1)));
            assert!(!within_cap(None));
            let table = [
                CompiledStdModule {
                    dotted: "Ipe.A",
                    source: "",
                    tier: ipe_stdlib::StdTier::Public,
                },
                CompiledStdModule {
                    dotted: "Ipe.B",
                    source: "x",
                    tier: ipe_stdlib::StdTier::Public,
                },
            ];
            assert_eq!(table_footprint(&table), Some(2));
        }

        #[test]
        fn only_a_table_module_names_an_entry() {
            let tuple = StdlibEntry::of(&["Ipe".to_owned(), "Tuple".to_owned()]);
            assert!(
                tuple.is_some_and(|entry| entry.copy.as_os_str() == "Ipe.Tuple.ipe"
                    && entry.temp.as_os_str() == ".Ipe.Tuple.ipe.tmp")
            );
            for refused in [
                vec!["Ipe".to_owned(), "Nope".to_owned()],
                vec!["Main".to_owned()],
                vec!["..".to_owned()],
                vec!["Ipe".to_owned(), "../../etc/passwd".to_owned()],
                vec!["Ipe.Tuple".to_owned()],
                vec![],
            ] {
                assert!(StdlibEntry::of(&refused).is_none(), "{refused:?}");
            }
        }

        #[test]
        fn the_key_is_a_full_sha256_digest_under_the_stdlib_dir() {
            let key = cache_key();
            assert_eq!(key.len(), 64);
            assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(dir_under(Path::new("/c")).starts_with("/c/ipe/stdlib"));
        }

        #[cfg(unix)]
        mod disk {
            use std::fs;
            use std::os::unix::fs::PermissionsExt as _;

            use super::super::*;

            fn tuple() -> Vec<String> {
                vec!["Ipe".to_owned(), "Tuple".to_owned()]
            }

            fn tuple_source() -> &'static str {
                COMPILED_STD_MODULES
                    .iter()
                    .find(|module| module.dotted == "Ipe.Tuple")
                    .map_or("", |module| module.source)
            }

            /// A fresh private directory to root a cache base in.
            #[allow(clippy::expect_used)] // test fixture: a failed mkdir IS the failure
            fn scratch(name: &str) -> PathBuf {
                let base = ipe_test_temp::temp_root()
                    .canonicalize()
                    .expect("canonical temp dir");
                let dir = base.join(format!(
                    "ipe-stdlib-cache-{name}-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                ));
                let _ = fs::remove_dir_all(&dir);
                fs::create_dir_all(&dir).expect("create scratch dir");
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                    .expect("make scratch dir private");
                dir
            }

            fn mode(path: &Path) -> u32 {
                fs::symlink_metadata(path).map_or(0, |meta| meta.permissions().mode() & 0o777)
            }

            /// Replace the copy at `path` with `bytes`, writable, as a tamperer would.
            #[allow(clippy::expect_used)] // test fixture: a failed tamper IS the failure
            fn tamper(path: &Path, bytes: &[u8]) {
                fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("chmod");
                fs::write(path, bytes).expect("tamper");
            }

            #[test]
            #[allow(clippy::expect_used)] // test fixture: a refused cache IS the failure
            fn a_copy_is_written_read_only_into_a_private_versioned_dir() {
                let base = scratch("fresh");
                let cache = StdlibCache::open(&base).expect("the cache opens");
                let path = cache
                    .materialise(&tuple(), tuple_source())
                    .expect("the copy is materialised");
                assert_eq!(path, dir_under(&base).join("Ipe.Tuple.ipe"));
                assert_eq!(
                    fs::read_to_string(&path).ok().as_deref(),
                    Some(tuple_source())
                );
                assert_eq!(mode(&path), 0o444);
                assert_eq!(mode(&dir_under(&base)), 0o700);
                assert!(!dir_under(&base).join(".Ipe.Tuple.ipe.tmp").exists());
                assert_eq!(cache.materialise(&tuple(), tuple_source()), Some(path));
            }

            #[test]
            #[allow(clippy::expect_used)] // test fixture: a refused cache IS the failure
            fn a_tampered_partial_or_writable_copy_is_rewritten_never_served() {
                let base = scratch("tampered");
                let cache = StdlibCache::open(&base).expect("the cache opens");
                let entry = StdlibEntry::of(&tuple()).expect("a table module");
                let path = cache
                    .materialise(&tuple(), tuple_source())
                    .expect("the copy is materialised");
                let truncated = tuple_source().as_bytes().get(..10).unwrap_or_default();
                let appended = format!("{}\nevil = 1\n", tuple_source());
                for bad in [b"module Evil".as_slice(), truncated, appended.as_bytes()] {
                    tamper(&path, bad);
                    assert!(!cache.holds(&entry), "a tampered copy never holds");
                    assert_eq!(
                        cache.materialise(&tuple(), tuple_source()),
                        Some(path.clone())
                    );
                    assert_eq!(
                        fs::read_to_string(&path).ok().as_deref(),
                        Some(tuple_source())
                    );
                    assert_eq!(mode(&path), 0o444);
                }
                tamper(&path, tuple_source().as_bytes());
                assert!(!cache.holds(&entry), "a writable copy never holds");
                assert_eq!(
                    cache.materialise(&tuple(), tuple_source()),
                    Some(path.clone())
                );
                assert_eq!(mode(&path), 0o444);
            }

            #[test]
            #[allow(clippy::expect_used)] // test fixture: a failed plant IS the failure
            fn a_planted_link_is_replaced_and_its_target_left_untouched() {
                let base = scratch("link");
                let cache = StdlibCache::open(&base).expect("the cache opens");
                let victim = base.join("victim.txt");
                fs::write(&victim, "victim").expect("write victim");
                let copy = dir_under(&base).join("Ipe.Tuple.ipe");
                std::os::unix::fs::symlink(&victim, &copy).expect("plant link");
                let temp = dir_under(&base).join(".Ipe.Tuple.ipe.tmp");
                std::os::unix::fs::symlink(&victim, &temp).expect("plant temp link");
                assert_eq!(
                    cache.materialise(&tuple(), tuple_source()),
                    Some(copy.clone())
                );
                assert_eq!(fs::read_to_string(&victim).ok().as_deref(), Some("victim"));
                assert!(fs::symlink_metadata(&copy).is_ok_and(|meta| meta.is_file()));
                assert_eq!(
                    fs::read_to_string(&copy).ok().as_deref(),
                    Some(tuple_source())
                );
            }

            #[test]
            #[allow(clippy::expect_used)] // test fixture: a failed mkdir IS the failure
            fn a_directory_squatting_the_copy_name_yields_no_copy() {
                let base = scratch("squat");
                let cache = StdlibCache::open(&base).expect("the cache opens");
                fs::create_dir(dir_under(&base).join("Ipe.Tuple.ipe")).expect("squat");
                assert_eq!(cache.materialise(&tuple(), tuple_source()), None);
            }

            #[test]
            #[allow(clippy::expect_used)] // test fixture: a refused cache IS the failure
            fn a_foreign_module_or_foreign_text_writes_nothing() {
                let base = scratch("foreign");
                let cache = StdlibCache::open(&base).expect("the cache opens");
                assert_eq!(
                    cache.materialise(&tuple(), "module Ipe.Tuple exposing (x)"),
                    None
                );
                assert_eq!(
                    cache.materialise(&["Main".to_owned()], tuple_source()),
                    None
                );
                assert_eq!(
                    cache.materialise(&["Ipe".to_owned(), "..".to_owned()], tuple_source()),
                    None
                );
                let written = fs::read_dir(dir_under(&base)).map_or(usize::MAX, Iterator::count);
                assert_eq!(written, 0, "no refused module leaves a file behind");
            }

            #[test]
            #[allow(clippy::expect_used)] // test fixture: a failed chmod IS the failure
            fn a_cache_base_other_users_can_write_is_refused() {
                let base = scratch("shared");
                fs::set_permissions(&base, fs::Permissions::from_mode(0o777)).expect("chmod");
                assert!(StdlibCache::open(&base).is_none());
                fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("chmod");
            }
        }
    }
}

/// The driver's project loader, holding where stdlib copies are cached.
struct DriverLoader {
    /// The per-user cache base stdlib copies go under; `None` keeps the
    /// embedded stdlib without an openable file.
    stdlib_cache_base: Option<PathBuf>,
}

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
        let stdlib_cache = self
            .stdlib_cache_base
            .as_deref()
            .and_then(stdlib_cache::StdlibCache::open);
        let files = resolved
            .snapshot
            .modules()
            .iter()
            .map(|(module, held)| {
                let held_path = || held.path().to_path_buf();
                let (origin, path) = match held.origin() {
                    SourceOrigin::Own(SourceDir::Src | SourceDir::Tests) => {
                        (ipe_canon::ModuleOrigin::User, held_path())
                    }
                    SourceOrigin::Stdlib => (
                        ipe_canon::ModuleOrigin::EmbeddedStdlib,
                        stdlib_cache
                            .as_ref()
                            .and_then(|cache| cache.materialise(module, held.text()))
                            .unwrap_or_else(held_path),
                    ),
                    SourceOrigin::FfiInterface => {
                        (ipe_canon::ModuleOrigin::FfiInterface, held_path())
                    }
                };
                let file = LoadedFile {
                    path,
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
    let loader = DriverLoader {
        stdlib_cache_base: crate::resolve::default_cache_base().ok(),
    };
    ipe_lsp_server::run_stdio(&loader).map_err(|e| CliError::Usage(text::msg::lsp_failed(&e)))
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

    /// A loader that leaves the embedded stdlib without a cached copy.
    const NO_STDLIB_CACHE: DriverLoader = DriverLoader {
        stdlib_cache_base: None,
    };

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
            CliError::RuntimeHomeUnknown,
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
    fn every_ffi_prep_error() -> [FfiPrepError; 8] {
        let witness = FfiPrepError::ReservedModuleExists;
        match witness {
            FfiPrepError::ModuleClaimed { .. }
            | FfiPrepError::ReservedModuleExists
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
        assert_eq!(source_side.len(), 3, "{source_side:?}");
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
        let loaded = NO_STDLIB_CACHE.load(std::slice::from_ref(&folder), &main, Some(MAIN));
        let expected = CliError::NoManifest { dir: folder }.to_string();
        let err = loaded.err();
        assert_eq!(err, Some(LoadError::RootRefused(expected)));
        assert_eq!(
            err.as_ref().map(LoadError::disposition),
            Some(ipe_lsp_server::LoadDisposition::Refuse)
        );
    }

    /// A package that declares a dependency refuses the load with the
    /// compiler's own not-compiled refusal, and the server keeps serving: the
    /// refusal is a disposition, never a crash.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed fixture IS the failure
    fn a_declared_dependency_refuses_the_load() {
        let tree = crate::project_root::SourceTree::main(MAIN)
            .field("dependencies = [ depPath \"s-lib\" \"../s-lib\" ]");
        let fixture = RootFixture::from_tree(&tree).expect("fixture");
        let main = fixture.path().join("src").join("Main.ipe");
        let loaded = NO_STDLIB_CACHE.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
        let err = loaded.err();
        assert!(
            matches!(&err, Some(LoadError::RootRefused(detail)) if detail.contains("`s-lib`")),
            "{err:?}"
        );
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
        let loaded = NO_STDLIB_CACHE.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
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

    /// An asserted call into an uninstalled crate is a source refusal: the
    /// load degrades with the IPE-F4414 refusal of that call, never refuses
    /// the workspace, since an edit to the call lifts it.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed fixture write IS the failure
    fn an_asserted_call_refusal_degrades_the_load() {
        let asserted = "module Main exposing (shifted)\nimport Rust.Ffi\n\n\n\
                        shifted : Int -> Result Error Int\nshifted =\n    Rust.Ffi.call \"tm::shift\"\n";
        let fixture = RootFixture::main(asserted).expect("fixture");
        let main = fixture.path().join("src/Main.ipe");
        let loaded = NO_STDLIB_CACHE.load(&[fixture.path().to_path_buf()], &main, Some(asserted));
        let err = loaded.err();
        assert!(
            matches!(&err, Some(LoadError::Pipeline(detail))
                if detail.contains("IPE-F4414") && detail.contains("tm::shift")),
            "{err:?}"
        );
        assert_eq!(
            err.as_ref().map(LoadError::disposition),
            Some(ipe_lsp_server::LoadDisposition::Degrade)
        );
    }

    /// A tampered FFI catalog under the project root refuses the load rather than degrading it.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed write IS the failure
    fn a_tampered_catalog_refuses_the_load() {
        let fixture = RootFixture::main(MAIN).expect("fixture");
        let main = fixture.path().join("src/Main.ipe");
        let cache = private_chain(fixture.path(), &ipe_ffi::driver::FFI_CACHE_COMPONENTS);
        fs::write(cache.join("x.consumer.json"), "{ not json").expect("write artifact");
        let loaded = NO_STDLIB_CACHE.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
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
        let loaded = NO_STDLIB_CACHE.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
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

        let loaded = NO_STDLIB_CACHE.load(&[fixture.path().to_path_buf()], &main, Some(MAIN));
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
        let loaded = NO_STDLIB_CACHE
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

    /// An imported stdlib module loads at its verified read-only cache copy, a user module at its source.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed fixture or load IS the failure
    fn a_loaded_stdlib_module_points_at_its_verified_cache_copy() {
        let source = "module Main exposing (main)\n\nimport Ipe.Tuple as Tuple\n\nmain =\n    Tuple.first ( 1, 2 )\n";
        let fixture = RootFixture::main(source).expect("fixture");
        let base = fixture.path().join("cache-base");
        fs::create_dir(&base).expect("cache base");
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("private base");
        let caching = DriverLoader {
            stdlib_cache_base: Some(base.clone()),
        };
        let main = fixture.path().join("src").join("Main.ipe");
        let loaded = caching
            .load(&[fixture.path().to_path_buf()], &main, Some(source))
            .expect("the project loads");
        let tuple = loaded
            .files
            .get(&vec!["Ipe".to_owned(), "Tuple".to_owned()])
            .expect("the stdlib closure holds Ipe.Tuple");
        assert_eq!(tuple.origin, ipe_canon::ModuleOrigin::EmbeddedStdlib);
        assert_eq!(
            tuple.path,
            stdlib_cache::dir_under(&base).join("Ipe.Tuple.ipe")
        );
        assert_eq!(
            fs::read_to_string(&tuple.path).ok().as_deref(),
            Some(tuple.text.as_str())
        );
        let mode = fs::metadata(&tuple.path).map_or(0, |meta| meta.permissions().mode() & 0o777);
        assert_eq!(mode, 0o444);
        let user = loaded
            .files
            .get(&vec!["Main".to_owned()])
            .expect("the entry module loads");
        assert_eq!(user.path, main);
    }

    /// With no cache base the stdlib keeps its synthetic path, which names no openable file.
    #[test]
    #[allow(clippy::expect_used)] // test fixture: a failed fixture or load IS the failure
    fn without_a_cache_base_the_stdlib_keeps_no_openable_path() {
        let source = "module Main exposing (main)\n\nimport Ipe.Tuple as Tuple\n\nmain =\n    Tuple.first ( 1, 2 )\n";
        let fixture = RootFixture::main(source).expect("fixture");
        let main = fixture.path().join("src").join("Main.ipe");
        let loaded = NO_STDLIB_CACHE
            .load(&[fixture.path().to_path_buf()], &main, Some(source))
            .expect("the project loads");
        let tuple = loaded
            .files
            .get(&vec!["Ipe".to_owned(), "Tuple".to_owned()])
            .expect("the stdlib closure holds Ipe.Tuple");
        assert!(tuple.path.is_relative(), "{}", tuple.path.display());
    }
}
