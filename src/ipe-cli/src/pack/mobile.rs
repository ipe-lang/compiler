//! Mobile packaging: wrapping a built client-wasm Web SPA in a thin native
//! system-webview shell for iOS or Android.
//!
//! The `--target wasm` build produces a self-contained offline SPA bundle
//! (`index.html` + a boot script + the `wasm-bindgen` glue + the `.wasm`). This
//! module lays out a native shell *around* that bundle: an iOS Xcode project
//! whose `WKWebView` serves the bundle through a `WKURLSchemeHandler` (so the
//! `.wasm` loads with the correct MIME, which a bare `file://` load cannot
//! guarantee), or an Android Gradle project whose `WebView` serves it through a
//! `WebViewAssetLoader`. The webview loads ONLY the bundled local assets — an
//! offline app, never a remote-web wrapper.
//!
//! The `Info.plist` / `AndroidManifest.xml` permission entries are never authored
//! here: they come only from [`crate::pack::permissions`], the single source of
//! truth for what a packaged app may do. This module assembles the manifest
//! *around* that derivation, so a mobile bundle can neither under-declare relative
//! to consent nor smuggle an OS permission the app never accepted.
//!
//! ## Provable here vs authored-but-unrun
//! The project GENERATION, the manifest MERGE, and the wasm BUNDLING are produced
//! and asserted end-to-end on this box (the layout + the derived-permission
//! manifest are pure data). The Android build MAY run where the SDK is present;
//! the iOS build needs macOS + Xcode + signing and belongs on that runner. This
//! module never fakes a mobile toolchain invocation.

use std::collections::BTreeSet;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};

use ipe_fs_open::{EntryCap, EntryName, FileId, FileKind, HeldDir, OpenRefusal};
use ipe_ir::Capability;
use ipe_runtime_rust::encoding::MountBase;

use crate::CliError;
use crate::driver::BundleProfile;
use crate::output_dir::OwnedDir;
use crate::text;

use super::permissions::{self, Platform};

/// A mobile operating system this packager targets.
///
/// A closed set (no wildcard), so a new mobile OS forces a decision at every match
/// rather than silently falling through.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum MobileOs {
    /// An iOS app — an Xcode project with a `WKWebView` + `WKURLSchemeHandler`
    /// shell and an `Info.plist`.
    Ios,
    /// An Android app — a Gradle project with a `WebView` + `WebViewAssetLoader`
    /// shell and an `AndroidManifest.xml`.
    Android,
}

impl MobileOs {
    /// The lowercase wire name of this OS — the `web solo <os>` delivery host word
    /// and the `dist/<os>/` bundle directory.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::Android => "android",
        }
    }

    /// The permission [`Platform`] a mobile bundle derives its OS permissions for.
    #[must_use]
    pub const fn platform(self) -> Platform {
        match self {
            Self::Ios => Platform::Ios,
            Self::Android => Platform::Android,
        }
    }

    /// Whether the actual native build for this OS can run on this Linux host.
    ///
    /// The Android build MAY run where the Android SDK is installed; the iOS build
    /// needs macOS + Xcode + signing, so it is always authored-but-unrun here.
    #[must_use]
    pub const fn build_runs_on_linux(self) -> bool {
        matches!(self, Self::Android)
    }
}

impl std::str::FromStr for MobileOs {
    type Err = UnknownMobileOs;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "ios" => Ok(Self::Ios),
            "android" => Ok(Self::Android),
            other => Err(UnknownMobileOs(other.to_owned())),
        }
    }
}

/// An unrecognised mobile-OS token where an `ios`/`android` host was expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownMobileOs(pub String);

impl std::fmt::Display for UnknownMobileOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown mobile OS {:?} (expected one of: ios, android)",
            self.0
        )
    }
}

impl std::error::Error for UnknownMobileOs {}

/// Resolve the mobile OS a `web solo <os>` delivery host names.
///
/// The mobile host word is always explicit — this host is not a mobile device, so
/// there is no host default. An absent word is a typed refusal, an unrecognised
/// one another; the delivery grammar only ever passes `ios`/`android`.
///
/// # Errors
/// [`MobileRefusal::MissingOs`] for an absent OS word;
/// [`MobileRefusal::UnknownOs`] for an OS word outside the closed set.
pub fn resolve_os(explicit: Option<&str>) -> Result<MobileOs, MobileRefusal> {
    explicit.map_or(Err(MobileRefusal::MissingOs), |name| {
        name.parse::<MobileOs>()
            .map_err(|e| MobileRefusal::UnknownOs(e.0))
    })
}

/// The declared web-delivery capability a mobile bundle requires of the app.
///
/// A mobile shell hosts the client-wasm SPA; only a `Web` app compiled for the
/// wasm client target has such a bundle. Modelled as the two independent facts the
/// gate reads, so the refusal can name exactly which one is missing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WebSpaCapability {
    /// Whether the app's declared shape is `Web` (or unset — inference decides).
    /// A `Terminal` / `WebView` / `Program` shape has no client-wasm SPA to host.
    pub shape_is_web: bool,
    /// Whether the project's `[wasm]` mode is active (`solo` / `hydrate`), so a
    /// `--target wasm` build produces a hostable bundle.
    pub wasm_enabled: bool,
}

/// Gate an app for mobile packaging: it must be a wasm-enabled `Web` SPA.
///
/// A mobile shell has nothing to host unless the app both declares (or infers) a
/// `Web` shape and enables the wasm client target. Either fact missing is a
/// fail-closed, typed refusal naming exactly what is absent — never a bundle
/// produced around an empty or non-existent SPA.
///
/// # Errors
/// [`MobileRefusal::NotWebShape`] when the declared shape is not `Web`;
/// [`MobileRefusal::WasmDisabled`] when the `[wasm]` mode is off/absent.
pub const fn require_web_spa(cap: WebSpaCapability) -> Result<(), MobileRefusal> {
    if !cap.shape_is_web {
        return Err(MobileRefusal::NotWebShape);
    }
    if !cap.wasm_enabled {
        return Err(MobileRefusal::WasmDisabled);
    }
    Ok(())
}

/// A typed, fail-closed refusal from the mobile packager.
///
/// Every mobile-packaging error the packager itself raises is a member here, so
/// the CLI boundary renders each with its remedy (and its stable code, where one
/// is registered) and no path produces a bundle it should have refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MobileRefusal {
    /// No mobile-OS host word was given, and there is no host default for a
    /// mobile target.
    MissingOs,
    /// The mobile-OS host word named an OS outside the closed set.
    UnknownOs(String),
    /// The app's declared shape is not `Web`, so it has no client-wasm SPA to host
    /// in a webview.
    NotWebShape,
    /// The app is a `Web` app but its `[wasm]` mode is off/absent, so a
    /// `--target wasm` build produces no hostable SPA bundle.
    WasmDisabled,
    /// `delivery.browser.basePath` read after the wasm build differs from the one the
    /// shell was planned for, so the bundle's URLs and the shell's handlers
    /// would name two different mount paths.
    ManifestChanged {
        /// The mount base read before the build.
        before: MountBase,
        /// The mount base read after the build.
        after: MountBase,
    },
}

impl std::fmt::Display for MobileRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingOs => write!(
                f,
                "error[IPE-P0020]: a mobile bundle needs an OS — \
                 name one: `ipe dev build web solo <ios|android>`"
            ),
            Self::UnknownOs(got) => write!(
                f,
                "error[IPE-P0021]: unknown mobile OS {got:?} \
                 (expected `ipe dev build web solo <ios|android>`)"
            ),
            Self::NotWebShape => write!(
                f,
                "error[IPE-P0022]: `web solo <ios|android>` wraps a client-wasm `Web` SPA, \
                 but this app's shape is not `Web`\n  \
                 = a mobile bundle hosts the app's browser SPA in a system webview; only a \
                 `Web` app compiled to wasm has such a bundle. Declare a `Web` program shape, \
                 or choose the matching host for this app."
            ),
            Self::WasmDisabled => write!(
                f,
                "error[IPE-P0023]: `web solo <ios|android>` wraps the wasm client, \
                 but this project's `[wasm]` mode is off (or absent)\n  \
                 = enable the wasm client target so a hostable browser bundle exists: set \
                 `[wasm] mode = Solo` (or `Hydrate`) in package.ipe."
            ),
            Self::ManifestChanged { before, after } => write!(
                f,
                "error: `delivery.browser.basePath` changed from `{}` to `{}` while the \
                 wasm bundle was building\n  \
                 = the bundle and the mobile shell must serve one mount path; leave \
                 package.ipe unchanged during the pack and run it again.",
                before.dir_url(),
                after.dir_url()
            ),
        }
    }
}

impl std::error::Error for MobileRefusal {}

/// How deep below `www/` the asset walk descends, in directory levels.
///
/// A wasm SPA holds `index.html`, a boot script and `pkg/*`, so a few levels
/// suffice; a deeper tree is refused rather than walked.
pub const MAX_ASSET_DEPTH: NonZeroUsize = NonZeroUsize::MIN.saturating_add(31);

/// How many entries, files and directories alike, the asset walk visits in all.
///
/// Each listing is charged to this budget in full the moment it is read, so
/// the listings held along the open path never hold more names than it.
pub const MAX_ASSETS: NonZeroU32 = NonZeroU32::MIN.saturating_add(65_535);

/// The ceilings one asset walk runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AssetLimits {
    /// The deepest directory level below `www/` the walk enters.
    depth: NonZeroUsize,
    /// The most entries the walk visits, and the most one directory may list.
    entries: NonZeroU32,
}

impl AssetLimits {
    /// The ceilings every packaged bundle is collected under.
    const PRODUCTION: Self = Self {
        depth: MAX_ASSET_DEPTH,
        entries: MAX_ASSETS,
    };
}

/// An asset's identity: its entry names below `www/`, one per directory level.
///
/// Built name by name during the walk, never stripped or joined from an
/// absolute path, and only from names that are UTF-8, so its `/`-joined shell
/// form spells exactly the entries it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetPath {
    /// The entry names, outermost directory first; never empty.
    segments: Vec<EntryName>,
    /// The names joined by `/`.
    shell_rel: String,
}

impl AssetPath {
    /// The asset path `segments` spells, or `None` when it is empty or a name is not UTF-8.
    fn new(segments: Vec<EntryName>) -> Option<Self> {
        if segments.is_empty() {
            return None;
        }
        let mut shell_rel = String::new();
        for (index, name) in segments.iter().enumerate() {
            if index > 0 {
                shell_rel.push('/');
            }
            shell_rel.push_str(name.as_os_str().to_str()?);
        }
        Some(Self {
            segments,
            shell_rel,
        })
    }

    /// The entry names, outermost directory first.
    #[must_use]
    pub fn segments(&self) -> &[EntryName] {
        &self.segments
    }

    /// The `/`-joined form the shell layout places the asset under.
    #[must_use]
    pub fn to_shell_rel(&self) -> &str {
        &self.shell_rel
    }

    /// Whether this is the top-level `index.html`.
    fn is_index_html(&self) -> bool {
        matches!(self.segments.as_slice(), [only] if only.as_os_str() == "index.html")
    }
}

impl Ord for AssetPath {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.segments
            .iter()
            .map(EntryName::as_os_str)
            .cmp(other.segments.iter().map(EntryName::as_os_str))
    }
}

impl PartialOrd for AssetPath {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// One file a bundled SPA asset carries, named by its path below `www/`.
///
/// A typed value rather than a loose string so the asset set is inspectable and
/// a test can assert the full copied file set without materialising bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetFile {
    /// The asset's entry names below `www/`, which are also its path below the
    /// native project's web-asset root.
    pub path: AssetPath,
}

/// The emitted `www/` directory an SPA bundle was collected from, with its identity then.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaRoot {
    /// The `www/` path the walk opened.
    path: PathBuf,
    /// The identity of the directory the walk held.
    id: FileId,
}

impl SpaRoot {
    /// Prove the path still names the directory the bundle was collected from.
    ///
    /// # Errors
    /// [`BundleError::Replaced`] when `www/` is gone or now names another
    /// object; [`BundleError::Io`] when it cannot be opened or identified.
    pub fn verify_unreplaced(&self) -> Result<(), BundleError> {
        match open_www(&self.path).and_then(|dir| dir.id()) {
            Ok(id) if id == self.id => Ok(()),
            Ok(_) | Err(OpenRefusal::Absent | OpenRefusal::Link | OpenRefusal::NotRegular(_)) => {
                Err(BundleError::Replaced {
                    path: self.path.clone(),
                })
            }
            Err(refusal) => Err(BundleError::Io {
                path: self.path.clone(),
                source: refusal.into_io(),
            }),
        }
    }

    /// The path of `asset` below this root, joined from its entry names.
    fn source_of(&self, asset: &AssetPath) -> PathBuf {
        joined(&self.path, asset.segments())
    }
}

/// The offline SPA bundle a mobile shell hosts: the ordered set of asset files
/// copied out of a `--target wasm` build's `www/` tree.
///
/// Pure data derived from the emitted `www/` directory, so a test can assert the
/// full asset set without running a device toolchain. The webview serves these
/// and only these — local assets, no remote URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaBundle {
    /// The `www/` directory the assets were collected from.
    spa: SpaRoot,
    /// The asset files, sorted by [`AssetPath`].
    assets: Vec<AssetFile>,
}

impl SpaBundle {
    /// Collect the SPA asset set from an emitted `www/` directory.
    ///
    /// The walk holds `www_dir` and every directory below it as an open handle
    /// and names each asset by the entry names it descended through. Every
    /// regular file becomes one [`AssetFile`]; a link, FIFO, socket, device or
    /// other special file, or a name the shell cannot place, is refused rather
    /// than skipped. The set is sorted for determinism. An `index.html` is
    /// required — its absence means the input was not a `--target wasm` bundle,
    /// a fail-closed error rather than an empty shell.
    ///
    /// # Errors
    /// [`BundleError::NoIndexHtml`] when `www_dir` has no `index.html`;
    /// [`BundleError::UnplaceableAsset`] for an entry the shell cannot place;
    /// [`BundleError::TooDeep`] past [`MAX_ASSET_DEPTH`];
    /// [`BundleError::TooManyAssets`] past [`MAX_ASSETS`];
    /// [`BundleError::Io`] naming the exact path on any other walk failure.
    pub fn from_www_dir(www_dir: &Path) -> Result<Self, BundleError> {
        Self::from_www_dir_with(www_dir, AssetLimits::PRODUCTION)
    }

    /// [`SpaBundle::from_www_dir`] under the ceilings `limits`.
    fn from_www_dir_with(www_dir: &Path, limits: AssetLimits) -> Result<Self, BundleError> {
        let mut walk = AssetWalk {
            root: www_dir,
            limits,
            visited: 0,
            assets: Vec::new(),
        };
        let root =
            open_www(www_dir).map_err(|refusal| walk.refused(www_dir.to_path_buf(), refusal))?;
        let id = root
            .id()
            .map_err(|refusal| walk.refused(www_dir.to_path_buf(), refusal))?;
        walk.descend(&root, &mut Vec::new(), 0)?;
        let mut assets = walk.assets;
        assets.sort_by(|a, b| a.path.cmp(&b.path));
        if !assets.iter().any(|a| a.path.is_index_html()) {
            return Err(BundleError::NoIndexHtml {
                dir: www_dir.to_path_buf(),
            });
        }
        Ok(Self {
            spa: SpaRoot {
                path: www_dir.to_path_buf(),
                id,
            },
            assets,
        })
    }

    /// The asset files, sorted by [`AssetPath`].
    #[must_use]
    pub fn assets(&self) -> &[AssetFile] {
        &self.assets
    }
}

/// Open the emitted `www/` directory, its own entry held without following a link.
///
/// Only the levels above `www/` are followed, so a link standing at `www/`
/// itself is refused rather than walked or copied through.
///
/// # Errors
/// [`OpenRefusal::BadName`] when `www_dir` ends in no plain entry name;
/// [`OpenRefusal::Link`] when `www/` is a link; the refusal of any other
/// level that cannot be opened.
fn open_www(www_dir: &Path) -> Result<HeldDir, OpenRefusal> {
    let (Some(parent), Some(name)) = (www_dir.parent(), www_dir.file_name()) else {
        return Err(OpenRefusal::BadName);
    };
    let name = EntryName::new(name).ok_or(OpenRefusal::BadName)?;
    HeldDir::open_root(parent)?.child_dir(&name)
}

/// `root` with `names` appended, one component per name.
fn joined(root: &Path, names: &[EntryName]) -> PathBuf {
    names
        .iter()
        .fold(root.to_path_buf(), |path, name| path.join(name.as_os_str()))
}

/// One bounded walk of an emitted `www/` tree through held directory handles.
struct AssetWalk<'root> {
    /// The `www/` path, for messages only; never reopened.
    root: &'root Path,
    /// The ceilings this walk runs under.
    limits: AssetLimits,
    /// How many entries the walk has visited so far.
    visited: u32,
    /// The regular files found so far.
    assets: Vec<AssetFile>,
}

impl AssetWalk<'_> {
    /// Visit every entry of `dir`, the directory `prefix` names `depth` levels below `www/`.
    fn descend(
        &mut self,
        dir: &HeldDir,
        prefix: &mut Vec<EntryName>,
        depth: usize,
    ) -> Result<(), BundleError> {
        let listing = dir
            .entries(self.listing_cap())
            .map_err(|refusal| self.refused(joined(self.root, prefix), refusal))?;
        self.charge(listing.len())?;
        for (name, kind) in listing {
            let shown = joined(self.root, prefix).join(name.as_os_str());
            if name.as_os_str().to_str().is_none() {
                return Err(BundleError::UnplaceableAsset {
                    path: shown,
                    reason: AssetRefusal::NotUtf8,
                });
            }
            match kind {
                FileKind::Regular => {
                    let mut segments = prefix.clone();
                    segments.push(name);
                    let path = AssetPath::new(segments).ok_or(BundleError::UnplaceableAsset {
                        path: shown,
                        reason: AssetRefusal::NotUtf8,
                    })?;
                    self.assets.push(AssetFile { path });
                }
                FileKind::Dir => {
                    let Some(next) = depth
                        .checked_add(1)
                        .filter(|next| *next <= self.limits.depth.get())
                    else {
                        return Err(BundleError::TooDeep {
                            path: shown,
                            limit: self.limits.depth,
                        });
                    };
                    let child = dir
                        .child_dir(&name)
                        .map_err(|refusal| self.refused(shown, refusal))?;
                    prefix.push(name);
                    let walked = self.descend(&child, prefix, next);
                    prefix.pop();
                    walked?;
                }
                FileKind::Symlink
                | FileKind::Fifo
                | FileKind::Socket
                | FileKind::Device
                | FileKind::Other => {
                    return Err(BundleError::UnplaceableAsset {
                        path: shown,
                        reason: AssetRefusal::Kind(kind),
                    });
                }
            }
        }
        Ok(())
    }

    /// Charge a listing of `listed` names to the entry budget before any of it
    /// is visited, refusing once the budget is exceeded.
    ///
    /// Every listing on the open path is held while the walk descends; charging
    /// each in full on read keeps their names together within the budget.
    fn charge(&mut self, listed: usize) -> Result<(), BundleError> {
        let listed = u32::try_from(listed).unwrap_or(u32::MAX);
        self.visited = self.visited.saturating_add(listed);
        if self.visited > self.limits.entries.get() {
            return Err(BundleError::TooManyAssets {
                limit: self.limits.entries,
            });
        }
        Ok(())
    }

    /// The most names the next directory listing may hold: what is left of the
    /// walk's entry budget. A spent budget still lists one name, which the
    /// charge then refuses.
    fn listing_cap(&self) -> EntryCap {
        let left = self.limits.entries.get().saturating_sub(self.visited);
        EntryCap::new(left).unwrap_or(EntryCap::from_nonzero(NonZeroU32::MIN))
    }

    /// The bundle error for `refusal` met at `path`.
    ///
    /// An entry that turned into a link or another kind between its listing
    /// and its open is refused as that kind, never followed or skipped.
    fn refused(&self, path: PathBuf, refusal: OpenRefusal) -> BundleError {
        match refusal {
            OpenRefusal::Link => BundleError::UnplaceableAsset {
                path,
                reason: AssetRefusal::Kind(FileKind::Symlink),
            },
            OpenRefusal::NotRegular(kind) => BundleError::UnplaceableAsset {
                path,
                reason: AssetRefusal::Kind(kind),
            },
            OpenRefusal::BadName => BundleError::UnplaceableAsset {
                path,
                reason: AssetRefusal::BadName,
            },
            OpenRefusal::TooManyEntries(_) => BundleError::TooManyAssets {
                limit: self.limits.entries,
            },
            OpenRefusal::Absent
            | OpenRefusal::Denied
            | OpenRefusal::InUse
            | OpenRefusal::TooLarge(_)
            | OpenRefusal::NotUtf8
            | OpenRefusal::Io(_) => BundleError::Io {
                path,
                source: refusal.into_io(),
            },
        }
    }
}

/// Why the shell cannot place one entry of the emitted `www/` tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetRefusal {
    /// The entry's name is not valid UTF-8, which a shell asset path cannot carry.
    NotUtf8,
    /// The entry's name is not one plain entry name a held handle can open.
    BadName,
    /// The entry is not a regular file or a directory: this is what it is.
    Kind(FileKind),
}

impl std::fmt::Display for AssetRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str(text::mobile_asset_not_utf8()),
            Self::BadName => f.write_str(text::mobile_asset_bad_name()),
            Self::Kind(kind) => f.write_str(&text::mobile_asset_kind(kind)),
        }
    }
}

/// A path shown in a bundle message: escaped, so a control character, a
/// direction override or a byte that is not UTF-8 is spelled out, never shown raw
/// or replaced.
struct EscapedPath<'path>(&'path Path);

impl std::fmt::Display for EscapedPath<'_> {
    // The escaped `Debug` form is the point: `display()` shows control and
    // direction characters raw and replaces a byte that is not UTF-8.
    #[allow(clippy::unnecessary_debug_formatting)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// A failure while collecting the SPA bundle from an emitted `www/` tree.
#[derive(Debug)]
pub enum BundleError {
    /// The emitted `www/` directory has no `index.html` — the input was not a
    /// `--target wasm` bundle. Carries the directory inspected.
    NoIndexHtml {
        /// The `www/` directory that lacked an `index.html`.
        dir: PathBuf,
    },
    /// An entry of the `www/` tree the shell cannot place.
    UnplaceableAsset {
        /// The entry's full path, for the message only; never reopened.
        path: PathBuf,
        /// Why it cannot be placed.
        reason: AssetRefusal,
    },
    /// The `www/` tree nests directories deeper than the walk descends.
    TooDeep {
        /// The first directory past the ceiling, for the message only.
        path: PathBuf,
        /// The deepest level the walk enters.
        limit: NonZeroUsize,
    },
    /// The `www/` tree holds more entries than the walk visits.
    TooManyAssets {
        /// The most entries the walk visits.
        limit: NonZeroU32,
    },
    /// The `www/` path names another object than the directory collected.
    Replaced {
        /// The `www/` path.
        path: PathBuf,
    },
    /// A filesystem error while walking the `www/` tree.
    Io {
        /// The path the walk failed on.
        path: PathBuf,
        /// The underlying OS error.
        source: std::io::Error,
    },
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::NoIndexHtml { dir } => text::mobile_bundle_no_index(&EscapedPath(dir)),
            Self::UnplaceableAsset { path, reason } => {
                text::mobile_bundle_unplaceable(&EscapedPath(path), reason)
            }
            Self::TooDeep { path, limit } => {
                text::mobile_bundle_too_deep(limit, &EscapedPath(path))
            }
            Self::TooManyAssets { limit } => text::mobile_bundle_too_many(limit),
            Self::Replaced { path } => text::mobile_bundle_replaced(&EscapedPath(path)),
            Self::Io { path, source } => text::mobile_bundle_io(&EscapedPath(path), source),
        };
        f.write_str(&message)
    }
}

impl std::error::Error for BundleError {}

/// The origin of a generated shell file's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellContent {
    /// Write this literal generated text (a manifest, a source file, a build
    /// script).
    Generated(String),
    /// Copy the bundled SPA asset at this path below the emitted `www/` tree.
    Asset(AssetPath),
    /// Copy the rendered app icon here from the source icon.
    Icon,
}

/// One file the native shell project lays down: its project-relative path and
/// where its bytes come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellFile {
    /// The path of this file relative to the shell project root, `/`-separated.
    pub rel_path: String,
    /// Where the file's bytes come from.
    pub content: ShellContent,
}

/// The materialization-free description of a mobile shell project for one OS.
///
/// Its root directory name and the ordered set of files it contains (generated
/// sources + the bundled SPA assets + an optional icon). Pure data derived from
/// the identity + permissions + SPA bundle, so a test can assert the full layout —
/// including the derived-permission manifest — on this Linux box without running
/// that OS's toolchain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellLayout {
    /// The mobile OS this layout targets.
    pub os: MobileOs,
    /// The shell project root directory name (e.g. `AppName-ios/`).
    pub root_name: String,
    /// The ordered files the shell project contains.
    pub files: Vec<ShellFile>,
    /// The emitted `www/` directory the bundled assets are copied from.
    pub spa: SpaRoot,
}

impl ShellLayout {
    /// The literal generated text of the file at `rel_path`, if it is a generated
    /// file. Used by tests to assert manifest/source content.
    #[must_use]
    pub fn generated(&self, rel_path: &str) -> Option<&str> {
        self.files.iter().find_map(|file| match &file.content {
            ShellContent::Generated(text) if file.rel_path == rel_path => Some(text.as_str()),
            _ => None,
        })
    }
}

/// Assemble the native shell project layout for `os` from the app identity, its
/// accepted capabilities, the offline SPA bundle, and an optional icon.
///
/// The `Info.plist` / `AndroidManifest.xml` permission entries are derived from
/// `accepts` through [`permissions::derive_permissions`] — never authored here.
/// The SPA bundle assets are placed under the OS's web-asset root, and the shell
/// serves them at `base`'s [`MountBase::dir_url`] on a local origin (never a
/// remote URL) — the same mount path the wasm build baked into the bundle's own
/// URLs. A request outside that directory has no mapping and answers a local 404.
///
/// # Errors
/// Propagates any error from the permission derivation.
pub fn layout(
    os: MobileOs,
    profile: BundleProfile,
    identity: &super::desktop::BundleIdentity,
    accepts: &BTreeSet<Capability>,
    bundle: &SpaBundle,
    icon: Option<&Path>,
    base: &MountBase,
) -> Result<ShellLayout, super::super::CliError> {
    match os {
        MobileOs::Android => android_layout(profile, identity, accepts, bundle, icon, base),
        MobileOs::Ios => ios_layout(identity, accepts, bundle, icon, base),
    }
}

/// The bundle-app-name segment used in filenames and identifiers, sanitised to a
/// `[a-z0-9-]` reverse-DNS segment.
fn app_slug(name: &str) -> String {
    super::desktop::sanitise_identifier(name)
}

// ── Android ──────────────────────────────────────────────────────────────────

/// Assemble the Android Gradle shell project layout.
///
/// The SPA assets ride under `app/src/main/assets/www/`; a `WebViewAssetLoader`
/// path handler registered at `base`'s directory serves them at
/// [`android_entry_url`], so the webview loads the bundle from a same-origin
/// local URL (no remote host, no `file://`). The `AndroidManifest.xml`
/// `<uses-permission>` lines come only from the permission derivation.
fn android_layout(
    profile: BundleProfile,
    identity: &super::desktop::BundleIdentity,
    accepts: &BTreeSet<Capability>,
    bundle: &SpaBundle,
    icon: Option<&Path>,
    base: &MountBase,
) -> Result<ShellLayout, super::super::CliError> {
    let slug = app_slug(&identity.name);
    let root_name = format!("{slug}-android");
    let mut files = Vec::new();

    let manifest = render_android_manifest(identity, accepts)?;
    files.push(ShellFile {
        rel_path: "app/src/main/AndroidManifest.xml".to_owned(),
        content: ShellContent::Generated(manifest),
    });
    files.push(ShellFile {
        rel_path: "app/build.gradle".to_owned(),
        content: ShellContent::Generated(render_android_build_gradle(identity)),
    });
    files.push(ShellFile {
        rel_path: "settings.gradle".to_owned(),
        // A SINGLE-quoted Groovy string: `$`/`{`/`}` are literal here, so a
        // `${…}` in the app name cannot become live GString interpolation that
        // Gradle evaluates at configuration time. Matches every other Gradle sink,
        // which is why they are safe; the escaper still neutralises `'`/`\`.
        content: ShellContent::Generated(format!(
            "rootProject.name = '{}'\ninclude \":app\"\n",
            gradle_string_escape(&identity.name)
        )),
    });
    files.push(ShellFile {
        rel_path: "app/src/main/java/dev/ipe/app/MainActivity.java".to_owned(),
        content: ShellContent::Generated(render_android_activity(base)),
    });
    files.push(ShellFile {
        rel_path: "README.txt".to_owned(),
        content: ShellContent::Generated(android_readme(&root_name, profile, base)),
    });

    // The offline SPA assets, under the WebViewAssetLoader-served asset root.
    for asset in &bundle.assets {
        files.push(ShellFile {
            rel_path: format!("app/src/main/assets/www/{}", asset.path.to_shell_rel()),
            content: ShellContent::Asset(asset.path.clone()),
        });
    }

    if icon.is_some() {
        files.push(ShellFile {
            rel_path: "app/src/main/res/mipmap/ic_launcher.png".to_owned(),
            content: ShellContent::Icon,
        });
    }

    Ok(ShellLayout {
        os: MobileOs::Android,
        root_name,
        files,
        spa: bundle.spa.clone(),
    })
}

/// Render the `AndroidManifest.xml`, splicing the derived `<uses-permission>`
/// lines (from the permission derivation, never authored here) into a fixed
/// application element.
fn render_android_manifest(
    identity: &super::desktop::BundleIdentity,
    accepts: &BTreeSet<Capability>,
) -> Result<String, super::super::CliError> {
    use std::fmt::Write as _;

    let permission_set = permissions::derive_permissions(accepts, Platform::Android)?;
    let fragment = permission_set.to_android_manifest_entries();

    let mut perms = String::new();
    for line in fragment.lines() {
        // The derived line's `android:name` is a fixed constant from the closed
        // table, never user text.
        let _ = writeln!(perms, "    {line}");
    }

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n\
         \x20   package=\"{package}\">\n\
         {perms}\
         \x20   <application\n\
         \x20       android:label=\"{label}\"\n\
         \x20       android:icon=\"@mipmap/ic_launcher\"\n\
         \x20       android:usesCleartextTraffic=\"false\">\n\
         \x20       <activity\n\
         \x20           android:name=\"dev.ipe.app.MainActivity\"\n\
         \x20           android:exported=\"true\">\n\
         \x20           <intent-filter>\n\
         \x20               <action android:name=\"android.intent.action.MAIN\" />\n\
         \x20               <category android:name=\"android.intent.category.LAUNCHER\" />\n\
         \x20           </intent-filter>\n\
         \x20       </activity>\n\
         \x20   </application>\n\
         </manifest>\n",
        package = xml_attr_escape(&android_package_id(identity)),
        label = xml_attr_escape(&identity.name),
    ))
}

/// The Android application id (reverse-DNS package), from the identity's bundle
/// identifier so a single identity drives every OS.
///
/// Android package/`applicationId`/`namespace` segments are Java identifiers:
/// each must match `[a-zA-Z_][a-zA-Z0-9_]*` (no hyphen, no leading digit). The
/// Apple-shaped identifier permits `-` inside a segment, so each segment is
/// coerced to a valid Java identifier here (`-` → `_`, a leading digit prefixed
/// with `_`, an empty segment becomes `app`).
fn android_package_id(identity: &super::desktop::BundleIdentity) -> String {
    identity
        .identifier
        .split('.')
        .map(java_identifier_segment)
        .collect::<Vec<_>>()
        .join(".")
}

/// Coerce one dotted segment into a valid Java identifier: keep alphanumerics and
/// `_`, map every other character to `_`, prefix a leading digit with `_`, and
/// map an empty result to `app`.
fn java_identifier_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for ch in segment.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        return "app".to_owned();
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Render the app-module `build.gradle`.
fn render_android_build_gradle(identity: &super::desktop::BundleIdentity) -> String {
    format!(
        "plugins {{ id 'com.android.application' }}\n\
         android {{\n\
         \x20   namespace '{ns}'\n\
         \x20   compileSdk 34\n\
         \x20   defaultConfig {{\n\
         \x20       applicationId '{app_id}'\n\
         \x20       minSdk 24\n\
         \x20       targetSdk 34\n\
         \x20       versionName '{version}'\n\
         \x20       versionCode 1\n\
         \x20   }}\n\
         }}\n\
         dependencies {{\n\
         \x20   implementation 'androidx.webkit:webkit:1.11.0'\n\
         \x20   implementation 'androidx.appcompat:appcompat:1.7.0'\n\
         }}\n",
        ns = gradle_string_escape(&android_package_id(identity)),
        app_id = gradle_string_escape(&android_package_id(identity)),
        version = gradle_string_escape(&identity.version),
    )
}

/// The local origin a `WebViewAssetLoader` serves on; it never leaves the device.
const ANDROID_ASSET_ORIGIN: &str = "https://appassets.androidplatform.net";

/// The URL the Android shell opens: [`ANDROID_ASSET_ORIGIN`] plus `base`'s
/// [`MountBase::dir_url`].
fn android_entry_url(base: &MountBase) -> String {
    let dir = base.dir_url();
    let mut url = String::with_capacity(ANDROID_ASSET_ORIGIN.len().saturating_add(dir.len()));
    url.push_str(ANDROID_ASSET_ORIGIN);
    url.push_str(&dir);
    url
}

/// Render the `MainActivity` that serves the offline SPA at `base`'s directory.
///
/// A `BundleHandler` registered at [`MountBase::dir_url`] maps the path below it
/// into `assets/www/` (the empty path is `index.html`) and refuses a `\`, a `%`,
/// and an empty, `.` or `..` segment. Every request the loader leaves unmapped
/// answers a local 404, so the webview never reaches the network. The base
/// reaches the Java text only as [`JavaStringLiteral`]s.
fn render_android_activity(base: &MountBase) -> String {
    format!(
        "package dev.ipe.app;\n\
         \n\
         import android.app.Activity;\n\
         import android.content.Context;\n\
         import android.os.Bundle;\n\
         import android.webkit.WebView;\n\
         import android.webkit.WebViewClient;\n\
         import android.webkit.WebResourceRequest;\n\
         import android.webkit.WebResourceResponse;\n\
         import androidx.webkit.WebViewAssetLoader;\n\
         import java.io.ByteArrayInputStream;\n\
         import java.util.Collections;\n\
         \n\
         public final class MainActivity extends Activity {{\n\
         \x20   /** The directory the bundle is served at: the manifest's mount base. */\n\
         \x20   private static final String BUNDLE_DIR = {dir};\n\
         \x20   /** The URL the shell opens: the local asset origin plus BUNDLE_DIR. */\n\
         \x20   private static final String ENTRY_URL = {entry};\n\
         \n\
         \x20   /** Serves assets/www/ for the path below BUNDLE_DIR. */\n\
         \x20   private static final class BundleHandler implements WebViewAssetLoader.PathHandler {{\n\
         \x20       private final WebViewAssetLoader.AssetsPathHandler assets;\n\
         \n\
         \x20       BundleHandler(Context context) {{\n\
         \x20           this.assets = new WebViewAssetLoader.AssetsPathHandler(context);\n\
         \x20       }}\n\
         \n\
         \x20       @Override\n\
         \x20       public WebResourceResponse handle(String path) {{\n\
         \x20           if (path.isEmpty()) {{\n\
         \x20               return assets.handle(\"www/index.html\");\n\
         \x20           }}\n\
         \x20           if (path.indexOf('\\\\') >= 0 || path.indexOf('%') >= 0) {{\n\
         \x20               return null;\n\
         \x20           }}\n\
         \x20           for (String segment : path.split(\"/\", -1)) {{\n\
         \x20               if (segment.isEmpty() || segment.equals(\".\") || segment.equals(\"..\")) {{\n\
         \x20                   return null;\n\
         \x20               }}\n\
         \x20           }}\n\
         \x20           return assets.handle(\"www/\" + path);\n\
         \x20       }}\n\
         \x20   }}\n\
         \n\
         \x20   /** The answer to every request the loader leaves unmapped: a local 404. */\n\
         \x20   private static WebResourceResponse localNotFound() {{\n\
         \x20       return new WebResourceResponse(\"text/plain\", \"utf-8\", 404, \"Not Found\",\n\
         \x20               Collections.<String, String>emptyMap(),\n\
         \x20               new ByteArrayInputStream(new byte[0]));\n\
         \x20   }}\n\
         \n\
         \x20   @Override\n\
         \x20   protected void onCreate(Bundle savedInstanceState) {{\n\
         \x20       super.onCreate(savedInstanceState);\n\
         \x20       final WebViewAssetLoader loader = new WebViewAssetLoader.Builder()\n\
         \x20           .addPathHandler(BUNDLE_DIR, new BundleHandler(this))\n\
         \x20           .build();\n\
         \x20       WebView webView = new WebView(this);\n\
         \x20       webView.getSettings().setJavaScriptEnabled(true);\n\
         \x20       webView.getSettings().setAllowFileAccess(false);\n\
         \x20       webView.getSettings().setAllowContentAccess(false);\n\
         \x20       webView.setWebViewClient(new WebViewClient() {{\n\
         \x20           @Override\n\
         \x20           public WebResourceResponse shouldInterceptRequest(\n\
         \x20                   WebView view, WebResourceRequest request) {{\n\
         \x20               WebResourceResponse mapped = loader.shouldInterceptRequest(request.getUrl());\n\
         \x20               return mapped != null ? mapped : localNotFound();\n\
         \x20           }}\n\
         \x20       }});\n\
         \x20       setContentView(webView);\n\
         \x20       webView.loadUrl(ENTRY_URL);\n\
         \x20   }}\n\
         }}\n",
        dir = JavaStringLiteral::of(&base.dir_url()),
        entry = JavaStringLiteral::of(&android_entry_url(base)),
    )
}

/// The Android shell's build/README note.
///
/// The Gradle project carries no `signingConfig`, so the note states that it is
/// unsigned and what each Gradle task yields, for either profile.
fn android_readme(root_name: &str, profile: BundleProfile, base: &MountBase) -> String {
    let purpose = match profile {
        BundleProfile::Dev => "a dev bundle, for local install and inspection",
        BundleProfile::Release => {
            "a production bundle, distributable once signed with your own keystore"
        }
    };
    format!(
        "{root_name}: an Android system-webview shell for an offline Ipê Web SPA\n\
         ({purpose}).\n\
         \n\
         The client-wasm SPA rides under app/src/main/assets/www/; a WebViewAssetLoader\n\
         serves it at {entry}, so the WebView loads a same-origin local bundle (no\n\
         remote host, no file:// access); any other request answers a local 404.\n\
         The <uses-permission> lines in AndroidManifest.xml are derived from the app's\n\
         accepted web capabilities — never hand-authored.\n\
         \n\
         Signing: this Gradle project is unsigned.\n\
         - ./gradlew assembleDebug (requires the Android SDK; API 34) builds an APK\n\
         \x20 signed with the SDK's debug key, for local install only.\n\
         - A store build needs your own keystore: add a signingConfig for it to\n\
         \x20 app/build.gradle, then run ./gradlew assembleRelease.\n",
        entry = android_entry_url(base),
    )
}

// ── iOS ──────────────────────────────────────────────────────────────────────

/// Assemble the iOS Xcode shell project layout.
///
/// The SPA assets ride under `App/www/`; a `WKURLSchemeHandler` serves them under
/// a custom `ipe-app://` scheme with the correct MIME per extension (a bare
/// `file://` load cannot serve `.wasm` with `application/wasm`), so the
/// `WKWebView` loads [`ios_entry_url`] — `base`'s directory on a local origin,
/// never a remote URL. The `Info.plist` usage-description keys come only from the
/// permission derivation.
fn ios_layout(
    identity: &super::desktop::BundleIdentity,
    accepts: &BTreeSet<Capability>,
    bundle: &SpaBundle,
    icon: Option<&Path>,
    base: &MountBase,
) -> Result<ShellLayout, super::super::CliError> {
    let slug = app_slug(&identity.name);
    let root_name = format!("{slug}-ios");
    let mut files = Vec::new();

    let plist = render_ios_info_plist(identity, accepts)?;
    files.push(ShellFile {
        rel_path: "App/Info.plist".to_owned(),
        content: ShellContent::Generated(plist),
    });
    files.push(ShellFile {
        rel_path: "App/AppDelegate.swift".to_owned(),
        content: ShellContent::Generated(render_ios_app_delegate(base)),
    });
    files.push(ShellFile {
        rel_path: "App/SchemeHandler.swift".to_owned(),
        content: ShellContent::Generated(render_ios_scheme_handler(base)),
    });
    files.push(ShellFile {
        rel_path: "README.txt".to_owned(),
        content: ShellContent::Generated(ios_readme(&root_name, base)),
    });

    for asset in &bundle.assets {
        files.push(ShellFile {
            rel_path: format!("App/www/{}", asset.path.to_shell_rel()),
            content: ShellContent::Asset(asset.path.clone()),
        });
    }

    if icon.is_some() {
        files.push(ShellFile {
            rel_path: "App/Assets.xcassets/AppIcon.appiconset/icon.png".to_owned(),
            content: ShellContent::Icon,
        });
    }

    Ok(ShellLayout {
        os: MobileOs::Ios,
        root_name,
        files,
        spa: bundle.spa.clone(),
    })
}

/// Render the iOS `Info.plist`, assembling the fixed identity keys and the derived
/// usage-description keys.
///
/// The permission keys come ONLY from [`permissions::derive_permissions`] on
/// [`Platform::Ios`]; this function never writes an `NS…UsageDescription` key
/// itself. An app that accepts no permission-bearing web capability yields a plist
/// with no usage-description keys. Identity strings are XML-escaped.
fn render_ios_info_plist(
    identity: &super::desktop::BundleIdentity,
    accepts: &BTreeSet<Capability>,
) -> Result<String, super::super::CliError> {
    use std::fmt::Write as _;

    let permission_set = permissions::derive_permissions(accepts, Platform::Ios)?;
    let usage_entries = permission_set.to_info_plist_entries();

    let mut body = String::new();
    let mut pair = |key: &str, value: &str| {
        let _ = writeln!(body, "\t<key>{}</key>", plist_escape(key));
        let _ = writeln!(body, "\t<string>{}</string>", plist_escape(value));
    };
    pair("CFBundleName", &identity.name);
    pair("CFBundleDisplayName", &identity.name);
    pair("CFBundleIdentifier", &identity.identifier);
    pair("CFBundleVersion", &identity.version);
    pair("CFBundleShortVersionString", &identity.version);
    pair("CFBundleExecutable", &app_slug(&identity.name));
    pair("CFBundlePackageType", "APPL");
    // The permission keys — from the permission derivation, never authored here.
    for (key, purpose) in usage_entries {
        pair(&key, &purpose);
    }

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n{body}</dict>\n\
         </plist>\n"
    ))
}

/// The custom-scheme origin the iOS shell serves on; it never leaves the device.
const IOS_SCHEME_ORIGIN: &str = "ipe-app://app";

/// The URL the iOS shell opens: [`IOS_SCHEME_ORIGIN`] plus `base`'s
/// [`MountBase::dir_url`].
fn ios_entry_url(base: &MountBase) -> String {
    let dir = base.dir_url();
    let mut url = String::with_capacity(IOS_SCHEME_ORIGIN.len().saturating_add(dir.len()));
    url.push_str(IOS_SCHEME_ORIGIN);
    url.push_str(&dir);
    url
}

/// Render the iOS `AppDelegate` that hosts a `WKWebView` bound to the custom-scheme
/// handler and opens [`ios_entry_url`], served from bundled assets — the webview
/// never reaches a remote host. The base reaches the Swift text only as a
/// [`SwiftStringLiteral`].
fn render_ios_app_delegate(base: &MountBase) -> String {
    format!(
        "import UIKit\n\
         import WebKit\n\
         \n\
         @main\n\
         final class AppDelegate: UIResponder, UIApplicationDelegate {{\n\
         \x20   var window: UIWindow?\n\
         \x20   var webView: WKWebView?\n\
         \n\
         \x20   func application(_ application: UIApplication,\n\
         \x20       didFinishLaunchingWithOptions launchOptions:\n\
         \x20       [UIApplication.LaunchOptionsKey: Any]?) -> Bool {{\n\
         \x20       let config = WKWebViewConfiguration()\n\
         \x20       config.setURLSchemeHandler(SchemeHandler(), forURLScheme: \"ipe-app\")\n\
         \x20       let webView = WKWebView(frame: .zero, configuration: config)\n\
         \x20       self.webView = webView\n\
         \x20       let window = UIWindow(frame: UIScreen.main.bounds)\n\
         \x20       let controller = UIViewController()\n\
         \x20       controller.view = webView\n\
         \x20       window.rootViewController = controller\n\
         \x20       window.makeKeyAndVisible()\n\
         \x20       self.window = window\n\
         \x20       if let url = URL(string: {entry}) {{\n\
         \x20           webView.load(URLRequest(url: url))\n\
         \x20       }}\n\
         \x20       return true\n\
         \x20   }}\n\
         }}\n",
        entry = SwiftStringLiteral::of(&ios_entry_url(base)),
    )
}

/// Render the `WKURLSchemeHandler` that serves the bundled SPA assets under the
/// custom `ipe-app://` scheme, with a correct MIME per file extension.
///
/// `WKWebView` cannot cleanly `file://`-load a `.wasm` with the required
/// `application/wasm` MIME; a custom scheme handler resolves each request to a
/// bundled resource and sets its content type explicitly. The handler strips
/// `base`'s segments from the request path (a path outside the base answers
/// 404), maps the bare directory to `index.html`, refuses an empty, `.` or `..`
/// segment and a `\`, and serves a resolved file only when it lies below the
/// `www/` directory plus `/`. Every refusal answers a local 404. The base's
/// segments reach the Swift text only as [`SwiftStringLiteral`]s.
fn render_ios_scheme_handler(base: &MountBase) -> String {
    let segments = base
        .segments()
        .map(|segment| SwiftStringLiteral::of(segment).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "import Foundation\n\
         import WebKit\n\
         \n\
         final class SchemeHandler: NSObject, WKURLSchemeHandler {{\n\
         \x20   /// The manifest mount base's path segments; the bundle is served below them.\n\
         \x20   static let baseSegments: [String] = [{segments}]\n\
         \n\
         \x20   func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {{\n\
         \x20       guard let url = urlSchemeTask.request.url,\n\
         \x20             let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {{\n\
         \x20           SchemeHandler.notFound(urlSchemeTask)\n\
         \x20           return\n\
         \x20       }}\n\
         \x20       let path = components.path.isEmpty ? \"/\" : components.path\n\
         \x20       guard path.hasPrefix(\"/\") else {{\n\
         \x20           SchemeHandler.notFound(urlSchemeTask)\n\
         \x20           return\n\
         \x20       }}\n\
         \x20       var segments = path.dropFirst()\n\
         \x20           .split(separator: \"/\", omittingEmptySubsequences: false)\n\
         \x20           .map(String.init)\n\
         \x20       for expected in SchemeHandler.baseSegments {{\n\
         \x20           guard let first = segments.first, first == expected else {{\n\
         \x20               SchemeHandler.notFound(urlSchemeTask)\n\
         \x20               return\n\
         \x20           }}\n\
         \x20           segments.removeFirst()\n\
         \x20       }}\n\
         \x20       if segments.isEmpty || segments == [\"\"] {{\n\
         \x20           segments = [\"index.html\"]\n\
         \x20       }}\n\
         \x20       for segment in segments {{\n\
         \x20           if segment.isEmpty || segment == \".\" || segment == \"..\"\n\
         \x20               || segment.contains(\"\\\\\") {{\n\
         \x20               SchemeHandler.notFound(urlSchemeTask)\n\
         \x20               return\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       guard let www = Bundle.main.resourceURL?.appendingPathComponent(\"www\") else {{\n\
         \x20           SchemeHandler.notFound(urlSchemeTask)\n\
         \x20           return\n\
         \x20       }}\n\
         \x20       let boundary = www.standardizedFileURL.path + \"/\"\n\
         \x20       let resolved = segments\n\
         \x20           .reduce(www) {{ $0.appendingPathComponent($1) }}\n\
         \x20           .standardizedFileURL\n\
         \x20       guard resolved.path.hasPrefix(boundary),\n\
         \x20             let data = try? Data(contentsOf: resolved) else {{\n\
         \x20           SchemeHandler.notFound(urlSchemeTask)\n\
         \x20           return\n\
         \x20       }}\n\
         \x20       let mime = SchemeHandler.mimeType(for: resolved.pathExtension)\n\
         \x20       let response = URLResponse(url: url, mimeType: mime,\n\
         \x20           expectedContentLength: data.count, textEncodingName: nil)\n\
         \x20       urlSchemeTask.didReceive(response)\n\
         \x20       urlSchemeTask.didReceive(data)\n\
         \x20       urlSchemeTask.didFinish()\n\
         \x20   }}\n\
         \n\
         \x20   func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {{}}\n\
         \n\
         \x20   /// Answer a local 404: nothing outside the bundle is ever fetched.\n\
         \x20   static func notFound(_ urlSchemeTask: WKURLSchemeTask) {{\n\
         \x20       guard let url = urlSchemeTask.request.url,\n\
         \x20             let response = HTTPURLResponse(url: url, statusCode: 404,\n\
         \x20                 httpVersion: \"HTTP/1.1\",\n\
         \x20                 headerFields: [\"Content-Type\": \"text/plain\"]) else {{\n\
         \x20           urlSchemeTask.didFailWithError(URLError(.fileDoesNotExist))\n\
         \x20           return\n\
         \x20       }}\n\
         \x20       urlSchemeTask.didReceive(response)\n\
         \x20       urlSchemeTask.didReceive(Data())\n\
         \x20       urlSchemeTask.didFinish()\n\
         \x20   }}\n\
         \n\
         \x20   static func mimeType(for ext: String) -> String {{\n\
         \x20       switch ext.lowercased() {{\n\
         \x20       case \"html\": return \"text/html\"\n\
         \x20       case \"js\": return \"text/javascript\"\n\
         \x20       case \"wasm\": return \"application/wasm\"\n\
         \x20       case \"json\": return \"application/json\"\n\
         \x20       case \"css\": return \"text/css\"\n\
         \x20       default: return \"application/octet-stream\"\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n"
    )
}

/// The iOS shell's build/README note.
fn ios_readme(root_name: &str, base: &MountBase) -> String {
    format!(
        "{root_name}: an iOS system-webview shell for an offline Ipê Web SPA.\n\
         \n\
         The client-wasm SPA rides under App/www/; a WKURLSchemeHandler serves it under\n\
         the custom ipe-app:// scheme with a correct MIME per file (WKWebView cannot\n\
         cleanly file://-load .wasm), so the WKWebView loads {entry} —\n\
         a local origin, never a remote URL; an ipe-app:// request outside the\n\
         bundle answers a local 404.\n\
         The Info.plist NS…UsageDescription keys are derived from the app's accepted\n\
         web capabilities — never hand-authored.\n\
         \n\
         Build: open this project in Xcode on macOS; a signed, runnable .ipa requires\n\
         macOS + Xcode + a signing identity (out of scope on this host).\n",
        entry = ios_entry_url(base),
    )
}

// ── Escaping ─────────────────────────────────────────────────────────────────

/// Escape an author-supplied string for a plist text node. Identity values are
/// author-supplied, so they are escaped; the derived permission keys/purposes are
/// fixed ASCII. Routes through the packager's shared XML escape ([`crate::pack::xml_escape`]).
fn plist_escape(text: &str) -> String {
    crate::pack::xml_escape(text)
}

/// Escape an author-supplied string for an XML attribute value — the identity
/// strings spliced into the Android manifest. Routes through the packager's
/// shared XML escape ([`crate::pack::xml_escape`]).
fn xml_attr_escape(text: &str) -> String {
    crate::pack::xml_escape(text)
}

/// Escape a Gradle single-quoted / double-quoted string value: strip the quote and
/// backslash and line breaks that would break the single-line grammar. Identity
/// strings reach `build.gradle` / `settings.gradle`, so they are sanitised.
fn gradle_string_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\'' | '"' | '\\' | '\n' | '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// A complete double-quoted Java string literal, quotes included, whose value
/// is exactly the text it was built from.
///
/// Printable ASCII other than `"` and `\` passes through; `"`, `\`, newline,
/// carriage return and tab take their named escapes; any other character up to
/// U+00FF is an octal escape, and anything above is one `\uXXXX` per UTF-16
/// unit. A `\uXXXX` is never emitted for a unit at or below U+00FF: Java
/// translates unicode escapes before it lexes, so `"`, `\` or
/// `\u000a` would end the literal or the line.
#[derive(Clone, Debug, PartialEq, Eq)]
struct JavaStringLiteral(String);

impl JavaStringLiteral {
    /// Quote `text` as a Java string literal.
    fn of(text: &str) -> Self {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(text.len().saturating_add(2));
        out.push('"');
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                _ if ch == ' ' || ch.is_ascii_graphic() => out.push(ch),
                _ if u32::from(ch) <= 0xff => {
                    let _ = write!(out, "\\{:03o}", u32::from(ch));
                }
                _ => {
                    let mut units = [0_u16; 2];
                    for unit in ch.encode_utf16(&mut units) {
                        let _ = write!(out, "\\u{unit:04x}");
                    }
                }
            }
        }
        out.push('"');
        Self(out)
    }
}

impl std::fmt::Display for JavaStringLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A complete double-quoted Swift string literal, quotes included, whose value
/// is exactly the text it was built from.
///
/// Printable ASCII other than `"` and `\` passes through, so no `\(` can open an
/// interpolation; `"`, `\`, newline, carriage return, tab and NUL take their
/// named escapes; every other character is a `\u{X}` escape.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SwiftStringLiteral(String);

impl SwiftStringLiteral {
    /// Quote `text` as a Swift string literal.
    fn of(text: &str) -> Self {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(text.len().saturating_add(2));
        out.push('"');
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\0' => out.push_str("\\0"),
                _ if ch == ' ' || ch.is_ascii_graphic() => out.push(ch),
                _ => {
                    let _ = write!(out, "\\u{{{:x}}}", u32::from(ch));
                }
            }
        }
        out.push('"');
        Self(out)
    }
}

impl std::fmt::Display for SwiftStringLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Materialise `layout` as the shell `dist/<root_name>` inside the owned `dist`.
///
/// Generated files are written verbatim, bundled SPA assets and the source icon
/// are copied into place. A fresh, deterministic tree: an existing shell directory
/// of the same name is removed first so a re-pack never leaves stale files behind.
/// Every path is a [`crate::output_dir::OwnedPath`], so a symlink planted in the
/// owned `dist` is refused — never removed through, written through, or copied
/// onto.
///
/// # Errors
/// [`CliError::Usage`] carrying [`BundleError::Replaced`] when the emitted
/// `www/` is no longer the directory the bundle was collected from;
/// [`CliError::OutputRefused`] for a symlink or non-plain name on the way;
/// [`CliError::Io`] naming the exact path on any filesystem failure.
pub fn materialise(
    layout: &ShellLayout,
    icon: Option<&Path>,
    dist: &OwnedDir,
) -> Result<PathBuf, CliError> {
    layout
        .spa
        .verify_unreplaced()
        .map_err(|e| CliError::Usage(crate::text::Message::relay(&e)))?;
    let root = dist.path_to(&layout.root_name)?;
    root.remove()?;
    root.ensure_dir()?;

    for file in &layout.files {
        let out_file =
            dist.path_to(Path::new(&layout.root_name).join(rel_to_native(&file.rel_path)))?;
        match &file.content {
            ShellContent::Generated(text) => out_file.write(text.as_bytes())?,
            ShellContent::Asset(asset) => out_file.copy_from(&layout.spa.source_of(asset))?,
            ShellContent::Icon => {
                if let Some(src) = icon {
                    out_file.copy_from(src)?;
                }
            }
        }
    }
    Ok(root.path())
}

/// Translate a shell-relative `/`-separated path into a native `PathBuf`.
fn rel_to_native(rel: &str) -> PathBuf {
    rel.split('/').collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_ir::WebCapability;

    fn accepts(items: &[Capability]) -> BTreeSet<Capability> {
        items.iter().copied().collect()
    }

    fn web(axis: WebCapability) -> Capability {
        Capability::JsPort(axis)
    }

    fn identity() -> super::super::desktop::BundleIdentity {
        super::super::desktop::BundleIdentity::new("Geo App", Some("1.2.3"), None)
    }

    /// A fresh scratch directory unique to this call.
    fn scratch(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe-mobile-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk scratch");
        dir
    }

    /// A `www/` tree holding `index.html` and the given extra files, under a fresh scratch dir.
    fn www_with(tag: &str, files: &[&str]) -> (PathBuf, PathBuf) {
        let base = scratch(tag);
        let www = base.join("www");
        std::fs::create_dir_all(&www).expect("mk www");
        std::fs::write(www.join("index.html"), b"<html>").expect("write index");
        for rel in files {
            let path = rel.split('/').fold(www.clone(), |p, s| p.join(s));
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("mk parent");
            }
            std::fs::write(&path, b"x").expect("write asset");
        }
        (base, www)
    }

    /// A minimal SPA bundle collected from a real emitted-shaped `www/` tree.
    fn bundle() -> SpaBundle {
        let (_base, www) = www_with("bundle", &["boot.js", "pkg/ipe_app_bg.wasm"]);
        SpaBundle::from_www_dir(&www).expect("collect the bundle")
    }

    /// The `/`-joined asset paths of `spa`, in bundle order.
    fn rels(spa: &SpaBundle) -> Vec<&str> {
        spa.assets().iter().map(|a| a.path.to_shell_rel()).collect()
    }

    // ── OS resolution ─────────────────────────────────────────────────────────

    #[test]
    fn explicit_os_parses() {
        assert_eq!(resolve_os(Some("ios")), Ok(MobileOs::Ios));
        assert_eq!(resolve_os(Some("android")), Ok(MobileOs::Android));
    }

    #[test]
    fn a_bare_mobile_target_is_refused_needing_an_os() {
        let err = resolve_os(None).expect_err("a bare mobile target names no OS");
        assert_eq!(err, MobileRefusal::MissingOs);
        assert!(err.to_string().contains("ios"));
    }

    #[test]
    fn unknown_os_is_refused_naming_it() {
        let err = resolve_os(Some("blackberry")).expect_err("not a mobile OS");
        assert_eq!(err, MobileRefusal::UnknownOs("blackberry".to_owned()));
        assert!(err.to_string().contains("blackberry"));
    }

    #[test]
    fn os_round_trips_its_wire_name() {
        for os in [MobileOs::Ios, MobileOs::Android] {
            assert_eq!(os.as_str().parse::<MobileOs>(), Ok(os));
        }
    }

    // ── Shape/wasm refusal (fail-closed) ──────────────────────────────────────

    #[test]
    fn a_wasm_web_app_is_packageable() {
        require_web_spa(WebSpaCapability {
            shape_is_web: true,
            wasm_enabled: true,
        })
        .expect("a wasm-enabled web app packages");
    }

    #[test]
    fn a_non_web_app_is_refused() {
        let err = require_web_spa(WebSpaCapability {
            shape_is_web: false,
            wasm_enabled: true,
        })
        .expect_err("a non-web app is refused");
        assert_eq!(err, MobileRefusal::NotWebShape);
        assert!(err.to_string().contains("IPE-P0022"), "carries the code");
    }

    #[test]
    fn a_web_app_without_wasm_is_refused() {
        let err = require_web_spa(WebSpaCapability {
            shape_is_web: true,
            wasm_enabled: false,
        })
        .expect_err("a web app with wasm off is refused");
        assert_eq!(err, MobileRefusal::WasmDisabled);
        assert!(err.to_string().contains("IPE-P0023"), "carries the code");
    }

    // ── SPA bundle collection ─────────────────────────────────────────────────

    #[test]
    fn a_www_dir_without_index_html_is_refused() {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipe-mobile-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk tmp");
        std::fs::write(dir.join("boot.js"), b"x").expect("write");
        let err = SpaBundle::from_www_dir(&dir).expect_err("no index.html is refused");
        assert!(matches!(err, BundleError::NoIndexHtml { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_www_dir_collects_its_files_sorted() {
        let (_base, www) = www_with("ok", &["boot.js", "pkg/app_bg.wasm"]);
        let spa = SpaBundle::from_www_dir(&www).expect("collect");
        assert_eq!(rels(&spa), vec!["boot.js", "index.html", "pkg/app_bg.wasm"]);
        spa.spa
            .verify_unreplaced()
            .expect("an untouched www/ is the directory collected");
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn non_utf8_dir_name_is_refused_not_collapsed() {
        use std::os::unix::ffi::OsStrExt;
        let (_base, www) = www_with("non-utf8-dir", &[]);
        let odd = www.join(std::ffi::OsStr::from_bytes(b"\xff"));
        std::fs::create_dir_all(&odd).expect("mk non-UTF-8 dir");
        std::fs::write(odd.join("index.html"), b"decoy").expect("write decoy");
        let err = SpaBundle::from_www_dir(&www).expect_err("a non-UTF-8 directory is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::NotUtf8,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn non_utf8_top_level_file_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let (_base, www) = www_with("non-utf8-file", &[]);
        std::fs::write(www.join(std::ffi::OsStr::from_bytes(b"\xff")), b"x")
            .expect("write non-UTF-8 file");
        let err = SpaBundle::from_www_dir(&www).expect_err("a non-UTF-8 file is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::NotUtf8,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_www_is_refused() {
        let (base, www) = www_with("symlink", &[]);
        let outside = base.join("outside.js");
        std::fs::write(&outside, b"outside").expect("write outside file");
        std::os::unix::fs::symlink(&outside, www.join("boot.js")).expect("plant link");
        let err = SpaBundle::from_www_dir(&www).expect_err("a link in www/ is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::Kind(FileKind::Symlink),
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn fifo_in_www_is_refused() {
        let (_base, www) = www_with("fifo", &[]);
        rustix::fs::mknodat(
            rustix::fs::CWD,
            www.join("pipe"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .expect("make FIFO");
        let err = SpaBundle::from_www_dir(&www).expect_err("a FIFO in www/ is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::Kind(FileKind::Fifo),
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn walk_past_max_depth_is_too_deep() {
        let nested = |levels: usize| {
            let mut rel = "d/".repeat(levels);
            rel.push_str("leaf.js");
            rel
        };
        let at_ceiling = nested(MAX_ASSET_DEPTH.get());
        let (_base, www) = www_with("depth-ok", &[&at_ceiling]);
        let spa = SpaBundle::from_www_dir(&www).expect("exactly the ceiling is walked");
        assert!(rels(&spa).contains(&at_ceiling.as_str()));

        let past = nested(MAX_ASSET_DEPTH.get().saturating_add(1));
        let (_base, www) = www_with("depth-past", &[&past]);
        let err = SpaBundle::from_www_dir(&www).expect_err("one level past is refused");
        assert!(
            matches!(&err, BundleError::TooDeep { limit, .. } if *limit == MAX_ASSET_DEPTH),
            "{err}"
        );
    }

    #[test]
    fn more_than_max_assets_is_refused() {
        let limits = |entries: u32| AssetLimits {
            depth: MAX_ASSET_DEPTH,
            entries: NonZeroU32::new(entries).expect("a non-zero ceiling"),
        };
        // `index.html`, `boot.js`, `pkg/` and `pkg/app.wasm`: four entries.
        let (_base, www) = www_with("ceiling", &["boot.js", "pkg/app.wasm"]);
        SpaBundle::from_www_dir_with(&www, limits(4)).expect("exactly the ceiling is walked");
        let err = SpaBundle::from_www_dir_with(&www, limits(3))
            .expect_err("one entry past the ceiling is refused");
        assert!(
            matches!(&err, BundleError::TooManyAssets { limit } if limit.get() == 3),
            "{err}"
        );
    }

    #[test]
    fn a_listing_is_charged_in_full_before_any_of_it_is_entered() {
        // `www/` lists three names, so with four entries in all the first
        // directory entered may list only one: its two names are refused
        // before its `g/` is ever reached.
        let (_base, www) = www_with("charged", &["a/f", "a/g/x", "b/f", "b/g/x"]);
        let limits = AssetLimits {
            depth: NonZeroUsize::MIN,
            entries: NonZeroU32::new(4).expect("a non-zero ceiling"),
        };
        let err = SpaBundle::from_www_dir_with(&www, limits).expect_err("over budget");
        assert!(
            matches!(&err, BundleError::TooManyAssets { limit } if limit.get() == 4),
            "{err}"
        );
    }

    #[test]
    fn www_replaced_between_collect_and_materialise_is_refused() {
        let (base, www) = www_with("replaced", &["boot.js"]);
        let spa = SpaBundle::from_www_dir(&www).expect("collect");
        let shell = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &accepts(&[]),
            &spa,
            None,
            &MountBase::root(),
        )
        .expect("layout");
        std::fs::rename(&www, base.join("www-collected")).expect("move www away");
        std::fs::create_dir_all(&www).expect("recreate www");
        std::fs::write(www.join("index.html"), b"swapped").expect("write swapped index");

        assert!(matches!(
            shell.spa.verify_unreplaced(),
            Err(BundleError::Replaced { .. })
        ));
        let dist = OwnedDir::claim(&base.join("dist")).expect("claim dist");
        let result = materialise(&shell, None, &dist);
        assert!(matches!(result, Err(CliError::Usage(_))));
        assert!(
            !base.join("dist").join(&shell.root_name).exists(),
            "nothing is laid down from a replaced www/"
        );
    }

    #[test]
    fn each_listing_is_capped_at_the_entry_budget_left() {
        let walk = |visited: u32| AssetWalk {
            root: Path::new("www"),
            limits: AssetLimits {
                depth: MAX_ASSET_DEPTH,
                entries: NonZeroU32::new(4).expect("a non-zero ceiling"),
            },
            visited,
            assets: Vec::new(),
        };
        assert_eq!(walk(0).listing_cap().get(), 4);
        assert_eq!(
            walk(3).listing_cap().get(),
            1,
            "a nested listing holds only what the walk may still visit"
        );
        assert_eq!(
            walk(4).listing_cap().get(),
            1,
            "a spent budget lists one name, which the visit refuses"
        );
    }

    #[test]
    fn bundle_messages_come_from_the_catalog_with_escaped_paths() {
        let limit = NonZeroU32::new(3).expect("a non-zero ceiling");
        assert_eq!(
            BundleError::TooManyAssets { limit }.to_string(),
            text::mobile_bundle_too_many(&limit).as_str()
        );
        let hostile = PathBuf::from("www/a\u{1b}[31m\u{202e}b\nc.js");
        let shown = BundleError::UnplaceableAsset {
            path: hostile,
            reason: AssetRefusal::Kind(FileKind::Fifo),
        }
        .to_string();
        assert!(
            shown.contains(r"\u{1b}[31m\u{202e}b\nc.js"),
            "every control and direction character is spelled out: {shown}"
        );
        assert!(
            shown.contains(text::mobile_asset_kind(&FileKind::Fifo).as_str()),
            "{shown}"
        );
        assert!(
            !shown.contains(['\u{1b}', '\u{202e}', '\n']),
            "nothing reaches the terminal raw: {shown}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_is_shown_escaped_not_replaced() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"www/\xff.js")).to_path_buf();
        let shown = BundleError::Replaced { path }.to_string();
        assert!(shown.contains(r"\xFF.js"), "{shown}");
        assert!(!shown.contains('\u{fffd}'), "{shown}");
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_www_is_refused_not_followed() {
        let (base, real) = www_with("linked-www", &["boot.js"]);
        let link = base.join("www-link");
        std::os::unix::fs::symlink(&real, &link).expect("plant www link");
        let err = SpaBundle::from_www_dir(&link).expect_err("a linked www/ is refused");
        assert!(
            matches!(
                &err,
                BundleError::UnplaceableAsset {
                    reason: AssetRefusal::Kind(FileKind::Symlink),
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn www_swapped_for_a_link_to_itself_is_replaced() {
        let (base, www) = www_with("www-self-link", &["boot.js"]);
        let spa = SpaBundle::from_www_dir(&www).expect("collect");
        let moved = base.join("www-collected");
        std::fs::rename(&www, &moved).expect("move www away");
        std::os::unix::fs::symlink(&moved, &www).expect("link www to the collected dir");
        assert!(
            matches!(
                spa.spa.verify_unreplaced(),
                Err(BundleError::Replaced { .. })
            ),
            "a link at www/ is not the directory collected, even when it reaches it"
        );
    }

    // ── Android: manifest permissions come only from the derivation ───────────

    #[test]
    fn android_geolocation_yields_the_location_uses_permission() {
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let layout = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &a,
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let manifest = layout
            .generated("app/src/main/AndroidManifest.xml")
            .expect("android manifest");
        assert!(
            manifest.contains("android.permission.ACCESS_FINE_LOCATION"),
            "manifest carries the derived location permission: {manifest}"
        );
    }

    #[test]
    fn android_app_accepting_nothing_has_no_uses_permission() {
        let layout = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &accepts(&[]),
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let manifest = layout
            .generated("app/src/main/AndroidManifest.xml")
            .expect("android manifest");
        assert!(
            !manifest.contains("uses-permission"),
            "a pure app declares no <uses-permission>: {manifest}"
        );
        // But the application element is still present.
        assert!(manifest.contains("<application"));
        assert!(manifest.contains("dev.ipe.app.MainActivity"));
    }

    #[test]
    fn android_package_id_is_a_valid_java_identifier() {
        // A hyphenated app name yields an Apple identifier segment with a `-`,
        // which is illegal in an Android package/applicationId. The manifest must
        // carry a coerced, hyphen-free package.
        let hyphenated = super::super::desktop::BundleIdentity::new("wasm-spa", None, None);
        let layout = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &hyphenated,
            &accepts(&[]),
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let manifest = layout
            .generated("app/src/main/AndroidManifest.xml")
            .expect("android manifest");
        assert!(
            manifest.contains("package=\"com.ipe.wasm_spa\""),
            "the Android package is a hyphen-free Java identifier: {manifest}"
        );
        // The package attribute specifically carries no hyphen (the human label
        // legitimately keeps the raw name).
        assert!(!manifest.contains("package=\"com.ipe.wasm-spa\""));
        // build.gradle's namespace/applicationId agree.
        let gradle = layout.generated("app/build.gradle").expect("build.gradle");
        assert!(gradle.contains("com.ipe.wasm_spa"));
        assert!(!gradle.contains("wasm-spa"));
    }

    #[test]
    fn android_non_web_capability_backs_no_permission() {
        let a = accepts(&[Capability::Network, Capability::NativeFfi]);
        let layout = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &a,
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let manifest = layout
            .generated("app/src/main/AndroidManifest.xml")
            .expect("android manifest");
        assert!(!manifest.contains("uses-permission"));
    }

    #[test]
    fn android_layout_bundles_the_spa_assets_offline() {
        let layout = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &accepts(&[]),
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let paths: Vec<&str> = layout.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(paths.contains(&"app/src/main/assets/www/index.html"));
        assert!(paths.contains(&"app/src/main/assets/www/pkg/ipe_app_bg.wasm"));
        // The activity loads the local asset-loader URL — never a remote host.
        let activity = layout
            .generated("app/src/main/java/dev/ipe/app/MainActivity.java")
            .expect("activity");
        assert!(activity.contains("ENTRY_URL = \"https://appassets.androidplatform.net/\";"));
        assert!(!activity.contains("http://") || activity.contains("https://appassets"));
    }

    // ── iOS: plist permissions come only from the derivation ──────────────────

    #[test]
    fn ios_geolocation_yields_the_location_usage_key() {
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let layout = layout(
            MobileOs::Ios,
            BundleProfile::Dev,
            &identity(),
            &a,
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let plist = layout.generated("App/Info.plist").expect("ios plist");
        assert!(
            plist.contains("NSLocationWhenInUseUsageDescription"),
            "plist carries the derived location usage key: {plist}"
        );
        assert!(plist.contains("This app uses your location"));
    }

    #[test]
    fn ios_app_accepting_nothing_has_no_usage_keys() {
        let layout = layout(
            MobileOs::Ios,
            BundleProfile::Dev,
            &identity(),
            &accepts(&[]),
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let plist = layout.generated("App/Info.plist").expect("ios plist");
        assert!(
            !plist.contains("UsageDescription"),
            "a pure app declares no usage-description keys: {plist}"
        );
        assert!(plist.contains("CFBundleIdentifier"));
    }

    #[test]
    fn ios_scheme_handler_serves_wasm_with_the_correct_mime() {
        let layout = layout(
            MobileOs::Ios,
            BundleProfile::Dev,
            &identity(),
            &accepts(&[]),
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let handler = layout
            .generated("App/SchemeHandler.swift")
            .expect("scheme handler");
        assert!(
            handler.contains("application/wasm"),
            "the scheme handler serves .wasm with application/wasm: {handler}"
        );
        // The app loads a local custom-scheme URL, never a remote http(s) host.
        let delegate = layout
            .generated("App/AppDelegate.swift")
            .expect("app delegate");
        assert!(delegate.contains("URL(string: \"ipe-app://app/\")"));
        assert!(!delegate.contains("http://"));
    }

    #[test]
    fn ios_layout_bundles_the_spa_assets_offline() {
        let layout = layout(
            MobileOs::Ios,
            BundleProfile::Dev,
            &identity(),
            &accepts(&[]),
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let paths: Vec<&str> = layout.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(paths.contains(&"App/www/index.html"));
        assert!(paths.contains(&"App/www/pkg/ipe_app_bg.wasm"));
    }

    // ── Identity escaping (injection cannot smuggle XML) ──────────────────────

    #[test]
    fn a_hostile_app_name_is_xml_escaped_in_the_manifests() {
        let hostile = super::super::desktop::BundleIdentity::new(
            "Evil\"</manifest><x>",
            Some("1.0.0"),
            Some("com.evil.\"<x>"),
        );
        let a = accepts(&[]);
        let android = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &hostile,
            &a,
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let manifest = android
            .generated("app/src/main/AndroidManifest.xml")
            .expect("android manifest");
        assert!(
            !manifest.contains("<x>"),
            "a hostile identity cannot inject raw XML into the manifest: {manifest}"
        );

        let ios = layout(
            MobileOs::Ios,
            BundleProfile::Dev,
            &hostile,
            &a,
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let plist = ios.generated("App/Info.plist").expect("ios plist");
        assert!(
            !plist.contains("<x>"),
            "a hostile identity cannot inject raw XML into the plist: {plist}"
        );
    }

    #[test]
    fn a_gstring_bearing_app_name_cannot_inject_into_settings_gradle() {
        // Gradle evaluates `settings.gradle` as Groovy at configuration time; in a
        // DOUBLE-quoted string `${…}` is live interpolation → code execution when
        // anyone runs `./gradlew`. A single-quoted string renders `$` literal.
        let hostile = super::super::desktop::BundleIdentity::new(
            "App${new ProcessBuilder('id').start()}",
            Some("1.0.0"),
            Some("com.evil.app"),
        );
        let android = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &hostile,
            &accepts(&[]),
            &bundle(),
            None,
            &MountBase::root(),
        )
        .expect("layout");
        let settings = android
            .generated("settings.gradle")
            .expect("settings.gradle");
        assert!(
            settings.contains("rootProject.name = '"),
            "rootProject.name must be a single-quoted Groovy string: {settings}"
        );
        assert!(
            !settings.contains("rootProject.name = \""),
            "rootProject.name must NOT be double-quoted — `${{…}}` would be live \
             GString interpolation Gradle evaluates: {settings}"
        );
    }

    // ── Icon ──────────────────────────────────────────────────────────────────

    #[test]
    fn an_icon_is_placed_per_os_and_omitted_when_absent() {
        let icon = PathBuf::from("/tmp/icon.png");
        for os in [MobileOs::Ios, MobileOs::Android] {
            let with = layout(
                os,
                BundleProfile::Dev,
                &identity(),
                &accepts(&[]),
                &bundle(),
                Some(&icon),
                &MountBase::root(),
            )
            .expect("l");
            assert!(
                with.files.iter().any(|f| f.content == ShellContent::Icon),
                "an icon file is present on {os:?} when the manifest declares one"
            );
            let without = layout(
                os,
                BundleProfile::Dev,
                &identity(),
                &accepts(&[]),
                &bundle(),
                None,
                &MountBase::root(),
            )
            .expect("l");
            assert!(
                without
                    .files
                    .iter()
                    .all(|f| f.content != ShellContent::Icon),
                "no icon file on {os:?} when the manifest declares none"
            );
        }
    }

    /// The Android README states the project is unsigned under either profile, and
    /// names the keystore step a store build needs; it never claims a signed build.
    #[test]
    fn android_readme_states_the_project_is_unsigned() {
        let dev = android_readme("app-android", BundleProfile::Dev, &MountBase::root());
        let release = android_readme("app-android", BundleProfile::Release, &MountBase::root());
        for note in [&dev, &release] {
            assert!(note.contains("this Gradle project is unsigned"), "{note}");
            assert!(note.contains("debug key, for local install only"), "{note}");
            assert!(note.contains("signingConfig"), "{note}");
            assert!(note.contains("assembleRelease"), "{note}");
        }
        assert!(dev.contains("a dev bundle"), "{dev}");
        assert!(release.contains("a production bundle"), "{release}");
        assert_ne!(dev, release);
    }

    // ── Mount base: every shell URL and handler boundary derives from it ──────

    /// The root base and a nested one, each with its directory URL.
    fn bases() -> [(MountBase, &'static str); 2] {
        [
            (MountBase::root(), "/"),
            (
                MountBase::parse("/app").expect("a legal mount base"),
                "/app/",
            ),
        ]
    }

    fn shell_text(os: MobileOs, base: &MountBase, rel_path: &str) -> String {
        layout(
            os,
            BundleProfile::Dev,
            &identity(),
            &accepts(&[]),
            &bundle(),
            None,
            base,
        )
        .expect("layout")
        .generated(rel_path)
        .expect("generated shell file")
        .to_owned()
    }

    const ACTIVITY: &str = "app/src/main/java/dev/ipe/app/MainActivity.java";

    #[test]
    fn android_handler_registered_at_base() {
        for (base, dir) in bases() {
            let activity = shell_text(MobileOs::Android, &base, ACTIVITY);
            assert!(
                activity.contains(&format!("String BUNDLE_DIR = \"{dir}\";")),
                "{activity}"
            );
            assert!(
                activity.contains(".addPathHandler(BUNDLE_DIR, new BundleHandler(this))"),
                "{activity}"
            );
            assert!(
                !activity.contains("addPathHandler(\"/assets/\""),
                "{activity}"
            );
        }
    }

    #[test]
    fn android_loads_dir_url() {
        for (base, dir) in bases() {
            let activity = shell_text(MobileOs::Android, &base, ACTIVITY);
            assert!(
                activity.contains(&format!(
                    "String ENTRY_URL = \"https://appassets.androidplatform.net{dir}\";"
                )),
                "{activity}"
            );
            assert!(
                activity.contains("webView.loadUrl(ENTRY_URL);"),
                "{activity}"
            );
            assert!(!activity.contains("/assets/www/"), "{activity}");
            let readme = shell_text(MobileOs::Android, &base, "README.txt");
            assert!(
                readme.contains(&format!("https://appassets.androidplatform.net{dir}")),
                "{readme}"
            );
        }
    }

    #[test]
    fn android_null_intercept_answers_local_404() {
        for (base, _) in bases() {
            let activity = shell_text(MobileOs::Android, &base, ACTIVITY);
            assert!(
                activity.contains("return mapped != null ? mapped : localNotFound();"),
                "{activity}"
            );
            assert!(
                activity.contains("404, \"Not Found\""),
                "the unmapped answer is a local 404: {activity}"
            );
            assert!(
                !activity.contains("return loader.shouldInterceptRequest("),
                "a null from the loader must never fall through to the network: {activity}"
            );
            assert!(activity.contains("segment.equals(\"..\")"), "{activity}");
            assert!(
                activity.contains("assets.handle(\"www/index.html\")"),
                "{activity}"
            );
        }
    }

    #[test]
    fn ios_handler_boundary_is_dir_plus_slash() {
        for (base, segments) in [
            (MountBase::root(), "[]"),
            (
                MountBase::parse("/app/v2").expect("a legal mount base"),
                "[\"app\", \"v2\"]",
            ),
        ] {
            let handler = shell_text(MobileOs::Ios, &base, "App/SchemeHandler.swift");
            assert!(
                handler.contains(&format!("static let baseSegments: [String] = {segments}")),
                "{handler}"
            );
            assert!(
                handler.contains("let boundary = www.standardizedFileURL.path + \"/\""),
                "{handler}"
            );
            assert!(
                handler.contains("resolved.path.hasPrefix(boundary)"),
                "{handler}"
            );
            assert!(!handler.contains("hasPrefix(base"), "{handler}");
            assert!(handler.contains("segment == \"..\""), "{handler}");
            assert!(handler.contains("statusCode: 404"), "{handler}");
        }
    }

    #[test]
    fn ios_root_maps_to_index() {
        for (base, dir) in bases() {
            let handler = shell_text(MobileOs::Ios, &base, "App/SchemeHandler.swift");
            assert!(
                handler.contains("if segments.isEmpty || segments == [\"\"] {"),
                "{handler}"
            );
            assert!(handler.contains("segments = [\"index.html\"]"), "{handler}");
            assert!(
                handler.contains("omittingEmptySubsequences: false"),
                "the trailing-slash directory keeps its empty segment: {handler}"
            );
            let delegate = shell_text(MobileOs::Ios, &base, "App/AppDelegate.swift");
            assert!(
                delegate.contains(&format!("URL(string: \"ipe-app://app{dir}\")")),
                "{delegate}"
            );
            assert!(!delegate.contains("ipe-app://app/index.html"), "{delegate}");
        }
    }

    /// The iOS note scopes its 404 claim to the custom scheme: a `WKWebView`
    /// routes only `ipe-app://` loads to the handler, never an `https://` one.
    #[test]
    fn ios_readme_scopes_the_local_404_to_the_custom_scheme() {
        for (base, dir) in bases() {
            let readme = shell_text(MobileOs::Ios, &base, "README.txt");
            assert!(readme.contains(&format!("ipe-app://app{dir}")), "{readme}");
            assert!(
                readme.contains("an ipe-app:// request outside the\nbundle answers a local 404"),
                "{readme}"
            );
            assert!(!readme.contains("any other request"), "{readme}");
        }
    }

    // ── Literal escapers: hostile text never leaves its literal ───────────────

    /// The UTF-16 units of every `\uXXXX` Java's pre-lexing translation would
    /// read in `literal`: a `\` that an even run of backslashes precedes, then
    /// `u`s, then four hex digits.
    fn java_unicode_escapes(literal: &str) -> Vec<u32> {
        let chars: Vec<char> = literal.chars().collect();
        let mut units = Vec::new();
        let mut backslashes = 0_usize;
        for (at, ch) in chars.iter().enumerate() {
            if *ch != '\\' {
                backslashes = 0;
                continue;
            }
            if backslashes.is_multiple_of(2) {
                let rest: String = chars.iter().skip(at + 1).collect();
                let hex = rest.trim_start_matches('u');
                if hex.len() < rest.len() {
                    let digits: String = hex.chars().take(4).collect();
                    if let Ok(unit) = u32::from_str_radix(&digits, 16) {
                        units.push(unit);
                    }
                }
            }
            backslashes += 1;
        }
        units
    }

    #[test]
    fn java_string_literal_keeps_hostile_text_inside_the_literal() {
        let cases = [
            ("a\"b", r#""a\"b""#),
            ("a\\b", r#""a\\b""#),
            ("a\nb", r#""a\nb""#),
            ("a\rb\tc", r#""a\rb\tc""#),
            ("$x${y}", r#""$x${y}""#),
            ("\\u0022", r#""\\u0022""#),
            ("\u{7}", r#""\007""#),
            ("\u{7f}", r#""\177""#),
            ("é", r#""\351""#),
            ("\u{2028}", r#""\u2028""#),
            ("😀", r#""\ud83d\ude00""#),
        ];
        for (text, quoted) in cases {
            let literal = JavaStringLiteral::of(text).to_string();
            assert_eq!(literal, quoted, "{text:?}");
            assert!(
                java_unicode_escapes(&literal)
                    .iter()
                    .all(|unit| *unit > 0xff),
                "no unicode escape Java translates before lexing names a quote, \
                 backslash or line break: {literal}"
            );
            assert!(!literal.contains(['\n', '\r']), "{literal}");
        }
    }

    #[test]
    fn swift_string_literal_keeps_hostile_text_inside_the_literal() {
        let cases = [
            ("a\"b", r#""a\"b""#),
            ("a\\b", r#""a\\b""#),
            ("a\nb", r#""a\nb""#),
            ("a\rb\tc", r#""a\rb\tc""#),
            ("$x${y}", r#""$x${y}""#),
            ("\\(exit(1))", r#""\\(exit(1))""#),
            ("\0", r#""\0""#),
            ("\u{7}", r#""\u{7}""#),
            ("é", r#""\u{e9}""#),
            ("\u{202e}", r#""\u{202e}""#),
            ("😀", r#""\u{1f600}""#),
        ];
        for (text, quoted) in cases {
            let literal = SwiftStringLiteral::of(text).to_string();
            assert_eq!(literal, quoted, "{text:?}");
            assert!(!literal.contains(['\n', '\r', '\0']), "{literal}");
        }
    }

    #[test]
    fn manifest_changed_names_both_bases_and_the_remedy() {
        let shown = MobileRefusal::ManifestChanged {
            before: MountBase::root(),
            after: MountBase::parse("/app").expect("a legal mount base"),
        }
        .to_string();
        assert!(shown.contains("from `/` to `/app/`"), "{shown}");
        assert!(shown.contains("run it again"), "{shown}");
    }
}
