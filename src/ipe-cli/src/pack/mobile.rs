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
use ipe_ir::{Capability, WebCapability};
use ipe_runtime_rust::encoding::{MountBase, ServerOrigins};
use ipe_runtime_rust::js_port_glue::native_bridge;

use crate::CliError;
use crate::driver::BundleProfile;
use crate::output_dir::OwnedDir;
use crate::project::{ProjectManifest, PushDelivery};
use crate::text;

use super::permissions::{self, Platform, RequestGroup, RuntimeRequestGroup};

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
    /// The [`ManifestPin`] read after the wasm build differs from the one the
    /// shell was planned for, so the bundle and the shell would be built from
    /// two manifests.
    ManifestChanged {
        /// The pinned fields that differ.
        moved: MovedFields,
    },
    /// The project accepts push but names no `delivery.mobile.push`, so the
    /// shell has no identifiers to register with.
    PushUnconfigured,
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
            Self::ManifestChanged { moved } => write!(
                f,
                "error: {moved} changed in package.ipe while the wasm bundle was building\n  \
                 = the bundle and the mobile shell must be built from one manifest; leave \
                 package.ipe unchanged during the pack and run it again."
            ),
            Self::PushUnconfigured => write!(
                f,
                "error: this project accepts `JsPort Push`, but package.ipe names no \
                 `delivery.mobile.push`\n  \
                 = a mobile shell registers for push with its APNs environment and Firebase \
                 client identifiers: set `delivery.mobile.push = {{ apns = Production, fcm = \
                 {{ projectId, applicationId, apiKey, senderId }} }}`."
            ),
        }
    }
}

impl std::error::Error for MobileRefusal {}

/// Everything the mobile shell and the wasm bundle must agree on.
///
/// The shell is laid out from the pin captured before the wasm build, and the
/// build reads the manifest again on its own; a pin read after the build that
/// differs is refused ([`ManifestPin::moved_to`]). Every field is compared, so a
/// field added here is compared too.
#[derive(Clone, Debug)]
pub struct ManifestPin {
    /// `delivery.browser.basePath`: the mount path the bundle's URLs and the
    /// shell's handlers name.
    base: MountBase,
    /// `delivery.servers`: the origins the bundle may reach besides its own.
    servers: ServerOrigins,
    /// `delivery.mobile.push`: the identifiers the shell registers for push
    /// with; its `Debug` never prints an identifier.
    push: Option<PushDelivery>,
    /// `capabilities.accepts`: the capabilities the bundle's consent gate
    /// grants and the shell's OS permissions are derived from.
    accepts: BTreeSet<Capability>,
}

impl ManifestPin {
    /// The pin of the parsed manifest `manifest`.
    #[must_use]
    pub fn of(manifest: &ProjectManifest) -> Self {
        Self {
            base: manifest.delivery.browser.base.clone(),
            servers: manifest.delivery.servers.clone(),
            push: manifest.delivery.mobile.push.clone(),
            accepts: manifest.capabilities_accept.clone(),
        }
    }

    /// The mount base the shell is laid out for.
    #[must_use]
    pub const fn base(&self) -> &MountBase {
        &self.base
    }

    /// The accepted capabilities the shell's permissions are derived from.
    #[must_use]
    pub const fn accepts(&self) -> &BTreeSet<Capability> {
        &self.accepts
    }

    /// The origins the shell lets the bundle reach besides its own.
    #[must_use]
    pub const fn servers(&self) -> &ServerOrigins {
        &self.servers
    }

    /// The push identifiers the shell registers with, when the manifest names them.
    #[must_use]
    pub const fn push(&self) -> Option<&PushDelivery> {
        self.push.as_ref()
    }

    /// The fields of `after` that differ from this pin, or `None` when every
    /// field is equal.
    ///
    /// The one comparison of two pins: both are destructured in full, so a
    /// field added to the pin does not compile until it is compared here.
    #[must_use]
    pub fn moved_to(&self, after: &Self) -> Option<MovedFields> {
        let Self {
            base,
            servers,
            push,
            accepts,
        } = self;
        let Self {
            base: base_after,
            servers: servers_after,
            push: push_after,
            accepts: accepts_after,
        } = after;
        let fields: Vec<PinnedField> = [
            (PinnedField::BasePath, base != base_after),
            (PinnedField::Servers, servers != servers_after),
            (PinnedField::Push, push != push_after),
            (PinnedField::Accepts, accepts != accepts_after),
        ]
        .into_iter()
        .filter_map(|(field, moved)| moved.then_some(field))
        .collect();
        if fields.is_empty() {
            None
        } else {
            Some(MovedFields(fields))
        }
    }
}

/// One field of a [`ManifestPin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PinnedField {
    /// `delivery.browser.basePath`.
    BasePath,
    /// `delivery.servers`.
    Servers,
    /// `delivery.mobile.push`.
    Push,
    /// `capabilities.accepts`.
    Accepts,
}

impl PinnedField {
    /// The manifest key the field is read from.
    #[must_use]
    pub const fn manifest_key(self) -> &'static str {
        match self {
            Self::BasePath => "delivery.browser.basePath",
            Self::Servers => "delivery.servers",
            Self::Push => "delivery.mobile.push",
            Self::Accepts => "capabilities.accepts",
        }
    }
}

/// The fields two pins differ in, in [`PinnedField`] order; never empty.
///
/// Built only by [`ManifestPin::moved_to`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MovedFields(Vec<PinnedField>);

impl MovedFields {
    /// The fields that differ.
    #[must_use]
    pub fn fields(&self) -> &[PinnedField] {
        &self.0
    }
}

impl std::fmt::Display for MovedFields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, field) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "`{}`", field.manifest_key())?;
        }
        Ok(())
    }
}

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

/// Assemble the native shell project layout for `os` from the app identity, the
/// manifest pin, the offline SPA bundle, and an optional icon.
///
/// The `Info.plist` / `AndroidManifest.xml` permission entries are derived from
/// the pin's accepted capabilities through [`permissions::derive_permissions`] —
/// never authored here. The SPA bundle assets are placed under the OS's
/// web-asset root, and the shell serves them at the pin's
/// [`MountBase::dir_url`] on a local origin (never a remote URL) — the same
/// mount path the wasm build baked into the bundle's own URLs. The Android shell
/// answers every request one of three ways: a request to its local origin is
/// served from the bundle or answered by a local 404, a request to an origin of
/// `delivery.servers` goes to the network, and any other request is answered by
/// a local 403.
///
/// # Errors
/// Propagates any error from the permission derivation, and refuses an Android
/// shell that serves push when the pin names no push identifiers
/// ([`MobileRefusal::PushUnconfigured`]).
pub fn layout(
    os: MobileOs,
    profile: BundleProfile,
    identity: &super::desktop::BundleIdentity,
    pin: &ManifestPin,
    bundle: &SpaBundle,
    icon: Option<&Path>,
) -> Result<ShellLayout, super::super::CliError> {
    match os {
        MobileOs::Android => android_layout(profile, identity, pin, bundle, icon),
        MobileOs::Ios => ios_layout(identity, pin.accepts(), bundle, icon, pin.base()),
    }
}

/// The bundle-app-name segment used in filenames and identifiers, sanitised to a
/// `[a-z0-9-]` reverse-DNS segment.
fn app_slug(name: &str) -> String {
    super::desktop::sanitise_identifier(name)
}

/// A generated shell file at `rel_path` holding `text`.
const fn generated_file(rel_path: String, text: String) -> ShellFile {
    ShellFile {
        rel_path,
        content: ShellContent::Generated(text),
    }
}

// ── Android ──────────────────────────────────────────────────────────────────

/// The directory every Java source of the Android shell lives in.
const ANDROID_JAVA_DIR: &str = "app/src/main/java/dev/ipe/app/";

/// The file the capture file provider reads its one exposed directory from.
const ANDROID_CAPTURE_PATHS: &str = "app/src/main/res/xml/capture_paths.xml";

/// The Firebase Cloud Messaging client library a push shell links.
const FIREBASE_MESSAGING_VERSION: &str = "24.0.0";

/// The `androidx.core` library: notifications and the capture file provider.
const ANDROIDX_CORE_VERSION: &str = "1.13.1";

/// The most bytes of one push message's sealed field the push service reads.
const FCM_DATA_MAX_BYTES: usize = 4096;

/// The title a push notification shows when its sealed payload does not open.
const PUSH_PLACEHOLDER_TITLE: &str = "New notification";

/// The cache subdirectory a captured photo is written to, and the only
/// directory the capture file provider exposes.
const CAPTURE_DIR: &str = "capture";

/// The activity request code of the file chooser and the camera capture.
const CHOOSER_REQUEST: u16 = 100;

/// The deepest a bridge request nests: the envelope and its arguments object.
const REQUEST_MAX_DEPTH: u32 = 2;

/// The longest request id [`native_bridge::RequestId::new`] admits.
const REQUEST_ID_MAX_LEN: usize = 16;

/// The header a local 403 names the refusal in, and its value.
const BLOCKED_HEADER: (&str, &str) = ("X-Ipe-Blocked", "origin");

/// The version of the subscription text a push shell hands the page.
const SUBSCRIPTION_VERSION: u32 = 1;

/// The bridge's wire words, each as the Java constant naming it and its value.
///
/// The runtime encodes requests and parses replies with the same words; a test
/// holds the two equal.
const BRIDGE_WORDS: &[(&str, &str)] = &[
    ("FIELD_V", "v"),
    ("FIELD_ID", "id"),
    ("FIELD_CAP", "cap"),
    ("FIELD_OP", "op"),
    ("FIELD_ARGS", "args"),
    ("FIELD_OK", "ok"),
    ("FIELD_REJECT", "reject"),
    ("FIELD_CAPS", "caps"),
    ("FIELD_STATE", "state"),
    ("FIELD_SUBSCRIPTION", "subscription"),
    ("FIELD_EVENT", "event"),
    ("FIELD_TITLE", "title"),
    ("FIELD_BODY", "body"),
    ("FIELD_TAG", "tag"),
    ("FIELD_APPLICATION_KEY", "applicationKey"),
    ("EVENT_NOTIFICATION_OPENED", "notificationOpened"),
    ("EVENT_SUBSCRIPTION_CHANGED", "subscriptionChanged"),
];

/// The push shell's own wire words: the subscription text's keys and the
/// sealed push message's fields.
const PUSH_WORDS: &[(&str, &str)] = &[
    ("SUBSCRIPTION_KIND", "kind"),
    ("SUBSCRIPTION_KIND_FCM", "fcm"),
    ("SUBSCRIPTION_TOKEN", "token"),
    ("SUBSCRIPTION_P256DH", "p256dh"),
    ("SUBSCRIPTION_AUTH", "auth"),
    ("SEALED_FIELD", "s"),
    ("SEALED_TITLE", "t"),
    ("SEALED_BODY", "b"),
    ("SEALED_TAG", "g"),
];

/// Whether `value` is a Java `int`.
const fn fits_java_int(value: usize) -> bool {
    value <= 0x7fff_ffff
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a ceiling the Android shell renders as a Java `int` or `long` leaves that type, or the notification burst is empty [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    fits_java_int(native_bridge::BRIDGE_MAX_REQUEST_BYTES)
        && fits_java_int(native_bridge::BRIDGE_MAX_REPLY_BYTES)
        && fits_java_int(native_bridge::BRIDGE_MAX_OUTSTANDING)
        && fits_java_int(native_bridge::NOTIFICATION_TITLE_MAX_BYTES)
        && fits_java_int(native_bridge::NOTIFICATION_BODY_MAX_BYTES)
        && fits_java_int(native_bridge::NOTIFICATION_TAG_MAX_BYTES)
        && fits_java_int(FCM_DATA_MAX_BYTES)
        && fits_java_int(REQUEST_ID_MAX_LEN)
        && native_bridge::BRIDGE_PROTOCOL_VERSION <= 0x7fff_ffff
        && SUBSCRIPTION_VERSION <= 0x7fff_ffff
        && REQUEST_MAX_DEPTH <= 0x7fff_ffff
        && native_bridge::BRIDGE_NOTIFY_BURST > 0
        && native_bridge::BRIDGE_NOTIFY_BURST <= 0x7fff_ffff
        && native_bridge::BRIDGE_NOTIFY_WINDOW_MS <= 0x7fff_ffff_ffff_ffff,
    "an Android shell ceiling leaves its Java type, or the notification burst is empty"
);

/// The runtime's wire member for the bridged axis `cap`.
const fn wire_cap(cap: ipe_kernels::BridgeCap) -> native_bridge::BridgeCap {
    match cap {
        ipe_kernels::BridgeCap::Notification => native_bridge::BridgeCap::Notification,
        ipe_kernels::BridgeCap::Push => native_bridge::BridgeCap::Push,
    }
}

/// The `MainActivity` field holding the request group `group`.
const fn group_field(group: RequestGroup) -> &'static str {
    match group {
        RequestGroup::Location => "locationGroup",
        RequestGroup::Notifications => "notificationsGroup",
        RequestGroup::RecordAudio => "recordAudioGroup",
        RequestGroup::Camera => "cameraGroup",
    }
}

/// A web-view facility the Android shell's chrome client serves, only for an
/// accepted axis that covers it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum ChromeFacility {
    /// The page's location prompt.
    Geolocation,
    /// The file chooser.
    FileChooser,
    /// A photo taken in place of a chosen file.
    Capture,
    /// The microphone stream of `getUserMedia`.
    AudioCapture,
    /// The camera stream of `getUserMedia`.
    VideoCapture,
}

impl ChromeFacility {
    /// Every facility, in declaration order.
    const ALL: &'static [Self] = &[
        Self::Geolocation,
        Self::FileChooser,
        Self::Capture,
        Self::AudioCapture,
        Self::VideoCapture,
    ];

    /// The `Shell` flag that turns the facility on.
    const fn java_name(self) -> &'static str {
        match self {
            Self::Geolocation => "GEOLOCATION",
            Self::FileChooser => "FILE_CHOOSER",
            Self::Capture => "CAPTURE",
            Self::AudioCapture => "AUDIO_CAPTURE",
            Self::VideoCapture => "VIDEO_CAPTURE",
        }
    }
}

/// The chrome-client facilities an accepted `axis` covers.
///
/// Exhaustive over the closed [`WebCapability`] vocabulary, so a new axis
/// forces a decision here; an axis without a row serves no facility.
#[deny(clippy::wildcard_enum_match_arm)]
const fn chrome_facilities(axis: WebCapability) -> &'static [ChromeFacility] {
    match axis {
        WebCapability::Geolocation => &[ChromeFacility::Geolocation],
        WebCapability::File => &[ChromeFacility::FileChooser],
        WebCapability::Camera => &[ChromeFacility::FileChooser, ChromeFacility::Capture],
        WebCapability::Microphone => &[ChromeFacility::AudioCapture],
        WebCapability::Recorder => &[ChromeFacility::AudioCapture, ChromeFacility::VideoCapture],
        WebCapability::Notification
        | WebCapability::Push
        | WebCapability::Vibration
        | WebCapability::NetworkInfo
        | WebCapability::Clipboard
        | WebCapability::Storage
        | WebCapability::Share
        | WebCapability::Battery
        | WebCapability::Gamepad
        | WebCapability::Visibility
        | WebCapability::MediaQuery
        | WebCapability::Connectivity
        | WebCapability::Raw
        | WebCapability::Speech
        | WebCapability::Permission
        | WebCapability::Orientation
        | WebCapability::Motion
        | WebCapability::Channel
        | WebCapability::Fullscreen
        | WebCapability::ScreenOrientation
        | WebCapability::WakeLock
        | WebCapability::WebAuthn => &[],
    }
}

/// The authority of the capture file provider of the app `package`.
fn capture_authority(package: &str) -> String {
    let mut authority = String::with_capacity(
        package
            .len()
            .saturating_add(CAPTURE_DIR.len())
            .saturating_add(1),
    );
    authority.push_str(package);
    authority.push('.');
    authority.push_str(CAPTURE_DIR);
    authority
}

/// What the Android shell serves, read once from the identity and the pin.
struct AndroidPlan<'a> {
    /// The Android package, a valid Java package name.
    package: String,
    /// The app identity.
    identity: &'a super::desktop::BundleIdentity,
    /// The manifest pin the shell is laid out from.
    pin: &'a ManifestPin,
    /// The OS permissions the accepted capabilities derive.
    permissions: permissions::PermissionSet,
    /// The request groups the manifest declares in full.
    groups: Vec<RuntimeRequestGroup>,
    /// The chrome-client facilities the accepted axes cover.
    facilities: BTreeSet<ChromeFacility>,
    /// The bridged capabilities the shell serves natively.
    caps: Vec<native_bridge::BridgeCap>,
    /// The push identifiers, when the shell serves push.
    push: Option<&'a PushDelivery>,
}

impl<'a> AndroidPlan<'a> {
    /// The plan of the shell for `identity` laid out from `pin`.
    fn of(
        identity: &'a super::desktop::BundleIdentity,
        pin: &'a ManifestPin,
    ) -> Result<Self, super::super::CliError> {
        let accepts = pin.accepts();
        let permissions = permissions::derive_permissions(accepts, Platform::Android)?;
        let groups = permissions.android_runtime_request_groups();
        let mut facilities = BTreeSet::new();
        for capability in accepts {
            if let Capability::JsPort(axis) = capability {
                facilities.extend(chrome_facilities(*axis).iter().copied());
            }
        }
        let caps: Vec<native_bridge::BridgeCap> = ipe_kernels::BridgeCap::ALL
            .iter()
            .copied()
            .filter(|cap| accepts.contains(&Capability::JsPort(cap.axis())))
            .map(wire_cap)
            .collect();
        let push = if caps.contains(&native_bridge::BridgeCap::Push) {
            Some(pin.push().ok_or_else(|| {
                CliError::Usage(text::Message::relay(&MobileRefusal::PushUnconfigured))
            })?)
        } else {
            None
        };
        Ok(Self {
            package: android_package_id(identity),
            identity,
            pin,
            permissions,
            groups,
            facilities,
            caps,
            push,
        })
    }

    /// Whether the shell serves `facility`.
    fn serves(&self, facility: ChromeFacility) -> bool {
        self.facilities.contains(&facility)
    }
}

/// Assemble the Android Gradle shell project layout.
///
/// The SPA assets ride under `app/src/main/assets/www/`; a `WebViewAssetLoader`
/// path handler registered at the pin's base directory serves them at
/// [`android_entry_url`]. A request to that local origin is served from the
/// bundle or answered by a local 404, a request to an origin of
/// `delivery.servers` goes to the network, and any other request is answered
/// by a local 403. The `AndroidManifest.xml` `<uses-permission>` lines come only
/// from the permission derivation, and each is asked at the moment of use.
fn android_layout(
    profile: BundleProfile,
    identity: &super::desktop::BundleIdentity,
    pin: &ManifestPin,
    bundle: &SpaBundle,
    icon: Option<&Path>,
) -> Result<ShellLayout, super::super::CliError> {
    let plan = AndroidPlan::of(identity, pin)?;
    let slug = app_slug(&identity.name);
    let root_name = format!("{slug}-android");
    let mut files = vec![
        generated_file(
            "app/src/main/AndroidManifest.xml".to_owned(),
            render_android_manifest(&plan),
        ),
        generated_file(
            "app/build.gradle".to_owned(),
            render_android_build_gradle(&plan),
        ),
        // A SINGLE-quoted Groovy string: `$`/`{`/`}` are literal here, so a
        // `${…}` in the app name cannot become live GString interpolation that
        // Gradle evaluates at configuration time. Matches every other Gradle sink,
        // which is why they are safe; the escaper still neutralises `'`/`\`.
        generated_file(
            "settings.gradle".to_owned(),
            format!(
                "rootProject.name = '{}'\ninclude \":app\"\n",
                gradle_string_escape(&identity.name)
            ),
        ),
        generated_file(
            "README.txt".to_owned(),
            android_readme(&root_name, profile, pin.base()),
        ),
    ];
    files.extend(android_java_sources(&plan));
    if plan.serves(ChromeFacility::Capture) {
        files.push(generated_file(
            ANDROID_CAPTURE_PATHS.to_owned(),
            render_capture_paths(),
        ));
    }

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

/// The Java sources of the shell: the fixed templates with their slots filled,
/// and `Shell.java`, which holds every constant they read.
fn android_java_sources(plan: &AndroidPlan<'_>) -> Vec<ShellFile> {
    let base = plan.pin.base();
    let dir = JavaStringLiteral::of(&base.dir_url()).to_string();
    let entry = JavaStringLiteral::of(&android_entry_url(base)).to_string();
    let groups = render_permission_groups(plan);
    let group_list = RequestGroup::ALL
        .iter()
        .map(|group| group_field(*group))
        .collect::<Vec<_>>()
        .join(", ");
    let push_dispatch = if plan.push.is_some() {
        "ShellPush.handle(activity, (String) op, arguments, reply);"
    } else {
        "reply.reject(Shell.REJECT_REFUSED);"
    };
    let mut sources = vec![
        ("Shell.java", render_android_shell(plan)),
        (
            "MainActivity.java",
            fill(
                MAIN_ACTIVITY_JAVA,
                &[
                    ("BUNDLE_DIR", dir.as_str()),
                    ("ENTRY_URL", entry.as_str()),
                    ("PERMISSION_GROUPS", groups.as_str()),
                    ("GROUP_LIST", group_list.as_str()),
                ],
            ),
        ),
        (
            "ShellBridge.java",
            fill(SHELL_BRIDGE_JAVA, &[("PUSH_DISPATCH", push_dispatch)]),
        ),
        ("ShellJson.java", SHELL_JSON_JAVA.to_owned()),
        (
            "ShellNotifications.java",
            SHELL_NOTIFICATIONS_JAVA.to_owned(),
        ),
    ];
    if plan.push.is_some() {
        sources.extend([
            ("ShellPush.java", SHELL_PUSH_JAVA.to_owned()),
            ("PushKeys.java", PUSH_KEYS_JAVA.to_owned()),
            ("PushService.java", PUSH_SERVICE_JAVA.to_owned()),
            ("IpeApplication.java", IPE_APPLICATION_JAVA.to_owned()),
        ]);
    }
    sources
        .into_iter()
        .map(|(name, text)| generated_file(format!("{ANDROID_JAVA_DIR}{name}"), text))
        .collect()
}

/// The text of `template` with each `@@NAME@@` slot that `slots` names replaced
/// by its value.
///
/// One left-to-right pass: a value is copied as it is and never scanned for
/// slots, and a slot `slots` does not name is kept as written.
fn fill(template: &str, slots: &[(&str, &str)]) -> String {
    const MARK: &str = "@@";
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some((before, after)) = rest.split_once(MARK) {
        out.push_str(before);
        let Some((name, tail)) = after.split_once(MARK) else {
            out.push_str(MARK);
            rest = after;
            continue;
        };
        let kept = [MARK, name, MARK].concat();
        let kept_text: &str = &kept;
        out.push_str(
            slots
                .iter()
                .find_map(|(slot, value)| (*slot == name).then_some(*value))
                .unwrap_or(kept_text),
        );
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// The `MainActivity` fields of the four request groups, each declared only when
/// the manifest declares every permission of the group.
fn render_permission_groups(plan: &AndroidPlan<'_>) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    for group in RequestGroup::ALL {
        let row = RuntimeRequestGroup::of(*group);
        let names = row
            .permissions
            .iter()
            .map(|permission| format!("Manifest.permission.{}", permission.name()))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "    /** Asked at the moment of use, when the manifest declares it. */\n    \
             final PermissionGroup {field} = new PermissionGroup(\n            \
             new String[] {{{names}}}, {code}, {min_sdk}, {declared});",
            field = group_field(*group),
            code = row.code.get(),
            min_sdk = row.min_sdk.map_or(0, u32::from),
            declared = plan.groups.contains(&row),
        );
    }
    out
}

/// Append the Java constant `name` of type `ty` and value `value` to `out`.
fn java_const(out: &mut String, ty: &str, name: &str, value: &str) {
    use std::fmt::Write as _;

    let _ = writeln!(out, "    static final {ty} {name} = {value};");
}

/// Append the Java string constant `name` holding `value` to `out`.
fn java_string(out: &mut String, name: &str, value: &str) {
    java_const(
        out,
        "String",
        name,
        &JavaStringLiteral::of(value).to_string(),
    );
}

/// A Java array initializer of `items`.
fn java_array<I: IntoIterator<Item = String>>(items: I) -> String {
    let joined = items.into_iter().collect::<Vec<_>>().join(", ");
    format!("{{{joined}}}")
}

/// Render `Shell.java`: every constant the Java shell reads, each defined once.
///
/// The bridge's constants come from the runtime's own definitions, the
/// identity's text reaches it only as [`JavaStringLiteral`]s, and the allowed
/// origins are exactly `delivery.servers`.
fn render_android_shell(plan: &AndroidPlan<'_>) -> String {
    let mut out = String::from(
        "package dev.ipe.app;\n\n/** The shell's constants: generated, each defined once. */\n\
         final class Shell {\n    private Shell() {\n    }\n\n",
    );
    render_shell_identity(&mut out, plan);
    render_shell_bridge(&mut out, plan);
    if let Some(push) = plan.push {
        render_shell_push(&mut out, push);
    }
    out.push_str("}\n");
    out
}

/// The identity, origin and facility constants of `Shell.java`.
fn render_shell_identity(out: &mut String, plan: &AndroidPlan<'_>) {
    java_string(out, "PACKAGE", &plan.package);
    java_string(out, "APP_LABEL", &plan.identity.name);
    java_const(out, "String", "NOTIFICATION_CHANNEL", "PACKAGE");
    java_string(out, "CAPTURE_AUTHORITY", &capture_authority(&plan.package));
    java_string(out, "CAPTURE_DIR", CAPTURE_DIR);
    java_const(out, "int", "CHOOSER_REQUEST", &CHOOSER_REQUEST.to_string());
    java_const(
        out,
        "int",
        "NOTIFICATIONS_MIN_SDK",
        &RequestGroup::Notifications
            .min_sdk()
            .map_or(0, u32::from)
            .to_string(),
    );
    java_string(out, "LOCAL_ORIGIN", ANDROID_ASSET_ORIGIN);
    java_const(
        out,
        "String[]",
        "ALLOWED_ORIGINS",
        &java_array(
            plan.pin
                .servers()
                .origins()
                .map(|origin| JavaStringLiteral::of(&origin.https()).to_string()),
        ),
    );
    java_string(out, "BLOCKED_HEADER", BLOCKED_HEADER.0);
    java_string(out, "BLOCKED_ORIGIN", BLOCKED_HEADER.1);
    for facility in ChromeFacility::ALL {
        java_const(
            out,
            "boolean",
            facility.java_name(),
            if plan.serves(*facility) {
                "true"
            } else {
                "false"
            },
        );
    }
}

/// The bridge constants of `Shell.java`, from the runtime's definitions.
fn render_shell_bridge(out: &mut String, plan: &AndroidPlan<'_>) {
    let int = |out: &mut String, name: &str, value: usize| {
        java_const(out, "int", name, &value.to_string());
    };
    java_const(
        out,
        "int",
        "BRIDGE_PROTOCOL_VERSION",
        &native_bridge::BRIDGE_PROTOCOL_VERSION.to_string(),
    );
    java_string(
        out,
        "BRIDGE_CHANNEL_NAME",
        native_bridge::BRIDGE_CHANNEL_NAME,
    );
    int(
        out,
        "BRIDGE_MAX_REQUEST_BYTES",
        native_bridge::BRIDGE_MAX_REQUEST_BYTES,
    );
    int(
        out,
        "BRIDGE_MAX_REPLY_BYTES",
        native_bridge::BRIDGE_MAX_REPLY_BYTES,
    );
    int(
        out,
        "BRIDGE_MAX_OUTSTANDING",
        native_bridge::BRIDGE_MAX_OUTSTANDING,
    );
    java_const(
        out,
        "int",
        "BRIDGE_NOTIFY_BURST",
        &native_bridge::BRIDGE_NOTIFY_BURST.to_string(),
    );
    java_const(
        out,
        "long",
        "BRIDGE_NOTIFY_WINDOW_MS",
        &format!("{}L", native_bridge::BRIDGE_NOTIFY_WINDOW_MS),
    );
    int(
        out,
        "NOTIFICATION_TITLE_MAX_BYTES",
        native_bridge::NOTIFICATION_TITLE_MAX_BYTES,
    );
    int(
        out,
        "NOTIFICATION_BODY_MAX_BYTES",
        native_bridge::NOTIFICATION_BODY_MAX_BYTES,
    );
    int(
        out,
        "NOTIFICATION_TAG_MAX_BYTES",
        native_bridge::NOTIFICATION_TAG_MAX_BYTES,
    );
    java_string(
        out,
        "NOTIFICATION_TAG_PUNCTUATION",
        native_bridge::NOTIFICATION_TAG_PUNCTUATION,
    );
    java_string(out, "HELLO_ID", native_bridge::HELLO_ID);
    int(out, "REQUEST_ID_MAX_LEN", REQUEST_ID_MAX_LEN);
    java_const(
        out,
        "int",
        "REQUEST_MAX_DEPTH",
        &REQUEST_MAX_DEPTH.to_string(),
    );
    render_shell_vocabulary(out);
    java_const(
        out,
        "String[]",
        "ACCEPTED_CAPS",
        &java_array(plan.caps.iter().map(|cap| cap.glue_name().to_owned())),
    );
}

/// The bridge's closed vocabularies in `Shell.java`: the capabilities, the
/// operations, the refusals, the permission states and the wire words.
fn render_shell_vocabulary(out: &mut String) {
    java_string(
        out,
        native_bridge::HANDSHAKE_CAP_GLUE_NAME,
        native_bridge::HANDSHAKE_CAP_NAME,
    );
    for cap in native_bridge::BridgeCap::ALL {
        java_string(out, cap.glue_name(), cap.as_str());
    }
    for op in native_bridge::BridgeOp::ALL {
        java_string(out, op.glue_name(), op.op_name());
    }
    for reject in native_bridge::Reject::ALL {
        java_string(out, reject.glue_name(), reject.as_str());
    }
    for state in native_bridge::PermissionState::ALL {
        java_string(out, state.glue_name(), state.as_str());
    }
    for (name, value) in BRIDGE_WORDS {
        java_string(out, name, value);
    }
}

/// The push constants of `Shell.java`: the Firebase client identifiers and the
/// push wire words.
fn render_shell_push(out: &mut String, push: &PushDelivery) {
    java_string(out, "FCM_PROJECT_ID", push.fcm.project_id.as_str());
    java_string(out, "FCM_APPLICATION_ID", push.fcm.application_id.as_str());
    java_string(out, "FCM_API_KEY", push.fcm.api_key.as_str());
    java_string(out, "FCM_SENDER_ID", push.fcm.sender_id.as_str());
    java_const(
        out,
        "int",
        "FCM_DATA_MAX_BYTES",
        &FCM_DATA_MAX_BYTES.to_string(),
    );
    java_string(out, "PUSH_PLACEHOLDER_TITLE", PUSH_PLACEHOLDER_TITLE);
    java_const(
        out,
        "int",
        "SUBSCRIPTION_VERSION",
        &SUBSCRIPTION_VERSION.to_string(),
    );
    for (name, value) in PUSH_WORDS {
        java_string(out, name, value);
    }
}

/// The launcher activity element of the Android manifest.
const ANDROID_ACTIVITY_XML: &str = r#"        <activity
            android:name="dev.ipe.app.MainActivity"
            android:exported="true"
            android:launchMode="singleTop"
            android:configChanges="orientation|screenSize|screenLayout|smallestScreenSize|keyboardHidden|uiMode">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
"#;

/// The push elements of the Android manifest: registration waits for a
/// subscription, and the push service is the app's own.
const ANDROID_PUSH_XML: &str = r#"        <meta-data
            android:name="firebase_messaging_auto_init_enabled"
            android:value="false" />
        <service
            android:name="dev.ipe.app.PushService"
            android:exported="false">
            <intent-filter>
                <action android:name="com.google.firebase.MESSAGING_EVENT" />
            </intent-filter>
        </service>
"#;

/// Render the `AndroidManifest.xml`, splicing the derived `<uses-permission>`
/// lines (from the permission derivation, never authored here) into a fixed
/// application element.
///
/// `INTERNET` is declared only when `delivery.servers` lists an origin, the
/// capture file provider only for the capture facility, and the push service
/// only when the shell serves push.
fn render_android_manifest(plan: &AndroidPlan<'_>) -> String {
    use std::fmt::Write as _;

    let package = xml_attr_escape(&plan.package);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n\
         \x20   package=\"{package}\">"
    );
    for line in plan.permissions.to_android_manifest_entries().lines() {
        // The derived line's `android:name` is a fixed constant from the closed
        // table, never user text.
        let _ = writeln!(out, "    {line}");
    }
    if !plan.pin.servers().is_empty() {
        out.push_str("    <uses-permission android:name=\"android.permission.INTERNET\" />\n");
    }
    out.push_str("    <application\n");
    if plan.push.is_some() {
        out.push_str("        android:name=\"dev.ipe.app.IpeApplication\"\n");
    }
    let _ = writeln!(
        out,
        "        android:label=\"{label}\"\n\
         \x20       android:icon=\"@mipmap/ic_launcher\"\n\
         \x20       android:usesCleartextTraffic=\"false\">",
        label = xml_attr_escape(&plan.identity.name),
    );
    out.push_str(ANDROID_ACTIVITY_XML);
    if plan.serves(ChromeFacility::Capture) {
        let _ = writeln!(
            out,
            "        <provider\n\
             \x20           android:name=\"androidx.core.content.FileProvider\"\n\
             \x20           android:authorities=\"{authority}\"\n\
             \x20           android:exported=\"false\"\n\
             \x20           android:grantUriPermissions=\"true\">\n\
             \x20           <meta-data\n\
             \x20               android:name=\"android.support.FILE_PROVIDER_PATHS\"\n\
             \x20               android:resource=\"@xml/capture_paths\" />\n\
             \x20       </provider>",
            authority = xml_attr_escape(&capture_authority(&plan.package)),
        );
    }
    if plan.push.is_some() {
        out.push_str(ANDROID_PUSH_XML);
    }
    out.push_str("    </application>\n</manifest>\n");
    out
}

/// Render the capture file provider's paths: the one capture cache directory.
fn render_capture_paths() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <paths>\n\
         \x20   <cache-path name=\"{CAPTURE_DIR}\" path=\"{CAPTURE_DIR}/\" />\n\
         </paths>\n"
    )
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

/// Render the app-module `build.gradle`; the Firebase library is linked only
/// when the shell serves push.
fn render_android_build_gradle(plan: &AndroidPlan<'_>) -> String {
    let push = if plan.push.is_some() {
        format!(
            "    implementation 'com.google.firebase:firebase-messaging:{FIREBASE_MESSAGING_VERSION}'\n"
        )
    } else {
        String::new()
    };
    format!(
        "plugins {{ id 'com.android.application' }}\n\
         android {{\n\
         \x20   namespace '{ns}'\n\
         \x20   compileSdk 34\n\
         \x20   defaultConfig {{\n\
         \x20       applicationId '{ns}'\n\
         \x20       minSdk 24\n\
         \x20       targetSdk 34\n\
         \x20       versionName '{version}'\n\
         \x20       versionCode 1\n\
         \x20   }}\n\
         \x20   compileOptions {{\n\
         \x20       sourceCompatibility JavaVersion.VERSION_1_8\n\
         \x20       targetCompatibility JavaVersion.VERSION_1_8\n\
         \x20   }}\n\
         }}\n\
         dependencies {{\n\
         \x20   implementation 'androidx.webkit:webkit:1.11.0'\n\
         \x20   implementation 'androidx.appcompat:appcompat:1.7.0'\n\
         \x20   implementation 'androidx.core:core:{ANDROIDX_CORE_VERSION}'\n\
         {push}\
         }}\n",
        ns = gradle_string_escape(&plan.package),
        version = gradle_string_escape(&plan.identity.version),
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

/// The `MainActivity` template: the web view, its request rule, its chrome
/// client and the permission groups.
///
/// A `BundleHandler` registered at the base directory maps the path below it
/// into `assets/www/` (the empty path is `index.html`) and refuses a `\`, a `%`,
/// and an empty, `.` or `..` segment. A local request the loader leaves
/// unmapped answers a local 404, a request to an origin of `Shell.ALLOWED_ORIGINS`
/// goes to the network, and any other answers a local 403. A permission is
/// asked only when a page asks for the facility it backs, and a media request
/// is granted only the resources an accepted axis covers.
const MAIN_ACTIVITY_JAVA: &str = r#"package dev.ipe.app;

import android.Manifest;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.provider.MediaStore;
import android.webkit.GeolocationPermissions;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.core.content.FileProvider;
import androidx.webkit.WebViewAssetLoader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public final class MainActivity extends Activity {
    /** The directory the bundle is served at: the manifest's mount base. */
    private static final String BUNDLE_DIR = @@BUNDLE_DIR@@;
    /** The URL the shell opens: the local asset origin plus BUNDLE_DIR. */
    private static final String ENTRY_URL = @@ENTRY_URL@@;

    /** Serves assets/www/ for the path below BUNDLE_DIR. */
    private static final class BundleHandler implements WebViewAssetLoader.PathHandler {
        private final WebViewAssetLoader.AssetsPathHandler assets;

        BundleHandler(Context context) {
            this.assets = new WebViewAssetLoader.AssetsPathHandler(context);
        }

        @Override
        public WebResourceResponse handle(String path) {
            if (path.isEmpty()) {
                return assets.handle("www/index.html");
            }
            if (path.indexOf('\\') >= 0 || path.indexOf('%') >= 0) {
                return null;
            }
            for (String segment : path.split("/", -1)) {
                if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                    return null;
                }
            }
            return assets.handle("www/" + path);
        }
    }

    /** The answer to every local request the loader leaves unmapped: a local 404. */
    private static WebResourceResponse localNotFound() {
        return new WebResourceResponse("text/plain", "utf-8", 404, "Not Found",
                Collections.<String, String>emptyMap(),
                new ByteArrayInputStream(new byte[0]));
    }

    /** The answer to a request for an origin outside delivery.servers: a local 403. */
    private static WebResourceResponse blocked() {
        return new WebResourceResponse("text/plain", "utf-8", 403, "Forbidden",
                Collections.singletonMap(Shell.BLOCKED_HEADER, Shell.BLOCKED_ORIGIN),
                new ByteArrayInputStream(new byte[0]));
    }

    /** The https origin of url, or null for any other scheme, a user name or no host. */
    static String originOf(Uri url) {
        if (url == null || !"https".equals(url.getScheme()) || url.getUserInfo() != null) {
            return null;
        }
        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return null;
        }
        String origin = "https://" + host.toLowerCase(Locale.ROOT);
        int port = url.getPort();
        return port == -1 || port == 443 ? origin : origin + ":" + port;
    }

    /** Whether origin is one of delivery.servers. */
    private static boolean isAllowed(String origin) {
        if (origin == null) {
            return false;
        }
        for (String allowed : Shell.ALLOWED_ORIGINS) {
            if (allowed.equals(origin)) {
                return true;
            }
        }
        return false;
    }

    /** The outcome of one runtime permission request. */
    interface Granted {
        void done(boolean granted);
    }

    /** One runtime permission request group: its permissions are asked in one request. */
    static final class PermissionGroup {
        private final String[] permissions;
        private final int code;
        private final int minSdk;
        private final boolean declared;
        private final List<Granted> waiters = new ArrayList<>();

        PermissionGroup(String[] permissions, int code, int minSdk, boolean declared) {
            this.permissions = permissions;
            this.code = code;
            this.minSdk = minSdk;
            this.declared = declared;
        }

        /** Whether the manifest declares this group. */
        boolean declared() {
            return declared;
        }

        /** Whether the app holds the group: below its API level, or one permission granted. */
        boolean held(Activity activity) {
            if (Build.VERSION.SDK_INT < minSdk) {
                return true;
            }
            for (String permission : permissions) {
                if (activity.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Ask for the group when wanted, at the moment of use. Returns false, and never
         * calls granted, when the group is not wanted, not declared, or has too many
         * waiters; otherwise granted is called exactly once.
         */
        boolean ask(Activity activity, boolean wanted, Granted granted) {
            if (!wanted || !declared) {
                return false;
            }
            if (held(activity)) {
                granted.done(true);
                return true;
            }
            if (waiters.size() >= Shell.BRIDGE_MAX_OUTSTANDING) {
                return false;
            }
            waiters.add(granted);
            if (waiters.size() == 1) {
                activity.requestPermissions(permissions, code);
            }
            return true;
        }

        /** Settle every waiter when requestCode is this group's; whether it was. */
        boolean finish(Activity activity, int requestCode) {
            if (requestCode != code) {
                return false;
            }
            boolean granted = held(activity);
            List<Granted> settled = new ArrayList<>(waiters);
            waiters.clear();
            for (Granted waiter : settled) {
                waiter.done(granted);
            }
            return true;
        }
    }

@@PERMISSION_GROUPS@@
    private PermissionGroup[] groups() {
        return new PermissionGroup[] {@@GROUP_LIST@@};
    }

    private ShellBridge bridge;
    private ValueCallback<Uri[]> chooser;
    private Uri captureUri;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final WebViewAssetLoader loader = new WebViewAssetLoader.Builder()
            .addPathHandler(BUNDLE_DIR, new BundleHandler(this))
            .build();
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setSupportMultipleWindows(false);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
        settings.setGeolocationEnabled(Shell.GEOLOCATION);
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(
                    WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                String origin = originOf(url);
                if (Shell.LOCAL_ORIGIN.equals(origin)) {
                    WebResourceResponse mapped = loader.shouldInterceptRequest(url);
                    return mapped != null ? mapped : localNotFound();
                }
                return isAllowed(origin) ? null : blocked();
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                if (request.isForMainFrame() && Shell.LOCAL_ORIGIN.equals(originOf(url))) {
                    return false;
                }
                if (request.hasGesture() && originOf(url) != null) {
                    openExternally(url);
                }
                return true;
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                if (bridge != null) {
                    bridge.pageStarted();
                }
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onGeolocationPermissionsShowPrompt(
                    final String origin, final GeolocationPermissions.Callback callback) {
                boolean wanted = Shell.GEOLOCATION
                        && Shell.LOCAL_ORIGIN.equals(originOf(Uri.parse(origin)));
                if (!locationGroup.ask(MainActivity.this, wanted,
                        granted -> callback.invoke(origin, granted, false))) {
                    callback.invoke(origin, false, false);
                }
            }

            @Override
            public void onPermissionRequest(final PermissionRequest request) {
                if (!Shell.LOCAL_ORIGIN.equals(originOf(request.getOrigin()))) {
                    request.deny();
                    return;
                }
                boolean audio = false;
                boolean video = false;
                for (String resource : request.getResources()) {
                    if (PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(resource)) {
                        audio = true;
                    } else if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(resource)) {
                        video = true;
                    }
                }
                boolean wantAudio = Shell.AUDIO_CAPTURE && audio;
                boolean wantVideo = Shell.VIDEO_CAPTURE && video;
                if (!wantAudio && !wantVideo) {
                    request.deny();
                    return;
                }
                askMedia(request, wantAudio, wantVideo);
            }

            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback,
                    FileChooserParams params) {
                if (!Shell.FILE_CHOOSER || chooser != null) {
                    return false;
                }
                chooser = callback;
                if (Shell.CAPTURE && params.isCaptureEnabled()) {
                    Granted capture = granted -> {
                        if (granted) {
                            launchCapture();
                        } else {
                            deliver(null);
                        }
                    };
                    if (!cameraGroup.declared()) {
                        capture.done(true);
                    } else if (!cameraGroup.ask(MainActivity.this, true, capture)) {
                        capture.done(false);
                    }
                    return true;
                }
                try {
                    startActivityForResult(params.createIntent(), Shell.CHOOSER_REQUEST);
                } catch (ActivityNotFoundException e) {
                    chooser = null;
                    return false;
                }
                return true;
            }

            @Override
            public boolean onCreateWindow(WebView view, boolean isDialog, boolean isUserGesture,
                    Message resultMsg) {
                return false;
            }
        });
        bridge = ShellBridge.install(this, webView);
        setContentView(webView);
        webView.loadUrl(ENTRY_URL);
        if (bridge != null) {
            bridge.tapped(getIntent());
        }
    }

    /** Ask for the audio group, then the camera group, then grant what both allow. */
    private void askMedia(final PermissionRequest request, final boolean wantAudio,
            final boolean wantVideo) {
        Granted afterAudio = audioGranted -> {
            Granted afterVideo = videoGranted ->
                    grantMedia(request, wantAudio && audioGranted, wantVideo && videoGranted);
            if (!cameraGroup.ask(this, wantVideo, afterVideo)) {
                afterVideo.done(false);
            }
        };
        if (!recordAudioGroup.ask(this, wantAudio, afterAudio)) {
            afterAudio.done(false);
        }
    }

    /** Grant exactly the media resources allowed, or deny when none is. */
    private static void grantMedia(PermissionRequest request, boolean audio, boolean video) {
        List<String> resources = new ArrayList<>();
        if (audio) {
            resources.add(PermissionRequest.RESOURCE_AUDIO_CAPTURE);
        }
        if (video) {
            resources.add(PermissionRequest.RESOURCE_VIDEO_CAPTURE);
        }
        if (resources.isEmpty()) {
            request.deny();
        } else {
            request.grant(resources.toArray(new String[0]));
        }
    }

    /** Take one photo into the private capture directory and hand it to the chooser. */
    private void launchCapture() {
        try {
            File dir = new File(getCacheDir(), Shell.CAPTURE_DIR);
            File[] stale = dir.listFiles();
            if (stale != null) {
                for (File old : stale) {
                    if (!old.delete()) {
                        deliver(null);
                        return;
                    }
                }
            }
            if (!dir.isDirectory() && !dir.mkdirs()) {
                deliver(null);
                return;
            }
            File file = File.createTempFile("photo", ".jpg", dir);
            Uri uri = FileProvider.getUriForFile(this, Shell.CAPTURE_AUTHORITY, file);
            Intent intent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
            intent.putExtra(MediaStore.EXTRA_OUTPUT, uri);
            intent.setClipData(ClipData.newRawUri("", uri));
            intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    | Intent.FLAG_GRANT_READ_URI_PERMISSION);
            captureUri = uri;
            startActivityForResult(intent, Shell.CHOOSER_REQUEST);
        } catch (IOException | IllegalArgumentException | ActivityNotFoundException
                | SecurityException e) {
            deliver(null);
        }
    }

    /** Answer the open file chooser once, and forget it. */
    private void deliver(Uri[] result) {
        ValueCallback<Uri[]> callback = chooser;
        chooser = null;
        captureUri = null;
        if (callback != null) {
            callback.onReceiveValue(result);
        }
    }

    /** Open url in the device's browser; a link nothing opens is dropped. */
    private void openExternally(Uri url) {
        Intent intent = new Intent(Intent.ACTION_VIEW, url);
        intent.addCategory(Intent.CATEGORY_BROWSABLE);
        try {
            startActivity(intent);
        } catch (ActivityNotFoundException e) {
            return;
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != Shell.CHOOSER_REQUEST) {
            super.onActivityResult(requestCode, resultCode, data);
            return;
        }
        Uri shot = captureUri;
        if (shot != null) {
            Uri[] taken = new Uri[1];
            taken[0] = shot;
            deliver(resultCode == RESULT_OK ? taken : null);
        } else {
            deliver(WebChromeClient.FileChooserParams.parseResult(resultCode, data));
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions,
            int[] grantResults) {
        for (PermissionGroup group : groups()) {
            if (group.finish(this, requestCode)) {
                return;
            }
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (bridge != null) {
            bridge.tapped(intent);
        }
    }
}
"#;

/// The bridge template: one message listener on the local origin, the request
/// grammar, the outstanding ceiling, the handshake and the event channel.
const SHELL_BRIDGE_JAVA: &str = r#"package dev.ipe.app;

import android.content.Intent;
import android.net.Uri;
import android.webkit.WebView;
import androidx.webkit.JavaScriptReplyProxy;
import androidx.webkit.WebMessageCompat;
import androidx.webkit.WebViewCompat;
import androidx.webkit.WebViewFeature;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import org.json.JSONArray;
import org.json.JSONObject;

/** The native bridge: one message listener, on the bundle's own origin only. */
final class ShellBridge {
    /** The keys of a request envelope, each exactly once. */
    private static final String[] ENVELOPE = {
        Shell.FIELD_V, Shell.FIELD_ID, Shell.FIELD_CAP, Shell.FIELD_OP, Shell.FIELD_ARGS,
    };

    private static WeakReference<ShellBridge> live = new WeakReference<>(null);

    private final MainActivity activity;
    private JavaScriptReplyProxy eventProxy;
    private String heldTap;
    private int outstanding;

    private ShellBridge(MainActivity activity) {
        this.activity = activity;
    }

    /** The installed bridge, while its activity lives. */
    static ShellBridge live() {
        return live.get();
    }

    /** Install the listener on webView, or null when no capability is bridged. */
    static ShellBridge install(MainActivity activity, WebView webView) {
        if (Shell.ACCEPTED_CAPS.length == 0
                || !WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            return null;
        }
        ShellBridge bridge = new ShellBridge(activity);
        WebViewCompat.addWebMessageListener(webView, Shell.BRIDGE_CHANNEL_NAME,
                Collections.singleton(Shell.LOCAL_ORIGIN), bridge::onMessage);
        live = new WeakReference<>(bridge);
        return bridge;
    }

    /** One message from the page; anything outside the request grammar is dropped. */
    private void onMessage(WebView view, WebMessageCompat message, Uri sourceOrigin,
            boolean isMainFrame, JavaScriptReplyProxy proxy) {
        if (!isMainFrame) {
            return;
        }
        if (!Shell.LOCAL_ORIGIN.equals(MainActivity.originOf(sourceOrigin))) {
            return;
        }
        String data = message.getData();
        if (data == null || data.length() > Shell.BRIDGE_MAX_REQUEST_BYTES
                || ShellNotifications.utf8(data) > Shell.BRIDGE_MAX_REQUEST_BYTES) {
            return;
        }
        if (!ShellJson.nestsWithin(data, Shell.REQUEST_MAX_DEPTH)) {
            return;
        }
        JSONObject fields = ShellJson.parseObject(data);
        if (fields == null) {
            return;
        }
        Object id = fields.opt(Shell.FIELD_ID);
        if (!(id instanceof String) || !isRequestId((String) id)) {
            return;
        }
        dispatch((String) id, fields, proxy);
    }

    /** Whether text is 1 to REQUEST_ID_MAX_LEN lowercase hex digits. */
    private static boolean isRequestId(String text) {
        if (text.isEmpty() || text.length() > Shell.REQUEST_ID_MAX_LEN) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    /** Whether fields holds exactly the envelope keys. */
    private static boolean isEnvelope(JSONObject fields) {
        if (fields.length() != ENVELOPE.length) {
            return false;
        }
        for (String key : ENVELOPE) {
            if (!fields.has(key)) {
                return false;
            }
        }
        return true;
    }

    /** Whether the shell serves cap. */
    private static boolean accepted(String cap) {
        for (String served : Shell.ACCEPTED_CAPS) {
            if (served.equals(cap)) {
                return true;
            }
        }
        return false;
    }

    private void dispatch(String id, JSONObject fields, JavaScriptReplyProxy proxy) {
        Reply reply = new Reply(this, proxy, id);
        Object version = fields.opt(Shell.FIELD_V);
        if (!(version instanceof Number)
                || ((Number) version).doubleValue() != Shell.BRIDGE_PROTOCOL_VERSION) {
            reply.reject(Shell.REJECT_VERSION);
            return;
        }
        Object cap = fields.opt(Shell.FIELD_CAP);
        Object op = fields.opt(Shell.FIELD_OP);
        Object args = fields.opt(Shell.FIELD_ARGS);
        if (!isEnvelope(fields) || !(cap instanceof String) || !(op instanceof String)
                || !(args instanceof JSONObject)) {
            reply.reject(Shell.REJECT_REFUSED);
            return;
        }
        JSONObject arguments = (JSONObject) args;
        if (Shell.CAP_BRIDGE.equals(cap)) {
            if (Shell.HELLO_ID.equals(id) && Shell.OP_HELLO.equals(op) && arguments.length() == 0) {
                hello(proxy, reply);
            } else {
                reply.reject(Shell.REJECT_REFUSED);
            }
            return;
        }
        if (Shell.HELLO_ID.equals(id) || !accepted((String) cap)) {
            reply.reject(Shell.REJECT_REFUSED);
            return;
        }
        if (outstanding >= Shell.BRIDGE_MAX_OUTSTANDING) {
            reply.reject(Shell.REJECT_LIMIT);
            return;
        }
        reply.count();
        if (Shell.CAP_NOTIFICATION.equals(cap)) {
            ShellNotifications.handle(activity, (String) op, arguments, reply);
        } else if (Shell.CAP_PUSH.equals(cap)) {
            @@PUSH_DISPATCH@@
        } else {
            reply.reject(Shell.REJECT_REFUSED);
        }
    }

    /** Answer the handshake, and open the event channel on this page. */
    private void hello(JavaScriptReplyProxy proxy, Reply reply) {
        JSONArray caps = new JSONArray();
        for (String cap : Shell.ACCEPTED_CAPS) {
            caps.put(cap);
        }
        eventProxy = proxy;
        reply.ok(ShellJson.object(Shell.FIELD_V, Shell.BRIDGE_PROTOCOL_VERSION,
                Shell.FIELD_CAPS, caps));
        String tag = heldTap;
        heldTap = null;
        if (tag != null) {
            opened(tag);
        }
    }

    /** A new page is loading: its handshake opens the event channel again. */
    void pageStarted() {
        eventProxy = null;
    }

    /** The activity was opened by intent: a notification tap when its nonce verifies. */
    void tapped(Intent intent) {
        String tag = ShellNotifications.tappedTag(activity, intent);
        if (tag != null) {
            opened(tag);
        }
    }

    private void opened(String tag) {
        if (eventProxy == null) {
            heldTap = tag;
            return;
        }
        send(ShellJson.object(Shell.FIELD_V, Shell.BRIDGE_PROTOCOL_VERSION,
                Shell.FIELD_EVENT, Shell.EVENT_NOTIFICATION_OPENED, Shell.FIELD_TAG, tag));
    }

    /** The push subscription changed to text, or ended when text is null. */
    void subscriptionChanged(String text) {
        send(ShellJson.object(Shell.FIELD_V, Shell.BRIDGE_PROTOCOL_VERSION,
                Shell.FIELD_EVENT, Shell.EVENT_SUBSCRIPTION_CHANGED,
                Shell.FIELD_SUBSCRIPTION, text == null ? JSONObject.NULL : text));
    }

    private void send(JSONObject event) {
        JavaScriptReplyProxy proxy = eventProxy;
        if (proxy == null || event == null) {
            return;
        }
        String text = event.toString();
        if (ShellNotifications.utf8(text) <= Shell.BRIDGE_MAX_REPLY_BYTES) {
            proxy.postMessage(text);
        }
    }

    /** The one answer to one request. */
    static final class Reply {
        private final ShellBridge bridge;
        private final JavaScriptReplyProxy proxy;
        private final String id;
        private boolean counted;
        private boolean answered;

        Reply(ShellBridge bridge, JavaScriptReplyProxy proxy, String id) {
            this.bridge = bridge;
            this.proxy = proxy;
            this.id = id;
        }

        /** Count this request as outstanding until it is answered. */
        void count() {
            counted = true;
            bridge.outstanding++;
        }

        /** Answer with payload; a missing payload is unavailable. */
        void ok(JSONObject payload) {
            if (payload == null) {
                reject(Shell.REJECT_UNAVAILABLE);
                return;
            }
            JSONObject message = ShellJson.object(Shell.FIELD_V, Shell.BRIDGE_PROTOCOL_VERSION,
                    Shell.FIELD_ID, id, Shell.FIELD_OK, payload);
            if (message == null) {
                reject(Shell.REJECT_UNAVAILABLE);
                return;
            }
            String text = message.toString();
            if (ShellNotifications.utf8(text) > Shell.BRIDGE_MAX_REPLY_BYTES) {
                reject(Shell.REJECT_LIMIT);
                return;
            }
            answer(text);
        }

        /** Answer with the refusal code. */
        void reject(String code) {
            JSONObject message = ShellJson.object(Shell.FIELD_V, Shell.BRIDGE_PROTOCOL_VERSION,
                    Shell.FIELD_ID, id, Shell.FIELD_REJECT, code);
            answer(message == null ? null : message.toString());
        }

        private void answer(String text) {
            if (answered) {
                return;
            }
            answered = true;
            if (counted) {
                bridge.outstanding--;
            }
            if (text != null) {
                proxy.postMessage(text);
            }
        }
    }
}
"#;

/// The strict JSON pre-scan and parse the bridge reads requests with.
const SHELL_JSON_JAVA: &str = r#"package dev.ipe.app;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

/** The strict JSON reading and writing the bridge uses. */
final class ShellJson {
    /** The letters a JSON literal (true, false, null) or an exponent spells. */
    private static final String LITERAL_LETTERS = "aeflnrstuE";

    private ShellJson() {
    }

    /**
     * Whether text, outside its strings, holds only JSON's own characters and nests
     * no deeper than depth. Run before the lenient platform parser sees the text.
     */
    static boolean nestsWithin(String text, int depth) {
        int level = 0;
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                } else if (c < 0x20) {
                    return false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{' || c == '[') {
                level++;
                if (level > depth) {
                    return false;
                }
            } else if (c == '}' || c == ']') {
                level--;
                if (level < 0) {
                    return false;
                }
            } else if (!(c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':' || c == ','
                    || c == '-' || c == '+' || c == '.' || (c >= '0' && c <= '9')
                    || LITERAL_LETTERS.indexOf(c) >= 0)) {
                return false;
            }
        }
        return !inString && level == 0;
    }

    /** The one JSON object text spells, with nothing after it, or null. */
    static JSONObject parseObject(String text) {
        try {
            JSONTokener tokener = new JSONTokener(text);
            Object value = tokener.nextValue();
            if (!(value instanceof JSONObject) || tokener.nextClean() != '\0') {
                return null;
            }
            return (JSONObject) value;
        } catch (JSONException e) {
            return null;
        }
    }

    /** The object of the alternating key, value pairs, or null for a malformed list. */
    static JSONObject object(Object... pairs) {
        if (pairs.length % 2 != 0) {
            return null;
        }
        JSONObject result = new JSONObject();
        try {
            for (int i = 0; i < pairs.length; i += 2) {
                if (!(pairs[i] instanceof String) || pairs[i + 1] == null) {
                    return null;
                }
                result.put((String) pairs[i], pairs[i + 1]);
            }
        } catch (JSONException e) {
            return null;
        }
        return result;
    }
}
"#;

/// The notification capability: its permission, its burst window, its posting
/// and its nonce-checked taps.
const SHELL_NOTIFICATIONS_JAVA: &str = r#"package dev.ipe.app;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemClock;
import android.util.Base64;
import androidx.core.app.NotificationChannelCompat;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;

/** The notification capability: its permission, its posting and its taps. */
final class ShellNotifications {
    private static final String TAG_EXTRA = Shell.PACKAGE + ".notificationTag";
    private static final String NONCE_EXTRA = Shell.PACKAGE + ".notificationNonce";
    private static final String PREFS = Shell.PACKAGE + ".notifications";
    private static final String NONCE_KEY = "tapNonce";
    private static final int NONCE_BYTES = 16;
    private static final AtomicInteger IDS = new AtomicInteger(1);
    /** When each of the last BRIDGE_NOTIFY_BURST notifications was shown, oldest at shownNext. */
    private static final long[] SHOWN = new long[Shell.BRIDGE_NOTIFY_BURST];
    private static int shownCount;
    private static int shownNext;

    private ShellNotifications() {
    }

    static void handle(final MainActivity activity, String op, JSONObject args,
            final ShellBridge.Reply reply) {
        if (Shell.OP_NOTIFICATION_SHOW.equals(op)) {
            show(activity, args, reply);
            return;
        }
        boolean permission = Shell.OP_NOTIFICATION_PERMISSION.equals(op);
        boolean request = Shell.OP_NOTIFICATION_REQUEST.equals(op);
        if (!(permission || request) || args.length() != 0) {
            reply.reject(Shell.REJECT_REFUSED);
            return;
        }
        if (permission) {
            reply.ok(state(enabled(activity)));
            return;
        }
        if (!activity.notificationsGroup.ask(activity, true,
                granted -> reply.ok(state(enabled(activity))))) {
            reply.ok(state(false));
        }
    }

    private static JSONObject state(boolean granted) {
        return ShellJson.object(Shell.FIELD_STATE,
                granted ? Shell.STATE_GRANTED : Shell.STATE_DENIED);
    }

    private static void show(Context context, JSONObject args, ShellBridge.Reply reply) {
        Object title = args.opt(Shell.FIELD_TITLE);
        Object body = args.opt(Shell.FIELD_BODY);
        Object tag = args.opt(Shell.FIELD_TAG);
        if (args.length() != 3 || !(title instanceof String) || !(body instanceof String)
                || !(tag instanceof String)) {
            reply.reject(Shell.REJECT_REFUSED);
            return;
        }
        if (utf8((String) title) > Shell.NOTIFICATION_TITLE_MAX_BYTES
                || utf8((String) body) > Shell.NOTIFICATION_BODY_MAX_BYTES) {
            reply.reject(Shell.REJECT_LIMIT);
            return;
        }
        if (!isTag((String) tag)) {
            reply.reject(Shell.REJECT_REFUSED);
            return;
        }
        if (!enabled(context)) {
            reply.reject(Shell.REJECT_DENIED);
            return;
        }
        if (!admit()) {
            reply.reject(Shell.REJECT_LIMIT);
            return;
        }
        if (post(context, (String) title, (String) body, (String) tag)) {
            reply.ok(ShellJson.object());
        } else {
            reply.reject(Shell.REJECT_UNAVAILABLE);
        }
    }

    /** Whether one more notification fits the burst window, recording it when it does. */
    private static synchronized boolean admit() {
        long now = SystemClock.elapsedRealtime();
        if (shownCount == SHOWN.length) {
            if (now - SHOWN[shownNext] < Shell.BRIDGE_NOTIFY_WINDOW_MS) {
                return false;
            }
        } else {
            shownCount++;
        }
        SHOWN[shownNext] = now;
        shownNext = (shownNext + 1) % SHOWN.length;
        return true;
    }

    /** The UTF-8 length of text. */
    static int utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8).length;
    }

    /** Whether tag is in the tag grammar: short, ASCII letters, digits and the punctuation. */
    static boolean isTag(String tag) {
        if (tag.length() > Shell.NOTIFICATION_TAG_MAX_BYTES) {
            return false;
        }
        for (int i = 0; i < tag.length(); i++) {
            char c = tag.charAt(i);
            boolean alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9');
            if (!alnum && Shell.NOTIFICATION_TAG_PUNCTUATION.indexOf(c) < 0) {
                return false;
            }
        }
        return true;
    }

    /** Whether the app may post a notification now. */
    static boolean enabled(Context context) {
        if (Build.VERSION.SDK_INT >= Shell.NOTIFICATIONS_MIN_SDK
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        return NotificationManagerCompat.from(context).areNotificationsEnabled();
    }

    /** Post one notification; an empty tag gets a fresh id, a tag replaces its own. */
    @SuppressLint("MissingPermission")
    static boolean post(Context context, String title, String body, String tag) {
        try {
            NotificationManagerCompat manager = NotificationManagerCompat.from(context);
            manager.createNotificationChannel(new NotificationChannelCompat.Builder(
                    Shell.NOTIFICATION_CHANNEL, NotificationManagerCompat.IMPORTANCE_DEFAULT)
                    .setName(Shell.APP_LABEL)
                    .build());
            int icon = context.getApplicationInfo().icon;
            int id = IDS.getAndIncrement();
            NotificationCompat.Builder builder =
                    new NotificationCompat.Builder(context, Shell.NOTIFICATION_CHANNEL)
                    .setSmallIcon(icon != 0 ? icon : android.R.drawable.ic_dialog_info)
                    .setContentTitle(title)
                    .setContentText(body)
                    .setAutoCancel(true)
                    .setContentIntent(tapIntent(context, tag, id));
            if (tag.isEmpty()) {
                manager.notify(id, builder.build());
            } else {
                manager.notify(tag, 0, builder.build());
            }
            return true;
        } catch (SecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** The intent a tap on a notification tagged tag delivers, carrying the app's nonce. */
    private static PendingIntent tapIntent(Context context, String tag, int code) {
        Intent intent = new Intent(context, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        intent.putExtra(TAG_EXTRA, tag);
        intent.putExtra(NONCE_EXTRA, nonce(context));
        return PendingIntent.getActivity(context, code, intent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    /** The app's private tap nonce, made once. */
    private static synchronized String nonce(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String nonce = prefs.getString(NONCE_KEY, null);
        if (nonce == null) {
            byte[] bytes = new byte[NONCE_BYTES];
            new SecureRandom().nextBytes(bytes);
            nonce = Base64.encodeToString(bytes, Base64.NO_WRAP);
            prefs.edit().putString(NONCE_KEY, nonce).apply();
        }
        return nonce;
    }

    /**
     * The tag of the notification tap intent carries, or null. An intent another app
     * sends lacks the nonce, so it opens nothing.
     */
    static String tappedTag(Context context, Intent intent) {
        if (intent == null) {
            return null;
        }
        try {
            String tag = intent.getStringExtra(TAG_EXTRA);
            String nonce = intent.getStringExtra(NONCE_EXTRA);
            intent.removeExtra(TAG_EXTRA);
            intent.removeExtra(NONCE_EXTRA);
            if (tag == null || nonce == null || !isTag(tag)) {
                return null;
            }
            byte[] expected = nonce(context).getBytes(StandardCharsets.UTF_8);
            byte[] given = nonce.getBytes(StandardCharsets.UTF_8);
            return MessageDigest.isEqual(expected, given) ? tag : null;
        } catch (RuntimeException e) {
            return null;
        }
    }
}
"#;

/// The push capability: subscribing, the current subscription, dropping it.
const SHELL_PUSH_JAVA: &str = r#"package dev.ipe.app;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import com.google.firebase.messaging.FirebaseMessaging;
import org.json.JSONObject;

/** The push capability: a Firebase registration carrying the shell's own receiver keys. */
final class ShellPush {
    private ShellPush() {
    }

    static void handle(MainActivity activity, String op, JSONObject args,
            ShellBridge.Reply reply) {
        if (Shell.OP_PUSH_SUBSCRIBE.equals(op)) {
            subscribe(activity, args, reply);
            return;
        }
        boolean current = Shell.OP_PUSH_CURRENT.equals(op);
        boolean unsubscribe = Shell.OP_PUSH_UNSUBSCRIBE.equals(op);
        if (!(current || unsubscribe) || args.length() != 0) {
            reply.reject(Shell.REJECT_REFUSED);
            return;
        }
        if (current) {
            current(activity, reply);
        } else {
            unsubscribe(activity, reply);
        }
    }

    private static void subscribe(final MainActivity activity, JSONObject args,
            final ShellBridge.Reply reply) {
        Object key = args.opt(Shell.FIELD_APPLICATION_KEY);
        if (args.length() != 1 || !(key instanceof String)
                || !PushKeys.isApplicationKey((String) key)) {
            reply.reject(Shell.REJECT_REFUSED);
            return;
        }
        MainActivity.Granted after = granted -> {
            if (!ShellNotifications.enabled(activity)) {
                reply.reject(Shell.REJECT_DENIED);
                return;
            }
            PushKeys keys = PushKeys.loadOrCreate(activity);
            if (keys == null) {
                reply.reject(Shell.REJECT_UNAVAILABLE);
                return;
            }
            token(keys, reply, true);
        };
        if (!activity.notificationsGroup.ask(activity, true, after)) {
            after.done(false);
        }
    }

    private static void current(Context context, ShellBridge.Reply reply) {
        PushKeys keys = PushKeys.load(context);
        if (keys == null) {
            reply.ok(ShellJson.object(Shell.FIELD_SUBSCRIPTION, JSONObject.NULL));
            return;
        }
        token(keys, reply, false);
    }

    private static void unsubscribe(Context context, final ShellBridge.Reply reply) {
        PushKeys.clear(context);
        FirebaseMessaging messaging = messaging();
        if (messaging == null) {
            reply.ok(ShellJson.object());
            return;
        }
        messaging.setAutoInitEnabled(false);
        messaging.deleteToken().addOnCompleteListener(task -> reply.ok(ShellJson.object()));
    }

    /** Answer with the subscription of the current registration token. */
    private static void token(final PushKeys keys, final ShellBridge.Reply reply,
            boolean register) {
        FirebaseMessaging messaging = messaging();
        if (messaging == null) {
            reply.reject(Shell.REJECT_UNAVAILABLE);
            return;
        }
        if (register) {
            messaging.setAutoInitEnabled(true);
        }
        messaging.getToken().addOnCompleteListener(task -> {
            String text = task.isSuccessful() ? keys.subscription(task.getResult()) : null;
            if (text == null) {
                reply.reject(Shell.REJECT_UNAVAILABLE);
                return;
            }
            reply.ok(ShellJson.object(Shell.FIELD_SUBSCRIPTION, text));
        });
    }

    private static FirebaseMessaging messaging() {
        try {
            return FirebaseMessaging.getInstance();
        } catch (IllegalStateException e) {
            return null;
        }
    }

    /** The registration token changed: tell the page, when it has a subscription. */
    static void tokenChanged(final Context context, final String token) {
        new Handler(Looper.getMainLooper()).post(() -> {
            ShellBridge bridge = ShellBridge.live();
            if (bridge == null) {
                return;
            }
            PushKeys keys = PushKeys.load(context);
            if (keys == null) {
                return;
            }
            String text = keys.subscription(token);
            if (text != null) {
                bridge.subscriptionChanged(text);
            }
        });
    }
}
"#;

/// The push receiver keys, wrapped by a device-held key, and the opening of a
/// sealed push message.
const PUSH_KEYS_JAVA: &str = r#"package dev.ipe.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;

/**
 * The push receiver keys: a P-256 key pair and an authentication secret, kept wrapped
 * under a device keystore key. They open the sealed (aes128gcm) notification a push
 * message carries.
 */
final class PushKeys {
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String WRAP_ALIAS = Shell.PACKAGE + ".pushWrap";
    private static final String PREFS = Shell.PACKAGE + ".pushKeys";
    private static final String WRAPPED_PRIVATE = "wrappedPrivate";
    private static final String RECEIVER_PUBLIC = "receiverPublic";
    private static final String WRAPPED_SECRET = "wrappedSecret";
    private static final String CURVE = "secp256r1";
    private static final String EC = "EC";
    private static final String GCM = "AES/GCM/NoPadding";
    private static final String HMAC = "HmacSHA256";
    private static final String KEY_INFO = "WebPush: info";
    private static final String CEK_INFO = "Content-Encoding: aes128gcm";
    private static final String NONCE_INFO = "Content-Encoding: nonce";
    private static final int WRAP_KEY_BITS = 256;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int TAG_BYTES = TAG_BITS / 8;
    private static final int CEK_BYTES = 16;
    private static final int COORDINATE_BYTES = 32;
    private static final int POINT_BYTES = 1 + 2 * COORDINATE_BYTES;
    private static final int SECRET_BYTES = 16;
    private static final int SALT_BYTES = 16;
    private static final int HEADER_BYTES = SALT_BYTES + 4 + 1 + POINT_BYTES;
    private static final int MIN_RECORD = TAG_BYTES + 2;
    private static final byte UNCOMPRESSED = 0x04;
    private static final byte LAST_RECORD = 0x02;
    private static final int TOKEN_MAX_LEN = 4096;
    private static final int B64_FLAGS = Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING;
    private static final int KEY_TEXT_MAX = (POINT_BYTES * 4 + 2) / 3;

    private static ECParameterSpec curve;

    private final PrivateKey receiverPrivate;
    private final byte[] receiverPublic;
    private final byte[] secret;

    private PushKeys(PrivateKey receiverPrivate, byte[] receiverPublic, byte[] secret) {
        this.receiverPrivate = receiverPrivate;
        this.receiverPublic = receiverPublic;
        this.secret = secret;
    }

    /** Whether text is an unpadded base64url P-256 point on the curve. */
    static boolean isApplicationKey(String text) {
        if (text.isEmpty() || text.length() > KEY_TEXT_MAX) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9');
            if (!alnum && c != '-' && c != '_') {
                return false;
            }
        }
        byte[] raw = decode(text);
        return raw != null && decodePoint(raw) != null;
    }

    private static byte[] decode(String text) {
        try {
            return Base64.decode(text, B64_FLAGS);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String encode(byte[] raw) {
        return Base64.encodeToString(raw, B64_FLAGS);
    }

    private static synchronized ECParameterSpec curve() throws GeneralSecurityException {
        if (curve == null) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(EC);
            generator.initialize(new ECGenParameterSpec(CURVE));
            curve = ((ECPublicKey) generator.generateKeyPair().getPublic()).getParams();
        }
        return curve;
    }

    /** The public key an uncompressed point on the curve spells, or null. */
    static ECPublicKey decodePoint(byte[] raw) {
        try {
            if (raw.length != POINT_BYTES || raw[0] != UNCOMPRESSED) {
                return null;
            }
            ECParameterSpec params = curve();
            EllipticCurve shape = params.getCurve();
            if (!(shape.getField() instanceof ECFieldFp)) {
                return null;
            }
            BigInteger p = ((ECFieldFp) shape.getField()).getP();
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(raw, 1, 1 + COORDINATE_BYTES));
            BigInteger y = new BigInteger(1,
                    Arrays.copyOfRange(raw, 1 + COORDINATE_BYTES, POINT_BYTES));
            if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0) {
                return null;
            }
            BigInteger left = y.multiply(y).mod(p);
            BigInteger right = x.pow(3).add(shape.getA().multiply(x)).add(shape.getB()).mod(p);
            if (!left.equals(right)) {
                return null;
            }
            return (ECPublicKey) KeyFactory.getInstance(EC)
                    .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params));
        } catch (GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }

    /** The uncompressed point of key, or null. */
    private static byte[] point(ECPublicKey key) {
        byte[] x = fixed(key.getW().getAffineX());
        byte[] y = fixed(key.getW().getAffineY());
        if (x == null || y == null) {
            return null;
        }
        ByteBuffer out = ByteBuffer.allocate(POINT_BYTES);
        out.put(UNCOMPRESSED).put(x).put(y);
        return out.array();
    }

    /** value as exactly COORDINATE_BYTES big-endian bytes, or null when it does not fit. */
    private static byte[] fixed(BigInteger value) {
        byte[] raw = value.toByteArray();
        int start = 0;
        while (start < raw.length - 1 && raw[start] == 0) {
            start++;
        }
        int length = raw.length - start;
        if (value.signum() < 0 || length > COORDINATE_BYTES) {
            return null;
        }
        byte[] out = new byte[COORDINATE_BYTES];
        System.arraycopy(raw, start, out, COORDINATE_BYTES - length, length);
        return out;
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static KeyStore keystore() throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(KEYSTORE);
        store.load(null);
        return store;
    }

    /** The device keystore key the receiver keys are wrapped under; made when create. */
    private static SecretKey wrapKey(boolean create) throws GeneralSecurityException, IOException {
        Key existing = keystore().getKey(WRAP_ALIAS, null);
        if (existing instanceof SecretKey) {
            return (SecretKey) existing;
        }
        if (!create) {
            return null;
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(WRAP_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(WRAP_KEY_BITS)
                .build());
        return generator.generateKey();
    }

    private static String wrap(SecretKey key, byte[] plain) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(GCM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        if (iv == null || iv.length != IV_BYTES) {
            throw new GeneralSecurityException();
        }
        byte[] sealed = cipher.doFinal(plain);
        ByteBuffer out = ByteBuffer.allocate(1 + IV_BYTES + sealed.length);
        out.put((byte) IV_BYTES).put(iv).put(sealed);
        return encode(out.array());
    }

    private static byte[] unwrap(SecretKey key, String text) throws GeneralSecurityException {
        byte[] raw = decode(text);
        if (raw == null || raw.length < 1 + IV_BYTES + TAG_BYTES || raw[0] != IV_BYTES) {
            throw new GeneralSecurityException();
        }
        Cipher cipher = Cipher.getInstance(GCM);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, raw, 1, IV_BYTES));
        return cipher.doFinal(raw, 1 + IV_BYTES, raw.length - 1 - IV_BYTES);
    }

    /** The stored receiver keys, or null when none are stored or they do not open. */
    static synchronized PushKeys load(Context context) {
        SharedPreferences prefs = prefs(context);
        String wrappedPrivate = prefs.getString(WRAPPED_PRIVATE, null);
        String receiverPublic = prefs.getString(RECEIVER_PUBLIC, null);
        String wrappedSecret = prefs.getString(WRAPPED_SECRET, null);
        if (wrappedPrivate == null || receiverPublic == null || wrappedSecret == null) {
            return null;
        }
        try {
            SecretKey key = wrapKey(false);
            if (key == null) {
                return null;
            }
            PrivateKey receiverPrivate = KeyFactory.getInstance(EC)
                    .generatePrivate(new PKCS8EncodedKeySpec(unwrap(key, wrappedPrivate)));
            byte[] publicPoint = decode(receiverPublic);
            byte[] secret = unwrap(key, wrappedSecret);
            if (publicPoint == null || decodePoint(publicPoint) == null
                    || secret.length != SECRET_BYTES) {
                return null;
            }
            return new PushKeys(receiverPrivate, publicPoint, secret);
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            return null;
        }
    }

    /** The stored receiver keys, made and stored first when there are none. */
    static synchronized PushKeys loadOrCreate(Context context) {
        PushKeys existing = load(context);
        if (existing != null) {
            return existing;
        }
        try {
            SecretKey key = wrapKey(true);
            KeyPairGenerator generator = KeyPairGenerator.getInstance(EC);
            generator.initialize(new ECGenParameterSpec(CURVE));
            KeyPair pair = generator.generateKeyPair();
            byte[] publicPoint = point((ECPublicKey) pair.getPublic());
            if (publicPoint == null) {
                return null;
            }
            byte[] secret = new byte[SECRET_BYTES];
            new SecureRandom().nextBytes(secret);
            boolean saved = prefs(context).edit()
                    .putString(WRAPPED_PRIVATE, wrap(key, pair.getPrivate().getEncoded()))
                    .putString(RECEIVER_PUBLIC, encode(publicPoint))
                    .putString(WRAPPED_SECRET, wrap(key, secret))
                    .commit();
            return saved ? new PushKeys(pair.getPrivate(), publicPoint, secret) : null;
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            return null;
        }
    }

    /** Forget the receiver keys and the key they are wrapped under. */
    static synchronized void clear(Context context) {
        prefs(context).edit().clear().commit();
        try {
            keystore().deleteEntry(WRAP_ALIAS);
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            return;
        }
    }

    /** The canonical subscription text for token, or null for a token outside its grammar. */
    String subscription(String token) {
        if (token == null || token.isEmpty() || token.length() > TOKEN_MAX_LEN) {
            return null;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            boolean alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9');
            if (!alnum && c != '-' && c != '_' && c != ':') {
                return null;
            }
        }
        JSONObject text = ShellJson.object(Shell.FIELD_V, Shell.SUBSCRIPTION_VERSION,
                Shell.SUBSCRIPTION_KIND, Shell.SUBSCRIPTION_KIND_FCM,
                Shell.SUBSCRIPTION_TOKEN, token,
                Shell.SUBSCRIPTION_P256DH, encode(receiverPublic),
                Shell.SUBSCRIPTION_AUTH, encode(secret));
        return text == null ? null : text.toString();
    }

    private static byte[] hmac(byte[] key, byte[]... parts) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(key, HMAC));
        for (byte[] part : parts) {
            mac.update(part);
        }
        return mac.doFinal();
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    /** The plaintext of one sealed aes128gcm record addressed to these keys, or null. */
    byte[] open(byte[] body) {
        try {
            if (body.length < HEADER_BYTES) {
                return null;
            }
            ByteBuffer in = ByteBuffer.wrap(body);
            byte[] salt = new byte[SALT_BYTES];
            in.get(salt);
            int recordSize = in.getInt();
            int idLength = in.get() & 0xff;
            if (recordSize < MIN_RECORD || idLength != POINT_BYTES) {
                return null;
            }
            byte[] senderPoint = new byte[POINT_BYTES];
            in.get(senderPoint);
            byte[] sealed = new byte[in.remaining()];
            in.get(sealed);
            if (sealed.length > recordSize || sealed.length <= TAG_BYTES) {
                return null;
            }
            ECPublicKey sender = decodePoint(senderPoint);
            if (sender == null) {
                return null;
            }
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(receiverPrivate);
            agreement.doPhase(sender, true);
            byte[] shared = agreement.generateSecret();
            byte[] keyInfo = ByteBuffer.allocate(KEY_INFO.length() + 1 + 2 * POINT_BYTES)
                    .put(ascii(KEY_INFO)).put((byte) 0).put(receiverPublic).put(senderPoint)
                    .array();
            byte[] ikm = hmac(hmac(secret, shared), keyInfo, new byte[] {(byte) 1});
            byte[] prk = hmac(salt, ikm);
            byte[] cek = Arrays.copyOf(hmac(prk, ascii(CEK_INFO), new byte[] {0, 1}), CEK_BYTES);
            byte[] nonce = Arrays.copyOf(hmac(prk, ascii(NONCE_INFO), new byte[] {0, 1}), IV_BYTES);
            Cipher cipher = Cipher.getInstance(GCM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, KeyProperties.KEY_ALGORITHM_AES),
                    new GCMParameterSpec(TAG_BITS, nonce));
            byte[] plain = cipher.doFinal(sealed);
            int end = plain.length - 1;
            while (end >= 0 && plain[end] == 0) {
                end--;
            }
            if (end < 0 || plain[end] != LAST_RECORD) {
                return null;
            }
            return Arrays.copyOf(plain, end);
        } catch (GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }

    /**
     * The title, body and tag of the sealed notification data carries, or null when the
     * message is anything else: more fields, an unopenable record, text that is not
     * strict UTF-8, or fields outside the notification grammar.
     */
    String[] readSealed(Map<String, String> data) {
        if (data == null || data.size() != 1) {
            return null;
        }
        String sealed = data.get(Shell.SEALED_FIELD);
        if (sealed == null || sealed.length() > Shell.FCM_DATA_MAX_BYTES) {
            return null;
        }
        byte[] body = decode(sealed);
        byte[] plain = body == null ? null : open(body);
        if (plain == null) {
            return null;
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(plain))
                    .toString();
        } catch (CharacterCodingException e) {
            return null;
        }
        if (!ShellJson.nestsWithin(text, 1)) {
            return null;
        }
        JSONObject fields = ShellJson.parseObject(text);
        if (fields == null || fields.length() != 3) {
            return null;
        }
        Object title = fields.opt(Shell.SEALED_TITLE);
        Object message = fields.opt(Shell.SEALED_BODY);
        Object tag = fields.opt(Shell.SEALED_TAG);
        if (!(title instanceof String) || !(message instanceof String)
                || !(tag instanceof String)) {
            return null;
        }
        if (ShellNotifications.utf8((String) title) > Shell.NOTIFICATION_TITLE_MAX_BYTES
                || ShellNotifications.utf8((String) message) > Shell.NOTIFICATION_BODY_MAX_BYTES
                || !ShellNotifications.isTag((String) tag)) {
            return null;
        }
        return new String[] {(String) title, (String) message, (String) tag};
    }
}
"#;

/// The push service: a sealed message opens and posts; a new token tells the page.
const PUSH_SERVICE_JAVA: &str = r#"package dev.ipe.app;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

/** Receives push messages: a sealed notification opens with the receiver keys and posts. */
public final class PushService extends FirebaseMessagingService {
    @Override
    public void onMessageReceived(RemoteMessage message) {
        PushKeys keys = PushKeys.load(this);
        if (keys == null || !ShellNotifications.enabled(this)) {
            return;
        }
        String[] sealed = keys.readSealed(message.getData());
        if (sealed == null) {
            ShellNotifications.post(this, Shell.PUSH_PLACEHOLDER_TITLE, "", "");
            return;
        }
        ShellNotifications.post(this, sealed[0], sealed[1], sealed[2]);
    }

    @Override
    public void onNewToken(String token) {
        ShellPush.tokenChanged(getApplicationContext(), token);
    }
}
"#;

/// The application class that initializes Firebase from the manifest's public
/// client identifiers.
const IPE_APPLICATION_JAVA: &str = r#"package dev.ipe.app;

import android.app.Application;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;

/** Initializes Firebase from the manifest's public client identifiers. */
public final class IpeApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        if (FirebaseApp.getApps(this).isEmpty()) {
            FirebaseApp.initializeApp(this, new FirebaseOptions.Builder()
                    .setProjectId(Shell.FCM_PROJECT_ID)
                    .setApplicationId(Shell.FCM_APPLICATION_ID)
                    .setApiKey(Shell.FCM_API_KEY)
                    .setGcmSenderId(Shell.FCM_SENDER_ID)
                    .build());
        }
    }
}
"#;

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
         file:// access). Every request is answered one of three ways:\n\
         - a request to that local origin is served from the bundle, or answered by a\n\
         \x20 local 404;\n\
         - a request to an origin listed in delivery.servers goes to the network;\n\
         - any other request is answered by a local 403 carrying {header}: {value}.\n\
         The <uses-permission> lines in AndroidManifest.xml are derived from the app's\n\
         accepted web capabilities — never hand-authored — and each is asked only\n\
         when the page first uses the facility it backs.\n\
         \n\
         Notifications and push reach the page through one message channel on the\n\
         local origin only. A push server sends data-only messages whose sealed field\n\
         is encrypted to the subscription's receiver keys; the shell opens them on the\n\
         device and posts the notification itself.\n\
         \n\
         Not checked without a device: the permission prompts, the camera capture,\n\
         notification taps and push delivery. Check them on a device before release.\n\
         \n\
         Signing: this Gradle project is unsigned.\n\
         - ./gradlew assembleDebug (requires the Android SDK; API 34) builds an APK\n\
         \x20 signed with the SDK's debug key, for local install only.\n\
         - A store build needs your own keystore: add a signingConfig for it to\n\
         \x20 app/build.gradle, then run ./gradlew assembleRelease.\n",
        entry = android_entry_url(base),
        header = BLOCKED_HEADER.0,
        value = BLOCKED_HEADER.1,
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
            &shell_pin(&accepts(&[]), &MountBase::root()),
            &spa,
            None,
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
            &shell_pin(&a, &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&accepts(&[]), &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&accepts(&[]), &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&a, &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&accepts(&[]), &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&a, &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&accepts(&[]), &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&accepts(&[]), &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&accepts(&[]), &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&a, &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&a, &MountBase::root()),
            &bundle(),
            None,
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
            &shell_pin(&accepts(&[]), &MountBase::root()),
            &bundle(),
            None,
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
                &shell_pin(&accepts(&[]), &MountBase::root()),
                &bundle(),
                Some(&icon),
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
                &shell_pin(&accepts(&[]), &MountBase::root()),
                &bundle(),
                None,
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
            &shell_pin(&accepts(&[]), base),
            &bundle(),
            None,
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
                activity.contains("if (Shell.LOCAL_ORIGIN.equals(origin)) {"),
                "only the local origin is answered from the bundle: {activity}"
            );
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

    /// A pin over `base` and `servers`, with no push identifiers.
    fn pin(base: &str, servers: &[&str]) -> ManifestPin {
        ManifestPin {
            base: MountBase::parse(base).expect("a legal mount base"),
            servers: ServerOrigins::new(servers.iter().map(|raw| {
                ipe_runtime_rust::encoding::ServerOrigin::parse(raw).expect("a legal origin")
            }))
            .expect("a legal origin set"),
            push: None,
            accepts: BTreeSet::new(),
        }
    }

    #[test]
    fn manifest_changed_names_every_moved_field_and_the_remedy() {
        let before = pin("/", &[]);
        let after = pin("/app", &["https://api.example"]);
        let moved = before.moved_to(&after).expect("two fields moved");
        assert_eq!(
            moved.fields(),
            [PinnedField::BasePath, PinnedField::Servers]
        );
        let shown = MobileRefusal::ManifestChanged { moved }.to_string();
        assert!(
            shown
                .contains("`delivery.browser.basePath`, `delivery.servers` changed in package.ipe"),
            "{shown}"
        );
        assert!(!shown.contains("delivery.mobile.push"), "{shown}");
        assert!(shown.contains("run it again"), "{shown}");
        assert_eq!(before.moved_to(&before), None, "an equal pin moved nothing");
        let granted = ManifestPin {
            accepts: accepts(&[web(WebCapability::Geolocation)]),
            ..pin("/", &[])
        };
        assert_eq!(
            before.moved_to(&granted),
            Some(MovedFields(vec![PinnedField::Accepts])),
            "an accept granted during the build moves the accepts"
        );
    }

    // ── Android shell: request rule, bridge, permissions, push ────────────────

    /// A pin over `base` that accepts `accepts`, with no servers and no push.
    fn shell_pin(accepts: &BTreeSet<Capability>, base: &MountBase) -> ManifestPin {
        ManifestPin {
            base: base.clone(),
            servers: ServerOrigins::none(),
            push: None,
            accepts: accepts.clone(),
        }
    }

    /// Push identifiers in the manifest grammar.
    fn push_delivery() -> PushDelivery {
        use crate::project::{
            ApnsEnvironment, FcmApiKey, FcmApplicationId, FcmIdentifiers, FcmProjectId, FcmSenderId,
        };
        PushDelivery {
            apns: ApnsEnvironment::Production,
            fcm: FcmIdentifiers {
                project_id: FcmProjectId::parse("demo-project").expect("an FCM id"),
                application_id: FcmApplicationId::parse("1:123:android:abc").expect("an FCM id"),
                api_key: FcmApiKey::parse("AIzaDemoKey").expect("an FCM id"),
                sender_id: FcmSenderId::parse("123").expect("an FCM id"),
            },
        }
    }

    /// Every axis the Android shell serves something for, two servers and push.
    fn full_pin() -> ManifestPin {
        ManifestPin {
            push: Some(push_delivery()),
            accepts: accepts(&[
                web(WebCapability::Notification),
                web(WebCapability::Push),
                web(WebCapability::Geolocation),
                web(WebCapability::Camera),
                web(WebCapability::Recorder),
                web(WebCapability::File),
                web(WebCapability::Microphone),
            ]),
            ..pin(
                "/app",
                &["https://push.example:8443", "https://api.example"],
            )
        }
    }

    /// The Android layout laid out from `pin`.
    fn android(pin: &ManifestPin) -> ShellLayout {
        layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            pin,
            &bundle(),
            None,
        )
        .expect("android layout")
    }

    /// The generated text of `rel_path` in `shell`, or the empty string.
    fn text_of<'a>(shell: &'a ShellLayout, rel_path: &str) -> &'a str {
        shell.generated(rel_path).unwrap_or_default()
    }

    /// The generated Java sources of `shell`, by path.
    fn java_sources(shell: &ShellLayout) -> Vec<(&str, &str)> {
        shell
            .files
            .iter()
            .filter_map(|file| match &file.content {
                ShellContent::Generated(text) if file.rel_path.starts_with(ANDROID_JAVA_DIR) => {
                    Some((file.rel_path.as_str(), text.as_str()))
                }
                ShellContent::Generated(_) | ShellContent::Asset(_) | ShellContent::Icon => None,
            })
            .collect()
    }

    /// The path of the Java source `name`.
    fn java_path(name: &str) -> String {
        format!("{ANDROID_JAVA_DIR}{name}")
    }

    /// The constants `Shell.java` declares, as name and value text.
    fn shell_constants(shell: &ShellLayout) -> Vec<(String, String)> {
        text_of(shell, &java_path("Shell.java"))
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("static final ")?;
                let (_, declaration) = rest.split_once(' ')?;
                let (name, value) = declaration.split_once(" = ")?;
                Some((name.to_owned(), value.strip_suffix(';')?.to_owned()))
            })
            .collect()
    }

    /// The value text of the `Shell.java` constant `name`.
    fn constant(shell: &ShellLayout, name: &str) -> Option<String> {
        shell_constants(shell)
            .into_iter()
            .find_map(|(declared, value)| (declared == name).then_some(value))
    }

    /// The `Shell.java` string constant `name` as the Java literal of `value`.
    fn quoted(value: &str) -> String {
        JavaStringLiteral::of(value).to_string()
    }

    /// `inner` between braces: a Java array initializer.
    fn braces(inner: &str) -> String {
        let mut text = String::from('{');
        text.push_str(inner);
        text.push('}');
        text
    }

    /// The bridge wire word the Java constant `name` holds.
    fn word(name: &str) -> &'static str {
        BRIDGE_WORDS
            .iter()
            .chain(PUSH_WORDS)
            .find_map(|(declared, value)| (*declared == name).then_some(*value))
            .unwrap_or_default()
    }

    #[test]
    fn android_allowed_origins_are_exactly_the_servers() {
        let full = android(&full_pin());
        assert_eq!(
            constant(&full, "ALLOWED_ORIGINS"),
            Some(braces(
                "\"https://api.example\", \"https://push.example:8443\""
            ))
        );
        let manifest = text_of(&full, "app/src/main/AndroidManifest.xml");
        assert!(
            manifest.contains("android.permission.INTERNET"),
            "{manifest}"
        );
        let none = android(&pin("/", &[]));
        assert_eq!(constant(&none, "ALLOWED_ORIGINS"), Some(braces("")));
        let manifest = text_of(&none, "app/src/main/AndroidManifest.xml");
        assert!(
            !manifest.contains("android.permission.INTERNET"),
            "no server, no network permission: {manifest}"
        );
        for shell in [&full, &none] {
            let all = shell_constants(shell);
            assert!(
                all.iter()
                    .all(|(_, value)| !value.contains("http://") && !value.contains('*')),
                "no cleartext or wildcard origin: {all:?}"
            );
        }
    }

    #[test]
    fn android_request_rule_is_local_then_servers_then_403() {
        let shell = android(&full_pin());
        let activity = text_of(&shell, &java_path("MainActivity.java"));
        for needle in [
            "if (Shell.LOCAL_ORIGIN.equals(origin)) {",
            "return mapped != null ? mapped : localNotFound();",
            "return isAllowed(origin) ? null : blocked();",
            "403, \"Forbidden\"",
            "Collections.singletonMap(Shell.BLOCKED_HEADER, Shell.BLOCKED_ORIGIN)",
            "!\"https\".equals(url.getScheme())",
        ] {
            assert!(activity.contains(needle), "{needle}: {activity}");
        }
        assert_eq!(
            constant(&shell, "BLOCKED_HEADER"),
            Some(quoted(BLOCKED_HEADER.0))
        );
        assert_eq!(
            constant(&shell, "BLOCKED_ORIGIN"),
            Some(quoted(BLOCKED_HEADER.1))
        );
        assert_eq!(
            constant(&shell, "LOCAL_ORIGIN"),
            Some(quoted(ANDROID_ASSET_ORIGIN))
        );
    }

    #[test]
    fn android_bridge_listens_on_the_local_origin_main_frame_only() {
        for pin in [full_pin(), pin("/", &[])] {
            let shell = android(&pin);
            let bridge = text_of(&shell, &java_path("ShellBridge.java"));
            let listener = "Collections.singleton(Shell.LOCAL_ORIGIN), bridge::onMessage)";
            assert_eq!(bridge.matches(listener).count(), 1, "{bridge}");
            assert_eq!(
                bridge.matches("addWebMessageListener(").count(),
                1,
                "{bridge}"
            );
            let frame = bridge.find("if (!isMainFrame)");
            let origin = bridge.find("MainActivity.originOf(sourceOrigin)");
            let data = bridge.find("message.getData()");
            assert!(
                frame.is_some() && frame < origin && origin < data,
                "the frame and the origin are checked before the data is read: {bridge}"
            );
            for (_, source) in java_sources(&shell) {
                assert!(!source.contains("addJavascriptInterface"), "{source}");
                assert!(!source.contains("evaluateJavascript"), "{source}");
            }
        }
    }

    #[test]
    fn android_hostile_name_stays_inside_its_literals() {
        let hostile = super::super::desktop::BundleIdentity::new(
            "Evil\"); x(); // \\u0022 <a href=\"&\">",
            Some("1.0.0"),
            None,
        );
        let pin = pin("/", &[]);
        let shell = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &hostile,
            &pin,
            &bundle(),
            None,
        )
        .expect("android layout");
        assert_eq!(
            constant(&shell, "APP_LABEL"),
            Some(quoted(&hostile.name)),
            "the label reaches Java only as its literal"
        );
        let manifest = text_of(&shell, "app/src/main/AndroidManifest.xml");
        assert!(
            manifest.contains(&format!(
                "android:label=\"{}\"",
                xml_attr_escape(&hostile.name)
            )),
            "{manifest}"
        );
        assert!(!manifest.contains("href=\"&\""), "{manifest}");
    }

    #[test]
    fn android_runtime_constants_come_from_the_runtime() {
        let shell = android(&full_pin());
        let numbers = [
            (
                "BRIDGE_PROTOCOL_VERSION",
                native_bridge::BRIDGE_PROTOCOL_VERSION.to_string(),
            ),
            (
                "BRIDGE_MAX_REQUEST_BYTES",
                native_bridge::BRIDGE_MAX_REQUEST_BYTES.to_string(),
            ),
            (
                "BRIDGE_MAX_REPLY_BYTES",
                native_bridge::BRIDGE_MAX_REPLY_BYTES.to_string(),
            ),
            (
                "BRIDGE_MAX_OUTSTANDING",
                native_bridge::BRIDGE_MAX_OUTSTANDING.to_string(),
            ),
            (
                "BRIDGE_NOTIFY_BURST",
                native_bridge::BRIDGE_NOTIFY_BURST.to_string(),
            ),
            (
                "BRIDGE_NOTIFY_WINDOW_MS",
                format!("{}L", native_bridge::BRIDGE_NOTIFY_WINDOW_MS),
            ),
            (
                "NOTIFICATION_TITLE_MAX_BYTES",
                native_bridge::NOTIFICATION_TITLE_MAX_BYTES.to_string(),
            ),
            (
                "NOTIFICATION_BODY_MAX_BYTES",
                native_bridge::NOTIFICATION_BODY_MAX_BYTES.to_string(),
            ),
            (
                "NOTIFICATION_TAG_MAX_BYTES",
                native_bridge::NOTIFICATION_TAG_MAX_BYTES.to_string(),
            ),
        ];
        for (name, value) in numbers {
            assert_eq!(constant(&shell, name), Some(value), "{name}");
        }
        assert_eq!(
            constant(&shell, "BRIDGE_CHANNEL_NAME"),
            Some(quoted(native_bridge::BRIDGE_CHANNEL_NAME))
        );
        assert_eq!(
            constant(&shell, native_bridge::HANDSHAKE_CAP_GLUE_NAME),
            Some(quoted(native_bridge::HANDSHAKE_CAP_NAME))
        );
        for op in native_bridge::BridgeOp::ALL {
            assert_eq!(constant(&shell, op.glue_name()), Some(quoted(op.op_name())));
        }
        for reject in native_bridge::Reject::ALL {
            assert_eq!(
                constant(&shell, reject.glue_name()),
                Some(quoted(reject.as_str()))
            );
        }
        let all = shell_constants(&shell);
        let mut names: Vec<&str> = all.iter().map(|(name, _)| name.as_str()).collect();
        let declared = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), declared, "each constant is declared once");
        for (path, source) in java_sources(&shell) {
            if path.ends_with("/Shell.java") {
                continue;
            }
            for (_, value) in BRIDGE_WORDS.iter().chain(PUSH_WORDS) {
                assert!(
                    !source.contains(&quoted(value)),
                    "the wire word {value} is spelled only in Shell.java: {path}"
                );
            }
            assert!(
                !source.contains(&quoted(native_bridge::BRIDGE_CHANNEL_NAME)),
                "{path}"
            );
        }
    }

    #[test]
    fn android_every_shell_reference_is_declared() {
        for pin in [full_pin(), pin("/", &[])] {
            let shell = android(&pin);
            let all = shell_constants(&shell);
            for (path, source) in java_sources(&shell) {
                assert!(!source.contains("@@"), "every slot is filled: {path}");
                for (at, _) in source.match_indices("Shell.") {
                    let before = source.get(..at).and_then(|head| head.chars().next_back());
                    if before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
                        continue;
                    }
                    let name: String = source
                        .get(at + "Shell.".len()..)
                        .unwrap_or_default()
                        .chars()
                        .take_while(|ch| {
                            ch.is_ascii_uppercase() || ch.is_ascii_digit() || *ch == '_'
                        })
                        .collect();
                    if name.is_empty() {
                        continue;
                    }
                    assert!(
                        all.iter().any(|(declared, _)| *declared == name),
                        "{path} reads Shell.{name}, which Shell.java does not declare"
                    );
                }
            }
            for file in &shell.files {
                if let ShellContent::Generated(text) = &file.content {
                    assert!(!text.contains("@@"), "{}", file.rel_path);
                }
            }
        }
    }

    #[test]
    fn android_wire_words_agree_with_the_runtime_codec() {
        let show = native_bridge::BridgeRequest::new(
            native_bridge::RequestId::new("a1").expect("an id"),
            native_bridge::BridgeCall::NotificationShow {
                title: "t".to_owned(),
                body: "b".to_owned(),
                tag: "g".to_owned(),
            },
        )
        .expect("a request")
        .encode()
        .expect("encoded");
        let value: serde_json::Value = serde_json::from_str(&show).expect("json");
        let envelope = value.as_object().expect("an object");
        let mut keys: Vec<&str> = envelope.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = vec![
            word("FIELD_V"),
            word("FIELD_ID"),
            word("FIELD_CAP"),
            word("FIELD_OP"),
            word("FIELD_ARGS"),
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);
        let args = envelope
            .get(word("FIELD_ARGS"))
            .and_then(serde_json::Value::as_object)
            .expect("args");
        for field in ["FIELD_TITLE", "FIELD_BODY", "FIELD_TAG"] {
            assert!(args.contains_key(word(field)), "{field}");
        }
        let subscribe = native_bridge::BridgeRequest::new(
            native_bridge::RequestId::new("b2").expect("an id"),
            native_bridge::BridgeCall::PushSubscribe {
                application_key: "k".to_owned(),
            },
        )
        .expect("a request")
        .encode()
        .expect("encoded");
        assert!(
            subscribe.contains(&format!("\"{}\"", word("FIELD_APPLICATION_KEY"))),
            "{subscribe}"
        );

        let id = native_bridge::RequestId::new("c3").expect("an id");
        let reply = serde_json::json!({
            (word("FIELD_V")): native_bridge::BRIDGE_PROTOCOL_VERSION,
            (word("FIELD_ID")): "c3",
            (word("FIELD_OK")): { (word("FIELD_STATE")): native_bridge::PermissionState::Granted.as_str() },
        })
        .to_string();
        let parsed =
            native_bridge::parse_reply(&reply, std::slice::from_ref(&id)).expect("a reply");
        assert_eq!(
            native_bridge::notification_frame(
                native_bridge::BridgeOp::NotificationPermission,
                &parsed
            ),
            Some(native_bridge::NotificationFrame::Granted)
        );
        let refused = serde_json::json!({
            (word("FIELD_V")): native_bridge::BRIDGE_PROTOCOL_VERSION,
            (word("FIELD_ID")): "c3",
            (word("FIELD_REJECT")): native_bridge::Reject::Denied.as_str(),
        })
        .to_string();
        assert!(native_bridge::parse_reply(&refused, std::slice::from_ref(&id)).is_ok());
    }

    #[test]
    fn android_request_id_ceiling_matches_the_runtime() {
        let longest = "f".repeat(REQUEST_ID_MAX_LEN);
        assert!(native_bridge::RequestId::new(&longest).is_ok());
        let past = "f".repeat(REQUEST_ID_MAX_LEN + 1);
        assert!(native_bridge::RequestId::new(&past).is_err());
    }

    #[test]
    fn android_wire_caps_agree_with_the_kernel_caps() {
        assert_eq!(
            ipe_kernels::BridgeCap::ALL.len(),
            native_bridge::BridgeCap::ALL.len()
        );
        for cap in ipe_kernels::BridgeCap::ALL {
            assert_eq!(wire_cap(*cap).as_str(), cap.as_str());
        }
    }

    #[test]
    fn android_accepted_caps_are_the_accepted_bridge_axes() {
        let cases = [
            (accepts(&[]), braces("")),
            (
                accepts(&[web(WebCapability::Notification)]),
                braces("CAP_NOTIFICATION"),
            ),
        ];
        for (accepted, rendered) in cases {
            let shell = android(&shell_pin(&accepted, &MountBase::root()));
            assert_eq!(constant(&shell, "ACCEPTED_CAPS"), Some(rendered));
        }
        assert_eq!(
            constant(&android(&full_pin()), "ACCEPTED_CAPS"),
            Some(braces("CAP_NOTIFICATION, CAP_PUSH"))
        );
    }

    #[test]
    fn android_push_without_identifiers_is_refused() {
        let accepted = accepts(&[web(WebCapability::Push)]);
        let refused = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &shell_pin(&accepted, &MountBase::root()),
            &bundle(),
            None,
        );
        assert!(matches!(refused, Err(CliError::Usage(_))), "{refused:?}");
    }

    #[test]
    fn android_push_files_ship_only_with_push() {
        let push_only = [
            "ShellPush.java",
            "PushKeys.java",
            "PushService.java",
            "IpeApplication.java",
        ];
        let full = android(&full_pin());
        let plain = android(&shell_pin(
            &accepts(&[web(WebCapability::Notification)]),
            &MountBase::root(),
        ));
        for name in push_only {
            assert!(full.generated(&java_path(name)).is_some(), "{name}");
            assert!(plain.generated(&java_path(name)).is_none(), "{name}");
        }
        let gradle = text_of(&full, "app/build.gradle");
        assert!(gradle.contains("firebase-messaging"), "{gradle}");
        assert!(!text_of(&plain, "app/build.gradle").contains("firebase"));
        let manifest = text_of(&full, "app/src/main/AndroidManifest.xml");
        for needle in [
            "android:name=\"dev.ipe.app.IpeApplication\"",
            "android:name=\"dev.ipe.app.PushService\"",
            "android:exported=\"false\">",
            "com.google.firebase.MESSAGING_EVENT",
            "firebase_messaging_auto_init_enabled",
        ] {
            assert!(manifest.contains(needle), "{needle}: {manifest}");
        }
        let plain_manifest = text_of(&plain, "app/src/main/AndroidManifest.xml");
        assert!(!plain_manifest.contains("firebase"), "{plain_manifest}");
        assert!(
            !plain_manifest.contains("IpeApplication"),
            "{plain_manifest}"
        );
        assert!(
            text_of(&full, &java_path("ShellBridge.java"))
                .contains("ShellPush.handle(activity, (String) op, arguments, reply);")
        );
        assert!(
            !text_of(&plain, &java_path("ShellBridge.java")).contains("ShellPush"),
            "a shell without push never names the push class"
        );
        assert!(constant(&plain, "FCM_API_KEY").is_none());
        assert_eq!(constant(&full, "FCM_API_KEY"), Some(quoted("AIzaDemoKey")));
    }

    #[test]
    fn android_capture_provider_ships_only_with_camera() {
        let camera = android(&shell_pin(
            &accepts(&[web(WebCapability::Camera)]),
            &MountBase::root(),
        ));
        let manifest = text_of(&camera, "app/src/main/AndroidManifest.xml");
        assert!(
            manifest.contains("androidx.core.content.FileProvider"),
            "{manifest}"
        );
        assert!(
            manifest.contains("android:exported=\"false\""),
            "{manifest}"
        );
        assert!(manifest.contains(".capture\""), "{manifest}");
        assert_eq!(
            camera.generated(ANDROID_CAPTURE_PATHS),
            Some(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<paths>\n    \
                 <cache-path name=\"capture\" path=\"capture/\" />\n</paths>\n"
            )
        );
        assert_eq!(constant(&camera, "CAPTURE").as_deref(), Some("true"));
        let file = android(&shell_pin(
            &accepts(&[web(WebCapability::File)]),
            &MountBase::root(),
        ));
        assert!(file.generated(ANDROID_CAPTURE_PATHS).is_none());
        assert!(!text_of(&file, "app/src/main/AndroidManifest.xml").contains("FileProvider"));
        assert_eq!(constant(&file, "CAPTURE").as_deref(), Some("false"));
        assert_eq!(constant(&file, "FILE_CHOOSER").as_deref(), Some("true"));
    }

    #[test]
    fn android_permissions_are_asked_only_at_the_moment_of_use() {
        let shell = android(&full_pin());
        let activity = text_of(&shell, &java_path("MainActivity.java"));
        let asks: usize = java_sources(&shell)
            .iter()
            .map(|(_, source)| source.matches("requestPermissions(").count())
            .sum();
        assert_eq!(asks, 1, "one request site, inside PermissionGroup.ask");
        let on_create = activity
            .split_once("protected void onCreate(")
            .map_or("", |(_, rest)| {
                rest.split_once("\n    }\n").map_or(rest, |(body, _)| body)
            });
        let (setup, callbacks) = on_create
            .split_once("webView.setWebChromeClient(")
            .unwrap_or_default();
        let launch = callbacks
            .split_once("bridge = ShellBridge.install(")
            .map_or("", |(_, rest)| rest);
        assert!(!launch.is_empty(), "{on_create}");
        for straight in [setup, launch] {
            assert!(
                !straight.contains(".ask(") && !straight.contains("requestPermissions"),
                "nothing is asked at launch: {straight}"
            );
        }
        for group in RequestGroup::ALL {
            assert_ne!(CHOOSER_REQUEST, group.code().get());
        }
    }

    #[test]
    fn android_groups_are_declared_only_when_the_manifest_declares_them() {
        let shell = android(&shell_pin(
            &accepts(&[web(WebCapability::Microphone)]),
            &MountBase::root(),
        ));
        let activity = text_of(&shell, &java_path("MainActivity.java"));
        assert!(
            activity.contains(&format!(
                "final PermissionGroup recordAudioGroup = new PermissionGroup(\n            \
                 new String[] {{Manifest.permission.RECORD_AUDIO}}, {}, 0, true);",
                RequestGroup::RecordAudio.code().get()
            )),
            "{activity}"
        );
        assert!(
            activity.contains(&format!(
                "final PermissionGroup cameraGroup = new PermissionGroup(\n            \
                 new String[] {{Manifest.permission.CAMERA}}, {}, 0, false);",
                RequestGroup::Camera.code().get()
            )),
            "{activity}"
        );
        assert!(
            activity.contains(
                "new PermissionGroup[] {locationGroup, notificationsGroup, recordAudioGroup, cameraGroup}"
            ),
            "{activity}"
        );
    }

    #[test]
    fn android_facilities_follow_the_accepted_axes() {
        for axis in WebCapability::ALL {
            let pin = shell_pin(&accepts(&[web(*axis)]), &MountBase::root());
            let Ok(plan) = AndroidPlan::of(&identity(), &pin) else {
                continue;
            };
            for facility in ChromeFacility::ALL {
                let served = chrome_facilities(*axis).contains(facility);
                assert_eq!(plan.serves(*facility), served, "{axis:?} {facility:?}");
            }
            let declared =
                |group: RequestGroup| plan.groups.contains(&RuntimeRequestGroup::of(group));
            if plan.serves(ChromeFacility::AudioCapture) {
                assert!(declared(RequestGroup::RecordAudio), "{axis:?}");
            }
            if plan.serves(ChromeFacility::VideoCapture) {
                assert!(declared(RequestGroup::Camera), "{axis:?}");
            }
            if plan.serves(ChromeFacility::Geolocation) {
                assert!(declared(RequestGroup::Location), "{axis:?}");
            }
        }
        let none = android(&pin("/", &[]));
        for facility in ChromeFacility::ALL {
            assert_eq!(
                constant(&none, facility.java_name()).as_deref(),
                Some("false")
            );
        }
    }

    #[test]
    fn fill_copies_values_without_rescanning_them() {
        assert_eq!(fill("@@A@@@@B@@", &[("A", "@@B@@"), ("B", "x")]), "@@B@@x");
        assert_eq!(fill("a @@C@@ b", &[("A", "x")]), "a @@C@@ b");
        assert_eq!(fill("a @@open", &[("open", "x")]), "a @@open");
    }

    #[test]
    fn pin_accessors_return_the_pinned_fields() {
        let full = full_pin();
        assert_eq!(full.servers().len(), 2);
        assert_eq!(full.push(), Some(&push_delivery()));
        assert!(pin("/", &[]).push().is_none());
        assert!(pin("/", &[]).servers().is_empty());
    }
}
