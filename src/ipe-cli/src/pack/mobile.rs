//! Mobile packaging: wrapping a built client-wasm Web SPA in a thin native
//! system-webview shell for iOS or Android.
//!
//! The `web client` build produces a self-contained offline SPA bundle
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
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use ipe_fs_open::{ByteCap, EntryCap, EntryName, FileId, FileKind, HeldDir, OpenRefusal};
use ipe_ir::{Capability, WebCapability};
use ipe_runtime_rust::csp::{
    self, BundleHost, BundleReach, BundleWorker, ContentSecurityPolicy, ReachRefusal,
};
use ipe_runtime_rust::encoding::{MountBase, ServerOrigin};
use ipe_runtime_rust::js_port_glue::native_bridge;

use crate::CliError;
use crate::driver::BundleProfile;
use crate::output_dir::OwnedDir;
use crate::project::{BundleId, MobileDelivery, ProjectManifest, PushDelivery, ScreenOrientation};
use crate::text;

use super::permissions::{self, ApiLevel, Platform, RequestGroup, RuntimeRequestGroup};

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
    /// The lowercase wire name of this OS — the `web client <os>` delivery host word
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

/// Resolve the mobile OS a `web client <os>` delivery host names.
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
/// A mobile shell hosts the client-wasm SPA, which the `web client` delivery
/// builds for any `Web` app: the client derives the wasm target itself, and the
/// manifest's `wasm` field only tunes that bundle. The one fact the gate reads is
/// whether the app is a `Web` app.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WebSpaCapability {
    /// Whether the app's declared shape is `Web` (or unset — inference decides).
    /// A `Terminal` / `WebView` / `Program` shape has no client-wasm SPA to host.
    pub shape_is_web: bool,
}

/// Gate an app for mobile packaging: it must be a `Web` app, the one shape a
/// `web client` build turns into a hostable SPA.
///
/// A non-`Web` app is a fail-closed, typed refusal — never a bundle produced
/// around an empty or non-existent SPA.
///
/// # Errors
/// [`MobileRefusal::NotWebShape`] when the declared shape is not `Web`.
pub const fn require_web_spa(cap: WebSpaCapability) -> Result<(), MobileRefusal> {
    if cap.shape_is_web {
        Ok(())
    } else {
        Err(MobileRefusal::NotWebShape)
    }
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
    /// `delivery.servers` names the Android shell's local asset host, so the
    /// local origin and that server would be one origin to the shell.
    AssetOriginListed {
        /// The refused server origin.
        origin: ServerOrigin,
    },
}

impl From<ReachRefusal> for MobileRefusal {
    fn from(refusal: ReachRefusal) -> Self {
        match refusal {
            ReachRefusal::LocalOriginListed { origin } => Self::AssetOriginListed { origin },
        }
    }
}

impl std::fmt::Display for MobileRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingOs => write!(
                f,
                "error[IPE-P0020]: a mobile bundle needs an OS — \
                 name one: `ipe dev build web client <ios|android>`"
            ),
            Self::UnknownOs(got) => write!(
                f,
                "error[IPE-P0021]: unknown mobile OS {got:?} \
                 (expected `ipe dev build web client <ios|android>`)"
            ),
            Self::NotWebShape => write!(
                f,
                "error[IPE-P0022]: `web client <ios|android>` wraps a client-wasm `Web` SPA, \
                 but this app's shape is not `Web`\n  \
                 = a mobile bundle hosts the app's browser SPA in a system webview; only a \
                 `Web` app compiled to wasm has such a bundle. Declare a `Web` program shape, \
                 or choose the matching host for this app."
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
            Self::AssetOriginListed { origin } => {
                f.write_str(&text::mobile_asset_origin_listed(&origin.https()))
            }
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
    /// `delivery.servers`: the origins the bundle may reach besides its own,
    /// read only as a [`BundleReach`].
    servers: PinnedServers,
    /// `delivery.mobile.push`: the identifiers the shell registers for push
    /// with; its `Debug` never prints an identifier.
    push: Option<PushDelivery>,
    /// `capabilities.accepts`: the capabilities the bundle's consent gate
    /// grants and the shell's OS permissions are derived from.
    accepts: BTreeSet<Capability>,
}

/// The identity a mobile shell is laid out under: its bundle identity and its
/// launch orientation, read once from `delivery.mobile`.
///
/// [`layout`] takes only this, and [`ShellIdentity::of`] is its one production
/// constructor, so a declared `bundleId` or `orientation` cannot be dropped on
/// the way to a shell.
#[derive(Clone, Debug)]
pub struct ShellIdentity {
    /// The name, version, and bundle identifier every shell file reads.
    identity: super::desktop::BundleIdentity,
    /// The launch orientation the shell enforces.
    orientation: ScreenOrientation,
}

impl ShellIdentity {
    /// The shell identity of the parsed manifest `manifest`.
    ///
    /// An absent `bundleId` is [`BundleId::derived`] from the manifest name.
    #[must_use]
    pub fn of(manifest: &ProjectManifest) -> Self {
        // `push` is read by `ManifestPin::of`: the shell and the bundle must
        // agree on it.
        let MobileDelivery {
            bundle_id,
            orientation,
            push: _,
        } = &manifest.delivery.mobile;
        let identifier = bundle_id
            .clone()
            .unwrap_or_else(|| BundleId::derived(&manifest.name));
        let version = manifest.version.as_ref().map(ToString::to_string);
        Self {
            identity: super::desktop::BundleIdentity::new(
                &manifest.name,
                version.as_deref(),
                identifier,
            ),
            orientation: *orientation,
        }
    }

    /// A shell identity built from its parts, for layout unit tests.
    #[cfg(test)]
    #[must_use]
    pub const fn for_test(
        identity: super::desktop::BundleIdentity,
        orientation: ScreenOrientation,
    ) -> Self {
        Self {
            identity,
            orientation,
        }
    }
}

impl ManifestPin {
    /// The pin of the parsed manifest `manifest`.
    #[must_use]
    pub fn of(manifest: &ProjectManifest) -> Self {
        Self {
            base: manifest.delivery.browser.base.clone(),
            servers: PinnedServers::new(manifest.delivery.servers.clone()),
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

    /// What a bundle on `host` laid out from this pin may reach: the one input
    /// to every confinement list a shell renders.
    ///
    /// # Errors
    /// [`MobileRefusal::AssetOriginListed`] when `host` is
    /// [`BundleHost::AndroidAssets`] and `delivery.servers` names its asset host.
    pub fn reach(&self, host: BundleHost) -> Result<BundleReach<'_>, MobileRefusal> {
        Ok(self.servers.reach(host)?)
    }

    /// The bundle policies the wasm build may have rendered for this pin.
    ///
    /// The build's worker follows the capabilities the program reaches, which
    /// the consent gate holds within the accepted ones, so a push worker is
    /// admitted only when push is accepted. The pack never sees the reached
    /// set, so an accepted push the program does not reach still admits the
    /// worker-free page; the Android header then carries `worker-src 'self'`
    /// where that page falls back to `script-src 'self'`, which admits the
    /// same scripts, and `connect-src` is identical for both workers.
    fn served_policies(&self) -> Vec<(BundleWorker, String)> {
        let reach = self.servers.served();
        let push = self
            .accepts
            .contains(&Capability::JsPort(WebCapability::Push));
        [BundleWorker::None, BundleWorker::Push]
            .into_iter()
            .filter(|worker| push || *worker == BundleWorker::None)
            .map(|worker| {
                let meta = ContentSecurityPolicy::for_bundle(&reach, worker).meta_element();
                (worker, meta)
            })
            .collect()
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

mod pinned_servers {
    use ipe_runtime_rust::csp::{BundleHost, BundleReach, ReachRefusal};
    use ipe_runtime_rust::encoding::ServerOrigins;

    /// A pin's `delivery.servers`, readable only as a [`BundleReach`].
    ///
    /// Its origins are private to this module, so every confinement list a
    /// shell renders is derived from one reach, never from the origins read
    /// again beside it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PinnedServers(ServerOrigins);

    impl PinnedServers {
        /// Pin `origins`.
        #[must_use]
        pub const fn new(origins: ServerOrigins) -> Self {
            Self(origins)
        }

        /// What a bundle on `host` may reach.
        ///
        /// # Errors
        /// The refusal of a server `host` answers locally.
        pub fn reach(&self, host: BundleHost) -> Result<BundleReach<'_>, ReachRefusal> {
            BundleReach::new(host, &self.0)
        }

        /// What the bundle a web server serves may reach.
        #[must_use]
        pub const fn served(&self) -> BundleReach<'_> {
            BundleReach::served(&self.0)
        }

        /// The pinned origins, for a test to render what the wasm build renders.
        #[cfg(test)]
        #[must_use]
        pub const fn origins(&self) -> &ServerOrigins {
            &self.0
        }
    }
}

use pinned_servers::PinnedServers;

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
        self.hold().map(drop)
    }

    /// Hold `www/`, proven to be the directory the bundle was collected from.
    ///
    /// Every asset is read through the returned handle, so an entry swapped
    /// for a link after the walk is refused rather than followed.
    ///
    /// # Errors
    /// As [`SpaRoot::verify_unreplaced`].
    fn hold(&self) -> Result<HeldDir, BundleError> {
        match open_www(&self.path).and_then(|dir| dir.id().map(|id| (dir, id))) {
            Ok((dir, id)) if id == self.id => Ok(dir),
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

    /// The path of `asset` below this root, joined from its entry names; for
    /// messages only, never reopened.
    fn shown(&self, asset: &AssetPath) -> PathBuf {
        joined(&self.path, asset.segments())
    }

    /// The bytes of `asset`, read through `www`, the handle [`SpaRoot::hold`]
    /// proved, without following a link at any level.
    ///
    /// # Errors
    /// The refusal met opening or reading it; [`OpenRefusal::TooLarge`] past `cap`.
    fn read(www: &HeldDir, asset: &AssetPath, cap: ByteCap) -> Result<Vec<u8>, OpenRefusal> {
        www.open_rel(asset.segments())
            .and_then(|file| file.read_bytes(cap))
    }
}

/// The offline SPA bundle a mobile shell hosts: the ordered set of asset files
/// copied out of a `web client` build's `www/` tree.
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
    /// required — its absence means the input was not a `web client` bundle,
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
        bundle_refusal(path, refusal, self.limits.entries)
    }
}

/// The bundle error for `refusal` met at `path`, under an entry budget of `entries`.
///
/// An entry that turned into a link or another kind between its listing and
/// its open is refused as that kind, never followed or skipped.
fn bundle_refusal(path: PathBuf, refusal: OpenRefusal, entries: NonZeroU32) -> BundleError {
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
        OpenRefusal::TooManyEntries(_) => BundleError::TooManyAssets { limit: entries },
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
    /// `web client` bundle. Carries the directory inspected.
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
    /// The bundle's `index.html` does not carry exactly one policy meta the
    /// wasm build renders for the pinned servers and capabilities.
    PolicyMismatch {
        /// The `index.html` path, for the message only.
        path: PathBuf,
    },
    /// The bundle's `index.html` is larger than the pack reads.
    IndexTooLarge {
        /// The `index.html` path, for the message only.
        path: PathBuf,
        /// The most bytes the pack reads.
        cap: u64,
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
            Self::PolicyMismatch { path } => {
                text::mobile_bundle_policy_mismatch(&EscapedPath(path))
            }
            Self::IndexTooLarge { path, cap } => {
                text::mobile_bundle_index_too_large(&EscapedPath(path), cap)
            }
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
    /// Copy the bundle's `index.html` with its policy meta swapped for the
    /// shell host's.
    ///
    /// The copy holds exactly one policy meta the wasm build may have rendered
    /// for the pin, replaced by the shell host's form of the same policy; any
    /// other content is refused, never copied.
    PolicedIndex {
        /// The `index.html` asset.
        asset: AssetPath,
        /// Each policy meta the build may have rendered, with its host form.
        swaps: Vec<PolicySwap>,
    },
    /// Copy the rendered app icon here from the source icon.
    Icon,
}

/// One bundle policy meta and its shell-host form, for one worker choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySwap {
    /// The meta the wasm build renders for a web server.
    served: String,
    /// The same policy rendered for the shell's host.
    hosted: String,
}

/// The most bytes of a bundle's `index.html` the pack reads.
///
/// The emitted page is under 2 KiB, so a larger file is refused unread.
pub const MAX_INDEX_HTML_BYTES: u64 = 64 * 1024;

/// [`MAX_INDEX_HTML_BYTES`] as the cap a held read takes.
const INDEX_HTML_CAP: ByteCap =
    ByteCap::from_nonzero(NonZeroU64::MIN.saturating_add(MAX_INDEX_HTML_BYTES.saturating_sub(1)));

/// The most bytes of any one bundled asset the pack reads.
///
/// An emitted bundle's largest asset, its wasm module, stays far below this;
/// a larger file is refused before it is read.
pub const MAX_ASSET_BYTES: u64 = 256 * 1024 * 1024;

/// [`MAX_ASSET_BYTES`] as the cap a held read takes.
const ASSET_CAP: ByteCap =
    ByteCap::from_nonzero(NonZeroU64::MIN.saturating_add(MAX_ASSET_BYTES.saturating_sub(1)));

/// How a bundled asset at `asset` is laid out for a shell whose bundle has
/// `reach`.
///
/// The top-level `index.html` is policed; every other asset is copied.
fn bundle_content(asset: &AssetPath, pin: &ManifestPin, reach: &BundleReach<'_>) -> ShellContent {
    if !asset.is_index_html() {
        return ShellContent::Asset(asset.clone());
    }
    let swaps = pin
        .served_policies()
        .into_iter()
        .map(|(worker, served)| PolicySwap {
            served,
            hosted: ContentSecurityPolicy::for_bundle(reach, worker).meta_element(),
        })
        .collect();
    ShellContent::PolicedIndex {
        asset: asset.clone(),
        swaps,
    }
}

/// The `index.html` asset `asset`, read through `www`, with its one policy
/// meta swapped.
///
/// # Errors
/// [`BundleError::IndexTooLarge`] past [`MAX_INDEX_HTML_BYTES`];
/// [`BundleError::PolicyMismatch`] when the page is not UTF-8, or does not
/// hold exactly one meta of exactly one of `swaps`; the refusal of a link,
/// another kind of entry, or a read failure met on the way.
fn policed_index(
    spa: &SpaRoot,
    www: &HeldDir,
    asset: &AssetPath,
    swaps: &[PolicySwap],
) -> Result<String, BundleError> {
    let shown = spa.shown(asset);
    let bytes = match SpaRoot::read(www, asset, INDEX_HTML_CAP) {
        Ok(bytes) => bytes,
        Err(OpenRefusal::TooLarge(_)) => {
            return Err(BundleError::IndexTooLarge {
                path: shown,
                cap: MAX_INDEX_HTML_BYTES,
            });
        }
        Err(refusal) => return Err(bundle_refusal(shown, refusal, MAX_ASSETS)),
    };
    swapped_policy(&shown, bytes, swaps)
}

/// `bytes`, the page at `shown`, with its one policy meta swapped.
///
/// # Errors
/// [`BundleError::PolicyMismatch`] when the page is not UTF-8, or does not
/// hold exactly one meta of exactly one of `swaps`.
fn swapped_policy(
    shown: &Path,
    bytes: Vec<u8>,
    swaps: &[PolicySwap],
) -> Result<String, BundleError> {
    let mismatch = || BundleError::PolicyMismatch {
        path: shown.to_path_buf(),
    };
    let page = String::from_utf8(bytes).map_err(|_| mismatch())?;
    let mut held = swaps.iter().filter(|swap| page.contains(&swap.served));
    let (Some(swap), None) = (held.next(), held.next()) else {
        return Err(mismatch());
    };
    if page.matches(&swap.served).nth(1).is_some() {
        return Err(mismatch());
    }
    Ok(page.replacen(&swap.served, &swap.hosted, 1))
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
/// `delivery.servers` goes to the network (never as the main frame), and any
/// other request is answered by a local 403; service-worker requests follow the
/// same rule.
///
/// # Errors
/// Propagates any error from the permission derivation, and refuses an Android
/// shell that serves push when the pin names no push identifiers
/// ([`MobileRefusal::PushUnconfigured`]) or whose `delivery.servers` names its
/// local asset host ([`MobileRefusal::AssetOriginListed`]).
pub fn layout(
    os: MobileOs,
    profile: BundleProfile,
    shell: &ShellIdentity,
    pin: &ManifestPin,
    bundle: &SpaBundle,
    icon: Option<&Path>,
) -> Result<ShellLayout, super::super::CliError> {
    match os {
        MobileOs::Android => android_layout(profile, shell, pin, bundle, icon),
        MobileOs::Ios => ios_layout(shell, pin, bundle, icon),
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

/// A web-view facility the Android shell's web view or chrome client serves,
/// only for an accepted axis that covers it.
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
    /// The page's `localStorage`.
    DomStorage,
}

impl ChromeFacility {
    /// Every facility, in declaration order.
    const ALL: &'static [Self] = &[
        Self::Geolocation,
        Self::FileChooser,
        Self::Capture,
        Self::AudioCapture,
        Self::VideoCapture,
        Self::DomStorage,
    ];

    /// The `Shell` flag that turns the facility on.
    const fn java_name(self) -> &'static str {
        match self {
            Self::Geolocation => "GEOLOCATION",
            Self::FileChooser => "FILE_CHOOSER",
            Self::Capture => "CAPTURE",
            Self::AudioCapture => "AUDIO_CAPTURE",
            Self::VideoCapture => "VIDEO_CAPTURE",
            Self::DomStorage => "DOM_STORAGE",
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
        WebCapability::Storage => &[ChromeFacility::DomStorage],
        WebCapability::Notification
        | WebCapability::Push
        | WebCapability::Vibration
        | WebCapability::NetworkInfo
        | WebCapability::Clipboard
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
    /// The Android package: the bundle identifier, verbatim.
    package: &'a str,
    /// The app identity.
    identity: &'a super::desktop::BundleIdentity,
    /// The launch orientation the activity declares.
    orientation: ScreenOrientation,
    /// The manifest pin the shell is laid out from.
    pin: &'a ManifestPin,
    /// What the bundle may reach: the one input to every confinement list.
    reach: BundleReach<'a>,
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
    /// The plan of the shell for `shell` laid out from `pin`.
    fn of(shell: &'a ShellIdentity, pin: &'a ManifestPin) -> Result<Self, super::super::CliError> {
        let identity = &shell.identity;
        let reach = pin
            .reach(BundleHost::AndroidAssets)
            .map_err(|refusal| CliError::Usage(text::Message::relay(&refusal)))?;
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
            package: identity.identifier.as_str(),
            identity,
            orientation: shell.orientation,
            pin,
            reach,
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

    /// The policy every response the shell builds carries as a header.
    fn policy(&self) -> ContentSecurityPolicy<'a> {
        let worker = if self.push.is_some() {
            BundleWorker::Push
        } else {
            BundleWorker::None
        };
        ContentSecurityPolicy::for_bundle(&self.reach, worker)
    }
}

/// Assemble the Android Gradle shell project layout.
///
/// The SPA assets ride under `app/src/main/assets/www/`; a `WebViewAssetLoader`
/// path handler registered at the pin's base directory serves them at
/// [`android_entry_url`]. A request to that local origin is served from the
/// bundle or answered by a local 404, a request to an origin of
/// `delivery.servers` goes to the network (never as the main frame), and any
/// other request, a service worker's included, is answered by a local 403. The
/// `AndroidManifest.xml` `<uses-permission>` lines come only
/// from the permission derivation, and each is asked at the moment of use.
fn android_layout(
    profile: BundleProfile,
    shell: &ShellIdentity,
    pin: &ManifestPin,
    bundle: &SpaBundle,
    icon: Option<&Path>,
) -> Result<ShellLayout, super::super::CliError> {
    let plan = AndroidPlan::of(shell, pin)?;
    let identity = &shell.identity;
    let slug = app_slug(&identity.name);
    let root_name = format!("{slug}-android");
    let mut files = vec![
        generated_file(
            "app/src/main/AndroidManifest.xml".to_owned(),
            render_android_manifest(&plan, icon.is_some()),
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
                "{ANDROID_GRADLE_REPOSITORIES}rootProject.name = '{}'\ninclude \":app\"\n",
                gradle_string_escape(&identity.name)
            ),
        ),
        generated_file(
            "gradle.properties".to_owned(),
            ANDROID_GRADLE_PROPERTIES.to_owned(),
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
            content: bundle_content(&asset.path, pin, &plan.reach),
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
            min_sdk = row.min_sdk.map_or(0, |level| u32::from(level.get())),
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
    java_string(out, "PACKAGE", plan.package);
    java_string(out, "APP_LABEL", &plan.identity.name);
    java_const(out, "String", "NOTIFICATION_CHANNEL", "PACKAGE");
    java_string(out, "CAPTURE_AUTHORITY", &capture_authority(plan.package));
    java_string(out, "CAPTURE_DIR", CAPTURE_DIR);
    java_const(out, "int", "CHOOSER_REQUEST", &CHOOSER_REQUEST.to_string());
    java_const(
        out,
        "int",
        "NOTIFICATIONS_MIN_SDK",
        &RequestGroup::Notifications
            .min_sdk()
            .map_or(0, |level| u32::from(level.get()))
            .to_string(),
    );
    java_string(out, "LOCAL_ORIGIN", csp::ANDROID_ASSET_ORIGIN);
    java_const(
        out,
        "String[]",
        "ALLOWED_ORIGINS",
        &java_array(
            plan.reach
                .network_origins()
                .map(|origin| JavaStringLiteral::of(&origin.https()).to_string()),
        ),
    );
    java_string(out, "CSP_HEADER", csp::HEADER_NAME);
    java_string(
        out,
        "CONTENT_SECURITY_POLICY",
        &plan.policy().header_value(),
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

/// The `android:screenOrientation` value that enforces `orientation`.
const fn android_screen_orientation(orientation: ScreenOrientation) -> &'static str {
    match orientation {
        ScreenOrientation::Portrait => "portrait",
        ScreenOrientation::Landscape => "sensorLandscape",
        ScreenOrientation::Any => "unspecified",
    }
}

/// Render the launcher activity element of the Android manifest, locked to
/// `orientation`.
fn render_android_activity(orientation: ScreenOrientation) -> String {
    format!(
        r#"        <activity
            android:name="dev.ipe.app.MainActivity"
            android:exported="true"
            android:launchMode="singleTop"
            android:screenOrientation="{screen}"
            android:configChanges="orientation|screenSize|screenLayout|smallestScreenSize|keyboardHidden|uiMode">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
"#,
        screen = android_screen_orientation(orientation),
    )
}

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
/// `INTERNET` is declared only when the bundle reaches a server origin, the
/// capture file provider only for the capture facility, and the push service
/// only when the shell serves push.
fn render_android_manifest(plan: &AndroidPlan<'_>, icon: bool) -> String {
    use std::fmt::Write as _;

    // The package is the Gradle `namespace` (Android Gradle plugin 8 refuses a
    // manifest `package` attribute).
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n",
    );
    for line in plan.permissions.to_android_manifest_entries().lines() {
        // The derived line's `android:name` is a fixed constant from the closed
        // table, never user text.
        let _ = writeln!(out, "    {line}");
    }
    if plan.reach.network_origins().next().is_some() {
        out.push_str("    <uses-permission android:name=\"android.permission.INTERNET\" />\n");
    }
    out.push_str("    <application\n");
    if plan.push.is_some() {
        out.push_str("        android:name=\"dev.ipe.app.IpeApplication\"\n");
    }
    let _ = writeln!(
        out,
        "        android:label=\"{label}\"",
        label = xml_attr_escape(&plan.identity.name),
    );
    // The launcher icon resource exists only when the manifest names an icon.
    if icon {
        out.push_str("        android:icon=\"@mipmap/ic_launcher\"\n");
    }
    out.push_str("        android:usesCleartextTraffic=\"false\">\n");
    out.push_str(&render_android_activity(plan.orientation));
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
            authority = xml_attr_escape(&capture_authority(plan.package)),
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

/// The Android Gradle plugin the app module applies.
const ANDROID_GRADLE_PLUGIN_VERSION: &str = "8.5.2";

/// The oldest Gradle the pinned Android Gradle plugin runs on.
const ANDROID_GRADLE_MIN_VERSION: &str = "8.7";

/// The API level the shell compiles against and targets.
const ANDROID_API_LEVEL: ApiLevel = ApiLevel::new(34);

/// The oldest API level the shell installs on.
const ANDROID_MIN_API_LEVEL: ApiLevel = ApiLevel::new(24);

/// The newest `compileSdk` the pinned Android Gradle plugin supports.
///
/// Moves with [`ANDROID_GRADLE_PLUGIN_VERSION`]: an Android Gradle plugin bump
/// and this level are one review.
const ANDROID_GRADLE_PLUGIN_MAX_API_LEVEL: ApiLevel = ApiLevel::new(34);

/// The `targetSdk` from which Android ignores `screenOrientation` on large screens.
///
/// Reaching it changes what the manifest's `orientation` promises, so the
/// shell's level stays under it until the `Ipe.Package` orientation contract
/// is revisited.
const ANDROID_ORIENTATION_ADVISORY_FROM: ApiLevel = ApiLevel::new(36);

/// The `androidx.webkit` library: the asset loader and the message bridge.
const ANDROIDX_WEBKIT_VERSION: &str = "1.11.0";

/// The `androidx.appcompat` library the shell's activity extends.
const ANDROIDX_APPCOMPAT_VERSION: &str = "1.7.0";

/// Whether the Android levels agree: the minimum is under the target, the
/// target is one the pinned Gradle plugin supports and sits under the
/// orientation advisory, and every runtime-request level lies above the
/// minimum and within the target.
const fn android_levels_agree() -> bool {
    let min = ANDROID_MIN_API_LEVEL.get();
    let api = ANDROID_API_LEVEL.get();
    let mut agree = min < api
        && api <= ANDROID_GRADLE_PLUGIN_MAX_API_LEVEL.get()
        && api < ANDROID_ORIENTATION_ADVISORY_FROM.get();
    let mut rest = RequestGroup::ALL;
    while let [group, tail @ ..] = rest {
        if let Some(level) = group.min_sdk() {
            agree = agree && min < level.get() && level.get() <= api;
        }
        rest = tail;
    }
    agree
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if an Android API level drifts out of order with the minimum, the Gradle plugin ceiling, the orientation advisory or a runtime-request level [ledger #boundary]
const _: () = assert!(android_levels_agree());

/// The repositories `settings.gradle` resolves plugins and dependencies from.
const ANDROID_GRADLE_REPOSITORIES: &str = "pluginManagement {\n\
    \x20   repositories {\n\
    \x20       google()\n\
    \x20       mavenCentral()\n\
    \x20       gradlePluginPortal()\n\
    \x20   }\n\
    }\n\
    dependencyResolutionManagement {\n\
    \x20   repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)\n\
    \x20   repositories {\n\
    \x20       google()\n\
    \x20       mavenCentral()\n\
    \x20   }\n\
    }\n";

/// `gradle.properties`: the `AndroidX` libraries the shell links need it.
const ANDROID_GRADLE_PROPERTIES: &str = "android.useAndroidX=true\n";

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
        "plugins {{ id 'com.android.application' version '{ANDROID_GRADLE_PLUGIN_VERSION}' }}\n\
         android {{\n\
         \x20   namespace '{ns}'\n\
         \x20   compileSdk {ANDROID_API_LEVEL}\n\
         \x20   defaultConfig {{\n\
         \x20       applicationId '{ns}'\n\
         \x20       minSdk {ANDROID_MIN_API_LEVEL}\n\
         \x20       targetSdk {ANDROID_API_LEVEL}\n\
         \x20       versionName '{version}'\n\
         \x20       versionCode 1\n\
         \x20   }}\n\
         \x20   compileOptions {{\n\
         \x20       sourceCompatibility JavaVersion.VERSION_1_8\n\
         \x20       targetCompatibility JavaVersion.VERSION_1_8\n\
         \x20   }}\n\
         }}\n\
         dependencies {{\n\
         \x20   implementation 'androidx.webkit:webkit:{ANDROIDX_WEBKIT_VERSION}'\n\
         \x20   implementation 'androidx.appcompat:appcompat:{ANDROIDX_APPCOMPAT_VERSION}'\n\
         \x20   implementation 'androidx.core:core:{ANDROIDX_CORE_VERSION}'\n\
         {push}\
         }}\n",
        ns = gradle_string_escape(plan.package),
        version = gradle_string_escape(&plan.identity.version),
    )
}

/// The URL the Android shell opens: [`csp::ANDROID_ASSET_ORIGIN`] plus
/// `base`'s [`MountBase::dir_url`].
fn android_entry_url(base: &MountBase) -> String {
    let dir = base.dir_url();
    let mut url = String::with_capacity(csp::ANDROID_ASSET_ORIGIN.len().saturating_add(dir.len()));
    url.push_str(csp::ANDROID_ASSET_ORIGIN);
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
/// goes to the network unless it is the main frame, and any other answers a
/// local 403; the page and its service workers share that one `answer`. Every
/// response the shell builds is made by one `confined`, which sets the bundle
/// policy header. A
/// permission is
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
import android.webkit.ServiceWorkerClient;
import android.webkit.ServiceWorkerController;
import android.webkit.ServiceWorkerWebSettings;
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
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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

    /**
     * The one constructor of every response the shell builds: it drops any
     * policy header in headers, and any header with no name or value, and sets
     * the bundle policy in its place. A status and reason the constructor
     * would throw on read 200 OK.
     */
    private static WebResourceResponse confined(String mime, String encoding, int status,
            String reason, Map<String, String> headers, InputStream data) {
        Map<String, String> policed = new HashMap<>();
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                String name = header.getKey();
                String value = header.getValue();
                if (name != null && value != null && !Shell.CSP_HEADER.equalsIgnoreCase(name)) {
                    policed.put(name, value);
                }
            }
        }
        policed.put(Shell.CSP_HEADER, Shell.CONTENT_SECURITY_POLICY);
        if (!settable(status, reason)) {
            status = 200;
            reason = "OK";
        }
        return new WebResourceResponse(mime, encoding, status, reason, policed, data);
    }

    /**
     * Whether the response constructor takes status and reason: a status in
     * 100..299 or 400..599 and a reason of printable ASCII that is not blank.
     */
    private static boolean settable(int status, String reason) {
        if (status < 100 || status > 599 || (status >= 300 && status <= 399)) {
            return false;
        }
        if (reason == null || reason.trim().isEmpty()) {
            return false;
        }
        for (int i = 0; i < reason.length(); i++) {
            char c = reason.charAt(i);
            if (c < 0x20 || c > 0x7E) {
                return false;
            }
        }
        return true;
    }

    /**
     * The answer to a local request: the bundle file the loader mapped, rebuilt
     * through confined, or a local 404 when it mapped none.
     */
    private static WebResourceResponse local(WebResourceResponse mapped) {
        if (mapped == null || mapped.getData() == null) {
            return localNotFound();
        }
        return confined(mapped.getMimeType(), mapped.getEncoding(), mapped.getStatusCode(),
                mapped.getReasonPhrase(), mapped.getResponseHeaders(), mapped.getData());
    }

    /** The answer to every local request the loader leaves unmapped: a local 404. */
    private static WebResourceResponse localNotFound() {
        return confined("text/plain", "utf-8", 404, "Not Found",
                Collections.<String, String>emptyMap(),
                new ByteArrayInputStream(new byte[0]));
    }

    /** The answer to a request for an origin outside delivery.servers: a local 403. */
    private static WebResourceResponse blocked() {
        return confined("text/plain", "utf-8", 403, "Forbidden",
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

    /**
     * The one answer to every request the page or its service worker makes: the
     * local origin from the bundle (else a local 404); a delivery.servers origin
     * passed through, but never as the main frame; anything else a local 403.
     */
    static WebResourceResponse answer(WebViewAssetLoader loader, Uri url, boolean mainFrame) {
        String origin = originOf(url);
        if (Shell.LOCAL_ORIGIN.equals(origin)) {
            return local(loader.shouldInterceptRequest(url));
        }
        return !mainFrame && isAllowed(origin) ? null : blocked();
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
        settings.setDomStorageEnabled(Shell.DOM_STORAGE);
        ServiceWorkerController workers = ServiceWorkerController.getInstance();
        ServiceWorkerWebSettings workerSettings = workers.getServiceWorkerWebSettings();
        workerSettings.setAllowFileAccess(false);
        workerSettings.setAllowContentAccess(false);
        workers.setServiceWorkerClient(new ServiceWorkerClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebResourceRequest request) {
                return answer(loader, request.getUrl(), request.isForMainFrame());
            }
        });
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(
                    WebView view, WebResourceRequest request) {
                return answer(loader, request.getUrl(), request.isForMainFrame());
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                String origin = originOf(url);
                boolean local = Shell.LOCAL_ORIGIN.equals(origin);
                if (request.isForMainFrame() && local) {
                    return false;
                }
                if (request.hasGesture() && origin != null && !local) {
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
const SHELL_BRIDGE_JAVA: &str = r"package dev.ipe.app;

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
";

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
const SHELL_PUSH_JAVA: &str = r"package dev.ipe.app;

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
";

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
const IPE_APPLICATION_JAVA: &str = r"package dev.ipe.app;

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
";

/// The Android build steps: wrapper bootstrap, debug build, install, store build.
///
/// The one rendering every producer (the release-note under `pack web client
/// android`, and this README) carries verbatim, so neither can hand-write a
/// `gradlew` line that drifts from the other.
pub(crate) fn android_build_steps() -> crate::text::Message {
    crate::text::android_build_steps(&ANDROID_GRADLE_MIN_VERSION, &ANDROID_API_LEVEL)
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
         file:// access). Every request is answered one of three ways:\n\
         - a request to that local origin is served from the bundle, or answered by a\n\
         \x20 local 404;\n\
         - a request to an origin listed in delivery.servers goes to the network,\n\
         \x20 except as the page itself;\n\
         - any other request is answered by a local 403 carrying {header}: {value}.\n\
         Every response the shell builds carries a {csp_header} header, and the\n\
         bundle's own policy meta is rewritten to the same connect-src: exactly\n\
         {local} plus the https and wss forms of each delivery.servers origin.\n\
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
         Signing: this Gradle project is unsigned by default.\n\
         \n\
         {steps}\n",
        entry = android_entry_url(base),
        header = BLOCKED_HEADER.0,
        value = BLOCKED_HEADER.1,
        csp_header = csp::HEADER_NAME,
        local = csp::ANDROID_ASSET_ORIGIN,
        steps = android_build_steps(),
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
    shell: &ShellIdentity,
    pin: &ManifestPin,
    bundle: &SpaBundle,
    icon: Option<&Path>,
) -> Result<ShellLayout, super::super::CliError> {
    let identity = &shell.identity;
    let accepts = pin.accepts();
    let base = pin.base();
    let reach = pin
        .reach(BundleHost::IosScheme)
        .map_err(|refusal| CliError::Usage(text::Message::relay(&refusal)))?;
    let slug = app_slug(&identity.name);
    let root_name = format!("{slug}-ios");
    let mut files = Vec::new();

    let plist = render_ios_info_plist(shell, accepts)?;
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
            content: bundle_content(&asset.path, pin, &reach),
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

/// The iPhone `UISupportedInterfaceOrientations` that enforce `orientation`.
const fn ios_orientations(orientation: ScreenOrientation) -> &'static [&'static str] {
    match orientation {
        ScreenOrientation::Portrait => &["UIInterfaceOrientationPortrait"],
        ScreenOrientation::Landscape => &[
            "UIInterfaceOrientationLandscapeLeft",
            "UIInterfaceOrientationLandscapeRight",
        ],
        ScreenOrientation::Any => &[
            "UIInterfaceOrientationPortrait",
            "UIInterfaceOrientationLandscapeLeft",
            "UIInterfaceOrientationLandscapeRight",
        ],
    }
}

/// The iPad `UISupportedInterfaceOrientations~ipad` that enforce `orientation`.
const fn ios_ipad_orientations(orientation: ScreenOrientation) -> &'static [&'static str] {
    match orientation {
        ScreenOrientation::Portrait => &["UIInterfaceOrientationPortrait"],
        ScreenOrientation::Landscape => &[
            "UIInterfaceOrientationLandscapeLeft",
            "UIInterfaceOrientationLandscapeRight",
        ],
        ScreenOrientation::Any => &[
            "UIInterfaceOrientationPortrait",
            "UIInterfaceOrientationPortraitUpsideDown",
            "UIInterfaceOrientationLandscapeLeft",
            "UIInterfaceOrientationLandscapeRight",
        ],
    }
}

/// Whether `orientation` locks the app, which on iPad needs the multitasking
/// opt-out `UIRequiresFullScreen`.
const fn ios_requires_full_screen(orientation: ScreenOrientation) -> bool {
    match orientation {
        ScreenOrientation::Portrait | ScreenOrientation::Landscape => true,
        ScreenOrientation::Any => false,
    }
}

/// Render the iOS `Info.plist`, assembling the fixed identity keys, the
/// orientation keys, and the derived usage-description keys.
///
/// The permission keys come ONLY from [`permissions::derive_permissions`] on
/// [`Platform::Ios`]; this function never writes an `NS…UsageDescription` key
/// itself. An app that accepts no permission-bearing web capability yields a plist
/// with no usage-description keys. Every key and string is XML-escaped.
fn render_ios_info_plist(
    shell: &ShellIdentity,
    accepts: &BTreeSet<Capability>,
) -> Result<String, super::super::CliError> {
    use std::fmt::Write as _;

    let identity = &shell.identity;
    let permission_set = permissions::derive_permissions(accepts, Platform::Ios)?;
    let usage_entries = permission_set.to_info_plist_entries();

    let mut body = String::new();
    let pair = |body: &mut String, key: &str, value: &str| {
        let _ = writeln!(body, "\t<key>{}</key>", plist_escape(key));
        let _ = writeln!(body, "\t<string>{}</string>", plist_escape(value));
    };
    let array = |body: &mut String, key: &str, values: &[&str]| {
        let _ = writeln!(body, "\t<key>{}</key>", plist_escape(key));
        body.push_str("\t<array>\n");
        for value in values {
            let _ = writeln!(body, "\t\t<string>{}</string>", plist_escape(value));
        }
        body.push_str("\t</array>\n");
    };
    pair(&mut body, "CFBundleName", &identity.name);
    pair(&mut body, "CFBundleDisplayName", &identity.name);
    pair(
        &mut body,
        "CFBundleIdentifier",
        identity.identifier.as_str(),
    );
    pair(&mut body, "CFBundleVersion", &identity.version);
    pair(&mut body, "CFBundleShortVersionString", &identity.version);
    pair(&mut body, "CFBundleExecutable", &app_slug(&identity.name));
    pair(&mut body, "CFBundlePackageType", "APPL");
    array(
        &mut body,
        "UISupportedInterfaceOrientations",
        ios_orientations(shell.orientation),
    );
    array(
        &mut body,
        "UISupportedInterfaceOrientations~ipad",
        ios_ipad_orientations(shell.orientation),
    );
    if ios_requires_full_screen(shell.orientation) {
        let _ = writeln!(
            body,
            "\t<key>{}</key>\n\t<true/>",
            plist_escape("UIRequiresFullScreen")
        );
    }
    // The permission keys — from the permission derivation, never authored here.
    for (key, purpose) in usage_entries {
        pair(&mut body, &key, &purpose);
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

/// The URL the iOS shell opens: [`csp::IOS_SCHEME_ORIGIN`] plus `base`'s
/// [`MountBase::dir_url`].
fn ios_entry_url(base: &MountBase) -> String {
    let dir = base.dir_url();
    let mut url = String::with_capacity(csp::IOS_SCHEME_ORIGIN.len().saturating_add(dir.len()));
    url.push_str(csp::IOS_SCHEME_ORIGIN);
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
/// Generated files are written verbatim, bundled SPA assets are read through
/// the held `www/` and written, and the source icon is copied into place. The
/// shell is built whole in a staging directory beside `dist/<root_name>` and
/// put there in one rename ([`OwnedDir::stage_dir`]): a fresh, deterministic
/// tree that replaces the previous shell only once complete, so a refusal at
/// any file leaves the previous shell exactly as it was, and no staging entry.
/// Every path is a [`crate::output_dir::OwnedPath`], so a symlink planted in the
/// owned `dist` is refused — never removed through, written through, or copied
/// onto.
///
/// # Errors
/// [`CliError::Usage`] carrying [`BundleError::Replaced`] when the emitted
/// `www/` is no longer the directory the bundle was collected from;
/// [`CliError::OutputRefused`] for a symlink or non-plain name on the way;
/// [`CliError::Usage`] carrying [`BundleError::PolicyMismatch`] or
/// [`BundleError::IndexTooLarge`] when the bundle's `index.html` cannot be
/// policed, before any shell file is written;
/// [`CliError::Usage`] carrying [`BundleError::UnplaceableAsset`] for an asset
/// that is no longer a regular file below the held `www/` (a link, a FIFO),
/// or [`BundleError::Io`] for one past [`MAX_ASSET_BYTES`], never read;
/// [`CliError::Io`] naming the exact path on any filesystem failure.
pub fn materialise(
    layout: &ShellLayout,
    icon: Option<&Path>,
    dist: &OwnedDir,
) -> Result<PathBuf, CliError> {
    let refused = |e: BundleError| CliError::Usage(crate::text::Message::relay(&e));
    // Every asset is read through this one held `www/`, proven to be the
    // directory collected, never reopened by path.
    let www = layout.spa.hold().map_err(refused)?;
    // Every policed page is read and proven before the shell directory is
    // touched, so a refusal lays nothing down.
    let laid = layout
        .files
        .iter()
        .map(|file| -> Result<_, BundleError> {
            let bytes = match &file.content {
                ShellContent::Generated(text) => Laid::Text(text),
                ShellContent::Asset(asset) => Laid::Copy(asset),
                ShellContent::PolicedIndex { asset, swaps } => {
                    Laid::Policed(policed_index(&layout.spa, &www, asset, swaps)?)
                }
                ShellContent::Icon => Laid::Icon,
            };
            Ok((file, bytes))
        })
        .collect::<Result<Vec<_>, BundleError>>()
        .map_err(refused)?;
    let staged = dist.stage_dir(&layout.root_name)?;

    for (file, bytes) in laid {
        let out_file = staged.path_to(rel_to_native(&file.rel_path))?;
        match bytes {
            Laid::Text(text) => out_file.write(text.as_bytes())?,
            Laid::Policed(page) => out_file.write(page.as_bytes())?,
            Laid::Copy(asset) => {
                let copied = SpaRoot::read(&www, asset, ASSET_CAP).map_err(|refusal| {
                    refused(bundle_refusal(layout.spa.shown(asset), refusal, MAX_ASSETS))
                })?;
                out_file.write(&copied)?;
            }
            Laid::Icon => {
                if let Some(src) = icon {
                    out_file.copy_from(src)?;
                }
            }
        }
    }
    staged.promote()
}

/// The bytes one shell file is laid down with, read before any is written.
enum Laid<'layout> {
    /// Generated text, written verbatim.
    Text(&'layout str),
    /// A bundle asset, read through the held `www/` as it is written.
    Copy(&'layout AssetPath),
    /// A policed `index.html`, already read and proven.
    Policed(String),
    /// The source icon, copied when given.
    Icon,
}

/// Translate a shell-relative `/`-separated path into a native `PathBuf`.
fn rel_to_native(rel: &str) -> PathBuf {
    rel.split('/').collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output_dir::test_links::{staging_leftovers, tree_snapshot};
    use ipe_runtime_rust::encoding::ServerOrigins;

    fn accepts(items: &[Capability]) -> BTreeSet<Capability> {
        items.iter().copied().collect()
    }

    fn web(axis: WebCapability) -> Capability {
        Capability::JsPort(axis)
    }

    fn identity() -> ShellIdentity {
        shell_of(
            "Geo App",
            BundleId::derived("Geo App"),
            ScreenOrientation::Any,
        )
    }

    /// The shell identity of an app named `name` with bundle id `id`, locked to
    /// `orientation`.
    fn shell_of(name: &str, id: BundleId, orientation: ScreenOrientation) -> ShellIdentity {
        ShellIdentity::for_test(
            super::super::desktop::BundleIdentity::new(name, Some("1.2.3"), id),
            orientation,
        )
    }

    /// A bundle id the grammar accepts.
    fn bundle_id(text: &str) -> BundleId {
        BundleId::parse(text).expect("a grammar-valid bundle id")
    }

    /// The `layout` of `os` for `shell` over the capture-serving pin.
    fn layout_of(os: MobileOs, shell: &ShellIdentity) -> ShellLayout {
        layout(os, BundleProfile::Dev, shell, &full_pin(), &bundle(), None).expect("layout")
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
    fn a_web_app_is_packageable() {
        require_web_spa(WebSpaCapability { shape_is_web: true })
            .expect("a web app packages: `web client` builds its SPA");
    }

    #[test]
    fn a_non_web_app_is_refused() {
        let err = require_web_spa(WebSpaCapability {
            shape_is_web: false,
        })
        .expect_err("a non-web app is refused");
        assert_eq!(err, MobileRefusal::NotWebShape);
        assert!(err.to_string().contains("IPE-P0022"), "carries the code");
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
    fn the_android_package_is_the_bundle_id_verbatim() {
        let shell = layout_of(
            MobileOs::Android,
            &shell_of("Shop", bundle_id("io.acme.Shop"), ScreenOrientation::Any),
        );
        let manifest = text_of(&shell, "app/src/main/AndroidManifest.xml");
        assert!(
            !manifest.contains("package="),
            "the package lives in the Gradle namespace only: {manifest}"
        );
        assert!(
            manifest.contains(&format!(
                "android:authorities=\"io.acme.Shop.{CAPTURE_DIR}\""
            )),
            "the capture authority is the bundle id verbatim: {manifest}"
        );
        let gradle = text_of(&shell, "app/build.gradle");
        assert!(gradle.contains("namespace 'io.acme.Shop'"), "{gradle}");
        assert!(gradle.contains("applicationId 'io.acme.Shop'"), "{gradle}");
        assert_eq!(
            constant(&shell, "PACKAGE"),
            Some(quoted("io.acme.Shop")),
            "the shell's package constant is the bundle id verbatim"
        );
        assert_eq!(
            constant(&shell, "CAPTURE_AUTHORITY"),
            Some(quoted(&format!("io.acme.Shop.{CAPTURE_DIR}")))
        );
    }

    #[test]
    fn the_ios_bundle_identifier_is_the_bundle_id_verbatim() {
        let shell = layout_of(
            MobileOs::Ios,
            &shell_of("Shop", bundle_id("io.acme.Shop"), ScreenOrientation::Any),
        );
        let plist = text_of(&shell, "App/Info.plist");
        assert!(
            plist.contains("\t<key>CFBundleIdentifier</key>\n\t<string>io.acme.Shop</string>\n"),
            "{plist}"
        );
    }

    #[test]
    fn the_android_activity_enforces_the_declared_orientation() {
        for orientation in [
            ScreenOrientation::Portrait,
            ScreenOrientation::Landscape,
            ScreenOrientation::Any,
        ] {
            let expected = match orientation {
                ScreenOrientation::Portrait => "portrait",
                ScreenOrientation::Landscape => "sensorLandscape",
                ScreenOrientation::Any => "unspecified",
            };
            let shell = layout_of(
                MobileOs::Android,
                &shell_of("Geo App", BundleId::derived("Geo App"), orientation),
            );
            let manifest = text_of(&shell, "app/src/main/AndroidManifest.xml");
            assert_eq!(
                manifest.matches("android:screenOrientation=").count(),
                1,
                "{manifest}"
            );
            assert!(
                manifest.contains(&format!("android:screenOrientation=\"{expected}\"")),
                "{orientation:?}: {manifest}"
            );
        }
    }

    /// The `<array>` of `key` in `plist`, as its strings.
    fn plist_array<'a>(plist: &'a str, key: &str) -> Option<Vec<&'a str>> {
        let open = format!("\t<key>{key}</key>\n\t<array>\n");
        let (_, rest) = plist.split_once(open.as_str())?;
        let (body, _) = rest.split_once("\t</array>")?;
        Some(
            body.lines()
                .filter_map(|line| {
                    line.trim()
                        .strip_prefix("<string>")
                        .and_then(|l| l.strip_suffix("</string>"))
                })
                .collect(),
        )
    }

    #[test]
    fn the_ios_plist_enforces_the_declared_orientation() {
        const PORTRAIT: &str = "UIInterfaceOrientationPortrait";
        const UPSIDE_DOWN: &str = "UIInterfaceOrientationPortraitUpsideDown";
        const LEFT: &str = "UIInterfaceOrientationLandscapeLeft";
        const RIGHT: &str = "UIInterfaceOrientationLandscapeRight";
        for orientation in [
            ScreenOrientation::Portrait,
            ScreenOrientation::Landscape,
            ScreenOrientation::Any,
        ] {
            let (phone, pad, full_screen): (&[&str], &[&str], bool) = match orientation {
                ScreenOrientation::Portrait => (&[PORTRAIT], &[PORTRAIT], true),
                ScreenOrientation::Landscape => (&[LEFT, RIGHT], &[LEFT, RIGHT], true),
                ScreenOrientation::Any => (
                    &[PORTRAIT, LEFT, RIGHT],
                    &[PORTRAIT, UPSIDE_DOWN, LEFT, RIGHT],
                    false,
                ),
            };
            let shell = layout_of(
                MobileOs::Ios,
                &shell_of("Geo App", BundleId::derived("Geo App"), orientation),
            );
            let plist = text_of(&shell, "App/Info.plist");
            assert_eq!(
                plist_array(plist, "UISupportedInterfaceOrientations").as_deref(),
                Some(phone),
                "{orientation:?}: {plist}"
            );
            assert_eq!(
                plist_array(plist, "UISupportedInterfaceOrientations~ipad").as_deref(),
                Some(pad),
                "{orientation:?}: {plist}"
            );
            assert_eq!(
                plist.contains("\t<key>UIRequiresFullScreen</key>\n\t<true/>"),
                full_screen,
                "{orientation:?}: {plist}"
            );
        }
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
        let hostile = shell_of(
            "Evil\"</manifest><x>",
            BundleId::derived("Evil\"</manifest><x>"),
            ScreenOrientation::Portrait,
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
        let hostile = shell_of(
            "App${new ProcessBuilder('id').start()}",
            bundle_id("com.evil.app"),
            ScreenOrientation::Any,
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

    /// The Gradle project resolves on its own: `settings.gradle` names where
    /// plugins and libraries come from, the plugin carries a version, and
    /// `gradle.properties` enables the `AndroidX` libraries the shell links.
    #[test]
    fn android_gradle_project_names_its_repositories_and_plugin_version() {
        let shell = android(&full_pin());
        let settings = text_of(&shell, "settings.gradle");
        for needle in [
            "pluginManagement {",
            "dependencyResolutionManagement {",
            "google()",
            "mavenCentral()",
            "gradlePluginPortal()",
        ] {
            assert!(settings.contains(needle), "{needle}: {settings}");
        }
        assert!(
            settings.find("pluginManagement {") < settings.find("rootProject.name"),
            "pluginManagement leads settings.gradle: {settings}"
        );
        let gradle = text_of(&shell, "app/build.gradle");
        let plugin =
            format!("id 'com.android.application' version '{ANDROID_GRADLE_PLUGIN_VERSION}'");
        assert!(gradle.contains(&plugin), "{gradle}");
        assert!(!gradle.contains("repositories"), "{gradle}");
        let properties = text_of(&shell, "gradle.properties");
        assert!(
            properties
                .lines()
                .any(|line| line == "android.useAndroidX=true"),
            "{properties}"
        );
        let readme = text_of(&shell, "README.txt");
        assert!(readme.contains("gradle wrapper"), "{readme}");
        assert!(readme.contains(ANDROID_GRADLE_MIN_VERSION), "{readme}");
    }

    /// `app/build.gradle` fills every toolchain number from its one const:
    /// each API level line and each `AndroidX` library line appears exactly once.
    #[test]
    fn android_gradle_renders_each_toolchain_number_from_its_const() {
        let shell = android(&full_pin());
        let gradle = text_of(&shell, "app/build.gradle");
        for expected in [
            format!("compileSdk {ANDROID_API_LEVEL}"),
            format!("targetSdk {ANDROID_API_LEVEL}"),
            format!("minSdk {ANDROID_MIN_API_LEVEL}"),
            format!("implementation 'androidx.webkit:webkit:{ANDROIDX_WEBKIT_VERSION}'"),
            format!("implementation 'androidx.appcompat:appcompat:{ANDROIDX_APPCOMPAT_VERSION}'"),
            format!("implementation 'androidx.core:core:{ANDROIDX_CORE_VERSION}'"),
        ] {
            assert_eq!(
                gradle
                    .lines()
                    .filter(|line| line.trim() == expected)
                    .count(),
                1,
                "{expected}: {gradle}"
            );
        }
        assert_eq!(
            gradle
                .lines()
                .filter(|line| line.contains("androidx."))
                .count(),
            3,
            "every AndroidX library is one of the three const-rendered lines: {gradle}"
        );
    }

    /// The build steps name the API level the shell compiles against.
    #[test]
    fn android_build_steps_name_the_api_level() {
        let steps = android_build_steps();
        let level = format!("API {ANDROID_API_LEVEL}");
        assert!(steps.contains(level.as_str()), "{steps}");
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
            if os == MobileOs::Android {
                let manifest = text_of(&with, "app/src/main/AndroidManifest.xml");
                assert!(
                    manifest.contains("android:icon=\"@mipmap/ic_launcher\""),
                    "{manifest}"
                );
            }
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
            if os == MobileOs::Android {
                let manifest = text_of(&without, "app/src/main/AndroidManifest.xml");
                assert!(
                    !manifest.contains("android:icon="),
                    "no icon reference without an icon resource: {manifest}"
                );
                assert!(
                    manifest.contains("android:usesCleartextTraffic=\"false\">"),
                    "{manifest}"
                );
            }
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

    /// The README carries the one rendered `android_build_steps()` block
    /// verbatim, not a paraphrase or a hand-written subset of it.
    #[test]
    fn android_readme_carries_build_steps() {
        let readme = android_readme("app-android", BundleProfile::Dev, &MountBase::root());
        assert!(
            readme.contains(android_build_steps().as_str()),
            "README must carry the rendered android_build_steps() block verbatim: {readme}"
        );
    }

    // ── Android build steps: one source for every surface ──────────────────────

    /// The text strictly between one `open`/`close` marker pair in `doc`, or why
    /// there is not exactly one pair: no `open`, a second `open` before the
    /// first `close`, or an `open` with no matching `close`.
    fn marked_block<'a>(doc: &'a str, open: &str, close: &str) -> Result<&'a str, String> {
        let Some(start) = doc.find(open) else {
            return Err(format!("no `{open}` marker"));
        };
        let after_open = &doc[start.saturating_add(open.len())..];
        if after_open.contains(open) {
            return Err(format!("more than one `{open}` marker"));
        }
        let Some(end) = after_open.find(close) else {
            return Err(format!("`{open}` marker has no matching `{close}`"));
        };
        Ok(after_open[..end].trim())
    }

    /// [`marked_block`] refuses a missing, doubled, or unterminated marker, and
    /// extracts the trimmed interior on a clean fixture — so a test that reads
    /// `marked_block`'s `Ok` cannot be fooled by a scanner that always succeeds.
    #[test]
    fn marked_block_refuses_a_missing_doubled_or_unterminated_marker() {
        const OPEN: &str = "<!-- m -->";
        const CLOSE: &str = "<!-- /m -->";
        assert!(marked_block("no marker here", OPEN, CLOSE).is_err());
        assert!(
            marked_block(&format!("{OPEN}a{CLOSE}...{OPEN}b{CLOSE}"), OPEN, CLOSE).is_err(),
            "a second open marker must be refused, not silently paired with the first close"
        );
        assert!(
            marked_block(&format!("{OPEN}a, no close"), OPEN, CLOSE).is_err(),
            "an unterminated marker must be refused"
        );
        assert_eq!(
            marked_block(&format!("before{OPEN}  x  {CLOSE}after"), OPEN, CLOSE),
            Ok("x")
        );
    }

    /// The repository root this `ipe-cli` crate was built from.
    fn repo_root_for_tests() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("src/ipe-cli has a repo root two levels up")
    }

    /// The doc guide's one `android-build-steps` block is line-for-line equal
    /// to the catalog's own rendering, so the guide cannot hand-drift from the
    /// fn every other producer calls.
    #[test]
    fn android_build_steps_docs_block_is_rendered_block() {
        let path = repo_root_for_tests().join("docs/guide/delivery.md");
        let doc = std::fs::read_to_string(&path).expect("docs/guide/delivery.md reads");
        let block = marked_block(
            &doc,
            "<!-- android-build-steps -->",
            "<!-- /android-build-steps -->",
        )
        .expect("exactly one android-build-steps marker pair in docs/guide/delivery.md");
        let steps = android_build_steps();
        let rendered: Vec<&str> = steps.lines().collect();
        let doc_lines: Vec<&str> = block.lines().collect();
        assert_eq!(
            doc_lines, rendered,
            "docs/guide/delivery.md's android-build-steps block drifted from \
             android_build_steps() — regenerate it, never hand-edit"
        );
    }

    /// One `file:line` a line scan refuses outside the regions it skips.
    #[derive(Debug, PartialEq, Eq)]
    struct StrayGradleLine {
        file: String,
        line: usize,
    }

    impl std::fmt::Display for StrayGradleLine {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}:{}", self.file, self.line)
        }
    }

    /// The `## android-build-steps` catalog heading: the steps' one source.
    const STEPS_SECTION: &str = "## android-build-steps";

    /// The doc marker opening a block byte-pinned to the rendered steps.
    const STEPS_BLOCK: &str = "<!-- android-build-steps -->";

    /// Every line of `text` naming `gradlew`/`gradle wrapper` outside the
    /// catalog section or a marked doc block, labelled `file` for the report.
    fn stray_gradle_lines(file: &str, text: &str) -> Vec<StrayGradleLine> {
        stray_lines(file, text, &[STEPS_SECTION, STEPS_BLOCK], |line| {
            line.contains("gradlew") || line.contains("gradle wrapper")
        })
    }

    /// Every line of `text` that `refused` matches outside the regions the
    /// `skipped` openers start, labelled `file` for the report.
    ///
    /// A skipped region ends at the next `#`/`##` heading or at the closing
    /// `<!-- /android-build-steps -->` marker.
    fn stray_lines(
        file: &str,
        text: &str,
        skipped: &[&str],
        refused: impl Fn(&str) -> bool,
    ) -> Vec<StrayGradleLine> {
        let mut inside = false;
        let mut hits = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if skipped.contains(&trimmed) {
                inside = true;
                continue;
            }
            if inside
                && (trimmed.starts_with("## ")
                    || trimmed.starts_with("# ")
                    || trimmed == "<!-- /android-build-steps -->")
            {
                inside = false;
            }
            if inside {
                continue;
            }
            if refused(line) {
                hits.push(StrayGradleLine {
                    file: file.to_owned(),
                    line: idx.saturating_add(1),
                });
            }
        }
        hits
    }

    /// `.md` files under `root` (or `root` itself, when it is already a file),
    /// walked to a depth and count ceiling so a cyclic or runaway tree cannot
    /// hang the scan.
    fn markdown_files_under(root: &Path) -> Vec<PathBuf> {
        const MAX_DEPTH: usize = 12;
        const MAX_FILES: usize = 4096;

        fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
            assert!(
                depth <= MAX_DEPTH,
                "android-build-steps scan: depth ceiling exceeded under {}",
                dir.display()
            );
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                assert!(
                    out.len() <= MAX_FILES,
                    "android-build-steps scan: file-count ceiling exceeded under {}",
                    dir.display()
                );
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, depth.saturating_add(1), out);
                } else if path.extension().is_some_and(|ext| ext == "md") {
                    out.push(path);
                }
            }
        }

        if root.is_file() {
            return vec![root.to_path_buf()];
        }
        let mut out = Vec::new();
        walk(root, 0, &mut out);
        out
    }

    /// Every file the hand-written-Gradle scan walks: the whole `docs/` tree,
    /// the README, the CLI help pages, and the message catalog — every surface
    /// a build procedure could be hand-copied into.
    fn gradle_scan_targets(repo_root: &Path, cli_manifest_dir: &Path) -> Vec<PathBuf> {
        let mut files = markdown_files_under(&repo_root.join("docs"));
        files.push(repo_root.join("README.md"));
        files.extend(markdown_files_under(&cli_manifest_dir.join("help")));
        files.push(cli_manifest_dir.join("text/messages.md"));
        files
    }

    /// No file under `docs/`, `README.md`, the CLI help pages, or the message
    /// catalog hand-writes a `gradlew`/`gradle wrapper` line outside the one
    /// catalog section or the one marked doc block: every other mention must
    /// come from rendering [`android_build_steps`], never from a second,
    /// independently drifting copy.
    #[test]
    fn no_hand_written_gradle_commands() {
        let cli_manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = repo_root_for_tests();
        let mut hits = Vec::new();
        for file in gradle_scan_targets(repo_root, cli_manifest_dir) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            let label = file
                .strip_prefix(repo_root)
                .unwrap_or(&file)
                .display()
                .to_string();
            hits.extend(stray_gradle_lines(&label, &text));
        }
        assert!(
            hits.is_empty(),
            "hand-written gradlew/gradle-wrapper line(s) outside android-build-steps: {}",
            hits.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// [`stray_gradle_lines`] finds a stray `./gradlew` line outside the
    /// sanctioned sections, and finds nothing on a clean fixture — so
    /// `no_hand_written_gradle_commands` above cannot pass vacuously on a
    /// scanner that never actually looks.
    #[test]
    fn stray_gradle_lines_finds_the_offender_and_nothing_on_a_clean_fixture() {
        let dirty = "intro\n./gradlew build\nmore text\n";
        let hits = stray_gradle_lines("fixture.md", dirty);
        assert_eq!(
            hits,
            vec![StrayGradleLine {
                file: "fixture.md".to_owned(),
                line: 2,
            }]
        );

        let clean =
            "## android-build-steps\n\n1. `gradlew assembleDebug`\n\n## next\n\nno gradle here\n";
        assert!(stray_gradle_lines("fixture.md", clean).is_empty());
    }

    /// Whether `line` writes one of our API levels as `API <level>`.
    fn names_our_api_level(line: &str) -> bool {
        [ANDROID_API_LEVEL, ANDROID_MIN_API_LEVEL]
            .into_iter()
            .any(|level| line.contains(&format!("API {level}")))
    }

    /// Whether `line` writes a Gradle SDK key followed by a literal number.
    fn names_a_literal_sdk_level(line: &str) -> bool {
        ["compileSdk ", "targetSdk ", "minSdk "]
            .into_iter()
            .any(|key| {
                line.match_indices(key).any(|(at, _)| {
                    line.get(at.saturating_add(key.len())..)
                        .and_then(|rest| rest.bytes().next())
                        .is_some_and(|byte| byte.is_ascii_digit())
                })
            })
    }

    /// The line that opens `mobile.rs`'s test module.
    const TEST_MODULE_MARKER: &str = "#[cfg(test)]\nmod tests";

    /// The production part of a Rust `source`: the text before its test
    /// module, or `None` when it has none, so the scan fails closed.
    fn production_part(source: &str) -> Option<&str> {
        source
            .find(TEST_MODULE_MARKER)
            .and_then(|at| source.get(..at))
    }

    /// Every production line of the Rust `source` writing a Gradle SDK key
    /// with a literal level, or `None` when `source` has no test module.
    fn stray_rust_sdk_lines(file: &str, source: &str) -> Option<Vec<StrayGradleLine>> {
        production_part(source).map(|part| stray_lines(file, part, &[], names_a_literal_sdk_level))
    }

    /// No surface spells one of our Android API levels a second time: the docs,
    /// README, help, catalog and `Ipe.Package` name `API <level>` only inside the
    /// block byte-pinned to the rendered steps (the catalog section holds the
    /// `{api}` placeholder, so a literal there is red too), and the production
    /// renderer writes no SDK key with a literal number.
    #[test]
    fn no_second_android_api_level_literal() {
        let cli_manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repo_root = repo_root_for_tests();
        let mut targets = gradle_scan_targets(repo_root, cli_manifest_dir);
        targets.push(repo_root.join("src/stdlib/Ipe/Package.ipe"));
        let mut hits = Vec::new();
        for file in targets {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            let label = file
                .strip_prefix(repo_root)
                .unwrap_or(&file)
                .display()
                .to_string();
            hits.extend(stray_lines(&label, &text, &[STEPS_BLOCK], |line| {
                names_our_api_level(line) || names_a_literal_sdk_level(line)
            }));
        }
        let rust =
            stray_rust_sdk_lines("src/ipe-cli/src/pack/mobile.rs", include_str!("mobile.rs"));
        assert!(
            rust.is_some(),
            "mobile.rs has no `{TEST_MODULE_MARKER}` line to cut the production part at"
        );
        hits.extend(rust.into_iter().flatten());
        assert!(
            hits.is_empty(),
            "a second literal of an Android API level outside its const: {}",
            hits.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// The API-level scan refuses a literal level outside the pinned block,
    /// spares the pinned block and a platform level that is not ours, and
    /// refuses a Rust source it cannot cut, so it cannot pass vacuously.
    #[test]
    fn api_level_scan_finds_a_literal_and_fails_closed() {
        let refused = |line: &str| names_our_api_level(line) || names_a_literal_sdk_level(line);
        let ours = format!("Android SDK, API {ANDROID_API_LEVEL}\n");
        assert_eq!(
            stray_lines("fixture.md", &ours, &[STEPS_BLOCK], refused),
            vec![StrayGradleLine {
                file: "fixture.md".to_owned(),
                line: 1,
            }]
        );
        let pinned = format!("{STEPS_BLOCK}\n{ours}<!-- /android-build-steps -->\n");
        assert!(stray_lines("fixture.md", &pinned, &[STEPS_BLOCK], refused).is_empty());
        let section = format!("{STEPS_SECTION}\n\n{ours}");
        assert_eq!(
            stray_lines("fixture.md", &section, &[STEPS_BLOCK], refused).len(),
            1,
            "the catalog section is not skipped: it must hold the placeholder"
        );
        let platform = ApiLevel::new(ANDROID_API_LEVEL.get().saturating_sub(1));
        assert_ne!(platform, ANDROID_MIN_API_LEVEL);
        let not_ours = format!("from API {platform} the OS gates it\n");
        assert!(stray_lines("fixture.md", &not_ours, &[STEPS_BLOCK], refused).is_empty());

        let rust = format!(
            "const X: &str = \"compileSdk {ANDROID_API_LEVEL}\";\n{TEST_MODULE_MARKER} {{}}\n"
        );
        assert_eq!(
            stray_rust_sdk_lines("fixture.rs", &rust).map(|hits| hits.len()),
            Some(1)
        );
        let placeholder =
            format!("const X: &str = \"compileSdk {{api}}\";\n{TEST_MODULE_MARKER} {{}}\n");
        assert_eq!(
            stray_rust_sdk_lines("fixture.rs", &placeholder).map(|hits| hits.len()),
            Some(0)
        );
        assert_eq!(stray_rust_sdk_lines("fixture.rs", "fn main() {}\n"), None);
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
                activity.contains("return local(loader.shouldInterceptRequest(url));"),
                "{activity}"
            );
            assert!(
                activity.contains("if (mapped == null || mapped.getData() == null) {"),
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
            servers: PinnedServers::new(
                ServerOrigins::new(servers.iter().map(|raw| {
                    ipe_runtime_rust::encoding::ServerOrigin::parse(raw).expect("a legal origin")
                }))
                .expect("a legal origin set"),
            ),
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
            servers: PinnedServers::new(ServerOrigins::none()),
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
                ShellContent::Generated(_)
                | ShellContent::Asset(_)
                | ShellContent::PolicedIndex { .. }
                | ShellContent::Icon => None,
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
            "return local(loader.shouldInterceptRequest(url));",
            "return !mainFrame && isAllowed(origin) ? null : blocked();",
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
            Some(quoted(csp::ANDROID_ASSET_ORIGIN))
        );
    }

    #[test]
    fn android_every_request_path_answers_through_the_one_rule() {
        let shell = android(&full_pin());
        let activity = text_of(&shell, &java_path("MainActivity.java"));
        let call = "return answer(loader, request.getUrl(), request.isForMainFrame());";
        assert_eq!(
            activity.matches(call).count(),
            2,
            "the page and its service workers answer through one rule: {activity}"
        );
        assert_eq!(
            activity.matches("loader.shouldInterceptRequest(").count(),
            1,
            "{activity}"
        );
        let client = activity.find("workers.setServiceWorkerClient(");
        let load = activity.find("webView.loadUrl(ENTRY_URL);");
        assert!(
            client.is_some() && client < load,
            "the service-worker client is installed before the first load: {activity}"
        );
        for needle in [
            "workerSettings.setAllowFileAccess(false);",
            "workerSettings.setAllowContentAccess(false);",
        ] {
            assert!(activity.contains(needle), "{needle}: {activity}");
        }
    }

    #[test]
    fn android_main_frame_never_leaves_the_local_origin() {
        let shell = android(&full_pin());
        let activity = text_of(&shell, &java_path("MainActivity.java"));
        assert!(
            activity.contains("return !mainFrame && isAllowed(origin) ? null : blocked();"),
            "a server document is refused as the main frame: {activity}"
        );
        assert!(
            !activity.contains("return isAllowed(origin) ? null : blocked();"),
            "{activity}"
        );
        assert!(
            activity.contains("if (request.hasGesture() && origin != null && !local) {"),
            "a gesture link to the local origin never leaves the app: {activity}"
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
        let hostile_name = "Evil\"); x(); // \\u0022 <a href=\"&\">";
        let hostile = shell_of(
            hostile_name,
            BundleId::derived(hostile_name),
            ScreenOrientation::Any,
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
            Some(quoted(hostile_name)),
            "the label reaches Java only as its literal"
        );
        let manifest = text_of(&shell, "app/src/main/AndroidManifest.xml");
        assert!(
            manifest.contains(&format!(
                "android:label=\"{}\"",
                xml_attr_escape(hostile_name)
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
            let identity = identity();
            let Ok(plan) = AndroidPlan::of(&identity, &pin) else {
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
    fn android_dom_storage_follows_the_storage_axis() {
        let stored = android(&shell_pin(
            &accepts(&[web(WebCapability::Storage)]),
            &MountBase::root(),
        ));
        assert_eq!(constant(&stored, "DOM_STORAGE").as_deref(), Some("true"));
        let activity = text_of(&stored, &java_path("MainActivity.java"));
        assert!(
            activity.contains("settings.setDomStorageEnabled(Shell.DOM_STORAGE);"),
            "{activity}"
        );
        let plain = android(&pin("/", &[]));
        assert_eq!(constant(&plain, "DOM_STORAGE").as_deref(), Some("false"));
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
        let reach = full.reach(BundleHost::Served).expect("a served reach");
        assert_eq!(reach.network_origins().count(), 2);
        assert_eq!(full.push(), Some(&push_delivery()));
        assert!(pin("/", &[]).push().is_none());
        let none = pin("/", &[]);
        let reach = none.reach(BundleHost::Served).expect("a served reach");
        assert_eq!(reach.network_origins().next(), None);
    }

    // ── Bundle policy: header, meta and their one reach ───────────────────────

    /// The server sets the policy tests lay shells out over.
    const SERVER_SETS: [&[&str]; 3] = [
        &[],
        &["https://api.example"],
        &["https://push.example:8443", "https://api.example"],
    ];

    /// The pin over `servers` with push configured and accepted.
    fn push_pin(servers: &[&str]) -> ManifestPin {
        ManifestPin {
            servers: pin("/", servers).servers,
            ..full_pin()
        }
    }

    /// The raw value of the `Shell.java` string constant `name`.
    fn string_constant(shell: &ShellLayout, name: &str) -> String {
        constant(shell, name)
            .and_then(|value| Some(value.strip_prefix('"')?.strip_suffix('"')?.to_owned()))
            .unwrap_or_default()
    }

    /// The directives of the policy `value`, each with its source words.
    fn directives_of(value: &str) -> Vec<(String, Vec<String>)> {
        value
            .split(';')
            .filter_map(|directive| {
                let mut words = directive.split_whitespace();
                let name = words.next()?.to_owned();
                Some((name, words.map(str::to_owned).collect()))
            })
            .collect()
    }

    /// The `connect-src` sources of the policy `value`.
    fn connect_of(value: &str) -> BTreeSet<String> {
        directives_of(value)
            .into_iter()
            .filter(|(name, _)| name == "connect-src")
            .flat_map(|(_, sources)| sources)
            .collect()
    }

    /// `text` with every whitespace run collapsed to one space.
    fn collapsed(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn android_header_connect_src_is_the_asset_origin_and_each_server() {
        for servers in SERVER_SETS {
            let shell = android(&pin("/", servers));
            let header = string_constant(&shell, "CONTENT_SECURITY_POLICY");
            let allowed = constant(&shell, "ALLOWED_ORIGINS").unwrap_or_default();
            let mut expected: BTreeSet<String> = allowed
                .trim_matches(|c| c == '{' || c == '}')
                .split(", ")
                .filter_map(|item| Some(item.strip_prefix('"')?.strip_suffix('"')?.to_owned()))
                .flat_map(|origin| [origin.replacen("https://", "wss://", 1), origin])
                .collect();
            expected.insert(csp::ANDROID_ASSET_ORIGIN.to_owned());
            assert_eq!(connect_of(&header), expected, "{header}");
            for server in servers {
                assert!(expected.contains(*server), "{server}: {expected:?}");
            }
            assert_eq!(
                expected.len(),
                servers.len().saturating_mul(2).saturating_add(1),
                "{expected:?}"
            );
            assert!(!header.contains("'self' wss"), "{header}");
        }
    }

    #[test]
    fn android_every_shell_built_response_is_confined() {
        let shell = android(&full_pin());
        let activity = collapsed(text_of(&shell, &java_path("MainActivity.java")));
        assert_eq!(
            activity.matches("new WebResourceResponse(").count(),
            1,
            "one constructor builds every response: {activity}"
        );
        assert!(
            !activity.contains("return mapped != null ? mapped"),
            "the loader's response is never returned as built: {activity}"
        );
        for needle in [
            "return local(loader.shouldInterceptRequest(url));",
            "return confined(mapped.getMimeType(), mapped.getEncoding(), mapped.getStatusCode(), \
             mapped.getReasonPhrase(), mapped.getResponseHeaders(), mapped.getData());",
            "if (name != null && value != null && !Shell.CSP_HEADER.equalsIgnoreCase(name)) {",
            "policed.put(Shell.CSP_HEADER, Shell.CONTENT_SECURITY_POLICY); \
             if (!settable(status, reason)) { status = 200; reason = \"OK\"; } \
             return new WebResourceResponse(mime, encoding, status, reason, policed, data);",
            "if (status < 100 || status > 599 || (status >= 300 && status <= 399)) { return false; }",
            "if (reason == null || reason.trim().isEmpty()) { return false; }",
            "if (c < 0x20 || c > 0x7E) { return false; }",
            "return confined(\"text/plain\", \"utf-8\", 404, \"Not Found\",",
            "return confined(\"text/plain\", \"utf-8\", 403, \"Forbidden\",",
        ] {
            assert!(activity.contains(needle), "{needle}: {activity}");
        }
        assert_eq!(
            activity.matches("Shell.CONTENT_SECURITY_POLICY").count(),
            1,
            "{activity}"
        );
    }

    #[test]
    fn android_policy_constants_are_declared_once() {
        let shell = android(&full_pin());
        let all = shell_constants(&shell);
        for name in [
            "LOCAL_ORIGIN",
            "ALLOWED_ORIGINS",
            "CSP_HEADER",
            "CONTENT_SECURITY_POLICY",
        ] {
            assert_eq!(
                all.iter().filter(|(declared, _)| declared == name).count(),
                1,
                "{name}: {all:?}"
            );
        }
        assert_eq!(
            constant(&shell, "CSP_HEADER"),
            Some(quoted(csp::HEADER_NAME))
        );
    }

    #[test]
    fn android_header_keeps_every_bundle_directive_but_connect_src() {
        let others = |value: &str| {
            directives_of(value)
                .into_iter()
                .filter(|(name, _)| name != "connect-src")
                .collect::<Vec<_>>()
        };
        for servers in SERVER_SETS {
            for (laid, worker) in [
                (pin("/", servers), BundleWorker::None),
                (push_pin(servers), BundleWorker::Push),
            ] {
                let shell = android(&laid);
                let header = string_constant(&shell, "CONTENT_SECURITY_POLICY");
                let meta =
                    ContentSecurityPolicy::bundle(laid.servers.origins(), worker).header_value();
                assert_eq!(others(&header), others(&meta), "{header} / {meta}");
                let mut admitted = connect_of(&meta);
                assert!(admitted.remove("'self'"), "{meta}");
                admitted.insert(csp::ANDROID_ASSET_ORIGIN.to_owned());
                assert!(connect_of(&header).is_subset(&admitted), "{header}");
                assert!(!connect_of(&header).contains("'self'"), "{header}");
            }
        }
    }

    #[test]
    fn the_pinned_servers_are_read_only_through_the_reach() {
        // The origins are a private field of `pinned_servers::PinnedServers`,
        // so the compiler refuses a read anywhere else; this pins what the
        // module itself hands out.
        let source = include_str!("mobile.rs");
        let production = source
            .split_once("#[cfg(test)]\nmod tests {")
            .map_or(source, |(head, _)| head);
        let module = production
            .split_once("mod pinned_servers {")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body)
            .expect("the pinned servers module");
        assert!(
            module.contains("pub struct PinnedServers(ServerOrigins);"),
            "the origins stay a private field: {module}"
        );
        let readers: Vec<&str> = module
            .match_indices("self.0")
            .filter_map(|(at, _)| {
                let (_, signature) = module.get(..at)?.rsplit_once("fn ")?;
                signature.split_once('(').map(|(name, _)| name)
            })
            .collect();
        assert_eq!(readers, ["reach", "served", "origins"]);
        let fields = module.matches(".0").count();
        assert_eq!(fields, 3, "every field read is one of the listed: {module}");
        // A destructuring read (`let Self(o) = self`, `|PinnedServers(o)| o`)
        // names no `.0`, so every function and every tuple pattern the module
        // holds is listed too.
        let functions: Vec<&str> = module
            .split("fn ")
            .skip(1)
            .filter_map(|rest| rest.split_once('(').map(|(name, _)| name))
            .collect();
        assert_eq!(functions, ["new", "reach", "served", "origins"], "{module}");
        assert_eq!(
            module.matches("Self(").count(),
            1,
            "only `new` builds: {module}"
        );
        assert_eq!(
            module.matches("PinnedServers(").count(),
            1,
            "only the declaration names the tuple: {module}"
        );
        assert!(
            module.contains("#[cfg(test)]\n        #[must_use]\n        pub const fn origins("),
            "the bare origins are a test's only: {module}"
        );
        assert_eq!(production.matches("impl PinnedServers").count(), 1);
        assert_eq!(production.matches("for PinnedServers").count(), 0);
    }

    #[test]
    fn an_android_shell_refuses_a_server_on_its_asset_host() {
        let with_port = format!("{}:8443", csp::ANDROID_ASSET_ORIGIN);
        let lay = |os: MobileOs, laid: &ManifestPin| {
            layout(os, BundleProfile::Dev, &identity(), laid, &bundle(), None)
        };
        for listed in [csp::ANDROID_ASSET_ORIGIN, with_port.as_str()] {
            let refused = pin("/", &["https://api.example", listed]);
            let result = lay(MobileOs::Android, &refused);
            assert!(matches!(result, Err(CliError::Usage(_))), "{listed}");
            assert!(
                lay(MobileOs::Ios, &refused).is_ok(),
                "only the Android shell answers that host locally"
            );
            let Err(err) = result else { return };
            let shown = err.to_string();
            assert!(
                shown.contains("`delivery.servers`") && shown.contains(listed),
                "{shown}"
            );
        }
        assert!(lay(MobileOs::Android, &pin("/", &["https://api.example"])).is_ok());
    }

    #[test]
    fn both_shells_police_only_the_top_level_index() {
        for os in [MobileOs::Android, MobileOs::Ios] {
            let shell = layout(
                os,
                BundleProfile::Dev,
                &identity(),
                &pin("/", &[]),
                &bundle(),
                None,
            )
            .expect("layout");
            let policed: Vec<&str> = shell
                .files
                .iter()
                .filter(|file| matches!(file.content, ShellContent::PolicedIndex { .. }))
                .map(|file| file.rel_path.as_str())
                .collect();
            assert_eq!(policed.len(), 1, "{policed:?}");
            assert!(
                policed.iter().all(|rel| rel.ends_with("www/index.html")),
                "{policed:?}"
            );
        }
    }

    #[test]
    fn android_readme_states_the_policy_header() {
        let shell = android(&pin("/", &["https://api.example"]));
        let readme = collapsed(text_of(&shell, "README.txt"));
        let reach = format!(
            "exactly {} plus the https and wss forms of each delivery.servers origin",
            csp::ANDROID_ASSET_ORIGIN
        );
        for needle in [
            "Every response the shell builds carries a Content-Security-Policy header",
            reach.as_str(),
        ] {
            assert!(readme.contains(needle), "{needle}: {readme}");
        }
    }

    // ── Bundle policy: the page the shell lays down ───────────────────────────

    /// A collected bundle whose `index.html` is `page`, with its scratch base.
    fn bundle_with_page(tag: &str, page: &str) -> (PathBuf, SpaBundle) {
        let (base, www) = www_with(tag, &["boot.js"]);
        std::fs::write(www.join("index.html"), page).expect("write index");
        let spa = SpaBundle::from_www_dir(&www).expect("collect");
        (base, spa)
    }

    /// A page carrying `metas` in its head.
    fn page_with(metas: &[&str]) -> String {
        let mut page = String::from("<!doctype html>\n<html><head>\n");
        for meta in metas {
            page.push_str(meta);
        }
        page.push_str("</head><body></body></html>\n");
        page
    }

    /// The policy meta the wasm build renders for `servers` and `worker`.
    fn served_meta(servers: &ServerOrigins, worker: BundleWorker) -> String {
        ContentSecurityPolicy::bundle(servers, worker).meta_element()
    }

    /// The `os` shell laid out from `laid` over `spa`, materialised under `base`.
    fn materialised(
        os: MobileOs,
        laid: &ManifestPin,
        base: &Path,
        spa: &SpaBundle,
    ) -> (ShellLayout, Result<PathBuf, CliError>) {
        let shell = layout(os, BundleProfile::Dev, &identity(), laid, spa, None).expect("layout");
        let dist = OwnedDir::claim(&base.join("dist")).expect("claim dist");
        let result = materialise(&shell, None, &dist);
        (shell, result)
    }

    #[test]
    fn a_shell_page_carries_its_host_policy() {
        let laid = pin("/", &["https://api.example"]);
        let page = page_with(&[&served_meta(laid.servers.origins(), BundleWorker::None)]);
        for (os, rel, host) in [
            (
                MobileOs::Android,
                "app/src/main/assets/www/index.html",
                BundleHost::AndroidAssets,
            ),
            (MobileOs::Ios, "App/www/index.html", BundleHost::IosScheme),
        ] {
            let (base, spa) = bundle_with_page("policed", &page);
            let (_, result) = materialised(os, &laid, &base, &spa);
            let root = result.expect("materialised");
            let written =
                std::fs::read_to_string(root.join(rel_to_native(rel))).expect("read the page");
            let reach = laid.reach(host).expect("a reach");
            let hosted = ContentSecurityPolicy::for_bundle(&reach, BundleWorker::None);
            assert_eq!(written, page_with(&[&hosted.meta_element()]));
            assert_eq!(
                connect_of(&hosted.header_value()).contains("'self'"),
                matches!(host, BundleHost::IosScheme),
                "{written}"
            );
        }
    }

    #[test]
    fn a_page_without_the_pinned_policy_lays_nothing_down() {
        let laid = pin("/", &["https://api.example"]);
        let other = pin("/", &["https://other.example"]);
        let meta = served_meta(laid.servers.origins(), BundleWorker::None);
        let pages = [
            page_with(&[]),
            page_with(&[&meta, &meta]),
            page_with(&[&served_meta(other.servers.origins(), BundleWorker::None)]),
            page_with(&[&served_meta(laid.servers.origins(), BundleWorker::Push)]),
        ];
        for page in &pages {
            let (base, spa) = bundle_with_page("mismatch", page);
            let (shell, result) = materialised(MobileOs::Android, &laid, &base, &spa);
            assert!(matches!(result, Err(CliError::Usage(_))), "{page}");
            assert!(
                !base.join("dist").join(&shell.root_name).exists(),
                "nothing is laid down: {page}"
            );
            let Err(err) = result else { return };
            assert!(
                err.to_string().contains("Content-Security-Policy meta"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_push_shell_admits_the_page_with_or_without_its_worker() {
        let laid = push_pin(&["https://api.example"]);
        for worker in [BundleWorker::None, BundleWorker::Push] {
            let page = page_with(&[&served_meta(laid.servers.origins(), worker)]);
            let (base, spa) = bundle_with_page("push", &page);
            let (_, result) = materialised(MobileOs::Android, &laid, &base, &spa);
            let root = result.expect("a reached or unreached worker both lay out");
            let rel = rel_to_native("app/src/main/assets/www/index.html");
            let written = std::fs::read_to_string(root.join(rel)).expect("read the page");
            let reach = laid.reach(BundleHost::AndroidAssets).expect("a reach");
            let hosted = ContentSecurityPolicy::for_bundle(&reach, worker);
            assert_eq!(written, page_with(&[&hosted.meta_element()]));
        }
    }

    #[test]
    fn a_page_past_the_cap_or_not_utf8_is_refused() {
        let laid = pin("/", &[]);
        let mut page = page_with(&[&served_meta(laid.servers.origins(), BundleWorker::None)]);
        let cap = usize::try_from(MAX_INDEX_HTML_BYTES).expect("a usize cap");
        page.push_str(&" ".repeat(cap.saturating_add(1).saturating_sub(page.len())));
        let (_base, spa) = bundle_with_page("oversized", &page);
        let index = spa
            .assets()
            .iter()
            .find(|asset| asset.path.is_index_html())
            .expect("an index");
        let reach = laid.reach(BundleHost::AndroidAssets).expect("a reach");
        let content = bundle_content(&index.path, &laid, &reach);
        assert!(matches!(content, ShellContent::PolicedIndex { .. }));
        let ShellContent::PolicedIndex { swaps, .. } = content else {
            return;
        };
        let www = spa.spa.hold().expect("hold www");
        let source = spa.spa.shown(&index.path);
        let refused = policed_index(&spa.spa, &www, &index.path, &swaps);
        assert!(matches!(
            refused,
            Err(BundleError::IndexTooLarge {
                cap: MAX_INDEX_HTML_BYTES,
                ..
            })
        ));
        page.truncate(cap);
        std::fs::write(&source, &page).expect("write the page at the cap");
        assert!(
            policed_index(&spa.spa, &www, &index.path, &swaps).is_ok(),
            "the cap itself is read"
        );
        let mut bytes = page.into_bytes();
        bytes.pop();
        bytes.insert(0, 0xff);
        std::fs::write(&source, bytes).expect("write a non-UTF-8 page at the cap");
        assert!(matches!(
            policed_index(&spa.spa, &www, &index.path, &swaps),
            Err(BundleError::PolicyMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_asset_swapped_for_a_link_after_the_walk_is_refused_not_copied() {
        let laid = pin("/", &[]);
        let page = page_with(&[&served_meta(laid.servers.origins(), BundleWorker::None)]);
        for victim in ["boot.js", "index.html"] {
            let (base, spa) = bundle_with_page("asset-link", &page);
            // The outside file is a page the policing admits, so only the
            // held read refuses it.
            let outside = base.join("outside.html");
            std::fs::write(&outside, &page).expect("write the outside file");
            let shell = layout(
                MobileOs::Android,
                BundleProfile::Dev,
                &identity(),
                &laid,
                &spa,
                None,
            )
            .expect("layout");
            let planted = base.join("www").join(victim);
            std::fs::remove_file(&planted).expect("remove the collected asset");
            std::os::unix::fs::symlink(&outside, &planted).expect("plant a link");
            let dist = OwnedDir::claim(&base.join("dist")).expect("claim dist");
            let err = materialise(&shell, None, &dist).expect_err("a linked asset is refused");
            assert!(matches!(err, CliError::Usage(_)), "{victim}: {err}");
            assert!(
                err.to_string()
                    .contains(text::mobile_asset_kind(&FileKind::Symlink).as_str()),
                "{victim}: {err}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_asset_swapped_for_a_fifo_after_the_walk_is_refused_unread() {
        let laid = pin("/", &[]);
        let page = page_with(&[&served_meta(laid.servers.origins(), BundleWorker::None)]);
        let (base, spa) = bundle_with_page("asset-fifo", &page);
        let shell = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &laid,
            &spa,
            None,
        )
        .expect("layout");
        let planted = base.join("www").join("boot.js");
        std::fs::remove_file(&planted).expect("remove the collected asset");
        let made = std::process::Command::new("mkfifo").arg(&planted).status();
        assert!(
            made.is_ok_and(|status| status.success()),
            "mkfifo plants the fixture"
        );
        let dist = OwnedDir::claim(&base.join("dist")).expect("claim dist");
        let err = materialise(&shell, None, &dist).expect_err("a fifo asset is refused");
        assert!(
            err.to_string()
                .contains(text::mobile_asset_kind(&FileKind::Fifo).as_str()),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_swapped_for_a_link_after_the_walk_is_refused_not_copied() {
        let laid = pin("/", &[]);
        let page = page_with(&[&served_meta(laid.servers.origins(), BundleWorker::None)]);
        let (base, www) = www_with("dir-link", &["pkg/app.js"]);
        std::fs::write(www.join("index.html"), &page).expect("write index");
        let spa = SpaBundle::from_www_dir(&www).expect("collect");
        let shell = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &laid,
            &spa,
            None,
        )
        .expect("layout");
        // The outside directory holds the same name, so only the held,
        // no-follow descent refuses it.
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).expect("mk outside");
        std::fs::write(outside.join("app.js"), b"outside").expect("write outside asset");
        std::fs::remove_dir_all(www.join("pkg")).expect("remove the collected directory");
        std::os::unix::fs::symlink(&outside, www.join("pkg")).expect("plant a link");
        let dist = OwnedDir::claim(&base.join("dist")).expect("claim dist");
        let err = materialise(&shell, None, &dist).expect_err("a linked directory is refused");
        assert!(
            err.to_string()
                .contains(text::mobile_asset_kind(&FileKind::Symlink).as_str()),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_asset_past_the_cap_is_refused_unread() {
        let laid = pin("/", &[]);
        let page = page_with(&[&served_meta(laid.servers.origins(), BundleWorker::None)]);
        let (base, spa) = bundle_with_page("asset-cap", &page);
        let shell = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &laid,
            &spa,
            None,
        )
        .expect("layout");
        // A sparse file: its length is past the cap, its blocks are not
        // written, and the held read refuses it on that length alone.
        std::fs::File::options()
            .write(true)
            .open(base.join("www").join("boot.js"))
            .and_then(|file| file.set_len(MAX_ASSET_BYTES.saturating_add(1)))
            .expect("grow the asset past the cap");
        let dist = OwnedDir::claim(&base.join("dist")).expect("claim dist");
        let err = materialise(&shell, None, &dist).expect_err("an oversized asset is refused");
        assert!(matches!(err, CliError::Usage(_)), "{err}");
        assert!(
            err.to_string()
                .contains(&format!("larger than {MAX_ASSET_BYTES} bytes")),
            "{err}"
        );
    }

    // ── Staged shell: complete or absent ──────────────────────────────────────

    /// An Android shell over a bundle whose `boot.js` asset is read after other shell files.
    fn staged_shell(tag: &str) -> (PathBuf, ShellLayout, OwnedDir) {
        let laid = pin("/", &[]);
        let page = page_with(&[&served_meta(laid.servers.origins(), BundleWorker::None)]);
        let (base, spa) = bundle_with_page(tag, &page);
        let shell = layout(
            MobileOs::Android,
            BundleProfile::Dev,
            &identity(),
            &laid,
            &spa,
            None,
        )
        .expect("layout");
        assert!(
            shell
                .files
                .iter()
                .position(|file| file.rel_path.ends_with("boot.js"))
                > Some(0),
            "control: a shell file is written before the asset"
        );
        let dist = OwnedDir::claim(&base.join("dist")).expect("claim dist");
        (base, shell, dist)
    }

    /// Remove the collected `boot.js`, so the shell's read of it is refused mid-write.
    fn drop_asset(base: &Path) {
        std::fs::remove_file(base.join("www").join("boot.js")).expect("remove the asset");
    }

    #[test]
    fn a_shell_refused_mid_write_lays_nothing_down() {
        let (base, shell, dist) = staged_shell("staged-absent");
        drop_asset(&base);
        let result = materialise(&shell, None, &dist);
        assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
        assert!(
            !dist.path().join(&shell.root_name).exists(),
            "no partial shell"
        );
        assert!(staging_leftovers(dist.path()).is_empty());
    }

    #[test]
    fn a_shell_refused_mid_write_keeps_the_previous_shell_byte_for_byte() {
        let (base, shell, dist) = staged_shell("staged-previous");
        let root = materialise(&shell, None, &dist).expect("the previous shell");
        let before = tree_snapshot(&root);
        assert!(before.len() > 1, "control: the previous shell holds files");
        drop_asset(&base);
        let result = materialise(&shell, None, &dist);
        assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
        assert_eq!(tree_snapshot(&root), before);
        assert!(staging_leftovers(dist.path()).is_empty());
    }

    #[test]
    fn a_staged_shell_lands_every_file_and_leaves_nothing_behind() {
        let (_base, shell, dist) = staged_shell("staged-happy");
        let root = materialise(&shell, None, &dist).expect("materialise");
        for file in &shell.files {
            assert!(
                root.join(rel_to_native(&file.rel_path)).is_file(),
                "{}",
                file.rel_path
            );
        }
        let again = materialise(&shell, None, &dist).expect("a re-pack");
        assert_eq!(again, root);
        assert!(staging_leftovers(dist.path()).is_empty());
    }
}
