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
use std::path::{Path, PathBuf};

use ipe_ir::Capability;

use crate::CliError;
use crate::output_dir::OwnedDir;

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
/// the CLI boundary renders each with a stable code and remedy and no path
/// produces a bundle it should have refused.
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
}

impl std::fmt::Display for MobileRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingOs => write!(
                f,
                "error[IPE-P0020]: a mobile bundle needs an OS — \
                 name one: `ipe build web solo <ios|android>`"
            ),
            Self::UnknownOs(got) => write!(
                f,
                "error[IPE-P0021]: unknown mobile OS {got:?} \
                 (expected `ipe build web solo <ios|android>`)"
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
        }
    }
}

impl std::error::Error for MobileRefusal {}

/// One file a bundled SPA asset carries: its shell-relative path (under the
/// native project's asset root) and the source path in the emitted `www/` tree.
///
/// A typed pair rather than loose tuples so the asset set is inspectable and a
/// test can assert the full copied file set without materialising bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetFile {
    /// The path of this asset relative to the native project's web-asset root,
    /// using `/` separators (mirrors the `www/`-relative path).
    pub rel_path: String,
    /// The absolute source path in the emitted `www/` tree.
    pub source: PathBuf,
}

/// The offline SPA bundle a mobile shell hosts: the ordered set of asset files
/// copied out of a `--target wasm` build's `www/` tree.
///
/// Pure data derived from the emitted `www/` directory, so a test can assert the
/// full asset set without running a device toolchain. The webview serves these
/// and only these — local assets, no remote URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaBundle {
    /// The asset files, in deterministic (sorted) order.
    pub assets: Vec<AssetFile>,
}

impl SpaBundle {
    /// Collect the SPA asset set from an emitted `www/` directory.
    ///
    /// Every regular file under `www_dir` becomes one [`AssetFile`] whose
    /// `rel_path` is its path relative to `www_dir` (with `/` separators). The set
    /// is sorted for determinism. An `index.html` is required — its absence means
    /// the input was not a `--target wasm` bundle, a fail-closed error rather than
    /// an empty shell.
    ///
    /// # Errors
    /// [`BundleError::NoIndexHtml`] when `www_dir` has no `index.html`;
    /// [`BundleError::Io`] naming the exact path on any directory-walk failure.
    pub fn from_www_dir(www_dir: &Path) -> Result<Self, BundleError> {
        let mut assets = Vec::new();
        collect_files(www_dir, www_dir, &mut assets)?;
        assets.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        if !assets.iter().any(|a| a.rel_path == "index.html") {
            return Err(BundleError::NoIndexHtml {
                dir: www_dir.to_path_buf(),
            });
        }
        Ok(Self { assets })
    }
}

/// Recursively collect every regular file under `dir` into `out`, keying each by
/// its path relative to `root` with `/` separators.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<AssetFile>) -> Result<(), BundleError> {
    let entries = std::fs::read_dir(dir).map_err(|source| BundleError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| BundleError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| BundleError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_dir() {
            collect_files(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let rel_path = rel
                .components()
                .filter_map(|c| match c {
                    std::path::Component::Normal(s) => s.to_str(),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/");
            out.push(AssetFile {
                rel_path,
                source: path,
            });
        }
    }
    Ok(())
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
        match self {
            Self::NoIndexHtml { dir } => write!(
                f,
                "no index.html in the emitted wasm bundle at {} — expected a `--target wasm` \
                 SPA (index.html + boot script + pkg/*.wasm)",
                dir.display()
            ),
            Self::Io { path, source } => write!(f, "reading {}: {}", path.display(), source),
        }
    }
}

impl std::error::Error for BundleError {}

/// The origin of a generated shell file's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellContent {
    /// Write this literal generated text (a manifest, a source file, a build
    /// script).
    Generated(String),
    /// Copy a bundled SPA asset here from the emitted `www/` tree.
    Asset(PathBuf),
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
/// The SPA bundle assets are placed under the OS's web-asset root and the webview
/// is wired to load `index.html` from there (a local origin, never a remote URL).
///
/// # Errors
/// Propagates any error from the permission derivation.
pub fn layout(
    os: MobileOs,
    identity: &super::desktop::BundleIdentity,
    accepts: &BTreeSet<Capability>,
    bundle: &SpaBundle,
    icon: Option<&Path>,
) -> Result<ShellLayout, super::super::CliError> {
    match os {
        MobileOs::Android => android_layout(identity, accepts, bundle, icon),
        MobileOs::Ios => ios_layout(identity, accepts, bundle, icon),
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
/// serves them at `https://appassets.androidplatform.net/assets/www/`, so the
/// webview loads `index.html` from a same-origin local URL (no remote host, no
/// `file://`). The `AndroidManifest.xml` `<uses-permission>` lines come only from
/// the permission derivation.
fn android_layout(
    identity: &super::desktop::BundleIdentity,
    accepts: &BTreeSet<Capability>,
    bundle: &SpaBundle,
    icon: Option<&Path>,
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
        content: ShellContent::Generated(render_android_activity(identity)),
    });
    files.push(ShellFile {
        rel_path: "README.txt".to_owned(),
        content: ShellContent::Generated(android_readme(&root_name)),
    });

    // The offline SPA assets, under the WebViewAssetLoader-served asset root.
    for asset in &bundle.assets {
        files.push(ShellFile {
            rel_path: format!("app/src/main/assets/www/{}", asset.rel_path),
            content: ShellContent::Asset(asset.source.clone()),
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

/// Render the `MainActivity` that wires a `WebView` to the offline SPA through a
/// `WebViewAssetLoader`. The loaded URL is a same-origin local asset URL — the
/// webview never reaches a remote host.
fn render_android_activity(_identity: &super::desktop::BundleIdentity) -> String {
    // The activity is a fixed shell (no author text is interpolated), so it needs
    // no escaping. It loads only the bundled local `index.html`.
    "package dev.ipe.app;\n\
     \n\
     import android.app.Activity;\n\
     import android.os.Bundle;\n\
     import android.webkit.WebView;\n\
     import android.webkit.WebViewClient;\n\
     import android.webkit.WebResourceRequest;\n\
     import android.webkit.WebResourceResponse;\n\
     import androidx.webkit.WebViewAssetLoader;\n\
     \n\
     public final class MainActivity extends Activity {\n\
     \x20   @Override\n\
     \x20   protected void onCreate(Bundle savedInstanceState) {\n\
     \x20       super.onCreate(savedInstanceState);\n\
     \x20       final WebViewAssetLoader loader = new WebViewAssetLoader.Builder()\n\
     \x20           .addPathHandler(\"/assets/\", new WebViewAssetLoader.AssetsPathHandler(this))\n\
     \x20           .build();\n\
     \x20       WebView webView = new WebView(this);\n\
     \x20       webView.getSettings().setJavaScriptEnabled(true);\n\
     \x20       webView.getSettings().setAllowFileAccess(false);\n\
     \x20       webView.getSettings().setAllowContentAccess(false);\n\
     \x20       webView.setWebViewClient(new WebViewClient() {\n\
     \x20           @Override\n\
     \x20           public WebResourceResponse shouldInterceptRequest(\n\
     \x20                   WebView view, WebResourceRequest request) {\n\
     \x20               return loader.shouldInterceptRequest(request.getUrl());\n\
     \x20           }\n\
     \x20       });\n\
     \x20       setContentView(webView);\n\
     \x20       webView.loadUrl(\
     \"https://appassets.androidplatform.net/assets/www/index.html\");\n\
     \x20   }\n\
     }\n"
    .to_owned()
}

/// The Android shell's build/README note.
fn android_readme(root_name: &str) -> String {
    format!(
        "{root_name}: an Android system-webview shell for an offline Ipê Web SPA.\n\
         \n\
         The client-wasm SPA rides under app/src/main/assets/www/; a WebViewAssetLoader\n\
         serves it at https://appassets.androidplatform.net/assets/www/index.html, so the\n\
         WebView loads a same-origin local bundle (no remote host, no file:// access).\n\
         The <uses-permission> lines in AndroidManifest.xml are derived from the app's\n\
         accepted web capabilities — never hand-authored.\n\
         \n\
         Build: ./gradlew assembleDebug   (requires the Android SDK; API 34).\n"
    )
}

// ── iOS ──────────────────────────────────────────────────────────────────────

/// Assemble the iOS Xcode shell project layout.
///
/// The SPA assets ride under `App/www/`; a `WKURLSchemeHandler` serves them under
/// a custom `ipe-app://` scheme with the correct MIME per extension (a bare
/// `file://` load cannot serve `.wasm` with `application/wasm`), so the
/// `WKWebView` loads `ipe-app://app/index.html` — a local origin, never a remote
/// URL. The `Info.plist` usage-description keys come only from the permission
/// derivation.
fn ios_layout(
    identity: &super::desktop::BundleIdentity,
    accepts: &BTreeSet<Capability>,
    bundle: &SpaBundle,
    icon: Option<&Path>,
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
        content: ShellContent::Generated(render_ios_app_delegate()),
    });
    files.push(ShellFile {
        rel_path: "App/SchemeHandler.swift".to_owned(),
        content: ShellContent::Generated(render_ios_scheme_handler()),
    });
    files.push(ShellFile {
        rel_path: "README.txt".to_owned(),
        content: ShellContent::Generated(ios_readme(&root_name)),
    });

    for asset in &bundle.assets {
        files.push(ShellFile {
            rel_path: format!("App/www/{}", asset.rel_path),
            content: ShellContent::Asset(asset.source.clone()),
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

/// Render the iOS `AppDelegate` that hosts a `WKWebView` bound to the custom-scheme
/// handler and loads the offline SPA. The loaded URL is the custom `ipe-app://`
/// scheme, served from bundled assets — the webview never reaches a remote host.
fn render_ios_app_delegate() -> String {
    // A fixed shell (no author text interpolated); it loads only the bundled
    // local index.html through the custom scheme.
    "import UIKit\n\
     import WebKit\n\
     \n\
     @main\n\
     final class AppDelegate: UIResponder, UIApplicationDelegate {\n\
     \x20   var window: UIWindow?\n\
     \x20   var webView: WKWebView?\n\
     \n\
     \x20   func application(_ application: UIApplication,\n\
     \x20       didFinishLaunchingWithOptions launchOptions:\n\
     \x20       [UIApplication.LaunchOptionsKey: Any]?) -> Bool {\n\
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
     \x20       if let url = URL(string: \"ipe-app://app/index.html\") {\n\
     \x20           webView.load(URLRequest(url: url))\n\
     \x20       }\n\
     \x20       return true\n\
     \x20   }\n\
     }\n"
    .to_owned()
}

/// Render the `WKURLSchemeHandler` that serves the bundled SPA assets under the
/// custom `ipe-app://` scheme, with a correct MIME per file extension.
///
/// `WKWebView` cannot cleanly `file://`-load a `.wasm` with the required
/// `application/wasm` MIME; a custom scheme handler resolves each request to a
/// bundled resource and sets its content type explicitly. Only paths under the
/// bundled `www/` are served — a request escaping it resolves to nothing.
fn render_ios_scheme_handler() -> String {
    // A fixed shell (no author text interpolated). It maps a request path to a
    // bundled resource under `www/` and refuses anything outside it.
    "import Foundation\n\
     import WebKit\n\
     \n\
     final class SchemeHandler: NSObject, WKURLSchemeHandler {\n\
     \x20   func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {\n\
     \x20       guard let url = urlSchemeTask.request.url else {\n\
     \x20           urlSchemeTask.didFailWithError(URLError(.badURL))\n\
     \x20           return\n\
     \x20       }\n\
     \x20       let path = url.path.isEmpty ? \"/index.html\" : url.path\n\
     \x20       let rel = path.hasPrefix(\"/\") ? String(path.dropFirst()) : path\n\
     \x20       guard let base = Bundle.main.resourceURL?\
     .appendingPathComponent(\"www\") else {\n\
     \x20           urlSchemeTask.didFailWithError(URLError(.fileDoesNotExist))\n\
     \x20           return\n\
     \x20       }\n\
     \x20       let resolved = base.appendingPathComponent(rel).standardizedFileURL\n\
     \x20       guard resolved.path.hasPrefix(base.standardizedFileURL.path),\n\
     \x20             let data = try? Data(contentsOf: resolved) else {\n\
     \x20           urlSchemeTask.didFailWithError(URLError(.fileDoesNotExist))\n\
     \x20           return\n\
     \x20       }\n\
     \x20       let mime = SchemeHandler.mimeType(for: resolved.pathExtension)\n\
     \x20       let response = URLResponse(url: url, mimeType: mime,\n\
     \x20           expectedContentLength: data.count, textEncodingName: nil)\n\
     \x20       urlSchemeTask.didReceive(response)\n\
     \x20       urlSchemeTask.didReceive(data)\n\
     \x20       urlSchemeTask.didFinish()\n\
     \x20   }\n\
     \n\
     \x20   func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) {}\n\
     \n\
     \x20   static func mimeType(for ext: String) -> String {\n\
     \x20       switch ext.lowercased() {\n\
     \x20       case \"html\": return \"text/html\"\n\
     \x20       case \"js\": return \"text/javascript\"\n\
     \x20       case \"wasm\": return \"application/wasm\"\n\
     \x20       case \"json\": return \"application/json\"\n\
     \x20       case \"css\": return \"text/css\"\n\
     \x20       default: return \"application/octet-stream\"\n\
     \x20       }\n\
     \x20   }\n\
     }\n"
    .to_owned()
}

/// The iOS shell's build/README note.
fn ios_readme(root_name: &str) -> String {
    format!(
        "{root_name}: an iOS system-webview shell for an offline Ipê Web SPA.\n\
         \n\
         The client-wasm SPA rides under App/www/; a WKURLSchemeHandler serves it under\n\
         the custom ipe-app:// scheme with a correct MIME per file (WKWebView cannot\n\
         cleanly file://-load .wasm), so the WKWebView loads ipe-app://app/index.html —\n\
         a local origin, never a remote URL. The Info.plist NS…UsageDescription keys are\n\
         derived from the app's accepted web capabilities — never hand-authored.\n\
         \n\
         Build: open this project in Xcode on macOS; a signed, runnable .ipa requires\n\
         macOS + Xcode + a signing identity (out of scope on this host).\n"
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
/// [`CliError::OutputRefused`] for a symlink or non-plain name on the way;
/// [`CliError::Io`] naming the exact path on any filesystem failure.
pub fn materialise(
    layout: &ShellLayout,
    icon: Option<&Path>,
    dist: &OwnedDir,
) -> Result<PathBuf, CliError> {
    let root = dist.path_to(&layout.root_name)?;
    root.remove()?;
    root.ensure_dir()?;

    for file in &layout.files {
        let out_file =
            dist.path_to(Path::new(&layout.root_name).join(rel_to_native(&file.rel_path)))?;
        match &file.content {
            ShellContent::Generated(text) => out_file.write(text.as_bytes())?,
            ShellContent::Asset(src) => out_file.copy_from(src)?,
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

    /// A minimal SPA bundle standing in for an emitted `www/` tree.
    fn bundle() -> SpaBundle {
        SpaBundle {
            assets: vec![
                AssetFile {
                    rel_path: "index.html".to_owned(),
                    source: PathBuf::from("/tmp/www/index.html"),
                },
                AssetFile {
                    rel_path: "boot.js".to_owned(),
                    source: PathBuf::from("/tmp/www/boot.js"),
                },
                AssetFile {
                    rel_path: "pkg/ipe_app_bg.wasm".to_owned(),
                    source: PathBuf::from("/tmp/www/pkg/ipe_app_bg.wasm"),
                },
            ],
        }
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
    }

    #[test]
    fn a_web_app_without_wasm_is_refused() {
        let err = require_web_spa(WebSpaCapability {
            shape_is_web: true,
            wasm_enabled: false,
        })
        .expect_err("a web app with wasm off is refused");
        assert_eq!(err, MobileRefusal::WasmDisabled);
    }

    // ── SPA bundle collection ─────────────────────────────────────────────────

    #[test]
    fn a_www_dir_without_index_html_is_refused() {
        let dir = std::env::temp_dir().join(format!("ipe-mobile-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk tmp");
        std::fs::write(dir.join("boot.js"), b"x").expect("write");
        let err = SpaBundle::from_www_dir(&dir).expect_err("no index.html is refused");
        assert!(matches!(err, BundleError::NoIndexHtml { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_www_dir_collects_its_files_sorted() {
        let dir = std::env::temp_dir().join(format!("ipe-mobile-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("pkg")).expect("mk tmp");
        std::fs::write(dir.join("index.html"), b"<html>").expect("write");
        std::fs::write(dir.join("boot.js"), b"boot").expect("write");
        std::fs::write(dir.join("pkg").join("app_bg.wasm"), b"\0asm").expect("write");
        let spa = SpaBundle::from_www_dir(&dir).expect("collect");
        let rels: Vec<&str> = spa.assets.iter().map(|a| a.rel_path.as_str()).collect();
        assert_eq!(rels, vec!["boot.js", "index.html", "pkg/app_bg.wasm"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Android: manifest permissions come only from the derivation ───────────

    #[test]
    fn android_geolocation_yields_the_location_uses_permission() {
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let layout = layout(MobileOs::Android, &identity(), &a, &bundle(), None).expect("layout");
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
            &identity(),
            &accepts(&[]),
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
            &hyphenated,
            &accepts(&[]),
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
        let layout = layout(MobileOs::Android, &identity(), &a, &bundle(), None).expect("layout");
        let manifest = layout
            .generated("app/src/main/AndroidManifest.xml")
            .expect("android manifest");
        assert!(!manifest.contains("uses-permission"));
    }

    #[test]
    fn android_layout_bundles_the_spa_assets_offline() {
        let layout = layout(
            MobileOs::Android,
            &identity(),
            &accepts(&[]),
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
        assert!(activity.contains("appassets.androidplatform.net/assets/www/index.html"));
        assert!(!activity.contains("http://") || activity.contains("https://appassets"));
    }

    // ── iOS: plist permissions come only from the derivation ──────────────────

    #[test]
    fn ios_geolocation_yields_the_location_usage_key() {
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let layout = layout(MobileOs::Ios, &identity(), &a, &bundle(), None).expect("layout");
        let plist = layout.generated("App/Info.plist").expect("ios plist");
        assert!(
            plist.contains("NSLocationWhenInUseUsageDescription"),
            "plist carries the derived location usage key: {plist}"
        );
        assert!(plist.contains("This app uses your location"));
    }

    #[test]
    fn ios_app_accepting_nothing_has_no_usage_keys() {
        let layout =
            layout(MobileOs::Ios, &identity(), &accepts(&[]), &bundle(), None).expect("layout");
        let plist = layout.generated("App/Info.plist").expect("ios plist");
        assert!(
            !plist.contains("UsageDescription"),
            "a pure app declares no usage-description keys: {plist}"
        );
        assert!(plist.contains("CFBundleIdentifier"));
    }

    #[test]
    fn ios_scheme_handler_serves_wasm_with_the_correct_mime() {
        let layout =
            layout(MobileOs::Ios, &identity(), &accepts(&[]), &bundle(), None).expect("layout");
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
        assert!(delegate.contains("ipe-app://app/index.html"));
        assert!(!delegate.contains("http://"));
    }

    #[test]
    fn ios_layout_bundles_the_spa_assets_offline() {
        let layout =
            layout(MobileOs::Ios, &identity(), &accepts(&[]), &bundle(), None).expect("layout");
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
        let android = layout(MobileOs::Android, &hostile, &a, &bundle(), None).expect("layout");
        let manifest = android
            .generated("app/src/main/AndroidManifest.xml")
            .expect("android manifest");
        assert!(
            !manifest.contains("<x>"),
            "a hostile identity cannot inject raw XML into the manifest: {manifest}"
        );

        let ios = layout(MobileOs::Ios, &hostile, &a, &bundle(), None).expect("layout");
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
        let android =
            layout(MobileOs::Android, &hostile, &accepts(&[]), &bundle(), None).expect("layout");
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
            let with = layout(os, &identity(), &accepts(&[]), &bundle(), Some(&icon)).expect("l");
            assert!(
                with.files.iter().any(|f| f.content == ShellContent::Icon),
                "an icon file is present on {os:?} when the manifest declares one"
            );
            let without = layout(os, &identity(), &accepts(&[]), &bundle(), None).expect("l");
            assert!(
                without
                    .files
                    .iter()
                    .all(|f| f.content != ShellContent::Icon),
                "no icon file on {os:?} when the manifest declares none"
            );
        }
    }
}
