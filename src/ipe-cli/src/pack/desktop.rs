//! Desktop packaging: turning a built `Ipe.WebView` app into a distributable
//! per-OS application bundle.
//!
//! The webview shell (wry/tao) already runs the app in a native window; this
//! module produces the shippable bundle *around* that binary — a macOS `.app`, a
//! Linux tarball (with a `.desktop` launcher + icon), or a Windows portable
//! `.exe` + zip — plus the per-OS icon formats derived from a single source icon.
//!
//! The macOS `Info.plist` permission keys are never authored here: they come
//! only from [`crate::pack::permissions`], the single source of truth for what a
//! packaged app may do. This module assembles the plist *around* that derivation,
//! so a desktop bundle can neither under-declare relative to consent nor smuggle
//! a permission the app never accepted.
//!
//! ## Provable here vs authored-but-unrun
//! The Linux tarball path is produced and asserted end-to-end on this box. The
//! macOS `.app`/`.dmg` and Windows `.exe`+zip runs belong on their OS runners;
//! their *layout* and *manifest content* are pure data, asserted here via unit
//! tests, but this module never fakes a mac/Windows toolchain invocation.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ipe_ir::Capability;

use crate::CliError;
use crate::output_dir::OwnedDir;

use super::permissions::{self, Platform};

/// A desktop operating system this packager targets.
///
/// A closed set (no wildcard), so a new desktop OS forces a decision at every
/// match rather than silently falling through.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum DesktopOs {
    /// A Linux desktop — a tarball carrying the binary, a `.desktop` launcher,
    /// and an icon; `WebKitGTK` is a documented runtime dependency.
    Linux,
    /// A macOS desktop — a `.app` bundle (`Contents/{MacOS,Resources}` +
    /// `Info.plist`); the system `WebKit` is the webview.
    MacOs,
    /// A Windows desktop — the `.exe` plus a portable zip; the `WebView2` runtime
    /// is a documented runtime dependency.
    Windows,
}

impl DesktopOs {
    /// The lowercase wire name of this OS — the `dist/<os>/` bundle directory and
    /// diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Windows => "windows",
        }
    }

    /// The desktop OS of the host this binary runs on — the OS a `web desktop`
    /// bundle targets (the grammar carries no cross-OS override).
    ///
    /// `None` on a host whose OS is not a desktop packaging target (so the caller
    /// asks the user to name one explicitly rather than guessing).
    #[must_use]
    pub fn host() -> Option<Self> {
        match std::env::consts::OS {
            "linux" => Some(Self::Linux),
            "macos" => Some(Self::MacOs),
            "windows" => Some(Self::Windows),
            _ => None,
        }
    }

    /// The Apple [`Platform`] a macOS bundle derives its permissions for, or
    /// `None` for the non-Apple desktop OSes (which gate no device capability by a
    /// static manifest, so they derive no OS permissions).
    #[must_use]
    const fn apple_platform(self) -> Option<Platform> {
        match self {
            Self::MacOs => Some(Platform::MacOs),
            Self::Linux | Self::Windows => None,
        }
    }

    /// The runtime-dependency note the bundle must carry so a packaged webview app
    /// can always find its system webview at launch.
    #[must_use]
    pub const fn webview_runtime_note(self) -> &'static str {
        match self {
            Self::Linux => {
                "This app requires WebKitGTK at runtime (Debian/Ubuntu: libwebkit2gtk-4.1-0)."
            }
            Self::MacOs => "This app uses the system WebKit; no extra runtime is required.",
            Self::Windows => {
                "This app requires the Microsoft Edge WebView2 runtime \
                 (https://developer.microsoft.com/microsoft-edge/webview2/)."
            }
        }
    }
}

impl std::str::FromStr for DesktopOs {
    type Err = UnknownDesktopOs;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "linux" => Ok(Self::Linux),
            "macos" => Ok(Self::MacOs),
            "windows" => Ok(Self::Windows),
            other => Err(UnknownDesktopOs(other.to_owned())),
        }
    }
}

/// An unrecognised desktop-OS token where linux/macos/windows was expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownDesktopOs(pub String);

impl std::fmt::Display for UnknownDesktopOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown desktop OS {:?} (expected one of: linux, macos, windows)",
            self.0
        )
    }
}

impl std::error::Error for UnknownDesktopOs {}

/// Resolve the desktop OS a `web desktop` bundle targets.
///
/// An explicit OS word parses to that OS; an absent word targets the host OS (the
/// `web desktop` delivery carries no cross-OS override). A host whose OS is not a
/// desktop packaging target is a typed refusal rather than a silent wrong-OS guess.
///
/// # Errors
/// [`DesktopRefusal::UnknownOs`] for an OS word outside the closed set;
/// [`DesktopRefusal::HostNotDesktop`] when the host OS is not a desktop
/// host.
pub fn resolve_os(explicit: Option<&str>) -> Result<DesktopOs, DesktopRefusal> {
    explicit.map_or_else(
        || {
            DesktopOs::host().ok_or_else(|| DesktopRefusal::HostNotDesktop {
                host: std::env::consts::OS.to_owned(),
            })
        },
        |name| {
            name.parse::<DesktopOs>()
                .map_err(|e| DesktopRefusal::UnknownOs(e.0))
        },
    )
}

/// The declared app shape a desktop bundle may be produced for.
///
/// Only [`AppShape::WebView`] is packageable as a desktop app; every other shape
/// is refused. Modelled as a closed set so the refusal names exactly what the app
/// is and why it cannot be packaged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppShape {
    /// An `Ipe.WebView` desktop app — the one packageable shape.
    WebView,
    /// A `Web` server app.
    Web,
    /// A `Terminal` app.
    Terminal,
    /// A plain `Program`.
    Program,
}

impl AppShape {
    /// The lowercase name of this shape, used in a refusal diagnostic.
    const fn as_str(self) -> &'static str {
        match self {
            Self::WebView => "webView",
            Self::Web => "web",
            Self::Terminal => "terminal",
            Self::Program => "program",
        }
    }
}

/// Gate an app's shape for desktop packaging: only a webview app proceeds.
///
/// # Errors
/// [`DesktopRefusal::NotWebView`] naming the actual shape, for any non-webview
/// app.
pub const fn require_webview(shape: AppShape) -> Result<(), DesktopRefusal> {
    match shape {
        AppShape::WebView => Ok(()),
        other => Err(DesktopRefusal::NotWebView {
            shape: other.as_str(),
        }),
    }
}

/// A typed, fail-closed refusal from the desktop packager.
///
/// Every desktop-packaging error the packager itself raises is a member here, so
/// the CLI boundary renders each with a stable code and remedy and no path
/// produces a bundle it should have refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DesktopRefusal {
    /// The app is not an `Ipe.WebView` app, so it has no native window to wrap
    /// into a desktop bundle. Carries the actual shape.
    NotWebView {
        /// The app's actual shape (`web` / `terminal` / `program`).
        shape: &'static str,
    },
    /// A desktop-OS word named an OS outside the closed set.
    UnknownOs(String),
    /// The host OS is not a desktop packaging target, so a `web desktop` bundle
    /// has no OS to target here.
    HostNotDesktop {
        /// The host OS token (`std::env::consts::OS`).
        host: String,
    },
}

impl std::fmt::Display for DesktopRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotWebView { shape } => write!(
                f,
                "error[IPE-P0010]: `web desktop` packages an `Ipe.WebView` app, \
                 but this app's shape is `{shape}`\n  \
                 = a desktop bundle wraps the native webview window; a `{shape}` app has no such \
                 window. Build a `WebView` app, or choose the matching host for a `{shape}` app."
            ),
            Self::UnknownOs(got) => write!(
                f,
                "error[IPE-P0011]: unknown desktop OS {got:?} \
                 (expected linux|macos|windows)"
            ),
            Self::HostNotDesktop { host } => write!(
                f,
                "error[IPE-P0012]: this host ({host:?}) is not a desktop packaging target — \
                 use `ipe build web desktop` (the host OS's bundle)"
            ),
        }
    }
}

impl std::error::Error for DesktopRefusal {}

/// The identity a bundle is labelled with, drawn from the project manifest.
///
/// Constructed once from the manifest so every renderer (plist, `.desktop`,
/// filenames) reads one validated identity rather than re-deriving names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleIdentity {
    /// The human-facing app name (the manifest `name`).
    pub name: String,
    /// The app version string (the manifest `version`, or `"0.0.0"` when the
    /// manifest declares none — a bundle always carries *some* version field).
    pub version: String,
    /// The reverse-DNS bundle identifier used on Apple platforms
    /// (`com.ipe.<sanitised-name>` when the manifest gives none).
    pub identifier: String,
}

impl BundleIdentity {
    /// Build an identity from a manifest name, optional version, and optional
    /// author-supplied identifier. A missing version defaults to `0.0.0`; a
    /// missing identifier is synthesised from the name.
    #[must_use]
    pub fn new(name: &str, version: Option<&str>, identifier: Option<&str>) -> Self {
        let version = version.unwrap_or("0.0.0").to_owned();
        let identifier = identifier.map_or_else(
            || format!("com.ipe.{}", sanitise_identifier(name)),
            str::to_owned,
        );
        Self {
            name: name.to_owned(),
            version,
            identifier,
        }
    }
}

/// Sanitise a name into the `[a-z0-9-]` segment an Apple reverse-DNS identifier
/// permits: lowercase, non-alphanumeric runs collapsed to a single `-`, and no
/// leading/trailing `-`. An empty result becomes `app` so the identifier is
/// always a valid segment.
pub(crate) fn sanitise_identifier(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = true; // suppress a leading dash
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "app".to_owned()
    } else {
        out
    }
}

/// Refuse a bundle root directory name that is not exactly one non-traversing
/// path component.
///
/// The macOS `.app` root keeps the raw display name, and that name flows into
/// `dist_dir.join(root_name)` for both the write and the pre-pack
/// `remove_dir_all` in [`materialise`]. A name carrying a path separator, a `..`
/// component, or an absolute prefix would resolve OUTSIDE `dist_dir` — turning a
/// pack into an arbitrary-path write and delete. This is the fail-closed
/// boundary: a `root_name` that is not one name reading back as itself
/// (`ipe_fs_open::is_one_spelled_name`: no separator, `..`, root, prefix or
/// NUL, and on Windows no name Win32 rewrites) is rejected before any layout is
/// returned, so no untrusted manifest name can escape the distribution
/// directory or land under another name.
///
/// `display_name` is the raw name, named only so the refusal message points at
/// the offending manifest field.
///
/// # Errors
/// [`CliError::Usage`] when `root_name` is not one spelled name.
fn reject_traversing_bundle_root(
    root_name: &str,
    display_name: &str,
) -> Result<(), super::super::CliError> {
    if ipe_fs_open::is_one_spelled_name(std::ffi::OsStr::new(root_name)) {
        return Ok(());
    }
    Err(super::super::CliError::Usage(
        crate::text::msg::bundle_name_not_a_component(&display_name),
    ))
}

/// The per-OS icon file a bundle carries, derived from the single source icon.
///
/// The *name* and *format* are decided here (pure data); rendering the source
/// bytes into the target format is a materialization concern. A source icon is a
/// PNG (the conventional cross-platform source); the per-OS output is `.icns`
/// (macOS), `.png` (Linux), or `.ico` (Windows).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IconPlan {
    /// The absolute source icon path from the manifest.
    pub source: PathBuf,
    /// The bundle-relative output icon filename (e.g. `AppName.icns`).
    pub output_name: String,
}

impl IconPlan {
    /// Plan the per-OS icon output for `os` from a source icon and the app name.
    #[must_use]
    pub fn new(os: DesktopOs, source: &Path, app_name: &str) -> Self {
        let stem = sanitise_identifier(app_name);
        let ext = match os {
            DesktopOs::MacOs => "icns",
            DesktopOs::Linux => "png",
            DesktopOs::Windows => "ico",
        };
        Self {
            source: source.to_path_buf(),
            output_name: format!("{stem}.{ext}"),
        }
    }
}

/// One file a bundle lays down: its bundle-relative path and where its bytes come
/// from.
///
/// A typed pair rather than loose tuples so the layout is inspectable and a
/// golden test can assert the full file set without materialising bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleFile {
    /// The path of this file relative to the bundle root, using `/` separators.
    pub rel_path: String,
    /// Where the file's bytes come from.
    pub content: BundleContent,
}

/// The origin of a bundle file's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleContent {
    /// Copy the compiled app binary here (marked executable).
    AppBinary,
    /// Copy the rendered per-OS icon here from the source icon.
    Icon,
    /// Write this literal generated text (a plist, a `.desktop`, a README note).
    Generated(String),
}

/// The complete, materialization-free description of a desktop bundle for one OS:
/// its root directory name and the ordered set of files it contains.
///
/// Pure data, derived from the identity + permissions + icon plan, so a golden
/// test can assert the full layout of a mac/Windows bundle on this Linux box
/// without running that OS's toolchain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleLayout {
    /// The desktop OS this layout targets.
    pub os: DesktopOs,
    /// The bundle root directory name (e.g. `AppName.app` or `appname/`).
    pub root_name: String,
    /// The ordered files the bundle contains.
    pub files: Vec<BundleFile>,
}

/// Assemble the bundle layout for `os` from the app identity, its accepted
/// capabilities, and an optional source icon.
///
/// The macOS `Info.plist` usage-description keys are derived from `accepts`
/// through [`permissions::derive_permissions`] — never authored here. A `None`
/// icon omits the icon file (and the plist/`.desktop` icon reference) rather than
/// inventing one.
///
/// # Errors
/// Propagates any error from the permission derivation (infallible over today's
/// closed capability vocabulary, but surfaced for forward-compatibility).
pub fn layout(
    os: DesktopOs,
    identity: &BundleIdentity,
    accepts: &BTreeSet<Capability>,
    icon: Option<&Path>,
) -> Result<BundleLayout, super::super::CliError> {
    let icon_plan = icon.map(|src| IconPlan::new(os, src, &identity.name));
    let bin_name = sanitise_identifier(&identity.name);
    let mut files = Vec::new();

    match os {
        DesktopOs::MacOs => {
            // The macOS bundle directory keeps the app's display name (spaces and
            // punctuation are legal in a `.app` name), so — unlike the fully
            // sanitised Linux/Windows roots — this is the one root_name derived
            // from the raw manifest name. That raw name reaches
            // `dist_dir.join(root_name)` and `remove_dir_all` in `materialise`, so
            // a name that is not a single, non-traversing path component
            // (`../victim`, `a/b`, an absolute path, a NUL byte) would let the
            // bundler write and delete OUTSIDE dist_dir or under another name.
            // Refuse fail-closed before any layout is returned: the bundle root
            // must be exactly one name that reads back as itself.
            let root_name = format!("{}.app", identity.name);
            reject_traversing_bundle_root(&root_name, &identity.name)?;
            // The Apple platform a macOS bundle derives its permissions for —
            // taken from the OS mapping, never hardcoded, so the platform a
            // bundle renders for is a single source.
            let apple = os.apple_platform().unwrap_or(Platform::MacOs);
            let plist = render_info_plist(apple, identity, accepts, icon_plan.as_ref())?;
            files.push(BundleFile {
                rel_path: format!("Contents/MacOS/{bin_name}"),
                content: BundleContent::AppBinary,
            });
            files.push(BundleFile {
                rel_path: "Contents/Info.plist".to_owned(),
                content: BundleContent::Generated(plist),
            });
            if let Some(plan) = &icon_plan {
                files.push(BundleFile {
                    rel_path: format!("Contents/Resources/{}", plan.output_name),
                    content: BundleContent::Icon,
                });
            }
            files.push(BundleFile {
                rel_path: "Contents/RUNTIME.txt".to_owned(),
                content: BundleContent::Generated(os.webview_runtime_note().to_owned()),
            });
            Ok(BundleLayout {
                os,
                root_name,
                files,
            })
        }
        DesktopOs::Linux => {
            let desktop = render_desktop_entry(identity, &bin_name, icon_plan.as_ref());
            files.push(BundleFile {
                rel_path: format!("bin/{bin_name}"),
                content: BundleContent::AppBinary,
            });
            files.push(BundleFile {
                rel_path: format!("{bin_name}.desktop"),
                content: BundleContent::Generated(desktop),
            });
            if let Some(plan) = &icon_plan {
                files.push(BundleFile {
                    rel_path: plan.output_name.clone(),
                    content: BundleContent::Icon,
                });
            }
            files.push(BundleFile {
                rel_path: "RUNTIME.txt".to_owned(),
                content: BundleContent::Generated(os.webview_runtime_note().to_owned()),
            });
            Ok(BundleLayout {
                os,
                root_name: bin_name,
                files,
            })
        }
        DesktopOs::Windows => {
            files.push(BundleFile {
                rel_path: format!("{bin_name}.exe"),
                content: BundleContent::AppBinary,
            });
            if let Some(plan) = &icon_plan {
                files.push(BundleFile {
                    rel_path: plan.output_name.clone(),
                    content: BundleContent::Icon,
                });
            }
            files.push(BundleFile {
                rel_path: "RUNTIME.txt".to_owned(),
                content: BundleContent::Generated(os.webview_runtime_note().to_owned()),
            });
            Ok(BundleLayout {
                os,
                root_name: bin_name,
                files,
            })
        }
    }
}

/// Render the macOS `Info.plist`, assembling the fixed identity keys and the
/// derived usage-description keys.
///
/// The permission keys come ONLY from [`permissions::derive_permissions`] on the
/// given Apple `apple_platform`; this function never writes an
/// `NS…UsageDescription` key itself. An app that accepts no permission-bearing
/// web capability yields a plist with no usage-description keys.
fn render_info_plist(
    apple_platform: Platform,
    identity: &BundleIdentity,
    accepts: &BTreeSet<Capability>,
    icon: Option<&IconPlan>,
) -> Result<String, super::super::CliError> {
    use std::fmt::Write as _;

    let permission_set = permissions::derive_permissions(accepts, apple_platform)?;
    let usage_entries = permission_set.to_info_plist_entries();

    let mut body = String::new();
    // Writing into an owned buffer never fails; the `let _` discards the always-Ok
    // `fmt::Result`.
    let mut pair = |key: &str, value: &str| {
        let _ = writeln!(body, "\t<key>{}</key>", plist_escape(key));
        let _ = writeln!(body, "\t<string>{}</string>", plist_escape(value));
    };
    pair("CFBundleName", &identity.name);
    pair("CFBundleDisplayName", &identity.name);
    pair("CFBundleIdentifier", &identity.identifier);
    pair("CFBundleVersion", &identity.version);
    pair("CFBundleShortVersionString", &identity.version);
    pair("CFBundleExecutable", &sanitise_identifier(&identity.name));
    pair("CFBundlePackageType", "APPL");
    if let Some(plan) = icon {
        // The icon-file key drops the extension, per Apple's `CFBundleIconFile`.
        let stem = plan
            .output_name
            .rsplit_once('.')
            .map_or(plan.output_name.as_str(), |(stem, _ext)| stem);
        pair("CFBundleIconFile", stem);
    }
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

/// Escape an author-supplied string for a plist text node. Bundle identity values
/// are author-supplied, so they are escaped even though the derived permission
/// keys/purposes are fixed ASCII. Routes through the packager's shared XML escape
/// ([`crate::pack::xml_escape`]).
fn plist_escape(text: &str) -> String {
    crate::pack::xml_escape(text)
}

/// Render a freedesktop `.desktop` launcher for the Linux bundle.
fn render_desktop_entry(
    identity: &BundleIdentity,
    bin_name: &str,
    icon: Option<&IconPlan>,
) -> String {
    let mut entry = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={}\n\
         Exec=bin/{bin_name}\n\
         Terminal=false\n\
         Categories=Utility;\n",
        desktop_value_escape(&identity.name)
    );
    if let Some(plan) = icon {
        use std::fmt::Write as _;
        let stem = plan
            .output_name
            .rsplit_once('.')
            .map_or(plan.output_name.as_str(), |(stem, _ext)| stem);
        let _ = writeln!(entry, "Icon={}", desktop_value_escape(stem));
    }
    entry
}

/// Escape a `.desktop` value: the format reserves control characters and treats a
/// literal backslash specially. Newlines/tabs would break the single-line
/// key=value grammar, so they are stripped; backslashes are doubled.
fn desktop_value_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\n' | '\r' | '\t' => {}
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out
}

/// Materialise `layout` as the bundle `dist/<root_name>` inside the owned `dist`.
///
/// Generated files are written verbatim, the compiled `binary` is copied (and
/// made executable on Unix), and the source `icon` is rendered into the bundle's
/// per-OS icon slot. A fresh, deterministic tree: an existing bundle directory of
/// the same name is removed first so a re-pack never leaves stale files behind.
/// Every path is a [`crate::output_dir::OwnedPath`], so a symlink planted in the owned `dist` is
/// refused — never removed through, written through, or copied onto.
///
/// Icon rendering is a byte copy of the source into the per-OS icon filename: the
/// source PNG is a valid Linux icon as-is, and the macOS `.icns` / Windows `.ico`
/// containers require an OS/tooling conversion step that belongs on their runner.
/// The bundle therefore carries the icon under its correct per-OS name; a real
/// `.icns`/`.ico` re-encode is the runner's job.
///
/// # Errors
/// [`CliError::OutputRefused`] for a symlink or non-plain name on the way;
/// [`CliError::Io`] naming the exact path on any filesystem failure.
pub fn materialise(
    layout: &BundleLayout,
    binary: &Path,
    icon: Option<&Path>,
    dist: &OwnedDir,
) -> Result<PathBuf, CliError> {
    let bundle_root = dist.path_to(&layout.root_name)?;
    bundle_root.remove()?;
    bundle_root.ensure_dir()?;

    for file in &layout.files {
        let out_file =
            dist.path_to(Path::new(&layout.root_name).join(rel_to_native(&file.rel_path)))?;
        match &file.content {
            BundleContent::Generated(text) => out_file.write(text.as_bytes())?,
            BundleContent::AppBinary => {
                out_file.copy_from(binary)?;
                make_executable(&out_file.path())?;
            }
            BundleContent::Icon => {
                // Present only when the layout carries an icon, which the layout
                // builder emits only when a source icon was given.
                if let Some(src) = icon {
                    out_file.copy_from(src)?;
                }
            }
        }
    }
    Ok(bundle_root.path())
}

/// Translate a bundle-relative `/`-separated path into a native `PathBuf`.
fn rel_to_native(rel: &str) -> PathBuf {
    rel.split('/').collect()
}

/// Set the owner-execute bit on a materialised file on Unix; a no-op elsewhere.
#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::symlink_metadata(path).map_err(|e| crate::io_err(path, e))?;
    let mut perms = meta.permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(path, perms).map_err(|e| crate::io_err(path, e))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), CliError> {
    Ok(())
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

    // ── OS resolution ─────────────────────────────────────────────────────────

    #[test]
    fn explicit_os_parses() {
        assert_eq!(resolve_os(Some("linux")), Ok(DesktopOs::Linux));
        assert_eq!(resolve_os(Some("macos")), Ok(DesktopOs::MacOs));
        assert_eq!(resolve_os(Some("windows")), Ok(DesktopOs::Windows));
    }

    #[test]
    fn unknown_os_is_refused_naming_it() {
        let err = resolve_os(Some("plan9")).expect_err("plan9 is not a desktop OS");
        assert_eq!(err, DesktopRefusal::UnknownOs("plan9".to_owned()));
        assert!(err.to_string().contains("plan9"));
    }

    #[test]
    fn bare_target_resolves_to_the_host() {
        // On any supported CI host this resolves; the value must match the host.
        if let Some(host) = DesktopOs::host() {
            assert_eq!(resolve_os(None), Ok(host));
        }
    }

    #[test]
    fn os_round_trips_its_wire_name() {
        for os in [DesktopOs::Linux, DesktopOs::MacOs, DesktopOs::Windows] {
            assert_eq!(os.as_str().parse::<DesktopOs>(), Ok(os));
        }
    }

    // ── Shape refusal ─────────────────────────────────────────────────────────

    #[test]
    fn a_webview_app_is_packageable() {
        require_webview(AppShape::WebView).expect("a webview app packages");
    }

    #[test]
    fn a_non_webview_app_is_refused_naming_its_shape() {
        for (shape, name) in [
            (AppShape::Web, "web"),
            (AppShape::Terminal, "terminal"),
            (AppShape::Program, "program"),
        ] {
            let err = require_webview(shape).expect_err("a non-webview app is refused");
            assert_eq!(err, DesktopRefusal::NotWebView { shape: name });
            assert!(
                err.to_string().contains(name),
                "refusal names the shape {name}"
            );
        }
    }

    // ── Info.plist: permissions come only from the permission derivation ──────

    #[test]
    fn geolocation_yields_the_location_usage_key() {
        // An app accepting geolocation must produce a plist carrying the derived
        // location usage key with its non-empty purpose.
        let identity = BundleIdentity::new("Geo App", Some("1.2.3"), None);
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let layout = layout(DesktopOs::MacOs, &identity, &a, None).expect("mac layout");
        let plist = plist_text(&layout);
        assert!(
            plist.contains("NSLocationWhenInUseUsageDescription"),
            "plist carries the location usage key: {plist}"
        );
        assert!(
            plist.contains("This app uses your location"),
            "plist carries the derived purpose string: {plist}"
        );
    }

    #[test]
    fn an_app_accepting_nothing_has_no_usage_keys() {
        // deny-by-default: no accepted web axis ⇒ no NS…UsageDescription key.
        let identity = BundleIdentity::new("Pure App", Some("0.1.0"), None);
        let layout = layout(DesktopOs::MacOs, &identity, &accepts(&[]), None).expect("mac layout");
        let plist = plist_text(&layout);
        assert!(
            !plist.contains("UsageDescription"),
            "a pure app declares no usage-description keys: {plist}"
        );
        // But the identity keys are still present.
        assert!(plist.contains("CFBundleIdentifier"));
        assert!(plist.contains("<string>0.1.0</string>"));
    }

    #[test]
    fn a_non_web_capability_backs_no_usage_key() {
        // A server-side capability (network) has no native-shell permission
        // surface; the plist must carry no usage key for it.
        let identity = BundleIdentity::new("Net App", None, None);
        let a = accepts(&[Capability::Network, Capability::NativeFfi]);
        let layout = layout(DesktopOs::MacOs, &identity, &a, None).expect("mac layout");
        assert!(!plist_text(&layout).contains("UsageDescription"));
    }

    /// Extract the rendered `Info.plist` text from a mac layout.
    fn plist_text(layout: &BundleLayout) -> String {
        generated_at(layout, "Contents/Info.plist").expect("mac layout has an Info.plist")
    }

    /// The literal generated text of the file at `rel_path`, if any.
    fn generated_at(layout: &BundleLayout, rel_path: &str) -> Option<String> {
        layout.files.iter().find_map(|file| match &file.content {
            BundleContent::Generated(text) if file.rel_path == rel_path => Some(text.clone()),
            _ => None,
        })
    }

    // ── Layout shape per OS ───────────────────────────────────────────────────

    #[test]
    fn mac_layout_places_binary_plist_and_icon() {
        let identity = BundleIdentity::new("My App", Some("2.0.0"), None);
        let icon = PathBuf::from("/tmp/icon.png");
        let layout =
            layout(DesktopOs::MacOs, &identity, &accepts(&[]), Some(&icon)).expect("mac layout");
        assert_eq!(layout.root_name, "My App.app");
        let paths: Vec<&str> = layout.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(paths.contains(&"Contents/MacOS/my-app"));
        assert!(paths.contains(&"Contents/Info.plist"));
        assert!(paths.contains(&"Contents/Resources/my-app.icns"));
    }

    #[test]
    fn a_traversing_app_name_is_refused_for_the_mac_bundle_root() {
        // A manifest name is untrusted. On macOS the `.app` root keeps the raw
        // name, which reaches `dist_dir.join(root_name)` and `remove_dir_all`; a
        // name that resolves outside `dist_dir` must be refused BEFORE a layout is
        // returned, never joined. Each of these would escape the distribution
        // directory (write + delete an arbitrary path) if the raw name were used.
        for hostile in [
            "../victim",
            "../../etc/cron.d/x",
            "a/b",
            "nested/../escape",
            "/abs/root",
            "with/slash",
            "nul\0byte",
        ] {
            let identity = BundleIdentity::new(hostile, Some("1.0.0"), None);
            let result = layout(DesktopOs::MacOs, &identity, &accepts(&[]), None);
            assert!(
                matches!(result, Err(crate::CliError::Usage(_))),
                "a traversing macOS bundle name {hostile:?} must be refused, not joined, got {result:?}"
            );
        }
    }

    #[test]
    fn a_plain_display_name_still_makes_a_valid_mac_bundle_root() {
        // The refusal must not over-reject: a normal display name with spaces and
        // punctuation is a legal single `.app` component and must still pass.
        for ok in ["My App", "App 2.0", "café", "under_score", "Dot.In.Name"] {
            let identity = BundleIdentity::new(ok, Some("1.0.0"), None);
            let layout =
                layout(DesktopOs::MacOs, &identity, &accepts(&[]), None).expect("mac layout");
            assert_eq!(layout.root_name, format!("{ok}.app"));
        }
    }

    #[test]
    fn linux_layout_has_binary_desktop_and_icon() {
        let identity = BundleIdentity::new("My App", Some("2.0.0"), None);
        let icon = PathBuf::from("/tmp/icon.png");
        let layout =
            layout(DesktopOs::Linux, &identity, &accepts(&[]), Some(&icon)).expect("linux layout");
        let paths: Vec<&str> = layout.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(paths.contains(&"bin/my-app"));
        assert!(paths.contains(&"my-app.desktop"));
        assert!(paths.contains(&"my-app.png"));
        // The .desktop launcher references the binary and icon.
        let desktop = generated(&layout, "my-app.desktop");
        assert!(desktop.contains("Exec=bin/my-app"));
        assert!(desktop.contains("Icon=my-app"));
    }

    #[test]
    fn windows_layout_has_exe_and_icon() {
        let identity = BundleIdentity::new("My App", None, None);
        let icon = PathBuf::from("/tmp/icon.png");
        let layout = layout(DesktopOs::Windows, &identity, &accepts(&[]), Some(&icon))
            .expect("windows layout");
        let paths: Vec<&str> = layout.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert!(paths.contains(&"my-app.exe"));
        assert!(paths.contains(&"my-app.ico"));
    }

    #[test]
    fn a_none_icon_omits_the_icon_file() {
        let identity = BundleIdentity::new("My App", None, None);
        for os in [DesktopOs::Linux, DesktopOs::MacOs, DesktopOs::Windows] {
            let layout = layout(os, &identity, &accepts(&[]), None).expect("layout");
            assert!(
                layout
                    .files
                    .iter()
                    .all(|f| f.content != BundleContent::Icon),
                "no icon file on {os:?} when the manifest declares none"
            );
        }
    }

    // ── Runtime-dependency note is always carried ─────────────────────────────

    #[test]
    fn every_bundle_carries_its_webview_runtime_note() {
        let identity = BundleIdentity::new("My App", None, None);
        for os in [DesktopOs::Linux, DesktopOs::MacOs, DesktopOs::Windows] {
            let layout = layout(os, &identity, &accepts(&[]), None).expect("layout");
            let note = generated_containing(&layout, "RUNTIME.txt");
            assert_eq!(note, os.webview_runtime_note());
            assert!(!note.is_empty(), "the {os:?} runtime note is non-empty");
        }
    }

    #[test]
    fn linux_note_names_webkitgtk() {
        assert!(
            DesktopOs::Linux
                .webview_runtime_note()
                .contains("WebKitGTK")
        );
    }

    #[test]
    fn windows_note_names_webview2() {
        assert!(
            DesktopOs::Windows
                .webview_runtime_note()
                .contains("WebView2")
        );
    }

    // ── Identity sanitisation ─────────────────────────────────────────────────

    #[test]
    fn identifier_is_synthesised_from_the_name_when_absent() {
        let id = BundleIdentity::new("My Cool App!", None, None);
        assert_eq!(id.identifier, "com.ipe.my-cool-app");
        assert_eq!(id.version, "0.0.0");
    }

    #[test]
    fn an_explicit_identifier_is_kept() {
        let id = BundleIdentity::new("X", Some("1.0.0"), Some("io.example.x"));
        assert_eq!(id.identifier, "io.example.x");
    }

    /// The literal generated text of the file at `rel_path`.
    fn generated(layout: &BundleLayout, rel_path: &str) -> String {
        generated_at(layout, rel_path).expect("a generated file at the path")
    }

    /// The literal generated text of the file whose path ends with `suffix`.
    fn generated_containing(layout: &BundleLayout, suffix: &str) -> String {
        layout
            .files
            .iter()
            .find_map(|file| match &file.content {
                BundleContent::Generated(text) if file.rel_path.ends_with(suffix) => {
                    Some(text.clone())
                }
                _ => None,
            })
            .expect("a generated file ending in the suffix")
    }
}
