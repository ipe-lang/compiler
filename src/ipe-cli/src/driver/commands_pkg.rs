use super::{
    CliError, build_emitted_project, build_project, build_source_graph,
    build_test_with_project_sources, build_with_sibling_discovery,
    capabilities_including_served_widgets, cargo_target_directory, classify_entry_shape,
    create_source_root, default_entry, discover_manifest, emit_machine_error, emitted_bin_filename,
    force_cargo_terminal_ui, resolve_runtime, resolve_vendored_runtime_dir, run_build,
    runtime_context_for_message, typecheck_entry_via_graph,
};
use crate::publisher::{AttestedActor, BlessedPublisher};
use crate::{
    Applicability, BTreeMap, Diagnostic, HelpLine, Interner, Path, PathBuf, Suggestion, Write,
    audit, cli_args, contained_path, delivery, ffi, fmt, fs, index, pack, progress, project,
    publish, resolve, scratch, style, toolchain, version_check,
};

/// Whether a delivery-routed bundle is a fast development build or a production
/// distributable. `build web <host>` yields [`BundleProfile::Dev`]; `release web
/// <host>` yields [`BundleProfile::Release`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleProfile {
    /// A fast, unoptimised bundle for the inner loop — a debug binary and the
    /// per-OS layout for local inspection. The `build` verb's bundle.
    Dev,
    /// The production distributable — an optimised binary and the per-OS runner
    /// notes a distributor follows to sign and finish the artifact. The `release`
    /// verb's bundle.
    Release,
}

impl BundleProfile {
    /// The cargo build the bundle's binary is compiled with: a plain debug build
    /// for [`Self::Dev`], an optimised `--release` build for [`Self::Release`].
    /// The one place the profile decides the compile, so the two bundle verbs
    /// stay a single packager parameterised by profile, not two code paths.
    const fn cargo_release(self) -> bool {
        matches!(self, Self::Release)
    }

    /// The compiled binary's `target/` profile subdirectory (`debug` / `release`),
    /// matching [`Self::cargo_release`].
    const fn target_subdir(self) -> &'static str {
        match self {
            Self::Dev => "debug",
            Self::Release => "release",
        }
    }
}

/// The delivery host a bundling verb (`build`/`release`) targets.
///
/// Resolved from the delivery grammar's [`delivery::Host`]: `desktop` routes to
/// the webview-native desktop packager, `ios`/`android` to the mobile
/// system-webview packager. The served/default host produces no bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleHost {
    /// `web desktop` — a self-contained per-OS desktop bundle for the host OS.
    Desktop,
    /// `web solo ios` / `web solo android` — a native mobile system-webview shell.
    Mobile(pack::mobile::MobileOs),
}

impl BundleHost {
    /// Map a resolved delivery [`delivery::Host`] onto the bundle host it
    /// packages, or `None` for the served/default host (which produces a plain
    /// artifact, not a bundle). The mobile host word is the delivery grammar's own
    /// `ios`/`android`, so the closed-set resolution below cannot fail in practice
    /// — a refusal is surfaced, never panicked.
    ///
    /// # Errors
    /// [`CliError::UsageOwned`] if the mobile OS resolution refuses (unreachable
    /// through the typed [`delivery::Host`]).
    pub fn from_delivery_host(host: delivery::Host) -> Result<Option<Self>, CliError> {
        let mobile = |word| {
            pack::mobile::resolve_os(Some(word))
                .map(Self::Mobile)
                .map_err(|r| CliError::UsageOwned(r.to_string()))
        };
        Ok(match host {
            delivery::Host::Default => None,
            delivery::Host::Desktop => Some(Self::Desktop),
            delivery::Host::Ios => Some(mobile("ios")?),
            delivery::Host::Android => Some(mobile("android")?),
        })
    }
}

/// Produce the delivery-routed application bundle for a resolved `web <host>`
/// delivery — the single entry point `build`/`release` call once they know the
/// bundle host and profile.
///
/// `web desktop` lays out a webview-native desktop bundle; `web solo ios|android`
/// builds the client-wasm SPA and lays out a native mobile system-webview shell.
/// The permission-manifest derivation ([`pack::permissions`]) remains the single
/// source of truth for what each bundle may do — this routing never authors a
/// permission, only chooses which packager runs.
///
/// # Errors
/// A [`pack::desktop::DesktopRefusal`] / [`pack::mobile::MobileRefusal`] wrapped
/// as [`CliError::UsageOwned`] when the app's shape/target does not fit the host;
/// the underlying build's errors; [`CliError::Io`] on any filesystem failure.
pub fn bundle_delivery(
    host: BundleHost,
    profile: BundleProfile,
    path: Option<&str>,
) -> Result<(), CliError> {
    match host {
        BundleHost::Desktop => pack_desktop(profile, path),
        BundleHost::Mobile(os) => pack_mobile(os, profile, path),
    }
}

// ── Pure gate layer ──────────────────────────────────────────────────────────
//
// These functions carry the fail-closed security gates (shape + permission
// validation) that must fire BEFORE any cargo build or I/O. They accept only
// typed values already parsed from the manifest, so they are exercisable in
// unit tests without a real project on disk.

/// Classify an app's [`pack::desktop::AppShape`] from its manifest-declared
/// shape (when present) or by inspecting the entry source (when absent).
///
/// The shape classification is a pure function of its inputs: no build, no I/O
/// beyond the entry-source read that `classify_entry_shape` performs when no
/// declared shape is available.
///
/// # Errors
/// [`CliError`] forwarded from [`classify_entry_shape`] when entry-source
/// classification is needed and the source cannot be read or parsed.
pub fn classify_desktop_shape(
    declared: Option<project::EntryShape>,
    root: &Path,
) -> Result<pack::desktop::AppShape, CliError> {
    match declared {
        Some(project::EntryShape::Web) => Ok(pack::desktop::AppShape::Web),
        Some(project::EntryShape::WebView) => Ok(pack::desktop::AppShape::WebView),
        Some(project::EntryShape::Terminal) => Ok(pack::desktop::AppShape::Terminal),
        Some(project::EntryShape::Program) => Ok(pack::desktop::AppShape::Program),
        None => match classify_entry_shape(root)? {
            delivery::Shape::Web => Ok(pack::desktop::AppShape::WebView),
            delivery::Shape::Tui | delivery::Shape::Cli => Ok(pack::desktop::AppShape::Terminal),
            // A `script` renders nothing and a `worker` runs a view-less loop
            // (a server is a `script` running `Server.listen`, rendering http
            // rather than a desktop window); all classify as a plain program so
            // the webview gate refuses them by name.
            delivery::Shape::Script | delivery::Shape::Worker => {
                Ok(pack::desktop::AppShape::Program)
            }
        },
    }
}

/// Gate the desktop bundle's app shape: refuse any shape that is not a
/// webview-capable `Web` or `WebView` app.
///
/// This is the principle-1 fail-closed gate that fires BEFORE any cargo build.
/// It delegates to [`pack::desktop::require_webview`], which is the single
/// source of truth for the webview requirement.
///
/// # Errors
/// [`CliError::UsageOwned`] wrapping [`pack::desktop::DesktopRefusal`] when the
/// shape is not webview-capable.
pub fn validate_desktop_shape(
    declared: Option<project::EntryShape>,
    root: &Path,
) -> Result<(), CliError> {
    let shape = classify_desktop_shape(declared, root)?;
    pack::desktop::require_webview(shape).map_err(|r| CliError::UsageOwned(r.to_string()))
}

/// Build the [`pack::mobile::WebSpaCapability`] from the manifest's declared
/// shape (when present) or by classifying the entry source.
///
/// # Errors
/// [`CliError`] forwarded from [`classify_entry_shape`] when entry-source
/// classification is needed and the source cannot be read or parsed.
pub fn classify_mobile_spa_cap(
    declared: Option<project::EntryShape>,
    root: &Path,
    wasm: &project::WasmConfig,
) -> Result<pack::mobile::WebSpaCapability, CliError> {
    let shape_is_web = match declared {
        Some(s) => s == project::EntryShape::Web,
        None => classify_entry_shape(root)? == delivery::Shape::Web,
    };
    Ok(pack::mobile::WebSpaCapability {
        shape_is_web,
        wasm_enabled: wasm.implies_wasm_target(),
    })
}

/// Gate the mobile bundle's web-SPA capability: refuse any shape that is not a
/// wasm-enabled `Web` app.
///
/// This is the principle-1 fail-closed gate that fires BEFORE any wasm build.
/// It delegates to [`pack::mobile::require_web_spa`], the single source of
/// truth for the web-SPA requirement.
///
/// # Errors
/// [`CliError::UsageOwned`] wrapping [`pack::mobile::MobileRefusal`] when the
/// shape is not a wasm-enabled `Web` app.
pub fn validate_mobile_shape(
    declared: Option<project::EntryShape>,
    root: &Path,
    wasm: &project::WasmConfig,
) -> Result<(), CliError> {
    let cap = classify_mobile_spa_cap(declared, root, wasm)?;
    pack::mobile::require_web_spa(cap).map_err(|r| CliError::UsageOwned(r.to_string()))
}

// ── Assembly seam ─────────────────────────────────────────────────────────────
//
// `BundleAssembler` owns the cargo-spawn and filesystem I/O that must happen
// after the pure gates pass. `pack_desktop` and `pack_mobile` are thin wrappers
// that parse the manifest, run the gates, then delegate here.

/// Owns the cargo-build and filesystem materialisation steps for a bundle.
///
/// The I/O half of the seam, never the validation half. It is unreachable
/// except through a gate witness ([`GatedDesktop`] / [`GatedMobile`]): its
/// constructor and assembly methods are private, so no in-crate caller can
/// obtain a runnable assembler without first passing the fail-closed shape gate
/// that mints the witness. "Assemble an ungated shape" has no representation.
struct BundleAssembler<'a> {
    manifest: &'a project::ProjectManifest,
    manifest_path: &'a Path,
    profile: BundleProfile,
}

/// A desktop-shape gate witness: proof that [`validate_desktop_shape`] passed
/// for the wrapped assembler. The ONLY way to obtain one is
/// [`BundleAssembler::gate_desktop`], which runs the gate first; its
/// [`assemble`](GatedDesktop::assemble) is the sole entry to desktop assembly.
pub struct GatedDesktop<'a>(BundleAssembler<'a>);

/// A mobile-shape gate witness: proof that [`validate_mobile_shape`] passed for
/// the wrapped assembler. The ONLY way to obtain one is
/// [`BundleAssembler::gate_mobile`], which runs the gate first; its
/// [`assemble`](GatedMobile::assemble) is the sole entry to mobile assembly.
pub struct GatedMobile<'a>(BundleAssembler<'a>);

impl GatedDesktop<'_> {
    /// Emit + compile the app and materialise the desktop bundle. Reachable
    /// only by holding this witness, so the shape gate is already proven passed.
    ///
    /// # Errors
    /// Build/emit errors from the underlying compile; [`CliError::Io`] on any
    /// filesystem failure while materialising the bundle.
    pub fn assemble(self, os: pack::desktop::DesktopOs) -> Result<(), CliError> {
        self.0.assemble_desktop(os)
    }
}

impl GatedMobile<'_> {
    /// Build the wasm SPA and materialise the mobile shell. Reachable only by
    /// holding this witness, so the shape gate is already proven passed.
    ///
    /// # Errors
    /// The wasm build's own errors; [`CliError::Io`] on any filesystem failure
    /// while collecting the bundle or materialising the shell.
    pub fn assemble(self, os: pack::mobile::MobileOs) -> Result<(), CliError> {
        self.0.assemble_mobile(os)
    }
}

impl<'a> BundleAssembler<'a> {
    /// Construct an assembler for `manifest` at the given profile. Private: a
    /// runnable assembler is reachable only through a gate witness.
    const fn new(
        manifest: &'a project::ProjectManifest,
        manifest_path: &'a Path,
        profile: BundleProfile,
    ) -> Self {
        Self {
            manifest,
            manifest_path,
            profile,
        }
    }

    /// Run the desktop shape gate ([`validate_desktop_shape`]) and, only when it
    /// passes, mint a [`GatedDesktop`] witness wrapping the assembler. This is
    /// the sole constructor of a runnable desktop assembler, so ungated desktop
    /// assembly is unrepresentable.
    ///
    /// # Errors
    /// [`CliError::UsageOwned`] wrapping a [`pack::desktop::DesktopRefusal`] when
    /// the shape is not webview-capable; classification errors from the entry
    /// source when no shape is declared.
    pub fn gate_desktop(
        manifest: &'a project::ProjectManifest,
        manifest_path: &'a Path,
        profile: BundleProfile,
        root: &Path,
    ) -> Result<GatedDesktop<'a>, CliError> {
        validate_desktop_shape(manifest.default_program().and_then(|p| p.shape), root)?;
        Ok(GatedDesktop(Self::new(manifest, manifest_path, profile)))
    }

    /// Run the mobile shape gate ([`validate_mobile_shape`]) and, only when it
    /// passes, mint a [`GatedMobile`] witness wrapping the assembler. This is the
    /// sole constructor of a runnable mobile assembler, so ungated mobile
    /// assembly is unrepresentable.
    ///
    /// # Errors
    /// [`CliError::UsageOwned`] wrapping a [`pack::mobile::MobileRefusal`] when
    /// the shape is not a wasm-enabled `Web` app; classification errors from the
    /// entry source when no shape is declared.
    pub fn gate_mobile(
        manifest: &'a project::ProjectManifest,
        manifest_path: &'a Path,
        profile: BundleProfile,
        root: &Path,
    ) -> Result<GatedMobile<'a>, CliError> {
        validate_mobile_shape(
            manifest.default_program().and_then(|p| p.shape),
            root,
            &manifest.wasm,
        )?;
        Ok(GatedMobile(Self::new(manifest, manifest_path, profile)))
    }

    /// Emit + compile the app to a binary, generate the desktop bundle layout,
    /// and materialise (Linux) or describe (macOS/Windows) the bundle on disk.
    /// Private: reached only through a [`GatedDesktop`] witness, so the shape
    /// gate is already proven passed.
    ///
    /// # Errors
    /// Build/emit errors from the underlying compile; [`CliError::Io`] on any
    /// filesystem failure while materialising the bundle.
    fn assemble_desktop(&self, os: pack::desktop::DesktopOs) -> Result<(), CliError> {
        let manifest = self.manifest;
        let identity = pack::desktop::BundleIdentity::new(
            &manifest.name,
            manifest
                .version
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            None,
        );
        let accepts = &manifest.capabilities_accept;
        let icon = manifest.icon.as_deref();

        let layout = pack::desktop::layout(os, &identity, accepts, icon)?;

        // Emit + compile the project to a binary. A webview app carries the
        // system webview as a dynamic dependency, so this is a plain
        // (non-static) native build.
        let build_dir = manifest.root.join("out").join("rust");
        let runtime_dir = resolve_vendored_runtime_dir(None, false)?;
        build_project(self.manifest_path, &build_dir, &runtime_dir)?;

        let cargo_bin = toolchain::require_cargo(toolchain::ToolIntent::Build)?;
        let mut cargo = std::process::Command::new(cargo_bin.path());
        cargo.arg("build").current_dir(&build_dir);
        // A `release web desktop` bundle carries an optimised binary; the
        // `build` dev bundle carries a plain debug one.
        if self.profile.cargo_release() {
            cargo.arg("--release");
        }
        force_cargo_terminal_ui(&mut cargo);
        build_emitted_project(&mut cargo, "the desktop app", None, &build_dir)?;

        // Locate the compiled binary via cargo metadata (the target dir may be
        // a global CARGO_TARGET_DIR), then materialise (Linux) or describe
        // (macOS/Windows).
        let target_dir = cargo_target_directory(&build_dir)?;
        let bin_name = emitted_bin_filename(&build_dir);
        let binary = target_dir
            .join(self.profile.target_subdir())
            .join(&bin_name);
        if !binary.is_file() {
            return Err(CliError::UsageOwned(format!(
                "expected app binary at {} — cargo build succeeded but the binary is missing",
                binary.display()
            )));
        }

        let dist = manifest.root.join("dist").join(os.as_str());
        pack::desktop::materialise(&layout, &binary, icon, &dist)
            .map_err(|e| io_err(&e.path, e.source))?;

        println!(
            "packaged `{}` for {} → {}",
            manifest.name,
            os.as_str(),
            dist.join(&layout.root_name).display()
        );
        println!("  {}", os.webview_runtime_note());
        if os != pack::desktop::DesktopOs::Linux {
            println!(
                "  note: the {} bundle layout is written here, but a signed, runnable {} \
                 artifact must be produced on a {} runner (unsigned; cross-tooling out of scope).",
                os.as_str(),
                os.as_str(),
                os.as_str()
            );
        }
        Ok(())
    }

    /// Build the wasm SPA, collect its `www/` tree, generate the mobile shell
    /// layout, and materialise the shell on disk. Private: reached only through
    /// a [`GatedMobile`] witness, so the shape gate is already proven passed.
    ///
    /// # Errors
    /// The wasm build's own errors; [`CliError::Io`] on any filesystem failure
    /// while collecting the bundle or materialising the shell.
    fn assemble_mobile(&self, os: pack::mobile::MobileOs) -> Result<(), CliError> {
        let manifest = self.manifest;
        let identity = pack::desktop::BundleIdentity::new(
            &manifest.name,
            manifest
                .version
                .as_ref()
                .map(ToString::to_string)
                .as_deref(),
            None,
        );
        let accepts = &manifest.capabilities_accept;
        let icon = manifest.icon.as_deref();

        // Build the `--target wasm` SPA into the project's `out/rust`, then
        // collect its `www/` tree. The wasm bundle pipeline (emit + cargo +
        // wasm-bindgen) is the single source of the hostable bundle; invoking
        // it through this binary keeps that pipeline authoritative rather than
        // re-implemented here.
        let build_dir = manifest.root.join("out").join("rust");
        build_wasm_for_mobile(self.manifest_path, &build_dir, self.profile)?;
        let www_dir = build_dir.join("www");
        let bundle = pack::mobile::SpaBundle::from_www_dir(&www_dir)
            .map_err(|e| CliError::UsageOwned(e.to_string()))?;

        let layout = pack::mobile::layout(os, &identity, accepts, &bundle, icon)?;

        let dist = manifest.root.join("dist").join(os.as_str());
        let shell_root = pack::mobile::materialise(&layout, icon, &dist)
            .map_err(|e| io_err(&e.path, e.source))?;

        println!(
            "packaged `{}` for {} → {}",
            manifest.name,
            os.as_str(),
            shell_root.display()
        );
        if os.build_runs_on_linux() {
            println!(
                "  note: an Android shell project is written here; run `./gradlew assembleDebug` \
                 inside it with the Android SDK to produce an APK."
            );
        } else {
            println!(
                "  note: the iOS shell project layout is written here, but a signed, runnable \
                 .ipa must be produced on a macOS runner with Xcode + a signing identity \
                 (out of scope)."
            );
        }
        Ok(())
    }
}

/// `build|release web desktop [<path>]` — build the app and lay out a
/// self-contained desktop bundle for the host OS.
///
/// A webview app is required: an app whose `programs` shape is declared
/// non-`WebView` is a typed refusal ([`pack::desktop::DesktopRefusal::NotWebView`])
/// naming its shape. The macOS `Info.plist` permission keys come only from the
/// permission derivation ([`pack::permissions`]).
///
/// The Linux bundle is produced end-to-end on this host (the binary is built and
/// the tarball layout materialised). A macOS/Windows host does not run its OS
/// toolchain here; it reports the bundle layout + manifest it *would* produce so
/// the author can inspect it, and directs the actual build to that OS's runner.
///
/// # Errors
/// [`CliError::UsageOwned`] wrapping a [`pack::desktop::DesktopRefusal`];
/// build/emit errors from the underlying compile; [`CliError::Io`] on any
/// filesystem failure while materialising the bundle.
pub fn pack_desktop(profile: BundleProfile, path: Option<&str>) -> Result<(), CliError> {
    // The desktop bundle is the host OS's webview-native app; the delivery
    // grammar carries no per-OS override (a cross-OS artifact is finished on that
    // OS's own runner), so the packager always targets this host's OS.
    let os = pack::desktop::resolve_os(None).map_err(|r| CliError::UsageOwned(r.to_string()))?;

    let root = path.map_or_else(|| PathBuf::from("."), PathBuf::from);
    let manifest_path = discover_manifest(&root)?.ok_or(CliError::Usage(
        "no package.ipe found — run inside a project or pass its path",
    ))?;
    let manifest = project::parse_manifest(&manifest_path)?;

    // Gate the app shape BEFORE any build. The desktop packager is the
    // webview-native host of the DOM `web` shape (`web desktop`): the shape is
    // pinned by `main` (the delivery SSOT), so it is classified from the entry
    // source. An author's declared `programs` shape, when present, is honoured
    // as an explicit override for the rare app that declares one; otherwise the
    // main-classified shape decides. A non-web `main` is refused up front,
    // naming its shape. The witness constructor runs the gate and is the only
    // way to obtain a runnable assembler — assembling an ungated shape has no
    // representation.
    BundleAssembler::gate_desktop(&manifest, &manifest_path, profile, &root)?.assemble(os)
}

/// `build|release web solo <os> [<path>]` — build the client-wasm SPA and lay out
/// a native mobile system-webview shell for `os` (`ios` / `android`) that hosts
/// the SPA offline from app assets.
///
/// A wasm-enabled `Web` app is required: a non-`Web` shape or a project with the
/// `[wasm]` mode off is a typed refusal ([`pack::mobile::MobileRefusal`]) BEFORE
/// any build. The `Info.plist` / `AndroidManifest.xml` permission entries come
/// only from the permission derivation ([`pack::permissions`]).
///
/// The wasm bundle is produced end-to-end on this host (the SPA is built and its
/// `www/` tree collected into the shell). The Android build MAY run where the SDK
/// is present; the iOS build needs macOS + Xcode + signing and is authored-but-unrun
/// here — the layout + derived-permission manifest are written for inspection, and
/// the actual build is directed to that OS's runner.
///
/// # Errors
/// [`CliError::UsageOwned`] wrapping a [`pack::mobile::MobileRefusal`]; the wasm
/// build's own errors; [`CliError::Io`] on any filesystem failure while
/// collecting the bundle or materialising the shell.
pub fn pack_mobile(
    os: pack::mobile::MobileOs,
    profile: BundleProfile,
    path: Option<&str>,
) -> Result<(), CliError> {
    let root = path.map_or_else(|| PathBuf::from("."), PathBuf::from);
    let manifest_path = discover_manifest(&root)?.ok_or(CliError::Usage(
        "no package.ipe found — run inside a project or pass its path",
    ))?;
    let manifest = project::parse_manifest(&manifest_path)?;

    // Gate the app's web-delivery capability BEFORE any build: it must be a
    // wasm-enabled `Web` SPA. A declared non-`Web` shape, or a `Web` app with the
    // `[wasm]` mode off, is refused up front (naming exactly what is missing). An
    // app that declares no shape at all is trusted to infer `Web`.
    // The mobile packager hosts the `web solo <ios|android>` SPA: the shape is
    // pinned by `main`. Honour an explicit declared shape when present, else
    // classify `main` — a non-web `main` fails the `require_web_spa` gate by
    // name rather than silently packaging a terminal or script app as an SPA.
    // The witness constructor runs the gate and is the only way to obtain a
    // runnable assembler — assembling an ungated shape has no representation.
    BundleAssembler::gate_mobile(&manifest, &manifest_path, profile, &root)?.assemble(os)
}

/// Build the hostable SPA bundle at `build_dir/www/` through this binary —
/// `ipe build --target wasm` for a dev bundle, `ipe release --target wasm` for a
/// production one.
///
/// Invoking the same binary keeps the wasm bundle pipeline (emit + cargo +
/// wasm-bindgen) authoritative — the mobile shell hosts exactly the bundle a
/// plain wasm build/release produces, never a re-implemented variant. The profile
/// carries through so a `release web solo <os>` shell hosts the production SPA.
///
/// # Errors
/// [`CliError::UsageOwned`] when this binary's path cannot be resolved or the
/// wasm build exits non-zero; [`CliError::Io`] when the build cannot be spawned.
pub fn build_wasm_for_mobile(
    manifest_path: &Path,
    build_dir: &Path,
    profile: BundleProfile,
) -> Result<(), CliError> {
    let exe = std::env::current_exe().map_err(|e| {
        CliError::UsageOwned(format!("cannot locate the ipe binary to build wasm: {e}"))
    })?;
    let project_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    // A dev shell hosts a `build --target wasm` bundle; a release shell hosts a
    // production `release --target wasm` bundle (Debug.* gated, optimised).
    let verb = match profile {
        BundleProfile::Dev => "build",
        BundleProfile::Release => "release",
    };
    let status = std::process::Command::new(&exe)
        .arg(verb)
        .arg(project_dir)
        .args(["--target", "wasm", "--out"])
        .arg(build_dir)
        .status()
        .map_err(|source| CliError::Io {
            path: exe.clone(),
            source,
        })?;
    if !status.success() {
        return Err(CliError::UsageOwned(format!(
            "the `--target wasm` build failed (exit {}) — the mobile shell hosts that \
             bundle, so it must build first",
            status.code().unwrap_or(1)
        )));
    }
    Ok(())
}

/// `build|release --emit-permissions <ios|macos|android> [<path>]` — the
/// read-only inspection face of the packager's permission derivation
/// ([`pack::permissions::derive_permissions`]), the single source of truth for
/// what a bundled app may do. Resolves the project manifest, reads its accepted
/// web capabilities, and prints the derived plist keys / Android manifest entries
/// for `raw_platform`, without building or writing anything.
///
/// `verb` names the calling delivery verb (`build` / `release`) so a bad platform
/// word errors in that command's voice.
///
/// # Errors
/// [`CliError::UsageOwned`] on a platform word outside the closed
/// `ios|macos|android` set; [`CliError::Usage`] when no `package.ipe` governs the
/// path; the manifest's own parse errors when it is malformed.
pub fn emit_permissions(
    raw_platform: &str,
    path: Option<&str>,
    verb: &str,
) -> Result<(), CliError> {
    use std::fmt::Write as _;

    let platform = raw_platform
        .parse::<pack::permissions::Platform>()
        .map_err(|e| CliError::UsageOwned(format!("ipe {verb} --emit-permissions: {e}")))?;

    let root = path.map_or_else(|| PathBuf::from("."), PathBuf::from);
    let manifest_path = discover_manifest(&root)?.ok_or(CliError::Usage(
        "no package.ipe found — run inside a project or pass its path",
    ))?;

    let manifest = project::parse_manifest(&manifest_path)?;
    let accepts = &manifest.capabilities_accept;
    let derived = pack::permissions::derive_permissions(accepts, platform)?;

    // Writing into an owned buffer never fails; the `let _` discards the always-Ok
    // `fmt::Result` so a print is one syscall over the whole report.
    let mut out = String::new();
    let _ = writeln!(
        out,
        "OS permissions for `{}` on {}",
        manifest.name,
        platform.as_str()
    );
    let breakdown = pack::permissions::per_axis_breakdown(accepts, platform);
    if breakdown.is_empty() {
        let _ = writeln!(
            out,
            "  (no web capabilities accepted — no OS permissions required)"
        );
    } else {
        for (axis, entries) in &breakdown {
            if entries.is_empty() {
                let _ = writeln!(
                    out,
                    "  js-port:{axis} → (no OS permission on this platform)"
                );
            } else {
                let _ = writeln!(out, "  js-port:{axis} → {}", entries.join(", "));
            }
        }
    }
    match platform {
        pack::permissions::Platform::Ios | pack::permissions::Platform::MacOs => {
            let _ = writeln!(out, "\nInfo.plist entries:");
            let plist = derived.to_info_plist_entries();
            if plist.is_empty() {
                let _ = writeln!(out, "  (none)");
            } else {
                for (key, purpose) in plist {
                    let _ = writeln!(out, "  {key} = {purpose:?}");
                }
            }
        }
        pack::permissions::Platform::Android => {
            let _ = writeln!(out, "\nAndroidManifest.xml fragment:");
            let fragment = derived.to_android_manifest_entries();
            if fragment.is_empty() {
                let _ = writeln!(out, "  (none)");
            } else {
                for line in fragment.lines() {
                    let _ = writeln!(out, "  {line}");
                }
            }
        }
    }
    print!("{out}");
    Ok(())
}

/// `ipe capabilities <entry.ipe>` — print the program's inferred security
/// capabilities, one per line in sorted order, or `none` when the program is
/// pure. Read-only analysis: nothing is emitted or written.
/// `ipe package <subcommand>` — package-authoring commands: `audit` (the SP4
/// Tier-1 package gate), `publish` (run the gate, compute the index entry, and
/// open the index PR), `validate-entry` (schema-check an entry file), and
/// `audit-entry` (the index CI's authoritative receiving gate).
///
/// # Errors
/// [`CliError::UsageOwned`] on a missing or unknown subcommand; the subcommand's
/// own errors (a build failure, a [`CliError::PackageAudit`] reject, or a
/// [`CliError::Publish`] refusal) otherwise.
pub fn run_package(rest: &[String]) -> Result<(), CliError> {
    match rest.split_first() {
        Some((sub, tail)) if sub == "audit" => audit::run_audit(tail),
        Some((sub, tail)) if sub == "publish" => publish::run_publish(tail),
        Some((sub, tail)) if sub == "validate-entry" => run_validate_entry(tail),
        Some((sub, tail)) if sub == "audit-entry" => run_audit_entry(tail),
        Some((sub, _)) => Err(cli_args::usage_unknown_subcommand(
            "package",
            sub,
            "`audit`, `audit-entry`, `publish`, or `validate-entry`",
        )),
        None => Err(CliError::Usage(
            "usage: ipe package <audit|audit-entry|publish|validate-entry> [<path>]",
        )),
    }
}

/// `ipe package validate-entry <packages/<name>.toml>` — validate one curated
/// index entry file against the entry schema, fail-closed.
///
/// The index repository's admission CI runs this on a submitted entry as its
/// cheap structural gate before the source-pin and `ipe package audit` steps: it
/// reuses the resolver's own parser ([`index::validate_entry_file`]), so a file
/// that validates here is exactly a file the resolver will later read. On success
/// it prints the package name and every version it parsed; on any malformed field
/// it exits non-zero with the parser's diagnostic.
///
/// # Errors
/// [`CliError::Usage`] when no entry file is given; [`CliError::UsageOwned`] on a
/// bad path or an extra argument; the parser's [`CliError::Resolve`] /
/// [`CliError::Io`] when the entry is malformed or unreadable.
pub fn run_validate_entry(rest: &[String]) -> Result<(), CliError> {
    let path = match rest {
        [one] => PathBuf::from(one),
        [] => {
            return Err(CliError::Usage(
                "usage: ipe package validate-entry <packages/<name>.toml>",
            ));
        }
        _ => {
            return Err(CliError::UsageOwned(
                "ipe package validate-entry: expected a single entry-file path".to_owned(),
            ));
        }
    };
    let entry = index::validate_entry_file(&path)?;
    let versions: Vec<String> = entry
        .versions
        .iter()
        .map(|v| v.version.to_string())
        .collect();
    let body = format!(
        "entry ok: {} (publisher {}) — {} version(s): {}",
        entry.name,
        entry.publisher,
        versions.len(),
        versions.join(", ")
    );
    print!("{}", style::frame(&style::gutter(&body)));
    Ok(())
}

/// `ipe package audit-entry <packages/<name>.toml> [--index <root>]
/// [--attested-actor <login>]` — the index CI's authoritative receiving gate for
/// a submitted entry.
///
/// `--attested-actor` is the authenticated PR author the admission workflow reads
/// from GitHub's event context. It is the only identity the reserved-namespace
/// exemption and the reserved smoke reset accept: absent it, or when it does not
/// equal the entry's claimed `publisher`, or is not the blessed first-party
/// identity, both privileges are refused (fail-closed). Every other check is
/// identical with or without it.
///
/// Composes the existing pieces in a fixed, fail-closed order so the CI cannot
/// diverge from `ipe package audit`:
///
/// 1. **Schema** — validate the entry via [`index::validate_entry_file`] (the same
///    parser `validate-entry` uses); reject on any malformation.
/// 2. **New versions** — compare against the baseline entry at
///    `<index-root>/packages/<name>.toml` (if it exists) and identify every
///    `[[version]]` that is not already in the baseline. When there is no baseline,
///    all versions are audited. A PR normally adds exactly one new version.
/// 3. **Fetch + verify** — for each new version, `git`-fetch the source at the
///    pinned revision and verify the fetched tree's `sha256` equals the entry's pin
///    via [`resolve::fetch_and_verify_index_version`] (verify-before-trust; a
///    mismatch is [`CliError::HashMismatch`], never a warning).
/// 4. **Audit** — run the full [`audit::run_audit`] gate (Tier-1 provenance,
///    capability consistency, enforced semver, supply-chain; Tier-2 for
///    native-bearing packages) on each verified source tree. Reject on the first
///    failing check.
///
/// Exits 0 with a per-version passing summary only when ALL steps pass for ALL new
/// versions. Any failure is a typed [`CliError`] + non-zero exit; no step is
/// warn-and-pass.
///
/// # Errors
/// [`CliError::Usage`] when no entry file is given; [`CliError::UsageOwned`] on
/// argument misuse; [`CliError::Resolve`] / [`CliError::Io`] on a schema or read
/// failure; [`CliError::HashMismatch`] on an integrity mismatch; and
/// [`CliError::PackageAudit`] when a Tier-1 check rejects a version.
pub fn run_audit_entry(rest: &[String]) -> Result<(), CliError> {
    let AuditEntryArgs {
        entry_path,
        index_root: index_root_opt,
        attested_actor,
    } = parse_audit_entry_args(rest)?;

    // Step 1 — schema: parse + validate the submitted entry file.
    let submitted = index::validate_entry_file(&entry_path)?;

    // The blessed privileges rest on the attested PR author, bound to the entry's
    // claimed publisher — never on the self-declared `publisher` alone.
    let blessing = BlessedPublisher::from_attested(attested_actor.as_ref(), &submitted.publisher);

    // Step 2 — baseline: read the previously-published entry (if any).
    // Fail closed: a present-but-unreadable baseline propagates as an error
    // so the structural prechecks below never run against an empty baseline and
    // silently classify every submitted version as "new".
    let index_root = index_root_opt.clone().unwrap_or_else(resolve::index_root);
    let baseline: Option<index::IndexEntry> =
        index::read_entry_lookup(&index_root, &submitted.name).require_present()?;

    // Structural prechecks (no fetch): version-count ceiling, per-version
    // immutability against the baseline, and source continuity (anti-squat). This
    // is the authoritative wall (ADR 0007) — it enforces these even for an entry
    // hand-edited around the author-side `ipe publish`, which an attacker opening
    // the index PR directly would bypass.
    index::admission_precheck(&submitted, baseline.as_ref(), attested_actor.as_ref())?;

    let baseline_by_version: std::collections::BTreeMap<&semver::Version, &index::EntryVersion> =
        baseline
            .as_ref()
            .map(|e| e.versions.iter().map(|v| (&v.version, v)).collect())
            .unwrap_or_default();

    // The new versions are those present in the submitted entry but absent from
    // the baseline. A PR normally adds exactly one. Each is fetched, hash-verified,
    // and audited below; an existing-number row is only the immutability check above.
    let new_versions: Vec<&index::EntryVersion> = submitted
        .versions
        .iter()
        .filter(|v| !baseline_by_version.contains_key(&v.version))
        .collect();

    if new_versions.is_empty() {
        return Err(CliError::UsageOwned(format!(
            "ipe package audit-entry: `{}` — every version in the submitted entry is already in \
             the baseline index; nothing new to audit",
            submitted.name
        )));
    }

    // A scratch root for fetch caches under the standard per-user cache root
    // (the write-boundary from PRINCIPLES.md), isolated per process so concurrent
    // audit-entry runs never share a cache directory.
    let cache_base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".ipe"));
    let scratch_root = cache_base
        .join("ipe")
        .join(format!("audit-entry-{}", std::process::id()));
    std::fs::create_dir_all(&scratch_root).map_err(|e| CliError::Io {
        path: scratch_root.clone(),
        source: e,
    })?;

    let mut passing: Vec<String> = Vec::new();

    for version in new_versions {
        let ver_str = version.version.to_string();

        // Step 3 — fetch + verify: git-clone the source at the pinned revision and
        // assert the fetched tree's sha256 equals the index pin. A mismatch is a
        // CliError::HashMismatch — the fetched bytes are not the source the
        // publisher registered, so nothing derived from them is trusted.
        let checkout =
            resolve::fetch_and_verify_index_version(&scratch_root, &submitted.name, version)?;

        // Step 4 — audit: run the full Tier-1 (+ Tier-2 where applicable) gate on
        // the verified source tree. Pass --index so the enforced-semver check reads
        // the right baseline. Reject on the first failing check.
        let checkout_str = checkout.to_string_lossy().into_owned();
        // Pass the submitted entry's claimed publisher (named in a reject) and the
        // attestation-backed blessing: the reserved-namespace ownership check
        // exempts only a proven blessed publisher and rejects any other whose
        // source tree provides a reserved-namespace (`Ipe.*`) module — the
        // admission-time squat-proofing of the trusted namespace.
        let mut audit_args: Vec<String> = vec![
            checkout_str,
            "--publisher".to_owned(),
            submitted.publisher.as_str().to_owned(),
        ];
        if let Some(ir) = &index_root_opt {
            audit_args.push("--index".to_owned());
            audit_args.push(ir.to_string_lossy().into_owned());
        }
        // Propagate typed errors directly — run_audit already produces a
        // descriptive typed CliError (PackageAudit / HashMismatch / etc.) whose
        // Display names the failing check; the version context is clear from
        // the eprintln below and the structured error kind.
        if let Err(e) = audit::run_audit_as(&audit_args, blessing.as_ref()) {
            eprintln!(
                "audit-entry: `{}` version {} rejected",
                submitted.name, ver_str
            );
            return Err(e);
        }

        passing.push(ver_str);
    }

    // All new versions passed — print the certified summary.
    let versions_list = passing.join(", ");
    let body = format!(
        "audit-entry: {} — {} new version(s) certified: {versions_list}",
        submitted.name,
        passing.len()
    );
    print!("{}", style::frame(&style::gutter(&body)));

    // Remove the per-run scratch directory (best-effort; a leftover is harmless).
    let _ = std::fs::remove_dir_all(&scratch_root);
    Ok(())
}

/// The parsed `ipe package audit-entry` invocation.
#[derive(Debug)]
pub struct AuditEntryArgs {
    /// The submitted `packages/<name>.toml` entry file.
    pub entry_path: PathBuf,
    /// The baseline index checkout (`--index`); the resolver's index root when absent.
    pub index_root: Option<PathBuf>,
    /// The admission workflow's authenticated PR author (`--attested-actor`).
    pub attested_actor: Option<AttestedActor>,
}

/// Parse `ipe package audit-entry`'s tail: a required positional entry-file path,
/// an optional `--index <dir>`, and an optional `--attested-actor <login>`.
///
/// # Errors
/// [`CliError::Usage`] when the entry file is missing; [`CliError::UsageOwned`] on
/// an unknown flag, a missing flag value, a duplicate flag/positional, or an
/// `--attested-actor` that is not a GitHub login.
pub fn parse_audit_entry_args(rest: &[String]) -> Result<AuditEntryArgs, CliError> {
    let mut entry_path: Option<PathBuf> = None;
    let mut index_root: Option<PathBuf> = None;
    let mut attested_actor: Option<AttestedActor> = None;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--attested-actor" => {
                let value = it.next().ok_or(CliError::Usage(
                    "ipe package audit-entry: --attested-actor needs a value",
                ))?;
                if attested_actor.is_some() {
                    return Err(CliError::Usage(
                        "ipe package audit-entry: --attested-actor given more than once",
                    ));
                }
                attested_actor = Some(AttestedActor::parse(value)?);
            }
            "--index" => {
                let value = it.next().ok_or(CliError::Usage(
                    "ipe package audit-entry: --index needs a value",
                ))?;
                if index_root.is_some() {
                    return Err(CliError::Usage(
                        "ipe package audit-entry: --index given more than once",
                    ));
                }
                index_root = Some(PathBuf::from(value));
            }
            flag if flag.starts_with('-') => {
                return Err(cli_args::usage_unknown_flag("package audit-entry", flag));
            }
            positional => {
                if entry_path.is_some() {
                    return Err(CliError::Usage(
                        "ipe package audit-entry: expected a single entry-file path",
                    ));
                }
                entry_path = Some(PathBuf::from(positional));
            }
        }
    }
    let entry_path = entry_path.ok_or(CliError::Usage(
        "usage: ipe package audit-entry <packages/<name>.toml> [--index <root>] \
         [--attested-actor <login>]",
    ))?;
    Ok(AuditEntryArgs {
        entry_path,
        index_root,
        attested_actor,
    })
}

/// Resolve a `check`/analysis `<path>` argument to the entry `.ipe` file the
/// source-graph pipeline reads. Same argument convention as `ipe build`:
///
/// 1. a directory → its `package.ipe`'s `src`-root `Main.ipe`;
/// 2. a `.ipe` file → itself.
///
/// A project's entry module is always `Main` (`project` module doc), so the
/// entry file is `<src_root>/Main.ipe`.
///
/// # Errors
/// [`CliError::Usage`] for a directory with no `package.ipe`; the manifest's own
/// parse errors otherwise.
pub fn resolve_analysis_entry(path: &Path) -> Result<PathBuf, CliError> {
    let manifest = discover_manifest(path)?;
    match manifest {
        Some(m) => {
            let parsed = project::parse_manifest(&m)?;
            analysis_root_of(&parsed)
        }
        None => Ok(path.to_path_buf()),
    }
}

/// The source file `ipe type-check` uses as its analysis root for a manifest
/// project.
///
/// An application uses `<src_root>/Main.ipe`. A library (a manifest declaring
/// `exposedModules` with no `src/Main.ipe` and no runnable program) has no
/// `main` to check, so its analysis root is its first exposed module's file —
/// checking the public surface is a library's meaningful verification. A
/// declared-program entry (when a `programs` stage names one) takes precedence,
/// resolved through the same [`contained_path::ContainedRelPath`] gate the build
/// path uses so an absolute or `..` entry cannot escape the source root.
///
/// # Errors
/// [`CliError::PathEscape`] when a declared program's entry resolves outside the
/// source root.
pub fn analysis_root_of(parsed: &project::ProjectManifest) -> Result<PathBuf, CliError> {
    let main = parsed.src_root.join("Main.ipe");
    if main.is_file() {
        return Ok(main);
    }
    // No Main: prefer a declared program's entry file, else the first exposed
    // module's file. Fall back to `Main.ipe` (the caller surfaces a clean
    // missing-entry diagnostic) when the manifest names neither.
    if let Some(program) = parsed.default_program() {
        let contained = contained_path::ContainedRelPath::parse(&parsed.src_root, &program.entry)
            .map_err(|reason| CliError::PathEscape {
            raw: program.entry.clone(),
            reason,
        })?;
        return Ok(contained.resolved().to_path_buf());
    }
    if let Some(module) = parsed.exposed_modules.first() {
        let rel: PathBuf = module.split('.').collect();
        return Ok(parsed.src_root.join(rel).with_extension("ipe"));
    }
    Ok(main)
}

/// `ipe type-check [<path>]` — type-check a program and stop. Runs the same
/// injection-aware source graph `ipe build` uses, but demands only the
/// `typecheck` query: no IR lowering, no Rust emission, nothing written. Exits
/// 0 with a friendly framed success line when the program type-checks, or
/// non-zero carrying the first rendered diagnostic when it does not.
///
/// With `--json`, each diagnostic is a JSON object on stderr, and success is the
/// shared machine envelope (`ipe.cli.type-check/1`, `status:ok`, empty payload)
/// on stdout — both machine-parseable.
pub fn run_type_check(rest: &[String]) -> Result<(), CliError> {
    // First, infallible format pass before the body's fallible parse, so a parse
    // error (an unknown flag, a second positional) still renders through the
    // requested machine surface rather than the human banner (see `run_build`).
    let format = cli_args::peek_output_format(rest);
    run_type_check_body(rest).map_err(|e| {
        if format == cli_args::OutputFormat::Human {
            e
        } else {
            emit_machine_error(format, "type-check", &e)
        }
    })
}

/// Inner implementation of [`run_type_check`], unaware of how a failure is
/// rendered; the caller routes any error through the resolved output format.
pub fn run_type_check_body(rest: &[String]) -> Result<(), CliError> {
    let args = cli_args::parse_type_check(rest)?;
    let arg = match args.entry {
        Some(e) => PathBuf::from(e),
        None => PathBuf::from(default_entry()?),
    };
    let entry = resolve_analysis_entry(&arg)?;
    // Propagate any diagnostic raw; `run_type_check` routes it through the
    // resolved output format (the single machine-error boundary).
    typecheck_entry_via_graph(&entry)?;
    match args.format {
        cli_args::OutputFormat::Json => {
            // The shared machine envelope; a clean type-check carries an empty
            // payload (the outcome is the `status`, there is no result data).
            let payload = cli_args::json::object(&[]);
            print!(
                "{}",
                crate::machine_output::MachineOutput::ok(
                    "ipe.cli.type-check/1",
                    "type-check",
                    payload,
                )
                .render_json()
            );
        }
        cli_args::OutputFormat::Plain => {
            println!("ok");
        }
        cli_args::OutputFormat::Human => {
            let p = style::Palette::for_stream(&std::io::stdout());
            let (glyph, tint) = style::Outcome::Success.glyph_and_tint(p);
            print!(
                "{}",
                style::frame(&style::gutter(&format!(
                    "{tint}{glyph} No type errors — this program type-checks.{}",
                    p.reset,
                )))
            );
        }
    }
    Ok(())
}

/// A single `ipe verify` stage: run the underlying check over an optional
/// `<path>` (the current project when `None`), returning its own error on
/// failure.
pub type VerifyStage = fn(Option<&str>) -> Result<(), CliError>;

/// The ordered stages `ipe verify` runs, each composing the same code path its
/// standalone command uses. The order is the cheapest, most localised check
/// first: a formatting scan reads source only; a type-check parses and infers
/// but emits nothing; a build compiles all the way to an artifact; a test run
/// exercises the project's `tests/Main.ipe` entry (when one exists).
pub const VERIFY_STAGES: &[(&str, VerifyStage)] = &[
    ("format", verify_fmt),
    ("type-check", verify_check),
    ("build", verify_build),
    ("test", verify_test),
];

/// Stage 1: the formatting scan — `ipe fmt --check` over `<path>` (the current
/// directory when none is given), reporting unformatted files without rewriting.
pub fn verify_fmt(path: Option<&str>) -> Result<(), CliError> {
    let mut rest: Vec<String> = Vec::new();
    if let Some(p) = path {
        rest.push(p.to_owned());
    }
    rest.push("--check".to_owned());
    fmt::run_fmt(&rest)
}

/// Stage 2: the type-check — the same source-graph pipeline as `ipe type-check`.
pub fn verify_check(path: Option<&str>) -> Result<(), CliError> {
    run_type_check(&path.map(str::to_owned).into_iter().collect::<Vec<_>>())
}

/// Stage 3: the build — the same compilation as `ipe build`.
pub fn verify_build(path: Option<&str>) -> Result<(), CliError> {
    run_build(&path.map(str::to_owned).into_iter().collect::<Vec<_>>())
}

/// The outcome of running a project's `tests/Main.ipe` entry.
///
/// A parsed result rather than a bare `Result<(), _>`: "the project defines no
/// test entry" is a distinct, legitimate state from "the tests ran and all
/// passed", and the two render differently (`no tests to run` vs `all passed`).
/// A failing test run is NOT this type — it is a hard [`CliError::TestFailed`],
/// because the test binary has already printed its own summary and the CLI's
/// only job is to fail non-zero. This makes the exit-code contract structural:
/// a `TestOutcome` value can never represent a failure, so no caller can
/// accidentally return success over failing tests.
#[derive(Debug, PartialEq, Eq)]
pub enum TestOutcome {
    /// The project has no `tests/Main.ipe` — there is nothing to run, which is
    /// not an error.
    NoTestEntry,
    /// The test entry was built, run, and every case passed (the binary exited
    /// zero).
    AllPassed,
}

/// Where the test binary's own `N passed, M failed` summary goes.
///
/// The default human path inherits stdout so the summary appears inline between
/// the progress lines; the `--json` path routes it to stderr so stdout carries
/// exactly the one JSON verdict line a consumer parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestStdio {
    /// Inherit stdout — the child's summary prints where the user sees it.
    Inherit,
    /// Redirect the child's stdout to stderr — keep our stdout machine-clean.
    Quiet,
}

/// Build and run a project's `tests/Main.ipe`, the single test runner shared by
/// `ipe test` and `ipe verify`'s final stage.
///
/// The test entry is the file at `<project-root>/tests/Main.ipe`. The project
/// root is the directory holding `package.ipe`; with no manifest it is the parent
/// of the entry's `src/` directory (the conventional layout), or the entry's
/// own directory for a flat single-directory project. The test entry is built
/// against the project's `src/` tree AND its `tests/` siblings, so a test that
/// imports the code under test resolves. When the test entry is absent the
/// runner returns [`TestOutcome::NoTestEntry`] — a project with no test entry is
/// not an error. When it exists, the test runner is compiled to a temporary
/// output directory, the emitted Rust project is built with `cargo build`, and
/// the resulting `ipe-app` binary is executed. The binary itself prints the
/// per-test failures and the `N passed, M failed` summary (from
/// `Ipe.Test.runMain`) to stdout; this function only classifies its exit code.
///
/// # Errors
/// [`CliError::TestFailed`] when the test binary exits non-zero (one or more
/// cases failed) — the binary's own output is the report. Otherwise any build
/// or toolchain error encountered while compiling the runner.
pub fn run_project_tests(path: Option<&str>) -> Result<TestOutcome, CliError> {
    run_project_tests_with(path, TestStdio::Inherit)
}

/// The shared test runner, parameterised by where the test binary's own summary
/// goes ([`TestStdio`]). See [`run_project_tests`] for the resolution rules.
///
/// # Errors
/// As [`run_project_tests`].
pub fn run_project_tests_with(
    path: Option<&str>,
    stdio: TestStdio,
) -> Result<TestOutcome, CliError> {
    // Resolve the project root from the supplied path (or cwd defaults).
    let entry_path = match path {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(default_entry()?),
    };

    // Resolve the project root and the source root (the `src/` tree the code
    // under test lives in). With a manifest, both come from it — the manifest's
    // directory and its declared `src_root` (honouring a `srcDir` override).
    // Without a manifest, the entry's own directory is the source root, and the
    // project root is the source root's parent when the entry lives under a
    // conventional `src/` directory (so `src/Main.ipe`'s sibling `tests/` tree
    // is at `<project-root>/tests`, not `src/tests`); otherwise the entry's
    // directory is itself the project root (a flat single-directory project).
    let manifest = discover_manifest(&entry_path)?;
    let (project_root, project_src_root): (PathBuf, PathBuf) = if let Some(m) = manifest.as_ref() {
        let root = m
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        (root, project::parse_manifest(m)?.src_root)
    } else {
        let src_root = entry_path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let root = if src_root.file_name().and_then(|n| n.to_str()) == Some("src") {
            src_root
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
        } else {
            src_root.clone()
        };
        (root, src_root)
    };

    let test_entry = project_root.join("tests").join("Main.ipe");
    if !test_entry.is_file() {
        // No test entry — there is nothing to run.
        return Ok(TestOutcome::NoTestEntry);
    }

    // Fail closed before emitting: the test stage shells out to cargo to build
    // the test runner, so a missing toolchain is reported with its root cause
    // rather than an opaque OS spawn error.
    let cargo_bin = toolchain::require_cargo(toolchain::ToolIntent::Test)?;

    let runtime_dir = resolve_runtime()?;

    // Emit into an exclusively-created, unpredictably-named temp directory so
    // concurrent verify runs cannot collide and an attacker cannot pre-seed the
    // path.
    let out_scratch = scratch::ScratchDir::new("ipe-verify-test").map_err(|e| CliError::Io {
        path: PathBuf::from("ipe-verify-test"),
        source: e,
    })?;
    let out_dir = out_scratch.path().to_path_buf();

    // Build the test entry. When the project has a `src/` tree, the test entry
    // is built against BOTH it (the code under test) and the `tests/` tree (its
    // test-only siblings), so a `tests/Main.ipe` importing `Lib.Foo` from
    // `src/Lib/Foo.ipe` resolves. A `tests/`-only project with no `src/` (a
    // standalone test) falls back to sibling discovery rooted at `tests/`. On
    // any compile failure the stage propagates that error directly — the error
    // is already a well-formed `CliError`.
    // Build, then run, the test entry. Everything after the temp output is
    // created runs inside this closure so a single cleanup below removes the
    // temp directory on EVERY exit — a compile failure, a cargo failure, a
    // spawn error, or a normal run — not only the success path.
    let outcome = build_and_run_test_entry(
        &project_src_root,
        &test_entry,
        &out_dir,
        &runtime_dir,
        cargo_bin.path(),
        stdio,
    );

    // `out_scratch` drops here, removing the temp directory on every exit path
    // (compile failure, cargo error, spawn error, or normal completion).
    drop(out_scratch);
    outcome
}

/// Compile the test entry into `out_dir`, build the emitted Rust project, and
/// run the resulting `ipe-app` binary, classifying its exit code.
///
/// Split from [`run_project_tests`] so the caller's temp-directory cleanup runs
/// on every exit of this fallible sequence, not only the success path.
///
/// # Errors
/// The compile/build error on a compile or cargo failure; [`CliError::Io`] when
/// the test binary cannot be spawned; [`CliError::TestFailed`] when it exits
/// non-zero (a failing case, or a crash/signal with no exit code).
pub fn build_and_run_test_entry(
    project_src_root: &Path,
    test_entry: &Path,
    out_dir: &Path,
    runtime_dir: &Path,
    cargo_bin: &Path,
    stdio: TestStdio,
) -> Result<TestOutcome, CliError> {
    if project_src_root.is_dir() {
        build_test_with_project_sources(project_src_root, test_entry, out_dir, runtime_dir)?;
    } else {
        build_with_sibling_discovery(test_entry, out_dir, runtime_dir)?;
    }

    // Compile the emitted Rust project.
    let mut cargo = std::process::Command::new(cargo_bin);
    cargo.arg("build").current_dir(out_dir);
    build_emitted_project(
        &mut cargo,
        "the emitted test runner",
        runtime_context_for_message(),
        out_dir,
    )?;

    // Locate the compiled binary via `cargo metadata` so a user-level
    // `CARGO_TARGET_DIR` pin or workspace override is respected. The binary
    // name matches the emitted crate's package name (read from `Cargo.toml`).
    let test_bin_name = emitted_bin_filename(out_dir);
    let mut bin = cargo_target_directory(out_dir)?;
    bin.push("debug");
    bin.push(&test_bin_name);

    // Run the test binary. `Ipe.Test.runMain` exits 0 on all-pass, 1 on any
    // failure — propagate that as a stage error. Under `--json` the child's own
    // human summary is captured and re-emitted on OUR stderr, so our stdout stays
    // a single JSON line a consumer can parse.
    let run_status = match stdio {
        TestStdio::Inherit => {
            std::process::Command::new(&bin)
                .status()
                .map_err(|e| CliError::Io {
                    path: bin.clone(),
                    source: e,
                })?
        }
        TestStdio::Quiet => {
            let output = std::process::Command::new(&bin)
                .stdout(std::process::Stdio::piped())
                .output()
                .map_err(|e| CliError::Io {
                    path: bin.clone(),
                    source: e,
                })?;
            let _ = std::io::stderr().write_all(&output.stdout);
            output.status
        }
    };

    if run_status.success() {
        Ok(TestOutcome::AllPassed)
    } else {
        // A zero exit is the ONLY success signal. Any other exit — a failing
        // case (1 from `Ipe.Test.runMain`) or a crash/signal (no code) — is a
        // failure; classify the absent code as a failure, never a pass.
        let code = run_status.code().unwrap_or(1);
        Err(CliError::TestFailed { code })
    }
}

/// Stage 4 of `ipe verify`: run the project's tests via the shared
/// [`run_project_tests`] runner, discarding the pass/no-entry distinction the
/// stage does not need (both are a passing stage).
///
/// # Errors
/// [`CliError::TestFailed`] when a test case fails; otherwise any build or
/// toolchain error from compiling the runner.
pub fn verify_test(path: Option<&str>) -> Result<(), CliError> {
    run_project_tests(path).map(|_| ())
}

/// `ipe test [<path>]` — build and run the project's tests, with human-friendly
/// output and a machine-readable exit code.
///
/// Compiles `tests/Main.ipe` against the project's `src/` tree and runs it. The
/// test binary prints the per-case failures and the `N passed, M failed`
/// summary itself (from `Ipe.Test.runMain`); this command wraps that in a
/// single progress stage — a light-yellow running line that settles to a green
/// check (`all tests passed` / `no tests to run`) or, on a failing case, a red
/// cross and a non-zero exit. A project with no `tests/Main.ipe` is not an
/// error: the command reports there is nothing to run and exits zero.
///
/// # Errors
/// [`CliError::UsageOwned`] on an unexpected option or extra argument.
/// [`CliError::TestFailed`] when a test case fails (the non-zero exit contract).
/// Otherwise any build or toolchain error from compiling the runner.
pub fn run_test(rest: &[String]) -> Result<(), CliError> {
    let (path, format) = cli_args::single_positional_with_format(rest, "test")?;

    if format == cli_args::OutputFormat::Json {
        return run_test_json(path);
    }

    // Wrap the runner in a progress stage so `ipe test` follows the same
    // running → ✓/✗ shape every other multi-step command uses. The stage writes
    // to stdout; the test binary the runner spawns inherits stdout too, so its
    // own summary appears between the running line and the settled outcome.
    let stage = progress::Stage::start(std::io::stdout(), "Running tests");
    match run_project_tests(path) {
        Ok(TestOutcome::AllPassed) => {
            stage.success("all tests passed");
            Ok(())
        }
        Ok(TestOutcome::NoTestEntry) => {
            stage.success("no tests to run (no tests/Main.ipe)");
            Ok(())
        }
        Err(err) => {
            // A failing case (or any build error) settles the stage red before
            // the error propagates to the exit-code contract.
            stage.failure("tests failed");
            Err(err)
        }
    }
}

/// `ipe test --json`: run the tests and emit a compact verdict object to stdout.
///
/// The test binary's own human `N passed, M failed` summary is routed to stderr
/// (via [`TestStdio::Quiet`]) so stdout carries exactly one JSON line a consumer
/// can parse. A failing case still exits non-zero: the verdict object is written,
/// then the already-emitted sentinel drives the exit without a second message.
pub fn run_test_json(path: Option<&str>) -> Result<(), CliError> {
    use cli_args::json;

    let verdict = |result: &str| json::object(&[("result", json::string(result))]);
    match run_project_tests_with(path, TestStdio::Quiet) {
        Ok(TestOutcome::AllPassed) => {
            println!("{}", verdict("passed"));
            Ok(())
        }
        Ok(TestOutcome::NoTestEntry) => {
            println!("{}", verdict("no-tests"));
            Ok(())
        }
        Err(CliError::TestFailed { code }) => {
            println!(
                "{}",
                json::object(&[
                    ("result", json::string("failed")),
                    ("exitCode", code.to_string()),
                ])
            );
            Err(CliError::DiagnosticJsonEmitted)
        }
        // A build/toolchain error is not a test verdict — surface it as itself.
        Err(other) => Err(other),
    }
}

/// `ipe verify [<path>]` — the one-command project gate.
///
/// Runs the project's checks in order — format, type-check, build, test —
/// stopping at the first failure. Each stage composes the same code path its
/// standalone command uses, so `verify` is a faithful union of them, never a
/// second implementation. `<path>` defaults to the current project.
///
/// The test stage builds and runs `tests/Main.ipe` when that file exists in the
/// project root. A project with no `tests/Main.ipe` passes the test stage
/// immediately — no test entry means no tests to run.
///
/// # Errors
/// [`CliError::UsageOwned`] on an unexpected option or extra argument. Otherwise
/// the first failing stage's own error, which carries its diagnostic and drives
/// the non-zero exit; a clean run exits 0.
pub fn run_verify(rest: &[String]) -> Result<(), CliError> {
    let (path, format) = cli_args::single_positional_with_format(rest, "verify")?;

    if format == cli_args::OutputFormat::Json {
        return run_verify_json(path);
    }

    let total = VERIFY_STAGES.len();

    for (index, (name, stage)) in VERIFY_STAGES.iter().enumerate() {
        let step = index + 1;
        // Each stage is one progress line: a light-yellow running line that
        // settles to a green ✓ or a red ✗ — the shared stage shape every
        // multi-step command uses, not a hand-rolled colour print.
        let line =
            progress::Stage::start(std::io::stdout(), format!("stage {step}/{total}: {name}"));
        if let Err(err) = stage(path) {
            line.failure(format!("stage {step}/{total}: {name} failed"));
            // The stage ran correctly and reported a real failure — a gate
            // result, not a misuse of `verify`. Rewrap it as [`VerifyFailed`] so
            // the stage's own rendered report is shown alone, never the `verify`
            // `--help` page a raw usage error would trigger.
            return Err(CliError::VerifyFailed {
                stage: name,
                report: err.to_string(),
            });
        }
        line.success(format!("stage {step}/{total}: {name} passed"));
    }

    let summary = progress::Stage::start(std::io::stdout(), "gate");
    summary.success(format!("all {total} stages passed"));
    Ok(())
}

/// `ipe verify --json`: run the gate and emit a single compact verdict object to
/// stdout — `{"result":"passed","stages":N}` on a clean run, or
/// `{"result":"failed","stage":"<name>"}` at the first failing stage (then a
/// non-zero exit via the already-emitted sentinel).
///
/// Each stage runs in a machine-quiet form so stdout carries EXACTLY the verdict
/// line: the type-check core prints nothing, the build banner and any stage
/// diagnostic go to stderr, and the test binary's summary is captured to stderr.
pub fn run_verify_json(path: Option<&str>) -> Result<(), CliError> {
    use cli_args::json;

    let stages: &[(&str, VerifyStage)] = &[
        ("format", verify_fmt),
        ("type-check", verify_check_quiet),
        ("build", verify_build),
        ("test", verify_test_quiet),
    ];

    for (name, stage) in stages {
        if stage(path).is_err() {
            println!(
                "{}",
                json::object(&[
                    ("result", json::string("failed")),
                    ("stage", json::string(name)),
                ])
            );
            return Err(CliError::DiagnosticJsonEmitted);
        }
    }
    println!(
        "{}",
        json::object(&[
            ("result", json::string("passed")),
            ("stages", stages.len().to_string()),
        ])
    );
    Ok(())
}

/// The type-check stage in machine-quiet form: the same source-graph type-check
/// as [`verify_check`], but through the non-printing core so stdout stays clean
/// for the JSON verdict (a diagnostic still renders through the error channel).
pub fn verify_check_quiet(path: Option<&str>) -> Result<(), CliError> {
    let arg = match path {
        Some(e) => PathBuf::from(e),
        None => PathBuf::from(default_entry()?),
    };
    let entry = resolve_analysis_entry(&arg)?;
    typecheck_entry_via_graph(&entry)
}

/// The test stage in machine-quiet form: the shared runner with the test
/// binary's own summary routed to stderr, so stdout stays the JSON verdict alone.
pub fn verify_test_quiet(path: Option<&str>) -> Result<(), CliError> {
    run_project_tests_with(path, TestStdio::Quiet).map(|_| ())
}

pub fn run_capabilities(rest: &[String]) -> Result<(), CliError> {
    let (format, positional) = cli_args::split_format(rest, "capabilities")?;
    let arg = match positional.first() {
        Some(e) => PathBuf::from(e),
        None => PathBuf::from(default_entry()?),
    };
    // Route a directory / project-root `.` to its entry `.ipe` file, the same
    // argument convention `ipe type-check` uses. Without this a bare
    // `ipe capabilities` in a project dir passes `.` straight to the reader and
    // fails with a raw "Is a directory" io error.
    let entry = resolve_analysis_entry(&arg)?;
    let graph = build_source_graph(&entry)?;
    let program = graph.run_attributed(&entry, |db, root, file| {
        ipe_db::lower_program(db, root, file).clone()
    })?;
    let caps = capabilities_including_served_widgets(
        &graph.db,
        graph.source_root,
        graph.entry_file,
        &program,
    );
    let names: Vec<&'static str> = caps.iter().map(|c| c.as_str()).collect();
    print!(
        "{}",
        render_capabilities(&names, format, &std::io::stdout())
    );
    Ok(())
}

/// Render a program's inferred capability set in the requested [`OutputFormat`].
///
/// - Human (default): a guttered, labelled report — a heading and one bullet per
///   capability, or a line saying the program is pure.
/// - `--plain`: the bare capability names, one per line, flush-left (or nothing
///   at all for a pure program — the scriptable form pipelines already consume).
/// - `--json`: the shared `{schema, status, command, payload}` machine envelope
///   (`ipe.cli.capabilities/1`), with the sorted capability name array under
///   `payload.capabilities` (empty for a pure program).
pub fn render_capabilities(
    names: &[&str],
    format: cli_args::OutputFormat,
    stream: &impl std::io::IsTerminal,
) -> String {
    use std::fmt::Write as _;

    use cli_args::OutputFormat::{Human, Json, Plain};
    match format {
        Plain => {
            // The historical scriptable form: bare names, one per line. A pure
            // program prints nothing, so `| wc -l` counts the capabilities.
            let mut out = String::new();
            for name in names {
                out.push_str(name);
                out.push('\n');
            }
            out
        }
        Json => {
            // The shared machine envelope: a command may never hand-roll a bare
            // success object. The capability list rides under `payload`.
            let payload =
                cli_args::json::object(&[("capabilities", cli_args::json::string_array(names))]);
            crate::machine_output::MachineOutput::ok(
                "ipe.cli.capabilities/1",
                "capabilities",
                payload,
            )
            .render_json()
        }
        Human => {
            let p = style::Palette::for_stream(stream);
            let mut body = String::new();
            if names.is_empty() {
                body.push_str("This program is pure — it exercises no security capabilities.\n");
            } else {
                let noun = if names.len() == 1 {
                    "capability"
                } else {
                    "capabilities"
                };
                let _ = writeln!(
                    body,
                    "This program exercises {} security {noun}:",
                    names.len(),
                );
                for name in names {
                    let _ = writeln!(
                        body,
                        "  {}{}{} {}{name}{}",
                        p.yellow,
                        // The step bullet from the SSOT; the tint is the soft
                        // yellow this capability list wears, not running amber.
                        style::outcome_glyph(style::Outcome::Step),
                        p.reset,
                        p.yellow,
                        p.reset,
                    );
                }
            }
            style::frame(&style::gutter(&body))
        }
    }
}

/// `ipe version` — print the ipe version in the requested format.
pub fn run_version(rest: &[String]) -> Result<(), CliError> {
    let (format, positional) = cli_args::split_format(rest, "version")?;
    if let Some(extra) = positional.first() {
        return Err(cli_args::usage_unexpected_argument("version", extra));
    }
    print!("{}", render_version(format, &std::io::stdout()));
    Ok(())
}

/// The one-liner installer URL.
///
/// The same script the docs' `curl … | sh` install uses; `ipe upgrade` re-runs it
/// to fetch the latest release binary and install it over the current one. `pub`
/// so the install-drift test can assert the README `curl` one-liner and this
/// self-updater URL stay in agreement.
pub const INSTALL_SH_URL: &str =
    "https://raw.githubusercontent.com/arthurmaciel/ipe-lang/main/install.sh";

/// `ipe upgrade` — self-update by re-running the release installer.
///
/// Checks the latest published release, then installs it when a newer one is
/// available (and confirmed). `--dry-run` shows what would run without touching
/// anything; `--check` reports only and never installs; `--yes`/`-y` or a
/// non-TTY stdout skips the prompt; `--plain`/`--json` emit machine output and
/// never prompt. `--check --exit-code` signals 10 (available), 0 (up-to-date),
/// or 2 (feed unreachable) via the process exit code.
///
/// The installer (`install.sh`) exits with code 2 when it finds no prebuilt
/// binary; that distinct code surfaces as [`CliError::UpgradeNoPrebuilt`].
///
/// # Errors
/// [`CliError::UsageOwned`] on an unknown flag or a non-POSIX host.
/// [`CliError::UpgradeNoPrebuilt`] when the installer exits 2.
/// [`CliError::UpgradeFeedUnreachable`] when the release feed is offline and
/// `--check`/`--exit-code` are not in use.
/// [`CliError::UpgradeCheckExit`] for `--check --exit-code` numeric signals.
#[allow(clippy::too_many_lines)]
pub fn run_upgrade(rest: &[String]) -> Result<(), CliError> {
    use std::io::IsTerminal as _;

    let mut dry_run = false;
    let mut yes = false;
    let mut check = false;
    let mut exit_code_flag = false;
    let mut format: Option<cli_args::OutputFormat> = None;

    for arg in rest {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--yes" | "-y" => yes = true,
            "--check" => check = true,
            "--exit-code" => exit_code_flag = true,
            "--plain" => {
                if format.is_some() {
                    return Err(CliError::UsageOwned(
                        "ipe upgrade: --plain and --json are mutually exclusive".to_owned(),
                    ));
                }
                format = Some(cli_args::OutputFormat::Plain);
            }
            "--json" => {
                if format.is_some() {
                    return Err(CliError::UsageOwned(
                        "ipe upgrade: --plain and --json are mutually exclusive".to_owned(),
                    ));
                }
                format = Some(cli_args::OutputFormat::Json);
            }
            other if other.starts_with('-') => {
                return Err(cli_args::usage_unknown_flag("upgrade", other));
            }
            other => {
                return Err(cli_args::usage_unexpected_argument("upgrade", other));
            }
        }
    }

    let fmt = format.unwrap_or_default();
    let command = format!("curl -fsSL {INSTALL_SH_URL} | sh");

    // --dry-run: show the installer command and stop — no version check needed.
    if dry_run {
        print!(
            "{}",
            style::frame(&style::gutter(&format!("would run: {command}")))
        );
        return Ok(());
    }

    let vc = version_check::version_check();
    let action = vc.action();

    // --plain / --json: emit machine output and never prompt or install.
    if fmt != cli_args::OutputFormat::Human {
        print!("{}", render_upgrade(&vc, &action, false, fmt));
        return match action {
            version_check::UpgradeAction::Unreachable => Err(CliError::UpgradeFeedUnreachable),
            _ => Ok(()),
        };
    }

    // Human output: print the status line.
    let stdout = std::io::stdout();
    let p = style::Palette::for_stream(&stdout);
    match action {
        version_check::UpgradeAction::UpToDate => {
            let v = vc.current.to_string();
            let (glyph, tint) = style::Outcome::Success.glyph_and_tint(p);
            print!(
                "{}",
                style::frame(&style::gutter(&format!(
                    "{tint}{glyph}{} ipe {v} — already the latest release",
                    p.reset
                )))
            );
            if check && exit_code_flag {
                return Err(CliError::UpgradeCheckExit {
                    code: check_exit_code(&version_check::UpgradeAction::UpToDate),
                });
            }
            return Ok(());
        }
        version_check::UpgradeAction::Unreachable => {
            let (glyph, tint) = style::Outcome::Failure.glyph_and_tint(p);
            print!(
                "{}",
                style::frame(&style::gutter(&format!(
                    "{tint}{glyph}{}  couldn't reach the release feed — check your connection",
                    p.reset
                )))
            );
            if check && exit_code_flag {
                return Err(CliError::UpgradeCheckExit {
                    code: check_exit_code(&version_check::UpgradeAction::Unreachable),
                });
            }
            return Err(CliError::UpgradeFeedUnreachable);
        }
        version_check::UpgradeAction::Available => {
            let cur = vc.current.to_string();
            let lat = vc
                .latest
                .as_ref()
                .map(semver::Version::to_string)
                .unwrap_or_default();
            print!(
                "{}",
                style::frame(&style::gutter(&format!(
                    "{}?{}  ipe {cur} \u{2192} {lat} available",
                    p.yellow, p.reset
                )))
            );
            if check {
                if exit_code_flag {
                    return Err(CliError::UpgradeCheckExit {
                        code: check_exit_code(&version_check::UpgradeAction::Available),
                    });
                }
                return Ok(());
            }
        }
    }

    // Available + not --check: confirm then install.
    let stdout_is_tty = stdout.is_terminal();
    let should_prompt = fmt == cli_args::OutputFormat::Human && stdout_is_tty && !yes;
    let confirmed = if should_prompt {
        use std::io::Write as _;
        print!(
            "{}",
            style::gutter(&format!("{}Upgrade now? [Y/n] ", style::GUTTER))
        );
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(n) if n > 0 => {
                matches!(line.trim().to_ascii_lowercase().as_str(), "" | "y" | "yes")
            }
            _ => false,
        }
    } else {
        // Non-TTY stdout or --yes: treat as confirmed.
        yes || !stdout_is_tty
    };

    if !confirmed {
        return Ok(());
    }

    run_installer(&command)
}

/// Spawn the installer script and wait for it to finish.
///
/// The installer script exits 2 when no prebuilt binary exists for the current
/// platform; any other non-zero exit is a generic failure.
///
/// # Errors
/// [`CliError::UsageOwned`] when the host is not POSIX, the installer cannot
/// be launched, or it exits with a non-zero code that is not 2.
/// [`CliError::UpgradeNoPrebuilt`] when the installer exits 2.
pub fn run_installer(command: &str) -> Result<(), CliError> {
    if cfg!(not(unix)) {
        return Err(CliError::UsageOwned(format!(
            "upgrade: not supported on this platform — run the installer manually:\n  {command}"
        )));
    }

    // Render the hand-off to the installer as a stage on stderr: a running
    // light-yellow line while we spawn `sh`, settled to a green success (or a
    // red failure) BEFORE the child inherits the terminal, so the installer's
    // own staged output begins on a fresh, uncorrupted line.
    let stage = progress::Stage::start(std::io::stderr(), "Launching the release installer…");
    let child = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .spawn();
    let mut child = match child {
        Ok(child) => {
            stage.success("Installer launched — following its progress below.");
            child
        }
        Err(e) => {
            stage.failure(format!(
                "Could not launch the installer (needs `sh` and `curl`): {e}"
            ));
            return Err(CliError::UsageOwned(format!(
                "upgrade: cannot launch the installer (needs `sh` and `curl`): {e}"
            )));
        }
    };
    let status = child.wait().map_err(|e| {
        CliError::UsageOwned(format!(
            "upgrade: the installer could not be waited on: {e}"
        ))
    })?;
    if status.success() {
        return Ok(());
    }
    // Exit code 2: the installer found no prebuilt binary for the requested
    // version and platform. Report it as a typed, operational failure — NOT
    // misuse — so the caller skips the `--help` page.
    if status.code() == Some(2) {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let platform = format!(
            "{}-{}",
            match os {
                "linux" => "linux",
                "macos" => "darwin",
                "freebsd" => "freebsd",
                "windows" => "windows",
                other => other,
            },
            match arch {
                "x86_64" => "x64",
                "aarch64" => "arm64",
                other => other,
            }
        );
        // The version is not known here (the installer resolves it); use the
        // running binary's version as the best available proxy.
        let version = format!("v{}", env!("CARGO_PKG_VERSION"));
        return Err(CliError::UpgradeNoPrebuilt { version, platform });
    }
    Err(CliError::UsageOwned(
        "upgrade: the installer exited non-zero — nothing was changed".to_owned(),
    ))
}

/// The process exit code for `ipe upgrade --check --exit-code`, mirroring
/// git's `--exit-code` convention.
pub const fn check_exit_code(action: &version_check::UpgradeAction) -> i32 {
    match action {
        version_check::UpgradeAction::Available => 10,
        version_check::UpgradeAction::UpToDate => 0,
        version_check::UpgradeAction::Unreachable => 2,
    }
}

/// Render the upgrade status in `--plain` or `--json` format.
///
/// `upgraded` is `true` when the installer was actually run this session,
/// yielding `"action":"upgraded"` in JSON rather than `"checked"`.
/// Neither format ever prompts.
pub fn render_upgrade(
    check: &version_check::VersionCheck,
    action: &version_check::UpgradeAction,
    upgraded: bool,
    format: cli_args::OutputFormat,
) -> String {
    use cli_args::OutputFormat::{Json, Plain};
    let cur = check.current.to_string();
    let lat = check.latest.as_ref().map(semver::Version::to_string);
    match format {
        Json => {
            let action_str = if upgraded {
                "upgraded"
            } else {
                match action {
                    version_check::UpgradeAction::UpToDate => "up-to-date",
                    version_check::UpgradeAction::Available => "checked",
                    version_check::UpgradeAction::Unreachable => "unreachable",
                }
            };
            let lat_json = lat
                .as_deref()
                .map_or_else(|| "null".to_owned(), cli_args::json::string);
            let obj = cli_args::json::object(&[
                ("current", cli_args::json::string(&cur)),
                ("latest", lat_json),
                (
                    "upgradeAvailable",
                    if check.upgrade_available {
                        "true".to_owned()
                    } else {
                        "false".to_owned()
                    },
                ),
                (
                    "reachedFeed",
                    if check.reached_feed {
                        "true".to_owned()
                    } else {
                        "false".to_owned()
                    },
                ),
                ("action", cli_args::json::string(action_str)),
            ]);
            format!("{obj}\n")
        }
        Plain => match action {
            version_check::UpgradeAction::UpToDate => format!("ipe {cur} up-to-date\n"),
            version_check::UpgradeAction::Available => {
                if upgraded {
                    format!("ipe upgraded to {}\n", lat.unwrap_or_default())
                } else {
                    format!("ipe {cur} -> {} available\n", lat.unwrap_or_default())
                }
            }
            version_check::UpgradeAction::Unreachable => "feed unreachable\n".to_owned(),
        },
        // Human format is handled directly in `run_upgrade`.
        cli_args::OutputFormat::Human => String::new(),
    }
}

/// Render the ipe version in the requested [`OutputFormat`].
///
/// - Human (default): a guttered `ipe <version>` line.
/// - `--plain`: the bare version string, flush-left, nothing else.
/// - `--json`: the shared `{schema, status, command, payload}` machine envelope,
///   with the version under `payload.version` (`ipe.cli.version/1`).
pub fn render_version(
    format: cli_args::OutputFormat,
    _stream: &impl std::io::IsTerminal,
) -> String {
    use cli_args::OutputFormat::{Human, Json, Plain};
    let version = env!("CARGO_PKG_VERSION");
    match format {
        Plain => format!("{version}\n"),
        // Route through the shared machine envelope so `version --json` carries the
        // same `{schema, status, command, payload}` invariants as every other
        // command — a command may never hand-roll a bare success object.
        Json => {
            let payload = cli_args::json::object(&[("version", cli_args::json::string(version))]);
            crate::machine_output::MachineOutput::ok("ipe.cli.version/1", "version", payload)
                .render_json()
        }
        Human => style::frame(&style::gutter(&format!("ipe {version}\n"))),
    }
}

/// Verify a declared capability set equals the set inferred from `entry`.
///
/// Returns `Ok(())` iff `declared` is exactly the inferred set. Otherwise a
/// [`CliError::CapabilityMismatch`] naming the capabilities used but not
/// declared and those declared but not used. This is the primitive SP2 (manifest
/// generation) and SP4 (sandbox configuration) consume to reject a drifted or
/// under-declared manifest.
///
/// # Errors
/// [`CliError::Pipeline`] / [`CliError::Io`] when `entry` cannot be lowered, or
/// [`CliError::CapabilityMismatch`] on a set mismatch.
pub fn verify_capabilities(
    entry: &Path,
    declared: &std::collections::BTreeSet<ipe_ir::Capability>,
) -> Result<(), CliError> {
    let graph = build_source_graph(entry)?;
    let program = graph.run_attributed(entry, |db, root, file| {
        ipe_db::lower_program(db, root, file).clone()
    })?;
    let inferred = capabilities_including_served_widgets(
        &graph.db,
        graph.source_root,
        graph.entry_file,
        &program,
    );
    if *declared == inferred {
        return Ok(());
    }
    let missing: Vec<&'static str> = inferred.difference(declared).map(|c| c.as_str()).collect();
    let extra: Vec<&'static str> = declared.difference(&inferred).map(|c| c.as_str()).collect();
    Err(CliError::CapabilityMismatch { missing, extra })
}

/// The security capabilities a whole PACKAGE exercises — the union over every
/// module the package ships, not just the entry's reachability closure.
///
/// A single-entry program's capability set is its entry's reachable kernels
/// ([`verify_capabilities`]). A publishable package is different: a downstream
/// consumer can `import` ANY exposed module, so a sibling module that makes a
/// network call is a real capability of the package even when the package's own
/// `Main` never reaches it. The declared `[capabilities]` set the index records
/// is the consumer's consent surface, so it must cover the whole shipped surface
/// — the same whole-tree posture the enforced-semver check already takes over the
/// package's public API.
///
/// This lowers each discovered module in turn (with every sibling source present,
/// so cross-module imports resolve) and unions their inferred capabilities. A
/// module that fails to lower on its own — e.g. one that is only meaningful as a
/// dependency of another — is skipped for the union rather than failing the whole
/// inference, so a helper module never masks a sibling's real effect.
///
/// # Errors
/// [`CliError::Pipeline`] / [`CliError::Io`] when the package cannot be read or
/// no module lowers at all.
pub fn infer_package_capabilities(
    manifest_path: &Path,
) -> Result<std::collections::BTreeSet<ipe_ir::Capability>, CliError> {
    let manifest = project::parse_manifest(manifest_path)?;
    let mut discovered = project::discover_modules(&manifest.src_root)?;

    // Read every module's source once; the shared map lets each per-module
    // lowering resolve its sibling imports.
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    for m in &discovered {
        let src =
            crate::io_bounded::read_to_string_capped(&m.path, crate::io_bounded::SOURCE_READ_CAP)?;
        sources.insert(m.module_path.clone(), (m.path.clone(), src));
    }

    // Inject the compiled-source stdlib closure (e.g. `Ipe.Css`) just like the
    // real build path, so a module that imports a compiled-source stdlib module
    // lowers standalone here instead of failing name resolution (which, since a
    // failing entry surfaces its real diagnostic, would otherwise abort build).
    let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);
    // Inject the FFI interface modules (installed crates + the asserted-call
    // `Rust.Ffi` module) exactly as the build does, so an FFI-using module
    // lowers here and its `native-ffi`/`ffi-raw` capabilities are inferred
    // rather than the whole module being skipped on a resolve failure.
    let ffi_injected = ffi::prepare_ffi(&mut sources, manifest_path)?.injected;
    let mut inferred: std::collections::BTreeSet<ipe_ir::Capability> =
        std::collections::BTreeSet::new();
    let mut any_lowered = false;
    // When nothing lowers, the entry module's real diagnostic is far more useful
    // than a generic "nothing lowered". Keep the best candidate to surface: the
    // entry module `Main` if it fails, otherwise the first failure seen.
    let mut lowering_error: Option<CliError> = None;

    // Lower each module as its own entry (a fresh database per module keeps the
    // interning deterministic and the borrow of the shared interner scoped). A
    // module that does not lower standalone is skipped, never fatal — its
    // capabilities, if any, surface through whichever sibling does reach it.
    for m in &discovered {
        let db = ipe_db::IpeDatabase::new();
        let source_root = create_source_root(&db, &sources, &injected, &ffi_injected);
        let Some(entry_file) = source_root.files(&db).get(&m.module_path).copied() else {
            continue;
        };
        match ipe_db::lower_program(&db, source_root, entry_file) {
            Ok(program) => {
                inferred.extend(capabilities_including_served_widgets(
                    &db,
                    source_root,
                    entry_file,
                    program,
                ));
                any_lowered = true;
            }
            Err((diag, _)) => {
                let is_entry = m.module_path.last().map(String::as_str) == Some("Main");
                if lowering_error.is_none() || is_entry {
                    let src = sources
                        .get(&m.module_path)
                        .map(|(_, s)| s.clone())
                        .unwrap_or_default();
                    lowering_error = Some(CliError::Pipeline {
                        file: m.path.clone(),
                        src,
                        diag: Box::new(diag.clone()),
                    });
                }
            }
        }
    }

    if any_lowered {
        Ok(inferred)
    } else {
        // Surface the real reason the entry could not be lowered, not a generic
        // "nothing lowered" that hides the actual compiler diagnostic.
        Err(lowering_error.unwrap_or(CliError::Usage(
            "package capability inference: no module in the package could be lowered",
        )))
    }
}

// ===========================================================================
// `fix` / `--fix` — apply machine-applicable suggestions
// ===========================================================================

/// Run the front of the pipeline (parse → canon → types → lower) and return the
/// first diagnostic it raises, or `None` when the program compiles cleanly.
pub fn pipeline_first_diagnostic(source: &str) -> Option<Diagnostic> {
    let mut interner = Interner::new();
    let module = match ipe_parse::parse_module(source, &mut interner) {
        Ok(m) => m,
        Err(d) => return Some(d),
    };
    let canonical = match ipe_canon::canonicalise(&module, &mut interner) {
        Ok(c) => c,
        Err(d) => return Some(d),
    };
    let types = match ipe_types::infer(&canonical, &mut interner) {
        Ok(t) => t,
        Err(d) => return Some(d),
    };
    // `--fix` diagnostic probe: single source, home is irrelevant — take just
    // the diagnostic. Source info not available here; location falls back.
    ipe_lower::lower(&canonical, &types, &mut interner, "", "")
        .err()
        .map(|(diag, _home)| diag)
}

/// Collect every [`Applicability::MachineApplicable`] suggestion a diagnostic
/// carries — the only kind eligible for auto-patch.
pub fn machine_applicable_suggestions(diag: &Diagnostic) -> Vec<Suggestion> {
    diag.help()
        .into_iter()
        .filter_map(|line| match line {
            HelpLine::Suggest(s) if s.applicability == Applicability::MachineApplicable => Some(s),
            _ => None,
        })
        .collect()
}

/// Validate spans against `src_len` and keep a non-overlapping subset, ordered
/// back-to-front (largest `lo` first) so applying them never shifts a
/// not-yet-applied span.
#[must_use]
pub fn select_non_overlapping(mut suggestions: Vec<Suggestion>, src_len: usize) -> Vec<Suggestion> {
    let limit = u32::try_from(src_len).unwrap_or(u32::MAX);
    suggestions.retain(|s| s.span.lo <= s.span.hi && s.span.hi <= limit);
    suggestions.sort_by(|a, b| {
        b.span
            .lo
            .cmp(&a.span.lo)
            .then_with(|| b.span.hi.cmp(&a.span.hi))
    });
    let mut kept: Vec<Suggestion> = Vec::new();
    // Lowest `lo` retained so far; the next (further-left) span must end at or
    // before it to avoid overlapping a span we already chose.
    let mut floor = u32::MAX;
    for s in suggestions {
        if s.span.hi <= floor {
            floor = s.span.lo;
            kept.push(s);
        }
    }
    kept
}

/// Apply `fixes` to `src`, returning the patched text.
///
/// `fixes` are assumed non-overlapping and ordered back-to-front. Returns `None`
/// if any span is out of bounds or not on a UTF-8 char boundary. Never indexes
/// raw bytes.
#[must_use]
pub fn apply_fixes(src: &str, fixes: &[Suggestion]) -> Option<String> {
    let mut out = src.to_owned();
    for s in fixes {
        let lo = usize::try_from(s.span.lo).ok()?;
        let hi = usize::try_from(s.span.hi).ok()?;
        if lo > hi || hi > out.len() || !out.is_char_boundary(lo) || !out.is_char_boundary(hi) {
            return None;
        }
        let before = out.get(..lo)?;
        let after = out.get(hi..)?;
        let mut next = String::with_capacity(before.len() + s.replacement.len() + after.len());
        next.push_str(before);
        next.push_str(&s.replacement);
        next.push_str(after);
        out = next;
    }
    Some(out)
}

/// 1-based `(line, column)` of a byte `offset` into `src`, counting columns in
/// characters. Clamps gracefully — never panics.
pub fn line_col(src: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in src.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line = line.saturating_add(1);
            col = 1;
        } else {
            col = col.saturating_add(1);
        }
    }
    (line, col)
}

/// The fix command/flow: read `entry`, run the pipeline, and apply the
/// machine-applicable suggestions of the first diagnostic.
///
/// `auto` (set by `--yes` / `--fix`) is durable authorization to apply every
/// edit without prompting; otherwise each edit is confirmed interactively on
/// stdin. The patch is never silent: every applied or skipped edit is reported
/// on `w`. The patched text is re-parsed before it replaces the file, and a
/// result that no longer parses is rejected (the file is left untouched).
///
/// Writes go through a temp file + atomic rename.
///
/// # Errors
/// Returns [`CliError::Io`] on a filesystem failure.
pub fn apply_fixes_cmd<W: Write>(entry: &Path, auto: bool, w: &mut W) -> Result<(), CliError> {
    let source =
        crate::io_bounded::read_to_string_capped(entry, crate::io_bounded::SOURCE_READ_CAP)?;

    let Some(diag) = pipeline_first_diagnostic(&source) else {
        writeln!(
            w,
            "fix: nothing to do — {} compiles cleanly",
            entry.display()
        )
        .map_err(|e| io_err(entry, e))?;
        return Ok(());
    };

    let candidates = machine_applicable_suggestions(&diag);
    let selected = select_non_overlapping(candidates, source.len());
    if selected.is_empty() {
        writeln!(
            w,
            "fix: no machine-applicable suggestions for {} [{}]",
            entry.display(),
            diag.code().as_str()
        )
        .map_err(|e| io_err(entry, e))?;
        return Ok(());
    }

    let mut chosen: Vec<Suggestion> = Vec::new();
    for s in &selected {
        let lo = usize::try_from(s.span.lo).unwrap_or(usize::MAX);
        let hi = usize::try_from(s.span.hi).unwrap_or(usize::MAX);
        let original = source.get(lo..hi).unwrap_or("");
        let (line, col) = line_col(&source, lo);
        if auto {
            writeln!(
                w,
                "fix: replacing `{original}` with `{}` at {}:{line}:{col}",
                s.replacement,
                entry.display()
            )
            .map_err(|e| io_err(entry, e))?;
            chosen.push(s.clone());
        } else {
            write!(
                w,
                "Replace `{original}` with `{}` at {}:{line}:{col}? [y/N] ",
                s.replacement,
                entry.display()
            )
            .map_err(|e| io_err(entry, e))?;
            w.flush().map_err(|e| io_err(entry, e))?;
            if read_yes_no() {
                chosen.push(s.clone());
            }
        }
    }

    if chosen.is_empty() {
        writeln!(w, "fix: no edits applied").map_err(|e| io_err(entry, e))?;
        return Ok(());
    }

    let Some(patched) = apply_fixes(&source, &chosen) else {
        writeln!(
            w,
            "fix: internal span mismatch — file left unchanged (please report)"
        )
        .map_err(|e| io_err(entry, e))?;
        return Ok(());
    };

    // Re-parse guard: refuse to keep a patch whose result no longer parses.
    let mut guard_interner = Interner::new();
    if ipe_parse::parse_module(&patched, &mut guard_interner).is_err() {
        writeln!(
            w,
            "fix: patched source no longer parses — rolled back, file left unchanged"
        )
        .map_err(|e| io_err(entry, e))?;
        return Ok(());
    }

    write_atomic(entry, &patched)?;
    writeln!(
        w,
        "fix: applied {} edit(s) to {}",
        chosen.len(),
        entry.display()
    )
    .map_err(|e| io_err(entry, e))?;
    Ok(())
}

/// Read a line from stdin and interpret it as a yes/no answer. EOF or any read
/// error is treated as "no" (the safe default for a mutating action).
pub fn read_yes_no() -> bool {
    read_yes_no_default(false)
}

/// Read a line from stdin and interpret it as a yes/no answer, taking `default`
/// when the answer is empty (a bare Enter). An explicit `y`/`yes` or `n`/`no`
/// overrides the default; EOF or any read error takes the default, so the caller
/// controls the fail-safe direction (default `false` for a mutating action).
pub fn read_yes_no_default(default: bool) -> bool {
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(_) => {
            let a = line.trim();
            if a.is_empty() {
                default
            } else {
                a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes")
            }
        }
        Err(_) => default,
    }
}

/// Write `contents` to `target` atomically: write a sibling temp file, then
/// rename it over `target` (atomic on a single filesystem). On a rename
/// failure the temp file is removed so no debris is left behind.
///
/// Retries ONCE, recreating `target`'s parent directory, when the write or
/// rename fails with `NotFound`. This closes a real race surfaced by the
/// emit→cargo bridge (`reconcile_emitted_project`, this function's
/// other caller besides `ipe fix`): several `crates/ipe/tests/
/// golden_*` integration-test files share ONE `CARGO_TARGET_TMPDIR`-rooted
/// output directory across sibling `#[test]` functions, and `cargo-nextest`
/// runs each test as its own process — so one test's `remove_dir_all` +
/// rebuild can delete a directory this function is mid-write into. A single
/// retry recovers from that transient case; a genuinely permanent failure
/// (permissions, a disallowed ancestor) still surfaces as an error after the
/// retry.
pub fn write_atomic(target: &Path, contents: &str) -> Result<(), CliError> {
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty());
    let name = target.file_name().map_or_else(
        || String::from("source.ipe"),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp_name = format!(".{name}.ipec-fix.{}.tmp", std::process::id());
    let tmp = match dir {
        Some(d) => d.join(tmp_name),
        None => PathBuf::from(tmp_name),
    };

    match write_and_rename(&tmp, target, contents) {
        Ok(()) => Ok(()),
        Err(CliError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            if let Some(d) = dir {
                fs::create_dir_all(d).map_err(|e| io_err(d, e))?;
            }
            write_and_rename(&tmp, target, contents)
        }
        Err(e) => Err(e),
    }
}

/// Write `contents` to `tmp`, then rename it over `target`. On a rename
/// failure the temp file is removed so no debris is left behind.
pub fn write_and_rename(tmp: &Path, target: &Path, contents: &str) -> Result<(), CliError> {
    fs::write(tmp, contents).map_err(|e| io_err(tmp, e))?;
    if let Err(e) = fs::rename(tmp, target) {
        let _ = fs::remove_file(tmp);
        return Err(io_err(target, e));
    }
    Ok(())
}

pub fn io_err(path: &Path, source: std::io::Error) -> CliError {
    CliError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Extract the source span from a diagnostic, returning [`ipe_diagnostics::Span::DUMMY`]
/// for the span-less [`Diagnostic::CompilerBug`] variant.
///
/// Used by the cross-module error-attribution path in [`compile_modules`] to
/// locate the source file that owns a diagnostic.
pub const fn diag_span(d: &Diagnostic) -> ipe_diagnostics::Span {
    match d {
        Diagnostic::Parse { span, .. }
        | Diagnostic::Name { span, .. }
        | Diagnostic::Type { span, .. }
        | Diagnostic::Lower { span, .. } => *span,
        Diagnostic::CompilerBug { .. }
        | Diagnostic::Ffi { .. }
        | Diagnostic::Sandbox { .. }
        | Diagnostic::Consent { .. }
        | Diagnostic::RegistryUnreachable { .. } => ipe_diagnostics::Span::DUMMY,
    }
}

// ── Refusal gate unit tests ───────────────────────────────────────────────────
//
// These tests drive the fail-closed shape/permission gates WITHOUT a real
// project on disk: they pass `Some(declared)` so `classify_entry_shape` (which
// reads source files) is bypassed. Any rejected path that no test drives is one
// edit away from silently passing — pin them here.

#[cfg(test)]
mod pack_gate_tests {
    use super::*;

    // ── Desktop gate refusals ─────────────────────────────────────────────────

    /// A declared `Terminal` shape must be refused for desktop packaging — a
    /// terminal app is not a webview-capable host.
    #[test]
    fn desktop_gate_refuses_terminal_shape() {
        let err = validate_desktop_shape(Some(project::EntryShape::Terminal), Path::new("."))
            .expect_err("Terminal shape must be refused");
        assert!(
            matches!(&err, CliError::UsageOwned(_)),
            "expected UsageOwned, got {err:?}"
        );
        let CliError::UsageOwned(msg) = err else {
            return;
        };
        assert!(
            msg.contains("Terminal") || msg.contains("terminal"),
            "refusal names the rejected shape: {msg}"
        );
    }

    /// A declared `Program` shape must be refused for desktop packaging — a
    /// plain program produces no desktop window.
    #[test]
    fn desktop_gate_refuses_program_shape() {
        let err = validate_desktop_shape(Some(project::EntryShape::Program), Path::new("."))
            .expect_err("Program shape must be refused");
        assert!(
            matches!(&err, CliError::UsageOwned(_)),
            "expected UsageOwned, got {err:?}"
        );
        let CliError::UsageOwned(msg) = err else {
            return;
        };
        assert!(
            msg.contains("Program") || msg.contains("program"),
            "refusal names the rejected shape: {msg}"
        );
    }

    /// A declared `WebView` shape passes the desktop gate — the desktop
    /// packager is the webview-native host.
    #[test]
    fn desktop_gate_accepts_webview_shape() {
        validate_desktop_shape(Some(project::EntryShape::WebView), Path::new("."))
            .expect("WebView shape must pass the desktop gate");
    }

    /// A declared `Web` shape is refused for desktop packaging — `Web` is a
    /// server/SPA shape, not a native-window shape; only `WebView` can be
    /// desktop-bundled.
    #[test]
    fn desktop_gate_refuses_web_shape() {
        let err = validate_desktop_shape(Some(project::EntryShape::Web), Path::new("."))
            .expect_err("Web shape must be refused for desktop");
        assert!(
            matches!(&err, CliError::UsageOwned(_)),
            "expected UsageOwned, got {err:?}"
        );
        let CliError::UsageOwned(msg) = err else {
            return;
        };
        assert!(
            msg.contains("web") || msg.contains("Web"),
            "refusal names the rejected shape: {msg}"
        );
    }

    // ── Desktop shape classification ──────────────────────────────────────────

    /// `EntryShape::Terminal` classifies to `AppShape::Terminal`.
    #[test]
    fn classify_terminal_declared_shape() {
        let shape = classify_desktop_shape(Some(project::EntryShape::Terminal), Path::new("."))
            .expect("classification must not fail for a declared shape");
        assert_eq!(shape, pack::desktop::AppShape::Terminal);
    }

    /// `EntryShape::Program` classifies to `AppShape::Program`.
    #[test]
    fn classify_program_declared_shape() {
        let shape = classify_desktop_shape(Some(project::EntryShape::Program), Path::new("."))
            .expect("classification must not fail for a declared shape");
        assert_eq!(shape, pack::desktop::AppShape::Program);
    }

    /// `EntryShape::WebView` classifies to `AppShape::WebView`.
    #[test]
    fn classify_webview_declared_shape() {
        let shape = classify_desktop_shape(Some(project::EntryShape::WebView), Path::new("."))
            .expect("classification must not fail for a declared shape");
        assert_eq!(shape, pack::desktop::AppShape::WebView);
    }

    /// `EntryShape::Web` classifies to `AppShape::Web`.
    #[test]
    fn classify_web_declared_shape() {
        let shape = classify_desktop_shape(Some(project::EntryShape::Web), Path::new("."))
            .expect("classification must not fail for a declared shape");
        assert_eq!(shape, pack::desktop::AppShape::Web);
    }

    // ── Mobile gate refusals ──────────────────────────────────────────────────

    /// A declared non-`Web` shape must be refused for mobile packaging — the
    /// mobile SPA shell only hosts `Web` apps.
    #[test]
    fn mobile_gate_refuses_terminal_shape() {
        let wasm_on = project::WasmConfig {
            mode: Some("solo".to_owned()),
            ..Default::default()
        };
        let err = validate_mobile_shape(
            Some(project::EntryShape::Terminal),
            Path::new("."),
            &wasm_on,
        )
        .expect_err("Terminal shape must be refused for mobile");
        assert!(
            matches!(&err, CliError::UsageOwned(_)),
            "expected UsageOwned, got {err:?}"
        );
        let CliError::UsageOwned(msg) = err else {
            return;
        };
        assert!(
            msg.contains("Terminal") || msg.contains("terminal") || msg.contains("Web"),
            "refusal names the shape or the required type: {msg}"
        );
    }

    /// A declared `Program` shape must be refused for mobile packaging.
    #[test]
    fn mobile_gate_refuses_program_shape() {
        let wasm_on = project::WasmConfig {
            mode: Some("solo".to_owned()),
            ..Default::default()
        };
        let err =
            validate_mobile_shape(Some(project::EntryShape::Program), Path::new("."), &wasm_on)
                .expect_err("Program shape must be refused for mobile");
        assert!(
            matches!(&err, CliError::UsageOwned(_)),
            "expected UsageOwned, got {err:?}"
        );
        let CliError::UsageOwned(msg) = err else {
            return;
        };
        assert!(
            msg.contains("Program") || msg.contains("program") || msg.contains("Web"),
            "refusal names the shape or the required type: {msg}"
        );
    }

    /// A `Web` shape with wasm mode `off` must be refused — the mobile shell
    /// requires `[wasm] mode` set to `spa` or `hydrate`.
    #[test]
    fn mobile_gate_refuses_web_shape_without_wasm() {
        let wasm_off = project::WasmConfig::default(); // mode = None -> off
        let err = validate_mobile_shape(Some(project::EntryShape::Web), Path::new("."), &wasm_off)
            .expect_err("Web shape without wasm must be refused for mobile");
        assert!(
            matches!(&err, CliError::UsageOwned(_)),
            "expected UsageOwned, got {err:?}"
        );
        let CliError::UsageOwned(msg) = err else {
            return;
        };
        assert!(
            msg.contains("wasm") || msg.contains("Wasm") || msg.contains("solo"),
            "refusal names the missing wasm capability: {msg}"
        );
    }

    /// A `Web` shape with wasm mode `spa` passes the mobile gate.
    #[test]
    fn mobile_gate_accepts_web_shape_with_wasm_spa() {
        let wasm_on = project::WasmConfig {
            mode: Some("solo".to_owned()),
            ..Default::default()
        };
        validate_mobile_shape(Some(project::EntryShape::Web), Path::new("."), &wasm_on)
            .expect("Web + wasm=spa must pass the mobile gate");
    }

    /// A `Web` shape with wasm mode `hydrate` also passes the mobile gate.
    #[test]
    fn mobile_gate_accepts_web_shape_with_wasm_hydrate() {
        let wasm_on = project::WasmConfig {
            mode: Some("hydrate".to_owned()),
            ..Default::default()
        };
        validate_mobile_shape(Some(project::EntryShape::Web), Path::new("."), &wasm_on)
            .expect("Web + wasm=hydrate must pass the mobile gate");
    }

    // ── Mobile capability classification ──────────────────────────────────────

    /// `Web` + wasm enabled -> `shape_is_web=true`, `wasm_enabled=true`.
    #[test]
    fn classify_mobile_cap_web_wasm_on() {
        let wasm_on = project::WasmConfig {
            mode: Some("solo".to_owned()),
            ..Default::default()
        };
        let cap = classify_mobile_spa_cap(Some(project::EntryShape::Web), Path::new("."), &wasm_on)
            .expect("classification must succeed");
        assert!(cap.shape_is_web, "Web shape must set shape_is_web");
        assert!(cap.wasm_enabled, "spa mode must set wasm_enabled");
    }

    /// `Terminal` + wasm enabled -> `shape_is_web=false`.
    #[test]
    fn classify_mobile_cap_terminal_wasm_on() {
        let wasm_on = project::WasmConfig {
            mode: Some("solo".to_owned()),
            ..Default::default()
        };
        let cap = classify_mobile_spa_cap(
            Some(project::EntryShape::Terminal),
            Path::new("."),
            &wasm_on,
        )
        .expect("classification must succeed");
        assert!(
            !cap.shape_is_web,
            "Terminal shape must set shape_is_web=false"
        );
    }

    /// `Web` + wasm off -> `wasm_enabled=false`.
    #[test]
    fn classify_mobile_cap_web_wasm_off() {
        let wasm_off = project::WasmConfig::default();
        let cap =
            classify_mobile_spa_cap(Some(project::EntryShape::Web), Path::new("."), &wasm_off)
                .expect("classification must succeed");
        assert!(cap.shape_is_web, "Web shape must set shape_is_web");
        assert!(!cap.wasm_enabled, "mode=None must set wasm_enabled=false");
    }
}
